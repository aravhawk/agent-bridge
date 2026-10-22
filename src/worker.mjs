import { randomUUID } from 'node:crypto';
import { BridgeError, DELIVERY_TRANSPORT_OUTCOME } from './policy.mjs';
import { subscriptionAccessAllowed, messageAccessAllowed, testEnvelopeAllowed } from './access.mjs';
import { signedHeaders } from './webhook.mjs';

const transient = status => status === 408 || status === 429 || (status >= 500 && status <= 599);
const backoff = attempt => Math.min(60000, 1000 * (2 ** Math.min(attempt - 1, 6)));

export class DeliveryWorker {
  constructor({ store, protector, transport, fridaySender, accessAllowed, policyId, enabled = false, clock = Date.now,
    maxAttempts = 5, leaseMs = 30000, messagePolicyIds = { jarvis: policyId, friday: policyId }, deliveryUntil = Infinity,
    probeMessageId, probeSender = 'jarvis' }) {
    this.store = store; this.protector = protector; this.transport = transport; this.fridaySender = fridaySender;
    this.accessAllowed = accessAllowed; this.enabled = enabled; this.clock = clock;
    this.policyId = policyId;
    this.messagePolicyIds = messagePolicyIds; this.deliveryUntil = deliveryUntil;
    this.probeMessageId = probeMessageId; this.probeSender = probeSender;
    this.maxAttempts = maxAttempts; this.leaseMs = leaseMs;
  }
  messageAllowed(state, message, now) {
    return messageAccessAllowed(state, message, this.messagePolicyIds, now) &&
      (!this.probeMessageId || testEnvelopeAllowed(message.envelope, this.probeMessageId, this.probeSender));
  }
  // One queue job dispatches one attempt. There is no loop, interval, timer,
  // assistant listen/inbox check, or live queue registration in this module.
  async run(jobId) {
    if (!this.enabled) throw new BridgeError('delivery_not_enabled', 503);
    const now = this.clock();
    const claimed = await this.store.transaction(state => {
      const job = state.jobs[jobId];
      if (!job || ['accepted', 'dead'].includes(job.state) || job.dueAt > now ||
          (job.state === 'leased' && job.leaseUntil > now)) return null;
      if (job.firstTransportOutcome?.terminal === true) {
        const status = job.firstTransportOutcome.status;
        job.state = status >= 200 && status < 300 ? 'accepted' : 'dead';
        return null; // Restore a committed one-shot result without another send.
      }
      if (job.attempts >= this.maxAttempts) {
        job.state = 'dead'; job.lastError = 'attempt_limit'; return null;
      }
      const sub = job.subscriptionId ? state.subscriptions[job.subscriptionId] : null;
      if (job.subscriptionId && (job.recipient !== sub?.recipient || job.subscriptionId !== sub?.id ||
          !subscriptionAccessAllowed(state, sub, this.policyId, this.clock()))) {
        job.state = 'dead'; job.lastError = 'subscription_inactive'; return null;
      }
      const message = state.messages[job.messageId];
      if (this.clock() >= this.deliveryUntil || !this.messageAllowed(state, message, this.clock()) ||
          message.envelope.to !== job.recipient || !message.jobIds.includes(jobId)) {
        job.state = 'dead'; job.lastError = 'message_authorization_inactive'; return null;
      }
      job.state = 'leased'; job.leaseId = randomUUID(); job.leaseUntil = now + this.leaseMs; job.attempts++;
      return { job, subscription: sub };
    });
    if (!claimed) return { attempted: false };
    const { job, subscription } = claimed;
    let accepted = false; let retry = false; let code = 'delivery_configuration_required'; let status = null;
    let transportOutcome = null, transportStarted = false;
    try {
      // Jarvis uses a finite verified-token lease plus durable resource denial.
      // Friday additionally requires its separately verified native authorizer.
      if ((!subscription && !this.accessAllowed) || (this.accessAllowed && !(await this.accessAllowed({ owner: subscription?.owner,
        recipient: job.recipient, subscriptionId: subscription?.id, messageId: job.messageId })))) {
        code = 'access_revoked';
      } else {
        // Recheck current DB state after asynchronous access validation. It is
        // still possible for in-flight network work to finish after revocation;
        // fencing prevents it from mutating a reclaimed job or newer state.
        const current = await this.store.transaction(state => {
          const activeJob = state.jobs[jobId];
          const activeSub = subscription ? state.subscriptions[subscription.id] : null;
          const message = state.messages[job.messageId];
          if (activeJob?.leaseId !== job.leaseId || activeJob.state !== 'leased' || activeJob.leaseUntil <= this.clock() ||
              this.clock() >= this.deliveryUntil || !this.messageAllowed(state, message, this.clock()) ||
              message.envelope.to !== activeJob.recipient || !message.jobIds.includes(jobId) ||
              (subscription && (activeJob.recipient !== activeSub?.recipient ||
                !subscriptionAccessAllowed(state, activeSub, this.policyId, this.clock())))) return null;
          return { subscription: activeSub, resourceDenials: state.resourceDenials, message };
        });
        if (!current) code = subscription ? 'subscription_inactive' : 'message_authorization_inactive';
        else {
          if (this.clock() >= this.deliveryUntil || !this.messageAllowed(current, current.message, this.clock())) {
            throw new BridgeError('message_authorization_inactive', 403);
          }
          let response;
          if (subscription) {
            if (!this.protector || !this.transport) throw new BridgeError('delivery_configuration_required', 503);
            const config = this.protector.open(current.subscription.sealed, subscription.id);
            const when = this.clock();
            if (!subscriptionAccessAllowed(current, current.subscription, this.policyId, when))
              throw new BridgeError('authorization_lease_expired', 403);
            const secrets = [config.secret, ...(config.previous || []).filter(x => x.until > when).map(x => x.secret)];
            transportStarted = true;
            response = await this.transport(config.url, { body: job.body,
              headers: signedHeaders({ id: job.eventId, body: job.body, secrets, subscriptionId: subscription.id, now: when }) });
          } else {
            if (!this.fridaySender) throw new BridgeError('friday_native_contract_unverified', 503);
            transportStarted = true;
            response = await this.fridaySender(job);
          }
          status = response.status;
          transportOutcome = response[DELIVERY_TRANSPORT_OUTCOME] || null;
          accepted = status >= 200 && status < 300;
          retry = !accepted && transient(status) && transportOutcome?.terminal !== true;
          code = accepted ? null : transient(status) ? 'transient_http' : 'permanent_http';
        }
      }
    } catch (error) {
      // A temporary DB failure during the access/state recheck has not granted
      // permission or sent anything. Keep this work pending within the existing
      // attempt/backoff budget; every retry must pass all authorization fences.
      // Configuration, encryption and public-address rejection remain terminal.
      transportOutcome = error?.[DELIVERY_TRANSPORT_OUTCOME] || null;
      const storageUnavailable = !transportStarted && error instanceof BridgeError && error.code === 'storage_unavailable';
      const transientError = ['callback_timeout', 'callback_transport_failed', 'callback_dns_failed'].includes(error?.code);
      retry = (storageUnavailable || transientError) && transportOutcome?.terminal !== true;
      code = storageUnavailable ? 'storage_unavailable' : transientError ? 'transport_transient' : 'delivery_configuration_required';
    }
    const completedAt = this.clock();
    const saved = await this.store.transaction(state => {
      const activeJob = state.jobs[jobId];
      if (activeJob?.leaseId !== job.leaseId || activeJob.state !== 'leased' || activeJob.leaseUntil <= this.clock()) return false;
      const sub = subscription ? state.subscriptions[subscription.id] : null;
      if (subscription && (activeJob.recipient !== sub?.recipient ||
          !subscriptionAccessAllowed(state, sub, this.policyId, this.clock()))) { accepted = false; retry = false; code = 'subscription_inactive'; }
      const message = state.messages[job.messageId];
      if (this.clock() >= this.deliveryUntil || !this.messageAllowed(state, message, this.clock()) ||
          message.envelope.to !== activeJob.recipient || !message.jobIds.includes(jobId)) {
        accepted = false; retry = false; code = 'message_authorization_inactive';
      }
      if (transportOutcome) {
        // Worker claims/queue callbacks are not HTTP sends. Count only adapter
        // transport invocations with a fenced outcome; DNS/TLS failure may mean
        // no request reached the receiver. Never overwrite the first evidence.
        activeJob.transportAttempts = (activeJob.transportAttempts || 0) + 1;
        activeJob.firstTransportOutcome ||= { at: completedAt, workerAttempt: job.attempts,
          status, error: transportOutcome.error || (status === null ? code : status >= 200 && status < 300 ? null
            : transient(status) ? 'transient_http' : 'permanent_http'), terminal: transportOutcome.terminal === true };
      }
      activeJob.state = accepted ? 'accepted' : retry && activeJob.attempts < this.maxAttempts ? 'pending' : 'dead';
      activeJob.lastError = code; activeJob.lastStatus = status;
      activeJob.dueAt = completedAt + backoff(activeJob.attempts);
      activeJob.leaseId = null; activeJob.leaseUntil = null;
      if (accepted) activeJob.acceptedAt = completedAt;
      return true;
    });
    return { attempted: true, committed: saved, transportAccepted: saved && accepted, status,
      retryAt: saved && retry && job.attempts < this.maxAttempts ? new Date(completedAt + backoff(job.attempts)).toISOString() : null };
  }
}

// Backend outbox reconciliation only; caller binds this to its authenticated
// managed queue. Never expose it as a receiver assistant tool or polling API.
export async function reconcileOutbox(store, enqueueJob, now = Date.now()) {
  if (typeof enqueueJob !== 'function') throw new BridgeError('queue_configuration_required', 503);
  const ids = await store.transaction(state => Object.values(state.jobs).filter(job =>
    (job.state === 'pending' && job.dueAt <= now) || (job.state === 'leased' && job.leaseUntil <= now))
    .map(job => ({ id: job.id, dueAt: job.dueAt })).slice(0, 100));
  for (const job of ids) await enqueueJob(job.id, job.dueAt);
  return { scheduled: ids.length };
}
