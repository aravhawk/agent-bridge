import { randomUUID } from 'node:crypto';
import { BridgeError } from './policy.mjs';
import { isActive } from './events.mjs';
import { signedHeaders } from './webhook.mjs';

const transient = status => status === 408 || status === 429 || (status >= 500 && status <= 599);
const backoff = attempt => Math.min(60000, 1000 * (2 ** Math.min(attempt - 1, 6)));

export class DeliveryWorker {
  constructor({ store, protector, transport, fridaySender, accessAllowed, enabled = false, clock = Date.now,
    maxAttempts = 5, leaseMs = 30000 }) {
    this.store = store; this.protector = protector; this.transport = transport; this.fridaySender = fridaySender;
    this.accessAllowed = accessAllowed; this.enabled = enabled; this.clock = clock;
    this.maxAttempts = maxAttempts; this.leaseMs = leaseMs;
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
      if (job.attempts >= this.maxAttempts) {
        job.state = 'dead'; job.lastError = 'attempt_limit'; return null;
      }
      const sub = job.subscriptionId ? state.subscriptions[job.subscriptionId] : null;
      if (job.subscriptionId && !isActive(sub, now)) {
        job.state = 'dead'; job.lastError = 'subscription_inactive'; return null;
      }
      job.state = 'leased'; job.leaseId = randomUUID(); job.leaseUntil = now + this.leaseMs; job.attempts++;
      return { job, subscription: sub };
    });
    if (!claimed) return { attempted: false };
    const { job, subscription } = claimed;
    let accepted = false; let retry = false; let code = 'delivery_configuration_required'; let status = null;
    try {
      // Required live authorizer rechecks grants/resource access. No configured
      // callback is trusted solely because it was subscribed in the past.
      if (!this.accessAllowed || !(await this.accessAllowed({ owner: subscription?.owner,
        recipient: job.recipient, subscriptionId: subscription?.id, messageId: job.messageId }))) {
        code = 'access_revoked';
      } else {
        // Recheck current DB state after asynchronous access validation. It is
        // still possible for in-flight network work to finish after revocation;
        // fencing prevents it from mutating a reclaimed job or newer state.
        const current = await this.store.transaction(state => {
          const activeJob = state.jobs[jobId];
          const activeSub = subscription ? state.subscriptions[subscription.id] : null;
          if (activeJob?.leaseId !== job.leaseId || activeJob.state !== 'leased' || activeJob.leaseUntil <= this.clock() ||
              (subscription && !isActive(activeSub, this.clock()))) return null;
          return { subscription: activeSub };
        });
        if (!current) code = 'subscription_inactive';
        else {
          let response;
          if (subscription) {
            if (!this.protector || !this.transport) throw new BridgeError('delivery_configuration_required', 503);
            const config = this.protector.open(current.subscription.sealed, subscription.id);
            const when = this.clock();
            const secrets = [config.secret, ...(config.previous || []).filter(x => x.until > when).map(x => x.secret)];
            response = await this.transport(config.url, { body: job.body,
              headers: signedHeaders({ id: job.eventId, body: job.body, secrets, subscriptionId: subscription.id, now: when }) });
          } else {
            if (!this.fridaySender) throw new BridgeError('friday_native_contract_unverified', 503);
            response = await this.fridaySender(job);
          }
          status = response.status;
          accepted = status >= 200 && status < 300;
          retry = !accepted && transient(status);
          code = accepted ? null : retry ? 'transient_http' : 'permanent_http';
        }
      }
    } catch (error) {
      // Transport failures are retryable. Configuration, encryption and public
      // address rejection require repair and must not consume repeat requests.
      retry = ['callback_timeout', 'callback_transport_failed', 'callback_dns_failed'].includes(error?.code);
      code = retry ? 'transport_transient' : 'delivery_configuration_required';
    }
    const completedAt = this.clock();
    const saved = await this.store.transaction(state => {
      const activeJob = state.jobs[jobId];
      if (activeJob?.leaseId !== job.leaseId || activeJob.state !== 'leased') return false;
      const sub = subscription ? state.subscriptions[subscription.id] : null;
      if (subscription && !isActive(sub, completedAt)) { accepted = false; retry = false; code = 'subscription_inactive'; }
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
