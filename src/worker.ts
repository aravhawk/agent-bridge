import { randomUUID } from 'node:crypto';
import { BridgeError, DELIVERY_TRANSPORT_OUTCOME } from './policy.ts';
import { subscriptionAccessAllowed, messageAccessAllowed, testEnvelopeAllowed } from './access.ts';
import { signedHeaders } from './webhook.ts';
import { EVENTS_PEER, PEER_IDS, peerCode } from './config.ts';
import type { DenialView } from './access.ts';
import type { Protector, TransportRequest } from './webhook.ts';
import type { WebhookSend } from './webhook-sender.ts';
import type { BridgeState, Job, Millis, PolicyIds, Role, SealedCallback, Store, StoredMessage, Subscription,
  TransportOutcome } from './types.ts';

/** Adapter evidence under DELIVERY_TRANSPORT_OUTCOME (restricted adapters mark one-shot sends terminal). */
interface AdapterOutcome { terminal?: boolean; error?: string }
/** Optional native authorizer; called with the job's current owner/recipient facts. */
export type DeliveryAccessCheck = (facts: { owner: string | undefined; recipient: Role; subscriptionId: string | undefined;
  messageId: string }) => boolean | Promise<boolean>;
/** A signed-callback transport; the worker reads only the response status (webhook.ts or a terminal wrapper). */
export type DeliveryTransport = (url: string, request: TransportRequest) => Promise<{ status: number | undefined }>;
export type JobScope = (state: BridgeState, job: Job) => boolean;
export interface DeliveryWorkerOptions {
  store: Store; protector?: Protector | undefined; transport?: DeliveryTransport | undefined; webhookSender?: WebhookSend | undefined;
  accessAllowed?: DeliveryAccessCheck | undefined; policyId?: string | undefined; enabled?: boolean; clock?: () => Millis;
  maxAttempts?: number; leaseMs?: number; messagePolicyIds?: PolicyIds; deliveryUntil?: Millis;
  probeMessageId?: string | null | undefined; probeSender?: Role; jobAllowed?: JobScope | undefined;
}
export interface RunResult {
  attempted: boolean; committed?: boolean; transportAccepted?: boolean; status?: number | null; retryAt?: string | null;
}
export type EnqueueJob = (id: string, dueAt: Millis) => unknown;

const transient = (status: number) => status === 408 || status === 429 || (status >= 500 && status <= 599);
const backoff = (attempt: number) => Math.min(60000, 1000 * (2 ** Math.min(attempt - 1, 6)));

export class DeliveryWorker {
  declare store: Store; declare protector: Protector | undefined; declare transport: DeliveryTransport | undefined;
  declare webhookSender: WebhookSend | undefined; declare accessAllowed: DeliveryAccessCheck | undefined;
  declare enabled: boolean; declare clock: () => Millis; declare policyId: string | undefined;
  declare messagePolicyIds: PolicyIds; declare deliveryUntil: Millis;
  declare probeMessageId: string | null | undefined; declare probeSender: Role;
  declare maxAttempts: number; declare leaseMs: number; declare jobAllowed: JobScope | undefined;
  constructor({ store, protector, transport, webhookSender, accessAllowed, policyId, enabled = false, clock = Date.now,
    maxAttempts = 5, leaseMs = 30000, messagePolicyIds = Object.fromEntries(PEER_IDS.map(id => [id, policyId as string])), deliveryUntil = Infinity,
    probeMessageId, probeSender = EVENTS_PEER, jobAllowed }: DeliveryWorkerOptions) {
    this.store = store; this.protector = protector; this.transport = transport; this.webhookSender = webhookSender;
    this.accessAllowed = accessAllowed; this.enabled = enabled; this.clock = clock;
    this.policyId = policyId;
    this.messagePolicyIds = messagePolicyIds; this.deliveryUntil = deliveryUntil;
    this.probeMessageId = probeMessageId; this.probeSender = probeSender;
    this.maxAttempts = maxAttempts; this.leaseMs = leaseMs; this.jobAllowed = jobAllowed;
  }
  messageAllowed(state: DenialView, message: StoredMessage | undefined, now: Millis): message is StoredMessage {
    return messageAccessAllowed(state, message, this.messagePolicyIds, now) &&
      (!this.probeMessageId || testEnvelopeAllowed(message.envelope, this.probeMessageId, this.probeSender));
  }
  // A job may persist a stricter limit (one-shot work); it never raises ours.
  attemptLimit(job: Job): number {
    // Number.isSafeInteger(...) implies maxAttempts is a number.
    return Number.isSafeInteger(job?.maxAttempts) && job.maxAttempts! >= 1 ? Math.min(this.maxAttempts, job.maxAttempts!) : this.maxAttempts;
  }
  // Restricted workers leave jobs outside their scope untouched: not leased,
  // counted or marked dead, so other work keeps its own lifecycle.
  outOfScope(state: BridgeState, job: Job): boolean { return !!this.jobAllowed && !this.jobAllowed(state, job); }
  // One queue job dispatches one attempt. There is no loop, interval, timer,
  // assistant listen/inbox check, or live queue registration in this module.
  async run(jobId: string): Promise<RunResult> {
    if (!this.enabled) throw new BridgeError('delivery_not_enabled', 503);
    const now = this.clock();
    const claimed = await this.store.transaction(state => {
      const job = state.jobs[jobId];
      if (!job || ['accepted', 'dead'].includes(job.state) || job.dueAt > now ||
          (job.state === 'leased' && (job.leaseUntil as Millis) > now) || this.outOfScope(state, job)) return null;
      if (job.firstTransportOutcome?.terminal === true) {
        const status = job.firstTransportOutcome.status;
        // A null status (no response) relationally compares as 0: not accepted.
        job.state = (status as number) >= 200 && (status as number) < 300 ? 'accepted' : 'dead';
        return null; // Restore a committed one-shot result without another send.
      }
      if (job.attempts >= this.attemptLimit(job)) {
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
    let accepted = false; let retry = false; let code: string | null = 'delivery_configuration_required'; let status: number | null = null;
    let transportOutcome: AdapterOutcome | null = null, transportStarted = false;
    try {
      // The events peer uses a finite verified-token lease plus durable resource
      // denial. The webhook peer additionally requires its verified native authorizer.
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
          if (activeJob?.leaseId !== job.leaseId || activeJob!.state !== 'leased' || (activeJob!.leaseUntil as Millis) <= this.clock() ||
              this.outOfScope(state, activeJob!) ||
              this.clock() >= this.deliveryUntil || !this.messageAllowed(state, message, this.clock()) ||
              message!.envelope.to !== activeJob!.recipient || !message!.jobIds.includes(jobId) ||
              (subscription && (activeJob!.recipient !== activeSub?.recipient ||
                !subscriptionAccessAllowed(state, activeSub, this.policyId, this.clock())))) return null;
          return { subscription: activeSub, resourceDenials: state.resourceDenials, message };
        });
        if (!current) code = subscription ? 'subscription_inactive' : 'message_authorization_inactive';
        else {
          if (this.clock() >= this.deliveryUntil || !this.messageAllowed(current, current.message, this.clock())) {
            throw new BridgeError('message_authorization_inactive', 403);
          }
          let response: { status: number | undefined };
          if (subscription) {
            if (!this.protector || !this.transport) throw new BridgeError('delivery_configuration_required', 503);
            // The recheck above verified this subscription's lease; its sealed callback is present.
            const config = this.protector.open(current.subscription!.sealed!, subscription.id) as SealedCallback;
            const when = this.clock();
            if (!subscriptionAccessAllowed(current, current.subscription, this.policyId, when))
              throw new BridgeError('authorization_lease_expired', 403);
            const secrets = [config.secret, ...(config.previous || []).filter(x => x.until > when).map(x => x.secret)];
            const headers = signedHeaders({ id: job.eventId, body: job.body, secrets, subscriptionId: subscription.id, now: when });
            transportStarted = true;
            // Ordinary signed callbacks have no adapter outcome marker. Record
            // the invocation, including a timeout, without implying host wake.
            // A restricted adapter's terminal marker still takes precedence.
            transportOutcome = { terminal: false };
            response = await this.transport(config.url, { body: job.body, headers });
          } else {
            if (!this.webhookSender) throw new BridgeError(peerCode('native_contract_unverified'), 503);
            transportStarted = true;
            response = await this.webhookSender(job);
          }
          // A client response always carries an HTTP status code.
          status = response.status as number;
          transportOutcome = (response as TransportOutcome)[DELIVERY_TRANSPORT_OUTCOME] as AdapterOutcome | undefined || transportOutcome;
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
      transportOutcome = (error as TransportOutcome | null | undefined)?.[DELIVERY_TRANSPORT_OUTCOME] as AdapterOutcome | undefined || transportOutcome;
      const storageUnavailable = !transportStarted && error instanceof BridgeError && error.code === 'storage_unavailable';
      const transientError = ['callback_timeout', 'callback_transport_failed', 'callback_dns_failed'].includes((error as { code?: unknown } | null | undefined)?.code as string);
      retry = (storageUnavailable || transientError) && transportOutcome?.terminal !== true;
      code = storageUnavailable ? 'storage_unavailable' : transientError ? 'transport_transient' : 'delivery_configuration_required';
    }
    const completedAt = this.clock();
    const saved = await this.store.transaction(state => {
      const activeJob = state.jobs[jobId];
      if (activeJob?.leaseId !== job.leaseId || activeJob!.state !== 'leased' || (activeJob!.leaseUntil as Millis) <= this.clock()) return false;
      const sub = subscription ? state.subscriptions[subscription.id] : null;
      if (subscription && (activeJob.recipient !== sub?.recipient ||
          !subscriptionAccessAllowed(state, sub, this.policyId, this.clock()))) { accepted = false; retry = false; code = 'subscription_inactive'; }
      const message = state.messages[job.messageId];
      if (this.clock() >= this.deliveryUntil || !this.messageAllowed(state, message, this.clock()) ||
          message.envelope.to !== activeJob.recipient || !message.jobIds.includes(jobId) || this.outOfScope(state, activeJob)) {
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
      activeJob.state = accepted ? 'accepted' : retry && activeJob.attempts < this.attemptLimit(activeJob) ? 'pending' : 'dead';
      activeJob.lastError = code; activeJob.lastStatus = status;
      activeJob.dueAt = completedAt + backoff(activeJob.attempts);
      activeJob.leaseId = null; activeJob.leaseUntil = null;
      if (accepted) activeJob.acceptedAt = completedAt;
      return true;
    });
    return { attempted: true, committed: saved, transportAccepted: saved && accepted, status,
      retryAt: saved && retry && job.attempts < this.attemptLimit(job) ? new Date(completedAt + backoff(job.attempts)).toISOString() : null };
  }
}

// Backend outbox reconciliation only; caller binds this to its authenticated
// managed queue. Never expose it as a receiver assistant tool or polling API.
export async function reconcileOutbox(store: Store, enqueueJob: EnqueueJob, now = Date.now()): Promise<{ scheduled: number }> {
  if (typeof enqueueJob !== 'function') throw new BridgeError('queue_configuration_required', 503);
  const ids = await store.transaction(state => Object.values(state.jobs).filter(job =>
    (job.state === 'pending' && job.dueAt <= now) || (job.state === 'leased' && (job.leaseUntil as Millis) <= now))
    .map(job => ({ id: job.id, dueAt: job.dueAt })).slice(0, 100));
  for (const job of ids) await enqueueJob(job.id, job.dueAt);
  return { scheduled: ids.length };
}

// Scheduled-tick catch-up: re-offer overdue outbox work to the native queue.
// Unlike reconcileOutbox above (kept unchanged for its existing callers):
// - eligibility: a pending job only after `pendingGraceMs` past its due time
//   (its own dispatch normally publishes it), an expired lease at once;
// - fairness: each offered job records `reofferedAt` durably, and jobs are
//   taken least-recently-offered first, so a backlog larger than `limit` is
//   worked through in rotation (every job within ceil(n / limit) runs), never
//   the same first `limit` forever;
// - priority only within a rotation round, from durable data only (never
//   request input): ACKs, then direct messages (WAKE), then SYNC batch
//   deliveries. Rotation comes first, so a job offered in an earlier round
//   waits behind jobs not yet offered, whatever their class; the bound is
//   fairness (every overdue job within ceil(n / limit) runs), not strict
//   priority. Immediate WAKE/ACK dispatch at send/completion is separate and
//   never waits for this backstop;
// - isolation: one job's publication failure does not stop the others; it is
//   counted, rotated to the back, and retried on a later run.
// Publication only enqueues the job ID: the worker's own leases, fencing and
// idempotence decide what is sent.
const jobPriority = (state: BridgeState, job: Job): number => {
  const message = state.messages[job.messageId];
  return message?.envelope?.kind === 'ack' ? 0 : message?.syncBatch ? 2 : 1;
};
export async function reofferOverdueJobs(store: Store, enqueueJob: EnqueueJob, now: Millis,
  { pendingGraceMs = 0, limit = 100 }: { pendingGraceMs?: number; limit?: number } = {}): Promise<{ scheduled: number; failed: number; deferred: number }> {
  if (typeof enqueueJob !== 'function') throw new BridgeError('queue_configuration_required', 503);
  const { picked, eligible } = await store.transaction(state => {
    const due = Object.values(state.jobs).filter(job => (job.state === 'pending' && job.dueAt <= now - pendingGraceMs) ||
      (job.state === 'leased' && (job.leaseUntil as Millis) <= now));
    due.sort((a, b) => (a.reofferedAt ?? 0) - (b.reofferedAt ?? 0) || jobPriority(state, a) - jobPriority(state, b) ||
      a.dueAt - b.dueAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return { picked: due.slice(0, limit).map(job => ({ id: job.id, dueAt: job.dueAt })), eligible: due.length };
  });
  let scheduled = 0, failed = 0;
  for (const job of picked) {
    try { await enqueueJob(job.id, job.dueAt); scheduled++; } catch { failed++; }
  }
  if (picked.length) {
    await store.transaction(state => { for (const { id } of picked) if (state.jobs[id]) state.jobs[id].reofferedAt = now; });
  }
  return { scheduled, failed, deferred: eligible - picked.length };
}
