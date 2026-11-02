import { dailyMessage, validateMessage, retainMessages, reserveMessage, checkMessageCapacity, MESSAGE_PROTOCOL, MESSAGE_TTL_MS } from './messages.ts';
import { randomUUID } from 'node:crypto';
import { BridgeError, validateEnvelope, SCOPES } from './policy.ts';
import { appendDeliveryJobs, authorizeRecipient, hasDeliveryDestination, ownKeys } from './events.ts';
import { verifiedMessageAuthorization, messageAccessAllowed, subscriptionAccessAllowed, testEnvelopeAllowed } from './access.ts';
import { diagnosticReadCandidate, diagnosticReadStatus, observeDiagnosticRead,
  canaryReadCandidate, canaryReadStatus, observeCanaryRead } from './observability.ts';
import { canaryEnvelope, reserveCanary, canaryReceipt } from './canary.ts';
import { EVENTS_PEER, NAMES } from './config.ts';
import { classify, enqueueSync, supersedeBySubject, cutBatch, presentBatch, batchEnvelopeView, ackBatch, batchOutcome, outstandingBatches, flushDue, markDispatched,
  reconcileSync, syncItemClaimRedirect, batchItemsBusy, stampAdmission, attachRoom, MAX_SYNC_BATCH_IDS } from './sync.ts';
import type { BridgeErrorDetails } from './policy.ts';
import type { ActiveSubscription } from './access.ts';
import type { JobOptions } from './events.ts';
import type { CanaryConfig } from './canary.ts';
import type { FlushResult, SyncClassification, SyncItemDisposition } from './sync.ts';
import type { BridgeState, CanaryReservation, Envelope, FirstTransportOutcome, JobState, MessageAuthorization, Millis, PolicyIds, Principal,
  Role, Store, StoredMessage, SyncBatchOutcome } from './types.ts';

/** Message tool input as read before validation: optional-chained reads only (any value is safe there). */
type MessageInput = { readonly kind?: unknown; readonly id?: string | { toLowerCase?: () => string };
  readonly sentAt?: unknown } | null | undefined;
/** The recipient rollout: the enabled recipients, or the parsed BRIDGE_WAKE_SYNC_RECIPIENTS status. */
export interface SyncConfiguration { valid: boolean; recipients: string[] }
/** Present only for a wake/sync-enabled recipient. */
export type Routing = SyncClassification & { policyIds: PolicyIds | undefined };
export type BatchPresentation = NonNullable<ReturnType<typeof presentBatch>>;
/** A send/stage outcome; the optional fields depend on routing and replay. */
export interface SendResult {
  messageId: string; queued: boolean; duplicate: boolean; jobIds: string[]; expired?: boolean;
  class?: 'wake' | 'sync'; promoted?: string; delivery?: 'batched' | 'immediate'; piggybackedSyncItems?: number;
}
export interface ReadResult {
  envelope: Envelope; authority?: string; expired?: boolean; receivedAt: string; syncBatches?: BatchPresentation[];
  syncBatchOutcome?: SyncBatchOutcome;
}
/** A claim (claimId, leaseUntil and held batches) or the recorded completion of a replay. */
export interface ClaimResult {
  claimId?: string; leaseUntil?: string; completed: boolean; duplicate?: boolean; ackMessageId?: string | null | undefined;
  syncBatchIds?: string[]; syncBatchesHeldElsewhere?: string[]; syncBatchesDeferred?: string[]; syncBatchesInactive?: string[];
}
/** The additive wake/sync status fields (syncStatus below). */
type SyncStatusView = ReturnType<typeof syncStatus>;
/** One delivery job as bridge_status reports it. */
export interface DeliveryStatus {
  eventId: string; state: JobState; attempts: number; transportAttempts: number | null;
  firstTransportOutcome: FirstTransportOutcome | null; lastStatus: number | null; lastError: string | null;
}
/** bridge_status: a stored message's delivery/receipt view, or the diagnostic read view of an unstored probe. */
export interface StatusResult {
  messageId: string; deliveries?: DeliveryStatus[]; receiptCompleted?: boolean; ackMessageId?: string | null;
  batchAckMessageId?: string | null; evidenceStatus?: string; wakeVerified?: boolean; canary?: unknown;
  messageStored?: boolean; readObservations?: Record<string, unknown>[]; sync?: SyncStatusView['sync']; syncBatch?: SyncStatusView['syncBatch'];
  piggybackedBatchIds?: string[];
  syncBatchOutcome?: SyncBatchOutcome;
  syncBatchOutcomes?: SyncBatchOutcome[];
}
export interface BatchAck { batchMessageId: string; ackMessageId: string | null }
export interface CompleteResult {
  completed: boolean; duplicate: boolean; ackMessageId: string | null | undefined; jobIds?: string[]; evidenceStatus: string;
  syncBatchesAcked?: string[]; syncBatchAcks?: BatchAck[];
  syncBatchOutcomes?: SyncBatchOutcome[];
}
export type AttachmentAdmission = (state: BridgeState, envelope: Envelope, principal: Principal, now: Millis) => void;
export interface BridgeOptions {
  store: Store; clock?: () => Millis; probeMessageId?: string | null | undefined; probeSender?: Role;
  messagePolicyIds?: PolicyIds | undefined; deliveryUntil?: Millis; dailyEnabled?: boolean;
  prepareMessage?: ((messageId: string) => Promise<unknown>) | undefined;
  prepareReceipt?: ((messageId: string) => Promise<unknown>) | undefined;
  canary?: CanaryConfig | undefined;
  wakeSync?: (() => string[] | { valid?: unknown; recipients?: unknown } | null | undefined) | undefined;
  admitAttachments?: AttachmentAdmission | undefined;
}

// Explicitly typed so bare fail(...)/conflict(...) statements narrow control flow.
const fail: (code: string, status?: number) => never = (code, status = 400) => { throw new BridgeError(code, status); };
// A conflict that names the IDs to use instead (batch or blocking items only).
const conflict: (code: string, details: BridgeErrorDetails | undefined) => never = (code, details) => { throw new BridgeError(code, 409, details); };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function messageId(value: unknown): asserts value is string { if (typeof value !== 'string' || !uuid.test(value)) fail('invalid_message_id'); }
function admitMessage(state: BridgeState, role: Role, now: Millis): void {
  // The verifier binds each of the two sender roles to its pinned identity.
  // Fixed role slots avoid caller-chosen bucket keys or unbounded limiter state.
  // This runs under the same durable row lock as message/job creation, so cold
  // starts and concurrent function instances cannot each grant a fresh budget.
  const admissions = state.probeAdmissions ||= {};
  const recent = (admissions[role] || []).filter(at => at > now - 60000);
  if (recent.length >= 10) fail('message_rate_limited', 429);
  admissions[role] = [...recent, now];
}
function incoming(state: BridgeState, principal: Principal, id: unknown, probeMessageId: string | null | undefined,
  probeSender: Role): StoredMessage {
  authorizeRecipient(principal); messageId(id);
  const message = state.messages[id];
  if (!message || message.envelope.to !== principal.role) fail('message_not_found', 404);
  if (probeMessageId && !testEnvelopeAllowed(message.envelope, probeMessageId, probeSender)) fail('contract_probe_only', 403);
  return message;
}
function requireAckPath(state: BridgeState, envelope: Envelope, authorization: MessageAuthorization | undefined,
  policyIds: PolicyIds | null | undefined, now: Millis, subscriptionId?: string): void {
  if (!dailyMessage(envelope) || envelope.kind === 'ack' || envelope.from !== EVENTS_PEER) return;
  // The webhook peer must not handle a source whose required ACK has no usable return
  // path. Cover its entire immutable authority lifetime, not just this instant.
  // Revocation/shortening during handling still fails closed at completion.
  // A pinned subscriptionId (canary) admits only that exact return path.
  if (!Object.values(state.subscriptions).some(sub => sub.owner === authorization?.owner &&
      (!subscriptionId || sub.id === subscriptionId) &&
      subscriptionAccessAllowed(state, sub, policyIds?.[EVENTS_PEER], now) &&
      // A matching owner (a hash) implies the authorization is present.
      sub.expiresAt >= authorization!.expiresAt)) fail('return_subscription_required', 503);
}
// A batch ACK must reach the events peer for at least this long (or until the
// batch itself ends, if sooner).
export const BATCH_ACK_MIN_WINDOW_MS = 5 * 60000;
// Latest time a batch's ACK can be delivered, or null when it has no usable
// return path. A batch is a synthetic message whose 12 h authority is derived
// from its items; it is not a sender's token, so (unlike requireAckPath for a
// real message) the return subscription is not required to cover it. The ACK
// itself is a normal one-hour, token-bound message: it lives until the
// earliest of the batch's expiry, one hour, and (toward the events peer) the
// latest active return subscription of the batch's owner, which must leave at
// least BATCH_ACK_MIN_WINDOW_MS after `margin` (or reach the batch's expiry).
// The completing principal's token bounds it further at creation. Nothing
// here grants authority: the window only ever shortens the ACK.
function batchAckWindow(state: BridgeState, batch: StoredMessage, policyIds: PolicyIds | null | undefined, now: Millis, margin = 0): Millis | null {
  const e = batch.envelope, expires = Date.parse(e.expiresAt as string);
  let until = Math.min(expires, now + MESSAGE_TTL_MS);
  if (e.from === EVENTS_PEER) {
    const best = Math.max(-Infinity, ...Object.values(state.subscriptions).filter((sub): sub is ActiveSubscription => sub.owner === batch.authorization?.owner &&
      subscriptionAccessAllowed(state, sub, policyIds?.[EVENTS_PEER], now)).map(sub => sub.expiresAt));
    if (!(best >= Math.min(expires, now + margin + BATCH_ACK_MIN_WINDOW_MS))) return null;
    until = Math.min(until, best);
  }
  return until > now ? until : null;
}
function requireBatchAckPath(state: BridgeState, batch: StoredMessage, policyIds: PolicyIds | null | undefined, now: Millis,
  margin: number): Millis {
  return batchAckWindow(state, batch, policyIds, now, margin) ?? fail('return_subscription_required', 503);
}
// Only a non-empty batch is acknowledged with an ACK message.
const batchHasItems = (state: BridgeState, batch: StoredMessage): boolean => batch.syncBatch!.itemIds.some(id => state.messages[id]);
// routing is present only for a wake/sync-enabled recipient: { class, promoted?, policyIds }.
function insert(state: BridgeState, envelope: Envelope, hash: string, now: Millis, authorization: MessageAuthorization | undefined,
  jobOptions?: JobOptions, routing?: Routing): SendResult {
  const saved = state.messages[envelope.id];
  if (saved && saved.hash !== hash) fail('message_id_conflict', 409);
  if (saved) return { messageId: envelope.id, queued: true, duplicate: true, jobIds: saved.jobIds };
  if (envelope.kind === 'ack') {
    const probe = state.messages[envelope.correlationId as string]?.envelope;
    if (!probe || probe.kind === 'ack' || (dailyMessage(envelope) !== dailyMessage(probe)) ||
        (dailyMessage(envelope) && (probe.threadId !== envelope.threadId || probe.route !== envelope.route)) || probe.from !== envelope.to || probe.to !== envelope.from) fail('invalid_correlation', 409);
  }
  const retainUntil = dailyMessage(envelope) ? reserveMessage(state, envelope, hash, now) : undefined;
  const queued = routing?.class === 'sync';
  // SYNC data waits for a batch, but still needs a recipient that can be woken.
  const jobIds = queued ? [] : appendDeliveryJobs(state, envelope, now, jobOptions);
  if (envelope.to === EVENTS_PEER && !(queued ? hasDeliveryDestination(state, envelope, now) : jobIds.length)) {
    fail('recipient_subscription_required', 503);
  }
  // Only an exact replay (returned above) arrives without a fresh authorization.
  const message = state.messages[envelope.id] = { envelope, hash, storedAt: now, jobIds, authorization: authorization!, ...(retainUntil ? { retainUntil } : {}) };
  if (!routing) return { messageId: envelope.id, queued: true, duplicate: false, jobIds };
  const routed = { class: routing.class, ...(routing.promoted ? { promoted: routing.promoted } : {}) };
  if (queued || envelope.subject !== undefined) stampAdmission(state, message);
  if (queued) {
    enqueueSync(state, message, now);
    return { messageId: envelope.id, queued: true, duplicate: false, jobIds, ...routed, delivery: 'batched' };
  }
  // Piggyback: pending SYNC data rides with this WAKE (no extra wake).
  supersedeBySubject(state, envelope, now);
  const batch = cutBatch(state, envelope.to, now, { reason: 'wake', policyIds: routing.policyIds });
  if (batch) Object.assign(message, { syncBatchIds: [batch.envelope.id] });
  return { messageId: envelope.id, queued: true, duplicate: false, jobIds, ...routed, delivery: 'immediate',
    ...(batch ? { piggybackedSyncItems: batch.syncBatch.itemIds.length } : {}) };
}

// Shared batch fence. A batch's own receipt is its only claim record, whether
// it is handled directly (claiming the batch) or with the message it was
// presented with (claiming that message). Claiming a message therefore also
// claims, with the same claimId and lease, each attached batch that was
// presented, is unacknowledged and is not held by another live claim; a batch
// held elsewhere is reported and excluded, and a direct claim of a batch held
// this way fails with receipt_busy. Messages without attached batches return
// nothing new.
function claimAttachedBatches(state: BridgeState, message: StoredMessage, principal: Principal, claimId: string, leaseUntil: Millis,
  now: Millis, policyIds: PolicyIds | null | undefined) {
  // An ACK is terminal: it never carries or collects SYNC data.
  if (!message.syncBatchIds?.length || message.envelope.kind === 'ack') return {};
  // A claim holds no more than one completion can acknowledge (its own ID
  // counts when the message is a batch). Further attached batches, possible
  // only in state written before this limit, are deferred: not held, so they
  // stay claimable directly and are replayed by bridge_inbox_read.
  const limit = MAX_SYNC_BATCH_IDS - (message.syncBatch ? 1 : 0);
  const held: string[] = [], heldElsewhere: string[] = [], deferred: string[] = [], inactive: string[] = [];
  for (const id of message.syncBatchIds) {
    const b = state.messages[id]?.syncBatch, receipt = state.receipts[id];
    if (!b?.presentedAt || b.ackedAt || b.reclaimedAt || receipt?.state === 'complete') continue;
    // Each batch is judged on its own current authority (policy, durable
    // denial, expiry), not the carrier's: a batch whose admission was
    // withdrawn is never held, so it is never ACKed through a fresh carrier.
    if (!messageAccessAllowed(state, state.messages[id], policyIds, now)) { inactive.push(id); continue; }
    // Held by another claim of the batch, or one of its items still has a
    // live independent claim (pre-fence): not this claim's to handle.
    if ((receipt?.leaseUntil as Millis) > now || batchItemsBusy(state, state.messages[id], claimId, now).length) { heldElsewhere.push(id); continue; }
    // Over the completion limit, or no usable return path for its own ACK
    // (it can still be claimed directly once one exists): not held.
    if (held.length >= limit || batchAckWindow(state, state.messages[id]!, policyIds, now, leaseUntil - now) === null) {
      deferred.push(id); continue;
    }
    state.receipts[id] = { state: 'claimed', owner: principal.principalKey, claimId, leaseUntil, viaMessage: message.envelope.id };
    held.push(id);
  }
  return { syncBatchIds: held, syncBatchesHeldElsewhere: heldElsewhere, ...(deferred.length ? { syncBatchesDeferred: deferred } : {}),
    ...(inactive.length ? { syncBatchesInactive: inactive } : {}) };
}

// Additive status for wake/sync messages only; v1 messages report nothing new.
function syncStatus(message: StoredMessage) {
  const s = message.sync, b = message.syncBatch;
  return { ...(s ? { sync: { class: 'sync', state: s.state, ...(s.deliveredAt ? { via: s.via,
    deliveredAt: new Date(s.deliveredAt).toISOString() } : {}), ...(s.batchId ? { batchMessageId: s.batchId } : {}),
    ...(s.redeliveries ? { redeliveries: s.redeliveries } : {}), ...(s.supersededBy ? { supersededBy: s.supersededBy } : {}) } } : {}),
    ...(b ? { syncBatch: { reason: b.reason, ...(b.trigger ? { trigger: b.trigger } : {}), itemCount: b.itemIds.length,
      presented: !!b.presentedAt, acknowledged: !!b.ackedAt, reclaimed: !!b.reclaimedAt,
      ...(b.recovery ? { recovery: { generation: b.recovery.generation, nextAt: new Date(b.recovery.nextAt).toISOString() } } : {}),
      ...(b.rehomedTo ? { rehomedTo: b.rehomedTo } : {}) } } : {}),
    ...(message.syncBatchIds ? { piggybackedBatchIds: [...message.syncBatchIds] } : {}) };
}

export class Bridge {
  declare admitAttachments: AttachmentAdmission | undefined; declare prepareMessage: BridgeOptions['prepareMessage'];
  declare prepareReceipt: BridgeOptions['prepareReceipt']; declare canary: CanaryConfig | undefined;
  declare wakeSync: BridgeOptions['wakeSync']; declare store: Store; declare clock: () => Millis; declare dailyEnabled: boolean;
  declare probeMessageId: string | null | undefined; declare probeSender: Role; declare messagePolicyIds: PolicyIds | undefined;
  declare deliveryUntil: Millis;
  // canary: trusted fixed configuration (canary.ts). When present this
  // instance admits only that one source and its server-created ACK.
  // wakeSync: trusted function returning either the recipients with wake/sync
  // enabled or the parsed rollout status (BRIDGE_WAKE_SYNC_RECIPIENTS, read per
  // use). Omitted or empty: v1 behavior. Invalid status is v1 for ordinary
  // traffic but fails scheduled flushes closed so it cannot trigger rollback.
  // admitAttachments: trusted (state, envelope, principal, now) check for
  // messages carrying attachmentIds; absent means attachments are disabled.
  constructor({ store, clock = Date.now, probeMessageId, probeSender = EVENTS_PEER, messagePolicyIds, deliveryUntil = Infinity, dailyEnabled = false, prepareMessage, prepareReceipt, canary, wakeSync, admitAttachments }: BridgeOptions) {
    this.admitAttachments = admitAttachments;
    this.prepareMessage = prepareMessage; this.prepareReceipt = prepareReceipt; this.canary = canary; this.wakeSync = wakeSync;
    this.store = store; this.clock = clock; this.dailyEnabled = dailyEnabled; this.probeMessageId = probeMessageId;
    this.probeSender = probeSender;
    this.messagePolicyIds = messagePolicyIds; this.deliveryUntil = deliveryUntil;
  }
  // Checked in the preparation and the final insertion transaction, before
  // any queue publication and again before the message is stored.
  attachmentAdmission(state: BridgeState, envelope: Envelope, principal: Principal, now: Millis): void {
    if (!envelope.attachmentIds) return;
    if (this.canary || this.probeMessageId || typeof this.admitAttachments !== 'function') fail('attachments_not_enabled', 503);
    this.admitAttachments(state, envelope, principal, now);
  }
  syncConfiguration(): SyncConfiguration {
    if (this.canary || this.probeMessageId || typeof this.wakeSync !== 'function') return { valid: true, recipients: [] };
    const configured = this.wakeSync();
    if (Array.isArray(configured)) return { valid: true, recipients: configured };
    if (configured && typeof configured.valid === 'boolean' && Array.isArray(configured.recipients)) return configured as SyncConfiguration;
    return { valid: false, recipients: [] };
  }
  syncEnabled(role: Role): boolean {
    const config = this.syncConfiguration();
    return config.valid && config.recipients.includes(role);
  }
  // One correlated ACK for a handled source (a direct message or a batch),
  // inserted with its delivery jobs in the caller's transaction. `until`
  // (batches) caps its lifetime to the usable return window.
  createAck(state: BridgeState, principal: Principal, original: Envelope, now: Millis, until?: Millis | null):
    { ackMessageId: string; jobIds: string[] } {
    const ackMessageId = randomUUID();
    const { envelope, hash } = dailyMessage(original) ? validateMessage({ protocol: MESSAGE_PROTOCOL,
      id: ackMessageId, from: principal.role, to: original.from, kind: 'ack', sentAt: new Date(now).toISOString(),
      expiresAt: new Date(Math.min(Date.parse(original.expiresAt), now + MESSAGE_TTL_MS, until ?? Infinity)).toISOString(),
      threadId: original.threadId, route: original.route, correlationId: original.id }, principal, now)
      : validateEnvelope({ id: ackMessageId, testId: original.testId,
        from: principal.role, to: original.from, kind: 'ack', sentAt: new Date(now).toISOString(),
        correlationId: original.id, marker: original.marker }, principal, now);
    // The canary ACK targets only the pinned return subscription, one attempt.
    const { jobIds } = insert(state, envelope, hash, now, verifiedMessageAuthorization(principal, envelope, now, this.deliveryUntil),
      this.canary ? { subscriptionId: this.canary.subscriptionId, maxAttempts: 1 } : undefined);
    // reserveCanary created the reservation when the canary source was sent.
    if (this.canary) (state[NAMES.canaryState] as CanaryReservation).ackMessageId = ackMessageId;
    return { ackMessageId, jobIds };
  }
  routing(envelope: Envelope, now: Millis): Routing | undefined {
    if (envelope.kind === 'ack' || !this.syncEnabled(envelope.to)) return undefined;
    return { ...classify(envelope, now), policyIds: this.messagePolicyIds };
  }
  async send(principal: Principal, input: unknown): Promise<SendResult> {
    // ACK is only emitted by the atomic completion operation, never separately.
    if ((input as MessageInput)?.kind !== 'probe') fail('use_receipt_complete_for_ack');
    return this.store.transaction(state => {
      // A replay of an already committed ID remains idempotent after downtime.
      // Only an exact canonical match skips the freshness rule; changed content
      // still conflicts, and a new stale ID is rejected.
      // A probe kind implies a non-nullish input.
      const saved = typeof (input as NonNullable<MessageInput>).id === 'string' && state.messages[((input as NonNullable<MessageInput>).id as string).toLowerCase()];
      const { envelope, hash } = validateEnvelope(input, principal, saved ? Date.parse((input as NonNullable<MessageInput>).sentAt as string) : this.clock());
      if (this.probeMessageId && !testEnvelopeAllowed(envelope, this.probeMessageId, this.probeSender)) fail('contract_probe_only', 403);
      const authorization = saved ? undefined : verifiedMessageAuthorization(principal, envelope, this.clock(), this.deliveryUntil);
      // Exact retransmissions stay idempotent even at the limit or after the
      // freshness window; changed bodies still take insert's conflict path.
      // Failed insertion rolls this admission back with the transaction.
      if (!saved) admitMessage(state, principal.role, this.clock());
      return insert(state, envelope, hash, this.clock(), authorization);
    });
  }
  async prepareMessageSend(principal: Principal, input: unknown): Promise<void> {
    if (!this.dailyEnabled) fail('daily_messages_not_enabled', 503);
    if ((input as MessageInput)?.kind === 'ack') fail('use_receipt_complete_for_ack');
    // Reserve native backend work BEFORE creating any content. If publishing
    // fails, no new message is saved. The queued dispatcher tolerates an early
    // callback and a failed DB commit without waking a recipient for absent data.
    const preparation = await this.store.transaction(state => {
      retainMessages(state, this.clock());
      // A missing ID reads the key 'undefined', which never holds a message.
      const prior = state.messages[(input as MessageInput)?.id?.toLowerCase?.() as string] || state.messageIds?.[(input as MessageInput)?.id?.toLowerCase?.() as string];
      const validated = validateMessage(input, principal, prior ? Date.parse((input as NonNullable<MessageInput>).sentAt as string) : this.clock());
      if (prior?.hash !== undefined && prior.hash !== validated.hash) fail('message_id_conflict', 409);
      if (this.canary) canaryEnvelope(validated.envelope, this.canary);
      if (!prior) {
        const authorization = verifiedMessageAuthorization(principal, validated.envelope, this.clock(), this.deliveryUntil);
        requireAckPath(state, validated.envelope, authorization, this.messagePolicyIds, this.clock(), this.canary?.subscriptionId);
        this.attachmentAdmission(state, validated.envelope, principal, this.clock());
        checkMessageCapacity(state);
        const now = this.clock();
        state.messagePreparations ||= {};
        for (const [id, entry] of Object.entries(state.messagePreparations)) if (entry.until <= now) delete state.messagePreparations[id];
        const pending = state.messagePreparations[validated.envelope.id];
        if (pending && pending.hash !== validated.hash) fail('message_id_conflict', 409);
        if (!pending) {
          admitMessage(state, principal.role, now); // Bound native queue publication too.
          state.messagePreparations[validated.envelope.id] = { hash: validated.hash, until: now + 60000 };
        }
      }
      // Durable lifetime reservation commits after every check, before publishing.
      if (this.canary) reserveCanary(state, this.canary, principal, validated.hash, !!prior, this.clock());
      return { id: validated.envelope.id, fresh: !prior };
    });
    if (preparation.fresh && this.prepareMessage) await this.prepareMessage(preparation.id);
  }
  // Synchronous final insertion shared by ordinary v1 sends and the disabled
  // task prototype. Call only after prepareMessageSend has successfully prearmed.
  stageMessage(state: BridgeState, principal: Principal, input: unknown): SendResult {
    if (!this.dailyEnabled) fail('daily_messages_not_enabled', 503);
    if ((input as MessageInput)?.kind === 'ack') fail('use_receipt_complete_for_ack');
    const now = this.clock(); retainMessages(state, now);
    const id = typeof (input as MessageInput)?.id === 'string' ? ((input as NonNullable<MessageInput>).id as string).toLowerCase() : '';
    const prior = state.messages[id] || state.messageIds?.[id];
    const { envelope, hash } = validateMessage(input, principal, prior ? Date.parse((input as NonNullable<MessageInput>).sentAt as string) : now);
    if (prior && prior.hash !== hash) fail('message_id_conflict', 409);
    if (this.canary) { canaryEnvelope(envelope, this.canary); reserveCanary(state, this.canary, principal, hash, !!prior, now); }
    if (prior) return state.messages[id]
      ? { messageId: id, queued: true, duplicate: true, jobIds: state.messages[id]!.jobIds }
      : { messageId: id, queued: false, duplicate: true, expired: true, jobIds: [] };
    if (Date.parse(envelope.expiresAt) <= now) fail('message_expired', 403);
    const authorization = verifiedMessageAuthorization(principal, envelope, now, this.deliveryUntil);
    requireAckPath(state, envelope, authorization, this.messagePolicyIds, now, this.canary?.subscriptionId);
    this.attachmentAdmission(state, envelope, principal, now);
    delete state.messagePreparations?.[envelope.id];
    return insert(state, envelope, hash, now, authorization, this.canary ? { maxAttempts: 1 } : undefined, this.routing(envelope, now));
  }
  async sendMessage(principal: Principal, input: unknown): Promise<SendResult> {
    await this.prepareMessageSend(principal, input);
    return this.store.transaction(state => this.stageMessage(state, principal, input));
  }
  async read(principal: Principal, params: unknown): Promise<ReadResult> {
    ownKeys(params, ['messageId']);
    let candidate = false, canary = false, output: ReadResult;
    try { output = await this.store.transaction(state => {
      const now = this.clock();
      retainMessages(state, now);
      candidate = diagnosticReadCandidate(state, principal, params.messageId, now);
      canary = canaryReadCandidate(state, principal, params.messageId, now);
      const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender);
      const syncBatches = this.syncBatches(state, message, principal.role, now);
      return { envelope: batchEnvelopeView(message), ...(dailyMessage(message.envelope) ? { authority: 'peer_data_requires_user_workflow',
        expired: Date.parse(message.envelope.expiresAt) <= this.clock() } : {}), receivedAt: new Date(message.storedAt).toISOString(),
        ...(syncBatches.length ? { syncBatches } : {}),
        ...(message.syncBatchOutcome ? { syncBatchOutcome: structuredClone(message.syncBatchOutcome) } : {}) };
    }); } catch (error) {
      if (candidate) await observeDiagnosticRead({ store: this.store, principal, messageId: params.messageId as string, error, failed: true, clock: this.clock });
      if (canary) await observeCanaryRead({ store: this.store, principal, messageId: params.messageId as string, error, failed: true, clock: this.clock });
      throw error;
    }
    if (candidate) await observeDiagnosticRead({ store: this.store, principal, messageId: params.messageId as string, clock: this.clock });
    if (canary) await observeCanaryRead({ store: this.store, principal, messageId: params.messageId as string, clock: this.clock });
    return output;
  }
  // Batches presented with a read message: its own items when it is a batch,
  // then those piggybacked on it. While the message is not yet completed, an
  // enabled recipient's read also drains pending SYNC data into a new batch
  // attached to it, so a re-read (e.g. after a lost response) is identical and
  // completing the message acknowledges what was presented with it.
  syncBatches(state: BridgeState, message: StoredMessage, role: Role, now: Millis): BatchPresentation[] {
    // An ACK is terminal: reading it never collects or presents SYNC data, so
    // handling an ACK can never lead to another (batch) ACK.
    if (!dailyMessage(message.envelope) || message.envelope.kind === 'ack' ||
        !messageAccessAllowed(state, message, this.messagePolicyIds, now)) return [];
    // Collect only while the message can still be completed in one call.
    if (this.syncEnabled(role) && state.receipts[message.envelope.id]?.state !== 'complete' && attachRoom(state, message) > 0) {
      const batch = cutBatch(state, role, now, { reason: 'read', policyIds: this.messagePolicyIds });
      if (batch) (message.syncBatchIds ||= []).push(batch.envelope.id);
    }
    return [...(message.syncBatch ? [message.envelope.id] : []), ...(message.syncBatchIds || [])]
      .map(id => presentBatch(state, id, now)).filter(Boolean) as BatchPresentation[];
  }
  // Start-of-turn inbox read for an enabled recipient. Returns every delivered
  // but unacknowledged batch (replayed until acknowledged, so a lost response or
  // crash loses nothing) plus any pending SYNC data cut into one new delta batch.
  // Reads serialize on the store lock: concurrent readers get the same batches.
  async inboxRead(principal: Principal, params: unknown = {}) {
    authorizeRecipient(principal); ownKeys(params, [], []);
    if (!this.syncEnabled(principal.role)) fail('wake_sync_not_enabled', 503);
    return this.store.transaction(state => {
      const now = this.clock(); retainMessages(state, now);
      cutBatch(state, principal.role, now, { reason: 'inbox', policyIds: this.messagePolicyIds });
      return { syncBatches: outstandingBatches(state, principal.role, now).map(id => presentBatch(state, id, now)) };
    });
  }
  // Scheduled flush (trigger route): see flushDue. Returns message IDs still to be
  // published for dispatch.
  async flushSync(): Promise<FlushResult> {
    const initial = this.syncConfiguration();
    if (!initial.valid) fail('wake_sync_configuration_invalid', 503);
    return this.store.transaction(state => {
      // Configuration can change while this call waits for the storage lock.
      // Judge rollout and rollback at the same locked boundary as the mutation.
      const config = this.syncConfiguration();
      if (!config.valid) fail('wake_sync_configuration_invalid', 503);
      const now = this.clock(); retainMessages(state, now);
      return flushDue(state, now, { policyIds: this.messagePolicyIds, recipients: config.recipients });
    });
  }
  async markSyncDispatched(ids: readonly string[]): Promise<void> {
    return this.store.transaction(state => { markDispatched(state, ids); });
  }
  async claim(principal: Principal, params: unknown): Promise<ClaimResult> {
    ownKeys(params, ['messageId']);
    return this.store.transaction(state => {
      const now = this.clock();
      retainMessages(state, this.clock());
      const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender);
      if (this.canary) canaryReceipt(state, this.canary, principal, params.messageId as string);
      const old = state.receipts[params.messageId as string];
      if (old?.state === 'complete') return { duplicate: true, completed: true, ackMessageId: old.ackMessageId };
      // Item vs batch fence: a queued or batch-carried SYNC item is handled only
      // through its batch, so its own claim is refused with the batch to use.
      if (message.sync) {
        reconcileSync(state, message.envelope.to, this.messagePolicyIds, now);
        const redirect = syncItemClaimRedirect(state, message);
        if (redirect) conflict(redirect.code, redirect.details);
      }
      if (!messageAccessAllowed(state, message, this.messagePolicyIds, now)) fail('message_authorization_inactive', 403);
      const leaseMs = 60000;
      // A batch's ACK needs a return window that outlasts this lease; a real
      // message keeps the v1 rule (the return path covers its authority).
      if (message.syncBatch) requireBatchAckPath(state, message, this.messagePolicyIds, now, leaseMs);
      else requireAckPath(state, message.envelope, message.authorization, this.messagePolicyIds, now, this.canary?.subscriptionId);
      if ((old?.leaseUntil as Millis) > now) fail('receipt_busy', 409);
      if (message.syncBatch) {
        const busy = batchItemsBusy(state, message, null, now);
        if (busy.length) conflict('sync_batch_item_busy', { itemIds: busy });
      }
      const claimId = randomUUID(), leaseUntil = now + leaseMs;
      state.receipts[params.messageId as string] = { state: 'claimed', owner: principal.principalKey,
        claimId, leaseUntil };
      const batches = claimAttachedBatches(state, message, principal, claimId, leaseUntil, now, this.messagePolicyIds);
      return { claimId, leaseUntil: new Date(leaseUntil).toISOString(), completed: false, ...batches };
    });
  }
  // An ACK means the receiver reports it handled the received data (read it
  // and ran its own workflow on it). It is not completion of any task the data
  // asks for, and the hosted IDs are not independent host verification.
  async complete(principal: Principal, params: unknown): Promise<CompleteResult> {
    ownKeys(params, ['messageId', 'claimId', 'hostedEventId', 'hostedTurnId', 'syncBatchIds', 'syncItemDispositions'],
      ['messageId', 'claimId', 'hostedEventId', 'hostedTurnId']);
    // Optional: the batch IDs this receiver saw with the message (from its own
    // read) and has handled. Only these are acknowledged; omitted means none.
    // Validated just below (invalid_params) before any use.
    const ackIds = (params.syncBatchIds ?? []) as string[];
    if (!Array.isArray(ackIds) || ackIds.length > MAX_SYNC_BATCH_IDS || new Set(ackIds).size !== ackIds.length ||
        ackIds.some(id => typeof id !== 'string' || !uuid.test(id))) fail('invalid_params');
    const rawDispositions = params.syncItemDispositions === undefined ? [] : params.syncItemDispositions;
    if (!Array.isArray(rawDispositions) || rawDispositions.length > 100) fail('invalid_params');
    for (const item of rawDispositions) {
      ownKeys(item, ['batchMessageId', 'messageId', 'disposition', 'handledAt'], ['batchMessageId', 'messageId', 'disposition']);
      if (typeof item.batchMessageId !== 'string' || !uuid.test(item.batchMessageId) || typeof item.messageId !== 'string' || !uuid.test(item.messageId) ||
        !['handled', 'skipped_expired'].includes(item.disposition as string)) fail('invalid_params');
      if (item.disposition === 'handled' ? typeof item.handledAt !== 'string' || !Number.isFinite(Date.parse(item.handledAt)) ||
        new Date(item.handledAt).toISOString() !== item.handledAt : item.handledAt !== undefined) fail('invalid_params');
    }
    // The bounded structural checks above narrow this untrusted optional input.
    const itemDispositions = rawDispositions as SyncItemDisposition[];
    if (new Set(itemDispositions.map(i => i.batchMessageId + ':' + i.messageId)).size !== itemDispositions.length) fail('invalid_params');
    for (const field of ['hostedEventId', 'hostedTurnId']) {
      if (params[field] !== null && (typeof params[field] !== 'string' || !/^[A-Za-z0-9_.:-]{1,160}$/.test(params[field] as string))) {
        fail('invalid_receipt_evidence');
      }
    }
    // Attached batches this completion may acknowledge: named, presented with
    // this message, and held by this very claim.
    const named = (state: BridgeState, message: StoredMessage): string[] => ackIds.filter(id => id !== (message.syncBatch ? params.messageId : null) &&
      (message.syncBatchIds || []).includes(id) && state.messages[id]?.syncBatch?.presentedAt &&
      state.receipts[id]?.state === 'claimed' && state.receipts[id].claimId === params.claimId &&
      messageAccessAllowed(state, state.messages[id], this.messagePolicyIds, this.clock()));
    if (this.prepareReceipt) {
      // Pre-arm native dispatch for EVERY ACK this completion can create (the
      // message's own, and each named batch's) before anything commits. Each
      // resolves through its own receipt's ackMessageId, so a lost response or
      // a failed scheduleJobs cannot strand any of them.
      const prepare = await this.store.transaction(state => {
        const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender);
        if (this.canary) canaryReceipt(state, this.canary, principal, params.messageId as string);
        const receipt = state.receipts[params.messageId as string];
        if (receipt?.owner !== principal.principalKey || receipt.claimId !== params.claimId) fail('receipt_claim_required', 409);
        if (receipt.state === 'complete') return [];
        if ((receipt.leaseUntil as Millis) <= this.clock() || !messageAccessAllowed(state, message, this.messagePolicyIds, this.clock())) fail('stale_receipt_claim', 409);
        if (!dailyMessage(message.envelope) || message.envelope.kind === 'ack') return [];
        return [params.messageId as string, ...named(state, message)];
      });
      for (const id of prepare) await this.prepareReceipt(id);
    }
    return this.store.transaction(state => {
      const now = this.clock(); retainMessages(state, now);
      const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender), original = message.envelope;
      if (this.canary) canaryReceipt(state, this.canary, principal, params.messageId as string);
      const receipt = state.receipts[params.messageId as string];
      if (receipt?.owner !== principal.principalKey) fail('receipt_claim_required', 409);
      // A retry after a lost response returns what was recorded: no new ACK.
      if (receipt.state === 'complete') return { completed: true, duplicate: true,
        ackMessageId: receipt.ackMessageId, evidenceStatus: 'reported_requires_independent_host_confirmation',
        ...(receipt.syncBatchOutcomes ? { syncBatchOutcomes: structuredClone(receipt.syncBatchOutcomes) } : {}),
        ...(receipt.syncBatchAcks?.length ? { syncBatchesAcked: receipt.syncBatchAcks.map(a => a.batchMessageId),
          syncBatchAcks: receipt.syncBatchAcks.map(a => ({ ...a })) } : {}) };
      if (!messageAccessAllowed(state, message, this.messagePolicyIds, now)) fail('message_authorization_inactive', 403);
      if (receipt.claimId !== params.claimId || (receipt.leaseUntil as Millis) <= now) fail('stale_receipt_claim', 409);
      // A batch is handled only after its full items were returned by a read.
      if (message.syncBatch && !message.syncBatch.presentedAt) fail('sync_batch_not_presented', 409);
      // Acknowledgement is bound to the completing receiver's own view and its
      // own claim: a batch's own ID on a direct completion, or an attached batch
      // that was presented with this message and is held by this very claim.
      // Unnamed batches stay outstanding; another claim's batch is never taken.
      const ownBatch = message.syncBatch ? params.messageId as string : null;
      for (const id of ackIds) {
        if (id === ownBatch) continue;
        if (!(message.syncBatchIds || []).includes(id) || !state.messages[id]?.syncBatch?.presentedAt) fail('sync_batch_not_presented', 409);
        if (state.receipts[id]?.state !== 'claimed' || state.receipts[id].claimId !== params.claimId) fail('sync_batch_not_held', 409);
        // Its own authority is rechecked now: withdrawn since the claim (policy
        // rotation, durable denial, expiry) refuses the whole completion, so
        // nothing commits and no ACK is created for it.
        if (!messageAccessAllowed(state, state.messages[id], this.messagePolicyIds, now)) {
          conflict('sync_batch_authorization_inactive', { batchMessageId: id });
        }
      }
      const handledBatches = [...new Set([...(ownBatch ? [ownBatch] : []), ...ackIds])];
      if (itemDispositions.some(i => !handledBatches.includes(i.batchMessageId))) fail('invalid_sync_item_disposition', 409);
      // Validate every disposition/missing item before any completion or ACK is
      // written, including batches whose items crossed expiry during this lease.
      for (const id of handledBatches) batchOutcome(state, id, now, itemDispositions);
      // A batch is never finalized with an item still under another live claim:
      // refuse the whole completion before anything changes.
      const busyItems = [...new Set(([ownBatch, ...ackIds].filter(Boolean) as string[])
        .flatMap(id => batchItemsBusy(state, state.messages[id], params.claimId, now)))];
      if (busyItems.length) conflict('sync_batch_item_busy', { itemIds: busyItems });
      // Every ACK this completion creates needs its return path now; any
      // missing one refuses the whole completion before anything changes.
      const ownUntil = message.syncBatch ? requireBatchAckPath(state, message, this.messagePolicyIds, now, 0) : undefined;
      if (!message.syncBatch) requireAckPath(state, original, message.authorization, this.messagePolicyIds, now, this.canary?.subscriptionId);
      const windows = Object.fromEntries(ackIds.filter(id => id !== ownBatch)
        .map(id => [id, requireBatchAckPath(state, state.messages[id]!, this.messagePolicyIds, now, 0)])); // Presented: present.
      // All ACK creation, receipt completion, and outbound jobs commit together.
      let ackMessageId: string | null = null; const jobIds: string[] = [];
      if (original.kind !== 'ack' && (!message.syncBatch || batchHasItems(state, message))) {
        const ack = this.createAck(state, principal, original, now, ownUntil);
        ackMessageId = ack.ackMessageId; jobIds.push(...ack.jobIds);
      }
      state.receipts[params.messageId as string] = { ...receipt, state: 'complete', completedAt: now,
        ackMessageId, hostedEventId: params.hostedEventId, hostedTurnId: params.hostedTurnId,
        evidenceStatus: 'reported_requires_independent_host_confirmation' };
      // Completing a batch acknowledges it and every item it presented, under
      // its one ACK. Completing a message also acknowledges exactly the named
      // batches it holds, each with its own correlated ACK (never the
      // message's), then releases its other holds so they can be claimed
      // directly.
      // claimId equals this receipt's claim (checked above).
      const evidence = { hostedEventId: params.hostedEventId, hostedTurnId: params.hostedTurnId, claimId: params.claimId as string, itemDispositions };
      const syncBatchAcks: { batchMessageId: string; ackMessageId: string | null }[] = [];
      if (ownBatch) ackBatch(state, ownBatch, principal, now, evidence, () => ackMessageId);
      for (const id of ackIds) {
        if (id === ownBatch) continue;
        const batchAck = ackBatch(state, id, principal, now, { ...evidence, via: params.messageId as string }, () => {
          if (!batchHasItems(state, state.messages[id]!)) return null;
          const ack = this.createAck(state, principal, state.messages[id]!.envelope, now, windows[id]);
          jobIds.push(...ack.jobIds);
          return ack.ackMessageId;
        });
        if (batchAck !== false) syncBatchAcks.push({ batchMessageId: id, ackMessageId: batchAck });
      }
      if (syncBatchAcks.length) state.receipts[params.messageId as string]!.syncBatchAcks = syncBatchAcks.map(a => ({ ...a }));
      for (const id of message.syncBatchIds || []) {
        if (state.receipts[id]?.state === 'claimed' && state.receipts[id].claimId === params.claimId) delete state.receipts[id];
      }
      const acked = [...(ownBatch && message.syncBatch!.ackedAt === now ? [ownBatch] : []), ...syncBatchAcks.map(a => a.batchMessageId)];
      const outcomes = acked.flatMap(id => state.messages[id]?.syncBatch?.outcome ? [structuredClone(state.messages[id]!.syncBatch!.outcome!)] : []);
      if (outcomes.length) state.receipts[params.messageId as string]!.syncBatchOutcomes = outcomes;
      return { completed: true, duplicate: false, ackMessageId, jobIds,
        evidenceStatus: 'reported_requires_independent_host_confirmation',
        ...(outcomes.length ? { syncBatchOutcomes: structuredClone(outcomes) } : {}),
        ...(acked.length ? { syncBatchesAcked: acked } : {}), ...(syncBatchAcks.length ? { syncBatchAcks } : {}) };
    });
  }
  async status(principal: Principal, params: unknown): Promise<StatusResult> {
    ownKeys(params, ['messageId']); messageId(params.messageId);
    if (!principal?.scopes?.some(x => Object.values(SCOPES[principal.role] || {}).includes(x))) fail('insufficient_scope', 403);
    return this.store.transaction(state => {
      retainMessages(state, this.clock());
      const message = state.messages[params.messageId as string];
      if (!message) {
        const diagnostic = diagnosticReadStatus(state, principal, params.messageId, this.clock());
        if (diagnostic) return diagnostic;
      }
      if (!message || ![message.envelope.from, message.envelope.to].includes(principal.role)) fail('message_not_found', 404);
      const receipt = state.receipts[params.messageId as string];
      const canary = canaryReadStatus(state, params.messageId, this.clock());
      return { messageId: params.messageId as string, // Checked by messageId() above.
        // A message's jobIds name its own stored jobs.
        deliveries: message.jobIds.map(id => ({ eventId: state.jobs[id]!.eventId, state: state.jobs[id]!.state,
          attempts: state.jobs[id]!.attempts, transportAttempts: state.jobs[id]!.transportAttempts ?? null,
          firstTransportOutcome: state.jobs[id]!.firstTransportOutcome || null,
          lastStatus: state.jobs[id]!.lastStatus ?? null, lastError: state.jobs[id]!.lastError ?? null })), receiptCompleted: receipt?.state === 'complete',
        ackMessageId: receipt?.ackMessageId || null,
        // A SYNC item has no ACK of its own; its batch's ACK covers it.
        ...(receipt?.batchAckMessageId ? { batchAckMessageId: receipt.batchAckMessageId } : {}),
        evidenceStatus: receipt?.evidenceStatus || 'no_hosted_receipt', wakeVerified: false, ...(canary ? { canary } : {}),
        ...(receipt?.syncBatchOutcomes ? { syncBatchOutcomes: structuredClone(receipt.syncBatchOutcomes) } : {}),
        ...(message.syncBatchOutcome ? { syncBatchOutcome: structuredClone(message.syncBatchOutcome) } : {}),
        ...syncStatus(message) };
    });
  }
}
