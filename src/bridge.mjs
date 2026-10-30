import { dailyMessage, validateMessage, retainMessages, reserveMessage, checkMessageCapacity, MESSAGE_PROTOCOL, MESSAGE_TTL_MS } from './messages.mjs';
import { randomUUID } from 'node:crypto';
import { BridgeError, validateEnvelope, SCOPES } from './policy.mjs';
import { appendDeliveryJobs, authorizeRecipient, hasDeliveryDestination, ownKeys } from './events.mjs';
import { verifiedMessageAuthorization, messageAccessAllowed, subscriptionAccessAllowed, testEnvelopeAllowed } from './access.mjs';
import { diagnosticReadCandidate, diagnosticReadStatus, observeDiagnosticRead,
  canaryReadCandidate, canaryReadStatus, observeCanaryRead } from './observability.mjs';
import { canaryEnvelope, reserveCanary, canaryReceipt } from './canary.mjs';
import { EVENTS_PEER, NAMES } from './config.mjs';
import { classify, enqueueSync, supersedeBySubject, cutBatch, presentBatch, ackBatch, outstandingBatches, flushDue, markDispatched } from './sync.mjs';

const fail = (code, status = 400) => { throw new BridgeError(code, status); };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function messageId(value) { if (typeof value !== 'string' || !uuid.test(value)) fail('invalid_message_id'); }
function admitMessage(state, role, now) {
  // The verifier binds each of the two sender roles to its pinned identity.
  // Fixed role slots avoid caller-chosen bucket keys or unbounded limiter state.
  // This runs under the same durable row lock as message/job creation, so cold
  // starts and concurrent function instances cannot each grant a fresh budget.
  const admissions = state.probeAdmissions ||= {};
  const recent = (admissions[role] || []).filter(at => at > now - 60000);
  if (recent.length >= 10) fail('message_rate_limited', 429);
  admissions[role] = [...recent, now];
}
function incoming(state, principal, id, probeMessageId, probeSender) {
  authorizeRecipient(principal); messageId(id);
  const message = state.messages[id];
  if (!message || message.envelope.to !== principal.role) fail('message_not_found', 404);
  if (probeMessageId && !testEnvelopeAllowed(message.envelope, probeMessageId, probeSender)) fail('contract_probe_only', 403);
  return message;
}
function requireAckPath(state, envelope, authorization, policyIds, now, subscriptionId, ackSuppressed = false) {
  // A suppressed ACK (wake/sync recipient or server batch) needs no return path.
  if (ackSuppressed || !dailyMessage(envelope) || envelope.kind === 'ack' || envelope.from !== EVENTS_PEER) return;
  // The webhook peer must not handle a source whose required ACK has no usable return
  // path. Cover its entire immutable authority lifetime, not just this instant.
  // Revocation/shortening during handling still fails closed at completion.
  // A pinned subscriptionId (canary) admits only that exact return path.
  if (!Object.values(state.subscriptions).some(sub => sub.owner === authorization?.owner &&
      (!subscriptionId || sub.id === subscriptionId) &&
      subscriptionAccessAllowed(state, sub, policyIds?.[EVENTS_PEER], now) &&
      sub.expiresAt >= authorization.expiresAt)) fail('return_subscription_required', 503);
}
// routing is present only for a wake/sync-enabled recipient: { class, promoted?, policyIds }.
function insert(state, envelope, hash, now, authorization, jobOptions, routing) {
  const saved = state.messages[envelope.id];
  if (saved && saved.hash !== hash) fail('message_id_conflict', 409);
  if (saved) return { messageId: envelope.id, queued: true, duplicate: true, jobIds: saved.jobIds };
  if (envelope.kind === 'ack') {
    const probe = state.messages[envelope.correlationId]?.envelope;
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
  const message = state.messages[envelope.id] = { envelope, hash, storedAt: now, jobIds, authorization, ...(retainUntil ? { retainUntil } : {}) };
  if (!routing) return { messageId: envelope.id, queued: true, duplicate: false, jobIds };
  const routed = { class: routing.class, ...(routing.promoted ? { promoted: routing.promoted } : {}) };
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

// Additive status for wake/sync messages only; v1 messages report nothing new.
function syncStatus(message) {
  const s = message.sync, b = message.syncBatch;
  return { ...(s ? { sync: { class: 'sync', state: s.state, ...(s.deliveredAt ? { via: s.via,
    deliveredAt: new Date(s.deliveredAt).toISOString() } : {}), ...(s.batchId ? { batchMessageId: s.batchId } : {}),
    ...(s.redeliveries ? { redeliveries: s.redeliveries } : {}), ...(s.supersededBy ? { supersededBy: s.supersededBy } : {}) } } : {}),
    ...(b ? { syncBatch: { reason: b.reason, ...(b.trigger ? { trigger: b.trigger } : {}), itemCount: b.itemIds.length,
      presented: !!b.presentedAt, acknowledged: !!b.ackedAt, reclaimed: !!b.reclaimedAt } } : {}),
    ...(message.syncBatchIds ? { piggybackedBatchIds: [...message.syncBatchIds] } : {}) };
}

export class Bridge {
  // canary: trusted fixed configuration (canary.mjs). When present this
  // instance admits only that one source and its server-created ACK.
  // wakeSync: trusted function returning the recipients with wake/sync enabled
  // (BRIDGE_WAKE_SYNC_RECIPIENTS, read per use). Omitted or empty: v1 behavior.
  constructor({ store, clock = Date.now, probeMessageId, probeSender = EVENTS_PEER, messagePolicyIds, deliveryUntil = Infinity, dailyEnabled = false, prepareMessage, prepareReceipt, canary, wakeSync }) {
    this.prepareMessage = prepareMessage; this.prepareReceipt = prepareReceipt; this.canary = canary; this.wakeSync = wakeSync;
    this.store = store; this.clock = clock; this.dailyEnabled = dailyEnabled; this.probeMessageId = probeMessageId;
    this.probeSender = probeSender;
    this.messagePolicyIds = messagePolicyIds; this.deliveryUntil = deliveryUntil;
  }
  syncEnabled(role) {
    if (this.canary || this.probeMessageId || typeof this.wakeSync !== 'function') return false;
    const recipients = this.wakeSync();
    return Array.isArray(recipients) && recipients.includes(role);
  }
  // No ACK wakes: the ACK's recipient is the source's sender. Server-composed
  // batches never ACK. The receipt itself is still recorded as before.
  ackSuppressed(message) {
    return !!message?.syncBatch || (dailyMessage(message?.envelope) && message.envelope.kind !== 'ack' && this.syncEnabled(message.envelope.from));
  }
  routing(envelope, now) {
    if (envelope.kind === 'ack' || !this.syncEnabled(envelope.to)) return undefined;
    return { ...classify(envelope, now), policyIds: this.messagePolicyIds };
  }
  async send(principal, input) {
    // ACK is only emitted by the atomic completion operation, never separately.
    if (input?.kind !== 'probe') fail('use_receipt_complete_for_ack');
    return this.store.transaction(state => {
      // A replay of an already committed ID remains idempotent after downtime.
      // Only an exact canonical match skips the freshness rule; changed content
      // still conflicts, and a new stale ID is rejected.
      const saved = typeof input.id === 'string' && state.messages[input.id.toLowerCase()];
      const { envelope, hash } = validateEnvelope(input, principal, saved ? Date.parse(input.sentAt) : this.clock());
      if (this.probeMessageId && !testEnvelopeAllowed(envelope, this.probeMessageId, this.probeSender)) fail('contract_probe_only', 403);
      const authorization = saved ? undefined : verifiedMessageAuthorization(principal, envelope, this.clock(), this.deliveryUntil);
      // Exact retransmissions stay idempotent even at the limit or after the
      // freshness window; changed bodies still take insert's conflict path.
      // Failed insertion rolls this admission back with the transaction.
      if (!saved) admitMessage(state, principal.role, this.clock());
      return insert(state, envelope, hash, this.clock(), authorization);
    });
  }
  async prepareMessageSend(principal, input) {
    if (!this.dailyEnabled) fail('daily_messages_not_enabled', 503);
    if (input?.kind === 'ack') fail('use_receipt_complete_for_ack');
    // Reserve native backend work BEFORE creating any content. If publishing
    // fails, no new message is saved. The queued dispatcher tolerates an early
    // callback and a failed DB commit without waking a recipient for absent data.
    const preparation = await this.store.transaction(state => {
      retainMessages(state, this.clock());
      const prior = state.messages[input?.id?.toLowerCase?.()] || state.messageIds?.[input?.id?.toLowerCase?.()];
      const validated = validateMessage(input, principal, prior ? Date.parse(input.sentAt) : this.clock());
      if (prior?.hash !== undefined && prior.hash !== validated.hash) fail('message_id_conflict', 409);
      if (this.canary) canaryEnvelope(validated.envelope, this.canary);
      if (!prior) {
        const authorization = verifiedMessageAuthorization(principal, validated.envelope, this.clock(), this.deliveryUntil);
        requireAckPath(state, validated.envelope, authorization, this.messagePolicyIds, this.clock(), this.canary?.subscriptionId,
          this.ackSuppressed({ envelope: validated.envelope }));
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
  stageMessage(state, principal, input) {
    if (!this.dailyEnabled) fail('daily_messages_not_enabled', 503);
    if (input?.kind === 'ack') fail('use_receipt_complete_for_ack');
    const now = this.clock(); retainMessages(state, now);
    const id = typeof input?.id === 'string' ? input.id.toLowerCase() : '';
    const prior = state.messages[id] || state.messageIds?.[id];
    const { envelope, hash } = validateMessage(input, principal, prior ? Date.parse(input.sentAt) : now);
    if (prior && prior.hash !== hash) fail('message_id_conflict', 409);
    if (this.canary) { canaryEnvelope(envelope, this.canary); reserveCanary(state, this.canary, principal, hash, !!prior, now); }
    if (prior) return state.messages[id]
      ? { messageId: id, queued: true, duplicate: true, jobIds: state.messages[id].jobIds }
      : { messageId: id, queued: false, duplicate: true, expired: true, jobIds: [] };
    if (Date.parse(envelope.expiresAt) <= now) fail('message_expired', 403);
    const authorization = verifiedMessageAuthorization(principal, envelope, now, this.deliveryUntil);
    requireAckPath(state, envelope, authorization, this.messagePolicyIds, now, this.canary?.subscriptionId, this.ackSuppressed({ envelope }));
    delete state.messagePreparations?.[envelope.id];
    return insert(state, envelope, hash, now, authorization, this.canary ? { maxAttempts: 1 } : undefined, this.routing(envelope, now));
  }
  async sendMessage(principal, input) {
    await this.prepareMessageSend(principal, input);
    return this.store.transaction(state => this.stageMessage(state, principal, input));
  }
  async read(principal, params) {
    ownKeys(params, ['messageId']);
    let candidate = false, canary = false, output;
    try { output = await this.store.transaction(state => {
      const now = this.clock();
      retainMessages(state, now);
      candidate = diagnosticReadCandidate(state, principal, params.messageId, now);
      canary = canaryReadCandidate(state, principal, params.messageId, now);
      const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender);
      const syncBatches = this.syncBatches(state, message, principal.role, now);
      return { envelope: message.envelope, ...(dailyMessage(message.envelope) ? { authority: 'peer_data_requires_user_workflow',
        expired: Date.parse(message.envelope.expiresAt) <= this.clock() } : {}), receivedAt: new Date(message.storedAt).toISOString(),
        ...(syncBatches.length ? { syncBatches } : {}) };
    }); } catch (error) {
      if (candidate) await observeDiagnosticRead({ store: this.store, principal, messageId: params.messageId, error, failed: true, clock: this.clock });
      if (canary) await observeCanaryRead({ store: this.store, principal, messageId: params.messageId, error, failed: true, clock: this.clock });
      throw error;
    }
    if (candidate) await observeDiagnosticRead({ store: this.store, principal, messageId: params.messageId, clock: this.clock });
    if (canary) await observeCanaryRead({ store: this.store, principal, messageId: params.messageId, clock: this.clock });
    return output;
  }
  // Batches presented with a read message: its own items when it is a batch,
  // then those piggybacked on it. While the message is not yet completed, an
  // enabled recipient's read also drains pending SYNC data into a new batch
  // attached to it, so a re-read (e.g. after a lost response) is identical and
  // completing the message acknowledges what was presented with it.
  syncBatches(state, message, role, now) {
    if (!dailyMessage(message.envelope)) return [];
    if (this.syncEnabled(role) && state.receipts[message.envelope.id]?.state !== 'complete') {
      const batch = cutBatch(state, role, now, { reason: 'read', policyIds: this.messagePolicyIds });
      if (batch) (message.syncBatchIds ||= []).push(batch.envelope.id);
    }
    return [...(message.syncBatch ? [message.envelope.id] : []), ...(message.syncBatchIds || [])]
      .map(id => presentBatch(state, id, now)).filter(Boolean);
  }
  // Start-of-turn inbox read for an enabled recipient. Returns every delivered
  // but unacknowledged batch (replayed until acknowledged, so a lost response or
  // crash loses nothing) plus any pending SYNC data cut into one new delta batch.
  // Reads serialize on the store lock: concurrent readers get the same batches.
  async inboxRead(principal, params = {}) {
    authorizeRecipient(principal); ownKeys(params, [], []);
    if (!this.syncEnabled(principal.role)) fail('wake_sync_not_enabled', 503);
    return this.store.transaction(state => {
      const now = this.clock(); retainMessages(state, now);
      cutBatch(state, principal.role, now, { reason: 'inbox', policyIds: this.messagePolicyIds });
      return { syncBatches: outstandingBatches(state, principal.role, now).map(id => presentBatch(state, id, now)) };
    });
  }
  // Hourly flush (trigger route): see flushDue. Returns message IDs still to be
  // published for dispatch.
  async flushSync() {
    return this.store.transaction(state => {
      const now = this.clock(); retainMessages(state, now);
      return flushDue(state, now, { policyIds: this.messagePolicyIds, recipients: this.wakeSync?.() || [] });
    });
  }
  async markSyncDispatched(ids) {
    return this.store.transaction(state => { markDispatched(state, ids); });
  }
  async claim(principal, params) {
    ownKeys(params, ['messageId']);
    return this.store.transaction(state => {
      const now = this.clock();
      retainMessages(state, this.clock());
      const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender);
      if (this.canary) canaryReceipt(state, this.canary, principal, params.messageId);
      const old = state.receipts[params.messageId];
      if (old?.state === 'complete') return { duplicate: true, completed: true, ackMessageId: old.ackMessageId };
      if (!messageAccessAllowed(state, message, this.messagePolicyIds, now)) fail('message_authorization_inactive', 403);
      requireAckPath(state, message.envelope, message.authorization, this.messagePolicyIds, now, this.canary?.subscriptionId,
        this.ackSuppressed(message));
      if (old?.leaseUntil > now) fail('receipt_busy', 409);
      const claimId = randomUUID();
      state.receipts[params.messageId] = { state: 'claimed', owner: principal.principalKey,
        claimId, leaseUntil: now + 60000 };
      return { claimId, leaseUntil: new Date(now + 60000).toISOString(), completed: false };
    });
  }
  async complete(principal, params) {
    ownKeys(params, ['messageId', 'claimId', 'hostedEventId', 'hostedTurnId']);
    for (const field of ['hostedEventId', 'hostedTurnId']) {
      if (params[field] !== null && (typeof params[field] !== 'string' || !/^[A-Za-z0-9_.:-]{1,160}$/.test(params[field]))) {
        fail('invalid_receipt_evidence');
      }
    }
    if (this.prepareReceipt) {
      const prepare = await this.store.transaction(state => {
        const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender);
        if (this.canary) canaryReceipt(state, this.canary, principal, params.messageId);
        const receipt = state.receipts[params.messageId];
        if (receipt?.owner !== principal.principalKey || receipt.claimId !== params.claimId) fail('receipt_claim_required', 409);
        if (receipt.state === 'complete') return false;
        if (receipt.leaseUntil <= this.clock() || !messageAccessAllowed(state, message, this.messagePolicyIds, this.clock())) fail('stale_receipt_claim', 409);
        return dailyMessage(message.envelope) && message.envelope.kind !== 'ack' && !this.ackSuppressed(message);
      });
      if (prepare) await this.prepareReceipt(params.messageId);
    }
    return this.store.transaction(state => {
      const now = this.clock(); retainMessages(state, now);
      const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender), original = message.envelope;
      if (this.canary) canaryReceipt(state, this.canary, principal, params.messageId);
      const receipt = state.receipts[params.messageId];
      if (receipt?.owner !== principal.principalKey) fail('receipt_claim_required', 409);
      if (receipt.state === 'complete') return { completed: true, duplicate: true,
        ackMessageId: receipt.ackMessageId, evidenceStatus: 'reported_requires_independent_host_confirmation' };
      if (!messageAccessAllowed(state, message, this.messagePolicyIds, now)) fail('message_authorization_inactive', 403);
      if (receipt.claimId !== params.claimId || receipt.leaseUntil <= now) fail('stale_receipt_claim', 409);
      // A batch is handled only after its full items were returned by a read.
      if (message.syncBatch && !message.syncBatch.presentedAt) fail('sync_batch_not_presented', 409);
      const ackSuppressed = original.kind !== 'ack' && this.ackSuppressed(message);
      requireAckPath(state, original, message.authorization, this.messagePolicyIds, now, this.canary?.subscriptionId, ackSuppressed);
      let ackMessageId = null; let jobIds = [];
      if (original.kind !== 'ack' && !ackSuppressed) {
        // All ACK creation, receipt completion, and outbound jobs commit together.
        ackMessageId = randomUUID();
        const { envelope, hash } = dailyMessage(original) ? validateMessage({ protocol: MESSAGE_PROTOCOL,
          id: ackMessageId, from: principal.role, to: original.from, kind: 'ack', sentAt: new Date(now).toISOString(),
          expiresAt: new Date(Math.min(Date.parse(original.expiresAt), now + MESSAGE_TTL_MS)).toISOString(),
          threadId: original.threadId, route: original.route, correlationId: original.id }, principal, now)
          : validateEnvelope({ id: ackMessageId, testId: original.testId,
            from: principal.role, to: original.from, kind: 'ack', sentAt: new Date(now).toISOString(),
            correlationId: original.id, marker: original.marker }, principal, now);
        // The canary ACK targets only the pinned return subscription, one attempt.
        ({ jobIds } = insert(state, envelope, hash, now, verifiedMessageAuthorization(principal, envelope, now, this.deliveryUntil),
          this.canary ? { subscriptionId: this.canary.subscriptionId, maxAttempts: 1 } : undefined));
        if (this.canary) state[NAMES.canaryState].ackMessageId = ackMessageId;
      }
      state.receipts[params.messageId] = { ...receipt, state: 'complete', completedAt: now,
        ackMessageId, hostedEventId: params.hostedEventId, hostedTurnId: params.hostedTurnId,
        evidenceStatus: 'reported_requires_independent_host_confirmation', ...(ackSuppressed ? { ackSuppressed: true } : {}) };
      // Completing a batch acknowledges it and every item it presented.
      // Completing a message also acknowledges the batches presented with it.
      const evidence = { hostedEventId: params.hostedEventId, hostedTurnId: params.hostedTurnId };
      if (message.syncBatch) ackBatch(state, params.messageId, principal, now, evidence);
      const syncBatchesAcked = (message.syncBatchIds || [])
        .filter(id => ackBatch(state, id, principal, now, { ...evidence, via: params.messageId }));
      return { completed: true, duplicate: false, ackMessageId, jobIds,
        evidenceStatus: 'reported_requires_independent_host_confirmation', ...(ackSuppressed ? { ackSuppressed: true } : {}),
        ...(syncBatchesAcked.length ? { syncBatchesAcked } : {}) };
    });
  }
  async status(principal, params) {
    ownKeys(params, ['messageId']); messageId(params.messageId);
    if (!principal?.scopes?.some(x => Object.values(SCOPES[principal.role] || {}).includes(x))) fail('insufficient_scope', 403);
    return this.store.transaction(state => {
      retainMessages(state, this.clock());
      const message = state.messages[params.messageId];
      if (!message) {
        const diagnostic = diagnosticReadStatus(state, principal, params.messageId, this.clock());
        if (diagnostic) return diagnostic;
      }
      if (!message || ![message.envelope.from, message.envelope.to].includes(principal.role)) fail('message_not_found', 404);
      const receipt = state.receipts[params.messageId];
      const canary = canaryReadStatus(state, params.messageId, this.clock());
      return { messageId: params.messageId,
        deliveries: message.jobIds.map(id => ({ eventId: state.jobs[id].eventId, state: state.jobs[id].state,
          attempts: state.jobs[id].attempts, transportAttempts: state.jobs[id].transportAttempts ?? null,
          firstTransportOutcome: state.jobs[id].firstTransportOutcome || null,
          lastStatus: state.jobs[id].lastStatus ?? null, lastError: state.jobs[id].lastError ?? null })), receiptCompleted: receipt?.state === 'complete',
        ackMessageId: receipt?.ackMessageId || null,
        evidenceStatus: receipt?.evidenceStatus || 'no_hosted_receipt', wakeVerified: false, ...(canary ? { canary } : {}),
        ...syncStatus(message) };
    });
  }
}
