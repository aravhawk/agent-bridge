import { dailyMessage, validateMessage, retainMessages, reserveMessage, checkMessageCapacity, MESSAGE_PROTOCOL, MESSAGE_TTL_MS } from './messages.mjs';
import { randomUUID } from 'node:crypto';
import { BridgeError, validateEnvelope, SCOPES } from './policy.mjs';
import { appendDeliveryJobs, authorizeRecipient, ownKeys } from './events.mjs';
import { verifiedMessageAuthorization, messageAccessAllowed, testEnvelopeAllowed } from './access.mjs';

const fail = (code, status = 400) => { throw new BridgeError(code, status); };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function messageId(value) { if (typeof value !== 'string' || !uuid.test(value)) fail('invalid_message_id'); }
function admitProbe(state, role, now) {
  // The verifier binds each of the two sender roles to its pinned identity.
  // Fixed role slots avoid caller-chosen bucket keys or unbounded limiter state.
  // This runs under the same durable row lock as message/job creation, so cold
  // starts and concurrent function instances cannot each grant a fresh budget.
  const admissions = state.probeAdmissions ||= {};
  const recent = (admissions[role] || []).filter(at => at > now - 60000);
  if (recent.length >= 10) fail('probe_rate_limited', 429);
  admissions[role] = [...recent, now];
}
function incoming(state, principal, id, probeMessageId, probeSender) {
  authorizeRecipient(principal); messageId(id);
  const message = state.messages[id];
  if (!message || message.envelope.to !== principal.role) fail('message_not_found', 404);
  if (probeMessageId && !testEnvelopeAllowed(message.envelope, probeMessageId, probeSender)) fail('contract_probe_only', 403);
  return message;
}
function insert(state, envelope, hash, now, authorization) {
  const saved = state.messages[envelope.id];
  if (saved && saved.hash !== hash) fail('message_id_conflict', 409);
  if (saved) return { messageId: envelope.id, queued: true, duplicate: true, jobIds: saved.jobIds };
  if (envelope.kind === 'ack') {
    const probe = state.messages[envelope.correlationId]?.envelope;
    if (!probe || probe.kind === 'ack' || (dailyMessage(envelope) !== dailyMessage(probe)) ||
        (dailyMessage(envelope) && (probe.threadId !== envelope.threadId || probe.route !== envelope.route)) || probe.from !== envelope.to || probe.to !== envelope.from) fail('invalid_correlation', 409);
  }
  const retainUntil = dailyMessage(envelope) ? reserveMessage(state, envelope, hash, now) : undefined;
  const jobIds = appendDeliveryJobs(state, envelope, now);
  if (envelope.to === 'jarvis' && !jobIds.length) fail('recipient_subscription_required', 503);
  state.messages[envelope.id] = { envelope, hash, storedAt: now, jobIds, authorization, ...(retainUntil ? { retainUntil } : {}) };
  return { messageId: envelope.id, queued: true, duplicate: false, jobIds };
}

export class Bridge {
  constructor({ store, clock = Date.now, probeMessageId, probeSender = 'jarvis', messagePolicyIds, deliveryUntil = Infinity, dailyEnabled = false, prepareMessage, prepareReceipt }) {
    this.prepareMessage = prepareMessage; this.prepareReceipt = prepareReceipt;
    this.store = store; this.clock = clock; this.dailyEnabled = dailyEnabled; this.probeMessageId = probeMessageId;
    this.probeSender = probeSender;
    this.messagePolicyIds = messagePolicyIds; this.deliveryUntil = deliveryUntil;
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
      if (!saved) admitProbe(state, principal.role, this.clock());
      return insert(state, envelope, hash, this.clock(), authorization);
    });
  }
  async sendMessage(principal, input) {
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
      if (!prior) {
        verifiedMessageAuthorization(principal, validated.envelope, this.clock(), this.deliveryUntil);
        checkMessageCapacity(state);
        const now = this.clock();
        state.messagePreparations ||= {};
        for (const [id, entry] of Object.entries(state.messagePreparations)) if (entry.until <= now) delete state.messagePreparations[id];
        const pending = state.messagePreparations[validated.envelope.id];
        if (pending && pending.hash !== validated.hash) fail('message_id_conflict', 409);
        if (!pending) {
          admitProbe(state, principal.role, now); // Bound native queue publication too.
          state.messagePreparations[validated.envelope.id] = { hash: validated.hash, until: now + 60000 };
        }
      }
      return { id: validated.envelope.id, fresh: !prior };
    });
    if (preparation.fresh && this.prepareMessage) await this.prepareMessage(preparation.id);
    return this.store.transaction(state => {
      const now = this.clock(); retainMessages(state, now);
      const id = typeof input?.id === 'string' ? input.id.toLowerCase() : '';
      const prior = state.messages[id] || state.messageIds?.[id];
      const { envelope, hash } = validateMessage(input, principal, prior ? Date.parse(input.sentAt) : now);
      if (prior && prior.hash !== hash) fail('message_id_conflict', 409);
      if (prior) return state.messages[id]
        ? { messageId: id, queued: true, duplicate: true, jobIds: state.messages[id].jobIds }
        : { messageId: id, queued: false, duplicate: true, expired: true, jobIds: [] };
      if (Date.parse(envelope.expiresAt) <= now) fail('message_expired', 403);
      const authorization = verifiedMessageAuthorization(principal, envelope, now, this.deliveryUntil);
      delete state.messagePreparations?.[envelope.id];
      return insert(state, envelope, hash, now, authorization);
    });
  }
  async read(principal, params) {
    ownKeys(params, ['messageId']);
    return this.store.transaction(state => {
      retainMessages(state, this.clock());
      const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender);
      return { envelope: message.envelope, ...(dailyMessage(message.envelope) ? { authority: 'peer_data_requires_user_workflow',
        expired: Date.parse(message.envelope.expiresAt) <= this.clock() } : {}), receivedAt: new Date(message.storedAt).toISOString() };
    });
  }
  async claim(principal, params) {
    ownKeys(params, ['messageId']);
    return this.store.transaction(state => {
      const now = this.clock();
      retainMessages(state, this.clock());
      const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender);
      const old = state.receipts[params.messageId];
      if (old?.state === 'complete') return { duplicate: true, completed: true, ackMessageId: old.ackMessageId };
      if (!messageAccessAllowed(state, message, this.messagePolicyIds, now)) fail('message_authorization_inactive', 403);
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
        const receipt = state.receipts[params.messageId];
        if (receipt?.owner !== principal.principalKey || receipt.claimId !== params.claimId) fail('receipt_claim_required', 409);
        if (receipt.state === 'complete') return false;
        if (receipt.leaseUntil <= this.clock() || !messageAccessAllowed(state, message, this.messagePolicyIds, this.clock())) fail('stale_receipt_claim', 409);
        return dailyMessage(message.envelope) && message.envelope.kind !== 'ack';
      });
      if (prepare) await this.prepareReceipt(params.messageId);
    }
    return this.store.transaction(state => {
      const now = this.clock(); retainMessages(state, now);
      const message = incoming(state, principal, params.messageId, this.probeMessageId, this.probeSender), original = message.envelope;
      const receipt = state.receipts[params.messageId];
      if (receipt?.owner !== principal.principalKey) fail('receipt_claim_required', 409);
      if (receipt.state === 'complete') return { completed: true, duplicate: true,
        ackMessageId: receipt.ackMessageId, evidenceStatus: 'reported_requires_independent_host_confirmation' };
      if (!messageAccessAllowed(state, message, this.messagePolicyIds, now)) fail('message_authorization_inactive', 403);
      if (receipt.claimId !== params.claimId || receipt.leaseUntil <= now) fail('stale_receipt_claim', 409);
      let ackMessageId = null; let jobIds = [];
      if (original.kind !== 'ack') {
        // All ACK creation, receipt completion, and outbound jobs commit together.
        ackMessageId = randomUUID();
        const { envelope, hash } = dailyMessage(original) ? validateMessage({ protocol: MESSAGE_PROTOCOL,
          id: ackMessageId, from: principal.role, to: original.from, kind: 'ack', sentAt: new Date(now).toISOString(),
          expiresAt: new Date(Math.min(Date.parse(original.expiresAt), now + MESSAGE_TTL_MS)).toISOString(),
          threadId: original.threadId, route: original.route, correlationId: original.id }, principal, now)
          : validateEnvelope({ id: ackMessageId, testId: original.testId,
            from: principal.role, to: original.from, kind: 'ack', sentAt: new Date(now).toISOString(),
            correlationId: original.id, marker: original.marker }, principal, now);
        ({ jobIds } = insert(state, envelope, hash, now, verifiedMessageAuthorization(principal, envelope, now, this.deliveryUntil)));
      }
      state.receipts[params.messageId] = { ...receipt, state: 'complete', completedAt: now,
        ackMessageId, hostedEventId: params.hostedEventId, hostedTurnId: params.hostedTurnId,
        evidenceStatus: 'reported_requires_independent_host_confirmation' };
      return { completed: true, duplicate: false, ackMessageId, jobIds,
        evidenceStatus: 'reported_requires_independent_host_confirmation' };
    });
  }
  async status(principal, params) {
    ownKeys(params, ['messageId']); messageId(params.messageId);
    if (!principal?.scopes?.some(x => Object.values(SCOPES[principal.role] || {}).includes(x))) fail('insufficient_scope', 403);
    return this.store.transaction(state => {
      retainMessages(state, this.clock());
      const message = state.messages[params.messageId];
      if (!message || ![message.envelope.from, message.envelope.to].includes(principal.role)) fail('message_not_found', 404);
      const receipt = state.receipts[params.messageId];
      return { messageId: params.messageId,
        deliveries: message.jobIds.map(id => ({ eventId: state.jobs[id].eventId, state: state.jobs[id].state,
          attempts: state.jobs[id].attempts, transportAttempts: state.jobs[id].transportAttempts ?? null,
          firstTransportOutcome: state.jobs[id].firstTransportOutcome || null,
          lastStatus: state.jobs[id].lastStatus ?? null, lastError: state.jobs[id].lastError ?? null })), receiptCompleted: receipt?.state === 'complete',
        ackMessageId: receipt?.ackMessageId || null,
        evidenceStatus: receipt?.evidenceStatus || 'no_hosted_receipt', wakeVerified: false };
    });
  }
}
