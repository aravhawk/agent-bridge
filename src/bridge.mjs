import { randomUUID } from 'node:crypto';
import { BridgeError, validateEnvelope, SCOPES } from './policy.mjs';
import { appendDeliveryJobs, authorizeRecipient, ownKeys } from './events.mjs';

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
function incoming(state, principal, id) {
  authorizeRecipient(principal); messageId(id);
  const message = state.messages[id];
  if (!message || message.envelope.to !== principal.role) fail('message_not_found', 404);
  return message;
}
function insert(state, envelope, hash, now) {
  const saved = state.messages[envelope.id];
  if (saved && saved.hash !== hash) fail('message_id_conflict', 409);
  if (saved) return { messageId: envelope.id, queued: true, duplicate: true, jobIds: saved.jobIds };
  if (envelope.kind === 'ack') {
    const probe = state.messages[envelope.correlationId]?.envelope;
    if (probe?.kind !== 'probe' || probe.from !== envelope.to || probe.to !== envelope.from) fail('invalid_correlation', 409);
  }
  const jobIds = appendDeliveryJobs(state, envelope, now);
  if (envelope.to === 'jarvis' && !jobIds.length) fail('recipient_subscription_required', 503);
  state.messages[envelope.id] = { envelope, hash, storedAt: now, jobIds };
  return { messageId: envelope.id, queued: true, duplicate: false, jobIds };
}

export class Bridge {
  constructor({ store, clock = Date.now }) { this.store = store; this.clock = clock; }
  async send(principal, input) {
    // ACK is only emitted by the atomic completion operation, never separately.
    if (input?.kind !== 'probe') fail('use_receipt_complete_for_ack');
    return this.store.transaction(state => {
      // A replay of an already committed ID remains idempotent after downtime.
      // Only an exact canonical match skips the freshness rule; changed content
      // still conflicts, and a new stale ID is rejected.
      const saved = typeof input.id === 'string' && state.messages[input.id.toLowerCase()];
      const { envelope, hash } = validateEnvelope(input, principal, saved ? Date.parse(input.sentAt) : this.clock());
      // Exact retransmissions stay idempotent even at the limit or after the
      // freshness window; changed bodies still take insert's conflict path.
      // Failed insertion rolls this admission back with the transaction.
      if (!saved) admitProbe(state, principal.role, this.clock());
      return insert(state, envelope, hash, this.clock());
    });
  }
  async read(principal, params) {
    ownKeys(params, ['messageId']);
    return this.store.transaction(state => {
      const message = incoming(state, principal, params.messageId);
      return { envelope: message.envelope, receivedAt: new Date(message.storedAt).toISOString() };
    });
  }
  async claim(principal, params) {
    ownKeys(params, ['messageId']); const now = this.clock();
    return this.store.transaction(state => {
      incoming(state, principal, params.messageId);
      const old = state.receipts[params.messageId];
      if (old?.state === 'complete') return { duplicate: true, completed: true, ackMessageId: old.ackMessageId };
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
    const now = this.clock();
    return this.store.transaction(state => {
      const original = incoming(state, principal, params.messageId).envelope;
      const receipt = state.receipts[params.messageId];
      if (receipt?.owner !== principal.principalKey) fail('receipt_claim_required', 409);
      if (receipt.state === 'complete') return { completed: true, duplicate: true,
        ackMessageId: receipt.ackMessageId, evidenceStatus: 'reported_requires_independent_host_confirmation' };
      if (receipt.claimId !== params.claimId || receipt.leaseUntil <= now) fail('stale_receipt_claim', 409);
      let ackMessageId = null; let jobIds = [];
      if (original.kind === 'probe') {
        // All ACK creation, receipt completion, and outbound jobs commit together.
        ackMessageId = randomUUID();
        const { envelope, hash } = validateEnvelope({ id: ackMessageId, testId: original.testId,
          from: principal.role, to: original.from, kind: 'ack', sentAt: new Date(now).toISOString(),
          correlationId: original.id, marker: original.marker }, principal, now);
        ({ jobIds } = insert(state, envelope, hash, now));
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
      const message = state.messages[params.messageId];
      if (!message || ![message.envelope.from, message.envelope.to].includes(principal.role)) fail('message_not_found', 404);
      const receipt = state.receipts[params.messageId];
      return { messageId: params.messageId,
        deliveries: message.jobIds.map(id => ({ eventId: state.jobs[id].eventId, state: state.jobs[id].state,
          attempts: state.jobs[id].attempts })), receiptCompleted: receipt?.state === 'complete',
        ackMessageId: receipt?.ackMessageId || null,
        evidenceStatus: receipt?.evidenceStatus || 'no_hosted_receipt', wakeVerified: false };
    });
  }
}
