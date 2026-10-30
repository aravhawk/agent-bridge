import { createHash } from 'node:crypto';
import { BridgeError, SCOPES } from './policy.mjs';
import { CONFIG, PEER_IDS } from './config.mjs';

// Stored and emitted protocol ID. Every accepted alias is normalized to it.
export const MESSAGE_PROTOCOL = CONFIG.protocol;
export const ACCEPTED_PROTOCOLS = CONFIG.acceptedProtocols;
export const MESSAGE_TTL_MS = 3600000;
// SYNC data waits for the next even-hour flush (up to three real hours), so a
// message classified 'sync' may live longer. Every other message keeps one hour.
export const SYNC_MESSAGE_TTL_MS = 12 * 3600000;
export const CONTENT_RETENTION_MS = 86400000;
export const IDEMPOTENCY_RETENTION_MS = 7 * 86400000;
const isoTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const fail = (code, status = 400) => { throw new BridgeError(code, status); };
export const dailyMessage = envelope => ACCEPTED_PROTOCOLS.includes(envelope?.protocol);
export const messageScope = (role, kind) => SCOPES[role]?.[kind === 'ack' ? 'ack' : 'probe'];

// Text is data for a single inbox. It cannot choose a host task, endpoint,
// credential, tool or permission. The native receiver owns workflow approval.
export function validateMessage(input, principal, now = Date.now()) {
  const keys = ['protocol', 'id', 'from', 'to', 'kind', 'sentAt', 'expiresAt', 'threadId', 'route', 'text', 'correlationId',
    ...CLASS_FIELDS];
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).some(k => !keys.includes(k)) || !PEER_IDS.includes(principal?.role) ||
      !ACCEPTED_PROTOCOLS.includes(input.protocol) || !uuid.test(input.id || '') || !uuid.test(input.threadId || '') ||
      input.from !== principal.role || !PEER_IDS.includes(input.to) || input.to === input.from ||
      input.route !== 'inbox' || !['message', 'status', 'handoff_request', 'ack'].includes(input.kind)) fail('invalid_message');
  if (!principal.scopes?.includes(messageScope(principal.role, input.kind))) fail('insufficient_scope', 403);
  const classified = classification(input);
  const sentAt = Date.parse(input.sentAt), expiresAt = Date.parse(input.expiresAt);
  if (typeof input.sentAt !== 'string' || typeof input.expiresAt !== 'string' ||
      !isoTime.test(input.sentAt) || !isoTime.test(input.expiresAt) ||
      !Number.isSafeInteger(sentAt) || !Number.isSafeInteger(expiresAt) || Math.abs(now - sentAt) > 300000 ||
      expiresAt <= sentAt || expiresAt - sentAt > (input.class === 'sync' ? SYNC_MESSAGE_TTL_MS : MESSAGE_TTL_MS)) fail('invalid_message_lifetime');
  if (input.kind === 'ack' ? input.text !== undefined || !uuid.test(input.correlationId || '')
    : input.correlationId !== undefined || typeof input.text !== 'string' || !input.text.trim() ||
      Buffer.byteLength(input.text, 'utf8') > 4096) fail('invalid_message_content');
  const envelope = { protocol: MESSAGE_PROTOCOL, id: input.id.toLowerCase(), from: input.from, to: input.to,
    kind: input.kind, sentAt: new Date(sentAt).toISOString(), expiresAt: new Date(expiresAt).toISOString(),
    threadId: input.threadId.toLowerCase(), route: 'inbox',
    ...(input.kind === 'ack' ? { correlationId: input.correlationId.toLowerCase() } : { text: input.text }), ...classified };
  const serialized = JSON.stringify(envelope);
  if (Buffer.byteLength(serialized) > 8192) fail('message_too_large', 413);
  return { envelope, hash: createHash('sha256').update(serialized).digest('hex') };
}

// Optional delivery-class fields. Absent fields leave the v1 envelope (and its
// hash) byte-identical; they are only ever additive. ACKs carry none.
const CLASS_FIELDS = ['class', 'subject', 'effectiveAt', 'dueAt'];
function classification(input) {
  if (CLASS_FIELDS.every(k => input[k] === undefined)) return {};
  if (input.kind === 'ack' || (input.class !== undefined && !['wake', 'sync'].includes(input.class))) fail('invalid_message');
  const subject = input.subject;
  if (subject !== undefined && (typeof subject !== 'string' || !subject.trim() || subject.trim().length > 200 ||
      /[\u0000-\u001f\u007f]/.test(subject))) fail('invalid_message_content');
  const times = {};
  for (const field of ['effectiveAt', 'dueAt']) {
    if (input[field] === undefined) continue;
    const at = Date.parse(input[field]);
    if (typeof input[field] !== 'string' || !isoTime.test(input[field]) || !Number.isSafeInteger(at)) fail('invalid_message_schedule');
    times[field] = new Date(at).toISOString();
  }
  return { ...(input.class !== undefined ? { class: input.class } : {}),
    ...(subject !== undefined ? { subject: subject.trim() } : {}), ...times };
}

// Lazy bounded retention on ordinary authenticated storage transitions; no
// timer, receiving-agent poll, migration or provider credential is introduced.
// Synthetic history, subscription ciphertext and revocation tombstones survive.
export function retainMessages(state, now) {
  for (const [id, m] of Object.entries(state.messages)) {
    if (dailyMessage(m.envelope) && m.retainUntil <= now) {
      for (const jobId of m.jobIds) delete state.jobs[jobId];
      delete state.receipts[id]; delete state.messages[id];
    }
  }
  for (const [id, entry] of Object.entries(state.messageIds || {})) {
    if (entry.until <= now) delete state.messageIds[id];
  }
}
export function checkMessageCapacity(state) {
  if (Object.values(state.messages).filter(m => dailyMessage(m.envelope) && m.envelope.kind !== 'ack').length >= 100 ||
      Object.values(state.messageIds || {}).filter(m => m.kind !== 'ack').length >= 1000) fail('message_capacity_reached', 429);
}
export function reserveMessage(state, envelope, hash, now) {
  state.messageIds ||= {};
  if (state.messageIds[envelope.id]) fail('message_id_conflict', 409);
  // At most 100 live source messages + their 100 atomic ACKs. Seven-day
  // tombstones cap at 1,000 source IDs + their ACKs. Backpressure beats eviction
  // that would silently allow a replay or discard an unhandled request.
  if (envelope.kind !== 'ack') checkMessageCapacity(state);
  const original = envelope.kind === 'ack' ? state.messages[envelope.correlationId] : null;
  const until = original ? state.messageIds[envelope.correlationId].until : now + IDEMPOTENCY_RETENTION_MS;
  state.messageIds[envelope.id] = { hash, kind: envelope.kind, until };
  return original ? original.retainUntil : now + CONTENT_RETENTION_MS;
}
