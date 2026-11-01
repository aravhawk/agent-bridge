import { createHash } from 'node:crypto';
import { BridgeError, SCOPES } from './policy.ts';
import { CONFIG, PEER_IDS } from './config.ts';
import type { BridgeState, DailyEnvelope, DailyKind, Envelope, JsonObject, Millis, Principal, Role, StoredMessage } from './types.ts';

/**
 * The untrusted message body viewed with the types its validators establish.
 * Each use is an erasure-only assertion: the JavaScript expressions (and their
 * coercions or TypeErrors on unexpected input) are exactly the original ones.
 */
interface MessageInput {
  protocol: string; id: string; from: Role; to: Role; kind: DailyKind; sentAt: string; expiresAt: string; threadId: string;
  route: 'inbox'; text: string; correlationId: string; class: 'wake' | 'sync'; subject: string; effectiveAt: string; dueAt: string;
  attachmentIds: string[];
}
type In = MessageInput & JsonObject;
export interface ValidatedMessage { envelope: DailyEnvelope; hash: string }

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
// Explicitly typed so a bare fail(...) statement narrows control flow.
const fail: (code: string, status?: number) => never = (code, status = 400) => { throw new BridgeError(code, status); };
/** A daily (v1 protocol) envelope, as opposed to a synthetic probe envelope. */
export const dailyMessage = (envelope: { protocol?: string | undefined } | null | undefined): envelope is DailyEnvelope =>
  ACCEPTED_PROTOCOLS.includes(envelope?.protocol as string);
export const messageScope = (role: Role | undefined, kind: string | undefined): string | undefined =>
  SCOPES[role as Role]?.[kind === 'ack' ? 'ack' : 'probe'];

// Text is data for a single inbox. It cannot choose a host task, endpoint,
// credential, tool or permission. The native receiver owns workflow approval.
export function validateMessage(input: unknown, principal: Principal | null | undefined, now = Date.now()): ValidatedMessage {
  const keys = ['protocol', 'id', 'from', 'to', 'kind', 'sentAt', 'expiresAt', 'threadId', 'route', 'text', 'correlationId',
    ...CLASS_FIELDS, 'attachmentIds'];
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input as In).some(k => !keys.includes(k)) || !PEER_IDS.includes(principal?.role as Role) ||
      !ACCEPTED_PROTOCOLS.includes((input as In).protocol) || !uuid.test((input as In).id || '') || !uuid.test((input as In).threadId || '') ||
      (input as In).from !== principal!.role || !PEER_IDS.includes((input as In).to) || (input as In).to === (input as In).from ||
      (input as In).route !== 'inbox' || !['message', 'status', 'handoff_request', 'ack'].includes((input as In).kind)) fail('invalid_message');
  // The validity check above refused a missing principal.
  if (!principal!.scopes?.includes(messageScope(principal!.role, (input as In).kind) as string)) fail('insufficient_scope', 403);
  const classified = classification(input as In), attached = attachmentRefs(input as In);
  const sentAt = Date.parse((input as In).sentAt), expiresAt = Date.parse((input as In).expiresAt);
  if (typeof (input as In).sentAt !== 'string' || typeof (input as In).expiresAt !== 'string' ||
      !isoTime.test((input as In).sentAt) || !isoTime.test((input as In).expiresAt) ||
      !Number.isSafeInteger(sentAt) || !Number.isSafeInteger(expiresAt) || Math.abs(now - sentAt) > 300000 ||
      expiresAt <= sentAt || expiresAt - sentAt > ((input as In).class === 'sync' ? SYNC_MESSAGE_TTL_MS : MESSAGE_TTL_MS)) fail('invalid_message_lifetime');
  if ((input as In).kind === 'ack' ? (input as In).text !== undefined || !uuid.test((input as In).correlationId || '')
    : (input as In).correlationId !== undefined || typeof (input as In).text !== 'string' || !(input as In).text.trim() ||
      Buffer.byteLength((input as In).text, 'utf8') > 4096) fail('invalid_message_content');
  const envelope: DailyEnvelope = { protocol: MESSAGE_PROTOCOL, id: (input as In).id.toLowerCase(), from: (input as In).from, to: (input as In).to,
    kind: (input as In).kind, sentAt: new Date(sentAt).toISOString(), expiresAt: new Date(expiresAt).toISOString(),
    threadId: (input as In).threadId.toLowerCase(), route: 'inbox',
    ...((input as In).kind === 'ack' ? { correlationId: (input as In).correlationId.toLowerCase() } : { text: (input as In).text }), ...classified,
    ...attached };
  const serialized = JSON.stringify(envelope);
  if (Buffer.byteLength(serialized) > 8192) fail('message_too_large', 413);
  return { envelope, hash: createHash('sha256').update(serialized).digest('hex') };
}

// Optional attachment references (IDs only; bytes never enter a message).
// Shape only here: ownership, state, recipient, policy and namespace are
// admitted by the attachment capability inside the message transactions.
export const MAX_MESSAGE_ATTACHMENTS = 4;
function attachmentRefs(input: In): { attachmentIds?: string[] } {
  if (input.attachmentIds === undefined) return {};
  const ids = input.attachmentIds;
  if (input.kind === 'ack' || !Array.isArray(ids) || ids.length < 1 || ids.length > MAX_MESSAGE_ATTACHMENTS ||
      ids.some(id => typeof id !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(id)) ||
      new Set(ids.map(id => id.toLowerCase())).size !== ids.length) fail('invalid_message');
  return { attachmentIds: ids.map(id => id.toLowerCase()) };
}

// Optional delivery-class fields. Absent fields leave the v1 envelope (and its
// hash) byte-identical; they are only ever additive. ACKs carry none.
const CLASS_FIELDS = ['class', 'subject', 'effectiveAt', 'dueAt'];
type Classification = Pick<DailyEnvelope, 'class' | 'subject' | 'effectiveAt' | 'dueAt'>;
function classification(input: In): Classification {
  if (CLASS_FIELDS.every(k => input[k] === undefined)) return {};
  if (input.kind === 'ack' || (input.class !== undefined && !['wake', 'sync'].includes(input.class))) fail('invalid_message');
  const subject = input.subject;
  if (subject !== undefined && (typeof subject !== 'string' || !subject.trim() || subject.trim().length > 200 ||
      /[\u0000-\u001f\u007f]/.test(subject))) fail('invalid_message_content');
  const times: Pick<DailyEnvelope, 'effectiveAt' | 'dueAt'> = {};
  for (const field of ['effectiveAt', 'dueAt'] as const) {
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
// SYNC data that is still pending, or in a batch not yet acknowledged, is held
// past content retention (bounded by SYNC_HOLD_MS and capacity backpressure)
// so queued context is never silently purged before the recipient has it.
export const SYNC_HOLD_MS = 6 * 86400000;
function heldForSync(state: BridgeState, m: StoredMessage, now: Millis): boolean {
  if (!(m.storedAt + SYNC_HOLD_MS > now)) return false;
  if (m.sync?.state === 'pending') return true;
  // Re-sent natively after a rollback: held until completed or recovered.
  if (m.sync?.state === 'delivered' && m.sync.via === 'native') return state.receipts[m.envelope.id]?.state !== 'complete';
  const batch = m.syncBatch ? m : m.sync?.state === 'delivered' && m.sync.batchId ? state.messages[m.sync.batchId] : null;
  return !!batch?.syncBatch && !batch.syncBatch.ackedAt && !batch.syncBatch.reclaimedAt;
}
export function retainMessages(state: BridgeState, now: Millis): void {
  for (const [id, m] of Object.entries(state.messages)) {
    // Daily messages always record retainUntil.
    if (dailyMessage(m.envelope) && (m.retainUntil as Millis) <= now && !heldForSync(state, m, now)) {
      for (const jobId of m.jobIds) delete state.jobs[jobId];
      delete state.receipts[id]; delete state.messages[id];
    }
  }
  for (const [id, entry] of Object.entries(state.messageIds || {})) {
    if (entry.until <= now) delete state.messageIds![id];
  }
}
export function checkMessageCapacity(state: BridgeState): void {
  if (Object.values(state.messages).filter(m => dailyMessage(m.envelope) && m.envelope.kind !== 'ack').length >= 100 ||
      Object.values(state.messageIds || {}).filter(m => m.kind !== 'ack').length >= 1000) fail('message_capacity_reached', 429);
}
export function reserveMessage(state: BridgeState, envelope: Envelope, hash: string, now: Millis): Millis | undefined {
  state.messageIds ||= {};
  if (state.messageIds[envelope.id]) fail('message_id_conflict', 409);
  // At most 100 live source messages + their 100 atomic ACKs. Seven-day
  // tombstones cap at 1,000 source IDs + their ACKs. Backpressure beats eviction
  // that would silently allow a replay or discard an unhandled request.
  if (envelope.kind !== 'ack') checkMessageCapacity(state);
  // An ACK carries correlationId; its original's ID entry was reserved by this same path.
  const original = envelope.kind === 'ack' ? state.messages[envelope.correlationId as string] : null;
  const until = original ? state.messageIds[envelope.correlationId as string]!.until : now + IDEMPOTENCY_RETENTION_MS;
  state.messageIds[envelope.id] = { hash, kind: envelope.kind, until };
  return original ? original.retainUntil : now + CONTENT_RETENTION_MS;
}
