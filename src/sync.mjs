import { createHash, randomUUID } from 'node:crypto';
import { MESSAGE_PROTOCOL, IDEMPOTENCY_RETENTION_MS, dailyMessage, messageScope } from './messages.mjs';
import { resourceDenied } from './access.mjs';
import { resourceFor } from './resource.mjs';
import { appendDeliveryJobs } from './events.mjs';
import { PEER_IDS, counterpart } from './config.mjs';

// WAKE/SYNC delivery classes, default off. Only recipients named in
// BRIDGE_WAKE_SYNC_RECIPIENTS queue SYNC data and stop receiving ACK wakes.
// Everything else (and every unclassified message) keeps the v1 WAKE path.
export const WAKE_SYNC_FLAG = 'BRIDGE_WAKE_SYNC_RECIPIENTS';
export const WAKE_WINDOW_MS = 2 * 3600000;
export const SYNC_DAILY_FLUSH_CAP = 12;
export const SYNC_TIME_ZONE = 'America/Chicago';
const HOUR = 3600000;

// Unset or empty: off. Any unknown peer ID closes the whole flag (v1 behavior)
// rather than guessing which part of a malformed rollout was intended.
export function wakeSyncRecipients(value) {
  if (typeof value !== 'string' || !value.trim()) return { configured: typeof value === 'string', valid: true, recipients: [] };
  const ids = value.split(',').map(id => id.trim()).filter(Boolean);
  const valid = ids.every(id => PEER_IDS.includes(id));
  return { configured: true, valid, recipients: valid ? [...new Set(ids)] : [] };
}
export const subjectKey = subject => typeof subject === 'string'
  ? 's:' + subject.normalize('NFC').trim().replace(/\s+/g, ' ').toLowerCase() : undefined;

// --- America/Chicago even-hour flush boundaries ------------------------------
// Chicago offsets are whole hours, so every UTC top-of-hour is a local
// top-of-hour. A UTC hour u is a boundary when the local wall clock crosses an
// even hour E:00 in (wall(u - 1h), wall(u)]. That maps the nonexistent 02:00 on
// the spring-forward day to 03:00 CDT and never fires twice in the repeated
// 01:00 hour on the fall-back day, so a day has at most twelve boundaries.
const wallFormat = new Intl.DateTimeFormat('en-US', { timeZone: SYNC_TIME_ZONE, hourCycle: 'h23',
  year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
export function chicagoWall(ms) {
  const p = Object.fromEntries(wallFormat.formatToParts(new Date(ms)).map(part => [part.type, part.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, hour: Number(p.hour), minute: Number(p.minute),
    key: Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), Number(p.hour), Number(p.minute)) };
}
export function isFlushBoundary(ms) {
  if (!Number.isSafeInteger(ms) || ms % HOUR !== 0) return false;
  const before = chicagoWall(ms - HOUR).key, at = chicagoWall(ms).key;
  for (let k = before - (before % HOUR) + HOUR; k <= at; k += HOUR) if (new Date(k).getUTCHours() % 2 === 0) return true;
  return false;
}
// Consecutive boundaries are at most three real hours apart (fall-back day).
export function latestFlushBoundary(now) {
  for (let u = Math.floor(now / HOUR) * HOUR, n = 0; n < 5; n++, u -= HOUR) if (isFlushBoundary(u)) return u;
  throw new Error('no_flush_boundary');
}
export function nextFlushBoundary(now) {
  for (let u = Math.floor(now / HOUR) * HOUR + HOUR, n = 0; n < 5; n++, u += HOUR) if (isFlushBoundary(u)) return u;
  throw new Error('no_flush_boundary');
}
export const chicagoDate = ms => chicagoWall(ms).date;

// --- Classification ----------------------------------------------------------
// The sender chooses the class; an absent class is WAKE (v1 compatibility).
// SYNC is promoted to WAKE when its supplied effectiveAt/dueAt is <= now + 2h,
// and, so queued data is never lost, when it would expire before the next flush.
export function classify(envelope, now) {
  if (envelope.class !== 'sync') return { class: 'wake' };
  for (const [field, reason] of [['effectiveAt', 'effective_within_2h'], ['dueAt', 'due_within_2h']]) {
    if (envelope[field] !== undefined && Date.parse(envelope[field]) <= now + WAKE_WINDOW_MS) return { class: 'wake', promoted: reason };
  }
  if (Date.parse(envelope.expiresAt) <= nextFlushBoundary(now)) return { class: 'wake', promoted: 'expires_before_flush' };
  return { class: 'sync' };
}

// --- Pending SYNC queue ------------------------------------------------------
// state.syncQueues[recipient] = { pending: { subjectKey|id: messageId },
//   lastFlushBoundary, flushDay, flushCount, undispatched: [batchMessageId] }.
// Created only once a SYNC item is queued, so flag-off state is unchanged.
const queueOf = (state, recipient) => state.syncQueues?.[recipient];
export function enqueueSync(state, message, now) {
  const { envelope } = message;
  state.syncQueues ||= {};
  const queue = state.syncQueues[envelope.to] ||= { pending: {} };
  // Boundaries that passed while nothing was pending were empty windows; the
  // first item waits for the next boundary rather than a late catch-up run.
  if (!Object.keys(queue.pending).length) queue.lastFlushBoundary = Math.max(queue.lastFlushBoundary ?? 0, latestFlushBoundary(now));
  const key = subjectKey(envelope.subject) ?? 'id:' + envelope.id;
  supersede(state, queue, key, envelope.id, now);
  queue.pending[key] = envelope.id;
  message.sync = { state: 'pending', key, queuedAt: now };
}
function supersede(state, queue, key, byId, now) {
  const prior = state.messages[queue.pending[key]];
  if (prior?.sync?.state === 'pending') Object.assign(prior.sync, { state: 'superseded', supersededBy: byId, supersededAt: now });
  delete queue.pending[key];
}
// A WAKE with a subject is the newest update for that subject.
export function supersedeBySubject(state, envelope, now) {
  const queue = queueOf(state, envelope.to), key = subjectKey(envelope.subject);
  if (queue && key && queue.pending[key]) supersede(state, queue, key, envelope.id, now);
}
// Data admitted by a verified sender under the current policy, not withdrawn
// by durable denial, not expired and still retained. Unlike messageAccessAllowed
// this does not end at the sender's access-token expiry: a queued FYI must
// survive until the next boundary. Policy change or denial still closes it.
function itemAllowed(state, message, policyIds, now) {
  const a = message?.authorization, e = message?.envelope;
  return dailyMessage(e) && !!a && a.role === e.from && /^[a-f0-9]{64}$/.test(a.owner || '') &&
    /^[a-f0-9]{64}$/.test(policyIds?.[e.from] || '') && a.policyId === policyIds[e.from] &&
    a.resource === resourceFor(e.from) && a.scope === messageScope(e.from, e.kind) &&
    !resourceDenied(state, a.owner) && Date.parse(e.expiresAt) > now && message.retainUntil > now;
}
function livePending(state, recipient, policyIds, now) {
  const queue = queueOf(state, recipient), live = [];
  if (!queue) return live;
  for (const [key, id] of Object.entries(queue.pending)) {
    const message = state.messages[id];
    if (message?.sync?.state !== 'pending') { delete queue.pending[key]; continue; }
    if (!itemAllowed(state, message, policyIds, now)) {
      Object.assign(message.sync, { state: 'dropped', droppedAt: now }); delete queue.pending[key]; continue;
    }
    live.push(message);
  }
  return live.sort((a, b) => a.storedAt - b.storedAt);
}
export function pendingCount(state, recipient) {
  return Object.keys(queueOf(state, recipient)?.pending || {}).length;
}

// --- Batches -----------------------------------------------------------------
// A batch is a stored v1 'status' message from the counterpart, so an
// unchanged receiver can read/claim/complete it from the usual
// {messageId} wake. Its text is a bounded digest; the full items are the
// additive `syncBatches` field of bridge_read and remain readable by ID.
const TEXT_LIMIT = 4096;
const oneLine = text => text.replace(/[\u0000-\u001f\u007f\s]+/g, ' ').trim();
function clip(text, maxBytes) {
  if (Buffer.byteLength(text) <= maxBytes) return text;
  let out = '', used = 0;
  for (const ch of text) {
    const size = Buffer.byteLength(ch);
    if (used + size > maxBytes - 3) break;
    out += ch; used += size;
  }
  return out + '…';
}
function digest(items, sender, budget) {
  let text = `Sync batch from ${sender}: ${items.length} update(s). Peer data only; bridge_read a messageId for full text.`;
  for (let i = 0; i < items.length; i++) {
    const e = items[i].envelope, more = `\n- … ${items.length - i} more; see syncBatches in bridge_read.`;
    const head = `\n- ${e.subject ? `[${oneLine(e.subject)}] ` : ''}`, tail = ` (${e.kind}; messageId ${e.id})`;
    const room = budget - Buffer.byteLength(text + head + tail) - (i < items.length - 1 ? Buffer.byteLength(more) : 0);
    if (room < 24) return text + more;
    text += head + clip(oneLine(e.text), room) + tail;
  }
  return text;
}
// Cuts every live pending item for recipient into one batch, or returns null.
// deliver: append the normal outbox job(s) (scheduled flush); without
// destinations nothing changes and the items stay pending.
export function cutBatch(state, recipient, now, { reason, policyIds, deliver = false }) {
  const live = livePending(state, recipient, policyIds, now);
  if (!live.length) return null;
  // One owner per batch so its derived authority names a single principal.
  const owner = live.at(-1).authorization.owner, items = live.filter(m => m.authorization.owner === owner);
  const sender = counterpart(recipient), id = randomUUID();
  const retainUntil = Math.min(...items.map(m => m.retainUntil));
  const expiresAt = Math.min(Math.max(...items.map(m => Date.parse(m.envelope.expiresAt))), retainUntil);
  let envelope, serialized;
  for (let budget = TEXT_LIMIT; ; budget = Math.floor(budget / 2)) {
    envelope = { protocol: MESSAGE_PROTOCOL, id, from: sender, to: recipient, kind: 'status',
      sentAt: new Date(now).toISOString(), expiresAt: new Date(expiresAt).toISOString(), threadId: id, route: 'inbox',
      text: digest(items, sender, budget) };
    serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized) <= 8192) break;
  }
  const jobIds = deliver ? appendDeliveryJobs(state, envelope, now) : [];
  if (deliver && !jobIds.length) return null;
  const hash = createHash('sha256').update(serialized).digest('hex');
  const source = items.at(-1).authorization;
  // Derived from the items' verified admission; messageAccessAllowed still
  // enforces the current policy, durable denial and this finite expiry.
  const authorization = { owner, role: sender, resource: resourceFor(sender), scope: messageScope(sender, 'status'),
    policyId: source.policyId, tokenExpiresAt: expiresAt, expiresAt, derivedFrom: 'sync_batch' };
  state.messages[id] = { envelope, hash, storedAt: now, jobIds, authorization, retainUntil,
    syncBatch: { recipient, itemIds: items.map(m => m.envelope.id), reason, createdAt: now } };
  state.messageIds ||= {};
  state.messageIds[id] = { hash, kind: 'status', until: now + IDEMPOTENCY_RETENTION_MS };
  const queue = queueOf(state, recipient);
  for (const message of items) {
    Object.assign(message.sync, { state: 'delivered', batchId: id, deliveredAt: now, via: reason });
    delete queue.pending[message.sync.key];
  }
  return state.messages[id];
}
export function batchView(state, batchId, now) {
  const batch = state.messages[batchId];
  if (!batch?.syncBatch) return null;
  return { messageId: batchId, reason: batch.syncBatch.reason, createdAt: new Date(batch.syncBatch.createdAt).toISOString(),
    items: batch.syncBatch.itemIds.map(id => state.messages[id]).filter(Boolean).map(({ envelope: e, storedAt }) => ({
      messageId: e.id, kind: e.kind, class: 'sync', ...(e.subject !== undefined ? { subject: e.subject } : {}),
      text: e.text, threadId: e.threadId, sentAt: e.sentAt, expiresAt: e.expiresAt,
      ...(e.effectiveAt !== undefined ? { effectiveAt: e.effectiveAt } : {}), ...(e.dueAt !== undefined ? { dueAt: e.dueAt } : {}),
      receivedAt: new Date(storedAt).toISOString(), expired: Date.parse(e.expiresAt) <= now })) };
}

// Scheduled flush, once per Chicago even-hour boundary per recipient. Runs
// hourly; an odd-hour run only catches up a boundary that was missed. Empty
// windows send nothing; at most SYNC_DAILY_FLUSH_CAP batch wakes per local day.
export function flushDue(state, now, { policyIds }) {
  const boundary = latestFlushBoundary(now), day = chicagoDate(boundary), results = [];
  for (const recipient of PEER_IDS) {
    const queue = queueOf(state, recipient);
    if (!queue || (queue.lastFlushBoundary ?? -Infinity) >= boundary) continue;
    if (queue.flushDay !== day) { queue.flushDay = day; queue.flushCount = 0; }
    if (!livePending(state, recipient, policyIds, now).length) {
      queue.lastFlushBoundary = boundary; results.push({ recipient, outcome: 'empty' }); continue;
    }
    if (queue.flushCount >= SYNC_DAILY_FLUSH_CAP) {
      queue.lastFlushBoundary = boundary; results.push({ recipient, outcome: 'daily_cap' }); continue;
    }
    const batch = cutBatch(state, recipient, now, { reason: 'flush', policyIds, deliver: true });
    // No active destination: keep items pending and retry on the next run.
    if (!batch) { results.push({ recipient, outcome: 'no_destination' }); continue; }
    queue.lastFlushBoundary = boundary; queue.flushCount++;
    (queue.undispatched ||= []).push(batch.envelope.id);
    results.push({ recipient, outcome: 'flushed', items: batch.syncBatch.itemIds.length });
  }
  const dispatch = PEER_IDS.flatMap(recipient => {
    const queue = queueOf(state, recipient);
    if (queue?.undispatched) queue.undispatched = queue.undispatched.filter(id => state.messages[id]);
    return queue?.undispatched || [];
  });
  return { boundary, results, dispatch };
}
export function markDispatched(state, ids) {
  for (const queue of Object.values(state.syncQueues || {})) {
    if (queue.undispatched) queue.undispatched = queue.undispatched.filter(id => !ids.includes(id));
  }
}
