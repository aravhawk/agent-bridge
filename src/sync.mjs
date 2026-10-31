import { createHash, randomUUID } from 'node:crypto';
import { MESSAGE_PROTOCOL, IDEMPOTENCY_RETENTION_MS, CONTENT_RETENTION_MS, dailyMessage, messageScope } from './messages.mjs';
import { messageAccessAllowed, resourceDenied } from './access.mjs';
import { resourceFor } from './resource.mjs';
import { appendDeliveryJobs } from './events.mjs';
import { PEER_IDS, counterpart } from './config.mjs';

// WAKE/SYNC delivery classes, default off. Only recipients named in
// BRIDGE_WAKE_SYNC_RECIPIENTS queue SYNC data and stop receiving ACK wakes.
// Everything else (and every unclassified message) keeps the v1 WAKE path.
export const WAKE_SYNC_FLAG = 'BRIDGE_WAKE_SYNC_RECIPIENTS';
// Maximum elapsed wait for queued SYNC data, measured from when the oldest
// pending item was queued (not in wall-clock hours, which DST stretches).
export const WAKE_WINDOW_MS = 2 * 3600000;
// Hourly scheduled runs (GitHub Actions) can start late. Anything effective,
// due or expiring within the 2h wait plus this slack is WAKE, not SYNC.
export const SCHEDULER_SLACK_MS = 30 * 60000;
export const SYNC_DEADLINE_MS = WAKE_WINDOW_MS + SCHEDULER_SLACK_MS;
// An unacknowledged batch is replayed for this long, then its unacknowledged
// items are queued again (flagged late) rather than abandoned.
export const SYNC_BATCH_TTL_MS = 12 * 3600000;
// Normal-day cap; see dailyFlushCap for the 25-hour fall-back day.
export const SYNC_DAILY_FLUSH_CAP = 12;
export const SYNC_TIME_ZONE = 'America/Chicago';
// bridge_receipt_complete accepts at most this many syncBatchIds. Every way a
// batch is attached to, or held by, one message stays within it, so the
// documented read -> claim -> complete flow always fits one completion.
export const MAX_SYNC_BATCH_IDS = 32;
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
// Boundaries can be three real hours apart (fall-back day), so the scheduled
// flush alone cannot bound the wait; flushDue also enforces WAKE_WINDOW_MS.
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
// Real hours in a Chicago calendar day: 23 (spring forward), 24 or 25 (fall back).
const dayHours = new Map();
export function chicagoDayHours(date) {
  if (!dayHours.has(date)) {
    const [y, m, d] = date.split('-').map(Number);
    let hours = 0;
    for (let u = Date.UTC(y, m - 1, d) - 12 * HOUR; u < Date.UTC(y, m - 1, d) + 36 * HOUR; u += HOUR) if (chicagoDate(u) === date) hours++;
    dayHours.set(date, hours);
  }
  return dayHours.get(date);
}
// With at most WAKE_WINDOW_MS between flushes under continuous traffic, a day
// needs ceil(hours / 2) batch wakes: 12 normally and on the spring-forward
// day, 13 on the fall-back day (e.g. 2026-11-01).
export const dailyFlushCap = date => Math.max(SYNC_DAILY_FLUSH_CAP, Math.ceil(chicagoDayHours(date) / 2));

// --- Classification ----------------------------------------------------------
// The sender chooses the class; an absent class is WAKE (v1 compatibility).
// SYNC is promoted to WAKE when its effectiveAt, dueAt or expiresAt falls at or
// before now + SYNC_DEADLINE_MS (the 2h maximum wait plus scheduler slack), so
// queued data is always delivered before it takes effect, is due or expires.
export function classify(envelope, now) {
  if (envelope.class !== 'sync') return { class: 'wake' };
  const deadline = now + SYNC_DEADLINE_MS;
  for (const [field, reason] of [['effectiveAt', 'effective_before_sync_deadline'], ['dueAt', 'due_before_sync_deadline'],
    ['expiresAt', 'expires_before_sync_deadline']]) {
    if (envelope[field] !== undefined && Date.parse(envelope[field]) <= deadline) return { class: 'wake', promoted: reason };
  }
  return { class: 'sync' };
}

// --- Pending SYNC queue ------------------------------------------------------
// state.syncQueues[recipient] = { pending: { subjectKey|id: messageId },
//   lastFlushBoundary, flushDay, flushCount, undispatched: [messageId] }.
// Created only once a SYNC item is queued, so flag-off state is unchanged.
// Item lifecycle (message.sync.state): pending -> delivered (in a batch, until
// that batch is acknowledged; or natively after a rollback, until completed) |
// superseded (newer same-subject update) | withdrawn (policy change or durable
// denial). Nothing is dropped for time: expired items are still delivered,
// flagged late. A queued or batch-carried item is handled only through its
// batch: its own claim is refused with a redirect (see syncItemClaimRedirect).
const queueOf = (state, recipient) => state.syncQueues?.[recipient];
const queueFor = (state, recipient) => (state.syncQueues ||= {})[recipient] ||= { pending: {} };
// queue.pending is keyed by slot: normally the subject key; an item whose
// order against a queued same-subject item is unknown keeps its own 'id:' slot.
const slotOf = sync => sync.slot ?? sync.key;
export function enqueueSync(state, message, now) {
  const { envelope } = message, queue = queueFor(state, envelope.to);
  const key = subjectKey(envelope.subject) ?? 'id:' + envelope.id;
  supersedePending(state, queue, key, envelope.id, now);
  queue.pending[key] = envelope.id;
  message.sync = { state: 'pending', key, queuedAt: now };
}
// A new admission is the newest update for its subject: every queued item
// with that subject (in any slot) is superseded.
function supersedePending(state, queue, key, byId, now, olderThan = null) {
  for (const [slot, id] of Object.entries(queue.pending)) {
    const prior = state.messages[id];
    if (prior?.sync?.state !== 'pending' || prior.sync.key !== key || (olderThan && admittedAfter(prior, olderThan) !== false)) continue;
    Object.assign(prior.sync, { state: 'superseded', supersededBy: byId, supersededAt: now });
    delete queue.pending[slot];
  }
}
// A WAKE with a subject is the newest update for that subject.
export function supersedeBySubject(state, envelope, now) {
  const queue = queueOf(state, envelope.to), key = subjectKey(envelope.subject);
  if (queue && key) supersedePending(state, queue, key, envelope.id, now);
}
// Data admitted by a verified sender under the current policy and not
// withdrawn by durable denial. Unlike messageAccessAllowed this does not end at
// the sender's access-token or the item's own expiry: queued data must still
// reach the recipient (flagged late). Policy change or denial still closes it.
function itemAllowed(state, message, policyIds) {
  const a = message?.authorization, e = message?.envelope;
  return dailyMessage(e) && !!a && a.role === e.from && /^[a-f0-9]{64}$/.test(a.owner || '') &&
    /^[a-f0-9]{64}$/.test(policyIds?.[e.from] || '') && a.policyId === policyIds[e.from] &&
    a.resource === resourceFor(e.from) && a.scope === messageScope(e.from, e.kind) && !resourceDenied(state, a.owner);
}
// Display/processing order only. Object key order is not durable (Postgres
// JSONB reorders keys), so ties are broken by ID here, and no supersede
// decision depends on this order.
const byId = (a, b) => (a.envelope.id < b.envelope.id ? -1 : a.envelope.id > b.envelope.id ? 1 : 0);
const batches = (state, recipient) => Object.values(state.messages)
  .filter(m => m.syncBatch?.recipient === recipient)
  .sort((a, b) => a.syncBatch.createdAt - b.syncBatch.createdAt || byId(a, b));
// Durable admission order. Every SYNC item and every subjected WAKE admitted
// for an enabled recipient gets the next value of one stored counter, in the
// same transaction that stores it, so two admissions in the same millisecond
// still have a strict order. (Unsubjected WAKEs never compete for a subject
// and keep the exact v1 record.)
export function stampAdmission(state, message) {
  message.syncSeq = state.syncAdmissionSeq = (Number.isSafeInteger(state.syncAdmissionSeq) ? state.syncAdmissionSeq : 0) + 1;
}
const stamped = m => Number.isSafeInteger(m.syncSeq);
// true: m was admitted after item; false: before; null: unknown. Only stored
// numbers are compared (acceptance time, then the admission sequence), never
// object key order. Unknown means the same millisecond with neither stamped:
// data admitted before the sequence existed, whose true order is not recorded
// anywhere and cannot be reconstructed.
function admittedAfter(m, item) {
  if (m.storedAt !== item.storedAt) return m.storedAt > item.storedAt;
  if (stamped(m) && stamped(item)) return m.syncSeq > item.syncSeq;
  return stamped(m) !== stamped(item) ? stamped(m) : null;
}
// Same-subject updates addressed to this recipient, other than item, that are
// not superseded or withdrawn: the newest one admitted after item, and whether
// any has an unknown order relative to it.
function orderAmong(state, item) {
  const { key } = item.sync;
  let newer = null, ambiguous = false;
  if (!key?.startsWith('s:')) return { newer, ambiguous };
  for (const m of Object.values(state.messages)) {
    if (m === item || m.syncBatch || m.envelope.to !== item.envelope.to || m.envelope.kind === 'ack' ||
        ['superseded', 'withdrawn'].includes(m.sync?.state) || (m.sync?.key ?? subjectKey(m.envelope.subject)) !== key) continue;
    const after = admittedAfter(m, item);
    if (after === null) ambiguous = true;
    else if (after && (!newer || admittedAfter(m, newer) === true)) newer = m;
  }
  return { newer, ambiguous };
}
// Put an undelivered or unhandled item back in the queue, unless a newer
// same-subject update exists (then it is superseded). Queued items it is newer
// than are superseded. Ordering is by admission, never by recovery or key
// order. When the order against another update is unknown (legacy tie), both
// are kept and flagged orderUnknown rather than guessing and discarding one.
function requeue(state, recipient, item, now, extra = {}) {
  const queue = queueFor(state, recipient), { key } = item.sync, { newer, ambiguous } = orderAmong(state, item);
  if (newer) { item.sync = { ...item.sync, state: 'superseded', supersededBy: newer.envelope.id, supersededAt: now }; return; }
  supersedePending(state, queue, key, item.envelope.id, now, item);
  if (ambiguous) {
    for (const id of Object.values(queue.pending)) {
      const peer = state.messages[id];
      if (peer?.sync?.state === 'pending' && peer.sync.key === key && admittedAfter(peer, item) === null) peer.sync.orderUnknown = true;
    }
  }
  const slot = queue.pending[key] ? 'id:' + item.envelope.id : key;
  queue.pending[slot] = item.envelope.id;
  item.sync = { state: 'pending', key, ...(slot !== key ? { slot } : {}), queuedAt: now,
    redeliveries: (item.sync.redeliveries || 0) + 1, ...(item.sync.nativeFailed ? { nativeFailed: true } : {}),
    ...(ambiguous || item.sync.orderUnknown ? { orderUnknown: true } : {}), ...extra };
}
// Unacknowledged batches whose replay lifetime is over: their unhandled items
// go back to the queue (a newer same-subject update supersedes them).
function reclaimExpired(state, recipient, now) {
  for (const batch of batches(state, recipient)) {
    const b = batch.syncBatch;
    if (b.ackedAt || b.reclaimedAt || Date.parse(batch.envelope.expiresAt) > now) continue;
    b.reclaimedAt = now;
    for (const id of b.itemIds) {
      const item = state.messages[id];
      if (item?.sync?.state !== 'delivered' || item.sync.batchId !== batch.envelope.id || state.receipts[id]?.state === 'complete') continue;
      requeue(state, recipient, item, now);
    }
  }
}
// Rollback re-sends items natively under their own IDs. If such an item is not
// completed and can no longer be delivered or claimed that way (its v1
// authority lapsed, or every native job is dead), it goes back to the queue for
// a derived batch instead of being stranded; it is never sent natively again.
function recoverNative(state, recipient, policyIds, now) {
  for (const item of Object.values(state.messages)) {
    if (item.envelope.to !== recipient || item.sync?.state !== 'delivered' || item.sync.via !== 'native') continue;
    const receipt = state.receipts[item.envelope.id];
    if (receipt?.state === 'complete' || (receipt?.leaseUntil > now && messageAccessAllowed(state, item, policyIds, now))) continue;
    const dead = item.jobIds.length > 0 && item.jobIds.every(id => !state.jobs[id] || state.jobs[id].state === 'dead');
    if (messageAccessAllowed(state, item, policyIds, now) && !dead) continue;
    requeue(state, recipient, item, now, { nativeFailed: true });
  }
}
// Bring a recipient's SYNC state up to date before any read, claim or flush.
export function reconcileSync(state, recipient, policyIds, now) {
  reclaimExpired(state, recipient, now);
  recoverNative(state, recipient, policyIds, now);
}
// Why an item may not be claimed on its own, or null when it may (no SYNC
// metadata, or re-sent natively after a rollback). Call after reconcileSync.
export function syncItemClaimRedirect(state, message) {
  const s = message.sync;
  if (!s || (s.state === 'delivered' && s.via === 'native')) return null;
  if (s.state === 'delivered' && s.batchId) return { code: 'sync_item_in_batch', details: { batchMessageId: s.batchId } };
  if (s.state === 'superseded') return { code: 'sync_item_superseded', details: { supersededBy: s.supersededBy } };
  return { code: 'sync_item_not_delivered' };
}
// Items of a batch whose receipt is a live claim other than claimId (only
// possible for claims written before item claims were fenced). While any
// exists, the batch can be neither claimed nor acknowledged.
export function batchItemsBusy(state, batch, claimId, now) {
  return (batch?.syncBatch?.itemIds || []).filter(id => {
    const receipt = state.receipts[id];
    return state.messages[id] && receipt?.state === 'claimed' && receipt.leaseUntil > now && receipt.claimId !== claimId;
  });
}
function livePending(state, recipient, policyIds, now) {
  reconcileSync(state, recipient, policyIds, now);
  const queue = queueOf(state, recipient), live = [];
  if (!queue) return live;
  for (const [key, id] of Object.entries(queue.pending)) {
    const message = state.messages[id];
    if (message?.sync?.state !== 'pending') { delete queue.pending[key]; continue; }
    if (!itemAllowed(state, message, policyIds)) {
      Object.assign(message.sync, { state: 'withdrawn', withdrawnAt: now }); delete queue.pending[key]; continue;
    }
    live.push(message);
  }
  return live.sort((a, b) => a.storedAt - b.storedAt || (a.syncSeq ?? 0) - (b.syncSeq ?? 0) || byId(a, b));
}
export function pendingCount(state, recipient) {
  return Object.keys(queueOf(state, recipient)?.pending || {}).length;
}
// Delivered but not yet acknowledged batches, oldest first; replayed by every
// inbox read until acknowledged (or reclaimed after SYNC_BATCH_TTL_MS).
export function outstandingBatches(state, recipient, now) {
  reclaimExpired(state, recipient, now);
  return batches(state, recipient).filter(m => !m.syncBatch.ackedAt && !m.syncBatch.reclaimedAt).map(m => m.envelope.id);
}

// --- Batches -----------------------------------------------------------------
// A batch is a stored v1 'status' message from the counterpart, so an
// unchanged receiver can read/claim/complete it from the usual
// {messageId} wake. Its text is a bounded digest; the full items are the
// additive `syncBatches` field of bridge_read/bridge_inbox_read and remain
// readable by ID. A batch counts as handled only once acknowledged after its
// full items were presented in a read result (see ackBatch).
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
  const expiresAt = now + SYNC_BATCH_TTL_MS;
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
  const late = items.filter(m => Date.parse(m.envelope.expiresAt) <= now || m.sync.redeliveries).map(m => m.envelope.id);
  state.messages[id] = { envelope, hash, storedAt: now, jobIds, authorization, retainUntil: now + CONTENT_RETENTION_MS,
    syncBatch: { recipient, itemIds: items.map(m => m.envelope.id), reason, createdAt: now, ...(late.length ? { lateItemIds: late } : {}) } };
  state.messageIds ||= {};
  state.messageIds[id] = { hash, kind: 'status', until: now + IDEMPOTENCY_RETENTION_MS };
  const queue = queueOf(state, recipient);
  for (const message of items) {
    delete queue.pending[slotOf(message.sync)];
    Object.assign(message.sync, { state: 'delivered', batchId: id, deliveredAt: now, via: reason });
    delete message.sync.slot;
  }
  return state.messages[id];
}
// Full item data for one batch. Returning it in a read result records that
// the receiver was given every item's text and ID (the precondition for ack).
export function presentBatch(state, batchId, now) {
  const batch = state.messages[batchId], b = batch?.syncBatch;
  if (!b) return null;
  b.presentedAt ??= now;
  return { messageId: batchId, reason: b.reason, createdAt: new Date(b.createdAt).toISOString(), acknowledged: !!b.ackedAt,
    items: b.itemIds.map(id => state.messages[id]).filter(Boolean).map(({ envelope: e, storedAt, sync }) => ({
      messageId: e.id, kind: e.kind, class: 'sync', ...(e.subject !== undefined ? { subject: e.subject } : {}),
      text: e.text, threadId: e.threadId, sentAt: e.sentAt, expiresAt: e.expiresAt,
      ...(e.effectiveAt !== undefined ? { effectiveAt: e.effectiveAt } : {}), ...(e.dueAt !== undefined ? { dueAt: e.dueAt } : {}),
      receivedAt: new Date(storedAt).toISOString(), expired: Date.parse(e.expiresAt) <= now,
      late: !!b.lateItemIds?.includes(e.id), orderUnknown: !!sync?.orderUnknown })) };
}
// Acknowledge a presented batch held by evidence.claimId: its receipt plus
// every item's receipt. The batch receipt must already be complete (direct
// completion, same transaction) or be a hold of that same claim; a receipt
// owned by any other claim, for the batch or an item, is never overwritten.
export function ackBatch(state, batchId, principal, now, evidence) {
  const batch = state.messages[batchId], b = batch?.syncBatch, held = state.receipts[batchId];
  if (!b?.presentedAt || b.ackedAt) return false;
  if (held?.state !== 'complete' && !(held?.state === 'claimed' && held.claimId === evidence.claimId)) return false;
  // Never finalize a batch while another live claim holds one of its items.
  if (batchItemsBusy(state, batch, evidence.claimId, now).length) return false;
  b.ackedAt = now;
  const receipt = { state: 'complete', owner: principal.principalKey, completedAt: now, ackMessageId: null,
    hostedEventId: evidence.hostedEventId, hostedTurnId: evidence.hostedTurnId,
    evidenceStatus: 'reported_requires_independent_host_confirmation', ackSuppressed: true };
  if (held.state !== 'complete') state.receipts[batchId] = { ...receipt, claimId: evidence.claimId, viaMessage: evidence.via };
  for (const id of b.itemIds) {
    // Covered already (completed by its own claim) or stale (lapsed lease).
    if (!state.messages[id] || state.receipts[id]?.state === 'complete') continue;
    state.receipts[id] = { ...receipt, viaBatch: batchId };
  }
  return true;
}

// Stranded piggyback batches: carried by another message (no delivery jobs of
// their own), never presented, not acknowledged, reclaimed or re-homed, and
// whose carrier can no longer get them read: the carrier's v1 authority lapsed
// or it was withdrawn, all its delivery jobs are dead, it was completed without
// the batch being presented, it is gone, or it has gone unread for the 2-hour
// wait. Such a batch keeps its identity and its single shared claim record;
// flushDue only gives it a new carrier. A carrier read in time keeps it.
function strandedBatches(state, recipient, policyIds, now) {
  return batches(state, recipient).filter(batch => {
    const b = batch.syncBatch;
    if (batch.jobIds.length || b.presentedAt || b.ackedAt || b.reclaimedAt || b.rehomedTo) return false;
    const carrier = Object.values(state.messages).find(m => m !== batch && m.syncBatchIds?.includes(batch.envelope.id));
    if (!carrier || now - b.createdAt >= WAKE_WINDOW_MS) return true;
    const dead = carrier.jobIds.length > 0 && carrier.jobIds.every(id => !state.jobs[id] || state.jobs[id].state === 'dead');
    return dead || state.receipts[carrier.envelope.id]?.state === 'complete' ||
      !messageAccessAllowed(state, carrier, policyIds, now);
  });
}
// How many more batches a message may carry: the completion limit less its own
// ID (when it is itself a batch) and its attached batches still awaiting
// acknowledgement. Acknowledged or reclaimed attachments no longer count.
export function attachRoom(state, message) {
  const open = (message.syncBatchIds || []).filter(id => {
    const b = state.messages[id]?.syncBatch;
    return b && !b.ackedAt && !b.reclaimedAt;
  }).length;
  return MAX_SYNC_BATCH_IDS - (message.syncBatch ? 1 : 0) - open;
}
const strandedItems = (state, stranded) => stranded.flatMap(batch => batch.syncBatch.itemIds.map(id => state.messages[id]).filter(Boolean));

// Hourly flush (any hour; the trigger runs at :00 UTC). Per recipient with
// pending items or stranded piggyback batches, flush one batch when:
//   scheduled - an America/Chicago even-hour boundary has passed since the last
//               flush with items queued before it (late runs still deliver);
//   max_wait  - waiting for the next hourly run would push the oldest pending
//               item past WAKE_WINDOW_MS of elapsed time (DST, missed runs);
//   expiring  - an item expires before the next run plus slack (or already did).
// Otherwise the run is a no-op; empty queues send nothing. At most
// dailyFlushCap(day) batch wakes per recipient per Chicago day. A recipient no
// longer enabled (rollback) gets its leftovers re-sent under their own message
// IDs where their v1 authority still allows, otherwise in one batch. Stranded
// piggyback batches count as due data: they ride the flush batch (attached,
// as with a WAKE), or, with nothing else due, the oldest one is delivered on
// its own; either way one wake and one daily-cap slot.
export function flushDue(state, now, { policyIds, recipients = [] }) {
  const boundary = latestFlushBoundary(now), nextRun = Math.floor(now / HOUR) * HOUR + HOUR;
  const day = chicagoDate(now), results = [];
  for (const recipient of PEER_IDS) {
    const queue = queueOf(state, recipient);
    if (!queue) continue;
    let live = livePending(state, recipient, policyIds, now);
    const stranded = strandedBatches(state, recipient, policyIds, now);
    if (!live.length && !stranded.length) continue;
    let reason;
    if (!recipients.includes(recipient)) {
      const native = [];
      for (const item of live) {
        if (item.sync.nativeFailed || !messageAccessAllowed(state, item, policyIds, now)) continue;
        const jobIds = appendDeliveryJobs(state, item.envelope, now);
        if (!jobIds.length) continue;
        item.jobIds = jobIds; native.push(item.envelope.id);
        delete queue.pending[slotOf(item.sync)];
        Object.assign(item.sync, { state: 'delivered', via: 'native', deliveredAt: now });
        delete item.sync.slot;
      }
      if (native.length) { (queue.undispatched ||= []).push(...native); results.push({ recipient, outcome: 'native', items: native.length }); }
      live = live.filter(item => !native.includes(item.envelope.id));
      if (!live.length && !stranded.length) continue;
      reason = 'rollback';
    } else {
      const due = [...live, ...strandedItems(state, stranded)];
      const oldest = Math.min(...due.map(m => m.sync?.queuedAt ?? m.storedAt));
      reason = boundary > (queue.lastFlushBoundary ?? -Infinity) && oldest < boundary ? 'scheduled'
        : nextRun > oldest + WAKE_WINDOW_MS ? 'max_wait'
          : due.some(m => Date.parse(m.envelope.expiresAt) <= nextRun + SCHEDULER_SLACK_MS) ? 'expiring' : null;
      if (!reason) continue;
      if (queue.flushDay !== day) { queue.flushDay = day; queue.flushCount = 0; }
      if (queue.flushCount >= dailyFlushCap(day)) { results.push({ recipient, outcome: 'daily_cap' }); continue; }
    }
    let batch = live.length ? cutBatch(state, recipient, now, { reason: 'flush', policyIds, deliver: true }) : null;
    let carried = stranded;
    if (!live.length) {
      // Nothing new: the oldest stranded batch is delivered on its own and
      // carries any others.
      const jobIds = appendDeliveryJobs(state, stranded[0].envelope, now);
      if (jobIds.length) { batch = stranded[0]; batch.jobIds = jobIds; carried = stranded.slice(1); }
    }
    // No active destination: keep items pending (held past retention) and retry next run.
    if (!batch) { results.push({ recipient, outcome: 'no_destination' }); continue; }
    // Attach only what fits one completion, oldest first. The rest stay
    // stranded, unchanged and unmarked, and are due again at the next run.
    const fitting = carried.slice(0, Math.max(0, attachRoom(state, batch)));
    for (const other of fitting) {
      (batch.syncBatchIds ||= []).push(other.envelope.id);
      Object.assign(other.syncBatch, { rehomedTo: batch.envelope.id, rehomedAt: now });
    }
    const rehomed = fitting.length + (batch === stranded[0] ? 1 : 0);
    if (batch === stranded[0]) Object.assign(batch.syncBatch, { rehomedTo: batch.envelope.id, rehomedAt: now });
    batch.syncBatch.trigger = reason;
    queue.lastFlushBoundary = boundary;
    if (reason !== 'rollback') queue.flushCount++;
    (queue.undispatched ||= []).push(batch.envelope.id);
    results.push({ recipient, outcome: 'flushed', reason, items: live.length ? batch.syncBatch.itemIds.length : 0,
      ...(rehomed ? { rehomedBatches: rehomed } : {}) });
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
