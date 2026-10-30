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
// that batch is acknowledged) | superseded (newer same-subject update) |
// withdrawn (policy change or durable denial). Nothing is dropped for time:
// expired items are still delivered, flagged late.
const queueOf = (state, recipient) => state.syncQueues?.[recipient];
const queueFor = (state, recipient) => (state.syncQueues ||= {})[recipient] ||= { pending: {} };
export function enqueueSync(state, message, now) {
  const { envelope } = message, queue = queueFor(state, envelope.to);
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
const batches = (state, recipient) => Object.values(state.messages)
  .filter(m => m.syncBatch?.recipient === recipient).sort((a, b) => a.syncBatch.createdAt - b.syncBatch.createdAt);
// Unacknowledged batches whose replay lifetime is over: their unacknowledged
// items go back to the queue (a newer same-subject item supersedes them).
function reclaimExpired(state, recipient, now) {
  for (const batch of batches(state, recipient)) {
    const b = batch.syncBatch;
    if (b.ackedAt || b.reclaimedAt || Date.parse(batch.envelope.expiresAt) > now) continue;
    b.reclaimedAt = now;
    const queue = queueFor(state, recipient);
    for (const id of b.itemIds) {
      const item = state.messages[id];
      if (item?.sync?.state !== 'delivered' || item.sync.batchId !== batch.envelope.id || state.receipts[id]?.state === 'complete') continue;
      const { key } = item.sync, newer = state.messages[queue.pending[key]];
      if (newer?.sync?.state === 'pending') { Object.assign(item.sync, { state: 'superseded', supersededBy: newer.envelope.id, supersededAt: now }); continue; }
      queue.pending[key] = id;
      item.sync = { state: 'pending', key, queuedAt: now, redeliveries: (item.sync.redeliveries || 0) + 1 };
    }
  }
}
function livePending(state, recipient, policyIds, now) {
  reclaimExpired(state, recipient, now);
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
  return live.sort((a, b) => a.storedAt - b.storedAt);
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
    Object.assign(message.sync, { state: 'delivered', batchId: id, deliveredAt: now, via: reason });
    delete queue.pending[message.sync.key];
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
    items: b.itemIds.map(id => state.messages[id]).filter(Boolean).map(({ envelope: e, storedAt }) => ({
      messageId: e.id, kind: e.kind, class: 'sync', ...(e.subject !== undefined ? { subject: e.subject } : {}),
      text: e.text, threadId: e.threadId, sentAt: e.sentAt, expiresAt: e.expiresAt,
      ...(e.effectiveAt !== undefined ? { effectiveAt: e.effectiveAt } : {}), ...(e.dueAt !== undefined ? { dueAt: e.dueAt } : {}),
      receivedAt: new Date(storedAt).toISOString(), expired: Date.parse(e.expiresAt) <= now,
      late: !!b.lateItemIds?.includes(e.id) })) };
}
// Acknowledge a presented batch held by evidence.claimId: its receipt plus
// every item's receipt. The batch receipt must already be complete (direct
// completion, same transaction) or be a hold of that same claim; a receipt
// owned by any other claim, for the batch or an item, is never overwritten.
export function ackBatch(state, batchId, principal, now, evidence) {
  const batch = state.messages[batchId], b = batch?.syncBatch, held = state.receipts[batchId];
  if (!b?.presentedAt || b.ackedAt) return false;
  if (held?.state !== 'complete' && !(held?.state === 'claimed' && held.claimId === evidence.claimId)) return false;
  b.ackedAt = now;
  const receipt = { state: 'complete', owner: principal.principalKey, completedAt: now, ackMessageId: null,
    hostedEventId: evidence.hostedEventId, hostedTurnId: evidence.hostedTurnId,
    evidenceStatus: 'reported_requires_independent_host_confirmation', ackSuppressed: true };
  if (held.state !== 'complete') state.receipts[batchId] = { ...receipt, claimId: evidence.claimId, viaMessage: evidence.via };
  for (const id of b.itemIds) {
    const own = state.receipts[id];
    if (!state.messages[id] || own?.state === 'complete' || (own?.leaseUntil > now && own.claimId !== evidence.claimId)) continue;
    state.receipts[id] = { ...receipt, viaBatch: batchId };
  }
  return true;
}

// Hourly flush (any hour; the trigger runs at :00 UTC). Per recipient with
// pending items, flush one batch when:
//   scheduled - an America/Chicago even-hour boundary has passed since the last
//               flush with items queued before it (late runs still deliver);
//   max_wait  - waiting for the next hourly run would push the oldest pending
//               item past WAKE_WINDOW_MS of elapsed time (DST, missed runs);
//   expiring  - an item expires before the next run plus slack (or already did).
// Otherwise the run is a no-op; empty queues send nothing. At most
// dailyFlushCap(day) batch wakes per recipient per Chicago day. A recipient no
// longer enabled (rollback) gets its leftovers re-sent under their own message
// IDs where their v1 authority still allows, otherwise in one batch.
export function flushDue(state, now, { policyIds, recipients = [] }) {
  const boundary = latestFlushBoundary(now), nextRun = Math.floor(now / HOUR) * HOUR + HOUR;
  const day = chicagoDate(now), results = [];
  for (const recipient of PEER_IDS) {
    const queue = queueOf(state, recipient);
    if (!queue) continue;
    let live = livePending(state, recipient, policyIds, now);
    if (!live.length) continue;
    let reason;
    if (!recipients.includes(recipient)) {
      const native = [];
      for (const item of live) {
        if (!messageAccessAllowed(state, item, policyIds, now)) continue;
        const jobIds = appendDeliveryJobs(state, item.envelope, now);
        if (!jobIds.length) continue;
        item.jobIds = jobIds; native.push(item.envelope.id);
        Object.assign(item.sync, { state: 'delivered', via: 'native', deliveredAt: now });
        delete queue.pending[item.sync.key];
      }
      if (native.length) { (queue.undispatched ||= []).push(...native); results.push({ recipient, outcome: 'native', items: native.length }); }
      live = live.filter(item => !native.includes(item.envelope.id));
      if (!live.length) continue;
      reason = 'rollback';
    } else {
      const oldest = Math.min(...live.map(m => m.sync.queuedAt));
      reason = boundary > (queue.lastFlushBoundary ?? -Infinity) && oldest < boundary ? 'scheduled'
        : nextRun > oldest + WAKE_WINDOW_MS ? 'max_wait'
          : live.some(m => Date.parse(m.envelope.expiresAt) <= nextRun + SCHEDULER_SLACK_MS) ? 'expiring' : null;
      if (!reason) continue;
      if (queue.flushDay !== day) { queue.flushDay = day; queue.flushCount = 0; }
      if (queue.flushCount >= dailyFlushCap(day)) { results.push({ recipient, outcome: 'daily_cap' }); continue; }
    }
    const batch = cutBatch(state, recipient, now, { reason: 'flush', policyIds, deliver: true });
    // No active destination: keep items pending (held past retention) and retry next run.
    if (!batch) { results.push({ recipient, outcome: 'no_destination' }); continue; }
    batch.syncBatch.trigger = reason;
    queue.lastFlushBoundary = boundary;
    if (reason !== 'rollback') queue.flushCount++;
    (queue.undispatched ||= []).push(batch.envelope.id);
    results.push({ recipient, outcome: 'flushed', reason, items: batch.syncBatch.itemIds.length });
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
