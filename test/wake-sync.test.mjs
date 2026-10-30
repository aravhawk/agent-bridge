import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generateKeyPair, SignJWT } from 'jose';
import { Bridge } from '../src/bridge.mjs';
import { MemoryStore, emptyState } from '../src/store.mjs';
import { VERIFIED_AUTHORIZATION, SCOPES } from '../src/policy.mjs';
import { validateMessage, MESSAGE_PROTOCOL, SYNC_MESSAGE_TTL_MS } from '../src/messages.mjs';
import { createProtector } from '../src/webhook.mjs';
import { NativeEvents, EVENT_NAME } from '../src/events.mjs';
import { createRuntime } from '../src/runtime.mjs';
import { resourceFor } from '../src/resource.mjs';
import { TOPIC } from '../src/queue.mjs';
import { ISSUER } from './fixtures/provider.mjs';
import { classify, wakeSyncRecipients, isFlushBoundary, latestFlushBoundary, nextFlushBoundary, chicagoDate,
  chicagoWall, flushWindowBoundary, SYNC_DAILY_FLUSH_CAP, WAKE_WINDOW_MS, FLUSH_WINDOW_MS } from '../src/sync.mjs';

const HOUR = 3600000, policy = 'c'.repeat(64);
// 2026-10-19 10:30 America/Chicago (CDT, UTC-5). Next even boundary: 12:00 CDT.
const start = Date.UTC(2026, 9, 19, 15, 30);
const iso = ms => new Date(ms).toISOString();
function who(role, until = start + 7 * 86400000) {
  return Object.defineProperty({ role, scopes: Object.values(SCOPES[role]), principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64) },
    VERIFIED_AUTHORIZATION, { value: { policyId: policy, expiresAt: until } });
}
const jarvis = who('jarvis'), friday = who('friday');
async function fixture({ recipients = ['friday'], at = start, wakeSync = true } = {}) {
  let now = at;
  const enabled = { recipients };
  const store = new MemoryStore(), clock = () => now;
  const bridge = new Bridge({ store, clock, dailyEnabled: true, messagePolicyIds: { jarvis: policy, friday: policy },
    ...(wakeSync ? { wakeSync: () => enabled.recipients } : {}) });
  const events = new NativeEvents({ store, protector: createProtector(randomBytes(32)), clock, policyId: policy, enabled: true,
    transport: async (_url, req) => ({ status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  await events.subscribe(who('jarvis', now + 7 * 86400000), { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  const message = (from = 'jarvis', extra = {}) => ({ protocol: MESSAGE_PROTOCOL, id: randomUUID(), from,
    to: from === 'jarvis' ? 'friday' : 'jarvis', kind: 'status', sentAt: iso(now), expiresAt: iso(now + HOUR),
    threadId: randomUUID(), route: 'inbox', text: 'Fixture status data only.', ...extra });
  const sync = (from = 'jarvis', extra = {}) => message(from, { class: 'sync', expiresAt: iso(now + 6 * HOUR), ...extra });
  const send = (m, principal = who(m.from, at + 7 * 86400000)) => bridge.sendMessage(principal, m);
  const handle = async (principal, id) => {
    const claim = await bridge.claim(principal, { messageId: id });
    return bridge.complete(principal, { messageId: id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
  };
  return { store, bridge, clock, enabled, message, sync, send, handle, snapshot: () => store.snapshot(),
    set: ms => { now = ms; }, advance: ms => { now += ms; } };
}
const jobsFor = (s, id) => Object.values(s.jobs).filter(job => job.messageId === id);

test('flag parsing: unset/empty is off, unknown peers close the whole flag', () => {
  assert.deepEqual(wakeSyncRecipients(undefined), { configured: false, valid: true, recipients: [] });
  assert.deepEqual(wakeSyncRecipients(''), { configured: true, valid: true, recipients: [] });
  assert.deepEqual(wakeSyncRecipients('friday'), { configured: true, valid: true, recipients: ['friday'] });
  assert.deepEqual(wakeSyncRecipients(' friday , jarvis,friday '), { configured: true, valid: true, recipients: ['friday', 'jarvis'] });
  assert.deepEqual(wakeSyncRecipients('friday,bogus'), { configured: true, valid: false, recipients: [] });
});

test('classification: unclassified and wake are WAKE, sync is SYNC; auto-promotion is inclusive at exactly now + 2h', () => {
  const now = start, base = { class: 'sync', expiresAt: iso(now + 6 * HOUR) };
  assert.deepEqual(classify({ expiresAt: iso(now + HOUR) }, now), { class: 'wake' });
  assert.deepEqual(classify({ ...base, class: 'wake' }, now), { class: 'wake' });
  assert.deepEqual(classify(base, now), { class: 'sync' });
  for (const [field, reason] of [['effectiveAt', 'effective_within_2h'], ['dueAt', 'due_within_2h']]) {
    assert.deepEqual(classify({ ...base, [field]: iso(now + WAKE_WINDOW_MS) }, now), { class: 'wake', promoted: reason });
    assert.deepEqual(classify({ ...base, [field]: iso(now + WAKE_WINDOW_MS + 1) }, now), { class: 'sync' });
    assert.deepEqual(classify({ ...base, [field]: iso(now - HOUR) }, now), { class: 'wake', promoted: reason });
  }
  // Safety net: SYNC data that would expire before the next flush window closes is never lost.
  const closes = Date.UTC(2026, 9, 19, 17) + FLUSH_WINDOW_MS;
  assert.equal(nextFlushBoundary(now), Date.UTC(2026, 9, 19, 17));
  assert.deepEqual(classify({ ...base, expiresAt: iso(closes) }, now), { class: 'wake', promoted: 'expires_before_flush' });
  assert.deepEqual(classify({ ...base, expiresAt: iso(closes + 1) }, now), { class: 'sync' });
});

test('validation: optional class fields are bounded; only sync may outlive one hour (max 12h); ACK-free v1 envelope is unchanged', () => {
  const m = { protocol: MESSAGE_PROTOCOL, id: randomUUID(), from: 'jarvis', to: 'friday', kind: 'status', sentAt: iso(start),
    expiresAt: iso(start + HOUR), threadId: randomUUID(), route: 'inbox', text: 'Fixture.' };
  const plain = validateMessage(m, jarvis, start);
  assert.deepEqual(Object.keys(plain.envelope), ['protocol', 'id', 'from', 'to', 'kind', 'sentAt', 'expiresAt', 'threadId', 'route', 'text']);
  const full = validateMessage({ ...m, class: 'sync', subject: '  Deploy  ', effectiveAt: '2026-10-20T12:00:00-05:00',
    dueAt: '2026-10-21T00:00:00Z', expiresAt: iso(start + SYNC_MESSAGE_TTL_MS) }, jarvis, start).envelope;
  assert.equal(full.subject, 'Deploy'); assert.equal(full.effectiveAt, '2026-10-20T17:00:00.000Z');
  assert.equal(full.dueAt, '2026-10-21T00:00:00.000Z'); assert.equal(full.class, 'sync');
  for (const [bad, code] of [[{ class: 'later' }, /invalid_message/], [{ subject: '' }, /invalid_message_content/],
    [{ subject: 'x'.repeat(201) }, /invalid_message_content/], [{ subject: 'a\nb' }, /invalid_message_content/],
    [{ effectiveAt: 'tomorrow' }, /invalid_message_schedule/], [{ dueAt: 5 }, /invalid_message_schedule/],
    [{ class: 'sync', expiresAt: iso(start + SYNC_MESSAGE_TTL_MS + 1) }, /invalid_message_lifetime/],
    [{ class: 'wake', expiresAt: iso(start + HOUR + 1) }, /invalid_message_lifetime/],
    [{ expiresAt: iso(start + HOUR + 1) }, /invalid_message_lifetime/]]) {
    assert.throws(() => validateMessage({ ...m, ...bad }, jarvis, start), code, JSON.stringify(bad));
  }
});

test('SYNC is queued without a wake; promotion at exactly now + 2h delivers immediately', async () => {
  const f = await fixture();
  const queued = f.sync(), sent = await f.send(queued);
  assert.deepEqual(sent, { messageId: queued.id, queued: true, duplicate: false, jobIds: [], class: 'sync', delivery: 'batched' });
  assert.equal(Object.keys(f.snapshot().jobs).length, 0);
  const due = f.sync('jarvis', { dueAt: iso(start + WAKE_WINDOW_MS) }), promoted = await f.send(due);
  assert.equal(promoted.class, 'wake'); assert.equal(promoted.promoted, 'due_within_2h'); assert.equal(promoted.jobIds.length, 1);
  // The promoted WAKE carries the earlier pending SYNC item with it.
  assert.equal(promoted.piggybackedSyncItems, 1);
  const later = f.sync('jarvis', { effectiveAt: iso(start + WAKE_WINDOW_MS + 1) });
  assert.equal((await f.send(later)).class, 'sync');
});

test('coalescing: pending SYNC dedupes by subject (latest wins), delta only, delivered items never repeat', async () => {
  const f = await fixture();
  const v1 = f.sync('jarvis', { subject: 'Deploy status', text: 'v1' }); await f.send(v1);
  const v2 = f.sync('jarvis', { subject: '  deploy   STATUS ', text: 'v2' }); await f.send(v2);
  const other = f.sync('jarvis', { subject: 'Owner change', text: 'other' }); await f.send(other);
  const bare = f.sync('jarvis', { text: 'no subject' }); await f.send(bare);
  const first = await f.bridge.inboxRead(friday);
  assert.equal(first.syncBatches.length, 1);
  assert.deepEqual(first.syncBatches[0].items.map(i => i.text), ['v2', 'other', 'no subject']);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync.state, 'superseded');
  assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync.supersededBy, v2.id);
  assert.equal((await f.bridge.status(jarvis, { messageId: v2.id })).sync.via, 'inbox');
  const v3 = f.sync('jarvis', { subject: 'Deploy status', text: 'v3' }); await f.send(v3);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches[0].items.map(i => i.messageId), [v3.id]);
  assert.equal(Object.keys(f.snapshot().jobs).length, 0, 'no item ever produced its own wake');
});

test('Chicago even-hour boundaries: twelve per local day, across both DST transitions', () => {
  const boundaries = (y, m, d) => {
    const out = [];
    for (let u = Date.UTC(y, m, d - 1); u < Date.UTC(y, m, d + 2); u += HOUR) {
      if (isFlushBoundary(u) && chicagoDate(u) === `${y}-${String(m + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`) out.push(u);
    }
    return out;
  };
  const normal = boundaries(2026, 9, 19);
  assert.equal(normal.length, 12);
  assert.deepEqual(normal.map(u => chicagoWall(u).hour), [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]);
  // Spring forward 2026-03-08: 02:00 CST does not exist; its boundary is 03:00 CDT.
  const spring = boundaries(2026, 2, 8);
  assert.equal(spring.length, 12);
  assert.equal(isFlushBoundary(Date.UTC(2026, 2, 8, 7)), false, '01:00 CST');
  assert.equal(isFlushBoundary(Date.UTC(2026, 2, 8, 8)), true, '03:00 CDT replaces 02:00');
  assert.equal(chicagoWall(Date.UTC(2026, 2, 8, 8)).hour, 3);
  assert.equal(isFlushBoundary(Date.UTC(2026, 2, 8, 9)), true, '04:00 CDT');
  // Fall back 2026-11-01: 01:00 repeats; neither instance is a boundary, 02:00 CST is.
  const fall = boundaries(2026, 10, 1);
  assert.equal(fall.length, 12);
  assert.equal(isFlushBoundary(Date.UTC(2026, 10, 1, 5)), true, '00:00 CDT');
  assert.equal(isFlushBoundary(Date.UTC(2026, 10, 1, 6)), false, '01:00 CDT');
  assert.equal(isFlushBoundary(Date.UTC(2026, 10, 1, 7)), false, '01:00 CST');
  assert.equal(isFlushBoundary(Date.UTC(2026, 10, 1, 8)), true, '02:00 CST');
  // Winter (CST, UTC-6): 12:00 local is 18:00Z.
  assert.equal(isFlushBoundary(Date.UTC(2026, 11, 15, 18)), true);
  assert.equal(isFlushBoundary(Date.UTC(2026, 11, 15, 17)), false);
  assert.equal(isFlushBoundary(Date.UTC(2026, 9, 19, 17, 1)), false, 'only top of hour');
  assert.equal(latestFlushBoundary(Date.UTC(2026, 9, 19, 18, 59)), Date.UTC(2026, 9, 19, 17));
  assert.equal(nextFlushBoundary(Date.UTC(2026, 9, 19, 17)), Date.UTC(2026, 9, 19, 19));
  // Lateness window: minutes 0-29 after the boundary only.
  assert.equal(flushWindowBoundary(Date.UTC(2026, 9, 19, 17)), Date.UTC(2026, 9, 19, 17));
  assert.equal(flushWindowBoundary(Date.UTC(2026, 9, 19, 17, 29, 59, 999)), Date.UTC(2026, 9, 19, 17));
  assert.equal(flushWindowBoundary(Date.UTC(2026, 9, 19, 17, 30)), null);
  assert.equal(flushWindowBoundary(Date.UTC(2026, 9, 19, 18, 5)), null, '13:05 CDT is odd');
  assert.equal(flushWindowBoundary(Date.UTC(2026, 10, 1, 6, 5)), null, '01:05 CDT on fall-back day');
  assert.equal(flushWindowBoundary(Date.UTC(2026, 10, 1, 7, 5)), null, '01:05 CST on fall-back day');
  assert.equal(flushWindowBoundary(Date.UTC(2026, 10, 1, 8, 5)), Date.UTC(2026, 10, 1, 8), '02:05 CST');
  assert.equal(flushWindowBoundary(Date.UTC(2026, 2, 8, 7, 5)), null, '01:05 CST on spring-forward day');
  assert.equal(flushWindowBoundary(Date.UTC(2026, 2, 8, 8, 5)), Date.UTC(2026, 2, 8, 8), '03:05 CDT replaces 02:00');
});

test('scheduled flush: one webhook per even Chicago hour, odd hours and empty windows send nothing', async () => {
  const f = await fixture();
  // Sender authority (token) expires before the flush; queued data still goes.
  const a = f.sync('jarvis', { subject: 'A' }), b = f.sync('jarvis', { subject: 'B' });
  await f.send(a, who('jarvis', start + 600000)); await f.send(b);
  f.set(Date.UTC(2026, 9, 19, 16, 0, 5)); // 11:00 CDT, odd
  assert.deepEqual(await f.bridge.flushSync(), { boundary: Date.UTC(2026, 9, 19, 15), results: [], dispatch: [], skipped: 'outside_flush_window' });
  f.set(Date.UTC(2026, 9, 19, 17, 0, 5)); // 12:00 CDT
  const flushed = await f.bridge.flushSync();
  assert.deepEqual(flushed.results, [{ recipient: 'friday', outcome: 'flushed', items: 2 }]);
  assert.equal(flushed.dispatch.length, 1);
  const batchId = flushed.dispatch[0], s = f.snapshot(), jobs = jobsFor(s, batchId);
  assert.equal(Object.keys(s.jobs).length, 1, 'exactly one webhook for the whole batch');
  assert.deepEqual(JSON.parse(jobs[0].body), { event: EVENT_NAME, data: { messageId: batchId } });
  // Same boundary again: no second batch; the batch stays queued for publication until marked.
  assert.deepEqual((await f.bridge.flushSync()).dispatch, [batchId]);
  await f.bridge.markSyncDispatched([batchId]);
  assert.deepEqual((await f.bridge.flushSync()).dispatch, []);
  // A late run after the 12:00 window closes is a no-op, not a catch-up.
  f.set(Date.UTC(2026, 9, 19, 17, 30));
  assert.deepEqual((await f.bridge.flushSync()).results, []);
  f.set(Date.UTC(2026, 9, 19, 19, 0, 5)); // 14:00 CDT, nothing pending
  const empty = await f.bridge.flushSync();
  assert.deepEqual(empty.results, [{ recipient: 'friday', outcome: 'empty' }]);
  assert.equal(Object.keys(f.snapshot().jobs).length, 1); assert.equal(Object.keys(f.snapshot().messages).length, 3);
  // The batch is a v1 status message an unchanged receiver can read/claim/complete.
  const read = await f.bridge.read(friday, { messageId: batchId });
  assert.equal(read.envelope.kind, 'status'); assert.equal(read.envelope.from, 'jarvis');
  assert.match(read.envelope.text, /2 update\(s\)/); assert.match(read.envelope.text, /\[A\]/);
  assert.deepEqual(read.syncBatches[0].items.map(i => i.messageId), [a.id, b.id]);
  const done = await f.handle(friday, batchId);
  assert.equal(done.ackMessageId, null); assert.equal(done.ackSuppressed, true);
  const itemStatus = await f.bridge.status(jarvis, { messageId: a.id });
  assert.equal(itemStatus.receiptCompleted, true); assert.equal(itemStatus.sync.via, 'flush');
  assert.equal(itemStatus.sync.batchMessageId, batchId);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, [], 'flushed items are not redelivered');
  assert.equal(Object.keys(f.snapshot().jobs).length, 1, 'batch receipt creates no ACK wake');
});

test('daily cap: at most twelve batch wakes per recipient per Chicago day; capped items wait, the next day resets', async () => {
  const midnight = Date.UTC(2026, 9, 19, 5); // 00:00 CDT
  const f = await fixture({ at: midnight - 30 * 60000 });
  let flushes = 0;
  for (let hour = 0; hour < 24; hour++) {
    await f.send(f.sync('jarvis', { text: `hour ${hour}` }));
    f.set(midnight + hour * HOUR + 5000);
    const out = await f.bridge.flushSync();
    flushes += out.results.filter(r => r.outcome === 'flushed').length;
    await f.bridge.markSyncDispatched(out.dispatch);
    f.advance(30 * 60000);
  }
  assert.equal(flushes, SYNC_DAILY_FLUSH_CAP);
  assert.equal(f.snapshot().syncQueues.friday.flushCount, 12);
  // Force a thirteenth attempt on the same local day.
  const nextDay = midnight + 24 * HOUR;
  await f.store.transaction(s => { s.syncQueues.friday.lastFlushBoundary = nextDay - 4 * HOUR; });
  f.set(nextDay - 2 * HOUR + 5000); // 22:00 CDT, same day
  const capped = await f.bridge.flushSync();
  assert.deepEqual(capped.results, [{ recipient: 'friday', outcome: 'daily_cap' }]);
  assert.equal(Object.keys(f.snapshot().syncQueues.friday.pending).length, 1);
  f.set(nextDay + 5000);
  const reset = await f.bridge.flushSync();
  assert.deepEqual(reset.results, [{ recipient: 'friday', outcome: 'flushed', items: 1 }]);
  assert.equal(f.snapshot().syncQueues.friday.flushCount, 1);
});

for (const [name, enqueueAt, quiet, boundary] of [
  ['spring forward', Date.UTC(2026, 2, 8, 6, 30), [Date.UTC(2026, 2, 8, 7)], Date.UTC(2026, 2, 8, 8)],
  ['fall back', Date.UTC(2026, 10, 1, 5, 30), [Date.UTC(2026, 10, 1, 6), Date.UTC(2026, 10, 1, 7)], Date.UTC(2026, 10, 1, 8)],
]) {
  test(`scheduled flush across DST (${name}) fires only at the even local boundary`, async () => {
    const f = await fixture({ at: enqueueAt });
    await f.send(f.sync());
    for (const at of quiet) { f.set(at + 5000); assert.deepEqual((await f.bridge.flushSync()).results, [], iso(at)); }
    f.set(boundary + 5000);
    assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'flushed', items: 1 }]);
  });
}

test('piggyback on WAKE: pending SYNC rides the next WAKE with no extra webhook and is not flushed again', async () => {
  const f = await fixture();
  const a = f.sync('jarvis', { subject: 'A' }), stale = f.sync('jarvis', { subject: 'Budget' });
  await f.send(a); await f.send(stale);
  const wake = f.message('jarvis', { subject: 'budget', text: 'Budget decision needed now.' });
  const sent = await f.send(wake);
  assert.equal(sent.class, 'wake'); assert.equal(sent.delivery, 'immediate'); assert.equal(sent.piggybackedSyncItems, 1);
  assert.equal(Object.keys(f.snapshot().jobs).length, 1, 'only the WAKE webhook');
  assert.equal((await f.bridge.status(jarvis, { messageId: stale.id })).sync.supersededBy, wake.id);
  const read = await f.bridge.read(friday, { messageId: wake.id });
  assert.equal(read.envelope.text, wake.text);
  assert.deepEqual(read.syncBatches.map(b => b.items.map(i => i.messageId)), [[a.id]]);
  assert.deepEqual((await f.bridge.read(friday, { messageId: wake.id })).syncBatches, read.syncBatches, 're-read is stable');
  f.set(Date.UTC(2026, 9, 19, 17, 0, 5));
  assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'empty' }]);
  assert.equal(Object.keys(f.snapshot().jobs).length, 1);
});

test('piggyback on inbox read: bridge_read drains pending SYNC into a batch attached to the read message', async () => {
  const f = await fixture();
  const wake = f.message(); await f.send(wake);
  const a = f.sync(); await f.send(a);
  const read = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(read.syncBatches.map(b => [b.reason, b.items.map(i => i.messageId)]), [['read', [a.id]]]);
  const again = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(again.syncBatches, read.syncBatches);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  await assert.rejects(f.bridge.inboxRead(jarvis), /wake_sync_not_enabled/);
  assert.equal(Object.keys(f.snapshot().jobs).length, 1);
});

test('no ACK wakes for an enabled recipient: receipts still complete, no reply message or job is created', async () => {
  const f = await fixture({ recipients: ['friday'] });
  const fromFriday = f.message('friday'); await f.send(fromFriday);
  const before = f.snapshot();
  const done = await f.handle(jarvis, fromFriday.id);
  assert.equal(done.ackMessageId, null); assert.equal(done.ackSuppressed, true);
  const after = f.snapshot();
  assert.deepEqual(Object.keys(after.messages), Object.keys(before.messages));
  assert.deepEqual(after.jobs, before.jobs);
  assert.equal(after.receipts[fromFriday.id].state, 'complete');
  const status = await f.bridge.status(friday, { messageId: fromFriday.id });
  assert.equal(status.receiptCompleted, true); assert.equal(status.ackMessageId, null);
  // Jarvis is not enabled yet, so Friday's receipts still ACK Jarvis exactly as before.
  const fromJarvis = f.message('jarvis'); await f.send(fromJarvis);
  assert.ok((await f.handle(friday, fromJarvis.id)).ackMessageId);
});

test('both recipients enabled: no ACK path is required or created in either direction', async () => {
  const f = await fixture({ recipients: ['friday', 'jarvis'] });
  await f.store.transaction(s => { for (const sub of Object.values(s.subscriptions)) sub.expiresAt = start - 1; });
  const m = f.message('jarvis');
  assert.equal((await f.send(m)).jobIds.length, 1, 'no return subscription needed when no ACK will be sent');
  assert.equal((await f.handle(friday, m.id)).ackMessageId, null);
  // SYNC to the events peer still needs a subscription that a batch could wake.
  await assert.rejects(f.send(f.sync('friday')), /recipient_subscription_required/);
});

test('flag off = v1: classified messages are delivered immediately, ACKs are created, no sync state exists', async () => {
  for (const options of [{ wakeSync: false }, { recipients: [] }]) {
    const f = await fixture(options);
    const plain = f.message(), classed = f.sync('jarvis', { subject: 'S', dueAt: iso(start + 86400000) });
    assert.deepEqual(await f.send(plain), { messageId: plain.id, queued: true, duplicate: false, jobIds: jobsFor(f.snapshot(), plain.id).map(j => j.id) });
    assert.equal((await f.send(classed)).jobIds.length, 1);
    const read = await f.bridge.read(friday, { messageId: plain.id });
    assert.equal('syncBatches' in read, false);
    assert.ok((await f.handle(friday, plain.id)).ackMessageId);
    const s = f.snapshot();
    assert.equal(s.syncQueues, undefined); assert.equal(Object.keys(s.jobs).length, 3);
    for (const m of Object.values(s.messages)) assert.deepEqual(Object.keys(m).sort(), ['authorization', 'envelope', 'hash', 'jobIds', 'retainUntil', 'storedAt']);
    f.set(Date.UTC(2026, 9, 19, 17, 1));
    assert.deepEqual(await f.bridge.flushSync(), { boundary: Date.UTC(2026, 9, 19, 17), results: [], dispatch: [] });
  }
});

test('unclassified messages to an enabled recipient store exactly the v1 record (WAKE)', async () => {
  const off = await fixture({ wakeSync: false }), on = await fixture({ recipients: ['friday'] });
  const m = off.message();
  const a = await off.send(m), b = await on.send(m);
  assert.deepEqual(b, { ...a, class: 'wake', delivery: 'immediate' });
  assert.deepEqual(on.snapshot().messages[m.id], off.snapshot().messages[m.id]);
  assert.deepEqual(on.snapshot().jobs, off.snapshot().jobs);
});

test('rollback: flipping the flag off sends new SYNC as WAKE and still flushes already-queued items', async () => {
  const f = await fixture();
  const queued = f.sync(); await f.send(queued);
  f.enabled.recipients = [];
  const after = f.sync(); assert.equal((await f.send(after)).jobIds.length, 1);
  const read = await f.bridge.read(friday, { messageId: after.id });
  assert.equal('syncBatches' in read, false, 'no additive field for a rolled-back receiver');
  f.set(Date.UTC(2026, 9, 19, 17, 0, 5));
  assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'flushed', items: 1 }]);
});

test('repository wiring: no Vercel cron; the GitHub Actions hourly trigger POSTs the route outside the MCP catch-all', () => {
  const config = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url)));
  assert.equal(config.crons, undefined, 'Hobby plans reject hourly Vercel crons');
  const workflow = readFileSync(new URL('../.github/workflows/bridge-cron-flush.yml', import.meta.url), 'utf8');
  for (const line of ["- cron: '0 * * * *'", 'workflow_dispatch:', 'permissions: {}', 'timeout-minutes: 5',
    'group: bridge-cron-flush', 'secrets.CRON_SECRET', 'vars.BRIDGE_CRON_URL', '--fail-with-body', '--request POST']) {
    assert.ok(workflow.includes(line), line);
  }
  assert.equal(/^\s*-?\s*uses:/m.test(workflow), false, 'no third-party actions');
  for (const name of ['BRIDGE_PUBLIC_ORIGIN', 'BRIDGE_PEERS']) assert.equal(workflow.includes(name), false, name);
  const catchAll = new RegExp('^' + config.rewrites[0].source + '$');
  assert.equal(catchAll.test('/api/cron'), false); assert.equal(catchAll.test('/api/queue'), false);
  assert.equal(catchAll.test('/bridge/friday/mcp'), true);
  assert.ok(config.functions['api/cron.mjs']);
});

async function runtimeFixture(changes = {}, at = start) {
  let document = emptyState(), now = at, consumer;
  const sends = [], posts = [];
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  class Pool { on() {} async connect() { return { release() {}, async query(sql, params) {
    if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(document) }] };
    if (sql.startsWith('UPDATE bridge_runtime_v1')) document = JSON.parse(params[0]);
    return { rows: [] };
  } }; } }
  const env = { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture', BRIDGE_DELIVERY_ENABLED: 'true',
    BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
    DATABASE_URL: 'postgresql://fixture.neon.tech/neondb?sslmode=require',
    BRIDGE_RECEIVER_POLICY: 'inbox-v1', FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true',
    FRIDAY_RECEIVER_ID: 'jarvis-friday-bridge-inbox', FRIDAY_WEBHOOK_URL: 'https://receiver.example.test/event', FRIDAY_WEBHOOK_KEY: 'FIXTURE_ONLY',
    BRIDGE_WAKE_SYNC_RECIPIENTS: 'friday', CRON_SECRET: 'fixture-cron-secret-value', ...changes };
  const rt = createRuntime({ env, Pool, keyResolver: publicKey, clock: () => now,
    queueClient: { async send(...args) { sends.push(args); }, handleCallback(fn) { consumer = fn; return fn; } },
    transportFactory: () => async (_url, req) => { const body = JSON.parse(req.body); posts.push(body);
      return { status: 200, body: JSON.stringify({ challenge: body.challenge }) }; } });
  const tokens = {};
  for (const role of ['jarvis', 'friday']) tokens[role] = await new SignJWT({ scope: Object.values(SCOPES[role]).join(' ') })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject('fixture').setAudience(resourceFor(role)).setIssuedAt().setExpirationTime('30d').sign(privateKey);
  const rpc = async (role, method, params) => {
    const response = await rt.handler(role)(new Request(resourceFor(role), { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tokens[role] },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })); return { status: response.status, body: await response.json() };
  };
  const call = async (role, name, args) => (await rpc(role, 'tools/call', { name, arguments: args })).body.result;
  const cron = (headers = {}, method = 'POST') => rt.cronHandler()(new Request('https://deployment.example.test/api/cron', { method, headers }));
  await rpc('jarvis', 'events/subscribe', { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  return { rt, env, rpc, call, cron, sends, posts, document: () => document, set: ms => { now = ms; },
    async consume(payload) { rt.queueHandler(); return consumer(payload, { topicName: TOPIC, region: 'iad1', deliveryCount: 1 }); },
    message: (extra = {}) => ({ protocol: MESSAGE_PROTOCOL, id: randomUUID(), from: 'jarvis', to: 'friday', kind: 'status', sentAt: iso(now),
      expiresAt: iso(now + 6 * HOUR), threadId: randomUUID(), route: 'inbox', text: 'Fixture runtime status', class: 'sync', ...extra }) };
}

test('runtime: tool schemas, readiness and inbox tool follow the per-recipient flag', async () => {
  const f = await runtimeFixture();
  const tools = role => f.rpc(role, 'tools/list', {}).then(r => r.body.result.tools);
  const fridayTools = await tools('friday'), jarvisTools = await tools('jarvis');
  assert.ok(fridayTools.some(t => t.name === 'bridge_inbox_read'));
  assert.equal(jarvisTools.some(t => t.name === 'bridge_inbox_read'), false);
  const schema = jarvisTools.find(t => t.name === 'bridge_message_send').inputSchema;
  for (const field of ['class', 'subject', 'effectiveAt', 'dueAt']) {
    assert.ok(schema.properties[field], field); assert.equal(schema.required.includes(field), false);
  }
  assert.deepEqual(schema.properties.class.enum, ['wake', 'sync']);
  const health = await f.call('friday', 'bridge_health', {});
  assert.deepEqual(health.structuredContent.readiness.wakeSync, { valid: true, recipients: ['friday'], flushScheduleConfigured: true });
  const off = await runtimeFixture({ BRIDGE_WAKE_SYNC_RECIPIENTS: undefined });
  assert.equal((await off.call('friday', 'bridge_health', {})).structuredContent.readiness.wakeSync, undefined);
  assert.equal((await off.rpc('friday', 'tools/list', {})).body.result.tools.some(t => t.name === 'bridge_inbox_read'), false);
});

const auth = { authorization: 'Bearer fixture-cron-secret-value' };
const outside = { status: 'skipped', reason: 'outside_flush_window' };
test('runtime cron auth: POST and GET need the exact CRON_SECRET bearer; other methods and an unset secret are refused', async () => {
  const f = await runtimeFixture({}, Date.UTC(2026, 9, 19, 17, 5));
  for (const method of ['POST', 'GET']) {
    assert.equal((await f.cron({}, method)).status, 401, method);
    assert.equal((await f.cron({ authorization: 'Bearer wrong-secret-value-xx' }, method)).status, 401, method);
    assert.equal((await f.cron({ authorization: 'fixture-cron-secret-value' }, method)).status, 401, method);
    assert.equal((await f.cron({ authorization: 'Bearer fixture-cron-secret-valuX' }, method)).status, 401, method);
    assert.equal((await f.cron(auth, method)).status, 200, method);
  }
  assert.equal((await f.cron(auth, 'PUT')).status, 405);
  for (const secret of [undefined, '', 'short-secret']) {
    const unset = await runtimeFixture({ CRON_SECRET: secret }, Date.UTC(2026, 9, 19, 17, 5));
    assert.equal((await unset.cron({ authorization: 'Bearer ' + secret })).status, 503, String(secret));
  }
  // Odd Chicago hour: an authenticated 200 no-op that touches no storage.
  const odd = await runtimeFixture({ DATABASE_URL: undefined }, Date.UTC(2026, 9, 19, 18, 0, 5));
  const response = await odd.cron(auth);
  assert.equal(response.status, 200); assert.deepEqual(await response.json(), outside);
});

test('runtime cron: even-hour POST flushes one standard-shaped webhook; late-in-window flushes, after-window and duplicate runs do not', async () => {
  const f = await runtimeFixture();
  const a = f.message({ subject: 'A' }), b = f.message({ subject: 'B' });
  for (const m of [a, b]) assert.equal((await f.call('jarvis', 'bridge_message_send', m)).structuredContent.delivery, 'batched');
  f.set(Date.UTC(2026, 9, 19, 16, 0, 5)); // 11:00 CDT
  assert.deepEqual(await (await f.cron(auth)).json(), outside);
  f.set(Date.UTC(2026, 9, 19, 17, 25)); // 12:25 CDT: late but inside the window
  const sendsBefore = f.sends.length;
  const out = await (await f.cron(auth)).json();
  assert.deepEqual(out, { status: 'ok', boundary: '2026-10-19T17:00:00.000Z', flushed: 1, capped: 0, dispatched: 1, dispatchPending: 0 });
  f.set(Date.UTC(2026, 9, 19, 17, 29)); // duplicate run, same even hour
  assert.deepEqual(await (await f.cron(auth)).json(), { status: 'ok', boundary: '2026-10-19T17:00:00.000Z', flushed: 0, capped: 0, dispatched: 0, dispatchPending: 0 });
  const dispatch = f.sends.slice(sendsBefore).map(args => args[1]).find(p => p.dispatchMessageId);
  const batchId = dispatch.dispatchMessageId;
  await f.consume(dispatch);
  const webhooks = f.posts.filter(p => p.event === EVENT_NAME);
  assert.deepEqual(webhooks, [{ event: EVENT_NAME, data: { messageId: batchId } }], 'one webhook, v1 payload shape');
  const read = (await f.call('friday', 'bridge_read', { messageId: batchId })).structuredContent;
  assert.deepEqual(read.syncBatches[0].items.map(i => i.subject), ['A', 'B']);
  assert.equal((await (await f.cron(auth, 'GET')).json()).flushed, 0, 'same boundary never flushes twice');
  // An item queued during the window waits for the next boundary; a run after the window is a no-op.
  await f.call('jarvis', 'bridge_message_send', f.message({ subject: 'C' }));
  f.set(Date.UTC(2026, 9, 19, 17, 30));
  assert.deepEqual(await (await f.cron(auth)).json(), outside);
  assert.equal(f.posts.filter(p => p.event === EVENT_NAME).length, 1);
  f.set(Date.UTC(2026, 9, 19, 19, 10)); // 14:10 CDT
  assert.equal((await (await f.cron(auth)).json()).flushed, 1);
  assert.deepEqual((await f.call('friday', 'bridge_inbox_read', {})).structuredContent, { syncBatches: [] });
  const disabled = await runtimeFixture({ BRIDGE_DELIVERY_ENABLED: 'false' }, Date.UTC(2026, 9, 19, 17, 5));
  assert.deepEqual(await (await disabled.cron(auth)).json(), { status: 'skipped', reason: 'delivery_not_enabled' });
});

// [UTC time, expected response]: number = batches flushed, 'skip' = outside the window.
for (const [name, enqueueAt, runs] of [
  ['fall back, Nov 1 2026', Date.UTC(2026, 10, 1, 5, 40), [ // 00:40 CDT
    [Date.UTC(2026, 10, 1, 6, 0, 5), 'skip'], // 01:00 CDT
    [Date.UTC(2026, 10, 1, 7, 0, 5), 'skip'], // 01:00 CST (repeated hour)
    [Date.UTC(2026, 10, 1, 7, 20), 'skip'],
    [Date.UTC(2026, 10, 1, 8, 12), 1], // 02:12 CST, late in window
    [Date.UTC(2026, 10, 1, 8, 20), 0], // duplicate in the same even hour
    [Date.UTC(2026, 10, 1, 9, 0, 5), 'skip'], // 03:00 CST
  ]],
  ['spring forward, Mar 8 2026', Date.UTC(2026, 2, 8, 6, 40), [ // 00:40 CST
    [Date.UTC(2026, 2, 8, 7, 0, 5), 'skip'], // 01:00 CST
    [Date.UTC(2026, 2, 8, 8, 5), 1], // 03:05 CDT, replaces the nonexistent 02:00
    [Date.UTC(2026, 2, 8, 8, 29), 0],
    [Date.UTC(2026, 2, 8, 8, 31), 'skip'],
    [Date.UTC(2026, 2, 8, 9, 0, 5), 0], // 04:00 CDT, empty window
  ]],
]) {
  test(`runtime cron across DST (${name}) flushes once, only in the even-hour window`, async () => {
    const f = await runtimeFixture({}, enqueueAt);
    assert.equal((await f.call('jarvis', 'bridge_message_send', f.message())).structuredContent.delivery, 'batched');
    for (const [at, expected] of runs) {
      f.set(at);
      const body = await (await f.cron(auth)).json();
      if (expected === 'skip') assert.deepEqual(body, outside, iso(at));
      else assert.equal(body.flushed, expected, iso(at));
    }
    assert.equal(f.posts.filter(p => p.event === EVENT_NAME).length, 0, 'webhook POSTs happen on queue dispatch, not inline');
    assert.equal(f.sends.filter(args => args[1].dispatchMessageId).length >= 1, true);
  });
}
