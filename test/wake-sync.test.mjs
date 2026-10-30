import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generateKeyPair, SignJWT } from 'jose';
import { Bridge } from '../src/bridge.mjs';
import { MemoryStore, emptyState } from '../src/store.mjs';
import { VERIFIED_AUTHORIZATION, SCOPES } from '../src/policy.mjs';
import { validateMessage, MESSAGE_PROTOCOL, SYNC_MESSAGE_TTL_MS, CONTENT_RETENTION_MS } from '../src/messages.mjs';
import { createProtector } from '../src/webhook.mjs';
import { NativeEvents, EVENT_NAME } from '../src/events.mjs';
import { createRuntime } from '../src/runtime.mjs';
import { resourceFor } from '../src/resource.mjs';
import { TOPIC } from '../src/queue.mjs';
import { ISSUER } from './fixtures/provider.mjs';
import { classify, wakeSyncRecipients, isFlushBoundary, latestFlushBoundary, nextFlushBoundary, chicagoDate,
  chicagoWall, chicagoDayHours, dailyFlushCap, SYNC_DAILY_FLUSH_CAP, WAKE_WINDOW_MS, SYNC_DEADLINE_MS,
  SYNC_BATCH_TTL_MS } from '../src/sync.mjs';

const HOUR = 3600000, MINUTE = 60000, policy = 'c'.repeat(64);
// 2026-10-19 10:30 America/Chicago (CDT, UTC-5). Next even boundary: 12:00 CDT = 17:00Z.
const start = Date.UTC(2026, 9, 19, 15, 30);
const noon = Date.UTC(2026, 9, 19, 17);
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
  const principal = role => who(role, at + 7 * 86400000);
  const send = (m, as = principal(m.from)) => bridge.sendMessage(as, m);
  const handle = async (as, id, syncBatchIds) => {
    const claim = await bridge.claim(as, { messageId: id });
    return bridge.complete(as, { messageId: id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null,
      ...(syncBatchIds ? { syncBatchIds } : {}) });
  };
  // A flagged receiver: read (full items), then claim/complete the batch receipt.
  const ack = async (id, as = principal('friday')) => { await bridge.read(as, { messageId: id }); return handle(as, id); };
  return { store, bridge, clock, enabled, message, sync, send, handle, ack, principal, snapshot: () => store.snapshot(),
    set: ms => { now = ms; }, advance: ms => { now += ms; } };
}
const jobsFor = (s, id) => Object.values(s.jobs).filter(job => job.messageId === id);
const batchesIn = s => Object.values(s.messages).filter(m => m.syncBatch);
const ids = batches => batches.map(b => b.items.map(i => i.messageId));

test('flag parsing: unset/empty is off, unknown peers close the whole flag', () => {
  assert.deepEqual(wakeSyncRecipients(undefined), { configured: false, valid: true, recipients: [] });
  assert.deepEqual(wakeSyncRecipients(''), { configured: true, valid: true, recipients: [] });
  assert.deepEqual(wakeSyncRecipients('friday'), { configured: true, valid: true, recipients: ['friday'] });
  assert.deepEqual(wakeSyncRecipients(' friday , jarvis,friday '), { configured: true, valid: true, recipients: ['friday', 'jarvis'] });
  assert.deepEqual(wakeSyncRecipients('friday,bogus'), { configured: true, valid: false, recipients: [] });
});

test('classification: promotion covers the 2h maximum wait plus scheduler slack, inclusive', () => {
  const now = start, base = { class: 'sync', expiresAt: iso(now + 6 * HOUR) }, deadline = now + SYNC_DEADLINE_MS;
  assert.equal(SYNC_DEADLINE_MS, 2.5 * HOUR);
  assert.deepEqual(classify({ expiresAt: iso(now + HOUR) }, now), { class: 'wake' });
  assert.deepEqual(classify({ ...base, class: 'wake' }, now), { class: 'wake' });
  assert.deepEqual(classify(base, now), { class: 'sync' });
  for (const [field, reason] of [['effectiveAt', 'effective_before_sync_deadline'], ['dueAt', 'due_before_sync_deadline'],
    ['expiresAt', 'expires_before_sync_deadline']]) {
    assert.deepEqual(classify({ ...base, [field]: iso(now + WAKE_WINDOW_MS) }, now), { class: 'wake', promoted: reason }, 'now + 2h');
    assert.deepEqual(classify({ ...base, [field]: iso(deadline) }, now), { class: 'wake', promoted: reason }, 'deadline');
    assert.deepEqual(classify({ ...base, [field]: iso(deadline + 1) }, now), { class: 'sync' }, 'deadline + 1ms');
  }
  assert.deepEqual(classify({ ...base, dueAt: iso(now - HOUR) }, now), { class: 'wake', promoted: 'due_before_sync_deadline' });
  // Formerly an expiry one second after the next theoretical boundary stayed SYNC.
  assert.equal(nextFlushBoundary(now), noon);
  assert.deepEqual(classify({ ...base, expiresAt: iso(noon + 1000) }, now), { class: 'wake', promoted: 'expires_before_sync_deadline' });
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

test('SYNC is queued without a wake; promotion delivers immediately with the pending items piggybacked', async () => {
  const f = await fixture();
  const queued = f.sync(), sent = await f.send(queued);
  assert.deepEqual(sent, { messageId: queued.id, queued: true, duplicate: false, jobIds: [], class: 'sync', delivery: 'batched' });
  assert.equal(Object.keys(f.snapshot().jobs).length, 0);
  const due = f.sync('jarvis', { dueAt: iso(start + WAKE_WINDOW_MS) }), promoted = await f.send(due);
  assert.equal(promoted.class, 'wake'); assert.equal(promoted.promoted, 'due_before_sync_deadline'); assert.equal(promoted.jobIds.length, 1);
  assert.equal(promoted.piggybackedSyncItems, 1);
  assert.equal((await f.send(f.sync('jarvis', { effectiveAt: iso(start + SYNC_DEADLINE_MS + 1) }))).class, 'sync');
});

test('coalescing: pending SYNC dedupes by subject (latest wins); after acknowledgement only the delta follows', async () => {
  const f = await fixture();
  const v1 = f.sync('jarvis', { subject: 'Deploy status', text: 'v1' }); await f.send(v1);
  const v2 = f.sync('jarvis', { subject: '  deploy   STATUS ', text: 'v2' }); await f.send(v2);
  await f.send(f.sync('jarvis', { subject: 'Owner change', text: 'other' }));
  await f.send(f.sync('jarvis', { text: 'no subject' }));
  const first = await f.bridge.inboxRead(friday);
  assert.equal(first.syncBatches.length, 1);
  assert.deepEqual(first.syncBatches[0].items.map(i => i.text), ['v2', 'other', 'no subject']);
  assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync.state, 'superseded');
  assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync.supersededBy, v2.id);
  await f.handle(friday, first.syncBatches[0].messageId);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  const v3 = f.sync('jarvis', { subject: 'Deploy status', text: 'v3' }); await f.send(v3);
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[v3.id]]);
  assert.equal(Object.keys(f.snapshot().jobs).length, 0, 'no item ever produced its own wake');
});

test('inbox read survives a lost response: unacknowledged batches replay until their receipt is acknowledged', async () => {
  const f = await fixture();
  const a = f.sync(); await f.send(a);
  const lost = await f.bridge.inboxRead(friday); // response never reaches the receiver
  const again = await f.bridge.inboxRead(friday);
  assert.deepEqual(again, lost, 're-read returns the same batch and items');
  assert.equal(batchesIn(f.snapshot()).length, 1, 'no second cut');
  const b = f.sync(); await f.send(b);
  const both = await f.bridge.inboxRead(friday);
  assert.deepEqual(ids(both.syncBatches), [[a.id], [b.id]]);
  const done = await f.handle(friday, lost.syncBatches[0].messageId);
  assert.equal(done.ackMessageId, null);
  assert.equal(f.snapshot().receipts[a.id].state, 'complete');
  assert.equal(f.snapshot().receipts[b.id], undefined, 'only the acknowledged batch is handled');
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[b.id]]);
  await f.handle(friday, both.syncBatches[1].messageId);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
});

test('concurrent inbox readers neither double-cut nor lose items', async () => {
  const f = await fixture();
  const sent = [];
  for (let i = 0; i < 5; i++) { const m = f.sync('jarvis', { subject: `s${i}` }); sent.push(m.id); await f.send(m); }
  const reads = await Promise.all(Array.from({ length: 6 }, () => f.bridge.inboxRead(friday)));
  for (const r of reads) assert.deepEqual(r, reads[0]);
  assert.equal(batchesIn(f.snapshot()).length, 1);
  assert.deepEqual(ids(reads[0].syncBatches).flat().sort(), sent.sort());
  await Promise.all([f.handle(friday, reads[0].syncBatches[0].messageId).catch(() => null),
    f.bridge.inboxRead(friday), f.send(f.sync('jarvis', { subject: 'late' }))]);
  const after = await f.bridge.inboxRead(friday);
  assert.equal(after.syncBatches.length, 1); assert.equal(after.syncBatches[0].items[0].subject, 'late');
});

test('an unacknowledged batch is reclaimed after its replay lifetime and its items are re-sent flagged late', async () => {
  const f = await fixture();
  const a = f.sync(); await f.send(a);
  const first = (await f.bridge.inboxRead(friday)).syncBatches[0];
  f.advance(SYNC_BATCH_TTL_MS);
  const next = (await f.bridge.inboxRead(friday)).syncBatches;
  assert.equal(next.length, 1); assert.notEqual(next[0].messageId, first.messageId);
  assert.deepEqual(next[0].items.map(i => [i.messageId, i.expired, i.late]), [[a.id, true, true]]);
  const status = await f.bridge.status(jarvis, { messageId: first.messageId });
  assert.equal(status.syncBatch.reclaimed, true); assert.equal(status.syncBatch.acknowledged, false);
  assert.equal((await f.bridge.status(jarvis, { messageId: a.id })).sync.redeliveries, 1);
});

test('Chicago even-hour boundaries and day lengths across both 2026 DST transitions', () => {
  const boundaries = (y, m, d) => {
    const out = [], date = `${y}-${String(m + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    for (let u = Date.UTC(y, m, d - 1); u < Date.UTC(y, m, d + 2); u += HOUR) if (isFlushBoundary(u) && chicagoDate(u) === date) out.push(u);
    return out;
  };
  assert.deepEqual(boundaries(2026, 9, 19).map(u => chicagoWall(u).hour), [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]);
  assert.equal(boundaries(2026, 2, 8).length, 12);
  assert.equal(isFlushBoundary(Date.UTC(2026, 2, 8, 7)), false, '01:00 CST');
  assert.equal(isFlushBoundary(Date.UTC(2026, 2, 8, 8)), true, '03:00 CDT replaces 02:00');
  assert.equal(boundaries(2026, 10, 1).length, 12);
  assert.equal(isFlushBoundary(Date.UTC(2026, 10, 1, 5)), true, '00:00 CDT');
  assert.equal(isFlushBoundary(Date.UTC(2026, 10, 1, 6)), false, '01:00 CDT');
  assert.equal(isFlushBoundary(Date.UTC(2026, 10, 1, 7)), false, '01:00 CST');
  assert.equal(isFlushBoundary(Date.UTC(2026, 10, 1, 8)), true, '02:00 CST: three elapsed hours after 00:00 CDT');
  assert.equal(isFlushBoundary(Date.UTC(2026, 11, 15, 18)), true, 'CST noon');
  assert.equal(latestFlushBoundary(Date.UTC(2026, 9, 19, 18, 59)), noon);
  assert.equal(nextFlushBoundary(noon), Date.UTC(2026, 9, 19, 19));
  assert.deepEqual([chicagoDayHours('2026-03-08'), chicagoDayHours('2026-10-19'), chicagoDayHours('2026-11-01')], [23, 24, 25]);
  assert.deepEqual([dailyFlushCap('2026-03-08'), dailyFlushCap('2026-10-19'), dailyFlushCap('2026-11-01')], [12, 12, 13]);
});

test('scheduled flush: one webhook at the even hour, late runs still deliver, odd hours and duplicates send nothing', async () => {
  const f = await fixture();
  // Sender authority (token) expires before the flush; queued data still goes.
  const a = f.sync('jarvis', { subject: 'A' }), b = f.sync('jarvis', { subject: 'B' });
  await f.send(a, who('jarvis', start + 10 * MINUTE)); await f.send(b);
  f.set(Date.UTC(2026, 9, 19, 16, 0, 5)); // 11:00 CDT
  assert.deepEqual(await f.bridge.flushSync(), { boundary: Date.UTC(2026, 9, 19, 15), results: [], dispatch: [] });
  f.set(noon + 40 * MINUTE); // 12:40 CDT: the 12:00 run arrives 40 minutes late
  const flushed = await f.bridge.flushSync();
  assert.deepEqual(flushed.results, [{ recipient: 'friday', outcome: 'flushed', reason: 'scheduled', items: 2 }]);
  const batchId = flushed.dispatch[0], s = f.snapshot();
  assert.equal(Object.keys(s.jobs).length, 1, 'exactly one webhook for the whole batch');
  assert.deepEqual(JSON.parse(jobsFor(s, batchId)[0].body), { event: EVENT_NAME, data: { messageId: batchId } });
  assert.deepEqual((await f.bridge.flushSync()).dispatch, [batchId], 'unpublished batch is re-offered, not re-cut');
  await f.bridge.markSyncDispatched([batchId]);
  assert.deepEqual(await f.bridge.flushSync(), { boundary: noon, results: [], dispatch: [] });
  f.set(Date.UTC(2026, 9, 19, 19, 0, 5)); // 14:00 CDT, nothing pending: empty window sends nothing
  assert.deepEqual((await f.bridge.flushSync()).results, []);
  assert.equal(Object.keys(f.snapshot().jobs).length, 1);
});

test('a skipped even-hour run is caught up by the next hourly run instead of waiting or dropping', async () => {
  const f = await fixture();
  const a = f.sync(); await f.send(a);
  // The 12:00 CDT run never happens; 13:00 CDT delivers.
  f.set(Date.UTC(2026, 9, 19, 18, 0, 5));
  assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'flushed', reason: 'scheduled', items: 1 }]);
  // Items that were queued but whose run was skipped long enough to expire are delivered, flagged late.
  const g = await fixture();
  const late = g.sync('jarvis', { expiresAt: iso(start + 3 * HOUR) }); await g.send(late);
  g.set(start + 4 * HOUR); // runs at 12:00 and 13:00 CDT both missed; item already expired
  const out = await g.bridge.flushSync();
  assert.equal(out.results[0].outcome, 'flushed');
  const view = (await g.bridge.read(friday, { messageId: out.dispatch[0] })).syncBatches[0].items[0];
  assert.deepEqual([view.messageId, view.expired, view.late], [late.id, true, true]);
});

test('scheduled batches are only handled once their full items were presented by a read', async () => {
  const f = await fixture();
  const a = f.sync('jarvis', { subject: 'A' }); await f.send(a);
  f.set(noon + 5000);
  const batchId = (await f.bridge.flushSync()).dispatch[0];
  const claim = await f.bridge.claim(friday, { messageId: batchId });
  await assert.rejects(f.bridge.complete(friday, { messageId: batchId, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null }),
    /sync_batch_not_presented/);
  assert.equal(f.snapshot().receipts[a.id], undefined);
  const read = await f.bridge.read(friday, { messageId: batchId });
  assert.equal(read.envelope.kind, 'status'); assert.equal(read.envelope.from, 'jarvis');
  assert.match(read.envelope.text, new RegExp(a.id));
  assert.deepEqual(read.syncBatches[0].items.map(i => [i.messageId, i.text]), [[a.id, a.text]]);
  const done = await f.bridge.complete(friday, { messageId: batchId, claimId: claim.claimId, hostedEventId: 'evt_1', hostedTurnId: null });
  assert.equal(done.ackMessageId, null); assert.equal(done.ackSuppressed, true);
  const item = await f.bridge.status(jarvis, { messageId: a.id });
  assert.equal(item.receiptCompleted, true); assert.equal(item.sync.via, 'flush'); assert.equal(item.sync.batchMessageId, batchId);
  assert.equal(f.snapshot().receipts[a.id].viaBatch, batchId);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  assert.equal(Object.keys(f.snapshot().jobs).length, 1, 'batch receipt creates no ACK wake');
});

// Hourly runs on time across a whole Chicago day, an item every 30 minutes:
// nobody waits more than 2 elapsed hours, and flushes stay within the day's cap.
for (const [name, y, m, d, flushes] of [['spring forward', 2026, 2, 8, 12], ['normal day', 2026, 9, 19, 12], ['fall back', 2026, 10, 1, 13]]) {
  test(`2h elapsed maximum holds all day (${name} ${y}-${m + 1}-${d})`, async () => {
    const date = `${y}-${String(m + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    let midnight = Date.UTC(y, m, d, 4);
    while (chicagoDate(midnight) !== date) midnight += HOUR;
    const end = midnight + chicagoDayHours(date) * HOUR;
    const f = await fixture({ at: midnight + 10 * MINUTE });
    let count = 0;
    for (let t = midnight + 10 * MINUTE; t < end; t += 30 * MINUTE) {
      f.set(t); await f.send(f.sync('jarvis', { text: iso(t) }));
      const run = Math.ceil(t / HOUR) * HOUR;
      if (t + 30 * MINUTE > run) {
        f.set(run + 5000);
        const out = await f.bridge.flushSync();
        count += out.results.filter(r => r.outcome === 'flushed').length;
        await f.bridge.markSyncDispatched(out.dispatch);
        for (const id of out.dispatch) await f.ack(id); // the woken receiver reads and acknowledges
      }
    }
    const items = Object.values(f.snapshot().messages).filter(x => x.sync && x.sync.state === 'delivered');
    const max = Math.max(...items.map(x => x.sync.deliveredAt - x.storedAt));
    assert.ok(max <= WAKE_WINDOW_MS, `max wait ${max / MINUTE} min`);
    assert.equal(count, flushes); assert.ok(count <= dailyFlushCap(date));
  });
}

for (const [name, queuedAt, runs] of [
  // 00:10 CDT; the next even hour (02:00 CST) is three elapsed hours away, so 01:00 CST flushes.
  ['fall back, Nov 1 2026', Date.UTC(2026, 10, 1, 5, 10), [[Date.UTC(2026, 10, 1, 6), null], [Date.UTC(2026, 10, 1, 7), 'max_wait'],
    [Date.UTC(2026, 10, 1, 8), null]]],
  // 00:10 CST; 03:00 CDT replaces the nonexistent 02:00, 1h50m later.
  ['spring forward, Mar 8 2026', Date.UTC(2026, 2, 8, 6, 10), [[Date.UTC(2026, 2, 8, 7), null], [Date.UTC(2026, 2, 8, 8), 'scheduled'],
    [Date.UTC(2026, 2, 8, 9), null]]],
]) {
  test(`DST (${name}): flushed before 2 elapsed hours, exactly once`, async () => {
    const f = await fixture({ at: queuedAt });
    await f.send(f.sync());
    for (const [at, reason] of runs) {
      f.set(at + 5000);
      const results = (await f.bridge.flushSync()).results;
      assert.deepEqual(results, reason ? [{ recipient: 'friday', outcome: 'flushed', reason, items: 1 }] : [], iso(at));
      if (reason) assert.ok(at + 5000 - queuedAt <= WAKE_WINDOW_MS);
    }
  });
}

test('daily cap: capped items wait (held, not dropped) and the next Chicago day resets the count', async () => {
  const f = await fixture();
  await f.send(f.sync());
  await f.store.transaction(s => { Object.assign(s.syncQueues.friday, { flushDay: '2026-10-19', flushCount: SYNC_DAILY_FLUSH_CAP }); });
  f.set(noon + 5000);
  assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'daily_cap' }]);
  assert.equal(Object.keys(f.snapshot().syncQueues.friday.pending).length, 1);
  f.set(Date.UTC(2026, 9, 20, 5, 0, 5)); // 00:00 CDT next day
  assert.equal((await f.bridge.flushSync()).results[0].outcome, 'flushed');
  assert.equal(f.snapshot().syncQueues.friday.flushCount, 1);
});

test('undeliverable SYNC data is held past content retention instead of being purged', async () => {
  const f = await fixture({ recipients: ['jarvis'] });
  const m = f.sync('friday'); await f.send(m);
  await f.store.transaction(s => { for (const sub of Object.values(s.subscriptions)) sub.expiresAt = start + 1; });
  f.set(noon + 5000);
  assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'jarvis', outcome: 'no_destination' }]);
  f.advance(CONTENT_RETENTION_MS + HOUR);
  await f.bridge.flushSync();
  assert.ok(f.snapshot().messages[m.id], 'still held');
  assert.equal((await f.bridge.status(friday, { messageId: m.id })).sync.state, 'pending');
});

test('piggyback on WAKE: completing the read WAKE with its batch IDs acknowledges exactly those batches', async () => {
  const f = await fixture();
  const a = f.sync('jarvis', { subject: 'A' }), stale = f.sync('jarvis', { subject: 'Budget' });
  await f.send(a); await f.send(stale);
  const wake = f.message('jarvis', { subject: 'budget', text: 'Budget decision needed now.' });
  const sent = await f.send(wake);
  assert.equal(sent.delivery, 'immediate'); assert.equal(sent.piggybackedSyncItems, 1);
  assert.equal(Object.keys(f.snapshot().jobs).length, 1, 'only the WAKE webhook');
  assert.equal((await f.bridge.status(jarvis, { messageId: stale.id })).sync.supersededBy, wake.id);
  const read = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(ids(read.syncBatches), [[a.id]]);
  assert.deepEqual((await f.bridge.read(friday, { messageId: wake.id })).syncBatches, read.syncBatches, 're-read is stable');
  const done = await f.handle(friday, wake.id, read.syncBatches.map(b => b.messageId));
  assert.deepEqual(done.syncBatchesAcked, [read.syncBatches[0].messageId]);
  assert.equal(f.snapshot().receipts[a.id].state, 'complete');
  assert.equal(f.snapshot().receipts[read.syncBatches[0].messageId].viaMessage, wake.id);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  f.set(noon + 5000);
  assert.deepEqual((await f.bridge.flushSync()).results, [], 'nothing is flushed again');
});

test('completing a WAKE acknowledges no batch it does not name, and rejects names it was never shown', async () => {
  const f = await fixture();
  const a = f.sync(); await f.send(a);
  const wake = f.message(); await f.send(wake);
  const attached = f.snapshot().messages[wake.id].syncBatchIds[0];
  // Never read: the attached batch was never presented, so naming it is refused and nothing changes.
  const claim = await f.bridge.claim(friday, { messageId: wake.id });
  for (const syncBatchIds of [[attached], [randomUUID()]]) {
    await assert.rejects(f.bridge.complete(friday, { messageId: wake.id, claimId: claim.claimId, hostedEventId: null,
      hostedTurnId: null, syncBatchIds }), /sync_batch_not_presented/);
  }
  await assert.rejects(f.bridge.complete(friday, { messageId: wake.id, claimId: claim.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: 'all' }), /invalid_params/);
  assert.equal(f.snapshot().receipts[wake.id].state, 'claimed');
  // Completing without naming batches (an unchanged receiver) acknowledges none.
  const done = await f.bridge.complete(friday, { messageId: wake.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
  assert.equal(done.syncBatchesAcked, undefined);
  assert.equal(f.snapshot().receipts[a.id], undefined);
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[a.id]]);
});

test('race: a batch shown to reader B during reader A\'s claim is not acknowledged by A\'s completion', async () => {
  const f = await fixture();
  const p = f.sync('jarvis', { subject: 'P' }); await f.send(p);
  const wake = f.message(); await f.send(wake); // P rides the WAKE
  // Reader A reads W, then claims it (the fence) and starts handling.
  const readA = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(ids(readA.syncBatches), [[p.id]]);
  const claimA = await f.bridge.claim(friday, { messageId: wake.id });
  // New SYNC data X arrives; reader B reads W during A's claim and is shown X, then loses the response.
  const x = f.sync('jarvis', { subject: 'X' }); await f.send(x);
  const readB = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(ids(readB.syncBatches), [[p.id], [x.id]]);
  const batchX = readB.syncBatches[1].messageId;
  // A completes with exactly what A saw.
  const doneA = await f.bridge.complete(friday, { messageId: wake.id, claimId: claimA.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: readA.syncBatches.map(b => b.messageId) });
  assert.deepEqual(doneA.syncBatchesAcked, [readA.syncBatches[0].messageId]);
  assert.equal(f.snapshot().receipts[p.id].state, 'complete');
  assert.equal(f.snapshot().receipts[x.id], undefined, 'X was never handled by A');
  assert.equal(f.snapshot().receipts[batchX], undefined);
  assert.equal((await f.bridge.status(jarvis, { messageId: batchX })).syncBatch.acknowledged, false);
  // X stays deliverable and is acknowledged by its own claim.
  const replay = await f.bridge.inboxRead(friday);
  assert.deepEqual(replay.syncBatches.map(b => b.messageId), [batchX]);
  const doneX = await f.handle(friday, batchX);
  assert.equal(doneX.completed, true);
  assert.equal(f.snapshot().receipts[x.id].state, 'complete');
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
});

test('bridge_read drains pending SYNC into a batch attached to an open message only', async () => {
  const f = await fixture();
  const wake = f.message(); await f.send(wake);
  const a = f.sync(); await f.send(a);
  const read = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(read.syncBatches.map(b => [b.reason, b.items.map(i => i.messageId)]), [['read', [a.id]]]);
  assert.deepEqual(await f.bridge.read(friday, { messageId: wake.id }), read);
  await f.handle(friday, wake.id, read.syncBatches.map(b => b.messageId));
  const b = f.sync(); await f.send(b);
  const later = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(ids(later.syncBatches), [[a.id]], 'a completed message collects nothing new');
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[b.id]]);
  await assert.rejects(f.bridge.inboxRead(jarvis), /wake_sync_not_enabled/);
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
  const status = await f.bridge.status(friday, { messageId: fromFriday.id });
  assert.equal(status.receiptCompleted, true); assert.equal(status.ackMessageId, null);
  const fromJarvis = f.message('jarvis'); await f.send(fromJarvis);
  assert.ok((await f.handle(friday, fromJarvis.id)).ackMessageId, 'Jarvis is not enabled, so it still gets ACKs');
});

test('both recipients enabled: no ACK path is required or created in either direction', async () => {
  const f = await fixture({ recipients: ['friday', 'jarvis'] });
  await f.store.transaction(s => { for (const sub of Object.values(s.subscriptions)) sub.expiresAt = start - 1; });
  const m = f.message('jarvis');
  assert.equal((await f.send(m)).jobIds.length, 1, 'no return subscription needed when no ACK will be sent');
  assert.equal((await f.handle(friday, m.id)).ackMessageId, null);
  await assert.rejects(f.send(f.sync('friday')), /recipient_subscription_required/);
});

test('flag unset = v1: every wake carries the native message ID, ACKs are created, no sync state exists', async () => {
  for (const options of [{ wakeSync: false }, { recipients: [] }]) {
    const f = await fixture(options);
    const plain = f.message(), classed = f.sync('jarvis', { subject: 'S', dueAt: iso(start + 86400000) });
    assert.deepEqual(await f.send(plain), { messageId: plain.id, queued: true, duplicate: false, jobIds: jobsFor(f.snapshot(), plain.id).map(j => j.id) });
    assert.equal((await f.send(classed)).jobIds.length, 1);
    const read = await f.bridge.read(friday, { messageId: plain.id });
    assert.equal('syncBatches' in read, false);
    assert.ok((await f.handle(friday, plain.id)).ackMessageId);
    const s = f.snapshot();
    assert.equal(s.syncQueues, undefined);
    const fridayJobs = Object.values(s.jobs).filter(j => j.recipient === 'friday');
    assert.deepEqual(fridayJobs.map(j => JSON.parse(j.body).data.messageId).sort(), [plain.id, classed.id].sort());
    for (const m of Object.values(s.messages)) assert.deepEqual(Object.keys(m).sort(), ['authorization', 'envelope', 'hash', 'jobIds', 'retainUntil', 'storedAt']);
    f.set(noon + 5000);
    assert.deepEqual(await f.bridge.flushSync(), { boundary: noon, results: [], dispatch: [] });
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

test('rollback: leftovers are re-sent under their own message IDs where v1 authority allows, otherwise in one batch', async () => {
  const f = await fixture();
  const native = f.sync(); await f.send(native);
  const expiredAuthority = f.sync(); await f.send(expiredAuthority, who('jarvis', start + 10 * MINUTE));
  f.enabled.recipients = [];
  const after = f.sync(); assert.equal((await f.send(after)).jobIds.length, 1, 'new SYNC is WAKE once rolled back');
  assert.equal('syncBatches' in await f.bridge.read(friday, { messageId: after.id }), false);
  f.set(start + 30 * MINUTE); // any run, no need to wait for an even hour
  const out = await f.bridge.flushSync();
  assert.deepEqual(out.results, [{ recipient: 'friday', outcome: 'native', items: 1 },
    { recipient: 'friday', outcome: 'flushed', reason: 'rollback', items: 1 }]);
  const s = f.snapshot();
  assert.deepEqual(JSON.parse(jobsFor(s, native.id)[0].body), { event: EVENT_NAME, data: { messageId: native.id } });
  assert.ok(out.dispatch.includes(native.id));
  const batch = batchesIn(s)[0];
  assert.deepEqual(batch.syncBatch.itemIds, [expiredAuthority.id]);
  assert.match(batch.envelope.text, new RegExp(expiredAuthority.id), 'unchanged receivers see the native ID in the text');
  // An unchanged receiver reads, claims and completes it as an ordinary status message.
  await f.ack(batch.envelope.id);
  assert.equal(f.snapshot().receipts[expiredAuthority.id].state, 'complete');
  // And handles the natively re-sent item exactly like any v1 message (ACK included).
  assert.ok((await f.handle(friday, native.id)).ackMessageId);
});

test('repository wiring: no Vercel cron; the GitHub Actions hourly trigger POSTs the route outside the MCP catch-all', () => {
  const config = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url)));
  assert.equal(config.crons, undefined, 'Hobby plans reject hourly Vercel crons');
  const workflow = readFileSync(new URL('../.github/workflows/bridge-cron-flush.yml', import.meta.url), 'utf8');
  for (const line of ["- cron: '0 * * * *'", 'workflow_dispatch:', 'permissions: {}', 'timeout-minutes: 5',
    'group: bridge-cron-flush', 'secrets.CRON_SECRET', 'vars.BRIDGE_CRON_URL', '--fail-with-body', '--request POST',
    'echo "::error::Bridge SYNC flush is not configured', 'exit 1']) {
    assert.ok(workflow.includes(line), line);
  }
  assert.equal(/^\s*-?\s*uses:/m.test(workflow), false, 'no third-party actions');
  assert.equal(/exit 0/.test(workflow), false, 'a missing secret or URL never passes silently');
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
  const complete = fridayTools.find(t => t.name === 'bridge_receipt_complete').inputSchema;
  assert.equal(complete.properties.syncBatchIds.type, 'array'); assert.equal(complete.required.includes('syncBatchIds'), false);
  assert.deepEqual(complete.required, ['messageId', 'claimId', 'hostedEventId', 'hostedTurnId']);
  const health = await f.call('friday', 'bridge_health', {});
  assert.deepEqual(health.structuredContent.readiness.wakeSync, { valid: true, recipients: ['friday'], flushScheduleConfigured: true });
  const off = await runtimeFixture({ BRIDGE_WAKE_SYNC_RECIPIENTS: undefined });
  assert.equal((await off.call('friday', 'bridge_health', {})).structuredContent.readiness.wakeSync, undefined);
  assert.equal((await off.rpc('friday', 'tools/list', {})).body.result.tools.some(t => t.name === 'bridge_inbox_read'), false);
});

const auth = { authorization: 'Bearer fixture-cron-secret-value' };
test('runtime cron auth: POST and GET need the exact CRON_SECRET bearer; other methods and an unset secret are refused', async () => {
  const f = await runtimeFixture({}, noon + 5 * MINUTE);
  for (const method of ['POST', 'GET']) {
    assert.equal((await f.cron({}, method)).status, 401, method);
    assert.equal((await f.cron({ authorization: 'Bearer wrong-secret-value-xx' }, method)).status, 401, method);
    assert.equal((await f.cron({ authorization: 'fixture-cron-secret-value' }, method)).status, 401, method);
    assert.equal((await f.cron({ authorization: 'Bearer fixture-cron-secret-valuX' }, method)).status, 401, method);
    assert.equal((await f.cron(auth, method)).status, 200, method);
  }
  assert.equal((await f.cron(auth, 'PUT')).status, 405);
  for (const secret of [undefined, '', 'short-secret']) {
    const unset = await runtimeFixture({ CRON_SECRET: secret }, noon + 5 * MINUTE);
    assert.equal((await unset.cron({ authorization: 'Bearer ' + secret })).status, 503, String(secret));
  }
  const disabled = await runtimeFixture({ BRIDGE_DELIVERY_ENABLED: 'false' }, noon + 5 * MINUTE);
  assert.deepEqual(await (await disabled.cron(auth)).json(), { status: 'skipped', reason: 'delivery_not_enabled' });
});

const idle = boundary => ({ status: 'ok', boundary, flushed: 0, capped: 0, redeliveredNative: 0, dispatched: 0, dispatchPending: 0 });
test('runtime cron: odd hour is a no-op; even-hour (late) POST flushes one v1-shaped webhook; the receiver reads and acknowledges', async () => {
  const f = await runtimeFixture();
  const a = f.message({ subject: 'A' }), b = f.message({ subject: 'B' });
  for (const m of [a, b]) assert.equal((await f.call('jarvis', 'bridge_message_send', m)).structuredContent.delivery, 'batched');
  f.set(Date.UTC(2026, 9, 19, 16, 0, 5)); // 11:00 CDT
  assert.deepEqual(await (await f.cron(auth)).json(), idle('2026-10-19T15:00:00.000Z'));
  f.set(noon + 25 * MINUTE); // 12:25 CDT: late run
  const sendsBefore = f.sends.length;
  assert.deepEqual(await (await f.cron(auth)).json(), { ...idle('2026-10-19T17:00:00.000Z'), flushed: 1, dispatched: 1 });
  f.set(noon + 29 * MINUTE);
  assert.deepEqual(await (await f.cron(auth, 'GET')).json(), idle('2026-10-19T17:00:00.000Z'), 'duplicate run, same even hour');
  const dispatch = f.sends.slice(sendsBefore).map(args => args[1]).find(p => p.dispatchMessageId);
  const batchId = dispatch.dispatchMessageId;
  await f.consume(dispatch);
  assert.deepEqual(f.posts.filter(p => p.event === EVENT_NAME), [{ event: EVENT_NAME, data: { messageId: batchId } }]);
  // Flagged receiver contract: read the woken message (full syncBatches), then claim and complete it.
  const read = (await f.call('friday', 'bridge_read', { messageId: batchId })).structuredContent;
  assert.deepEqual(read.syncBatches[0].items.map(i => i.subject), ['A', 'B']);
  assert.deepEqual((await f.call('friday', 'bridge_inbox_read', {})).structuredContent.syncBatches.map(x => x.messageId), [batchId],
    'unacknowledged batch replays');
  const claim = (await f.call('friday', 'bridge_receipt_claim', { messageId: batchId })).structuredContent;
  const done = (await f.call('friday', 'bridge_receipt_complete', { messageId: batchId, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null })).structuredContent;
  assert.equal(done.ackMessageId, null);
  assert.equal((await f.call('jarvis', 'bridge_status', { messageId: a.id })).structuredContent.receiptCompleted, true);
  assert.deepEqual((await f.call('friday', 'bridge_inbox_read', {})).structuredContent, { syncBatches: [] });
});

// [UTC run time, expected batches flushed by that run].
for (const [name, queuedAt, runs] of [
  ['fall back, Nov 1 2026', Date.UTC(2026, 10, 1, 5, 40), [ // 00:40 CDT
    [Date.UTC(2026, 10, 1, 6, 0, 5), 0], // 01:00 CDT
    [Date.UTC(2026, 10, 1, 7, 0, 5), 1], // 01:00 CST: waiting for 02:00 CST would exceed 2 elapsed hours
    [Date.UTC(2026, 10, 1, 7, 20), 0], // duplicate
    [Date.UTC(2026, 10, 1, 8, 0, 5), 0], // 02:00 CST, nothing pending
  ]],
  ['spring forward, Mar 8 2026', Date.UTC(2026, 2, 8, 6, 40), [ // 00:40 CST
    [Date.UTC(2026, 2, 8, 7, 0, 5), 0], // 01:00 CST
    [Date.UTC(2026, 2, 8, 8, 5), 1], // 03:05 CDT, replaces the nonexistent 02:00
    [Date.UTC(2026, 2, 8, 8, 29), 0],
    [Date.UTC(2026, 2, 8, 9, 0, 5), 0], // 04:00 CDT, empty
  ]],
]) {
  test(`runtime cron across DST (${name}): one flush within 2 elapsed hours`, async () => {
    const f = await runtimeFixture({}, queuedAt);
    assert.equal((await f.call('jarvis', 'bridge_message_send', f.message())).structuredContent.delivery, 'batched');
    for (const [at, expected] of runs) {
      f.set(at);
      const body = await (await f.cron(auth)).json();
      assert.equal(body.status, 'ok', iso(at)); assert.equal(body.flushed, expected, iso(at));
      if (expected) assert.ok(at - queuedAt <= WAKE_WINDOW_MS);
    }
    assert.equal(f.sends.filter(args => args[1].dispatchMessageId).length, 2, 'the send prearm plus one batch');
  });
}
