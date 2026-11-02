import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { generateKeyPair, SignJWT } from 'jose';
import { Bridge } from '../src/bridge.ts';
import { MemoryStore, emptyState } from '../src/store.ts';
import { VERIFIED_AUTHORIZATION, SCOPES, DELIVERY_TRANSPORT_OUTCOME } from '../src/policy.ts';
import { validateMessage, MESSAGE_PROTOCOL, SYNC_MESSAGE_TTL_MS, CONTENT_RETENTION_MS } from '../src/messages.ts';
import { createProtector } from '../src/webhook.ts';
import { NativeEvents, EVENT_NAME } from '../src/events.ts';
import { createRuntime } from '../src/runtime.ts';
import { resourceFor } from '../src/resource.ts';
import { TOPIC } from '../src/queue.ts';
import { DeliveryWorker, reofferOverdueJobs } from '../src/worker.ts';
import { ISSUER } from './fixtures/provider.ts';
import { classify, wakeSyncRecipients, isFlushBoundary, latestFlushBoundary, nextFlushBoundary, chicagoDate,
  chicagoWall, chicagoDayHours, dailyFlushCap, SYNC_DAILY_FLUSH_CAP, WAKE_WINDOW_MS, SYNC_DEADLINE_MS,
  SYNC_BATCH_TTL_MS, SYNC_RECEIPT_RECOVERY_MS, MAX_SYNC_RECEIPT_RECOVERIES } from '../src/sync.ts';
import type { BatchPresentation, BridgeOptions } from '../src/bridge.ts';
import type { RuntimePoolConstructor, RuntimeQueueClient } from '../src/runtime.ts';
import type { QueueClient } from '../src/queue.ts';
import type { TransportRequest, TransportResponse } from '../src/webhook.ts';
import type { BridgeError } from '../src/policy.ts';
import type { BridgeState, JsonObject, Principal, ResourceDenial, Store, StoredMessage, Transition, VerifiedPrincipal } from '../src/types.ts';
import type { ListedTool, RpcResponse, ToolCallResult } from './types.ts';

/** A message draft as the fixture builds it (the bridge validates it). */
type Draft = { id: string; from: string; to: string; kind: string; class?: string; subject?: string; text?: string; expiresAt: string;
  sentAt: string; threadId: string; [field: string]: unknown };
interface FixtureOptions {
  recipients?: string[]; at?: number; wakeSync?: boolean; bridgeOptions?: Partial<BridgeOptions>; wrapStore?: (store: Store) => Store;
}
type Fx = Awaited<ReturnType<typeof fixture>>;
/** Runtime tool outputs as these tests read them (a localized test view). */
type RtOutput = { [field: string]: unknown; error?: string; messageId: string; claimId: string; ackMessageId: string | null;
  delivery?: string; jobIds: string[]; syncBatches: BatchPresentation[]; syncBatchIds: string[]; syncBatchesAcked: string[];
  readiness: Record<string, unknown> & { wakeSync: Record<string, unknown> }; envelope: Record<string, unknown> };
type RtBody = RpcResponse<ToolCallResult<RtOutput> & { tools: ListedTool[] }>;
type SendArgs = Parameters<QueueClient['send']>;
/** The cron route's JSON report, as these tests read it. */
type CronReport = { [field: string]: unknown; status?: string; flushed?: number };
/** A completion result as the commit-fault store wrappers inspect it. */
type Done = { completed?: unknown; duplicate?: unknown } | null | undefined;
type Consumer = (payload: unknown, metadata: object) => Promise<unknown>;

const HOUR = 3600000, MINUTE = 60000, policy = 'c'.repeat(64);
// 2026-10-19 10:30 America/Chicago (CDT, UTC-5). Next even boundary: 12:00 CDT = 17:00Z.
const start = Date.UTC(2026, 9, 19, 15, 30);
const noon = Date.UTC(2026, 9, 19, 17);
const iso = (ms: number) => new Date(ms).toISOString();
function who(role: string, until = start + 7 * 86400000) {
  return Object.defineProperty<Principal>({ role, scopes: Object.values(SCOPES[role]!), principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64) },
    VERIFIED_AUTHORIZATION, { value: { policyId: policy, expiresAt: until } }) as VerifiedPrincipal;
}
const jarvis = who('jarvis'), friday = who('friday');
// bridgeOptions: extra Bridge options (e.g. a prepareReceipt spy); wrapStore:
// wraps the store the bridge (only) uses, for commit-fault injection.
async function fixture({ recipients = ['friday'], at = start, wakeSync = true, bridgeOptions = {}, wrapStore }: FixtureOptions = {}) {
  let now = at;
  const enabled: { recipients: string[] | null } = { recipients };
  const store = new MemoryStore(), clock = () => now;
  const bridge = new Bridge({ store: wrapStore ? wrapStore(store) : store, clock, dailyEnabled: true,
    messagePolicyIds: { jarvis: policy, friday: policy }, ...(wakeSync ? { wakeSync: () => enabled.recipients } : {}), ...bridgeOptions });
  const events = new NativeEvents({ store, protector: createProtector(randomBytes(32)), clock, policyId: policy, enabled: true,
    transport: async (_url: string, req: TransportRequest): Promise<TransportResponse> => ({ status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  await events.subscribe(who('jarvis', now + 7 * 86400000), { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  const message = (from = 'jarvis', extra: Record<string, unknown> = {}): Draft => ({ protocol: MESSAGE_PROTOCOL, id: randomUUID(), from,
    to: from === 'jarvis' ? 'friday' : 'jarvis', kind: 'status', sentAt: iso(now), expiresAt: iso(now + HOUR),
    threadId: randomUUID(), route: 'inbox', text: 'Fixture status data only.', ...extra });
  const sync = (from = 'jarvis', extra: Record<string, unknown> = {}) => message(from, { class: 'sync', expiresAt: iso(now + 6 * HOUR), ...extra });
  const principal = (role: string) => who(role, at + 7 * 86400000);
  const send = (m: Draft, as = principal(m.from)) => bridge.sendMessage(as, m);
  const handle = async (as: Principal, id: string, syncBatchIds?: string[]) => {
    const claim = await bridge.claim(as, { messageId: id });
    return bridge.complete(as, { messageId: id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null,
      ...(syncBatchIds ? { syncBatchIds } : {}) });
  };
  // The documented flagged-receiver flow for any woken message or batch: read,
  // claim, (handle), complete naming the batches from this read that this
  // claim may handle: the batch itself on a direct completion, plus attached
  // batches the claim holds.
  const receive = async (id: string, as = principal('friday')) => {
    const read = await bridge.read(as, { messageId: id });
    const claim = await bridge.claim(as, { messageId: id });
    const syncBatchIds = (read.syncBatches || []).map(b => b.messageId)
      .filter(batch => batch === id || claim.syncBatchIds?.includes(batch));
    return bridge.complete(as, { messageId: id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null, syncBatchIds });
  };
  return { store, bridge, events, clock, enabled, message, sync, send, handle, receive, principal, snapshot: () => store.snapshot(),
    set: (ms: number) => { now = ms; }, advance: (ms: number) => { now += ms; } };
}
const jobsFor = (s: BridgeState, id: string) => Object.values(s.jobs).filter(job => job.messageId === id);
const batchesIn = (s: BridgeState) => Object.values(s.messages).filter(m => m.syncBatch);
const ids = (batches: (BatchPresentation | null)[]) => batches.map(b => b!.items.map(i => i.messageId));

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
    ['expiresAt', 'expires_before_sync_deadline']] as [string, string][]) {
    assert.deepEqual(classify({ ...base, [field]: iso(now + WAKE_WINDOW_MS) }, now), { class: 'wake', promoted: reason }, 'now + 2h');
    assert.deepEqual(classify({ ...base, [field]: iso(deadline) }, now), { class: 'wake', promoted: reason }, 'deadline');
    assert.deepEqual(classify({ ...base, [field]: iso(deadline + 1) }, now), { class: 'sync' }, 'deadline + 1ms');
  }
  assert.deepEqual(classify({ ...base, dueAt: iso(now - HOUR) }, now), { class: 'wake', promoted: 'due_before_sync_deadline' });
  // Formerly an expiry one second after the next theoretical boundary stayed SYNC.
  assert.equal(nextFlushBoundary(now), noon);
  assert.deepEqual(classify({ ...base, expiresAt: iso(noon + 1000) }, now), { class: 'wake', promoted: 'expires_before_sync_deadline' });
});

test('workflow safety: handoff requests are always WAKE even when mislabeled SYNC, both directions', async () => {
  const base = { kind: 'handoff_request', class: 'sync', expiresAt: iso(start + 6 * HOUR) };
  assert.deepEqual(classify(base, start), { class: 'wake', promoted: 'handoff_requires_wake' });
  assert.deepEqual(classify({ ...base, effectiveAt: iso(start + 5 * HOUR), dueAt: iso(start + 5 * HOUR) }, start),
    { class: 'wake', promoted: 'handoff_requires_wake' });
  for (const [from, recipient] of [['jarvis', 'friday'], ['friday', 'jarvis']] as [string, string][]) {
    const f = await fixture({ recipients: [recipient] });
    const handoff = f.sync(from, { kind: 'handoff_request', subject: 'Workflow handoff',
      text: 'Receiver decision and workflow transition required.', effectiveAt: iso(start + 5 * HOUR), dueAt: iso(start + 5 * HOUR) });
    const first = await f.send(handoff), hash = f.snapshot().messageIds![handoff.id]!.hash;
    assert.equal(first.class, 'wake'); assert.equal(first.promoted, 'handoff_requires_wake');
    assert.equal(first.jobIds.length, 1); assert.equal(first.delivery, 'immediate');
    assert.equal(f.snapshot().messages[handoff.id]!.envelope.class, 'sync', 'canonical envelope remains sender-authored');
    const duplicate = await f.send(handoff);
    assert.equal(duplicate.duplicate, true); assert.equal(f.snapshot().messageIds![handoff.id]!.hash, hash);
    assert.equal(jobsFor(f.snapshot(), handoff.id).length, 1);
  }
  const off = await fixture({ wakeSync: false });
  const legacy = off.sync('jarvis', { kind: 'handoff_request' }), sent = await off.send(legacy);
  assert.equal(sent.jobIds.length, 1); assert.equal(off.snapshot().syncQueues, undefined);
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
    [{ expiresAt: iso(start + HOUR + 1) }, /invalid_message_lifetime/]] as [Record<string, unknown>, RegExp][]) {
    assert.throws(() => validateMessage({ ...m, ...bad }, jarvis, start), code!, JSON.stringify(bad));
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
  assert.deepEqual(first.syncBatches[0]!.items.map(i => i.text), ['v2', 'other', 'no subject']);
  assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync!.state, 'superseded');
  assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync!.supersededBy, v2.id);
  await f.handle(friday, first.syncBatches[0]!.messageId, [first.syncBatches[0]!.messageId]);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  const v3 = f.sync('jarvis', { subject: 'Deploy status', text: 'v3' }); await f.send(v3);
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[v3.id]]);
  const jobs = Object.values(f.snapshot().jobs);
  assert.equal(jobs.filter(j => j.recipient === 'friday').length, 0, 'no item ever produced its own wake');
  // The one handled batch got one ACK back to the sender (none per item).
  const acks = Object.values(f.snapshot().messages).filter(m => m.envelope.kind === 'ack');
  assert.deepEqual(acks.map(m => m.envelope.correlationId), [first.syncBatches[0]!.messageId]);
  assert.deepEqual(jobs.map(j => j.messageId), [acks[0]!.envelope.id]);
});

test('inbox read survives a lost response: unacknowledged batches replay until their receipt is acknowledged', async () => {
  const f = await fixture();
  const a = f.sync(); await f.send(a);
  const lost = await f.bridge.inboxRead(friday); // response never reaches the receiver
  const again = await f.bridge.inboxRead(friday);
  assert.deepEqual(again, lost, 're-read returns the same batch and items');
  assert.equal(batchesIn(f.snapshot()).length, 1, 'no second cut');
  f.advance(1000); // distinct cut times, so the replay order below is creation order
  const b = f.sync(); await f.send(b);
  const both = await f.bridge.inboxRead(friday);
  assert.deepEqual(ids(both.syncBatches), [[a.id], [b.id]]);
  const done = await f.handle(friday, lost.syncBatches[0]!.messageId, [lost.syncBatches[0]!.messageId]);
  assert.equal(f.snapshot().messages[done.ackMessageId!]!.envelope.correlationId, lost.syncBatches[0]!.messageId, 'batch ACK');
  assert.equal(f.snapshot().receipts[a.id]!.state, 'complete');
  assert.equal(f.snapshot().receipts[b.id], undefined, 'only the acknowledged batch is handled');
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[b.id]]);
  await f.handle(friday, both.syncBatches[1]!.messageId, [both.syncBatches[1]!.messageId]);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
});

test('concurrent inbox readers neither double-cut nor lose items', async () => {
  const f = await fixture();
  const sent = [];
  for (let i = 0; i < 5; i++) { const m = f.sync('jarvis', { subject: `s${i}` }); sent.push(m.id); await f.send(m); }
  const reads = await Promise.all(Array.from({ length: 6 }, () => f.bridge.inboxRead(friday)));
  for (const r of reads) assert.deepEqual(r, reads[0]);
  assert.equal(batchesIn(f.snapshot()).length, 1);
  assert.deepEqual(ids(reads[0]!.syncBatches).flat().sort(), sent.sort());
  await Promise.all([f.handle(friday, reads[0]!.syncBatches[0]!.messageId, [reads[0]!.syncBatches[0]!.messageId]).catch(() => null),
    f.bridge.inboxRead(friday), f.send(f.sync('jarvis', { subject: 'late' }))]);
  const after = await f.bridge.inboxRead(friday);
  assert.equal(after.syncBatches.length, 1); assert.equal(after.syncBatches[0]!.items[0]!.subject, 'late');
});

test('an unacknowledged batch is reclaimed after its replay lifetime and its items are re-sent flagged late', async () => {
  const f = await fixture();
  const a = f.sync(); await f.send(a);
  const first = (await f.bridge.inboxRead(friday)).syncBatches[0];
  f.advance(SYNC_BATCH_TTL_MS);
  const next = (await f.bridge.inboxRead(friday)).syncBatches;
  assert.equal(next.length, 1); assert.notEqual(next[0]!.messageId, first!.messageId);
  assert.deepEqual(next[0]!.items.map(i => [i.messageId, i.expired, i.late]), [[a.id, true, true]]);
  const status = await f.bridge.status(jarvis, { messageId: first!.messageId });
  assert.equal(status.syncBatch!.reclaimed, true); assert.equal(status.syncBatch!.acknowledged, false);
  assert.equal((await f.bridge.status(jarvis, { messageId: a.id })).sync!.redeliveries, 1);
});

test('Chicago even-hour boundaries and day lengths across both 2026 DST transitions', () => {
  const boundaries = (y: number, m: number, d: number) => {
    const out: number[] = [], date = `${y}-${String(m + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
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
  assert.deepEqual(JSON.parse(jobsFor(s, batchId!)[0]!.body), { event: EVENT_NAME, data: { messageId: batchId } });
  assert.deepEqual((await f.bridge.flushSync()).dispatch, [batchId], 'unpublished batch is re-offered, not re-cut');
  await f.bridge.markSyncDispatched([batchId!]);
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
  assert.equal(out.results[0]!.outcome, 'flushed');
  const view = (await g.bridge.read(friday, { messageId: out.dispatch[0] })).syncBatches![0]!.items[0];
  assert.deepEqual([view!.messageId, view!.expired, view!.late], [late.id, true, true]);
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
  assert.match(read.envelope.text!, new RegExp(a.id));
  assert.deepEqual(read.syncBatches![0]!.items.map(i => [i.messageId, i.text]), [[a.id, a.text]]);
  const done = await f.bridge.complete(friday, { messageId: batchId, claimId: claim.claimId, hostedEventId: 'evt_1', hostedTurnId: null });
  assert.equal('ackSuppressed' in done, false);
  const ack = f.snapshot().messages[done.ackMessageId!]!.envelope;
  assert.deepEqual([ack.kind, ack.from, ack.to, ack.correlationId, ack.threadId], ['ack', 'friday', 'jarvis', batchId, batchId]);
  const item = await f.bridge.status(jarvis, { messageId: a.id });
  assert.equal(item.receiptCompleted, true); assert.equal(item.sync!.via, 'flush'); assert.equal(item.sync!.batchMessageId, batchId);
  assert.equal(item.ackMessageId, null, 'no ACK per item'); assert.equal(item.batchAckMessageId, done.ackMessageId, 'covered by the batch ACK');
  assert.equal(f.snapshot().receipts[a.id]!.viaBatch, batchId);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  assert.deepEqual(Object.values(f.snapshot().jobs).map(j => [j.messageId, j.recipient]).sort(),
    [[batchId, 'friday'], [done.ackMessageId, 'jarvis']].sort(), 'the batch wake plus one batch ACK');
});

// Hourly runs on time across a whole Chicago day, an item every 30 minutes:
// nobody waits more than 2 elapsed hours, and flushes stay within the day's cap.
for (const [name, y, m, d, flushes] of [['spring forward', 2026, 2, 8, 12], ['normal day', 2026, 9, 19, 12], ['fall back', 2026, 10, 1, 13]] as [string, number, number, number, number][]) {
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
        for (const id of out.dispatch) await f.receive(id); // the woken receiver reads, claims and completes
      }
    }
    const items = Object.values(f.snapshot().messages).filter(x => x.sync && x.sync.state === 'delivered');
    const max = Math.max(...items.map(x => x.sync!.deliveredAt! - x.storedAt));
    assert.ok(max <= WAKE_WINDOW_MS, `max wait ${max / MINUTE} min`);
    assert.equal(count, flushes); assert.ok(count <= dailyFlushCap(date));
  });
}

test('malformed recipient rollout fails closed and preserves queued SYNC data', async () => {
  const f = await fixture();
  const queued = f.sync(); await f.send(queued);
  const before = f.snapshot();
  f.enabled.recipients = null;
  f.set(noon + 5000);
  await assert.rejects(f.bridge.flushSync(), /wake_sync_configuration_invalid/);
  assert.deepEqual(f.snapshot(), before);
  const urgent = f.message();
  const sent = await f.send(urgent);
  assert.equal(sent.jobIds.length, 1, 'ordinary direct traffic keeps the v1 route');
  assert.equal('delivery' in sent, false);
  const done = await f.handle(friday, urgent.id);
  assert.ok(done.ackMessageId, 'ordinary terminal ACK remains available');
});

test('flush rechecks an invalidated rollout after the storage-lock wait before mutating queued SYNC', async () => {
  let config = { valid: true, recipients: ['friday'] }, hold = false;
  let entered!: () => void, release!: () => void;
  const enteredLockWait = new Promise<void>(resolve => { entered = resolve; });
  const lockReleased = new Promise<void>(resolve => { release = resolve; });
  const f = await fixture({ bridgeOptions: { wakeSync: () => config }, wrapStore: (store: Store) => ({
    transaction: async <T>(fn: Transition<T>): Promise<T> => {
      if (!hold) return store.transaction(fn);
      hold = false; entered(); await lockReleased;
      return store.transaction(fn);
    },
  }) });
  const queued = f.sync(); await f.send(queued);
  f.set(noon + 5000);
  const before = f.snapshot();
  hold = true;
  const flushing = f.bridge.flushSync();
  await enteredLockWait;
  config = { valid: false, recipients: [] };
  release!();
  await assert.rejects(flushing, (error: BridgeError) => error.code === 'wake_sync_configuration_invalid' && error.status === 503);
  assert.deepEqual(f.snapshot(), before, 'invalidating while lock-waiting neither flushes nor rolls back queued data');
});

test('flush applies valid recipient removal observed after the storage-lock wait', async () => {
  let config = { valid: true, recipients: ['friday'] }, hold = false;
  let entered!: () => void, release!: () => void;
  const enteredLockWait = new Promise<void>(resolve => { entered = resolve; });
  const lockReleased = new Promise<void>(resolve => { release = resolve; });
  const f = await fixture({ bridgeOptions: { wakeSync: () => config }, wrapStore: (store: Store) => ({
    transaction: async <T>(fn: Transition<T>): Promise<T> => {
      if (!hold) return store.transaction(fn);
      hold = false; entered(); await lockReleased;
      return store.transaction(fn);
    },
  }) });
  const queued = f.sync(); await f.send(queued);
  f.set(noon + 5000);
  hold = true;
  const flushing = f.bridge.flushSync();
  await enteredLockWait;
  config = { valid: true, recipients: [] };
  release!();
  const out = await flushing;
  assert.deepEqual(out.results, [{ recipient: 'friday', outcome: 'native', items: 1 }]);
  assert.deepEqual(out.dispatch, [queued.id], 'the locked mutation uses rollback routing, not the stale enabled setting');
  assert.equal(f.snapshot().messages[queued.id]!.sync!.via, 'native');
});

for (const [name, queuedAt, runs] of [
  // 00:10 CDT; the next even hour (02:00 CST) is three elapsed hours away, so 01:00 CST flushes.
  ['fall back, Nov 1 2026', Date.UTC(2026, 10, 1, 5, 10), [[Date.UTC(2026, 10, 1, 6), null], [Date.UTC(2026, 10, 1, 7), 'max_wait'],
    [Date.UTC(2026, 10, 1, 8), null]]],
  // 00:10 CST; 03:00 CDT replaces the nonexistent 02:00, 1h50m later.
  ['spring forward, Mar 8 2026', Date.UTC(2026, 2, 8, 6, 10), [[Date.UTC(2026, 2, 8, 7), null], [Date.UTC(2026, 2, 8, 8), 'scheduled'],
    [Date.UTC(2026, 2, 8, 9), null]]],
] as [string, number, [number, string | null][]][]) {
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
  await f.store.transaction(s => { Object.assign(s.syncQueues!.friday!, { flushDay: '2026-10-19', flushCount: SYNC_DAILY_FLUSH_CAP }); });
  f.set(noon + 5000);
  assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'daily_cap' }]);
  assert.equal(Object.keys(f.snapshot().syncQueues!.friday!.pending).length, 1);
  f.set(Date.UTC(2026, 9, 20, 5, 0, 5)); // 00:00 CDT next day
  assert.equal((await f.bridge.flushSync()).results[0]!.outcome, 'flushed');
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 1);
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
  assert.equal((await f.bridge.status(friday, { messageId: m.id })).sync!.state, 'pending');
});

test('piggyback on WAKE: completing the read WAKE with its batch IDs acknowledges exactly those batches', async () => {
  const f = await fixture();
  const a = f.sync('jarvis', { subject: 'A' }), stale = f.sync('jarvis', { subject: 'Budget' });
  await f.send(a); await f.send(stale);
  const wake = f.message('jarvis', { subject: 'budget', text: 'Budget decision needed now.' });
  const sent = await f.send(wake);
  assert.equal(sent.delivery, 'immediate'); assert.equal(sent.piggybackedSyncItems, 1);
  assert.equal(Object.keys(f.snapshot().jobs).length, 1, 'only the WAKE webhook');
  assert.equal((await f.bridge.status(jarvis, { messageId: stale.id })).sync!.supersededBy, wake.id);
  const read = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(ids(read.syncBatches!), [[a.id]]);
  assert.deepEqual((await f.bridge.read(friday, { messageId: wake.id })).syncBatches, read.syncBatches, 're-read is stable');
  const done = await f.handle(friday, wake.id, read.syncBatches!.map(b => b.messageId));
  assert.deepEqual(done.syncBatchesAcked, [read.syncBatches![0]!.messageId]);
  assert.equal(f.snapshot().receipts[a.id]!.state, 'complete');
  assert.equal(f.snapshot().receipts[read.syncBatches![0]!.messageId]!.viaMessage, wake.id);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  f.set(noon + 5000);
  assert.deepEqual((await f.bridge.flushSync()).results, [], 'nothing is flushed again');
});

test('completing a WAKE acknowledges no batch it does not name, and rejects names it was never shown', async () => {
  const f = await fixture();
  const a = f.sync(); await f.send(a);
  const wake = f.message(); await f.send(wake);
  const attached = f.snapshot().messages[wake.id]!.syncBatchIds![0];
  // Never read: the attached batch was never presented, so naming it is refused and nothing changes.
  const claim = await f.bridge.claim(friday, { messageId: wake.id });
  for (const syncBatchIds of [[attached], [randomUUID()]]) {
    await assert.rejects(f.bridge.complete(friday, { messageId: wake.id, claimId: claim.claimId, hostedEventId: null,
      hostedTurnId: null, syncBatchIds }), /sync_batch_not_presented/);
  }
  await assert.rejects(f.bridge.complete(friday, { messageId: wake.id, claimId: claim.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: 'all' }), /invalid_params/);
  assert.equal(f.snapshot().receipts[wake.id]!.state, 'claimed');
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
  assert.deepEqual(ids(readA.syncBatches!), [[p.id]]);
  const claimA = await f.bridge.claim(friday, { messageId: wake.id });
  // New SYNC data X arrives; reader B reads W during A's claim and is shown X, then loses the response.
  const x = f.sync('jarvis', { subject: 'X' }); await f.send(x);
  const readB = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(ids(readB.syncBatches!), [[p.id], [x.id]]);
  const batchX = readB.syncBatches![1]!.messageId;
  // A completes with exactly what A saw.
  const doneA = await f.bridge.complete(friday, { messageId: wake.id, claimId: claimA.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: readA.syncBatches!.map(b => b.messageId) });
  assert.deepEqual(doneA.syncBatchesAcked, [readA.syncBatches![0]!.messageId]);
  assert.equal(f.snapshot().receipts[p.id]!.state, 'complete');
  assert.equal(f.snapshot().receipts[x.id], undefined, 'X was never handled by A');
  assert.equal(f.snapshot().receipts[batchX], undefined);
  assert.equal((await f.bridge.status(jarvis, { messageId: batchX })).syncBatch!.acknowledged, false);
  // X stays deliverable and is acknowledged by its own claim.
  const replay = await f.bridge.inboxRead(friday);
  assert.deepEqual(replay.syncBatches.map(b => b!.messageId), [batchX]);
  const doneX = await f.handle(friday, batchX, [batchX]);
  assert.deepEqual(doneX.syncBatchesAcked, [batchX]);
  assert.equal(doneX.completed, true);
  assert.equal(f.snapshot().receipts[x.id]!.state, 'complete');
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
});

test('direct batch: read B, claim B, complete B with syncBatchIds [B] acknowledges B exactly once', async () => {
  const f = await fixture();
  const a = f.sync(); await f.send(a);
  f.set(noon + 5000);
  const batchId = (await f.bridge.flushSync()).dispatch[0];
  await f.bridge.markSyncDispatched([batchId!]);
  const read = await f.bridge.read(friday, { messageId: batchId });
  assert.deepEqual(read.syncBatches!.map(b => b.messageId), [batchId], 'a direct read returns the batch itself');
  const claim = await f.bridge.claim(friday, { messageId: batchId });
  assert.equal(claim.syncBatchIds, undefined, 'nothing attached to hold');
  const complete = () => f.bridge.complete(friday, { messageId: batchId, claimId: claim.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: read.syncBatches!.map(b => b.messageId) });
  const done = await complete();
  assert.deepEqual(done.syncBatchesAcked, [batchId]);
  const ackedAt = f.snapshot().messages[batchId!]!.syncBatch!.ackedAt, receipt = f.snapshot().receipts[a.id];
  assert.equal(receipt!.state, 'complete'); assert.equal(receipt!.viaBatch, batchId);
  const again = await complete();
  assert.equal(again.duplicate, true); assert.equal(again.syncBatchesAcked, undefined);
  assert.equal(f.snapshot().messages[batchId!]!.syncBatch!.ackedAt, ackedAt);
  assert.deepEqual(f.snapshot().receipts[a.id], receipt, 'acknowledged once');
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  // The documented helper flow gives the same result for a fresh batch.
  await f.send(f.sync());
  f.set(noon + 2 * HOUR + 5000);
  const next = (await f.bridge.flushSync()).dispatch[0];
  assert.notEqual(next, batchId);
  assert.deepEqual((await f.receive(next!)).syncBatchesAcked, [next]);
});

// A WAKE W with batch B attached and presented: one reader holds W, another
// gets B from bridge_inbox_read. B has one claim record shared by both paths.
async function heldBatchFixture() {
  const f = await fixture();
  const a = f.sync('jarvis', { subject: 'A' }), x = f.sync('jarvis', { subject: 'X' });
  await f.send(a); await f.send(x);
  const wake = f.message(); await f.send(wake);
  const read = await f.bridge.read(friday, { messageId: wake.id });
  const batch = read.syncBatches![0]!.messageId;
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches.map(b => b!.messageId), [batch]);
  const complete = (id: string, claimId: string | undefined, syncBatchIds?: string[]) => f.bridge.complete(friday, { messageId: id, claimId, hostedEventId: null,
    hostedTurnId: null, ...(syncBatchIds ? { syncBatchIds } : {}) });
  return { f, a, x, wake, batch, complete };
}

test('shared batch fence (a): handling B via its WAKE and handling B directly are mutually exclusive', async () => {
  // W first: W's claim holds B, so the direct claim of B is refused.
  {
    const { f, wake, batch, complete } = await heldBatchFixture();
    const claimW = await f.bridge.claim(friday, { messageId: wake.id });
    assert.deepEqual([claimW.syncBatchIds, claimW.syncBatchesHeldElsewhere], [[batch], []]);
    await assert.rejects(f.bridge.claim(friday, { messageId: batch }), /receipt_busy/);
    assert.deepEqual((await complete(wake.id, claimW.claimId, [batch])).syncBatchesAcked, [batch]);
    assert.equal((await f.bridge.claim(friday, { messageId: batch })).duplicate, true, 'already handled via W');
  }
  // B first: the direct claim holds B, so W's claim excludes it and W cannot acknowledge it.
  {
    const { f, wake, batch, complete } = await heldBatchFixture();
    const claimB = await f.bridge.claim(friday, { messageId: batch });
    const claimW = await f.bridge.claim(friday, { messageId: wake.id });
    assert.deepEqual([claimW.syncBatchIds, claimW.syncBatchesHeldElsewhere], [[], [batch]]);
    await assert.rejects(complete(wake.id, claimW.claimId, [batch]), /sync_batch_not_held/);
    assert.equal(f.snapshot().receipts[wake.id]!.state, 'claimed', 'the rejected completion changed nothing');
    assert.deepEqual((await complete(batch, claimB.claimId, [batch])).syncBatchesAcked, [batch]);
  }
  // Simultaneous: exactly one path gets handling permission for B.
  for (let round = 0; round < 4; round++) {
    const { f, wake, batch } = await heldBatchFixture();
    const order = [() => f.bridge.claim(friday, { messageId: wake.id }), () => f.bridge.claim(friday, { messageId: batch })];
    if (round % 2) order.reverse();
    const settled = await Promise.allSettled(order.map(run => run()));
    const [viaW, direct] = round % 2 ? [settled[1], settled[0]] : settled;
    assert.equal(viaW!.status, 'fulfilled', 'W itself is always claimable');
    const viaWHolds = viaW!.value.syncBatchIds!.includes(batch), directHolds = direct!.status === 'fulfilled';
    assert.equal(viaWHolds !== directHolds, true, `exactly one holder (round ${round})`);
    if (!directHolds) assert.match(direct!.reason.code, /receipt_busy/);
    else assert.deepEqual(viaW!.value.syncBatchesHeldElsewhere, [batch]);
  }
});

test('shared batch fence (b): two simultaneous direct claims of a batch cannot both succeed', async () => {
  const { f, batch } = await heldBatchFixture();
  const settled = await Promise.allSettled(Array.from({ length: 5 }, () => f.bridge.claim(friday, { messageId: batch })));
  assert.equal(settled.filter(r => r.status === 'fulfilled').length, 1);
  for (const r of settled.filter(r => r.status === 'rejected')) assert.equal(r.reason.code, 'receipt_busy');
});

test('shared batch fence (c): a completion never overwrites a receipt owned by another claim', async () => {
  // W's completion against B held directly: B's receipt stays the direct claim's.
  {
    const { f, wake, batch, complete } = await heldBatchFixture();
    const claimB = await f.bridge.claim(friday, { messageId: batch });
    const heldB = f.snapshot().receipts[batch];
    const claimW = await f.bridge.claim(friday, { messageId: wake.id });
    await assert.rejects(complete(wake.id, claimW.claimId, [batch]), /sync_batch_not_held/);
    await complete(wake.id, claimW.claimId);
    assert.deepEqual(f.snapshot().receipts[batch], heldB);
    await complete(batch, claimB.claimId, [batch]);
    const doneB = f.snapshot().receipts[batch];
    assert.equal(doneB!.claimId, claimB.claimId); assert.equal(doneB!.viaMessage, undefined);
    // ...and vice versa: B's completion left W's own receipt as W's claim completed it.
    assert.equal(f.snapshot().receipts[wake.id]!.claimId, claimW.claimId);
    assert.equal(f.snapshot().receipts[wake.id]!.state, 'complete');
  }
  // Items are fenced by their batch: claiming one on its own is refused. A live
  // item claim left by older code keeps its receipt; W cannot take the batch.
  {
    const { f, a, x, wake, batch, complete } = await heldBatchFixture();
    await assert.rejects(f.bridge.claim(friday, { messageId: x.id }), /sync_item_in_batch/);
    const itemClaim = await legacyItemClaim(f, x.id, start + 60000);
    const claimW = await f.bridge.claim(friday, { messageId: wake.id });
    assert.deepEqual(claimW.syncBatchesHeldElsewhere, [batch]);
    await assert.rejects(complete(wake.id, claimW.claimId, [batch]), /sync_batch_not_held/);
    assert.deepEqual(f.snapshot().receipts[x.id], itemClaim);
    assert.equal(f.snapshot().receipts[a.id], undefined);
  }
  // A completion that does not name a held batch releases it for a direct claim at once.
  {
    const { f, wake, batch, complete } = await heldBatchFixture();
    const claimW = await f.bridge.claim(friday, { messageId: wake.id });
    await complete(wake.id, claimW.claimId);
    assert.equal(f.snapshot().receipts[batch], undefined);
    assert.ok((await f.bridge.claim(friday, { messageId: batch })).claimId);
  }
  // An expired W claim stops holding B; W then cannot complete or acknowledge anything.
  {
    const { f, wake, batch, complete } = await heldBatchFixture();
    const claimW = await f.bridge.claim(friday, { messageId: wake.id });
    f.advance(60000);
    const claimB = await f.bridge.claim(friday, { messageId: batch });
    await assert.rejects(complete(wake.id, claimW.claimId, [batch]), /stale_receipt_claim/);
    assert.equal(f.snapshot().receipts[batch]!.claimId, claimB.claimId);
  }
});

test('bridge_read drains pending SYNC into a batch attached to an open message only', async () => {
  const f = await fixture();
  const wake = f.message(); await f.send(wake);
  const a = f.sync(); await f.send(a);
  const read = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(read.syncBatches!.map(b => [b.reason, b.items.map(i => i.messageId)]), [['read', [a.id]]]);
  assert.deepEqual(await f.bridge.read(friday, { messageId: wake.id }), read);
  await f.handle(friday, wake.id, read.syncBatches!.map(b => b.messageId));
  const b = f.sync(); await f.send(b);
  const later = await f.bridge.read(friday, { messageId: wake.id });
  assert.deepEqual(ids(later.syncBatches!), [[a.id]], 'a completed message collects nothing new');
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[b.id]]);
  await assert.rejects(f.bridge.inboxRead(jarvis), /wake_sync_not_enabled/);
});

test('bridge_read cannot strand pending SYNC on a carrier whose authorization has expired', async () => {
  const f = await fixture();
  const wake = f.message(); await f.send(wake);
  const pending = f.sync(); await f.send(pending);
  f.set(noon + 5000); // The WAKE authorization has expired; the SYNC item remains live and due.

  const read = await f.bridge.read(friday, { messageId: wake.id });
  assert.equal(read.expired, true);
  assert.equal('syncBatches' in read, false, 'an inactive carrier cannot collect pending data');
  assert.equal(batchesIn(f.snapshot()).length, 0, 'read does not create a presented-but-unclaimable batch');
  await assert.rejects(f.bridge.claim(friday, { messageId: wake.id }), /message_authorization_inactive/);

  const flushed = await f.bridge.flushSync();
  assert.deepEqual(flushed.results, [{ recipient: 'friday', outcome: 'flushed', reason: 'scheduled', items: 1 }]);
  assert.equal(flushed.dispatch.length, 1);
  const batch = f.snapshot().messages[flushed.dispatch[0]!];
  assert.deepEqual(batch!.syncBatch!.itemIds, [pending.id], 'the still-pending item remains available to scheduled recovery');
});

test('bridge_read cannot present and strand an attached batch on an expired carrier', async () => {
  const f = await fixture();
  const pending = f.sync(); await f.send(pending);
  const wake = f.message(); await f.send(wake);
  const batchId = f.snapshot().messages[wake.id]!.syncBatchIds![0];
  assert.ok(batchId);
  assert.equal(f.snapshot().messages[batchId]!.syncBatch!.presentedAt, undefined);
  f.set(noon + 5000);

  const read = await f.bridge.read(friday, { messageId: wake.id });
  assert.equal(read.expired, true);
  assert.equal('syncBatches' in read, false, 'an inactive carrier cannot present its attached batch');
  assert.equal(f.snapshot().messages[batchId]!.syncBatch!.presentedAt, undefined);
  await assert.rejects(f.bridge.claim(friday, { messageId: wake.id }), /message_authorization_inactive/);

  const flushed = await f.bridge.flushSync();
  assert.deepEqual(flushed.dispatch, [batchId], 'the unpresented batch is recovered by the scheduled flush');
  assert.deepEqual(flushed.results,
    [{ recipient: 'friday', outcome: 'flushed', reason: 'scheduled', items: 0, rehomedBatches: 1 }]);
});

test('bridge_read cannot present an attached batch while its carrier policy is withdrawn', async () => {
  const f = await fixture();
  const pending = f.sync(); await f.send(pending);
  const wake = f.message(); await f.send(wake);
  const batchId = f.snapshot().messages[wake.id]!.syncBatchIds![0];
  (f.bridge.messagePolicyIds as Record<string, string>).jarvis = 'd'.repeat(64);

  const read = await f.bridge.read(friday, { messageId: wake.id });
  assert.equal('syncBatches' in read, false);
  assert.equal(f.snapshot().messages[batchId!]!.syncBatch!.presentedAt, undefined);
  await assert.rejects(f.bridge.claim(friday, { messageId: wake.id }), /message_authorization_inactive/);

  (f.bridge.messagePolicyIds as Record<string, string>).jarvis = policy;
  f.set(noon + 5000);
  assert.deepEqual((await f.bridge.flushSync()).dispatch, [batchId],
    'restoring the policy leaves the unpresented batch recoverable');
});

test('ACKs are not suppressed: an enabled recipient\'s direct messages get an immediate correlated ACK at completion', async () => {
  const f = await fixture({ recipients: ['friday'] });
  const fromFriday = f.message('friday'); await f.send(fromFriday);
  const before = f.snapshot();
  assert.equal(Object.values(before.messages).some(m => m.envelope.kind === 'ack'), false, 'no ACK at send or enqueue time');
  const done = await f.handle(jarvis, fromFriday.id);
  assert.equal('ackSuppressed' in done, false);
  const ack = f.snapshot().messages[done.ackMessageId!];
  assert.deepEqual([ack!.envelope.kind, ack!.envelope.to, ack!.envelope.correlationId], ['ack', 'friday', fromFriday.id]);
  assert.deepEqual(done.jobIds, ack!.jobIds); assert.equal(ack!.jobIds.length, 1, 'delivered at once, never batched');
  assert.equal(f.snapshot().syncQueues?.friday, undefined, 'an ACK is never queued as SYNC');
  const status = await f.bridge.status(friday, { messageId: fromFriday.id });
  assert.equal(status.receiptCompleted, true); assert.equal(status.ackMessageId, done.ackMessageId);
  // Completing the ACK itself (it is terminal) creates nothing.
  const terminal = await f.handle(friday, done.ackMessageId!);
  assert.equal(terminal.ackMessageId, null); assert.deepEqual(terminal.jobIds, []);
  const fromJarvis = f.message('jarvis'); await f.send(fromJarvis);
  assert.ok((await f.handle(friday, fromJarvis.id)).ackMessageId);
});

test('both recipients enabled: the v1 return-path rule applies again to direct messages in both directions', async () => {
  const f = await fixture({ recipients: ['friday', 'jarvis'] });
  const ok = f.message('jarvis'); await f.send(ok);
  await f.store.transaction(s => { for (const sub of Object.values(s.subscriptions)) sub.expiresAt = start - 1; });
  await assert.rejects(f.send(f.message('jarvis')), /return_subscription_required/, 'an ACK will be sent, so its path is required');
  await assert.rejects(f.bridge.claim(friday, { messageId: ok.id }), /return_subscription_required/);
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
  assert.deepEqual(JSON.parse(jobsFor(s, native.id)[0]!.body), { event: EVENT_NAME, data: { messageId: native.id } });
  assert.ok(out.dispatch.includes(native.id));
  const batch = batchesIn(s)[0];
  assert.deepEqual(batch!.syncBatch!.itemIds, [expiredAuthority.id]);
  assert.match(batch!.envelope.text!, new RegExp(expiredAuthority.id), 'unchanged receivers see the native ID in the text');
  // An unchanged receiver reads, claims and completes it as an ordinary status
  // message, without syncBatchIds; a direct completion still acknowledges itself.
  await f.bridge.read(friday, { messageId: batch!.envelope.id });
  assert.deepEqual((await f.handle(friday, batch!.envelope.id)).syncBatchesAcked, [batch!.envelope.id]);
  assert.equal(f.snapshot().receipts[expiredAuthority.id]!.state, 'complete');
  // And handles the natively re-sent item exactly like any v1 message (ACK included).
  assert.ok((await f.handle(friday, native.id)).ackMessageId);
});

// --- Round 4: item vs batch fence, newest-first reclaim, native rollback recovery ---
const rejectsWith = async (promise: Promise<unknown>, code: string, details?: object) => {
  const error = await promise.then(() => null, (e: BridgeError) => e);
  assert.ok(error, `expected ${code}`); assert.equal(error.code, code);
  if (details) assert.deepEqual(error.details, details);
};
// Simulates a live item claim written by the pre-fix code (independent item claims are now refused).
function legacyItemClaim(f: Fx, id: string, leaseUntil: number) {
  return f.store.transaction(s => {
    s.receipts[id] = { state: 'claimed', owner: friday.principalKey, claimId: randomUUID(), leaseUntil };
    return s.receipts[id];
  });
}

test('item fence: a batch-owned or pending SYNC item cannot be claimed on its own; the error names its batch', async () => {
  const f = await fixture();
  const x = f.sync(); await f.send(x);
  await rejectsWith(f.bridge.claim(friday, { messageId: x.id }), 'sync_item_not_delivered');
  const batch = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  // Unclaimed batch, batch claimed directly, and both raced together: the item never gets its own claim.
  await rejectsWith(f.bridge.claim(friday, { messageId: x.id }), 'sync_item_in_batch', { batchMessageId: batch });
  const settled = await Promise.allSettled([f.bridge.claim(friday, { messageId: x.id }), f.bridge.claim(friday, { messageId: batch })]);
  assert.equal(settled[0].status, 'rejected'); assert.equal(settled[0].reason.code, 'sync_item_in_batch');
  assert.equal(settled[1].status, 'fulfilled');
  assert.equal(f.snapshot().receipts[x.id], undefined, 'no receipt was written for the item');
  // Reading the item by ID is still allowed (data only).
  assert.equal((await f.bridge.read(friday, { messageId: x.id })).envelope.id, x.id);
  // Held through a parent WAKE: same refusal.
  const g = await fixture();
  const y = g.sync(); await g.send(y);
  const wake = g.message(); await g.send(wake);
  await g.bridge.read(friday, { messageId: wake.id });
  const claimW = await g.bridge.claim(friday, { messageId: wake.id });
  await rejectsWith(g.bridge.claim(friday, { messageId: y.id }), 'sync_item_in_batch', { batchMessageId: claimW.syncBatchIds![0] });
});

test('item fence: a live pre-existing item claim blocks batch claim and completion instead of a silent partial ack', async () => {
  const f = await fixture();
  const x = f.sync('jarvis', { subject: 'X' }), z = f.sync('jarvis', { subject: 'Z' });
  await f.send(x); await f.send(z);
  const batch = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  const claimB = await f.bridge.claim(friday, { messageId: batch });
  const itemClaim = await legacyItemClaim(f, x.id, start + 60000);
  const before = f.snapshot();
  await rejectsWith(f.bridge.complete(friday, { messageId: batch, claimId: claimB.claimId, hostedEventId: null, hostedTurnId: null,
    syncBatchIds: [batch] }), 'sync_batch_item_busy', { itemIds: [x.id] });
  assert.deepEqual(f.snapshot().receipts, before.receipts, 'nothing completed, nothing overwritten');
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.ackedAt, undefined, 'batch not finalized');
  // A new direct claim of the batch is refused too, and a parent WAKE claim does not hold it.
  f.advance(60000); // the batch claim lapses; the item claim was written with the same lease end
  await legacyItemClaim(f, x.id, f.clock() + 60000);
  await rejectsWith(f.bridge.claim(friday, { messageId: batch }), 'sync_batch_item_busy', { itemIds: [x.id] });
  // The batch stays outstanding and replays while the item claim lives (the item claimant may crash).
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches.map(b => b!.messageId), [batch]);
  // After the item claim's 60 s lease lapses the batch is claimable and covers every item.
  f.advance(60000);
  const done = await f.handle(friday, batch, [batch]);
  assert.deepEqual(done.syncBatchesAcked, [batch]);
  for (const id of [x.id, z.id]) assert.equal(f.snapshot().receipts[id]!.viaBatch, batch);
  assert.notEqual(f.snapshot().receipts[x.id]!.claimId, itemClaim.claimId);
  // An item completed by its own legacy claim counts as covered.
  const g = await fixture();
  const y = g.sync('jarvis', { expiresAt: iso(start + 3 * HOUR) }), z2 = g.sync('jarvis', { subject: 'still live' });
  await g.send(y); await g.send(z2);
  const gb = (await g.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  await g.store.transaction(s => {
    s.receipts[y.id] = { state: 'complete', owner: friday.principalKey, claimId: randomUUID(), completedAt: start };
    s.messages[y.id]!.envelope.attachmentIds = [randomUUID()]; // Synthetic legacy metadata only.
  });
  const prior = g.snapshot().receipts[y.id];
  for (const at of [start, start + 3 * HOUR]) {
    g.set(at);
    const items = (await g.bridge.read(friday, { messageId: gb })).syncBatches![0]!.items;
    assert.deepEqual(items.map(i => [i.messageId, i.disposition, i.text]), [[y.id, 'handled', ''], [z2.id, 'pending', z2.text]]);
    assert.equal('attachmentIds' in items[0]!, false, 'already handled bytes are never offered for re-execution');
  }
  const covered = await g.handle(friday, gb, [gb]);
  assert.deepEqual(covered.syncBatchesAcked, [gb]);
  assert.deepEqual(covered.syncBatchOutcomes![0]!.items, [{ messageId: y.id, disposition: 'handled' }, { messageId: z2.id, disposition: 'handled' }]);
  assert.deepEqual(g.snapshot().receipts[y.id], prior);
  assert.equal(g.snapshot().receipts[y.id]!.viaBatch, undefined, 'the item\'s own receipt is kept');
});

test('item fence: a parent WAKE claim excludes a batch whose item has a live independent claim', async () => {
  const f = await fixture();
  const x = f.sync(); await f.send(x);
  const wake = f.message(); await f.send(wake);
  const batch = (await f.bridge.read(friday, { messageId: wake.id })).syncBatches![0]!.messageId;
  await legacyItemClaim(f, x.id, start + 60000);
  const claimW = await f.bridge.claim(friday, { messageId: wake.id });
  assert.deepEqual([claimW.syncBatchIds, claimW.syncBatchesHeldElsewhere], [[], [batch]]);
  await rejectsWith(f.bridge.complete(friday, { messageId: wake.id, claimId: claimW.claimId, hostedEventId: null, hostedTurnId: null,
    syncBatchIds: [batch] }), 'sync_batch_not_held');
});

test('item fence: reclaimed batches redirect item claims to the replacement batch', async () => {
  const f = await fixture();
  const x = f.sync(); await f.send(x);
  const first = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  f.advance(SYNC_BATCH_TTL_MS);
  const second = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  assert.notEqual(second, first);
  await rejectsWith(f.bridge.claim(friday, { messageId: x.id }), 'sync_item_in_batch', { batchMessageId: second });
  await rejectsWith(f.bridge.claim(friday, { messageId: first }), 'message_authorization_inactive');
  assert.equal(f.snapshot().messages[x.id]!.sync!.livePresentedAt, start, 'presentation evidence survives reclaim');
  // Even after the old batch is pruned, do not infer that its previously live
  // item was never handled. The current batch still needs a disposition.
  await f.store.transaction(s => { delete s.messages[first]; });
  assert.equal((await f.bridge.read(friday, { messageId: second })).syncBatches![0]!.items[0]!.disposition, 'requires_disposition');
  const claim = await f.bridge.claim(friday, { messageId: second });
  const params = { messageId: second, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null, syncBatchIds: [second] };
  await assert.rejects(f.bridge.complete(friday, params), /sync_batch_disposition_required/);
  assert.deepEqual((await f.bridge.complete(friday, { ...params, syncItemDispositions: [
    { batchMessageId: second, messageId: x.id, disposition: 'skipped_expired' }] })).syncBatchesAcked, [second]);
  assert.equal(f.snapshot().receipts[x.id], undefined, 'reclaim does not revive an expired original receipt');
  assert.deepEqual(f.snapshot().messages[second]!.syncBatch!.outcome!.items, [{ messageId: x.id, disposition: 'skipped_expired' }]);
});

test('reclaim keeps the newest same-subject update when successive batches both expire', async () => {
  const f = await fixture();
  const v1 = f.sync('jarvis', { subject: 'Deploy', text: 'v1' }); await f.send(v1);
  const b1 = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  f.advance(HOUR);
  const v2 = f.sync('jarvis', { subject: 'Deploy', text: 'v2' }); await f.send(v2);
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[v1.id], [v2.id]]);
  f.advance(13 * HOUR);
  const replay = await f.bridge.inboxRead(friday);
  assert.deepEqual(ids(replay.syncBatches), [[v2.id]], 'v2 replays, v1 does not');
  assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync!.supersededBy, v2.id);
  assert.notEqual(replay.syncBatches[0]!.messageId, b1);
  // A newer update already acknowledged also keeps the older one from replaying.
  const g = await fixture();
  const o1 = g.sync('jarvis', { subject: 'Owner' }); await g.send(o1);
  await g.bridge.inboxRead(friday);
  g.advance(HOUR);
  const o2 = g.sync('jarvis', { subject: 'Owner' }); await g.send(o2);
  const both = (await g.bridge.inboxRead(friday)).syncBatches;
  await g.handle(friday, both[1]!.messageId, [both[1]!.messageId]);
  g.advance(13 * HOUR);
  assert.deepEqual((await g.bridge.inboxRead(friday)).syncBatches, []);
  assert.equal((await g.bridge.status(jarvis, { messageId: o1.id })).sync!.supersededBy, o2.id);
});

// Same-millisecond admissions: storedAt ties, so order must come from the
// durable admission sequence (or, for data admitted before it existed, never
// replay an older-or-equal update over one that is handled or still live).
const unstamp = (f: Fx) => f.store.transaction(s => { for (const m of Object.values(s.messages)) delete m.syncSeq; delete s.syncAdmissionSeq; });
// Postgres JSONB does not keep object key order. Rewrite every keyed map the
// SYNC logic iterates in the given key order (sorted or reverse-sorted), as a
// round trip through JSONB may, so results cannot depend on insertion order.
const reorder = (f: Fx, reverse: boolean) => f.store.transaction(s => {
  const rekey = <T>(obj: Record<string, T>): Record<string, T> => Object.fromEntries(Object.entries(obj).sort(([a], [b]) => (a < b ? -1 : 1) * (reverse ? -1 : 1)));
  s.messages = rekey(s.messages); s.receipts = rekey(s.receipts); s.jobs = rekey(s.jobs);
  for (const q of Object.values(s.syncQueues || {})) q.pending = rekey(q.pending);
});
test('same-millisecond updates: a newer acknowledged batch keeps the older one from replaying', async () => {
  for (const [legacy, reverse] of [[false, false], [false, true], [true, false], [true, true]] as [boolean, boolean][]) {
    const f = await fixture();
    const v1 = f.sync('jarvis', { subject: 'same-ms', text: 'v1' }); await f.send(v1);
    await f.bridge.inboxRead(friday);
    const v2 = f.sync('jarvis', { subject: 'same-ms', text: 'v2' }); await f.send(v2); // no clock advance
    const both = (await f.bridge.inboxRead(friday)).syncBatches;
    // Two batches cut in the same millisecond: display order is by ID only.
    assert.deepEqual(ids(both).sort(), [[v1.id], [v2.id]].sort());
    assert.equal(f.snapshot().messages[v1.id]!.storedAt, f.snapshot().messages[v2.id]!.storedAt);
    if (legacy) await unstamp(f); // snapshot written before admission order was recorded
    const b2 = both.find(b => b!.items[0]!.messageId === v2.id)!.messageId;
    assert.deepEqual((await f.receive(b2)).syncBatchesAcked, [b2]);
    await reorder(f, reverse);
    f.advance(13 * HOUR);
    const replay = (await f.bridge.inboxRead(friday)).syncBatches;
    if (!legacy) {
      assert.deepEqual(replay, [], `sequenced, ${reverse ? 'reversed' : 'sorted'} keys`);
      assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync!.supersededBy, v2.id);
    } else {
      // No recorded order: v1 may be the newest, so it is kept (flagged), not discarded.
      assert.deepEqual(replay.map(b => b!.items.map(i => [i.messageId, i.orderUnknown])), [[[v1.id, true]]]);
    }
  }
});

test('same-millisecond updates: a newer update in a still-live batch supersedes the reclaimed older one', async () => {
  for (const [legacy, reverse] of [[false, false], [false, true], [true, false]] as [boolean, boolean][]) {
    const f = await fixture();
    const v1 = f.sync('jarvis', { subject: 'same-ms' }); await f.send(v1);
    await f.bridge.inboxRead(friday);                    // B1 at t0 carries v1
    const v2 = f.sync('jarvis', { subject: 'same-ms' }); await f.send(v2); // same millisecond, stays pending
    if (legacy) await unstamp(f);
    f.advance(HOUR);
    const b2 = (await f.bridge.inboxRead(friday)).syncBatches.find(b => b!.items.some(i => i.messageId === v2.id))!.messageId;
    await reorder(f, reverse);
    f.advance(SYNC_BATCH_TTL_MS - HOUR);                 // B1 expired, B2 still live
    const replay = (await f.bridge.inboxRead(friday)).syncBatches;
    if (!legacy) {
      assert.deepEqual(replay.map(b => b!.messageId), [b2], `sequenced, ${reverse ? 'reversed' : 'sorted'} keys`);
      assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync!.supersededBy, v2.id);
    } else {
      // Unknown order: both survive; v1 is re-sent flagged, v2 stays in its live batch.
      assert.equal(replay.length, 2); assert.equal(replay[0]!.messageId, b2);
      assert.deepEqual(replay[1]!.items.map(i => [i.messageId, i.orderUnknown]), [[v1.id, true]]);
    }
  }
});

test('same-millisecond updates: a WAKE with the same subject is the newer update', async () => {
  const f = await fixture();
  const v1 = f.sync('jarvis', { subject: 'same-ms' }); await f.send(v1);
  await f.bridge.inboxRead(friday);
  const wake = f.message('jarvis', { subject: 'same-ms', text: 'decided' }); await f.send(wake);
  await f.handle(friday, wake.id);
  f.advance(13 * HOUR);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, []);
  assert.equal((await f.bridge.status(jarvis, { messageId: v1.id })).sync!.supersededBy, wake.id);
  // A sequenced WAKE admitted before a same-millisecond SYNC update does not hide it.
  const g = await fixture();
  const first = g.message('jarvis', { subject: 'same-ms' }); await g.send(first);
  const later = g.sync('jarvis', { subject: 'same-ms' }); await g.send(later);
  await g.bridge.inboxRead(friday);
  g.advance(13 * HOUR);
  assert.deepEqual(ids((await g.bridge.inboxRead(friday)).syncBatches), [[later.id]]);
});

test('same-millisecond updates: native recovery keeps only the newest of tied re-sends', async () => {
  for (const legacy of [false, true]) {
    const f = await fixture();
    const v1 = f.sync('jarvis', { subject: 'same-ms', text: 'v1' }), v2 = f.sync('jarvis', { subject: 'same-ms', text: 'v2' });
    await f.send(v1, who('jarvis', start + 60000));
    // v1 is still pending when v2 arrives, so v2 supersedes it at admission; recover v2 only.
    await f.send(v2, who('jarvis', start + 60000));
    if (legacy) await unstamp(f);
    f.enabled.recipients = [];
    assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'native', items: 1 }]);
    f.advance(2 * 60000);
    const out = await f.bridge.flushSync();
    const batch = batchesIn(f.snapshot()).find(b => out.dispatch.includes(b.envelope.id));
    assert.deepEqual(batch!.syncBatch!.itemIds, [v2.id]);
    assert.equal(f.snapshot().messages[v1.id]!.sync!.state, 'superseded');
  }
});

test('same-millisecond legacy ties with no recorded order keep both updates, whatever the key order', async () => {
  for (const reverse of [false, true]) {
    const f = await fixture();
    const v1 = f.sync('jarvis', { subject: 'same-ms' }); await f.send(v1);
    await f.bridge.inboxRead(friday);
    const v2 = f.sync('jarvis', { subject: 'same-ms' }); await f.send(v2);
    await f.bridge.inboxRead(friday);
    await unstamp(f); await reorder(f, reverse);
    f.advance(13 * HOUR);
    const replay = (await f.bridge.inboxRead(friday)).syncBatches;
    assert.equal(replay.length, 1, 'one new batch');
    const got = replay[0]!.items.map(i => [i.messageId, i.orderUnknown]).sort();
    assert.deepEqual(got, [[v1.id, true], [v2.id, true]].sort(), `neither is discarded (${reverse ? 'reversed' : 'sorted'} keys)`);
    for (const id of [v1.id, v2.id]) assert.equal(f.snapshot().messages[id]!.sync!.state, 'delivered');
  }
});

test('sequenced same-millisecond updates resolve identically under any key order, both batches expired', async () => {
  for (const reverse of [false, true]) {
    const f = await fixture();
    const v1 = f.sync('jarvis', { subject: 'same-ms' }); await f.send(v1);
    await f.bridge.inboxRead(friday);
    const v2 = f.sync('jarvis', { subject: 'same-ms' }); await f.send(v2);
    await f.bridge.inboxRead(friday);
    await reorder(f, reverse);
    f.advance(13 * HOUR);
    const replay = (await f.bridge.inboxRead(friday)).syncBatches;
    assert.deepEqual(replay.map(b => b!.items.map(i => [i.messageId, i.orderUnknown])), [[[v2.id, false]]]);
    assert.equal(f.snapshot().messages[v1.id]!.sync!.supersededBy, v2.id);
  }
});

test('rollback native delivery is recovered into a batch when its v1 authority lapses before completion', async () => {
  const f = await fixture();
  const x = f.sync(); await f.send(x, who('jarvis', start + 60000));
  f.enabled.recipients = [];
  assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'native', items: 1 }]);
  await f.bridge.claim(friday, { messageId: x.id }).then(c => assert.ok(c.claimId), () => assert.fail('native item is claimable directly'));
  f.advance(2 * 60000); // sender token expired: the native job can no longer deliver, nor the item be claimed natively
  // The claim attempt itself recovers the item into the queue and says so.
  await rejectsWith(f.bridge.claim(friday, { messageId: x.id }), 'sync_item_not_delivered');
  const out = await f.bridge.flushSync();
  assert.deepEqual(out.results, [{ recipient: 'friday', outcome: 'flushed', reason: 'rollback', items: 1 }]);
  const batch = batchesIn(f.snapshot()).find(b => b.syncBatch!.itemIds.includes(x.id));
  assert.ok(batch && out.dispatch.includes(batch.envelope.id), 'a derived batch carries X');
  await rejectsWith(f.bridge.claim(friday, { messageId: x.id }), 'sync_item_in_batch', { batchMessageId: batch.envelope.id });
  assert.deepEqual((await f.receive(batch.envelope.id)).syncBatchesAcked, [batch.envelope.id]);
  assert.equal(f.snapshot().receipts[x.id]!.viaBatch, batch.envelope.id);
  // Dead native jobs with still-valid authority also fall back to a batch (not native again).
  const g = await fixture();
  const y = g.sync(); await g.send(y);
  g.enabled.recipients = [];
  await g.bridge.flushSync();
  await g.store.transaction(s => { for (const id of s.messages[y.id]!.jobIds) s.jobs[id]!.state = 'dead'; });
  g.advance(HOUR);
  assert.deepEqual((await g.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'flushed', reason: 'rollback', items: 1 }]);
  // An uncompleted native item is held past content retention until it is recovered.
  const h = await fixture();
  const w = h.sync(); await h.send(w, who('jarvis', start + 60000));
  h.enabled.recipients = [];
  await h.bridge.flushSync();
  h.advance(CONTENT_RETENTION_MS + HOUR);
  await h.bridge.inboxRead(friday).catch(() => null); // any storage transition runs retention
  await h.bridge.status(friday, { messageId: w.id }).catch(() => null);
  assert.ok(h.snapshot().messages[w.id], 'held');
  assert.equal((await h.bridge.flushSync()).results[0]!.reason, 'rollback');
});

test('repository wiring: no Vercel cron and no GitHub Actions communication workflow; the route is outside the MCP catch-all', () => {
  const config = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url)) as unknown as string); // Buffer text
  assert.equal(config.crons, undefined, 'no Vercel cron (the scheduler is external: QStash or any bearer caller)');
  // Repository CI stays; nothing under .github drives agent communication.
  const workflows = readdirSync(new URL('../.github/workflows/', import.meta.url)).sort();
  assert.deepEqual(workflows, ['ci.yml', 'codeql.yml']);
  for (const name of workflows) {
    const text = readFileSync(new URL(`../.github/workflows/${name}`, import.meta.url), 'utf8');
    for (const word of ['/api/cron', 'CRON_SECRET', 'QSTASH', 'BRIDGE_CRON_URL', 'flush']) assert.equal(text.includes(word), false, `${name}: ${word}`);
  }
  const catchAll = new RegExp('^' + config.rewrites[0].source + '$');
  assert.equal(catchAll.test('/api/cron'), false); assert.equal(catchAll.test('/api/queue'), false);
  assert.equal(catchAll.test('/bridge/friday/mcp'), true);
  assert.ok(config.functions['api/cron.ts']);
});

async function runtimeFixture(changes: Record<string, string | undefined> = {}, at = start) {
  let document: BridgeState = emptyState(), now = at, consumer!: Consumer;
  const sends: SendArgs[] = [], posts: JsonObject[] = [];
  // Fault injection: faults.send(args) / faults.update() returning true makes
  // that queue publish or that storage write fail (the write is not applied).
  // faults.commit() returning true throws from COMMIT after the write was
  // applied: the server committed but the client lost the response.
  const faults: { send: ((args: SendArgs) => unknown) | null; update: (() => unknown) | null; commit: (() => unknown) | null } =
    { send: null, update: null, commit: null };
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  class Pool { on() {} async connect() { return { release() {}, async query(sql: string, params: string[]) {
    if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(document) }] };
    if (sql.startsWith('UPDATE bridge_runtime_v1')) {
      if (faults.update?.()) throw Error('FIXTURE_STORAGE_FAULT');
      document = JSON.parse(params[0]!);
    }
    if (sql === 'COMMIT' && faults.commit?.()) throw Error('FIXTURE_COMMIT_RESPONSE_LOST');
    return { rows: [] };
  } }; } }
  const env = { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture', BRIDGE_DELIVERY_ENABLED: 'true',
    BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
    DATABASE_URL: 'postgresql://fixture.neon.tech/neondb?sslmode=require',
    BRIDGE_RECEIVER_POLICY: 'inbox-v1', FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true',
    FRIDAY_RECEIVER_ID: 'jarvis-friday-bridge-inbox', FRIDAY_WEBHOOK_URL: 'https://receiver.example.test/event', FRIDAY_WEBHOOK_KEY: 'FIXTURE_ONLY',
    BRIDGE_WAKE_SYNC_RECIPIENTS: 'friday', CRON_SECRET: 'fixture-cron-secret-value', ...changes } as Record<string, string | undefined>;
  const rt = createRuntime({ env, Pool: Pool as unknown as RuntimePoolConstructor, keyResolver: publicKey, clock: () => now,
    queueClient: { async send(...args: SendArgs) { if (faults.send?.(args)) throw Error('FIXTURE_QUEUE_FAULT'); sends.push(args); },
      handleCallback(fn: Consumer) { consumer = fn; return fn; } } as unknown as RuntimeQueueClient, // Captures the consumer.
    transportFactory: () => async (_url: string, req: TransportRequest): Promise<TransportResponse> => { const body = JSON.parse(req.body); posts.push(body);
      return { status: 200, body: JSON.stringify({ challenge: body.challenge }) }; } });
  const tokens: Record<string, string> = {};
  for (const role of ['jarvis', 'friday']) tokens[role] = await new SignJWT({ scope: Object.values(SCOPES[role]!).join(' ') })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject('fixture').setAudience(resourceFor(role)).setIssuedAt().setExpirationTime('30d').sign(privateKey);
  const rpc = async (role: string, method: string, params?: object): Promise<{ status: number; body: RtBody }> => {
    const response = await rt.handler(role)(new Request(resourceFor(role), { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tokens[role] },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })); return { status: response.status, body: await response.json() as RtBody };
  };
  const call = async (role: string, name: string, args?: object) => (await rpc(role, 'tools/call', { name, arguments: args })).body.result;
  const cron = (headers: Record<string, string> = {}, method = 'POST') => rt.cronHandler()(new Request('https://deployment.example.test/api/cron', { method, headers }));
  await rpc('jarvis', 'events/subscribe', { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  return { rt, env, rpc, call, cron, sends, posts, faults, document: () => document, set: (ms: number) => { now = ms; },
    async consume(payload: unknown) { rt.queueHandler(); return consumer(payload, { topicName: TOPIC, region: 'iad1', deliveryCount: 1 }); },
    message: (extra: Record<string, unknown> = {}): Draft => ({ protocol: MESSAGE_PROTOCOL, id: randomUUID(), from: 'jarvis', to: 'friday', kind: 'status', sentAt: iso(now),
      expiresAt: iso(now + 6 * HOUR), threadId: randomUUID(), route: 'inbox', text: 'Fixture runtime status', class: 'sync', ...extra }) };
}

test('runtime: tool schemas, readiness and inbox tool follow the per-recipient flag', async () => {
  const f = await runtimeFixture();
  const tools = (role: string) => f.rpc(role, 'tools/list', {}).then(r => r.body.result.tools);
  const fridayTools = await tools('friday'), jarvisTools = await tools('jarvis');
  assert.ok(fridayTools.some(t => t.name === 'bridge_inbox_read'));
  assert.equal(jarvisTools.some(t => t.name === 'bridge_inbox_read'), false);
  const schema = jarvisTools.find(t => t.name === 'bridge_message_send')!.inputSchema;
  for (const field of ['class', 'subject', 'effectiveAt', 'dueAt']) {
    assert.ok(schema.properties[field], field); assert.equal(schema.required!.includes(field), false);
  }
  assert.deepEqual(schema.properties.class!.enum, ['wake', 'sync']);
  const complete = fridayTools.find(t => t.name === 'bridge_receipt_complete')!.inputSchema;
  assert.equal(complete.properties.syncBatchIds!.type, 'array'); assert.equal(complete.required!.includes('syncBatchIds'), false);
  assert.deepEqual(complete.required, ['messageId', 'claimId', 'hostedEventId', 'hostedTurnId']);
  const health = await f.call('friday', 'bridge_health', {});
  assert.deepEqual(health.structuredContent.readiness.wakeSync, { valid: true, recipients: ['friday'], flushScheduleConfigured: true });
  const off = await runtimeFixture({ BRIDGE_WAKE_SYNC_RECIPIENTS: undefined });
  assert.equal((await off.call('friday', 'bridge_health', {})).structuredContent.readiness.wakeSync, undefined);
  assert.equal((await off.rpc('friday', 'tools/list', {})).body.result.tools.some(t => t.name === 'bridge_inbox_read'), false);
});

test('runtime: malformed recipient rollout holds queued data while v1 direct delivery and ACKs continue', async () => {
  const f = await runtimeFixture();
  const queued = f.message({ subject: 'held' });
  assert.equal((await f.call('jarvis', 'bridge_message_send', queued)).structuredContent.delivery, 'batched');
  f.env.BRIDGE_WAKE_SYNC_RECIPIENTS = 'friday,bogus';
  const health = await f.call('friday', 'bridge_health', {});
  assert.deepEqual(health.structuredContent.readiness.wakeSync, { valid: false, recipients: [], flushScheduleConfigured: true });
  const before = structuredClone(f.document());
  f.set(noon + 5000);
  const failed = await f.cron(auth);
  assert.equal(failed.status, 503); assert.deepEqual(await failed.json(), { error: 'flush_unavailable' });
  assert.deepEqual(f.document(), before, 'invalid configuration cannot turn queued SYNC into rollback wakes');

  const direct = f.message({ expiresAt: iso(noon + HOUR) }); delete direct.class;
  const sent = (await f.call('jarvis', 'bridge_message_send', direct)).structuredContent;
  assert.equal('delivery' in sent, false); assert.equal(f.document().messages[direct.id]!.jobIds.length, 1);
  const claim = (await f.call('friday', 'bridge_receipt_claim', { messageId: direct.id })).structuredContent;
  const done = (await f.call('friday', 'bridge_receipt_complete', { messageId: direct.id, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null })).structuredContent;
  assert.ok(done.ackMessageId, 'ordinary terminal ACK remains enabled');
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

const idle = (boundary: string) => ({ status: 'ok', boundary, flushed: 0, capped: 0, redeliveredNative: 0, dispatched: 0, dispatchPending: 0 });
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
  const batchId = dispatch!.dispatchMessageId;
  await f.consume(dispatch);
  assert.deepEqual(f.posts.filter(p => p.event === EVENT_NAME), [{ event: EVENT_NAME, data: { messageId: batchId } }]);
  // Flagged receiver contract: read the woken message (full syncBatches), then claim and complete it.
  const read = (await f.call('friday', 'bridge_read', { messageId: batchId })).structuredContent;
  assert.deepEqual(read.syncBatches[0]!.items.map(i => i.subject), ['A', 'B']);
  assert.deepEqual((await f.call('friday', 'bridge_inbox_read', {})).structuredContent.syncBatches.map(x => x.messageId), [batchId],
    'unacknowledged batch replays');
  const claim = (await f.call('friday', 'bridge_receipt_claim', { messageId: batchId })).structuredContent;
  const done = (await f.call('friday', 'bridge_receipt_complete', { messageId: batchId, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null, syncBatchIds: read.syncBatches.map(x => x.messageId) })).structuredContent;
  assert.ok(done.ackMessageId, 'the batch gets one ACK'); assert.deepEqual(done.syncBatchesAcked, [batchId]);
  // Pre-armed before the commit: the receipt dispatch for the batch resolves to its ACK.
  assert.ok(f.sends.some(args => args[1].dispatchReceiptOf === batchId));
  const itemStatus = (await f.call('jarvis', 'bridge_status', { messageId: a.id })).structuredContent;
  assert.equal(itemStatus.receiptCompleted, true); assert.equal(itemStatus.batchAckMessageId, done.ackMessageId);
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
] as [string, number, [number, number][]][]) {
  test(`runtime cron across DST (${name}): one flush within 2 elapsed hours`, async () => {
    const f = await runtimeFixture({}, queuedAt);
    assert.equal((await f.call('jarvis', 'bridge_message_send', f.message())).structuredContent.delivery, 'batched');
    for (const [at, expected] of runs) {
      f.set(at);
      const body = await (await f.cron(auth)).json() as CronReport;
      assert.equal(body.status, 'ok', iso(at)); assert.equal(body.flushed, expected, iso(at));
      if (expected) assert.ok(at - queuedAt! <= WAKE_WINDOW_MS);
    }
    assert.equal(f.sends.filter(args => args[1].dispatchMessageId).length, 2, 'the send prearm plus one batch');
  });
}

test('runtime: an item claim redirect reaches the receiver as tool-error fields naming the batch', async () => {
  const f = await runtimeFixture();
  const x = f.message({ subject: 'X' });
  await f.call('jarvis', 'bridge_message_send', x);
  const pending = await f.call('friday', 'bridge_receipt_claim', { messageId: x.id });
  assert.equal(pending.isError, true); assert.deepEqual(pending.structuredContent, { error: 'sync_item_not_delivered' });
  const batch = (await f.call('friday', 'bridge_inbox_read', {})).structuredContent.syncBatches[0]!.messageId;
  const redirect = await f.call('friday', 'bridge_receipt_claim', { messageId: x.id });
  assert.equal(redirect.isError, true);
  assert.deepEqual(redirect.structuredContent, { error: 'sync_item_in_batch', batchMessageId: batch });
  assert.deepEqual(JSON.parse(redirect.content[0]!.text), redirect.structuredContent);
  const claim = (await f.call('friday', 'bridge_receipt_claim', { messageId: batch })).structuredContent;
  const done = (await f.call('friday', 'bridge_receipt_complete', { messageId: batch, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null, syncBatchIds: [batch] })).structuredContent;
  assert.deepEqual(done.syncBatchesAcked, [batch]);
  assert.equal((await f.call('friday', 'bridge_receipt_claim', { messageId: x.id })).structuredContent.duplicate, true,
    'a handled item reports its completed receipt');
});

// --- Flush trigger: unpublished dispatch must be a retryable failure ---------
const dispatchIds = (f: { sends: SendArgs[] }) => f.sends.map(args => args[1].dispatchMessageId).filter(Boolean);
const batchIdsOf = (f: { document: () => BridgeState }) => Object.values(f.document().messages).filter(m => m.syncBatch).map(m => m.envelope.id);
test('runtime cron: a queue outage after the flush commits is HTTP 503 until the same batch is published', async () => {
  const f = await runtimeFixture();
  const x = f.message({ subject: 'X' });
  assert.equal((await f.call('jarvis', 'bridge_message_send', x)).structuredContent.delivery, 'batched');
  f.set(noon + 5000);
  f.faults.send = () => true; // queue down after admission
  const failed = await f.cron(auth);
  assert.equal(failed.status, 503, 'retryable: the workflow curl retries and the run fails if it persists');
  assert.deepEqual(await failed.json(), { status: 'dispatch_pending', boundary: iso(noon), flushed: 1, capped: 0,
    redeliveredNative: 0, dispatched: 0, dispatchPending: 1 });
  const [batch] = batchIdsOf(f);
  assert.deepEqual(f.document().syncQueues!.friday!.undispatched, [batch], 'committed batch kept for publication');
  assert.equal(f.document().syncQueues!.friday!.flushCount, 1);
  // Still down on the curl retry: same batch, no re-cut, no extra cap slot.
  assert.equal((await f.cron(auth)).status, 503);
  // Queue recovers: the retry publishes the same batch once.
  f.faults.send = null;
  const ok = await f.cron(auth);
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), { status: 'ok', boundary: iso(noon), flushed: 0, capped: 0, redeliveredNative: 0,
    dispatched: 1, dispatchPending: 0 });
  assert.deepEqual(batchIdsOf(f), [batch]); assert.equal(f.document().syncQueues!.friday!.flushCount, 1);
  assert.deepEqual(f.document().syncQueues!.friday!.undispatched, []);
  const payload = f.sends.map(args => args[1]).find(p => p.dispatchMessageId === batch);
  await f.consume(payload);
  assert.deepEqual(f.posts.filter(p => p.event === EVENT_NAME), [{ event: EVENT_NAME, data: { messageId: batch } }]);
  assert.equal((await f.cron(auth)).status, 200, 'nothing left to publish');
});

test('runtime cron: partial publication marks what was published and is still a retryable 503', async () => {
  const f = await runtimeFixture({ BRIDGE_WAKE_SYNC_RECIPIENTS: 'friday,jarvis' });
  await f.call('jarvis', 'bridge_message_send', f.message({ subject: 'to friday' }));
  await f.call('friday', 'bridge_message_send', f.message({ from: 'friday', to: 'jarvis', subject: 'to jarvis' }));
  f.set(noon + 5000);
  const toFriday = (args: SendArgs) => { const id = args[1].dispatchMessageId || args[1].cleanupMessageId; return f.document().messages[id as string]?.envelope.to === 'friday'; };
  f.faults.send = toFriday;
  const partial = await f.cron(auth);
  assert.equal(partial.status, 503);
  assert.deepEqual(await partial.json(), { status: 'dispatch_pending', boundary: iso(noon), flushed: 2, capped: 0,
    redeliveredNative: 0, dispatched: 1, dispatchPending: 1 });
  const queues = f.document().syncQueues;
  assert.equal(queues!.jarvis!.undispatched!.length, 0, 'the published batch is marked');
  assert.equal(queues!.friday!.undispatched!.length, 1, 'the unpublished batch is kept');
  f.faults.send = null;
  const ok = await f.cron(auth);
  assert.equal(ok.status, 200); assert.deepEqual(await ok.json(), { ...idle(iso(noon)), dispatched: 1 });
  assert.equal(batchIdsOf(f).length, 2, 'no re-cut');
  assert.deepEqual([queues!.friday!.flushCount, queues!.jarvis!.flushCount], [1, 1]);
  assert.deepEqual([f.document().syncQueues!.friday!.flushCount, f.document().syncQueues!.jarvis!.flushCount], [1, 1]);
  assert.equal(new Set(dispatchIds(f)).size, dispatchIds(f).length, 'each batch published once');
});

test('runtime cron: a failed dispatch bookkeeping write is a 503; the retry republishes harmlessly and wakes once', async () => {
  const f = await runtimeFixture();
  await f.call('jarvis', 'bridge_message_send', f.message({ subject: 'X' }));
  f.set(noon + 5000);
  let updates = 0;
  f.faults.update = () => ++updates === 2; // 1st commit = flush, 2nd = marking it published
  const unconfirmed = await f.cron(auth);
  assert.equal(unconfirmed.status, 503);
  assert.deepEqual(await unconfirmed.json(), { status: 'dispatch_unconfirmed', boundary: iso(noon), flushed: 1, capped: 0,
    redeliveredNative: 0, dispatched: 1, dispatchPending: 1 });
  const [batch] = batchIdsOf(f);
  assert.deepEqual(f.document().syncQueues!.friday!.undispatched, [batch], 'not lost: still offered for publication');
  f.faults.update = null;
  assert.equal((await f.cron(auth)).status, 200);
  assert.deepEqual(dispatchIds(f).filter(id => id === batch).length, 2, 'published again (idempotent dispatch)');
  for (const payload of f.sends.map(args => args[1]).filter(p => p.dispatchMessageId === batch)) await f.consume(payload);
  assert.equal(f.posts.filter(p => p.event === EVENT_NAME).length, 1, 'the receiver is woken once');
  assert.deepEqual(batchIdsOf(f), [batch]);
});

test('runtime cron: a failed flush commit is a 503 that loses and duplicates nothing', async () => {
  const f = await runtimeFixture();
  const x = f.message({ subject: 'X' });
  await f.call('jarvis', 'bridge_message_send', x);
  f.set(noon + 5000);
  const sendsBefore = f.sends.length;
  f.faults.update = () => true;
  const failed = await f.cron(auth);
  assert.equal(failed.status, 503); assert.deepEqual(await failed.json(), { error: 'flush_unavailable' });
  assert.deepEqual(batchIdsOf(f), []); assert.equal(f.document().messages[x.id]!.sync!.state, 'pending');
  assert.equal(f.sends.length, sendsBefore, 'nothing published for an uncommitted flush');
  f.faults.update = null;
  const ok = await f.cron(auth);
  assert.equal(ok.status, 200); assert.equal((await ok.json() as CronReport).flushed, 1);
  assert.equal(batchIdsOf(f).length, 1);
});

test('runtime cron: a flush COMMIT whose response is lost is a 503; the retry finds the committed batch and wakes once', async () => {
  const f = await runtimeFixture();
  const x = f.message({ subject: 'X' });
  await f.call('jarvis', 'bridge_message_send', x);
  f.set(noon + 5000);
  const sendsBefore = f.sends.length;
  let commits = 0;
  f.faults.commit = () => ++commits === 1; // the flush transaction commits, its response is lost
  const lost = await f.cron(auth);
  assert.equal(lost.status, 503); assert.deepEqual(await lost.json(), { error: 'flush_unavailable' });
  // Durably committed despite the error: one batch, counted once, waiting to be published.
  const [batch] = batchIdsOf(f);
  assert.ok(batch);
  assert.deepEqual(f.document().syncQueues!.friday!.undispatched, [batch]);
  assert.equal(f.document().syncQueues!.friday!.flushCount, 1);
  assert.equal(f.sends.length, sendsBefore, 'this call published nothing');
  f.faults.commit = null;
  const retry = await f.cron(auth);
  assert.equal(retry.status, 200);
  assert.deepEqual(await retry.json(), { ...idle(iso(noon)), dispatched: 1 }, 'same batch published; nothing re-cut');
  assert.deepEqual(batchIdsOf(f), [batch]); assert.equal(f.document().syncQueues!.friday!.flushCount, 1);
  for (const payload of f.sends.map(args => args[1]).filter(p => p.dispatchMessageId === batch)) await f.consume(payload);
  assert.deepEqual(f.posts.filter(p => p.event === EVENT_NAME), [{ event: EVENT_NAME, data: { messageId: batch } }]);
});

test('runtime cron: a lost COMMIT response while recording publication is a 503 with no duplicate wake', async () => {
  const f = await runtimeFixture();
  await f.call('jarvis', 'bridge_message_send', f.message({ subject: 'X' }));
  f.set(noon + 5000);
  let commits = 0;
  f.faults.commit = () => ++commits === 2; // 1st = flush, 2nd = recording publication (applied, response lost)
  const unconfirmed = await f.cron(auth);
  assert.equal(unconfirmed.status, 503);
  assert.equal((await unconfirmed.json() as CronReport).status, 'dispatch_unconfirmed');
  const [batch] = batchIdsOf(f);
  assert.deepEqual(f.document().syncQueues!.friday!.undispatched, [], 'the recording did commit');
  f.faults.commit = null;
  assert.deepEqual(await (await f.cron(auth)).json(), idle(iso(noon)), 'retry: nothing left, nothing re-cut');
  assert.deepEqual(batchIdsOf(f), [batch]); assert.equal(f.document().syncQueues!.friday!.flushCount, 1);
  for (const payload of f.sends.map(args => args[1]).filter(p => p.dispatchMessageId === batch)) await f.consume(payload);
  assert.equal(f.posts.filter(p => p.event === EVENT_NAME).length, 1);
});

// --- Unread piggyback batches whose carrier cannot deliver them -------------
test('carrier loss (repro): an unread piggyback batch whose WAKE cannot be delivered goes out at the next due flush', async () => {
  const f = await fixture();
  const x = f.sync('jarvis', { subject: 'carrier-loss' }); await f.send(x);
  const w = f.message(); await f.send(w, who('jarvis', start + 30000));
  const batch = f.snapshot().messages[w.id]!.syncBatchIds![0];
  assert.deepEqual(f.snapshot().messages[batch!]!.jobIds, []);
  f.advance(60000);
  await assert.rejects(f.bridge.claim(friday, { messageId: w.id }), /message_authorization_inactive/);
  f.set(noon + 5000);
  const out = await f.bridge.flushSync();
  assert.ok(out.dispatch.includes(batch!), 'the same batch is dispatched on its own');
  assert.deepEqual(out.results, [{ recipient: 'friday', outcome: 'flushed', reason: 'scheduled', items: 0, rehomedBatches: 1 }]);
  assert.equal(f.snapshot().messages[batch!]!.jobIds.length, 1);
  assert.deepEqual(JSON.parse(jobsFor(f.snapshot(), batch!)[0]!.body), { event: EVENT_NAME, data: { messageId: batch } });
  // The receiver handles it directly, like any batch.
  assert.deepEqual((await f.receive(batch!)).syncBatchesAcked, [batch]);
  assert.equal(f.snapshot().receipts[x.id]!.viaBatch, batch);
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 1);
});

// Carrier W (sent 11:30 CDT, valid until 12:30) whose webhook jobs all died,
// with an unread batch B on it. The next due flush is 12:00.
async function deadCarrier(extra = {}) {
  const f = await fixture(extra);
  f.set(start + HOUR);
  const x = f.sync('jarvis', { subject: 'X' }); await f.send(x);
  const w = f.message(); await f.send(w);
  const batch = f.snapshot().messages[w.id]!.syncBatchIds![0];
  await f.store.transaction(s => { for (const id of s.messages[w.id]!.jobIds) s.jobs[id]!.state = 'dead'; });
  return { f, x, w, batch };
}

test('carrier loss: with new data due, the flush batch carries the stranded batch (one wake, batch identity kept)', async () => {
  const { f, x, batch } = await deadCarrier();
  const y = f.sync('jarvis', { subject: 'Y' }); await f.send(y);
  f.set(noon + 5000);
  const out = await f.bridge.flushSync();
  assert.deepEqual(out.results, [{ recipient: 'friday', outcome: 'flushed', reason: 'scheduled', items: 1, rehomedBatches: 1 }]);
  assert.equal(out.dispatch.length, 1, 'one webhook');
  const carrier = out.dispatch[0];
  assert.notEqual(carrier, batch); assert.deepEqual(f.snapshot().messages[batch!]!.jobIds, [], 'B keeps no jobs of its own');
  const read = await f.bridge.read(friday, { messageId: carrier });
  assert.deepEqual(ids(read.syncBatches!), [[y.id], [x.id]]);
  const claim = await f.bridge.claim(friday, { messageId: carrier });
  assert.deepEqual(claim.syncBatchIds, [batch], 'the shared fence holds B for this claim');
  const done = await f.bridge.complete(friday, { messageId: carrier, claimId: claim.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: [carrier, batch] });
  assert.deepEqual(done.syncBatchesAcked!.sort(), [carrier, batch].sort());
  for (const id of [x.id, y.id]) assert.equal(f.snapshot().receipts[id]!.state, 'complete');
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 1);
});

test('carrier loss: the original carrier and the new one share the batch fence', async () => {
  const { f, w, batch } = await deadCarrier();
  f.set(noon + 5000);
  await f.bridge.flushSync();
  // W is still readable; reading it presents B, and W's claim takes B first.
  const readW = await f.bridge.read(friday, { messageId: w.id });
  assert.deepEqual(readW.syncBatches!.map(b => b.messageId), [batch]);
  const claimW = await f.bridge.claim(friday, { messageId: w.id });
  assert.deepEqual(claimW.syncBatchIds, [batch]);
  await assert.rejects(f.bridge.claim(friday, { messageId: batch }), /receipt_busy/);
  await f.bridge.complete(friday, { messageId: w.id, claimId: claimW.claimId, hostedEventId: null, hostedTurnId: null, syncBatchIds: [batch] });
  assert.equal((await f.bridge.claim(friday, { messageId: batch })).duplicate, true, 'acknowledged once');
});

test('carrier loss: an accepted unread carrier recovers the same batch before carrier expiry; original evidence is unchanged', async () => {
  const f = await fixture();
  f.set(start + 30 * MINUTE);
  await f.send(f.sync());
  f.set(start + HOUR);
  const w = f.message(); await f.send(w);
  const batch = f.snapshot().messages[w.id]!.syncBatchIds![0]!;
  await f.store.transaction(s => { for (const id of s.messages[w.id]!.jobIds) s.jobs[id]!.state = 'accepted'; });
  const original = f.snapshot().messages[w.id];
  f.set(noon + 5000); // The carrier remains live; missing receipt now triggers recovery.
  const first = await f.bridge.flushSync();
  assert.deepEqual(first.dispatch, [batch]);
  assert.equal(first.results[0]!.outcome, 'receipt_recovery');
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.recovery!.generation, 1);
  assert.deepEqual(f.snapshot().messages[w.id], original);
  f.set(noon + HOUR + 5000); // Pending recovery stays with its existing outbox job.
  const second = await f.bridge.flushSync();
  assert.deepEqual(second.dispatch, [batch]);
  assert.deepEqual(second.results, []);
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.recovery!.generation, 1);
});

test('carrier loss: a carrier read in time keeps its batch piggybacked (no extra wake)', async () => {
  const f = await fixture();
  const x = f.sync(); await f.send(x);
  const w = f.message(); await f.send(w, who('jarvis', start + 30000));
  await f.bridge.read(friday, { messageId: w.id }); // presented before the carrier lapsed
  f.set(noon + 5000);
  assert.deepEqual(await f.bridge.flushSync(), { boundary: noon, results: [], dispatch: [] });
  f.set(noon + 3 * HOUR + 5000);
  assert.deepEqual((await f.bridge.flushSync()).dispatch, []);
});

test('carrier loss: daily cap and missing destination keep the stranded batch waiting, then deliver it once', async () => {
  const { f, batch } = await deadCarrier();
  await f.store.transaction(s => { Object.assign(s.syncQueues!.friday!, { flushDay: '2026-10-19', flushCount: SYNC_DAILY_FLUSH_CAP }); });
  f.set(noon + 5000);
  assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient: 'friday', outcome: 'daily_cap' }]);
  assert.deepEqual(f.snapshot().messages[batch!]!.jobIds, []);
  // The cap lifts (as on the next Chicago day) before the batch's 12 h replay lifetime ends.
  await f.store.transaction(s => { s.syncQueues!.friday!.flushDay = '2026-10-18'; });
  f.set(noon + 2 * HOUR + 5000);
  const out = await f.bridge.flushSync();
  assert.deepEqual(out.dispatch, [batch]);
  await f.bridge.markSyncDispatched(out.dispatch);
  f.set(noon + 4 * HOUR + 5000);
  assert.deepEqual((await f.bridge.flushSync()).dispatch, [], 'not rehomed twice');
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 1);
  // Events-peer recipient without an active subscription: nothing changes until one exists.
  const g = await fixture({ recipients: ['jarvis'] });
  const y = g.sync('friday'); await g.send(y);
  const wy = g.message('friday'); await g.send(wy, who('friday', start + 30000));
  const gb = g.snapshot().messages[wy.id]!.syncBatchIds![0];
  await g.store.transaction(s => { for (const sub of Object.values(s.subscriptions)) sub.expiresAt = start + 1; });
  g.set(noon + 5000);
  assert.deepEqual((await g.bridge.flushSync()).results, [{ recipient: 'jarvis', outcome: 'no_destination' }]);
  assert.deepEqual(g.snapshot().messages[gb!]!.jobIds, []); assert.equal(g.snapshot().messages[gb!]!.syncBatch!.rehomedTo, undefined);
});

test('carrier loss: repeated flushes in the same hour re-offer the same batch without re-homing or another cap slot', async () => {
  const { f, batch } = await deadCarrier();
  f.set(noon + 5000);
  const first = await f.bridge.flushSync();
  const again = await f.bridge.flushSync(); // e.g. curl retry after a lost publication
  assert.deepEqual([first.dispatch, again.dispatch], [[batch], [batch]]);
  assert.deepEqual(again.results, []);
  assert.equal(f.snapshot().messages[batch!]!.jobIds.length, 1);
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 1);
});

test('carrier loss: two stranded batches plus new data due together cost one wake and one cap slot', async () => {
  const f = await fixture();
  f.set(start + HOUR); // 11:30 CDT
  const strand = async (subject: string) => {
    const x = f.sync('jarvis', { subject }); await f.send(x);
    const w = f.message(); await f.send(w);
    await f.store.transaction(s => { for (const id of s.messages[w.id]!.jobIds) s.jobs[id]!.state = 'dead'; });
    return { x, w, batch: f.snapshot().messages[w.id]!.syncBatchIds![0] };
  };
  const one = await strand('one'), two = await strand('two'), held = await strand('held');
  // A receiver read and claimed the third carrier just before the run: its batch is held through that claim.
  f.set(noon - 30000);
  await f.bridge.read(friday, { messageId: held.w.id });
  const claimHeld = await f.bridge.claim(friday, { messageId: held.w.id });
  assert.deepEqual(claimHeld.syncBatchIds, [held.batch]);
  const z = f.sync('jarvis', { subject: 'new' }); await f.send(z); // newly pending at the due run
  const holdBefore = f.snapshot().receipts[held.batch!];
  const jobsBefore = Object.keys(f.snapshot().jobs).length;
  f.set(noon + 5000);
  // Concurrent and retried runs at the same due time.
  const runs = await Promise.all([f.bridge.flushSync(), f.bridge.flushSync()]);
  const retry = await f.bridge.flushSync();
  const flushed = [...runs, retry].flatMap(r => r.results);
  assert.deepEqual(flushed, [{ recipient: 'friday', outcome: 'flushed', reason: 'scheduled', items: 1, rehomedBatches: 2 }],
    'scheduled once across all runs');
  const carrier = runs[0].dispatch[0];
  for (const r of [...runs, retry]) assert.deepEqual(r.dispatch, [carrier], 'one wake for everything due');
  assert.equal(Object.keys(f.snapshot().jobs).length, jobsBefore + 1, 'one new delivery job, none per item or per batch');
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 1, 'same daily-cap accounting as a fresh flush');
  // Batch identity is reused: the stranded batches ride the flush batch; the held one is untouched.
  assert.deepEqual([...f.snapshot().messages[carrier!]!.syncBatchIds!].sort(), [one.batch, two.batch].sort());
  for (const b of [one.batch, two.batch]) {
    assert.deepEqual(f.snapshot().messages[b!]!.jobIds, []); assert.equal(f.snapshot().messages[b!]!.syncBatch!.rehomedTo, carrier);
  }
  assert.equal(f.snapshot().messages[held.batch!]!.syncBatch!.rehomedTo, undefined);
  assert.deepEqual(f.snapshot().receipts[held.batch!], holdBefore, 'the carrier-held receipt is not invalidated');
  // The new carrier's claim takes the two re-homed batches; the old IDs stay the only claim records for them.
  const read = await f.bridge.read(friday, { messageId: carrier });
  assert.deepEqual(read.syncBatches!.map(b => b.messageId).sort(), [carrier, one.batch, two.batch].sort());
  const claim = await f.bridge.claim(friday, { messageId: carrier });
  assert.deepEqual(claim.syncBatchIds!.sort(), [one.batch, two.batch].sort());
  for (const b of [one.batch, two.batch]) await assert.rejects(f.bridge.claim(friday, { messageId: b }), /receipt_busy/);
  // The old carrier is still valid and claimable, but it cannot take the batch the new carrier holds.
  const oldCarrier = await f.bridge.claim(friday, { messageId: one.w.id });
  assert.deepEqual([oldCarrier.syncBatchIds, oldCarrier.syncBatchesHeldElsewhere], [[], [one.batch]]);
  const done = await f.bridge.complete(friday, { messageId: carrier, claimId: claim.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: [carrier, one.batch, two.batch] });
  assert.deepEqual(done.syncBatchesAcked!.sort(), [carrier, one.batch, two.batch].sort());
  for (const id of [one.x.id, two.x.id, z.id]) assert.equal(f.snapshot().receipts[id]!.state, 'complete');
  // The held batch is still completed through its own carrier's claim.
  const heldDone = await f.bridge.complete(friday, { messageId: held.w.id, claimId: claimHeld.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: [held.batch] });
  assert.deepEqual(heldDone.syncBatchesAcked, [held.batch]);
  assert.equal(f.snapshot().receipts[held.x.id]!.state, 'complete');
});

test('carrier loss after rollback: a stranded batch is delivered on the next run even with the flag off', async () => {
  const { f, batch } = await deadCarrier();
  f.enabled.recipients = [];
  f.set(start + 30 * MINUTE); // any run
  const out = await f.bridge.flushSync();
  assert.deepEqual(out.results, [{ recipient: 'friday', outcome: 'flushed', reason: 'rollback', items: 0, rehomedBatches: 1 }]);
  assert.deepEqual(out.dispatch, [batch]);
  // An unchanged receiver reads, claims and completes it as a v1 status message.
  await f.bridge.read(friday, { messageId: batch });
  assert.deepEqual((await f.handle(friday, batch!)).syncBatchesAcked, [batch]);
});

// --- Completion capacity: at most 32 syncBatchIds per completion ------------
// n stranded piggyback batches: each loop sends a unique-subject SYNC, then a
// WAKE whose authority lapses 30 s later (so it carries and strands one batch).
async function strandMany(f: Fx, n: number) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const x = f.sync('jarvis', { subject: `s${i}` }); await f.send(x);
    const w = f.message(); await f.send(w, who('jarvis', f.clock() + 30000));
    out.push({ x, w, batch: f.snapshot().messages[w.id]!.syncBatchIds![0] });
    f.advance(60000); // stays under the 10-per-minute admission limit
  }
  return out;
}
test('completion capacity (repro): 33 stranded batches re-homed at one run stay completable with the documented flow', async () => {
  const f = await fixture();
  await strandMany(f, 33);
  assert.equal(Object.keys(f.snapshot().messages).length, 99);
  f.set(noon + 5000);
  const out = await f.bridge.flushSync();
  assert.equal(out.dispatch.length, 1, 'one carrier');
  const done = await f.receive(out.dispatch[0]!); // read -> claim -> complete with the read's held IDs
  assert.ok(done.syncBatchesAcked!.length <= 32);
});

// The carrier holds at most 32 IDs: its own (when it is a batch, as both a
// stranded carrier and a fresh flush batch are) plus 31 attached. The rest
// stay stranded with unchanged IDs and go out at the next due run, oldest first.
for (const [n, withNew] of [[31, false], [32, false], [33, false], [31, true], [32, true]] as [number, boolean][]) {
  test(`completion capacity: ${n} stranded batches${withNew ? ' plus new data' : ''} -> carrier fits 32, overflow follows`, async () => {
    const f = await fixture();
    const stranded = await strandMany(f, n);
    if (withNew) await f.send(f.sync('jarvis', { subject: 'new' }));
    f.set(noon + 5000);
    const out = await f.bridge.flushSync();
    assert.equal(out.dispatch.length, 1);
    const carrier = out.dispatch[0];
    await f.bridge.markSyncDispatched(out.dispatch); // as the trigger route does after publishing
    const attachedCount = withNew ? Math.min(n!, 31) : Math.min(n! - 1, 31);
    const overflow = n! - attachedCount - (withNew ? 0 : 1);
    assert.equal(f.snapshot().messages[carrier!]!.syncBatchIds?.length ?? 0, attachedCount);
    assert.equal(out.results[0]!.rehomedBatches, n! - overflow);
    const done = await f.receive(carrier!);
    assert.equal(done.syncBatchesAcked!.length, attachedCount + 1);
    const left = stranded.filter(t => !f.snapshot().messages[t.batch!]!.syncBatch!.ackedAt);
    assert.equal(left.length, overflow);
    for (const t of left) {
      const b = f.snapshot().messages[t.batch!];
      assert.deepEqual([b!.jobIds, b!.syncBatch!.rehomedTo], [[], undefined], 'overflow is not marked re-homed or handled');
      assert.equal(f.snapshot().receipts[t.x.id], undefined);
    }
    // Next hourly run: the overflow goes out (oldest first) and is completable.
    f.set(noon + HOUR + 5000);
    const next = await f.bridge.flushSync();
    if (!overflow) { assert.deepEqual(next.dispatch, []); return; }
    assert.deepEqual(next.dispatch, [left[0]!.batch]);
    assert.deepEqual((await f.receive(left[0]!.batch!)).syncBatchesAcked, [left[0]!.batch]);
    for (const t of stranded) assert.equal(f.snapshot().receipts[t.x.id]!.state, 'complete');
    assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 2);
  });
}

test('completion capacity: data arriving between flush and read is not collected into a full carrier', async () => {
  const f = await fixture();
  await strandMany(f, 32);
  f.set(noon + 5000);
  const carrier = (await f.bridge.flushSync()).dispatch[0];
  const z = f.sync('jarvis', { subject: 'late' }); await f.send(z);
  const read = await f.bridge.read(friday, { messageId: carrier });
  assert.equal(read.syncBatches!.length, 32, 'own + 31 attached; nothing collected');
  assert.equal(f.snapshot().messages[z.id]!.sync!.state, 'pending');
  assert.equal((await f.receive(carrier!)).syncBatchesAcked!.length, 32);
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[z.id]]);
});

test('completion capacity: repeated reads of one message stop collecting at 32 batches', async () => {
  const f = await fixture();
  const w = f.message(); await f.send(w);
  for (let i = 0; i < 34; i++) {
    await f.send(f.sync('jarvis', { subject: `r${i}` }));
    await f.bridge.read(friday, { messageId: w.id });
    f.advance(30000);
  }
  assert.equal(f.snapshot().messages[w.id]!.syncBatchIds!.length, 32);
  assert.equal(Object.values(f.snapshot().messages).filter(m => m.sync?.state === 'pending').length, 2);
  const done = await f.receive(w.id);
  assert.equal(done.syncBatchesAcked!.length, 32);
});

test('completion capacity: concurrent and retried flushes leave the overflow for exactly one later run', async () => {
  const f = await fixture();
  const stranded = await strandMany(f, 33);
  f.set(noon + 5000);
  const runs = [...await Promise.all([f.bridge.flushSync(), f.bridge.flushSync()]), await f.bridge.flushSync()];
  assert.equal(runs.flatMap(r => r.results).length, 1, 'scheduled once');
  const carrier = runs[0]!.dispatch[0];
  for (const r of runs) assert.deepEqual(r.dispatch, [carrier]);
  await f.bridge.markSyncDispatched([carrier!]);
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 1);
  const overflow = stranded.at(-1)!.batch;
  assert.equal(f.snapshot().messages[overflow!]!.syncBatch!.rehomedTo, undefined);
  f.set(noon + HOUR + 5000);
  const next = [...await Promise.all([f.bridge.flushSync(), f.bridge.flushSync()])];
  assert.equal(next.flatMap(r => r.results).length, 1);
  for (const r of next) assert.deepEqual(r.dispatch, [overflow]);
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 2);
});

test('completion capacity: an oversized existing carrier holds 32 and defers the rest, which stay claimable directly', async () => {
  const f = await fixture();
  const stranded = await strandMany(f, 33);
  f.set(noon + 5000);
  const carrier = (await f.bridge.flushSync()).dispatch[0];
  const overflow = stranded.at(-1)!.batch;
  // A snapshot written before the limit existed: all 33 attached to the carrier.
  await f.store.transaction(s => {
    s.messages[carrier!]!.syncBatchIds!.push(overflow!);
    Object.assign(s.messages[overflow!]!.syncBatch!, { rehomedTo: carrier, rehomedAt: noon + 5000 });
  });
  const read = await f.bridge.read(friday, { messageId: carrier });
  assert.equal(read.syncBatches!.length, 33, 'everything stays readable');
  const claim = await f.bridge.claim(friday, { messageId: carrier });
  assert.equal(claim.syncBatchIds!.length, 31); assert.deepEqual(claim.syncBatchesDeferred, [overflow]);
  // The deferred batch is not held by the carrier: it can be claimed directly at the same time.
  const direct = await f.bridge.claim(friday, { messageId: overflow });
  await assert.rejects(f.bridge.complete(friday, { messageId: carrier, claimId: claim.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: [carrier, overflow] }), /sync_batch_not_held/);
  const done = await f.bridge.complete(friday, { messageId: carrier, claimId: claim.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: [carrier, ...claim.syncBatchIds!] });
  assert.equal(done.syncBatchesAcked!.length, 32);
  assert.equal(f.snapshot().receipts[stranded.at(-1)!.x.id], undefined, 'deferred items not handled by the carrier');
  assert.deepEqual((await f.bridge.complete(friday, { messageId: overflow, claimId: direct.claimId, hostedEventId: null,
    hostedTurnId: null, syncBatchIds: [overflow] })).syncBatchesAcked, [overflow]);
  for (const t of stranded) assert.equal(f.snapshot().receipts[t.x.id]!.state, 'complete');
});

// --- Restored ACKs (owner instruction) ------------------------------------------
// ACK = the receiver reports it handled the received data. One immediate
// correlated ACK per handled direct message and per handled non-empty batch,
// created at completion (never at send or enqueue), never for an ACK.
const acksIn = (s: BridgeState) => Object.values(s.messages).filter(m => m.envelope.kind === 'ack');
const ackOf = (s: BridgeState, id: string) => acksIn(s).filter(m => m.envelope.correlationId === id);
// Records each pre-commit receipt dispatch together with whether the receipt
// was still uncommitted at that moment.
function prepareSpy(get: () => BridgeState | undefined) {
  const calls: { id: string; committed: boolean }[] = [];
  return { calls, prepareReceipt: async (id: string) => { calls.push({ id, committed: get()?.receipts[id]?.state === 'complete' }); } };
}

test('ACK (direct/urgent): a promoted WAKE is ACKed at completion only; an omitted piggyback batch gets no ACK until handled', async () => {
  let f!: Fx; const spy = prepareSpy(() => f.snapshot());
  f = await fixture({ bridgeOptions: { prepareReceipt: id => spy.prepareReceipt(id) } });
  const a = f.sync('jarvis', { subject: 'A' }); await f.send(a);
  const urgent = f.sync('jarvis', { subject: 'Now', dueAt: iso(start + HOUR) });
  const sent = await f.send(urgent);
  assert.equal(sent.class, 'wake'); assert.equal(sent.piggybackedSyncItems, 1);
  assert.deepEqual(acksIn(f.snapshot()), [], 'no ACK at send time');
  const read = await f.bridge.read(friday, { messageId: urgent.id });
  const batch = read.syncBatches![0]!.messageId;
  const claim = await f.bridge.claim(friday, { messageId: urgent.id });
  assert.deepEqual(claim.syncBatchIds, [batch]);
  assert.deepEqual(acksIn(f.snapshot()), [], 'no ACK at claim time');
  const done = await f.bridge.complete(friday, { messageId: urgent.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
  assert.deepEqual(spy.calls, [{ id: urgent.id, committed: false }], 'only the message ACK is pre-armed: the batch was not named');
  assert.deepEqual(ackOf(f.snapshot(), urgent.id).map(m => m.envelope.id), [done.ackMessageId]);
  assert.equal('syncBatchAcks' in done, false); assert.equal('syncBatchesAcked' in done, false);
  assert.deepEqual(ackOf(f.snapshot(), batch), [], 'omitted batch: no ACK');
  assert.equal(f.snapshot().receipts[batch], undefined, 'hold released, not acknowledged');
  // Handled later on its own: exactly one ACK for it.
  assert.deepEqual(ids((await f.bridge.inboxRead(friday)).syncBatches), [[a.id]]);
  const direct = await f.handle(friday, batch, [batch]);
  assert.deepEqual(ackOf(f.snapshot(), batch).map(m => m.envelope.id), [direct.ackMessageId]);
  assert.equal(acksIn(f.snapshot()).length, 2);
});

test('ACK (piggyback): the carrier ACK plus one separate ACK per handled attached batch; items share their batch ACK', async () => {
  let f!: Fx; const spy = prepareSpy(() => f.snapshot());
  f = await fixture({ bridgeOptions: { prepareReceipt: id => spy.prepareReceipt(id) } });
  const a = f.sync('jarvis', { subject: 'A' }), a2 = f.sync('jarvis', { subject: 'A2' }); await f.send(a); await f.send(a2);
  const w = f.message(); await f.send(w); // piggybacks batch 1 (a, a2)
  const b = f.sync('jarvis', { subject: 'B' }); await f.send(b);
  const read = await f.bridge.read(friday, { messageId: w.id }); // collects batch 2 (b)
  assert.deepEqual(ids(read.syncBatches!), [[a.id, a2.id], [b.id]]);
  const [b1, b2] = read.syncBatches!.map(x => x.messageId);
  const claim = await f.bridge.claim(friday, { messageId: w.id });
  assert.deepEqual(claim.syncBatchIds, [b1, b2]);
  const done = await f.bridge.complete(friday, { messageId: w.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null,
    syncBatchIds: [b1, b2] });
  assert.deepEqual(spy.calls, [w.id, b1, b2].map(id => ({ id, committed: false })), 'every ACK pre-armed before the commit');
  const s = f.snapshot();
  assert.deepEqual(done.syncBatchesAcked, [b1, b2]);
  assert.deepEqual(done.syncBatchAcks!.map(x => x.batchMessageId), [b1, b2]);
  const all = [done.ackMessageId, ...done.syncBatchAcks!.map(x => x.ackMessageId)];
  assert.equal(new Set(all).size, 3, 'three distinct ACKs; the carrier ACK is never reused');
  assert.deepEqual(all.map(id => s.messages[id!]!.envelope.correlationId), [w.id, b1, b2]);
  for (const id of all) assert.deepEqual([s.messages[id!]!.envelope.from, s.messages[id!]!.envelope.to], ['friday', 'jarvis']);
  // Each batch receipt links its own ACK (what queue dispatchReceiptOf resolves).
  assert.equal(s.receipts[w.id]!.ackMessageId, done.ackMessageId);
  for (const x of done.syncBatchAcks!) {
    assert.equal(s.receipts[x.batchMessageId]!.ackMessageId, x.ackMessageId);
    assert.equal(s.receipts[x.batchMessageId]!.viaMessage, w.id);
    assert.ok(s.messages[x.ackMessageId!]!.jobIds.length === 1);
  }
  // Items: no ACK of their own; covered by their batch's ACK.
  for (const [item, x] of [[a, 0], [a2, 0], [b, 1]] as [Draft, number][]) {
    assert.deepEqual([s.receipts[item!.id]!.ackMessageId, s.receipts[item!.id]!.batchAckMessageId], [null, done.syncBatchAcks![x!]!.ackMessageId]);
    assert.deepEqual(ackOf(s, item!.id), []);
  }
  assert.deepEqual(done.jobIds!.sort(), all.flatMap(id => s.messages[id!]!.jobIds).sort());
  // ACK -> no ACK: the original sender completing a batch ACK creates nothing.
  const back = await f.handle(jarvis, done.syncBatchAcks![0]!.ackMessageId!);
  assert.equal(back.ackMessageId, null); assert.deepEqual(back.jobIds, []);
  assert.equal(acksIn(f.snapshot()).length, 3);
});

test('ACK dedup: a lost completion response, retries and re-claims never duplicate an ACK or spend quota', async () => {
  let lose = false;
  const wrapStore = (inner: Store) => ({ transaction: async <T>(fn: Transition<T>): Promise<T> => {
    const out = await inner.transaction(fn);
    if (lose && (out as Done)?.completed === true && (out as NonNullable<Done>).duplicate === false) { lose = false; throw Error('FIXTURE_COMMIT_RESPONSE_LOST'); }
    return out;
  } });
  const f = await fixture({ wrapStore });
  const a = f.sync('jarvis', { subject: 'A' }); await f.send(a);
  const w = f.message(); await f.send(w);
  const read = await f.bridge.read(friday, { messageId: w.id }), batch = read.syncBatches![0]!.messageId;
  const claim = await f.bridge.claim(friday, { messageId: w.id });
  const params = { messageId: w.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null, syncBatchIds: [batch] };
  const before = f.snapshot();
  lose = true;
  await assert.rejects(f.bridge.complete(friday, params), /FIXTURE_COMMIT_RESPONSE_LOST/);
  const committed = f.snapshot();
  assert.equal(acksIn(committed).length, 2, 'committed despite the lost response');
  const retry = await f.bridge.complete(friday, params);
  assert.equal(retry.duplicate, true);
  assert.equal(retry.ackMessageId, committed.receipts[w.id]!.ackMessageId);
  assert.deepEqual(retry.syncBatchAcks, [{ batchMessageId: batch, ackMessageId: committed.receipts[batch]!.ackMessageId }]);
  assert.deepEqual(retry.syncBatchesAcked, [batch]);
  // Further retries, a direct re-claim of the batch, and a re-read change nothing.
  await f.bridge.complete(friday, params);
  assert.deepEqual(await f.bridge.claim(friday, { messageId: batch }), { duplicate: true, completed: true,
    ackMessageId: committed.receipts[batch]!.ackMessageId });
  await f.bridge.read(friday, { messageId: w.id });
  const after = f.snapshot();
  assert.equal(acksIn(after).length, 2);
  assert.deepEqual(after.probeAdmissions, before.probeAdmissions, 'ACKs never spend send admission quota');
  assert.deepEqual(Object.keys(after.messageIds!).length, Object.keys(committed.messageIds!).length);
  assert.deepEqual(after.jobs, committed.jobs);
});

test('ACK lost commit: a failed completion commit leaves the pre-armed dispatch harmless and the retry ACKs once', async () => {
  let failCommit = false;
  const wrapStore = (inner: Store) => ({ transaction: <T>(fn: Transition<T>) => inner.transaction(state => {
    const out = fn(state);
    if (failCommit && (out as Done)?.completed === true && (out as NonNullable<Done>).duplicate === false) { failCommit = false; throw Error('FIXTURE_COMMIT_FAILED'); }
    return out;
  }) });
  let f!: Fx; const spy = prepareSpy(() => f.snapshot());
  f = await fixture({ wrapStore, bridgeOptions: { prepareReceipt: id => spy.prepareReceipt(id) } });
  const a = f.sync('jarvis', { subject: 'A' }); await f.send(a);
  const w = f.message(); await f.send(w);
  const batch = (await f.bridge.read(friday, { messageId: w.id })).syncBatches![0]!.messageId;
  const claim = await f.bridge.claim(friday, { messageId: w.id });
  const params = { messageId: w.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null, syncBatchIds: [batch] };
  failCommit = true;
  await assert.rejects(f.bridge.complete(friday, params), /FIXTURE_COMMIT_FAILED/);
  assert.deepEqual(spy.calls.map(c => c.id), [w.id, batch], 'both ACK dispatches were armed before the failed commit');
  const rolled = f.snapshot();
  assert.deepEqual(acksIn(rolled), []);
  assert.equal(rolled.receipts[w.id]!.state, 'claimed'); assert.equal(rolled.messages[batch]!.syncBatch!.ackedAt, undefined);
  // What the queue's dispatchReceiptOf resolves now: nothing (no ACK, no spawned work).
  assert.equal(rolled.receipts[batch]!.ackMessageId, undefined);
  const done = await f.bridge.complete(friday, params);
  const s = f.snapshot();
  assert.equal(acksIn(s).length, 2);
  // And after the retry: each armed receipt resolves to its own ACK's jobs.
  for (const id of [w.id, batch]) assert.equal(s.messages[s.receipts[id]!.ackMessageId!]!.jobIds.length, 1, id);
  assert.equal(s.receipts[batch]!.ackMessageId, done.syncBatchAcks![0]!.ackMessageId);
});

test('ACK is terminal (repro): reading, claiming or completing an ACK collects no SYNC and the pending queue stays pending', async () => {
  // A legacy ACK created with the flag off...
  const f = await fixture({ recipients: [] });
  const m = f.message('jarvis'); await f.send(m);
  const ackId = (await f.handle(friday, m.id)).ackMessageId;
  assert.ok(ackId);
  // ...then batching is enabled for the ACK's recipient and SYNC is queued to it.
  f.enabled.recipients = ['jarvis'];
  const pending = f.sync('friday', { subject: 'queued for jarvis' }); await f.send(pending);
  const before = f.snapshot();
  assert.equal(before.messages[pending.id]!.sync!.state, 'pending');
  const read = await f.bridge.read(jarvis, { messageId: ackId });
  assert.equal('syncBatches' in read, false, 'an ACK read presents nothing');
  const claim = await f.bridge.claim(jarvis, { messageId: ackId });
  assert.equal('syncBatchIds' in claim, false);
  const done = await f.bridge.complete(jarvis, { messageId: ackId, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
  assert.deepEqual([done.ackMessageId, done.jobIds, 'syncBatchAcks' in done], [null, [], false]);
  const after = f.snapshot();
  assert.equal(after.messages[pending.id]!.sync!.state, 'pending', 'still queued');
  assert.deepEqual(batchesIn(after), [], 'no batch was cut');
  assert.equal(after.messages[ackId]!.syncBatchIds, undefined);
  assert.deepEqual(acksIn(after).map(x => x.envelope.id), [ackId], 'no reciprocal ACK');
  assert.deepEqual(after.jobs, before.jobs);
  // The data is intact for the next real read.
  assert.deepEqual(ids((await f.bridge.inboxRead(jarvis)).syncBatches), [[pending.id]]);
});

test('ACK return path (repro): a batch ACK needs only a usable return window, not the batch\'s 12 h synthetic authority', async () => {
  const f = await fixture();
  const setSub = (until: number) => f.store.transaction(s => { for (const sub of Object.values(s.subscriptions)) sub.expiresAt = until; });
  const a = f.sync('jarvis', { subject: 'A' }); await f.send(a);
  const batch = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  assert.equal(Date.parse(f.snapshot().messages[batch]!.envelope.expiresAt!), start + SYNC_BATCH_TTL_MS);
  // 30 minutes of return subscription: unobtainable under a 12 h coverage rule, enough for a <= 1 h ACK.
  await setSub(start + 30 * MINUTE);
  // The v1 rule still applies to a real message whose authority outlasts the path.
  await assert.rejects(f.send(f.message()), /return_subscription_required/);
  const claim = await f.bridge.claim(friday, { messageId: batch });
  // Revoked between claim and completion: refused, nothing changes.
  await setSub(start - 1);
  const params = { messageId: batch, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null, syncBatchIds: [batch] };
  const held = f.snapshot();
  await assert.rejects(f.bridge.complete(friday, params), /return_subscription_required/);
  assert.deepEqual(f.snapshot(), held);
  await setSub(start + 30 * MINUTE);
  const done = await f.bridge.complete(friday, params);
  const ack = f.snapshot().messages[done.ackMessageId!];
  assert.equal(Date.parse(ack!.envelope.expiresAt!), start + 30 * MINUTE, 'ACK lifetime capped to the return window');
  assert.ok(ack!.authorization.expiresAt <= start + 30 * MINUTE);
  // Too short a window (under 5 min past the lease) is refused at claim, with no state change.
  // (Sending a SYNC item keeps the strict v1 rule: after a rollback it is ACKed natively.)
  await setSub(start + 6 * HOUR);
  const b = f.sync('jarvis', { subject: 'B' }); await f.send(b);
  const next = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  await setSub(start + 5 * MINUTE);
  const before = f.snapshot();
  await assert.rejects(f.bridge.claim(friday, { messageId: next }), /return_subscription_required/);
  assert.deepEqual(f.snapshot(), before);
  // A durable denial of the return path's owner closes it the same way.
  await setSub(start + 30 * MINUTE);
  await f.store.transaction(s => { s.resourceDenials = { [jarvis.principalKey]: {} as ResourceDenial }; });
  await assert.rejects(f.bridge.claim(friday, { messageId: next }), /message_authorization_inactive|return_subscription_required/);
  assert.deepEqual(ackOf(f.snapshot(), next), []);
});

test('ACK return path: an attached batch without a usable return path is deferred at claim and cannot be ACKed by the carrier', async () => {
  const f = await fixture();
  const a = f.sync('jarvis', { subject: 'A' }); await f.send(a);
  const w = f.message(); await f.send(w);
  const batch = (await f.bridge.read(friday, { messageId: w.id })).syncBatches![0]!.messageId;
  // A batch owned by a principal that has no return subscription (e.g. a rotated key).
  await f.store.transaction(s => { s.messages[batch]!.authorization.owner = 'd'.repeat(64); });
  const claim = await f.bridge.claim(friday, { messageId: w.id });
  assert.deepEqual([claim.syncBatchIds, claim.syncBatchesDeferred], [[], [batch]]);
  await assert.rejects(f.bridge.complete(friday, { messageId: w.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null,
    syncBatchIds: [batch] }), /sync_batch_not_held/);
  const done = await f.bridge.complete(friday, { messageId: w.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
  assert.ok(done.ackMessageId); assert.deepEqual(ackOf(f.snapshot(), batch), []);
});

test('ACK: expired items are skipped without completing their original receipts; policy fences remain', async () => {
  const f = await fixture();
  const a = f.sync('jarvis', { subject: 'A', expiresAt: iso(start + 3 * HOUR) }); await f.send(a);
  f.set(start + 4 * HOUR);
  const read = await f.bridge.inboxRead(friday), batch = read.syncBatches[0]!.messageId;
  assert.equal(read.syncBatches[0]!.items[0]!.expired, true);
  const done = await f.handle(friday, batch, [batch]);
  assert.equal(f.snapshot().receipts[a.id], undefined, 'an expired v1 receipt is never completed through a batch');
  assert.deepEqual(ackOf(f.snapshot(), batch).map(m => m.envelope.id), [done.ackMessageId]);
  // A policy change closes the batch: no claim, no ACK.
  const g = await fixture();
  await g.send(g.sync('jarvis', { subject: 'P' }));
  const gb = (await g.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  (g.bridge.messagePolicyIds as Record<string, string>).jarvis = 'e'.repeat(64);
  await assert.rejects(g.bridge.claim(friday, { messageId: gb }), /message_authorization_inactive/);
  // A durable denial of the batch's sender after the claim refuses the completion.
  const h = await fixture();
  await h.send(h.sync('jarvis', { subject: 'D' }));
  const hb = (await h.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  const claim = await h.bridge.claim(friday, { messageId: hb });
  await h.store.transaction(s => { s.resourceDenials = { [jarvis.principalKey]: {} as ResourceDenial }; });
  await assert.rejects(h.bridge.complete(friday, { messageId: hb, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null,
    syncBatchIds: [hb] }), /message_authorization_inactive/);
  for (const x of [g, h]) assert.deepEqual(acksIn(x.snapshot()), []);
});

test('ACK (stranded fallback): a re-homed batch on a flush carrier gets its own ACK, and its old carrier does not repeat it', async () => {
  const { f, x, w, batch } = await deadCarrier();
  const y = f.sync('jarvis', { subject: 'Y' }); await f.send(y);
  f.set(noon + 5000);
  const carrier = (await f.bridge.flushSync()).dispatch[0];
  assert.notEqual(carrier, batch);
  const done = await f.receive(carrier!);
  assert.deepEqual(done.syncBatchesAcked, [carrier, batch]);
  const s = f.snapshot();
  assert.equal(s.messages[done.ackMessageId!]!.envelope.correlationId, carrier);
  assert.deepEqual(done.syncBatchAcks!.map(a => [a.batchMessageId, s.messages[a.ackMessageId!]!.envelope.correlationId]), [[batch, batch]]);
  assert.equal(s.receipts[x.id]!.batchAckMessageId, done.syncBatchAcks![0]!.ackMessageId);
  assert.equal(s.receipts[y.id]!.batchAckMessageId, done.ackMessageId);
  // The original carrier, if still handled, ACKs only itself.
  const old = await f.receive(w.id);
  assert.equal('syncBatchAcks' in old, false);
  assert.equal(ackOf(f.snapshot(), batch!).length, 1);
});

test('ACK capacity: a 32-ID completion creates and pre-arms 32 distinct batch ACKs in one commit', async () => {
  let f!: Fx; const spy = prepareSpy(() => f.snapshot());
  f = await fixture({ bridgeOptions: { prepareReceipt: id => spy.prepareReceipt(id) } });
  await strandMany(f, 32);
  f.set(noon + 5000);
  const carrier = (await f.bridge.flushSync()).dispatch[0];
  const done = await f.receive(carrier!);
  assert.equal(done.syncBatchesAcked!.length, 32);
  const acked = done.syncBatchesAcked, s = f.snapshot();
  assert.deepEqual(spy.calls.map(c => c.id).sort(), [...acked!].sort());
  assert.ok(spy.calls.every(c => !c.committed));
  const ackIds = acked!.map(id => s.receipts[id]!.ackMessageId);
  assert.equal(new Set(ackIds).size, 32);
  assert.deepEqual(ackIds.map(id => s.messages[id!]!.envelope.correlationId), acked);
  assert.equal(done.jobIds!.length, 32);
});

test('ACK with the flag turned off: an outstanding batch still gets exactly one ACK; v1 messages keep theirs', async () => {
  const f = await fixture();
  await f.send(f.sync('jarvis', { subject: 'A' }));
  const batch = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  f.enabled.recipients = [];
  const done = await f.handle(friday, batch, [batch]);
  assert.deepEqual(ackOf(f.snapshot(), batch).map(m => m.envelope.id), [done.ackMessageId]);
  const m = f.message(); await f.send(m);
  assert.equal('syncBatches' in await f.bridge.read(friday, { messageId: m.id }), false);
  assert.ok((await f.handle(friday, m.id)).ackMessageId);
  assert.equal(acksIn(f.snapshot()).length, 2);
});

test('ACK: an empty flush creates no batch and no ACK', async () => {
  const f = await fixture();
  f.set(noon + 5000);
  assert.deepEqual(await f.bridge.flushSync(), { boundary: noon, results: [], dispatch: [] });
  assert.deepEqual(Object.keys(f.snapshot().messages), []);
});

// --- ACK targets keep their own current authority -----------------------------
const OTHER_POLICY = 'd'.repeat(64);
const whoWith = (role: string, { policyId = policy, key }: { policyId?: string; key?: string } = {}) => Object.defineProperty<Principal>({ role, scopes: Object.values(SCOPES[role]!),
  principalKey: key || (role === 'jarvis' ? 'a' : 'b').repeat(64) }, VERIFIED_AUTHORIZATION,
{ value: { policyId, expiresAt: start + 7 * 86400000 } }) as VerifiedPrincipal;
// An old-policy batch stranded on its old carrier, then a policy rotation and
// new SYNC data: the noon flush makes a fresh (new-policy) carrier that
// attaches the old batch (normal carrier-loss fallback).
async function freshCarrierOldBatch(sender: string) {
  const recipient = sender === 'jarvis' ? 'friday' : 'jarvis';
  const f = await fixture({ recipients: [recipient] });
  const old = f.sync(sender, { subject: 'old' }); await f.send(old);
  const w = f.message(sender); await f.send(w);
  const oldBatch = f.snapshot().messages[w.id]!.syncBatchIds![0];
  (f.bridge.messagePolicyIds as Record<string, string>)[sender] = OTHER_POLICY;
  if (sender === 'jarvis') {
    // The events peer re-subscribes under the new policy (its return path).
    await f.store.transaction(s => { for (const sub of Object.values(s.subscriptions)) sub.authorization!.policyId = OTHER_POLICY; });
  }
  const fresh = f.sync(sender, { subject: 'new' }); await f.send(fresh, whoWith(sender, { policyId: OTHER_POLICY }));
  f.set(noon + 5000);
  const carrier = (await f.bridge.flushSync()).dispatch.find(id => id !== oldBatch);
  assert.deepEqual(f.snapshot().messages[carrier!]!.syncBatchIds, [oldBatch], 'old batch attached to the fresh carrier');
  return { f, recipient, old, fresh, oldBatch, carrier, as: whoWith(recipient) };
}
for (const sender of ['friday', 'jarvis']) {
  test(`ACK target authority (${sender} -> peer): a fresh carrier never holds or ACKs a batch whose policy was withdrawn`, async () => {
    const { f, old, fresh, oldBatch, carrier, as } = await freshCarrierOldBatch(sender);
    const read = await f.bridge.read(as, { messageId: carrier });
    assert.deepEqual(read.syncBatches!.map(b => b.messageId), [carrier, oldBatch]);
    const claim = await f.bridge.claim(as, { messageId: carrier });
    assert.deepEqual([claim.syncBatchIds, claim.syncBatchesInactive], [[], [oldBatch]]);
    assert.equal(f.snapshot().receipts[oldBatch!], undefined, 'not held');
    await assert.rejects(f.bridge.complete(as, { messageId: carrier, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null,
      syncBatchIds: [carrier, oldBatch] }), /sync_batch_not_held/);
    const done = await f.bridge.complete(as, { messageId: carrier, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null,
      syncBatchIds: [carrier] });
    assert.deepEqual(done.syncBatchesAcked, [carrier]); assert.equal('syncBatchAcks' in done, false);
    const s = f.snapshot();
    assert.deepEqual(ackOf(s, oldBatch!), [], 'no ACK for withdrawn data');
    assert.equal(s.receipts[old.id], undefined);
    assert.equal(s.receipts[fresh.id]!.batchAckMessageId, done.ackMessageId);
    // Not claimable directly either.
    await assert.rejects(f.bridge.claim(as, { messageId: oldBatch }), /message_authorization_inactive/);
  });
}

test('ACK target authority mid-await (friday -> jarvis): a batch denied between pre-arm and commit refuses the whole completion', async () => {
  let f!: Fx, deny = false;
  const itemOwner = 'f'.repeat(64);
  f = await fixture({ recipients: ['jarvis'], bridgeOptions: { prepareReceipt: async () => {
    if (deny) await f.store.transaction(s => { s.resourceDenials = { [itemOwner]: {} as ResourceDenial }; });
  } } });
  // Items admitted by one principal, the carrier by another (same role and policy).
  const item = f.sync('friday', { subject: 'I' }); await f.send(item, whoWith('friday', { key: itemOwner }));
  const w = f.message('friday'); await f.send(w);
  const batch = (await f.bridge.read(jarvis, { messageId: w.id })).syncBatches![0]!.messageId;
  const claim = await f.bridge.claim(jarvis, { messageId: w.id });
  assert.deepEqual(claim.syncBatchIds, [batch]);
  const params = { messageId: w.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null, syncBatchIds: [batch] };
  const before = f.snapshot();
  deny = true;
  await assert.rejects(f.bridge.complete(jarvis, params), (e: BridgeError) => e.code === 'sync_batch_authorization_inactive' &&
    e.details?.batchMessageId === batch);
  deny = false;
  const after = f.snapshot();
  assert.deepEqual(acksIn(after), []); assert.deepEqual(after.receipts, before.receipts, 'nothing committed');
  // The carrier alone still completes; the withdrawn batch gets no ACK.
  const done = await f.bridge.complete(jarvis, { ...params, syncBatchIds: [] });
  assert.ok(done.ackMessageId); assert.deepEqual(ackOf(f.snapshot(), batch), []);
});

test('ACK target authority mid-await (jarvis -> friday): a policy rotation between pre-arm and commit creates no ACK at all', async () => {
  let f!: Fx, rotate = false;
  f = await fixture({ bridgeOptions: { prepareReceipt: async () => { if (rotate) (f.bridge.messagePolicyIds as Record<string, string>).jarvis = OTHER_POLICY; } } });
  await f.send(f.sync('jarvis', { subject: 'I' }));
  const w = f.message(); await f.send(w);
  const batch = (await f.bridge.read(friday, { messageId: w.id })).syncBatches![0]!.messageId;
  const claim = await f.bridge.claim(friday, { messageId: w.id });
  const before = f.snapshot();
  rotate = true;
  await assert.rejects(f.bridge.complete(friday, { messageId: w.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null,
    syncBatchIds: [batch] }), /message_authorization_inactive/);
  assert.deepEqual(acksIn(f.snapshot()), []); assert.deepEqual(f.snapshot().receipts, before.receipts);
});

for (const direction of ['jarvis', 'friday']) test(`batch dispositions (${direction}): mixed live/expired, ACK read and lost-response replay are durable`, async () => {
  const f = await fixture({ recipients: ['jarvis', 'friday'] });
  const recipient = f.principal(direction === 'jarvis' ? 'friday' : 'jarvis');
  const expired = f.sync(direction, { expiresAt: iso(start + 3 * HOUR) });
  const live = f.sync(direction, { subject: 'live' });
  await f.send(expired); await f.send(live);
  f.set(start + 3 * HOUR);
  const read = await f.bridge.inboxRead(recipient), batch = read.syncBatches[0]!;
  assert.deepEqual(batch.items.map(i => [i.messageId, i.disposition, i.text]), [
    [expired.id, 'skipped_expired', ''], [live.id, 'pending', live.text]]);
  const claim = await f.bridge.claim(recipient, { messageId: batch.messageId });
  const params = { messageId: batch.messageId, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null };
  const done = await f.bridge.complete(recipient, params); // old successful input stays supported
  const outcome = { batchMessageId: batch.messageId, items: [{ messageId: expired.id, disposition: 'skipped_expired' },
    { messageId: live.id, disposition: 'handled' }], handledCount: 1, skippedExpiredCount: 1 };
  assert.deepEqual(done.syncBatchOutcomes, [outcome]);
  assert.equal(f.snapshot().receipts[expired.id], undefined);
  assert.equal(f.snapshot().receipts[live.id]!.state, 'complete');
  assert.deepEqual((await f.bridge.read(f.principal(direction), { messageId: done.ackMessageId })).syncBatchOutcome, outcome);
  assert.deepEqual((await f.bridge.status(f.principal(direction), { messageId: done.ackMessageId })).syncBatchOutcome, outcome);
  assert.equal((await f.bridge.status(recipient, { messageId: expired.id })).receiptCompleted, false);
  const before = f.snapshot();
  // Replay after both originals expire: the committed disposition must not be recomputed.
  f.set(start + 7 * HOUR);
  assert.deepEqual((await f.bridge.complete(recipient, params)).syncBatchOutcomes, [outcome]);
  assert.deepEqual(f.snapshot().receipts, before.receipts);
  assert.deepEqual(acksIn(f.snapshot()).map(m => m.envelope.id), acksIn(before).map(m => m.envelope.id));
  assert.equal((await f.bridge.claim(recipient, { messageId: batch.messageId })).completed, true);
});

test('batch dispositions: expiry crossing during a claim is skipped at commit, attached batches are exact and atomic', async () => {
  const f = await fixture();
  const x = f.sync('jarvis', { expiresAt: iso(start + 3 * HOUR) }); await f.send(x);
  f.set(start + 3 * HOUR - 20);
  const wake = f.message(); await f.send(wake);
  const read = await f.bridge.read(friday, { messageId: wake.id }), batch = read.syncBatches![0]!;
  assert.equal(batch.items[0]!.disposition, 'pending');
  const claim = await f.bridge.claim(friday, { messageId: wake.id });
  f.advance(20); // exact inclusive expiry, but the carrier and its 60 s claim are live
  const params = { messageId: wake.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null, syncBatchIds: [batch.messageId] };
  await assert.rejects(f.bridge.complete(friday, { ...params, syncBatchDispositions: [] }), /invalid_params/);
  assert.equal(acksIn(f.snapshot()).length, 0, 'a caller cannot invent dispositions or skip live items');
  await assert.rejects(f.bridge.complete(friday, params), /sync_batch_disposition_required/);
  assert.equal(acksIn(f.snapshot()).length, 0);
  await assert.rejects(f.bridge.complete(friday, { ...params, syncItemDispositions: [
    { batchMessageId: batch.messageId, messageId: randomUUID(), disposition: 'skipped_expired' }] }), /invalid_sync_item_disposition/);
  await assert.rejects(f.bridge.complete(friday, { ...params, syncItemDispositions: [
    { batchMessageId: randomUUID(), messageId: x.id, disposition: 'skipped_expired' }] }), /invalid_sync_item_disposition/);
  const explicit = { ...params, syncItemDispositions: [{ batchMessageId: batch.messageId, messageId: x.id, disposition: 'skipped_expired' }] };
  const done = await f.bridge.complete(friday, explicit);
  assert.deepEqual(done.syncBatchOutcomes, [{ batchMessageId: batch.messageId, items: [{ messageId: x.id, disposition: 'skipped_expired' }],
    handledCount: 0, skippedExpiredCount: 1 }]);
  assert.equal(f.snapshot().receipts[x.id], undefined);
  assert.equal(acksIn(f.snapshot()).length, 2, 'carrier ACK and truthful batch ACK, no per-item ACK');
  const ack = done.syncBatchAcks![0]!.ackMessageId!;
  assert.deepEqual((await f.bridge.read(jarvis, { messageId: ack })).syncBatchOutcome, done.syncBatchOutcomes![0]);
  assert.equal((await f.handle(jarvis, ack)).ackMessageId, null, 'ACK stays terminal');
  assert.deepEqual((await f.bridge.complete(friday, params)).syncBatchOutcomes, done.syncBatchOutcomes);
});

for (const disposition of ['handled', 'skipped_expired'] as const) test(`expiry crossing: explicit ${disposition} report, no expired v1 completion, stable post-ACK views`, async () => {
  const f = await fixture();
  const x = f.sync('jarvis', { expiresAt: iso(start + 3 * HOUR) }); await f.send(x);
  f.set(start + 3 * HOUR - 30);
  const batch = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  const claim = await f.bridge.claim(friday, { messageId: batch });
  const params = { messageId: batch, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null };
  // Cannot drop a still-live item using an expiry disposition.
  await assert.rejects(f.bridge.complete(friday, { ...params, syncItemDispositions: [
    { batchMessageId: batch, messageId: x.id, disposition: 'skipped_expired' }] }), /invalid_sync_item_disposition/);
  const handledAt = iso(f.clock() + 10);
  f.advance(30);
  await assert.rejects(f.bridge.complete(friday, params), /sync_batch_disposition_required/);
  assert.equal(acksIn(f.snapshot()).length, 0);
  // A refresh must not erase evidence that live text was already presented.
  assert.equal((await f.bridge.read(friday, { messageId: batch })).syncBatches![0]!.items[0]!.disposition, 'requires_disposition');
  for (const invalidAt of [iso(start + 3 * HOUR), iso(start), iso(f.clock() + 1)]) {
    await assert.rejects(f.bridge.complete(friday, { ...params, syncItemDispositions: [
      { batchMessageId: batch, messageId: x.id, disposition: 'handled', handledAt: invalidAt }] }), /invalid_sync_item_disposition/);
  }
  const attestation = { batchMessageId: batch, messageId: x.id, disposition, ...(disposition === 'handled' ? { handledAt } : {}) };
  const done = await f.bridge.complete(friday, { ...params, syncItemDispositions: [attestation] });
  const outcome = done.syncBatchOutcomes![0]!;
  assert.deepEqual(outcome.items, [{ messageId: x.id, disposition, ...(disposition === 'handled' ? { handledAt } : {}) }]);
  assert.equal(f.snapshot().receipts[x.id], undefined);
  await assert.rejects(f.bridge.claim(friday, { messageId: x.id }));
  assert.equal((await f.bridge.status(jarvis, { messageId: x.id })).receiptCompleted, false);
  f.advance(MINUTE);
  const read = await f.bridge.read(friday, { messageId: batch });
  assert.equal(read.syncBatches![0]!.items[0]!.disposition, disposition);
  assert.deepEqual(read.syncBatches![0]!.outcome, outcome);
  assert.deepEqual((await f.bridge.read(jarvis, { messageId: done.ackMessageId })).syncBatchOutcome, outcome);
  assert.deepEqual((await f.bridge.complete(friday, params)).syncBatchOutcomes, [outcome]);
  f.advance(SYNC_BATCH_TTL_MS);
  assert.deepEqual((await f.bridge.inboxRead(friday)).syncBatches, [], 'a skipped closure never requeues');
});

test('legacy body-bearing batch read is redacted without changing immutable hash/envelope/outbox; missing items fail closed', async () => {
  const f = await fixture();
  const secretBody = 'SYNTHETIC_EXPIRED_BODY', attachmentId = randomUUID();
  const x = f.sync('jarvis', { text: secretBody, expiresAt: iso(start + 3 * HOUR) }); await f.send(x);
  const batch = (await f.bridge.inboxRead(friday)).syncBatches[0]!.messageId;
  await f.store.transaction(s => {
    // Seed a pre-change stored envelope exactly as an older deployment could retain it.
    s.messages[batch]!.envelope.text = `${secretBody} attachmentIds ${attachmentId}`;
    s.messages[x.id]!.envelope.attachmentIds = [attachmentId];
    delete s.messages[batch]!.syncBatch!.livePresentedAt;
  });
  const before = f.snapshot();
  f.set(start + 3 * HOUR);
  const read = await f.bridge.read(friday, { messageId: batch });
  assert.equal(JSON.stringify(read).includes(secretBody), false);
  assert.equal(JSON.stringify(read).includes(attachmentId), false);
  assert.equal(read.syncBatches![0]!.items[0]!.disposition, 'requires_disposition', 'legacy full live presentation remains ambiguous');
  const after = f.snapshot();
  assert.deepEqual(after.messages[batch]!.envelope, before.messages[batch]!.envelope);
  assert.equal(after.messages[batch]!.hash, before.messages[batch]!.hash);
  assert.deepEqual(after.jobs, before.jobs);
  const claim = await f.bridge.claim(friday, { messageId: batch });
  const params = { messageId: batch, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null };
  await assert.rejects(f.bridge.complete(friday, params), /sync_batch_disposition_required/);
  await f.store.transaction(s => { delete s.messages[x.id]; });
  const missing = f.snapshot();
  await assert.rejects(f.bridge.read(friday, { messageId: batch }), /sync_batch_item_missing/);
  await assert.rejects(f.bridge.complete(friday, params), /sync_batch_item_missing/);
  assert.deepEqual(f.snapshot(), missing, 'no ACK or partial completion commits');
});

for (const scenario of ['accepted_without_read','omitted_attached_batch','crash_after_claim']) test(`event-only recovery: ${scenario} receives the same canonical batch through a fresh notification`, async () => {
  const f = await fixture();
  await f.send(f.sync());
  let batch: string;
  if (scenario === 'accepted_without_read') {
    f.set(noon);
    batch = (await f.bridge.flushSync()).dispatch[0]!;
    await f.bridge.markSyncDispatched([batch]);
  } else {
    const carrier = f.message(); await f.send(carrier);
    batch = (await f.bridge.read(friday, { messageId: carrier.id })).syncBatches![0]!.messageId;
    const claim = await f.bridge.claim(friday, { messageId: carrier.id });
    if (scenario === 'omitted_attached_batch') await f.bridge.complete(friday, {
      messageId: carrier.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
  }
  // Synthetic successful HTTP delivery, not a real receiver or provider test.
  await f.store.transaction(s => { for (const job of Object.values(s.jobs)) { job.state = 'accepted'; job.acceptedAt = f.clock(); } });
  const before = f.snapshot();
  f.advance(SYNC_RECEIPT_RECOVERY_MS); // Includes expiry of any 60 s receipt lease.
  const offered: string[] = [];
  assert.deepEqual(await reofferOverdueJobs(f.store, async id => { offered.push(id); }, f.clock()), { scheduled: 0, failed: 0, deferred: 0 });
  assert.deepEqual(offered, []);
  const recovered = await f.bridge.flushSync();
  assert.deepEqual(recovered.dispatch, [batch], 'native recovery keeps the canonical batch messageId');
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.ackedAt, undefined);
  for (const [id, job] of Object.entries(before.jobs)) assert.deepEqual(f.snapshot().jobs[id], job, 'original evidence stays immutable');
  const newJobs = Object.values(f.snapshot().jobs).filter(j => !before.jobs[j.id]);
  assert.equal(newJobs.length, 1);
  assert.equal(newJobs[0]!.syncRecoveryGeneration, 1);
  assert.equal(newJobs[0]!.maxAttempts, 1);
  assert.equal(JSON.parse(newJobs[0]!.body).data.messageId, batch);
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.recovery!.generation, 1);
  assert.equal((await f.bridge.read(friday, { messageId: batch })).syncBatches![0]!.messageId, batch);
  const receipt = await f.bridge.claim(friday, { messageId: batch });
  const done = await f.bridge.complete(friday, { messageId: batch, claimId: receipt.claimId, hostedEventId: null, hostedTurnId: null });
  assert.ok(done.ackMessageId);
  assert.deepEqual((await f.bridge.complete(friday, { messageId: batch, claimId: receipt.claimId, hostedEventId: null, hostedTurnId: null })).syncBatchOutcomes, done.syncBatchOutcomes);
});

function recoveryWorker(f: Fx, observed: { eventId: string; messageId: string }[], store: Store = f.store) {
  return new DeliveryWorker({ store, clock: f.clock, enabled: true, policyId: policy,
    messagePolicyIds: { jarvis: policy, friday: policy }, protector: f.events.protector,
    accessAllowed: async () => true,
    webhookSender: async job => { observed.push({ eventId: job.eventId, messageId: job.messageId }); return { status: 200, [DELIVERY_TRANSPORT_OUTCOME]: { terminal: false } }; },
    transport: async (_url, req) => { const event = JSON.parse(req.body); observed.push({ eventId: event.eventId, messageId: event.data.messageId }); return { status: 200 }; } });
}
async function recoveryFixture(from = 'jarvis', options: FixtureOptions = {}) {
  const f = await fixture({ ...options, recipients: [from === 'jarvis' ? 'friday' : 'jarvis'] });
  const item = f.sync(from); await f.send(item); f.set(noon);
  const batch = (await f.bridge.flushSync()).dispatch[0]!;
  await f.bridge.markSyncDispatched([batch]);
  const observed: { eventId: string; messageId: string }[] = [], worker = recoveryWorker(f, observed);
  for (const id of f.snapshot().messages[batch]!.jobIds) await worker.run(id);
  return { f, item, batch, observed, worker };
}
for (const from of ['jarvis', 'friday']) test(`receipt recovery (${from}): conservative backoff, fresh event IDs, immutable first HTTP evidence and bounded exhaustion`, async () => {
  const { f, batch, observed, worker } = await recoveryFixture(from);
  const initial = f.snapshot(), originalId = initial.messages[batch]!.jobIds[0]!;
  const original = initial.jobs[originalId];
  assert.equal(original!.state, 'accepted'); assert.equal(observed.length, 1);
  assert.equal(original!.firstTransportOutcome!.status, 200);
  let next = noon + SYNC_RECEIPT_RECOVERY_MS;
  for (let generation = 1; generation <= MAX_SYNC_RECEIPT_RECOVERIES; generation++) {
    f.set(next - 1); assert.deepEqual((await f.bridge.flushSync()).dispatch, []);
    f.set(next); assert.deepEqual((await f.bridge.flushSync()).dispatch, [batch]);
    const s = f.snapshot(), ids = s.messages[batch]!.jobIds.filter(id => s.jobs[id]!.syncRecoveryGeneration === generation);
    assert.equal(ids.length, 1); assert.equal(s.jobs[ids[0]!]!.maxAttempts, 1);
    assert.equal((await worker.run(ids[0]!)).transportAccepted, true);
    assert.equal((await worker.run(ids[0]!)).attempted, false, 'duplicate queue callback is not another send');
    await f.bridge.markSyncDispatched([batch]);
    assert.deepEqual(f.snapshot().jobs[originalId], original, 'original attempts/first outcome/body are never reset');
    assert.equal(f.snapshot().syncQueues![from === 'jarvis' ? 'friday' : 'jarvis']!.flushCount, generation + 1);
    next = s.messages[batch]!.syncBatch!.recovery!.nextAt;
  }
  f.set(next + HOUR);
  assert.deepEqual((await f.bridge.flushSync()).dispatch, []);
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.recovery!.generation, 4);
  assert.equal(observed.length, 5); assert.equal(new Set(observed.map(n => n.eventId)).size, 5);
  assert.deepEqual(new Set(observed.map(n => n.messageId)), new Set([batch]));
});

test('receipt recovery: live batch/item holds defer; completion, expiry and withdrawal suppress reserved recovery jobs', async () => {
  const { f, batch, item, worker, observed } = await recoveryFixture();
  f.set(noon + SYNC_RECEIPT_RECOVERY_MS - 1);
  await f.bridge.read(friday, { messageId: batch });
  const claim = await f.bridge.claim(friday, { messageId: batch });
  f.advance(1); assert.deepEqual((await f.bridge.flushSync()).dispatch, []);
  f.advance(60000); const out = await f.bridge.flushSync(); assert.deepEqual(out.dispatch, [batch]);
  const recovery = f.snapshot().messages[batch]!.jobIds.at(-1)!;
  const fresh = await f.bridge.claim(friday, { messageId: batch });
  await assert.rejects(f.bridge.complete(friday, { messageId: batch, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null }), /stale_receipt_claim/);
  const done = await f.bridge.complete(friday, { messageId: batch, claimId: fresh.claimId, hostedEventId: null, hostedTurnId: null });
  assert.ok(done.ackMessageId); assert.equal((await worker.run(recovery)).attempted, false);
  assert.equal(f.snapshot().jobs[recovery]!.lastError, 'sync_batch_receipt_inactive');
  assert.equal(observed.length, 1); assert.equal(f.snapshot().receipts[item.id]!.state, 'complete');
  await f.bridge.markSyncDispatched([batch]); f.advance(HOUR);
  assert.deepEqual((await f.bridge.flushSync()).dispatch, [], 'a terminal receipt/ACK cannot create another recovery');
  // Independent legacy item holds also fence generation reservation.
  const g = await recoveryFixture(); g.f.set(noon + SYNC_RECEIPT_RECOVERY_MS);
  await g.f.store.transaction(s => { s.receipts[g.item.id] = { state:'claimed', claimId:randomUUID(), owner:friday.principalKey, leaseUntil:g.f.clock()+60000 }; });
  assert.deepEqual((await g.f.bridge.flushSync()).dispatch, []);
  g.f.advance(60000); assert.deepEqual((await g.f.bridge.flushSync()).dispatch, [g.batch]);
  const gid = g.f.snapshot().messages[g.batch]!.jobIds.at(-1)!;
  (g.f.bridge.messagePolicyIds as Record<string,string>).jarvis = 'd'.repeat(64);
  assert.deepEqual((await g.f.bridge.flushSync()).results, [], 'withdrawn source is not re-notified');
  const denied = new DeliveryWorker({ store:g.f.store, enabled:true, clock:g.f.clock, messagePolicyIds:g.f.bridge.messagePolicyIds!,
    accessAllowed:async()=>true, webhookSender:async()=>{ throw Error('must not send'); } });
  assert.equal((await denied.run(gid)).attempted, false);
  const h = await recoveryFixture(); h.f.set(noon + SYNC_RECEIPT_RECOVERY_MS);
  await h.f.bridge.flushSync(); const hid = h.f.snapshot().messages[h.batch]!.jobIds.at(-1)!;
  h.f.set(Date.parse(h.f.snapshot().messages[h.batch]!.envelope.expiresAt!));
  assert.equal((await h.worker.run(hid)).attempted, false, 'an expired batch never gets a recovery send');
  assert.equal(h.observed.length, 1);
});

test('receipt recovery: concurrent ticks and a lost enqueue response preserve one durable generation across restart', async () => {
  const { f, batch } = await recoveryFixture(); f.set(noon + SYNC_RECEIPT_RECOVERY_MS);
  const before = f.snapshot();
  const all = await Promise.all(Array.from({ length: 8 }, () => f.bridge.flushSync()));
  assert.equal(all.flatMap(r => r.results).filter(r => r.outcome === 'receipt_recovery').length, 1);
  assert.ok(all.every(r => r.dispatch.includes(batch)));
  const s = f.snapshot(), ids = s.messages[batch]!.jobIds.filter(id => !before.jobs[id]);
  assert.equal(ids.length, 1); assert.equal(s.syncQueues!.friday!.flushCount, 2);
  // Commit survived the process; its first enqueue failed/response was lost.
  const restarted = new MemoryStore(JSON.parse(JSON.stringify(s)) as BridgeState);
  const bridge = new Bridge({ store:restarted, clock:f.clock, dailyEnabled:true,
    messagePolicyIds:{jarvis:policy,friday:policy}, wakeSync:()=>[] }); // rollback retains existing batches
  assert.deepEqual((await bridge.flushSync()).dispatch, [batch]);
  const failedEnqueue = await reofferOverdueJobs(restarted, () => { throw Error('synthetic enqueue failed'); }, f.clock(), { pendingGraceMs:10*MINUTE });
  assert.equal(failedEnqueue.failed, 1, 'recovery pending jobs do not wait the ordinary dispatch grace again');
  const observed: { eventId:string; messageId:string }[] = [], worker = recoveryWorker(f, observed, restarted);
  f.advance(10 * MINUTE);
  const first = await reofferOverdueJobs(restarted, async id => { await worker.run(id); throw Error('synthetic lost publication response'); }, f.clock());
  assert.equal(first.failed, 1); assert.equal(observed.length, 1);
  assert.deepEqual(await reofferOverdueJobs(restarted, () => { throw Error('accepted work must not be reoffered'); }, f.clock()), { scheduled:0, failed:0, deferred:0 });
  await bridge.markSyncDispatched([batch]);
  assert.deepEqual((await bridge.flushSync()).dispatch, [], 'no immediate new generation after delayed delivery');
  assert.equal(restarted.snapshot().messages[batch]!.syncBatch!.recovery!.generation, 1);
});

for (const afterCommit of [false, true]) test(`receipt recovery: ${afterCommit ? 'lost committed response' : 'failed transaction'} cannot double reserve a generation/day slot`, async () => {
  let armed = false;
  const isRecovery = (value: unknown): boolean => !!value && typeof value === 'object' && 'results' in value && Array.isArray(value.results) &&
    value.results.some((r:unknown) => !!r && typeof r === 'object' && 'outcome' in r && r.outcome === 'receipt_recovery');
  const setup = await recoveryFixture('jarvis', { wrapStore: store => ({ transaction: async fn => {
    const output = await store.transaction(s => { const result = fn(s); if (armed && !afterCommit && isRecovery(result)) { armed=false; throw Error('synthetic commit failure'); } return result; });
    if (armed && afterCommit && isRecovery(output)) { armed=false; throw Error('synthetic lost commit response'); }
    return output;
  } }) });
  const { f, batch } = setup; f.set(noon + SYNC_RECEIPT_RECOVERY_MS); armed = true;
  await assert.rejects(f.bridge.flushSync(), /synthetic/);
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.recovery?.generation ?? 0, afterCommit ? 1 : 0);
  assert.deepEqual((await f.bridge.flushSync()).dispatch, [batch]);
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.recovery!.generation, 1);
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, 2);
});

test('receipt recovery: shared day cap defers without broadening; rollback drains only preexisting batches; v1 remains unchanged', async () => {
  const { f, batch } = await recoveryFixture(); f.set(noon + SYNC_RECEIPT_RECOVERY_MS);
  await f.store.transaction(s => { s.syncQueues!.friday!.flushCount = SYNC_DAILY_FLUSH_CAP; });
  assert.deepEqual((await f.bridge.flushSync()).results, [{ recipient:'friday', outcome:'recovery_daily_cap' }]);
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.recovery, undefined);
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, SYNC_DAILY_FLUSH_CAP);
  // A slot is available (as after reset); rollback does not disable existing receipts.
  await f.store.transaction(s => { s.syncQueues!.friday!.flushCount = SYNC_DAILY_FLUSH_CAP - 1; });
  f.enabled.recipients = [];
  assert.deepEqual((await f.bridge.flushSync()).dispatch, [batch]);
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, SYNC_DAILY_FLUSH_CAP);
  const legacy = await fixture({ wakeSync:false }); const m = legacy.message(); await legacy.send(m);
  await legacy.store.transaction(s => { for(const job of Object.values(s.jobs)) job.state='accepted'; });
  const before = legacy.snapshot(); legacy.advance(SYNC_RECEIPT_RECOVERY_MS);
  assert.deepEqual((await legacy.bridge.flushSync()).dispatch, []);
  assert.deepEqual(legacy.snapshot().jobs, before.jobs, 'ordinary unclassified/flag-OFF v1 has no new recovery path');
});

test('receipt recovery: each generation has one transport attempt; receipt hold appearing during authorization prevents the send', async () => {
  const { f, batch } = await recoveryFixture(); f.set(noon + SYNC_RECEIPT_RECOVERY_MS);
  await f.bridge.flushSync(); const id = f.snapshot().messages[batch]!.jobIds.at(-1)!;
  let sends = 0;
  const failed = new DeliveryWorker({ store:f.store, clock:f.clock, enabled:true, messagePolicyIds:{jarvis:policy,friday:policy},
    accessAllowed:async()=>true, webhookSender:async()=>{ sends++; return {status:503,[DELIVERY_TRANSPORT_OUTCOME]:{terminal:false}}; } });
  await failed.run(id); assert.equal(f.snapshot().jobs[id]!.state, 'dead');
  assert.equal(f.snapshot().jobs[id]!.attempts, 1); assert.equal((await failed.run(id)).attempted, false); assert.equal(sends,1);
  await f.bridge.markSyncDispatched([batch]); f.advance(MINUTE);
  assert.deepEqual((await f.bridge.flushSync()).dispatch, [], 'transport failure does not bypass recovery backoff');
  const g = await recoveryFixture(); g.f.set(noon + SYNC_RECEIPT_RECOVERY_MS); await g.f.bridge.flushSync();
  const gid = g.f.snapshot().messages[g.batch]!.jobIds.at(-1)!;
  const racing = new DeliveryWorker({ store:g.f.store, clock:g.f.clock, enabled:true, messagePolicyIds:{jarvis:policy,friday:policy},
    accessAllowed:async()=>{ await g.f.bridge.read(friday,{messageId:g.batch}); await g.f.bridge.claim(friday,{messageId:g.batch}); return true; },
    webhookSender:async()=>{ throw Error('active receipt must fence this send'); } });
  const result = await racing.run(gid);
  assert.equal(result.transportAccepted, false);
  assert.equal(g.f.snapshot().jobs[gid]!.transportAttempts ?? 0, 0);
  assert.equal(g.f.snapshot().jobs[gid]!.state, 'dead');
});

test('receipt recovery: newly due data takes the last shared wake slot before an old recovery', async () => {
  const { f, batch } = await recoveryFixture();
  f.set(noon + HOUR); const next = f.sync('jarvis', {subject:'new data'}); await f.send(next);
  await f.store.transaction(s => { s.syncQueues!.friday!.flushCount = SYNC_DAILY_FLUSH_CAP - 1; });
  f.set(noon + 2 * HOUR);
  const flushed = await f.bridge.flushSync();
  assert.equal(flushed.dispatch.length, 1); assert.notEqual(flushed.dispatch[0], batch);
  assert.deepEqual(f.snapshot().messages[flushed.dispatch[0]!]!.syncBatch!.itemIds, [next.id]);
  assert.equal(f.snapshot().messages[batch]!.syncBatch!.recovery, undefined);
  assert.equal(f.snapshot().syncQueues!.friday!.flushCount, SYNC_DAILY_FLUSH_CAP);
  assert.equal(flushed.results.at(-1)!.outcome, 'recovery_daily_cap');
});
