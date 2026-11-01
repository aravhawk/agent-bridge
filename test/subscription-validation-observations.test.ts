import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStore, PostgresStore } from '../src/store.ts';
import { NativeEvents, EVENT_NAME } from '../src/events.ts';
import { createProtector } from '../src/webhook.ts';
import { BridgeError, SCOPES, VERIFIED_AUTHORIZATION } from '../src/policy.ts';
import { denyResourceAccess } from '../src/access.ts';
import { createMcpHandler } from '../src/mcp.ts';
import { resourceFor, metadataFor } from '../src/resource.ts';
import { OBSERVATION_LIMIT, OBSERVATION_TTL_MS } from '../src/observability.ts';
import type { StorePool } from '../src/store.ts';
import type { McpBridge } from '../src/mcp.ts';
import type { TransportRequest, TransportResponse } from '../src/webhook.ts';
import type { BridgeState, JsonObject, Principal, VerifiedPrincipal } from '../src/types.ts';

interface FakeDatabase { document: BridgeState; writes: number; rollbacks: number; queries: string[]; pool: StorePool }

// Offline mock verification only; no native callback, credential or send.
async function fixture() {
  let now = Date.parse('2026-10-22T00:00:00Z');
  const policyId = 'd'.repeat(64), store = new MemoryStore(), calls: TransportRequest[] = [];
  const principal = (owner = 'a'.repeat(64), scope: string[] = [SCOPES.jarvis!.ack], expiresAt = now + 2 * OBSERVATION_TTL_MS) =>
    Object.defineProperty<Principal>({ role: 'jarvis', principalKey: owner, scopes: scope }, VERIFIED_AUTHORIZATION,
      { value: { policyId, expiresAt } }) as VerifiedPrincipal;
  const who = principal(), params = { name: EVENT_NAME, arguments: { recipient: 'jarvis' },
    delivery: { mode: 'webhook', url: 'https://callback.example.test/PRIVATE_CALLBACK',
      secret: 'whsec_' + Buffer.alloc(32, 7).toString('base64') }, cursor: null };
  const events = new NativeEvents({ store, policyId, clock: () => now, enabled: true,
    protector: createProtector(Buffer.alloc(32, 4)), transport: async (_url, request) => {
      calls.push(request); return { status: 200, body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) } as TransportResponse;
    } });
  const sub = await events.subscribe(who, params);
  return { store, events, principal, who, params, sub, calls, clock: () => now, advance: (ms: number) => { now += ms; } };
}
const invalid = (error: BridgeError) => error.code === 'invalid_params' && error.status === 400;
const malformed = (params: object) => ({ ...params, unexpectedOption: 'PRIVATE_UNTRUSTED_CONTENT' });
const businessState = (snapshot: BridgeState) => {
  const state = structuredClone(snapshot);
  for (const sub of Object.values(state.subscriptions)) delete sub.renewalObservations;
  return state;
};
function database(snapshot: BridgeState) {
  const db = { document: structuredClone(snapshot), writes: 0, rollbacks: 0, queries: [] } as unknown as FakeDatabase; // pool is set next.
  db.pool = { connect: async () => {
    let pending: BridgeState | undefined;
    return { release() {}, query: async (sql: string, params: string[]) => {
      db.queries.push(sql);
      if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(db.document) }] };
      if (sql.startsWith('UPDATE ')) { db.writes++; pending = JSON.parse(params[0]!); }
      if (sql === 'COMMIT' && pending) db.document = pending;
      if (sql === 'ROLLBACK') { db.rollbacks++; pending = undefined; }
      return {};
    } };
  } } as unknown as StorePool; // A fake pg pool: SELECT/UPDATE/COMMIT/ROLLBACK only.
  return db;
}

test('rejected request for exact owned binding adds only bounded sanitized evidence, no callback or business changes', async () => {
  const f = await fixture(), before = f.store.snapshot();
  await assert.rejects(f.events.subscribe(f.who, malformed(f.params)), invalid);
  const state = f.store.snapshot(), record = state.subscriptions[f.sub.id]!.renewalObservations!.at(-1);
  assert.deepEqual(record, { at: f.clock(), outcome: 'error', code: 'invalid_params', authorityExpiry: 'unknown', refreshBefore: null });
  assert.deepEqual(businessState(state), businessState(before));
  assert.equal(f.calls.length, 1);
  const output = JSON.stringify(record);
  for (const value of ['PRIVATE_', f.params.delivery.url, f.params.delivery.secret, f.who.principalKey])
    assert.equal(output.includes(value), false);
});

test('recognizable invalid delivery metadata, missing secret, non-null cursor and bad maxAgeMs are recorded without acceptance', async () => {
  const f = await fixture(), { secret: ignored, ...withoutSecret } = f.params.delivery;
  for (const params of [{ ...f.params, delivery: { ...f.params.delivery, unexpected: 'PRIVATE_EXTRA' } },
    { ...f.params, delivery: withoutSecret }, { ...f.params, cursor: 'PRIVATE_CURSOR' },
    { ...f.params, maxAgeMs: 'PRIVATE_BAD_AGE' }]) {
    await assert.rejects(f.events.subscribe(f.who, params), invalid);
  }
  const state = f.store.snapshot();
  assert.equal(state.subscriptions[f.sub.id]!.renewalObservations!.length, 5);
  assert.equal(state.subscriptions[f.sub.id]!.renewalCount, 0);
  assert.deepEqual(state.jobs, {}); assert.equal(f.calls.length, 1);
});

test('unknown callback/owner binding rolls back without UPDATE or new subscription', async () => {
  const f = await fixture(), before = f.store.snapshot(), db = database(before);
  f.events.store = new PostgresStore(db.pool);
  await assert.rejects(f.events.subscribe(f.who, malformed({ ...f.params,
    delivery: { ...f.params.delivery, url: 'https://callback.example.test/other' } })), invalid);
  await assert.rejects(f.events.subscribe(f.principal('b'.repeat(64)), malformed(f.params)), invalid);
  assert.equal(db.writes, 0); assert.equal(db.rollbacks, 2);
  assert.deepEqual(db.document, before);
});

test('wrong scope, expired authority, malformed callback and unknown filters never reach the observation store', async () => {
  const f = await fixture(), db = database(f.store.snapshot()); f.events.store = new PostgresStore(db.pool);
  await assert.rejects(f.events.subscribe(f.principal(undefined, []), malformed(f.params)), (error: BridgeError) => error.code === 'insufficient_scope');
  const wrongRole = { ...f.who, role: 'friday', scopes: [SCOPES.friday!.ack] };
  await assert.rejects(f.events.subscribe(wrongRole, malformed(f.params)), (error: BridgeError) => error.code === 'insufficient_scope');
  await assert.rejects(f.events.subscribe(f.principal(undefined, undefined, f.clock()), malformed(f.params)), invalid);
  for (const params of [malformed({ ...f.params, delivery: { ...f.params.delivery, url: 'http://private.invalid/path' } }),
    malformed({ ...f.params, arguments: { recipient: 'jarvis', unknownFilter: true } }),
    malformed({ ...f.params, arguments: { recipient: 'friday' } }), malformed({ ...f.params, name: 'unknown.event' })])
    await assert.rejects(f.events.subscribe(f.who, params), invalid);
  assert.deepEqual(db.queries, []); assert.equal(db.writes, 0);
});

test('MCP pre-authentication failure produces no subscription-storage access', async () => {
  const f = await fixture(), db = database(f.store.snapshot()); f.events.store = new PostgresStore(db.pool);
  const handler = createMcpHandler({ enabled: true, verify: async () => { throw new BridgeError('unauthorized', 401); },
    bridge: {} as McpBridge, events: f.events, scheduleJobs: async () => {}, resourceMetadataUrl: metadataFor('jarvis') });
  const response = await handler(new Request(resourceFor('jarvis'), { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'events/subscribe', params: malformed(f.params) }) }));
  assert.equal(response.status, 401); assert.equal(response.headers.has('www-authenticate'), true);
  assert.deepEqual(db.queries, []);
});

test('observation storage/clock failure preserves original validation error and never retries', async () => {
  const f = await fixture(); let transactions = 0;
  f.events.store = { transaction: async () => { transactions++; throw new Error('PRIVATE_STORAGE_FAILURE'); } };
  await assert.rejects(f.events.subscribe(f.who, malformed(f.params)), invalid);
  assert.equal(transactions, 1);
  f.events.clock = () => { throw new Error('PRIVATE_CLOCK_FAILURE'); };
  await assert.rejects(f.events.subscribe(f.who, malformed(f.params)), invalid);
  assert.equal(transactions, 1); assert.equal(f.calls.length, 1);
});

test('concurrent validation observations stay bounded, survive restart and age out lazily', async () => {
  const f = await fixture();
  await Promise.all(Array.from({ length: 20 }, () => assert.rejects(f.events.subscribe(f.who, malformed(f.params)), invalid)));
  const saved = f.store.snapshot(); assert.equal(saved.subscriptions[f.sub.id]!.renewalObservations!.length, OBSERVATION_LIMIT);
  const restored = new MemoryStore(saved); f.events.store = restored;
  assert.equal((await f.events.status(f.who)).subscriptions[0]!.renewalObservations.length, OBSERVATION_LIMIT);
  f.advance(OBSERVATION_TTL_MS);
  assert.deepEqual((await f.events.status(f.who)).subscriptions[0]!.renewalObservations, []);
  assert.equal(f.calls.length, 1);
});

test('recording cannot reopen denied, unsubscribed or expired business state, or touch spent diagnostic evidence', async () => {
  for (const mode of ['denied', 'unsubscribed', 'expired']) {
    const f = await fixture();
    if (mode === 'denied') await denyResourceAccess(f.store, f.who.principalKey, f.clock());
    if (mode === 'unsubscribed') {
      const { secret: ignored, ...delivery } = f.params.delivery;
      await f.events.unsubscribe(f.who, { name: EVENT_NAME, arguments: f.params.arguments, delivery });
    }
    if (mode === 'expired') await f.store.transaction(s => { s.subscriptions[f.sub.id]!.expiresAt = f.clock(); });
    await f.store.transaction(s => { s.fridayWebhookDiagnostic = { messageId: '00000000-0000-4000-8000-000000000001', outcome: null }; });
    const before = businessState(f.store.snapshot());
    await assert.rejects(f.events.subscribe(f.who, malformed(f.params)), invalid);
    assert.deepEqual(businessState(f.store.snapshot()), before);
    assert.equal((await f.events.status(f.who)).subscriptions[0]!.active, false);
    assert.deepEqual(f.store.snapshot().jobs, {}); assert.equal(f.calls.length, 1);
  }
});
