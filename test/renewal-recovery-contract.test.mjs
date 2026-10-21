import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import { NativeEvents, EVENT_NAME } from '../src/events.mjs';
import { MemoryStore } from '../src/store.mjs';
import { createProtector } from '../src/webhook.mjs';
import { createMcpHandler } from '../src/mcp.mjs';
import { SCOPES, VERIFIED_AUTHORIZATION, createAccessVerifier } from '../src/policy.mjs';
import { resourceFor, metadataFor } from '../src/resource.mjs';
import { ISSUER } from './fixtures/provider.mjs';

// Offline protocol fixtures: only mock callback verification, no delivery worker,
// production credentials, provider request, automation or native send.
function fixture() {
  let now = Date.parse('2026-10-22T00:00:00Z');
  const clock = () => now, store = new MemoryStore(), policyId = 'd'.repeat(64), calls = [];
  const who = (expiry, owner = 'a'.repeat(64), scope = [SCOPES.jarvis.ack]) =>
    Object.defineProperty({ role: 'jarvis', principalKey: owner, scopes: scope }, VERIFIED_AUTHORIZATION,
      { value: { expiresAt: expiry, policyId } });
  const transport = async (_url, request) => {
    calls.push(request);
    return { status: 200, body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) };
  };
  const protector = createProtector(Buffer.alloc(32, 5));
  const create = initial => new NativeEvents({ store: initial ? new MemoryStore(initial) : store,
    clock, policyId, protector, transport, enabled: true });
  const params = { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, cursor: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/native',
      secret: 'whsec_' + Buffer.alloc(32, 7).toString('base64') } };
  return { clock, store, who, calls, create, events: create(), params, advance: ms => { now += ms; } };
}
const code = expected => error => error.code === expected;

test('expired token-bound lease recovers with later valid authority, same ID and null cursor across restart', async () => {
  const f = fixture(), original = await f.events.subscribe(f.who(f.clock() + 1000), f.params);
  f.advance(1001);
  const restarted = f.create(f.store.snapshot());
  const recovered = await restarted.subscribe(f.who(f.clock() + 60000), f.params);
  assert.equal(recovered.id, original.id);
  assert.deepEqual(Object.keys(recovered), ['id', 'refreshBefore', 'cursor', 'truncated']);
  assert.equal(recovered.cursor, null); assert.equal(recovered.truncated, false);
  assert.equal(Date.parse(recovered.refreshBefore), f.clock() + 60000);
  const status = (await restarted.status(f.who(f.clock() + 60000))).subscriptions[0];
  assert.equal(status.active, true); assert.equal(status.renewalCount, 1);
  assert.equal(Object.keys(restarted.store.snapshot().subscriptions).length, 1);
  assert.deepEqual(restarted.store.snapshot().jobs, {});
});

test('same-expiry policy does not revive an expired shorter grant even while token is still valid', async () => {
  const f = fixture(), principal = f.who(f.clock() + 60000);
  const original = await f.events.subscribe(principal, { ...f.params, ttlMs: 1000 });
  f.advance(1001);
  await assert.rejects(f.events.subscribe(principal, { ...f.params, ttlMs: 60000 }), code('subscription_expired'));
  const recovered = await f.events.subscribe(f.who(f.clock() + 120000), f.params);
  assert.equal(recovered.id, original.id);
});

test('null and omitted cursors preserve no-replay semantics; non-null cursors never become invented history', async () => {
  const f = fixture(), principal = f.who(f.clock() + 60000);
  const { cursor: omitted, ...withoutCursor } = f.params;
  const a = await f.events.subscribe(principal, withoutCursor);
  const b = await f.events.subscribe(principal, f.params);
  assert.equal(a.id, b.id); assert.equal(b.cursor, null);
  for (const cursor of ['history-position', '', 0, false, {}])
    await assert.rejects(f.events.subscribe(principal, { ...f.params, cursor }), code('invalid_params'));
  assert.equal(Object.keys(f.store.snapshot().subscriptions).length, 1);
});

test('draft maxAgeMs is accepted and ignored for null cursor/no-replay without changing identity or deadline', async () => {
  const f = fixture(), principal = f.who(f.clock() + 60000);
  const original = await f.events.subscribe(principal, f.params);
  for (const maxAgeMs of [0, 300000, Number.MAX_SAFE_INTEGER]) {
    const result = await f.events.subscribe(principal, { ...f.params, maxAgeMs });
    assert.deepEqual(result, original);
  }
  for (const maxAgeMs of [-1, 1.5, null, '300000', {}, Infinity, Number.MAX_SAFE_INTEGER + 1])
    await assert.rejects(f.events.subscribe(principal, { ...f.params, maxAgeMs }), code('invalid_params'));
  assert.equal(Object.keys(f.store.snapshot().subscriptions).length, 1);
  assert.deepEqual(f.store.snapshot().jobs, {});
});

test('secret rotation preserves identity; changed callback or owner is a different protocol identity', async () => {
  const f = fixture(), principal = f.who(f.clock() + 60000);
  const a = await f.events.subscribe(principal, f.params);
  const b = await f.events.subscribe(principal, { ...f.params, delivery: { ...f.params.delivery,
    secret: 'whsec_' + Buffer.alloc(32, 8).toString('base64') } });
  assert.equal(a.id, b.id); assert.equal(f.calls.length, 2);
  const normalized = await f.events.subscribe(principal, { ...f.params, delivery: { ...f.params.delivery,
    url: 'https://CALLBACK.example.test:443/native' } });
  assert.equal(normalized.id, a.id);
  const c = await f.events.subscribe(principal, { ...f.params, delivery: { ...f.params.delivery,
    url: 'https://callback.example.test/changed' } });
  const d = await f.events.subscribe(f.who(f.clock() + 60000, 'b'.repeat(64)), f.params);
  assert.notEqual(c.id, a.id); assert.notEqual(d.id, a.id);
  assert.equal(Object.keys(f.store.snapshot().subscriptions).length, 3);
});

test('client-supplied subscription IDs, unknown delivery metadata and changed filters are rejected before observations', async () => {
  const f = fixture(), principal = f.who(f.clock() + 60000);
  const a = await f.events.subscribe(principal, f.params), before = f.store.snapshot();
  for (const params of [{ ...f.params, id: a.id },
    { ...f.params, delivery: { ...f.params.delivery, subscriptionId: a.id } },
    { ...f.params, arguments: { recipient: 'friday' } }])
    await assert.rejects(f.events.subscribe(principal, params), code('invalid_params'));
  assert.deepEqual(f.store.snapshot(), before);
});

test('callback error has the OpenAI integration code/reason; MCP metadata does not alter subscription identity', async () => {
  const f = fixture(), principal = f.who(f.clock() + 60000);
  const handler = createMcpHandler({ enabled: true, verify: async () => principal, bridge: {}, events: f.events,
    scheduleJobs: async () => {}, health: () => ({}) });
  const request = params => new Request(resourceFor('jarvis'), { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 41,
      method: 'events/subscribe', params }) });
  const success = await handler(request({ ...f.params, _meta: { progressToken: 'fixture-context' } }));
  assert.equal(success.status, 200);
  const original = (await success.json()).result;
  f.advance(300001); f.events.transport = async () => ({ status: 200, body: '{}' });
  const failed = await handler(request(f.params)); const failure = await failed.json();
  // Use later valid authority so callback verification is the rejecting fence.
  assert.equal(failure.error.message, 'authorization_lease_required');
  const next = f.who(f.clock() + 60000);
  const callbackHandler = createMcpHandler({ enabled: true, verify: async () => next, bridge: {}, events: f.events,
    scheduleJobs: async () => {}, health: () => ({}) });
  const response = await callbackHandler(request(f.params)), rpc = await response.json();
  assert.equal(response.status, 400); assert.equal(rpc.error.code, -32015);
  assert.deepEqual(rpc.error.data, { reason: 'challenge_failed' });
  assert.equal((await f.events.status(next)).subscriptions[0].id, original.id);
});

test('expired JWT tolerance boundary can return 403 without challenge, while later expiry rejection returns 401 with challenge', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const expiry = 2000000000;
  const token = await new SignJWT({ scope: SCOPES.jarvis.ack }).setProtectedHeader({ alg: 'RS256' })
    .setIssuer(ISSUER).setSubject('fixture-recovery').setAudience(resourceFor('jarvis'))
    .setIssuedAt(expiry - 60).setExpirationTime(expiry).sign(privateKey);
  const f = fixture();
  for (const delta of [0, 1000, 5001]) {
    const when = expiry * 1000 + delta;
    const verify = createAccessVerifier({ issuer: ISSUER, audience: resourceFor('jarvis'),
      subject: 'fixture-recovery', role: 'jarvis', keyResolver: publicKey, currentDate: new Date(when) });
    const events = new NativeEvents({ store: new MemoryStore(), clock: () => when, policyId: 'd'.repeat(64),
      enabled: true, protector: createProtector(Buffer.alloc(32, 5)), transport: async () => assert.fail('no callback') });
    const handler = createMcpHandler({ enabled: true, verify, bridge: {}, events, scheduleJobs: async () => {},
      health: () => ({}), resourceMetadataUrl: metadataFor('jarvis') });
    // Match the actual verified policy rather than inject a caller-selected one.
    if (delta < 5000) {
      const who = await verify(new Request(resourceFor('jarvis'), { headers: { authorization: 'Bearer ' + token } }));
      events.policyId = who[VERIFIED_AUTHORIZATION].policyId;
    }
    const response = await handler(new Request(resourceFor('jarvis'), { method: 'POST', headers: {
      'content-type': 'application/json', authorization: 'Bearer ' + token },
      body: JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'events/subscribe', params: f.params }) }));
    const rpc = await response.json();
    assert.equal(response.status, delta < 5000 ? 403 : 401);
    assert.equal(rpc.error.message, delta < 5000 ? 'authorization_lease_required' : 'unauthorized');
    assert.equal(response.headers.has('www-authenticate'), delta >= 5000);
  }
});
