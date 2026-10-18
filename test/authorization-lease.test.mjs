import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { NativeEvents, EVENT_NAME } from '../src/events.mjs';
import { MemoryStore } from '../src/store.mjs';
import { Bridge } from '../src/bridge.mjs';
import { DeliveryWorker } from '../src/worker.mjs';
import { createProtector } from '../src/webhook.mjs';
import { VERIFIED_AUTHORIZATION, createAccessVerifier } from '../src/policy.mjs';
import { denyResourceAccess, subscriptionAccessAllowed } from '../src/access.mjs';
import { ISSUER, resourceFor } from '../src/resource.mjs';

function fixture() {
  let time = 1000000;
  const clock = () => time, policyId = 'd'.repeat(64), owner = 'a'.repeat(64);
  const principal = expiresAt => Object.defineProperty({ role: 'jarvis', principalKey: owner, scopes: ['bridge:ack:jarvis'] },
    VERIFIED_AUTHORIZATION, { value: { policyId, expiresAt } });
  const store = new MemoryStore(), calls = [], protector = createProtector(randomBytes(32));
  const transport = async (_url, req) => { calls.push(req); const body = JSON.parse(req.body);
    return { status: 202, body: body.type === 'verification' ? JSON.stringify({ challenge: body.challenge }) : '' }; };
  const events = new NativeEvents({ store, protector, transport, policyId, clock, enabled: true });
  const secret = 'whsec_' + randomBytes(32).toString('base64');
  const params = { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/lease', secret } };
  const tokenExpiry = time + 3600000;
  const who = principal(tokenExpiry), bridge = new Bridge({ store, clock });
  const subscribe = (p = who, extra = {}) => events.subscribe(p, { ...params, ...extra });
  const queue = async () => bridge.send({ role: 'friday', principalKey: 'b'.repeat(64), scopes: ['bridge:send:jarvis'] },
    { id: randomUUID(), testId: 'RN-JARVIS-FRIDAY-SYNTHETIC', from: 'friday', to: 'jarvis', kind: 'probe',
      sentAt: new Date(clock()).toISOString(), marker: 'RN-SYNTHETIC-NO-ACTIONS' });
  return { clock, policyId, owner, principal, who, tokenExpiry, store, calls, protector, transport, events, params,
    subscribe, queue, advance: ms => { time += ms; } };
}
const error = code => e => e.code === code;
test('requested/default/maximum lifetimes and token expiry cap every finite lease without a minimum clamp', async () => {
  for (const [ttlMs, duration] of [[undefined, 86400000], [null, 7 * 86400000], [10, 10], [20 * 86400000, 7 * 86400000]]) {
    const f = fixture(), expiry = f.clock() + 30 * 86400000;
    const result = await f.subscribe(f.principal(expiry), { ttlMs });
    assert.equal(Date.parse(result.refreshBefore), f.clock() + duration);
  }
  const f = fixture();
  const result = await f.subscribe(f.principal(f.clock() + 5));
  assert.equal(Date.parse(result.refreshBefore), f.clock() + 5);
  for (const ttlMs of [0, -1, 1.5, Infinity]) await assert.rejects(f.subscribe(f.who, { ttlMs }), error('invalid_params'));
});
test('same-expiry token cannot extend a lease; only later verified expiry permits extension across restarts', async () => {
  const f = fixture(), first = await f.subscribe(f.who, { ttlMs: 500 });
  f.advance(100);
  assert.equal((await f.subscribe(f.who, { ttlMs: 1000 })).refreshBefore, first.refreshBefore);
  const later = f.principal(f.tokenExpiry + 1000), next = await f.subscribe(later, { ttlMs: 1000 });
  assert.equal(Date.parse(next.refreshBefore), f.clock() + 1000);
  await assert.rejects(f.subscribe(f.who), error('stale_authorization'));
  const restarted = new NativeEvents({ ...f, store: new MemoryStore(f.store.snapshot()), enabled: true });
  assert.equal((await restarted.subscribe(later, { ...f.params, ttlMs: 10000 })).refreshBefore, next.refreshBefore);
  f.advance(1001);
  await assert.rejects(restarted.subscribe(later, f.params), error('subscription_expired'));
});
test('durable owner/resource denial survives restart, new tokens, new callbacks and renewal attempts', async () => {
  const f = fixture(); await f.subscribe(); await denyResourceAccess(f.store, f.owner, f.clock());
  const store = new MemoryStore(f.store.snapshot()), events = new NativeEvents({ ...f, store, enabled: true });
  for (const url of [f.params.delivery.url, 'https://callback.example.test/another'])
    await assert.rejects(events.subscribe(f.principal(f.tokenExpiry + 60000), { ...f.params,
      delivery: { ...f.params.delivery, url } }), error('access_revoked'));
  assert.equal(f.calls.length, 1); assert.equal(store.snapshot().resourceDenials[f.owner].status, 'denied');
});
test('expired queued jobs stop before any callback, even with an allow-true supplemental adapter', async () => {
  const f = fixture(); await f.subscribe(f.principal(f.clock() + 100)); const q = await f.queue(); f.advance(101);
  const result = await new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => true }).run(q.jobIds[0]);
  assert.equal(result.attempted, false); assert.equal(f.calls.length, 1);
  assert.equal(f.store.snapshot().jobs[q.jobIds[0]].state, 'dead');
});
test('changed runtime policy and mismatched queued recipient cannot reuse a valid saved lease', async () => {
  for (const mode of ['policy', 'recipient']) {
    const f = fixture(); await f.subscribe(); const q = await f.queue();
    if (mode === 'recipient') await f.store.transaction(s => { s.jobs[q.jobIds[0]].recipient = 'friday'; });
    const worker = new DeliveryWorker({ ...f, policyId: mode === 'policy' ? 'e'.repeat(64) : f.policyId,
      enabled: true, accessAllowed: async () => true });
    assert.equal((await worker.run(q.jobIds[0])).attempted, false); assert.equal(f.calls.length, 1);
  }
});
test('unsubscribe is immediate/idempotent and a fresh-token renewal cannot reactivate its tombstone', async () => {
  const f = fixture(), sub = await f.subscribe(), q = await f.queue();
  const { secret: ignored, ...delivery } = f.params.delivery;
  const params = { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, delivery };
  await f.events.unsubscribe(f.who, params); await f.events.unsubscribe(f.who, params);
  assert.equal(f.store.snapshot().subscriptions[sub.id].status, 'unsubscribed');
  await assert.rejects(f.subscribe(f.principal(f.tokenExpiry + 1000)), error('subscription_inactive'));
  await new DeliveryWorker({ ...f, enabled: true }).run(q.jobIds[0]); assert.equal(f.calls.length, 1);
});
test('callback crossing token expiry cannot commit even when verification succeeded', async () => {
  const f = fixture(); f.events.transport = async (_url, req) => {
    f.advance(11); return { status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }; };
  await assert.rejects(f.subscribe(f.principal(f.clock() + 10)), error('authorization_lease_required'));
  assert.deepEqual(f.store.snapshot().subscriptions, {});
});
test('denial during callback challenge is rechecked before committing a subscription', async () => {
  const f = fixture(); f.events.transport = async (_url, req) => {
    await denyResourceAccess(f.store, f.owner, f.clock());
    return { status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }; };
  await assert.rejects(f.subscribe(), error('access_revoked')); assert.deepEqual(f.store.snapshot().subscriptions, {});
});
test('unsubscribe racing initial callback verification leaves a durable tombstone, never an active subscription', async () => {
  const f = fixture(); f.events.transport = async (_url, req) => {
    const { secret: ignored, ...delivery } = f.params.delivery;
    await f.events.unsubscribe(f.who, { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, delivery });
    return { status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }; };
  await assert.rejects(f.subscribe(), error('authorization_lease_required'));
  assert.equal(Object.values(f.store.snapshot().subscriptions)[0].active, false);
});
test('legacy/malformed ownership, scope, recipient, status and pinned-policy metadata fail closed', async () => {
  const f = fixture(), sub = await f.subscribe(), original = f.store.snapshot().subscriptions[sub.id];
  const q = await f.queue();
  for (const mutate of [s => { delete s.authorization; }, s => { s.expiresAt = null; },
    s => { s.owner = 'b'.repeat(64); }, s => { s.recipient = 'friday'; }, s => { s.status = 'denied'; },
    s => { s.authorization.scope = 'profile'; }, s => { s.authorization.resource = resourceFor('friday'); },
    s => { s.authorization.policyId = 'c'.repeat(64); }, s => { s.expiresAt = s.authorization.tokenExpiresAt + 1; }]) {
    const s = structuredClone(original); mutate(s);
    assert.equal(subscriptionAccessAllowed({ resourceDenials: {} }, s, f.policyId, f.clock()), false);
  }
  await f.store.transaction(s => { delete s.subscriptions[sub.id].authorization; });
  await assert.rejects(f.subscribe(f.principal(f.tokenExpiry + 1000)), error('authorization_lease_required'));
  await new DeliveryWorker({ ...f, enabled: true }).run(q.jobIds[0]);
  assert.equal(f.calls.length, 1); assert.equal(f.store.snapshot().jobs[q.jobIds[0]].state, 'dead');
});
test('expiry and denial after asynchronous access checks stop delivery before the socket is used', async () => {
  for (const mode of ['expiry', 'deny']) {
    const f = fixture(); await f.subscribe(f.principal(f.clock() + 1000)); const q = await f.queue();
    const worker = new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => {
      if (mode === 'expiry') f.advance(1001); else await denyResourceAccess(f.store, f.owner, f.clock()); return true; } });
    const result = await worker.run(q.jobIds[0]); assert.equal(result.transportAccepted, false); assert.equal(f.calls.length, 1);
  }
});
test('final worker fence rejects acceptance after in-flight expiry or revocation', async () => {
  for (const mode of ['expiry', 'deny', 'lease']) {
    const f = fixture(); await f.subscribe(f.principal(f.clock() + 1000)); const q = await f.queue();
    const worker = new DeliveryWorker({ ...f, enabled: true, transport: async () => {
      if (mode === 'deny') await denyResourceAccess(f.store, f.owner, f.clock()); else f.advance(mode === 'lease' ? 30001 : 1001);
      return { status: 202, body: '' }; } });
    const result = await worker.run(q.jobIds[0]); assert.equal(result.transportAccepted, false);
    assert.notEqual(f.store.snapshot().jobs[q.jobIds[0]].state, 'accepted');
  }
});
test('JWT verification tolerance does not extend the hard subscription expiry or leak tokens into principal JSON', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const token = await new SignJWT({ scope: 'bridge:ack:jarvis' }).setProtectedHeader({ alg: 'RS256' })
    .setIssuer(ISSUER).setAudience(resourceFor('jarvis')).setSubject('fixture-lease-subject')
    .setIssuedAt(990).setExpirationTime(999).sign(privateKey);
  const who = await createAccessVerifier({ issuer: ISSUER, audience: resourceFor('jarvis'), subject: 'fixture-lease-subject',
    role: 'jarvis', keyResolver: publicKey, currentDate: new Date(1000000) })(new Request(resourceFor('jarvis'),
    { headers: { authorization: 'Bearer ' + token } }));
  assert.equal(who[VERIFIED_AUTHORIZATION].expiresAt, 999000);
  assert.equal(JSON.stringify(who).includes(token), false); assert.equal(JSON.stringify(who).includes('expiresAt'), false);
  const f = fixture(); f.events.policyId = who[VERIFIED_AUTHORIZATION].policyId;
  await assert.rejects(f.subscribe(who), error('authorization_lease_required')); assert.equal(f.calls.length, 0);
});
