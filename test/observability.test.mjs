import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { MemoryStore } from '../src/store.mjs';
import { NativeEvents, EVENT_NAME } from '../src/events.mjs';
import { Bridge } from '../src/bridge.mjs';
import { BridgeError, SCOPES, VERIFIED_AUTHORIZATION } from '../src/policy.mjs';
import { createProtector } from '../src/webhook.mjs';
import { createFridayDiagnostic } from '../src/friday-diagnostic.mjs';
import { denyResourceAccess } from '../src/access.mjs';
import { OBSERVATION_LIMIT, OBSERVATION_TTL_MS, DIAGNOSTIC_READ_WINDOW_MS } from '../src/observability.mjs';

const fail = code => error => error.code === code;
function fixture() {
  let now = Date.parse('2026-10-22T00:00:00Z');
  const clock = () => now, store = new MemoryStore(), policy = 'd'.repeat(64), posts = [];
  const principal = (role, owner = role === 'jarvis' ? 'a'.repeat(64) : 'b'.repeat(64),
    expiry = now + 7200000, scopes = Object.values(SCOPES[role])) =>
    Object.defineProperty({ role, principalKey: owner, scopes }, VERIFIED_AUTHORIZATION, { value: { policyId: policy, expiresAt: expiry } });
  const jarvis = principal('jarvis'), friday = principal('friday');
  const events = new NativeEvents({ store, clock, policyId: policy, enabled: true,
    protector: createProtector(Buffer.alloc(32, 4)), transport: async (_url, request) => ({
      status: 200, body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) }) });
  const params = { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/PRIVATE_CALLBACK_URL',
      secret: 'whsec_' + Buffer.alloc(32, 8).toString('base64') } };
  const bridge = new Bridge({ store, clock });
  const diagnosticOptions = { store, clock, endpoint: 'https://receiver.example.test/PRIVATE_RECEIVER_URL',
    secret: 'PRIVATE_RECEIVER_KEY', from: new Date(now).toISOString(), until: new Date(now + 3600000).toISOString(),
    transport: async (_url, request) => { posts.push(request); return { status: 200, body: 'PRIVATE_RESPONSE_BODY' }; } };
  return { store, clock, principal, jarvis, friday, events, params, bridge, posts, diagnosticOptions,
    advance: ms => { now += ms; }, diagnostic: createFridayDiagnostic(diagnosticOptions),
    status: async (who = jarvis) => (await events.status(who)).subscriptions[0] };
}

test('renewal results survive operation rollback, distinguish authority relations, and preserve successful counters', async () => {
  const f = fixture(), first = await f.events.subscribe(f.jarvis, f.params);
  f.advance(1); await f.events.subscribe(f.jarvis, f.params);
  f.advance(1); await f.events.subscribe(f.principal('jarvis', undefined, f.clock() + 8000000), f.params);
  const before = await f.status(); f.advance(300001);
  f.events.transport = async () => { throw Object.assign(new Error('PRIVATE_CALLBACK_ERROR'), { code: 'callback_timeout' }); };
  await assert.rejects(f.events.subscribe(f.principal('jarvis', undefined, f.clock() + 9000000), f.params), fail('callback_endpoint_error'));
  const after = await f.status();
  assert.equal(after.id, first.id); assert.equal(after.renewalCount, 2);
  assert.equal(after.lastSubscribedAt, before.lastSubscribedAt); assert.equal(after.refreshBefore, before.refreshBefore);
  assert.deepEqual(after.renewalObservations.map(r => r.authorityExpiry), ['new', 'same', 'later', 'later']);
  assert.deepEqual(after.renewalObservations.at(-1), { at: new Date(f.clock()).toISOString(), outcome: 'error',
    code: 'callback_endpoint_error', reason: 'timeout', authorityExpiry: 'later', refreshBefore: null });
  assert.equal(after.inactiveReason, null);
});

test('inactive reasons and recorded failures do not reopen expired, denied, or unsubscribed authority', async () => {
  for (const mode of ['expired', 'denied', 'unsubscribed']) {
    const f = fixture(); await f.events.subscribe(f.jarvis, f.params);
    if (mode === 'expired') f.advance(7200000);
    if (mode === 'denied') await denyResourceAccess(f.store, f.jarvis.principalKey, f.clock());
    if (mode === 'unsubscribed') {
      const { secret: ignored, ...delivery } = f.params.delivery;
      await f.events.unsubscribe(f.jarvis, { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, delivery });
    }
    const expected = { expired: 'authorization_lease_required', denied: 'access_revoked', unsubscribed: 'subscription_inactive' }[mode];
    await assert.rejects(f.events.subscribe(mode === 'expired' ? f.jarvis : f.principal('jarvis'), f.params), fail(expected));
    const status = await f.status(); assert.equal(status.active, false); assert.equal(status.inactiveReason, mode);
    assert.equal(status.renewalCount, 0); assert.equal(status.renewalObservations.at(-1).code, expected);
    assert.deepEqual(f.store.snapshot().jobs, {});
  }
});

test('renewal history is count bounded across concurrent calls, restart durable, and lazily age pruned', async () => {
  const f = fixture(); await f.events.subscribe(f.jarvis, f.params);
  await Promise.all(Array.from({ length: 20 }, () => f.events.subscribe(f.jarvis, f.params)));
  const status = await f.status(); assert.equal(status.renewalCount, 20);
  assert.equal(status.renewalObservations.length, OBSERVATION_LIMIT);
  const restored = new NativeEvents({ store: new MemoryStore(f.store.snapshot()), clock: f.clock, policyId: 'd'.repeat(64) });
  assert.deepEqual((await restored.status(f.jarvis)).subscriptions[0].renewalObservations, status.renewalObservations);
  f.advance(OBSERVATION_TTL_MS);
  assert.deepEqual((await f.status()).renewalObservations, []);
  assert.deepEqual(Object.values(f.store.snapshot().subscriptions)[0].renewalObservations, []);
});

test('wrong callers or unknown subscription identities cannot create an observation bucket; stored projections exclude sensitive fields', async () => {
  const f = fixture(), sub = await f.events.subscribe(f.jarvis, f.params);
  const before = f.store.snapshot();
  await assert.rejects(f.events.subscribe(f.friday, f.params), fail('insufficient_scope'));
  await assert.rejects(f.events.subscribe(f.principal('jarvis', undefined, undefined, []), f.params), fail('insufficient_scope'));
  assert.deepEqual(f.store.snapshot(), before);
  const other = f.principal('jarvis', 'c'.repeat(64));
  assert.deepEqual((await f.events.status(other)).subscriptions, []);
  f.events.transport = async () => { throw new Error('PRIVATE_INITIAL_ERROR'); };
  await assert.rejects(f.events.subscribe(other, f.params), fail('callback_endpoint_error'));
  assert.equal(Object.keys(f.store.snapshot().subscriptions).length, 1);
  await f.store.transaction(s => {
    s.subscriptions[sub.id].renewalObservations[0].payload = 'PRIVATE_MESSAGE_TEXT';
    s.subscriptions[sub.id].renewalObservations.push({ at: f.clock(), outcome: 'error',
      code: 'PRIVATE_UNTRUSTED_ERROR', authorityExpiry: 'same', refreshBefore: null });
  });
  const publicStatus = JSON.stringify(await f.status());
  for (const value of ['PRIVATE_', f.params.delivery.url, f.params.delivery.secret, f.jarvis.principalKey])
    assert.equal(publicStatus.includes(value), false, value);
  assert.equal(publicStatus.includes('PRIVATE_UNTRUSTED_ERROR'), false);
  assert.equal(JSON.stringify(f.store.snapshot().subscriptions[sub.id].renewalObservations).includes('PRIVATE_'), false);
});

test('recording storage failure cannot replace subscription success or the original callback error', async () => {
  const f = fixture(), transaction = f.store.transaction.bind(f.store); let calls = 0;
  f.events.store = { transaction: operation => ++calls === 3 ? Promise.reject(new Error('PRIVATE_OBSERVER_FAILURE')) : transaction(operation) };
  const sub = await f.events.subscribe(f.jarvis, f.params);
  assert.equal(f.store.snapshot().subscriptions[sub.id].active, true);
  assert.equal(f.store.snapshot().subscriptions[sub.id].renewalObservations, undefined);
  f.advance(300001); calls = 0;
  f.events.store = { transaction: operation => ++calls === 2 ? Promise.reject(new Error('PRIVATE_OBSERVER_FAILURE')) : transaction(operation) };
  f.events.transport = async () => { throw Object.assign(new Error('PRIVATE_TRANSPORT_FAILURE'), { code: 'callback_timeout' }); };
  await assert.rejects(f.events.subscribe(f.jarvis, f.params), e => e.code === 'callback_endpoint_error' && e.reason === 'timeout');
  assert.equal(f.store.snapshot().subscriptions[sub.id].renewalCount, 0);
});

test('even falsy operation rejections remain failures in evidence and preserve the original rejection', async () => {
  for (const rejection of [null, undefined, false, 0, '']) {
    const f = fixture(); await f.events.subscribe(f.jarvis, f.params);
    f.events.protector = { ...f.events.protector, seal() { throw rejection; } };
    await assert.rejects(f.events.subscribe(f.jarvis, f.params), error => error === rejection);
    const observed = (await f.status()).renewalObservations.at(-1);
    assert.equal(observed.outcome, 'error'); assert.equal(observed.code, 'bridge_unavailable');
    assert.equal((await f.status()).renewalCount, 0);
  }
});

test('a failed diagnostic read is recorded outside rollback without a stored message, receipt, job, or new transport', async () => {
  const f = fixture(), attempt = await f.diagnostic(f.jarvis), marker = f.store.snapshot().fridayWebhookDiagnostic;
  await assert.rejects(f.bridge.read(f.friday, { messageId: attempt.messageId }), fail('message_not_found'));
  const status = await f.bridge.status(f.friday, { messageId: attempt.messageId });
  assert.equal(status.messageStored, false); assert.equal(status.wakeVerified, false);
  assert.equal(status.readObservations[0].code, 'message_not_found');
  assert.equal(status.evidenceStatus, 'server_read_result_only_not_native_wake');
  assert.deepEqual(await f.bridge.status(f.jarvis, { messageId: attempt.messageId }), status);
  const state = f.store.snapshot(); assert.deepEqual(state.fridayWebhookDiagnostic, marker);
  for (const key of ['messages', 'receipts', 'jobs']) assert.deepEqual(state[key], {});
  assert.equal(f.posts.length, 1); assert.equal((await f.diagnostic(f.jarvis)).duplicate, true); assert.equal(f.posts.length, 1);
  for (const value of ['PRIVATE_', f.friday.principalKey, f.jarvis.principalKey, 'authorization', 'secret'])
    assert.equal(JSON.stringify(status).includes(value), false, value);
});

test('successful diagnostic read preserves its return value without retaining any source content or changing ordinary status', async () => {
  const f = fixture(), attempt = await f.diagnostic(f.jarvis);
  const envelope = { id: attempt.messageId, from: 'jarvis', to: 'friday', kind: 'probe', text: 'PRIVATE_MESSAGE_TEXT' };
  await f.store.transaction(s => { s.messages[attempt.messageId] = { envelope, storedAt: f.clock(), jobIds: [] }; });
  const read = await f.bridge.read(f.friday, { messageId: attempt.messageId });
  assert.deepEqual(read, { envelope, receivedAt: new Date(f.clock()).toISOString() });
  assert.equal(f.store.snapshot().diagnosticReadObservations.records[0].code, 'ok');
  assert.equal(JSON.stringify(f.store.snapshot().diagnosticReadObservations).includes('PRIVATE_'), false);
  const status = await f.bridge.status(f.friday, { messageId: attempt.messageId });
  assert.equal(status.receiptCompleted, false); assert.equal('messageStored' in status, false);
});

test('diagnostic traces require exact UUID, reader role/scope/owner and original recording window', async () => {
  const f = fixture(), attempt = await f.diagnostic(f.jarvis);
  for (const who of [f.jarvis, f.principal('friday', undefined, undefined, [])])
    await assert.rejects(f.bridge.read(who, { messageId: attempt.messageId }));
  await assert.rejects(f.bridge.read(f.friday, { messageId: randomUUID() }), fail('message_not_found'));
  assert.equal(f.store.snapshot().diagnosticReadObservations, undefined);
  await assert.rejects(f.bridge.read(f.friday, { messageId: attempt.messageId }), fail('message_not_found'));
  for (const who of [f.principal('jarvis', 'c'.repeat(64)), f.principal('friday', 'c'.repeat(64)),
    f.principal('jarvis', undefined, undefined, [SCOPES.jarvis.probe])])
    await assert.rejects(f.bridge.status(who, { messageId: attempt.messageId }), fail('message_not_found'));
  f.advance(DIAGNOSTIC_READ_WINDOW_MS);
  const previous = f.store.snapshot().diagnosticReadObservations;
  await assert.rejects(f.bridge.read(f.friday, { messageId: attempt.messageId }), fail('message_not_found'));
  assert.deepEqual(f.store.snapshot().diagnosticReadObservations, previous);
});

test('legacy ownerless marker is never backfilled or reset and gives no new Jarvis status access', async () => {
  const f = fixture(), attempt = await f.diagnostic(f.jarvis);
  await f.store.transaction(s => { delete s.fridayWebhookDiagnostic.owner; });
  const marker = f.store.snapshot().fridayWebhookDiagnostic;
  await assert.rejects(f.bridge.read(f.friday, { messageId: attempt.messageId }), fail('message_not_found'));
  await assert.rejects(f.bridge.status(f.jarvis, { messageId: attempt.messageId }), fail('message_not_found'));
  assert.equal((await f.bridge.status(f.friday, { messageId: attempt.messageId })).readObservations.length, 1);
  f.advance(OBSERVATION_TTL_MS);
  await assert.rejects(f.bridge.status(f.friday, { messageId: attempt.messageId }), fail('message_not_found'));
  // The read-status transaction rolls back on not-found; the projection still
  // never returns stale records. An owning operator can persist lazy pruning.
  assert.deepEqual(f.store.snapshot().fridayWebhookDiagnostic, marker);
  assert.equal((await createFridayDiagnostic({ ...f.diagnosticOptions,
    from: new Date(f.clock()).toISOString(), until: new Date(f.clock() + 60000).toISOString() })(f.jarvis)).duplicate, true);
  assert.equal(f.posts.length, 1);
});

test('diagnostic history is count bounded, UUID bound, sanitized and restart durable', async () => {
  const f = fixture(), attempt = await f.diagnostic(f.jarvis);
  await Promise.all(Array.from({ length: 15 }, () => assert.rejects(f.bridge.read(f.friday, { messageId: attempt.messageId }), fail('message_not_found'))));
  const before = await f.bridge.status(f.jarvis, { messageId: attempt.messageId });
  assert.equal(before.readObservations.length, OBSERVATION_LIMIT);
  const restart = new Bridge({ store: new MemoryStore(f.store.snapshot()), clock: f.clock });
  assert.deepEqual(await restart.status(f.jarvis, { messageId: attempt.messageId }), before);
  await f.store.transaction(s => {
    s.diagnosticReadObservations.records[0].payload = 'PRIVATE_TEXT';
    s.diagnosticReadObservations.records[0].reason = 'PRIVATE_REASON';
  });
  assert.equal(JSON.stringify(await f.bridge.status(f.jarvis, { messageId: attempt.messageId })).includes('PRIVATE_'), false);
  await f.store.transaction(s => { s.diagnosticReadObservations.messageId = randomUUID(); });
  assert.deepEqual((await f.bridge.status(f.jarvis, { messageId: attempt.messageId })).readObservations, []);
  f.advance(OBSERVATION_TTL_MS);
  assert.deepEqual((await f.bridge.status(f.jarvis, { messageId: attempt.messageId })).readObservations, []);
  assert.equal(f.posts.length, 1);
});

test('diagnostic observer storage failure preserves message_not_found and never retries the read or sender', async () => {
  const f = fixture(), attempt = await f.diagnostic(f.jarvis), transaction = f.store.transaction.bind(f.store); let calls = 0;
  f.bridge.store = { transaction: operation => ++calls === 2 ? Promise.reject(new Error('PRIVATE_AUDIT_FAILURE')) : transaction(operation) };
  await assert.rejects(f.bridge.read(f.friday, { messageId: attempt.messageId }), fail('message_not_found'));
  assert.equal(calls, 2); assert.equal(f.store.snapshot().diagnosticReadObservations, undefined);
  assert.equal(f.posts.length, 1); assert.deepEqual(f.store.snapshot().jobs, {});
});
