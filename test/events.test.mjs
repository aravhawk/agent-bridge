import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { Webhook } from 'standardwebhooks';
import { BridgeError, SCOPES, VERIFIED_AUTHORIZATION } from '../src/policy.mjs';
import { MemoryStore, PostgresStore } from '../src/store.mjs';
import { NativeEvents, EVENT_NAME } from '../src/events.mjs';
import { Bridge } from '../src/bridge.mjs';
import { DeliveryWorker, reconcileOutbox } from '../src/worker.mjs';
import { createMcpHandler } from './fixtures/rollback-mcp.mjs';
import { preparePrivatePlugin } from './fixtures/rollback-plugin-draft.mjs';
import { callbackUrl, validSecret, publicAddress, createPublicWebhookTransport, createProtector } from '../src/webhook.mjs';

// All callback domains and identities below are fake. Fake transports never
// perform a network operation. Keys exist only in process and authorize nothing.
const policyId = 'd'.repeat(64);
const principal = role => Object.defineProperty({ role, principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64),
  scopes: Object.values(SCOPES[role]) }, VERIFIED_AUTHORIZATION,
  { value: { policyId, expiresAt: Date.now() + 2 * 86400000 } });
const jarvis = principal('jarvis'), friday = principal('friday');
const now = Date.now();
const secret = () => 'whsec_' + randomBytes(32).toString('base64');
const params = key => ({ name: EVENT_NAME, arguments: { recipient: 'jarvis' },
  delivery: { mode: 'webhook', url: 'https://callback.example.test/native', secret: key }, cursor: null, ttlMs: null });
const probe = (from = 'friday', overrides = {}) => ({ id: randomUUID(), testId: 'RN-JARVIS-FRIDAY-SYNTHETIC',
  from, to: from === 'friday' ? 'jarvis' : 'friday', kind: 'probe', sentAt: new Date(now).toISOString(),
  marker: 'RN-SYNTHETIC-NO-ACTIONS', ...overrides });
const code = name => e => e instanceof BridgeError && e.code === name;
async function fixture({ responseStatus = 202 } = {}) {
  let time = now;
  const clock = () => time;
  const store = new MemoryStore(); const protector = createProtector(randomBytes(32));
  const calls = [];
  const transport = async (url, request) => {
    calls.push({ url, ...request });
    const data = JSON.parse(request.body);
    return { status: data.type === 'verification' ? 200 : responseStatus,
      body: data.type === 'verification' ? JSON.stringify({ challenge: data.challenge }) : '' };
  };
  const events = new NativeEvents({ store, protector, transport, policyId, enabled: true, clock });
  const key = secret(); const subscription = await events.subscribe(jarvis, params(key));
  const bridge = new Bridge({ store, clock, messagePolicyIds: { jarvis: policyId, friday: policyId } });
  return { store, protector, calls, events, key, subscription, bridge, clock, policyId,
    advance: ms => { time += ms; }, transport };
}

test('callback URL and secret inputs reject userinfo, non-HTTPS, literals, ports, fragments and malformed keys', () => {
  for (const url of ['http://public.example/path', 'https://user:secret@public.example/path',
    'https://127.0.0.1/path', 'https://[::1]/path', 'https://public.example:444/path',
    'https://public.example/path#fragment', 'https://public.example./path']) assert.throws(() => callbackUrl(url));
  for (const key of ['', 'not-a-key', 'whsec_' + Buffer.alloc(23).toString('base64'),
    'whsec_' + Buffer.alloc(65).toString('base64'), 'whsec_A===']) assert.throws(() => validSecret(key));
  assert.equal(callbackUrl('https://public.example/path?opaque=value'), 'https://public.example/path?opaque=value');
  assert.ok(validSecret(secret()));
});
test('address classification blocks local/private/reserved and IPv4-mapped private addresses', () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '172.16.1.1', '192.168.0.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '192.0.2.1', '198.18.0.1', '224.0.0.1', '240.0.0.1',
    '::', '::1', 'fe80::1', 'fc00::1', 'ff02::1', '2001:db8::1', '::ffff:127.0.0.1', 'bad']) {
    assert.equal(publicAddress(address), false, address);
  }
  assert.equal(publicAddress('8.8.8.8'), true);
  assert.equal(publicAddress('2606:4700:4700::1111'), true);
});
test('HTTPS transport pins checked DNS, retains TLS hostname, never redirects and rechecks DNS every attempt', async () => {
  let resolveCount = 0; let connections = 0;
  const transport = createPublicWebhookTransport({ enabled: true,
    resolve: async () => ++resolveCount === 1 ? [{ address: '8.8.8.8', family: 4 }] : [{ address: '127.0.0.1', family: 4 }],
    request: (u, options, callback) => {
      connections++;
      assert.equal(u.hostname, 'callback.example.test'); assert.equal(options.servername, u.hostname);
      assert.equal(options.rejectUnauthorized, true); assert.equal(options.agent, false);
      options.lookup(u.hostname, {}, (err, address, family) => {
        assert.equal(err, null); assert.equal(address, '8.8.8.8'); assert.equal(family, 4);
      });
      const req = new EventEmitter(); req.destroy = () => {};
      req.end = () => queueMicrotask(() => { const res = new EventEmitter(); res.statusCode = 302;
        res.destroy = () => {}; callback(res); res.emit('end'); });
      return req;
    } });
  assert.equal((await transport('https://callback.example.test/native', { body: '{}', headers: {} })).status, 302);
  await assert.rejects(transport('https://callback.example.test/native', { body: '{}', headers: {} }), code('callback_address_blocked'));
  assert.equal(connections, 1); assert.equal(resolveCount, 2);
});
test('mixed public/private DNS responses fail before any socket opens', async () => {
  const transport = createPublicWebhookTransport({ enabled: true,
    resolve: async () => [{ address: '8.8.8.8', family: 4 }, { address: '10.0.0.1', family: 4 }],
    request: () => assert.fail('socket must remain closed') });
  await assert.rejects(transport('https://callback.example.test/native', { body: '{}', headers: {} }), code('callback_address_blocked'));
  assert.throws(() => createPublicWebhookTransport(), code('delivery_not_enabled'));
});
test('failed callback verification never activates a subscription and returns categorized MCP error', async () => {
  const store = new MemoryStore();
  const events = new NativeEvents({ store, protector: createProtector(randomBytes(32)), policyId, enabled: true,
    transport: async () => ({ status: 200, body: '{"challenge":"wrong"}' }) });
  await assert.rejects(events.subscribe(jarvis, params(secret())), e => e.rpcCode === -32015 && e.reason === 'challenge_failed');
  assert.deepEqual(store.snapshot().subscriptions, {});
});
test('verified subscription is scoped, deterministic, encrypted and cached; refresh rotates both signing keys', async () => {
  const f = await fixture();
  new Webhook(f.key).verify(f.calls[0].body, f.calls[0].headers);
  const first = await f.events.subscribe(jarvis, params(f.key));
  assert.equal(first.id, f.subscription.id); assert.ok(Date.parse(first.refreshBefore) > now); assert.equal(f.calls.length, 1);
  const replacement = secret();
  const second = await f.events.subscribe(jarvis, params(replacement));
  assert.equal(second.id, first.id); assert.equal(f.calls.length, 2);
  const snapshot = f.store.snapshot();
  assert.equal(JSON.stringify(snapshot).includes(f.key), false);
  assert.equal(JSON.stringify(snapshot).includes('callback.example.test'), false);
  await assert.rejects(f.events.subscribe(friday, params(secret())), code('insufficient_scope'));
  await assert.rejects(f.events.subscribe(jarvis, { ...params(secret()), arguments: { recipient: 'friday' } }), code('invalid_params'));
  const queued = await f.bridge.send(friday, probe());
  const worker = new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => true });
  await worker.run(queued.jobIds[0]);
  const delivery = f.calls.at(-1);
  assert.equal(delivery.headers['webhook-signature'].split(' ').length, 2);
  new Webhook(replacement).verify(delivery.body, delivery.headers);
  new Webhook(f.key).verify(delivery.body, delivery.headers);
});
test('finite TTL is bounded, persistent subscriptions survive restart, explicit unsubscribe is idempotent and owner-bound', async () => {
  const f = await fixture();
  const finite = await f.events.subscribe(jarvis, { ...params(f.key), ttlMs: 120000 });
  assert.equal(Date.parse(finite.refreshBefore), now + 120000);
  await f.events.subscribe(jarvis, params(f.key));
  const restarted = new MemoryStore(f.store.snapshot());
  const events = new NativeEvents({ ...f, store: restarted, enabled: true });
  const other = { ...jarvis, principalKey: 'c'.repeat(64) };
  const { secret: ignored, ...delivery } = params(f.key).delivery;
  const unsub = { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, delivery };
  await events.unsubscribe(other, unsub);
  assert.equal(restarted.snapshot().subscriptions[finite.id].active, true);
  await events.unsubscribe(jarvis, unsub); await events.unsubscribe(jarvis, unsub);
  assert.equal(restarted.snapshot().subscriptions[finite.id].active, false);
});
test('concurrent duplicate sends create one durable message and one immutable event; changed body conflicts', async () => {
  const f = await fixture(); const envelope = probe();
  const results = await Promise.all(Array.from({ length: 8 }, () => f.bridge.send(friday, envelope)));
  assert.equal(results.filter(r => !r.duplicate).length, 1);
  assert.equal(Object.keys(f.store.snapshot().messages).length, 1);
  assert.equal(Object.keys(f.store.snapshot().jobs).length, 1);
  await assert.rejects(f.bridge.send(friday, { ...envelope, sentAt: new Date(now - 1000).toISOString() }), code('message_id_conflict'));
  f.advance(600000);
  assert.equal((await f.bridge.send(friday, envelope)).duplicate, true);
  await assert.rejects(f.bridge.send(friday, probe()), code('stale_or_future_message'));
});
test('retry preserves event/body identity, refreshes signature time and accepts only transport evidence', async () => {
  const f = await fixture({ responseStatus: 503 }); const queued = await f.bridge.send(friday, probe());
  const worker = new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => true });
  const first = await worker.run(queued.jobIds[0]); assert.equal(first.transportAccepted, false); assert.ok(first.retryAt);
  f.advance(2000); await worker.run(queued.jobIds[0]);
  const [a, b] = f.calls.slice(-2);
  assert.equal(a.body, b.body); assert.equal(a.headers['webhook-id'], b.headers['webhook-id']);
  assert.notEqual(a.headers['webhook-timestamp'], b.headers['webhook-timestamp']);
  assert.notEqual(a.headers['webhook-signature'], b.headers['webhook-signature']);
  assert.equal(JSON.parse(a.body).type, undefined);
  assert.deepEqual(Object.keys(JSON.parse(a.body).data), ['messageId']);
});
test('410/413 are terminal, access revocation stops send without deleting persistent subscription, disabled worker sends nothing', async () => {
  for (const responseStatus of [410, 413]) {
    const f = await fixture({ responseStatus }); const queued = await f.bridge.send(friday, probe());
    const worker = new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => true });
    await worker.run(queued.jobIds[0]); f.advance(60000); await worker.run(queued.jobIds[0]);
    assert.equal(f.calls.length, 2); assert.equal(f.store.snapshot().jobs[queued.jobIds[0]].state, 'dead');
  }
  const f = await fixture(); const queued = await f.bridge.send(friday, probe());
  await assert.rejects(new DeliveryWorker(f).run(queued.jobIds[0]), code('delivery_not_enabled'));
  await new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => false }).run(queued.jobIds[0]);
  assert.equal(f.calls.length, 1); assert.equal(f.store.snapshot().subscriptions[f.subscription.id].active, true);
});
test('expiry stops queued delivery, bounded attempts terminate repeated transient errors', async () => {
  const f = await fixture({ responseStatus: 503 });
  await f.events.subscribe(jarvis, { ...params(f.key), ttlMs: 60000 });
  const queued = await f.bridge.send(friday, probe()); f.advance(60001);
  await new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => true }).run(queued.jobIds[0]);
  assert.equal(f.calls.length, 1);
  const g = await fixture({ responseStatus: 503 }); const q = await g.bridge.send(friday, probe());
  const worker = new DeliveryWorker({ ...g, enabled: true, maxAttempts: 3, accessAllowed: async () => true });
  for (let i = 0; i < 5; i++) { await worker.run(q.jobIds[0]); g.advance(60001); }
  assert.equal(g.store.snapshot().jobs[q.jobIds[0]].attempts, 3);
  assert.equal(g.store.snapshot().jobs[q.jobIds[0]].state, 'dead');
});
test('expired worker cannot overwrite accepted state after another worker reclaims its lease', async () => {
  const f = await fixture(); const queued = await f.bridge.send(friday, probe());
  let finish; let started;
  const ready = new Promise(resolve => { started = resolve; });
  const slow = new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => true,
    transport: async () => { started(); return new Promise(resolve => { finish = resolve; }); } });
  const first = slow.run(queued.jobIds[0]); await ready; f.advance(30001);
  const second = await new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => true }).run(queued.jobIds[0]);
  assert.equal(second.transportAccepted, true);
  const accepted = f.store.snapshot().jobs[queued.jobIds[0]];
  assert.equal(accepted.transportAttempts, 1);
  assert.equal(accepted.firstTransportOutcome.workerAttempt, 2);
  assert.equal(accepted.firstTransportOutcome.status, 202);
  finish({ status: 503, body: '' }); assert.equal((await first).committed, false);
  assert.equal(accepted.state, 'accepted');
  assert.deepEqual(f.store.snapshot().jobs[queued.jobIds[0]], accepted);
});
test('receipt claims fence concurrent/expired turns; completion+ACK survives restart and duplicate completion', async () => {
  const f = await fixture(); const q = await f.bridge.send(friday, probe());
  const claims = await Promise.allSettled([f.bridge.claim(jarvis, { messageId: q.messageId }), f.bridge.claim(jarvis, { messageId: q.messageId })]);
  assert.equal(claims.filter(x => x.status === 'fulfilled').length, 1);
  const old = claims.find(x => x.status === 'fulfilled').value;
  f.advance(60001); const fresh = await f.bridge.claim(jarvis, { messageId: q.messageId });
  const evidence = { messageId: q.messageId, hostedEventId: 'evt_fixture', hostedTurnId: 'turn_fixture' };
  await assert.rejects(f.bridge.complete(jarvis, { ...evidence, claimId: old.claimId }), code('stale_receipt_claim'));
  const first = await f.bridge.complete(jarvis, { ...evidence, claimId: fresh.claimId });
  const restarted = new MemoryStore(f.store.snapshot());
  const second = await new Bridge({ store: restarted, clock: f.clock }).complete(jarvis, { ...evidence, claimId: fresh.claimId });
  assert.equal(second.duplicate, true); assert.equal(second.ackMessageId, first.ackMessageId);
  assert.equal(Object.values(restarted.snapshot().messages).filter(x => x.envelope.kind === 'ack').length, 1);
  const status = await f.bridge.status(friday, { messageId: q.messageId });
  assert.equal(status.wakeVerified, false); assert.equal(status.receiptCompleted, true);
  await assert.rejects(f.bridge.read(friday, { messageId: q.messageId }), code('message_not_found'));
});
test('ACK receipt is terminal and does not generate an ACK loop', async () => {
  const f = await fixture(); const q = await f.bridge.send(friday, probe());
  const claim = await f.bridge.claim(jarvis, { messageId: q.messageId });
  const ack = await f.bridge.complete(jarvis, { messageId: q.messageId, claimId: claim.claimId, hostedEventId: 'event1', hostedTurnId: 'turn1' });
  const reverse = await f.bridge.claim(friday, { messageId: ack.ackMessageId });
  const result = await f.bridge.complete(friday, { messageId: ack.ackMessageId, claimId: reverse.claimId, hostedEventId: 'event2', hostedTurnId: 'turn2' });
  assert.equal(result.ackMessageId, null); assert.equal(Object.keys(f.store.snapshot().messages).length, 2);
});
test('backend reconciliation schedules pending IDs without a receiver polling API', async () => {
  const f = await fixture(); await f.bridge.send(friday, probe()); const jobs = [];
  const r = await reconcileOutbox(f.store, async (id, at) => { jobs.push({ id, at }); }, now);
  assert.equal(r.scheduled, 1); assert.equal(jobs.length, 1);
});
test('MCP remains closed until fully configured; auth errors and raw internal errors stay sanitized', async () => {
  const request = () => new Request('https://bridge.example.test/bridge/jarvis/mcp', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"server/discover"}' });
  assert.equal((await createMcpHandler({})(request())).status, 503);
  const f = await fixture();
  const handler = verify => createMcpHandler({ enabled: true, verify, bridge: f.bridge, events: f.events, scheduleJobs: async () => {} });
  const denied = await handler(async () => { throw new BridgeError('unauthorized', 401); })(request());
  assert.equal(denied.status, 401);
  const internal = await handler(async () => { throw Error('DO_NOT_DISCLOSE'); })(request());
  assert.equal((await internal.text()).includes('DO_NOT_DISCLOSE'), false);
});
test('MCP discovery/tools and Event methods share the authenticated endpoint with scoped catalogs and bounded input', async () => {
  const f = await fixture(); const scheduled = [];
  const handler = who => createMcpHandler({ enabled: true, verify: async () => who, bridge: f.bridge, events: f.events,
    scheduleJobs: async ids => { scheduled.push(...ids); } });
  const rpc = async (who, method, params = {}) => {
    const response = await handler(who)(new Request('https://bridge.example.test/bridge/jarvis/mcp', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
    return { status: response.status, ...(await response.json()) };
  };
  const discovery = await rpc(jarvis, 'server/discover'); assert.ok(discovery.result.capabilities.events);
  assert.equal((await rpc(friday, 'server/discover')).result.capabilities.events, undefined);
  assert.equal((await rpc(jarvis, 'events/list')).result.events[0].name, EVENT_NAME);
  assert.equal((await rpc(friday, 'events/list')).status, 403);
  const restricted = { ...jarvis, scopes: [SCOPES.jarvis.ack] };
  assert.equal((await rpc(restricted, 'tools/list')).result.tools.some(t => t.name === 'bridge_send'), false);
  const sent = await rpc(friday, 'tools/call', { name: 'bridge_send', arguments: probe() });
  assert.equal(sent.result.structuredContent.queued, true); assert.equal(scheduled.length, 1);
  assert.equal('jobIds' in sent.result.structuredContent, false);
  const tooBig = await handler(jarvis)(new Request('https://bridge.example.test/mcp', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ padding: 'x'.repeat(40000) }) }));
  assert.equal(tooBig.status, 413);
});
test('optional validation diagnostic reports only allowlisted field shapes after authentication', async () => {
  const f = await fixture(), records = [];
  const make = verify => createMcpHandler({ enabled: true, verify, bridge: f.bridge, events: f.events,
    scheduleJobs: async () => assert.fail('no scheduling'), observeValidationFailure: facts => records.push(facts) });
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'bridge_status',
    arguments: { messageId: '00000000-0000-4000-8000-000000000001' },
    _meta: { progressToken: 'PRIVATE_PROGRESS_VALUE', PRIVATE_FIELD_NAME: 'PRIVATE_FIELD_VALUE' },
    PRIVATE_BUSINESS_FIELD: 'PRIVATE_BUSINESS_VALUE' } };
  const request = () => new Request('https://bridge.example.test/mcp', { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer PRIVATE_TOKEN' }, body: JSON.stringify(body) });
  const denied = await make(async () => { throw new BridgeError('unauthorized', 401); })(request());
  assert.equal(denied.status, 401); assert.equal(records.length, 0);
  const rejected = await make(async () => friday)(request());
  assert.equal(rejected.status, 400); assert.equal((await rejected.json()).error.message, 'invalid_params');
  assert.deepEqual(records[0], { stage: 'tools/call', envelopeKeys: ['jsonrpc', 'id', 'method', 'params'],
    paramsKeys: ['name', 'arguments', '_meta', '[other]'], argumentsKeys: ['messageId'],
    metaKeys: ['progressToken', '[other]'], tool: 'bridge_status', messageIdType: 'string' });
  const logged = JSON.stringify(records);
  for (const privateValue of ['PRIVATE_TOKEN', 'PRIVATE_PROGRESS_VALUE', 'PRIVATE_FIELD_NAME', 'PRIVATE_FIELD_VALUE',
    'PRIVATE_BUSINESS_FIELD', 'PRIVATE_BUSINESS_VALUE', body.params.arguments.messageId]) assert.equal(logged.includes(privateValue), false);
});
test('standard request metadata never becomes tool arguments and unknown business fields stay rejected', async () => {
  const f = await fixture(), before = f.store.snapshot();
  const handler = createMcpHandler({ enabled: true, verify: async () => friday, bridge: f.bridge,
    events: f.events, scheduleJobs: async () => assert.fail('no delivery') });
  const rpc = async params => {
    const response = await handler(new Request('https://bridge.example.test/mcp', { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params }) }));
    return { status: response.status, body: await response.json() };
  };
  const base = { name: 'bridge_status', arguments: { messageId: '00000000-0000-4000-8000-000000000001' } };
  for (const progressToken of ['native-fixture-progress', 7]) {
    const result = await rpc({ ...base, _meta: { progressToken, 'com.example/ignored': { arbitrary: true } } });
    assert.equal(result.status, 200); assert.equal(result.body.result.isError, true);
    assert.deepEqual(result.body.result.structuredContent, { error: 'message_not_found' });
    assert.equal(result.body.error, undefined);
  }
  for (const params of [{ ...base, unexpected: true }, { ...base, _meta: [] }, { ...base, _meta: null },
    { ...base, _meta: { progressToken: {} } }, { ...base, _meta: { progressToken: 1.5 } },
    { ...base, arguments: { ...base.arguments, _meta: { progressToken: 'inside-business-arguments' } } }]) {
    const result = await rpc(params); assert.equal(result.status, 400); assert.equal(result.body.error.message, 'invalid_params');
  }
  assert.deepEqual(f.store.snapshot(), before);
});
test('Postgres transaction locks before transition, commits atomically and rolls back sanitized failures', async () => {
  const calls = []; const state = new MemoryStore().snapshot();
  const db = { query: async (sql, values) => { calls.push({ sql, values });
    return sql.startsWith('SELECT') ? { rows: [{ document: structuredClone(state) }] } : { rows: [] }; }, release: () => calls.push({ sql: 'release' }) };
  const store = new PostgresStore({ connect: async () => db });
  await store.transaction(s => { s.receipts.fixture = { state: 'claimed' }; return { ok: true }; });
  assert.ok(calls[2].sql.endsWith('FOR UPDATE')); assert.equal(calls.at(-2).sql, 'COMMIT');
  await assert.rejects(store.transaction(() => { throw Error('PRIVATE_ERROR'); }), code('storage_unavailable'));
  assert.equal(calls.at(-2).sql, 'ROLLBACK');
});
test('callback DNS timeout and response size limits fail safely without redirect or sensitive output', async () => {
  const timeout = createPublicWebhookTransport({ enabled: true, timeoutMs: 5, resolve: () => new Promise(() => {}),
    request: () => assert.fail('must not connect') });
  await assert.rejects(timeout('https://callback.example.test/native', { body: '{}', headers: {} }), code('callback_timeout'));
  const tooLarge = createPublicWebhookTransport({ enabled: true, responseLimit: 4,
    resolve: async () => [{ address: '8.8.8.8', family: 4 }], request: (u, options, callback) => {
      const req = new EventEmitter(); req.destroy = () => {};
      req.end = () => queueMicrotask(() => { const res = new EventEmitter(); res.statusCode = 200; res.destroy = () => {};
        callback(res); res.emit('data', Buffer.from('SYNTHETIC_PRIVATE_BODY')); res.emit('end'); }); return req;
    } });
  await assert.rejects(tooLarge('https://callback.example.test/native', { body: '{}', headers: {} }), code('callback_response_too_large'));
});
test('old rotation signature expires; unknown host evidence is explicit and never verifies wake', async () => {
  const f = await fixture(); const replacement = secret(); await f.events.subscribe(jarvis, params(replacement));
  f.advance(300001);
  const queued = await f.bridge.send(friday, probe('friday', { sentAt: new Date(f.clock()).toISOString() }));
  await new DeliveryWorker({ ...f, enabled: true, accessAllowed: async () => true }).run(queued.jobIds[0]);
  assert.equal(f.calls.at(-1).headers['webhook-signature'].split(' ').length, 1);
  const claim = await f.bridge.claim(jarvis, { messageId: queued.messageId });
  const completed = await f.bridge.complete(jarvis, { messageId: queued.messageId, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null });
  assert.ok(completed.ackMessageId);
  assert.equal((await f.bridge.status(jarvis, { messageId: queued.messageId })).wakeVerified, false);
});
test('plugin preparation refuses missing live discovery/client and rejects other projects or the existing health path', () => {
  assert.throws(() => preparePrivatePlugin(), code('live_plugin_discovery_and_client_required'));
  const fixture = { liveDiscoveryVerified: true, clientId: 'NONSECRET_FIXTURE_CLIENT',
    discovery: { supportedVersions: ['2026-07-28'], capabilities: { events: {} } }, events: [{ name: EVENT_NAME }] };
  for (const endpoint of ['https://other-project.vercel.app/bridge/jarvis/mcp',
    'https://rn-jarvis-friday-discovery-20261018.vercel.app/mcp']) {
    assert.throws(() => preparePrivatePlugin({ ...fixture, endpoint }), code('verified_mcp_endpoint_required'));
  }
  // Fixture result remains in memory only. No archive/account/plugin is created.
  const files = preparePrivatePlugin({ ...fixture,
    endpoint: 'https://rn-jarvis-friday-discovery-20261018.vercel.app/bridge/jarvis/mcp' });
  assert.equal(JSON.parse(files['mcp.json']).mcpServers['rn-synthetic-bridge'].extensions['com.openai'].auth.client.tokenEndpointAuthMethod, 'none');
});
test('new Jarvis messages fail closed without native subscription; encrypted configuration is bound to its subscription ID', async () => {
  const store = new MemoryStore(); const bridge = new Bridge({ store, clock: () => now });
  await assert.rejects(bridge.send(friday, probe()), code('recipient_subscription_required'));
  assert.equal(Object.keys(store.snapshot().messages).length, 0);
  const protector = createProtector(randomBytes(32)); const key = secret();
  const sealed = protector.seal({ secret: key }, 'sub_fixture_1');
  assert.equal(protector.open(sealed, 'sub_fixture_1').secret, key);
  assert.throws(() => protector.open(sealed, 'sub_fixture_2'), code('storage_decryption_failed'));
  await assert.rejects(bridge.send(friday, { ...probe(), kind: 'ack' }), code('use_receipt_complete_for_ack'));
});
