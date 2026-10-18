import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { createContractObserver, createAccessVerifier } from '../src/policy.mjs';
import { generateKeyPair, SignJWT } from 'jose';
import { handle } from '../api/index.mjs';
import { createRuntime } from '../src/runtime.mjs';
import { resourceFor, metadataFor, ISSUER } from '../src/resource.mjs';
import { MemoryStore } from '../src/store.mjs';
import { emptyState } from '../src/store.mjs';
import { TOPIC, createQueueAdapter } from '../src/queue.mjs';
import queueHandler from '../api/queue.mjs';

const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
const request = (path, extra = {}) => new Request('https://rn-jarvis-friday-discovery-20261018.vercel.app' + path,
  { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }), ...extra });
test('public discovery challenges both resources and describes only the real provider', async () => {
  for (const role of ['friday', 'jarvis']) {
    const r = await handle(request(`/bridge/${role}/mcp`));
    assert.equal(r.status, 401); assert.equal(r.headers.get('www-authenticate'), `Bearer resource_metadata="${metadataFor(role)}"`);
    const metadata = await (await handle(new Request(metadataFor(role)))).json();
    assert.equal(metadata.resource, resourceFor(role)); assert.deepEqual(metadata.authorization_servers, [ISSUER]);
    assert.equal(JSON.stringify(metadata).includes('registration_endpoint'), false);
    assert.equal(metadata.scopes_supported.length, 2);
  }
});
test('configuration gaps cannot accept a bearer or enable delivery', async () => {
  const r = await handle(request('/bridge/friday/mcp', { headers: { ...headers, authorization: 'Bearer fixture' } }));
  assert.equal(r.status, 503); assert.deepEqual(await r.json(), { error: 'bridge_configuration_required' });
  const rt = createRuntime({ env: {}, queueClient: {} });
  assert.throws(() => rt.handler('friday'), /provider_contract_verification_required/);
});
test('contract observation verifies JWT policy but always503 and never emits tokens or private claims', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256'); const observations = [];
  const subject = 'fixture-private-subject';
  const token = await new SignJWT({ scopes: ['bridge:send:jarvis', 'bridge:ack:friday', 'offline_access'], email: 'fixture-private@example.test' })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject(subject).setAudience(resourceFor('friday'))
    .setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const observe = createContractObserver({ issuer: ISSUER, audience: resourceFor('friday'), role: 'friday',
    keyResolver: publicKey, emit: facts => observations.push(facts) });
  const req = request('/bridge/friday/mcp', { headers: { ...headers, authorization: `Bearer ${token}` } });
  assert.equal((await observe(req)).status, 503); assert.equal(observations[0].verified, true);
  assert.equal(observations[0].subjectDigest, createHash('sha256').update(subject).digest('hex'));
  assert.deepEqual(observations[0].claims.find(x => x.name === 'scopes'),
    { name: 'scopes', form: 'array', probeScope: true, ackScope: true, offlineScope: true });
  const output = JSON.stringify(observations);
  for (const privateValue of [token, subject, 'fixture-private@example.test']) assert.equal(output.includes(privateValue), false);
  const wrongAudience = createContractObserver({ issuer: ISSUER, audience: resourceFor('jarvis'), role: 'jarvis',
    keyResolver: publicKey, emit: facts => observations.push(facts) });
  assert.equal((await wrongAudience(req)).status, 503); assert.deepEqual(observations.at(-1), { verified: false, role: 'jarvis', rejectedCheck: 'aud' });
});
test('subject digest pins exactly one identity and configurable verified scope claim without changing principal identity', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256'); const subject = 'fixture-subject';
  const token = await new SignJWT({ scopes: ['bridge:send:jarvis', 'bridge:ack:friday'] }).setProtectedHeader({ alg: 'RS256' })
    .setIssuer(ISSUER).setSubject(subject).setAudience(resourceFor('friday')).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const options = { issuer: ISSUER, audience: resourceFor('friday'), role: 'friday', keyResolver: publicKey, scopeClaim: 'scopes' };
  const req = request('/bridge/friday/mcp', { headers: { ...headers, authorization: `Bearer ${token}` } });
  const hashed = await createAccessVerifier({ ...options, subjectHash: createHash('sha256').update(subject).digest('hex') })(req);
  const literal = await createAccessVerifier({ ...options, subject })(req);
  assert.equal(hashed.principalKey, literal.principalKey); assert.deepEqual(hashed.scopes, literal.scopes);
  await assert.rejects(createAccessVerifier({ ...options, subjectHash: 'a'.repeat(64) })(req), /forbidden_subject/);
  assert.throws(() => createAccessVerifier({ ...options, subject, subjectHash: 'a'.repeat(64) }), /provider_configuration_required/);
  assert.throws(() => createAccessVerifier({ ...options, subject, scopeClaim: 'arbitrary_claim' }), /provider_configuration_required/);
});
test('cross-origin bridge request fails before handler or authorization discovery', async () => {
  assert.equal((await handle(request('/bridge/friday/mcp', { headers: { ...headers, origin: 'https://other.example' } }))).status, 403);
});
test('optional timing evidence exposes only verified timestamps and cannot change authorization', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const observations = [], now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ scope: 'bridge:ack:friday', email: 'private@example.test', extra: 'private-claim' })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject('private-subject')
    .setAudience(resourceFor('friday')).setIssuedAt(now).setExpirationTime(now + 300).sign(privateKey);
  const options = { issuer: ISSUER, audience: resourceFor('friday'), subject: 'private-subject',
    role: 'friday', keyResolver: publicKey, observeTiming: facts => observations.push(facts) };
  const req = request('/bridge/friday/mcp', { headers: { ...headers, authorization: `Bearer ${token}` } });
  const principal = await createAccessVerifier(options)(req);
  assert.deepEqual(observations, [{ role: 'friday', issuedAt: now, expiresAt: now + 300 }]);
  assert.deepEqual(Object.keys(principal).sort(), ['principalKey', 'role', 'scopes']);
  for (const value of [token, 'private-subject', 'private@example.test', 'private-claim'])
    assert.equal(JSON.stringify(observations).includes(value), false);
  await assert.rejects(createAccessVerifier({ ...options, audience: resourceFor('jarvis') })(req), /unauthorized/);
  await assert.rejects(createAccessVerifier({ ...options, subject: 'other' })(req), /forbidden_subject/);
  assert.equal(observations.length, 1);
  const throwing = await createAccessVerifier({ ...options, observeTiming() { throw Error('fixture'); } })(req);
  assert.deepEqual(throwing, principal);
});
test('copied legacy files match the current production diagnostic source exactly', () => {
  for (const name of ['index', 'diagnostic']) {
    assert.deepEqual(readFileSync(new URL(`../legacy/${name}.mjs`, import.meta.url)),
      readFileSync(new URL(`./fixtures/original-health/api/${name}.mjs`, import.meta.url)));
  }
});
test('catch-all routing excludes the actual queue function path', () => {
  const config = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url)));
  const catchAll = new RegExp('^' + config.rewrites[0].source + '$');
  assert.equal(catchAll.test('/api/queue'), false);
  for (const path of ['/health', '/mcp', '/bridge/friday/mcp', '/bridge/jarvis/mcp', '/oauth-diag/public/mcp']) {
    assert.equal(catchAll.test(path), true);
  }
  assert.equal(config.functions['api/queue.mjs'].experimentalTriggers[0].topic, TOPIC);
  assert.equal(config.functions['api/queue.mjs'].experimentalTriggers[0].maxDeliveries, 20);
});
test('legacy health and health-only invocation still work through new router', async () => {
  assert.equal((await (await handle(new Request(resourceFor('friday').split('/bridge/')[0] + '/health'))).json()).events, false);
  const r = await handle(request('/mcp', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'probe_health', arguments: {} } }) }));
  assert.equal(JSON.parse((await r.json()).result.content[0].text).messageDelivery, false);
  assert.equal((await handle(new Request(metadataFor('friday').split('/.well-known/')[0] + '/.well-known/oauth-authorization-server'))).status, 503);
});
test('runtime requires real subject/claim contract, verifies audience, and blocks writes without readiness', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  let poolOptions;
  class FakePool { constructor(options) { poolOptions = options; } on() {} connect() { throw new Error('unexpected database access'); } }
  const rt = createRuntime({ env: { BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture-subject',
    DATABASE_URL: 'postgresql://fixture:fixture@fixture.neon.tech/neondb?sslmode=require' }, Pool: FakePool,
    keyResolver: publicKey, queueClient: {} });
  const token = await new SignJWT({ scope: 'bridge:send:jarvis bridge:ack:friday' }).setProtectedHeader({ alg: 'RS256' })
    .setIssuer(ISSUER).setSubject('fixture-subject').setAudience(resourceFor('friday')).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const handler = rt.handler('friday');
  assert.equal(poolOptions, undefined); // Discovery/health never initialize storage.
  const call = (method, params) => handler(request('/bridge/friday/mcp', { headers: { ...headers, authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
  assert.equal((await (await call('tools/list')).json()).result.tools.length, 6);
  const response = await call('tools/call', { name: 'bridge_send', arguments: {} });
  assert.equal(response.status, 503); assert.equal((await response.json()).error.message, 'receiver_readiness_required');
  const lookup = await call('tools/call', { name: 'bridge_status', arguments: { messageId: '00000000-0000-4000-8000-000000000001' } });
  assert.equal(lookup.status, 503); assert.equal(new URL(poolOptions.connectionString).searchParams.get('sslmode'), 'verify-full');
  const wrong = await rt.handler('jarvis')(request('/bridge/jarvis/mcp', { headers: { ...headers, authorization: `Bearer ${token}` } }));
  assert.equal(wrong.status, 401);
});
test('runtime bounds Jarvis subscription by verified expiry and durable denial while sends and queue remain disabled', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  let document = emptyState(), challenges = 0, queueSends = 0;
  class FakePool {
    on() {}
    async connect() { return { release() {}, async query(sql, params) {
      if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(document) }] };
      if (sql.startsWith('UPDATE rn_bridge_runtime')) document = JSON.parse(params[0]);
      return { rows: [] };
    } }; }
  }
  const rt = createRuntime({ env: { BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture-subject',
    BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_DELIVERY_ENABLED: 'false',
    BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
    DATABASE_URL: 'postgresql://fixture:fixture@fixture.neon.tech/neondb?sslmode=require' },
    Pool: FakePool, keyResolver: publicKey,
    queueClient: { async send() { queueSends++; } }, transportFactory: () => async (_url, req) => {
      challenges++; const body = JSON.parse(req.body); assert.equal(body.type, 'verification');
      return { status: 200, body: JSON.stringify({ challenge: body.challenge }) };
    } });
  const token = await new SignJWT({ scope: 'bridge:ack:jarvis bridge:send:friday' }).setProtectedHeader({ alg: 'RS256' })
    .setIssuer(ISSUER).setSubject('fixture-subject').setAudience(resourceFor('jarvis')).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const handler = rt.handler('jarvis');
  const rpc = (method, params) => handler(request('/bridge/jarvis/mcp', { headers: { ...headers, authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
  const subscribed = await (await rpc('events/subscribe', { name: 'bridge.message.received', arguments: { recipient: 'jarvis' },
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') }, ttlMs: null })).json();
  assert.ok(Date.parse(subscribed.result.refreshBefore) <= Date.now() + 300000); assert.equal(challenges, 1);
  assert.equal(Object.keys(document.subscriptions).length, 1);
  assert.equal(Object.values(document.subscriptions)[0].active, true);
  document.resourceDenials = { [Object.values(document.subscriptions)[0].owner]: { status: 'denied' } };
  const denied = await rpc('events/subscribe', { name: 'bridge.message.received', arguments: { recipient: 'jarvis' },
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') }, ttlMs: null });
  assert.equal(denied.status, 403); assert.equal((await denied.json()).error.message, 'access_revoked');
  assert.equal(challenges, 1); assert.equal(Object.keys(document.subscriptions).length, 1);
  const sent = await rpc('tools/call', { name: 'bridge_send', arguments: {} });
  assert.equal(sent.status, 503); assert.equal((await sent.json()).error.message, 'receiver_readiness_required');
  assert.deepEqual(document.messages, {}); assert.deepEqual(document.jobs, {}); assert.equal(queueSends, 0);
});
const id = 'job_' + 'a'.repeat(64);
async function queueFixture(state = 'pending') {
  let now = 100000;
  const store = new MemoryStore();
  await store.transaction(s => { s.jobs[id] = { id, state, attempts: 0, dueAt: now, leaseUntil: null }; });
  const calls = []; const worker = { async run() {} };
  const adapter = createQueueAdapter({ client: { async send(...args) { calls.push(args); } },
    store, worker, enabled: true, clock: () => now });
  return { adapter, store, calls, worker, advance: n => { now += n; } };
}
test('queue schedules identifiers only and preserves pending/delayed/leased work on retry', async () => {
  const { adapter, calls, store, worker } = await queueFixture();
  await adapter.scheduleJobs([id, id]); assert.equal(calls.length, 1);
  assert.deepEqual(calls[0][1], { jobId: id }); assert.equal(calls[0][0], TOPIC);
  const metadata = { topicName: TOPIC, region: 'iad1', deliveryCount: 1 };
  await assert.rejects(adapter.consume({ jobId: id }, metadata), /bridge_job_pending/);
  await store.transaction(s => { s.jobs[id].state = 'leased'; s.jobs[id].leaseUntil = 130000; });
  try { await adapter.consume({ jobId: id }, metadata); assert.fail(); }
  catch (e) { assert.deepEqual(adapter.retry(e, metadata), { afterSeconds: 30 }); }
  worker.run = async () => store.transaction(s => { s.jobs[id].state = 'accepted'; });
  await adapter.consume({ jobId: id }, metadata);
  assert.deepEqual(adapter.retry(new Error(), { deliveryCount: 20 }), { acknowledge: true });
});
test('queue ignores poisoned payloads and is disabled by default', async () => {
  const { adapter, worker } = await queueFixture(); let runs = 0; worker.run = async () => { runs++; };
  await adapter.consume({ jobId: id, body: 'forged' }, { topicName: TOPIC, region: 'iad1' });
  await adapter.consume({ jobId: id }, { topicName: 'other', region: 'iad1' }); assert.equal(runs, 0);
  await assert.rejects(createQueueAdapter({}).scheduleJobs([id]), /queue_not_enabled/);
});
test('private queue handler is disabled before any pool, SDK or transport work', async () => {
  const previous = process.env.BRIDGE_DELIVERY_ENABLED;
  delete process.env.BRIDGE_DELIVERY_ENABLED;
  try {
    const response = await queueHandler.fetch(new Request('https://fixture.example/api/queue', { method: 'POST', body: '{}' }));
    assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'delivery_not_enabled' });
  } finally {
    if (previous === undefined) delete process.env.BRIDGE_DELIVERY_ENABLED;
    else process.env.BRIDGE_DELIVERY_ENABLED = previous;
  }
});
