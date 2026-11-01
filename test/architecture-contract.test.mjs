import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { NativeEvents, EVENT_NAME } from '../src/events.mjs';
import { MemoryStore } from '../src/store.mjs';
import { createProtector } from '../src/webhook.mjs';
import { Bridge } from '../src/bridge.mjs';
import { createMcpHandler } from '../src/mcp.mjs';
import { BridgeError, VERIFIED_AUTHORIZATION, SCOPES, createAccessVerifier } from '../src/policy.mjs';
import { resourceFor, metadataFor } from '../src/resource.mjs';
import { DeliveryWorker } from '../src/worker.mjs';
import { ISSUER } from './fixtures/provider.mjs';

const start = Date.UTC(2026, 9, 22), policyId = 'c'.repeat(64);
function fixture() {
  let now = start;
  const clock = () => now, expiry = start + 600000, store = new MemoryStore();
  const who = role => Object.defineProperty({ role, principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64),
    scopes: Object.values(SCOPES[role]) }, VERIFIED_AUTHORIZATION, { value: { policyId, expiresAt: expiry } });
  const jarvis = who('jarvis'), friday = who('friday');
  const params = { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: 10000, cursor: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/contract',
      secret: 'whsec_' + Buffer.alloc(32, 6).toString('base64') } };
  const events = new NativeEvents({ store, protector: createProtector(Buffer.alloc(32, 7)),
    policyId, clock, enabled: true, transport: async (_url, req) => ({ status: 200,
      body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  const bridge = new Bridge({ store, clock, dailyEnabled: true, messagePolicyIds: { jarvis: policyId, friday: policyId } });
  return { jarvis, friday, params, events, bridge, store, clock, expiry, advance: ms => { now += ms; } };
}

test('MCP Event capabilities follow protocol discovery, role, scope and health-only fences', async () => {
  const f = fixture();
  const rpc = async (principal, method, params = {}, healthOnly = false) => {
    const handler = createMcpHandler({ enabled: true, healthOnly, verify: async () => principal,
      bridge: {}, events: {}, scheduleJobs: async () => {} });
    const response = await handler(new Request(resourceFor(principal.role), { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
    assert.equal(response.status, 200);
    return (await response.json()).result;
  };
  const pre2 = ['2025-03-26', '2025-06-18', '2025-11-25'];
  for (const protocolVersion of pre2) {
    const params = { protocolVersion, capabilities: {}, clientInfo: { name: 'fixture', version: '1' } };
    assert.deepEqual((await rpc(f.jarvis, 'initialize', params)).capabilities, { tools: {}, events: {} });
    assert.deepEqual((await rpc({ ...f.jarvis, scopes: [SCOPES.jarvis.probe] }, 'initialize', params)).capabilities, { tools: {} });
    assert.deepEqual((await rpc(f.friday, 'initialize', params)).capabilities, { tools: {} });
    assert.deepEqual((await rpc(f.jarvis, 'initialize', params, true)).capabilities, { tools: {} });
  }
  const v2 = { protocolVersion: '2026-07-28', capabilities: {}, clientInfo: { name: 'fixture', version: '1' } };
  assert.deepEqual((await rpc(f.jarvis, 'initialize', v2)).capabilities, { tools: {} });
  assert.deepEqual((await rpc(f.jarvis, 'server/discover')).capabilities, { tools: {}, events: {} });
  assert.deepEqual((await rpc({ ...f.jarvis, scopes: [SCOPES.jarvis.probe] }, 'server/discover')).capabilities, { tools: {} });
  assert.deepEqual((await rpc(f.friday, 'server/discover')).capabilities, { tools: {} });
  assert.deepEqual((await rpc(f.jarvis, 'server/discover', {}, true)).capabilities, { tools: {} });
});

test('contract: repeated subscribe re-grants TTL within the unchanged verified-token expiry', async () => {
  const f = fixture(), first = await f.events.subscribe(f.jarvis, f.params);
  f.advance(5000);
  const next = await f.events.subscribe(f.jarvis, f.params);
  assert.equal(next.id, first.id);
  assert.equal(Date.parse(next.refreshBefore), f.clock() + f.params.ttlMs);
  assert.ok(Date.parse(next.refreshBefore) <= f.expiry);
});

test('contract: an expired shorter TTL can recover under still-valid authority after restart', async () => {
  const f = fixture(), first = await f.events.subscribe(f.jarvis, f.params);
  f.advance(10001);
  f.events.store = new MemoryStore(f.store.snapshot());
  const next = await f.events.subscribe(f.jarvis, f.params);
  assert.equal(next.id, first.id);
  assert.equal(Date.parse(next.refreshBefore), f.clock() + f.params.ttlMs);
  assert.equal(Object.keys(f.events.store.snapshot().subscriptions).length, 1);
  assert.deepEqual(f.events.store.snapshot().jobs, {});
});

test('contract: a busy receipt is a tool execution error, not a failed MCP connection', async () => {
  const f = fixture(); await f.events.subscribe(f.jarvis, { ...f.params, ttlMs: null });
  const id = randomUUID();
  await f.bridge.sendMessage(f.friday, { protocol: 'jarvis-friday/1', id, threadId: randomUUID(),
    from: 'friday', to: 'jarvis', kind: 'message', route: 'inbox', text: 'Offline fixture only.',
    sentAt: new Date(f.clock()).toISOString(), expiresAt: new Date(f.clock() + 60000).toISOString() });
  const firstClaim = await f.bridge.claim(f.jarvis, { messageId: id });
  const handler = createMcpHandler({ enabled: true, verify: async () => f.jarvis,
    bridge: f.bridge, events: f.events, scheduleJobs: async () => {}, health: () => ({}) });
  const response = await handler(new Request(resourceFor('jarvis'), { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1,
      method: 'tools/call', params: { name: 'bridge_receipt_claim', arguments: { messageId: id } } }) }));
  const rpc = await response.json();
  assert.equal(response.status, 200);
  assert.equal(rpc.result.isError, true);
  assert.deepEqual(rpc.result.structuredContent, { error: 'receipt_busy' });
  assert.deepEqual(f.store.snapshot().receipts[id], {
    state: 'claimed', owner: f.jarvis.principalKey,
    claimId: firstClaim.claimId, leaseUntil: Date.parse(firstClaim.leaseUntil),
  });
});

for (const phase of ['access_check', 'state_recheck']) {
  test(`recovery: temporary storage failure in ${phase} does not permanently kill authorized queued work`, async () => {
    const f = fixture(); await f.events.subscribe(f.jarvis, { ...f.params, ttlMs: null });
    const id = randomUUID();
    const sent = await f.bridge.sendMessage(f.friday, { protocol: 'jarvis-friday/1', id, threadId: randomUUID(),
      from: 'friday', to: 'jarvis', kind: 'message', route: 'inbox', text: 'Offline recovery fixture.',
      sentAt: new Date(f.clock()).toISOString(), expiresAt: new Date(f.clock() + 600000).toISOString() });
    let reads = 0, posts = 0;
    const faultingStore = { transaction: op => {
      if (phase === 'state_recheck' && ++reads === 2) return Promise.reject(new BridgeError('storage_unavailable', 503));
      return f.store.transaction(op);
    } };
    const options = { store: faultingStore, clock: f.clock, enabled: true, policyId,
      messagePolicyIds: { jarvis: policyId, friday: policyId }, protector: f.events.protector,
      transport: async () => { posts++; return { status: 202 }; },
      accessAllowed: async () => {
        if (phase === 'access_check') throw new BridgeError('storage_unavailable', 503);
        return true;
      } };
    const first = await new DeliveryWorker(options).run(sent.jobIds[0]);
    assert.equal(posts, 0); assert.equal(first.transportAccepted, false);
    assert.equal(f.store.snapshot().jobs[sent.jobIds[0]].state, 'pending');
    assert.equal(f.store.snapshot().jobs[sent.jobIds[0]].lastError, 'storage_unavailable');
    const early = await new DeliveryWorker({ ...options, store: f.store, accessAllowed: async () => true }).run(sent.jobIds[0]);
    assert.equal(early.attempted, false); assert.equal(posts, 0);
    assert.equal(f.store.snapshot().jobs[sent.jobIds[0]].attempts, 1);
    f.advance(1001);
    const restarted = new MemoryStore(f.store.snapshot());
    const next = await new DeliveryWorker({ ...options, store: restarted, accessAllowed: async () => true }).run(sent.jobIds[0]);
    assert.equal(next.transportAccepted, true); assert.equal(posts, 1);
    assert.equal(restarted.snapshot().jobs[sent.jobIds[0]].attempts, 2);
  });
}

test('wire lifecycle: valid renewal, hard401 challenge, later verified token and same-identity recovery', async () => {
  const f = fixture(), { publicKey, privateKey } = await generateKeyPair('RS256');
  const sign = expiry => new SignJWT({ scope: SCOPES.jarvis.ack }).setProtectedHeader({ alg: 'RS256' })
    .setIssuer(ISSUER).setSubject('fixture-wire-lifecycle').setAudience(resourceFor('jarvis'))
    .setIssuedAt(Math.floor(start / 1000)).setExpirationTime(expiry / 1000).sign(privateKey);
  const verifier = () => createAccessVerifier({ issuer: ISSUER, audience: resourceFor('jarvis'),
    subject: 'fixture-wire-lifecycle', role: 'jarvis', keyResolver: publicKey, currentDate: new Date(f.clock()) });
  const token = await sign(start + 5000);
  const request = bearer => new Request(resourceFor('jarvis'), { method: 'POST', headers: {
    authorization: 'Bearer ' + bearer, 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'events/subscribe', params: { ...f.params, ttlMs: 1000 } }) });
  const principal = await verifier()(request(token));
  f.events.policyId = principal[VERIFIED_AUTHORIZATION].policyId;
  const handler = createMcpHandler({ enabled: true, verify: req => verifier()(req), bridge: f.bridge,
    events: f.events, scheduleJobs: async () => assert.fail('renewal never enqueues application events'),
    resourceMetadataUrl: metadataFor('jarvis') });
  const firstResponse = await handler(request(token)), first = (await firstResponse.json()).result;
  assert.equal(firstResponse.status, 200);
  f.advance(500);
  const renewal = (await (await handler(request(token))).json()).result;
  assert.equal(renewal.id, first.id); assert.equal(Date.parse(renewal.refreshBefore), f.clock() + 1000);
  f.advance(4500);
  const before = f.store.snapshot(), denied = await handler(request(token));
  assert.equal(denied.status, 401);
  assert.equal(denied.headers.get('www-authenticate'), `Bearer resource_metadata="${metadataFor('jarvis')}"`);
  assert.deepEqual(f.store.snapshot(), before, 'pre-auth failures neither renew nor journal');
  f.events.store = new MemoryStore(before);
  const fresh = await sign(start + 600000), recoveredResponse = await handler(request(fresh));
  const recovered = (await recoveredResponse.json()).result;
  assert.equal(recoveredResponse.status, 200); assert.equal(recovered.id, first.id);
  assert.equal(Date.parse(recovered.refreshBefore), f.clock() + 1000);
  assert.equal(Object.keys(f.events.store.snapshot().subscriptions).length, 1);
  assert.deepEqual(f.events.store.snapshot().jobs, {});
});

test('tool boundary consistently exposes sanitized execution failures while retaining protocol/auth failures', async () => {
  const f = fixture();
  const cases = [[new BridgeError('invalid_params', 400), 200, 'invalid_params'],
    [new BridgeError('receipt_busy', 409), 200, 'receipt_busy'],
    [new BridgeError('message_rate_limited', 429), 200, 'message_rate_limited'],
    [new BridgeError('receiver_readiness_required', 503), 200, 'receiver_readiness_required'],
    [Error('FIXTURE_PRIVATE_TOKEN_URL_BODY'), 200, 'bridge_unavailable'],
    [new BridgeError('insufficient_scope', 403), 403, 'insufficient_scope'],
    [new BridgeError('unauthorized', 401), 401, 'unauthorized']];
  for (const [error, status, code] of cases) {
    const handler = createMcpHandler({ enabled: true, verify: async () => f.jarvis,
      bridge: { claim: async () => { throw error; } }, events: f.events, scheduleJobs: async () => {},
      resourceMetadataUrl: metadataFor('jarvis') });
    const request = method => new Request(resourceFor('jarvis'), { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 43, method, params: { name: 'bridge_receipt_claim', arguments: { messageId: randomUUID() } } }) });
    const response = await handler(request('tools/call')), rpc = await response.json();
    assert.equal(response.status, status);
    if (status === 200) {
      assert.equal(rpc.result.isError, true); assert.deepEqual(rpc.result.structuredContent, { error: code });
      assert.deepEqual(JSON.parse(rpc.result.content[0].text), rpc.result.structuredContent);
    } else assert.equal(rpc.error.message, code);
    if (status === 401) assert.ok(response.headers.get('www-authenticate'));
    assert.equal(JSON.stringify(rpc).includes('FIXTURE_PRIVATE'), false);
    const unknown = await handler(request('fixture/unknown'));
    assert.equal(unknown.status, 400); assert.equal((await unknown.json()).error.code, -32601);
  }
});

test('storage retries remain bounded and never bypass source expiry, denial or terminal configuration errors', async () => {
  for (const mode of ['budget', 'expiry', 'denial', 'configuration']) {
    const f = fixture(); await f.events.subscribe(f.jarvis, { ...f.params, ttlMs: null });
    const id = randomUUID(), sent = await f.bridge.sendMessage(f.friday, { protocol: 'jarvis-friday/1', id,
      threadId: randomUUID(), from: 'friday', to: 'jarvis', kind: 'message', route: 'inbox', text: 'Offline budget fixture.',
      sentAt: new Date(f.clock()).toISOString(), expiresAt: new Date(f.clock() + 600000).toISOString() });
    let posts = 0, failures = mode === 'budget' ? Infinity : 1;
    const worker = new DeliveryWorker({ store: f.store, clock: f.clock, enabled: true, policyId,
      messagePolicyIds: { jarvis: policyId, friday: policyId }, protector: f.events.protector,
      transport: async () => { posts++; return { status: 202 }; }, accessAllowed: async () => {
        if (failures-- > 0) throw new BridgeError(mode === 'configuration' ? 'storage_configuration_required' : 'storage_unavailable', 503);
        return true;
      } });
    await worker.run(sent.jobIds[0]);
    if (mode === 'expiry') f.advance(600000);
    if (mode === 'denial') await f.store.transaction(s => { s.resourceDenials = { [f.friday.principalKey]: {} }; });
    for (let n = 0; n < 6; n++) { f.advance(16000); await worker.run(sent.jobIds[0]); }
    const job = f.store.snapshot().jobs[sent.jobIds[0]];
    assert.equal(job.state, 'dead'); assert.ok(job.attempts <= 5); assert.equal(posts, 0);
    if (mode === 'budget') { assert.equal(job.attempts, 5); assert.equal(job.lastError, 'storage_unavailable'); }
    else {
      assert.equal(job.attempts, 1);
      assert.equal(job.lastError, { expiry: 'subscription_inactive', denial: 'message_authorization_inactive',
        configuration: 'delivery_configuration_required' }[mode]);
    }
  }
});

test('an adapter storage error after transport starts is terminal, not a pre-send recovery opportunity', async () => {
  const f = fixture(); await f.events.subscribe(f.jarvis, { ...f.params, ttlMs: null });
  const id = randomUUID(), sent = await f.bridge.sendMessage(f.friday, { protocol: 'jarvis-friday/1', id,
    threadId: randomUUID(), from: 'friday', to: 'jarvis', kind: 'message', route: 'inbox', text: 'Offline ambiguous adapter fixture.',
    sentAt: new Date(f.clock()).toISOString(), expiresAt: new Date(f.clock() + 600000).toISOString() });
  let posts = 0;
  const worker = new DeliveryWorker({ store: f.store, clock: f.clock, enabled: true, policyId,
    messagePolicyIds: { jarvis: policyId, friday: policyId }, protector: f.events.protector,
    accessAllowed: async () => true, transport: async () => { posts++; throw new BridgeError('storage_unavailable', 503); } });
  await worker.run(sent.jobIds[0]); f.advance(30000); await worker.run(sent.jobIds[0]);
  const job = f.store.snapshot().jobs[sent.jobIds[0]];
  assert.equal(posts, 1); assert.equal(job.state, 'dead'); assert.equal(job.attempts, 1);
  assert.equal(job.lastError, 'delivery_configuration_required');
});

test('a failed immediate schedule reports uncertainty without promising an unwired reconciler', async () => {
  const f = fixture();
  const handler = createMcpHandler({ enabled: true, verify: async () => f.jarvis, events: f.events,
    bridge: { sendMessage: async () => ({ messageId: randomUUID(), queued: true, jobIds: ['job_' + 'a'.repeat(64)] }) },
    scheduleJobs: async () => { throw Error('FIXTURE_PRIVATE_BACKEND'); } });
  const response = await handler(new Request(resourceFor('jarvis'), { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 44, method: 'tools/call', params: { name: 'bridge_message_send', arguments: {} } }) }));
  const result = (await response.json()).result;
  assert.equal(result.isError, false); assert.equal(result.structuredContent.queued, true);
  assert.equal(result.structuredContent.scheduling, 'not_confirmed');
  assert.equal(result.structuredContent.deliveryScheduled, false);
  assert.equal(JSON.stringify(result).includes('reconciliation'), false);
  assert.equal(JSON.stringify(result).includes('FIXTURE_PRIVATE'), false);
});
