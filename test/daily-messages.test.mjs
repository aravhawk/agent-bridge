import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { Bridge } from '../src/bridge.mjs';
import { MemoryStore, emptyState } from '../src/store.mjs';
import { VERIFIED_AUTHORIZATION, SCOPES } from '../src/policy.mjs';
import { validateMessage, MESSAGE_PROTOCOL, retainMessages, CONTENT_RETENTION_MS, IDEMPOTENCY_RETENTION_MS } from '../src/messages.mjs';
import { createProtector } from '../src/webhook.mjs';
import { NativeEvents } from '../src/events.mjs';
import { DeliveryWorker } from '../src/worker.mjs';
import { createFridaySender } from '../src/friday-sender.mjs';
import { createRuntime } from '../src/runtime.mjs';
import { ISSUER, resourceFor } from '../src/resource.mjs';
import { TOPIC } from '../src/queue.mjs';

const start = Date.UTC(2026, 9, 19), policy = 'c'.repeat(64);
function who(role, until = start + 2 * 86400000) {
  return Object.defineProperty({ role, scopes: Object.values(SCOPES[role]), principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64) },
    VERIFIED_AUTHORIZATION, { value: { policyId: policy, expiresAt: until } });
}
const jarvis = who('jarvis'), friday = who('friday');
function fixture(snapshot) {
  let now = start;
  const store = new MemoryStore(snapshot), protector = createProtector(randomBytes(32));
  const clock = () => now, bridge = new Bridge({ store, clock, dailyEnabled: true,
    messagePolicyIds: { jarvis: policy, friday: policy } });
  const events = new NativeEvents({ store, protector, clock, policyId: policy, enabled: true,
    transport: async (_url, req) => ({ status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  const subscription = { name: 'bridge.message.received', arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } };
  const message = (from = 'jarvis', extra = {}) => ({ protocol: MESSAGE_PROTOCOL, id: randomUUID(), from,
    to: from === 'jarvis' ? 'friday' : 'jarvis', kind: 'message', sentAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 3600000).toISOString(), threadId: randomUUID(), route: 'inbox', text: 'Please review this request under Arav’s existing workflow.', ...extra });
  return { store, bridge, events, protector, clock, subscription, message, advance: n => { now += n; } };
}
const complete = (bridge, recipient, messageId, claimId) => bridge.complete(recipient,
  { messageId, claimId, hostedEventId: null, hostedTurnId: null });

test('daily messages accept only a scoped opposite-role inbox with bounded text and lifetime', () => {
  const f = fixture(), good = f.message();
  for (const kind of ['message', 'status', 'handoff_request']) assert.equal(validateMessage({ ...good, kind }, jarvis, start).envelope.kind, kind);
  for (const bad of [{ ...good, from: 'friday' }, { ...good, to: 'jarvis' }, { ...good, route: 'task-123' },
    { ...good, taskId: 'arbitrary' }, { ...good, url: 'https://untrusted.test' }, { ...good, approval: true },
    { ...good, text: 'a'.repeat(4097) }, { ...good, text: '😀'.repeat(1025) }, { ...good, text: ' ' },
    { ...good, text: '\u0000'.repeat(4096) }, { ...good, expiresAt: new Date(start + 3600001).toISOString() },
    { ...good, sentAt: new Date(start - 300001).toISOString() }, { ...good, sentAt: good.sentAt.slice(0, -1) }, { ...good, kind: 'execute' },
    { ...good, correlationId: randomUUID() }]) assert.throws(() => validateMessage(bad, jarvis, start));
  assert.throws(() => validateMessage(good, { ...jarvis, scopes: ['bridge:ack:jarvis'] }, start), /insufficient_scope/);
});

test('concurrent duplicate daily sends commit once and conflicting text never changes the saved body', async () => {
  const f = fixture(), m = f.message(); m.from = 'jarvis'; m.to = 'friday';
  const results = await Promise.all(Array.from({ length: 20 }, () => f.bridge.sendMessage(jarvis, m)));
  assert.equal(results.filter(r => !r.duplicate).length, 1);
  assert.equal(Object.keys(f.store.snapshot().jobs).length, 1);
  f.advance(600000);
  assert.equal((await f.bridge.sendMessage(jarvis, m)).duplicate, true);
  await assert.rejects(f.bridge.sendMessage(jarvis, { ...m, text: 'changed' }), /message_id_conflict/);
  assert.equal(f.store.snapshot().messages[m.id].envelope.text, m.text);
});

test('recipient isolation, source expiry and durable denial apply to daily reads/receipts/jobs', async () => {
  const f = fixture(), m = f.message();
  const sent = await f.bridge.sendMessage(who('jarvis', start + 1000), m);
  assert.equal(f.store.snapshot().messages[m.id].authorization.expiresAt, start + 1000);
  await assert.rejects(f.bridge.read(jarvis, { messageId: m.id }), /message_not_found/);
  const read = await f.bridge.read(friday, { messageId: m.id });
  assert.equal(read.authority, 'peer_data_requires_user_workflow');
  f.advance(1000);
  await assert.rejects(f.bridge.claim(friday, { messageId: m.id }), /message_authorization_inactive/);
  let posts = 0;
  const worker = new DeliveryWorker({ store: f.store, clock: f.clock, enabled: true,
    messagePolicyIds: { jarvis: policy, friday: policy }, accessAllowed: async () => true,
    fridaySender: async () => { posts++; return { status: 200 }; } });
  await worker.run(sent.jobIds[0]); assert.equal(posts, 0);
  const next = f.message(); await f.bridge.sendMessage(jarvis, next);
  await f.store.transaction(s => { s.resourceDenials = { [jarvis.principalKey]: { status: 'denied' } }; });
  await assert.rejects(f.bridge.claim(friday, { messageId: next.id }), /message_authorization_inactive/);
});

test('daily receipt commits exactly one correlated ACK, and ACK completion is terminal', async () => {
  const f = fixture(); await f.events.subscribe(jarvis, f.subscription);
  const m = f.message('friday', { kind: 'handoff_request' });
  await f.bridge.sendMessage(friday, m);
  const claim = await f.bridge.claim(jarvis, { messageId: m.id });
  const first = await complete(f.bridge, jarvis, m.id, claim.claimId);
  assert.ok(first.ackMessageId);
  assert.equal((await complete(f.bridge, jarvis, m.id, claim.claimId)).ackMessageId, first.ackMessageId);
  const ack = (await f.bridge.read(friday, { messageId: first.ackMessageId })).envelope;
  assert.equal(ack.protocol, MESSAGE_PROTOCOL); assert.equal(ack.correlationId, m.id);
  assert.equal(ack.threadId, m.threadId); assert.equal(ack.text, undefined);
  assert.equal(ack.expiresAt, m.expiresAt);
  const ackClaim = await f.bridge.claim(friday, { messageId: ack.id });
  assert.equal((await complete(f.bridge, friday, ack.id, ackClaim.claimId)).ackMessageId, null);
  assert.equal(Object.keys(f.store.snapshot().messages).length, 2);
  await assert.rejects(f.bridge.sendMessage(friday, ack), /use_receipt_complete_for_ack/);
});

test('retention deletes daily content/jobs/receipts but keeps replay tombstones and legacy/subscription/denial state', async () => {
  const f = fixture(), m = f.message(); await f.bridge.sendMessage(jarvis, m);
  await f.store.transaction(s => { s.messages.legacy = { envelope: { kind: 'probe' } }; s.subscriptions.keep = { sealed: 'ciphertext' }; s.resourceDenials = { keep: { status: 'denied' } }; });
  f.advance(CONTENT_RETENTION_MS);
  assert.deepEqual(await f.bridge.sendMessage(jarvis, m), { messageId: m.id, queued: false, duplicate: true, expired: true, jobIds: [] });
  let s = f.store.snapshot(); assert.equal(s.messages[m.id], undefined); assert.equal(Object.keys(s.jobs).length, 0);
  assert.ok(s.messageIds[m.id]); assert.ok(s.messages.legacy); assert.equal(s.subscriptions.keep.sealed, 'ciphertext'); assert.ok(s.resourceDenials.keep);
  await assert.rejects(f.bridge.sendMessage(jarvis, { ...m, text: 'resurrect' }), /message_id_conflict/);
  f.advance(IDEMPOTENCY_RETENTION_MS);
  await f.store.transaction(s => retainMessages(s, f.clock()));
  assert.equal(f.store.snapshot().messageIds[m.id], undefined);
  await assert.rejects(f.bridge.sendMessage(jarvis, m), /invalid_message_lifetime/);
});

test('daily live-capacity backpressure preserves pending messages and reserves room for atomic ACKs', async () => {
  const f = fixture(); await f.events.subscribe(jarvis, f.subscription);
  const messages = [];
  for (let i = 0; i < 100; i++) { if (i && i % 10 === 0) f.advance(60000); const m = f.message(); messages.push(m); await f.bridge.sendMessage(jarvis, m); }
  f.advance(60000);
  await assert.rejects(f.bridge.sendMessage(jarvis, f.message()), /message_capacity_reached/);
  const claim = await f.bridge.claim(friday, { messageId: messages[0].id });
  assert.ok((await complete(f.bridge, friday, messages[0].id, claim.claimId)).ackMessageId);
  assert.equal(Object.keys(f.store.snapshot().messages).length, 101);
});

test('daily transport retries transient failures at most five times with one stable event/body', async () => {
  const f = fixture(), m = f.message(); const sent = await f.bridge.sendMessage(jarvis, m), bodies = [];
  const fridaySender = createFridaySender({ enabled: true, contractVerified: true, endpoint: 'https://receiver.example.test/event',
    secret: 'FIXTURE_ONLY', transport: async (_url, req) => { bodies.push(req.body); return { status: 503 }; } });
  const worker = new DeliveryWorker({ store: f.store, clock: f.clock, enabled: true, fridaySender,
    messagePolicyIds: { jarvis: policy, friday: policy }, accessAllowed: async () => true });
  for (let i = 0; i < 8; i++) { await worker.run(sent.jobIds[0]); f.advance(60000); }
  assert.equal(bodies.length, 5); assert.equal(new Set(bodies).size, 1);
  assert.deepEqual(JSON.parse(bodies[0]), { event: 'bridge.message.received', data: { messageId: m.id } });
  assert.equal(f.store.snapshot().jobs[sent.jobIds[0]].state, 'dead');
});

test('subscription renewal records safe lifecycle metadata; same-token renewal never extends lease and denied renewal stays closed', async () => {
  const f = fixture(), firstToken = who('jarvis', start + 3600000);
  const first = await f.events.subscribe(firstToken, f.subscription);
  f.advance(60000);
  const same = await f.events.subscribe(firstToken, f.subscription); assert.equal(same.refreshBefore, first.refreshBefore);
  const renewed = await f.events.subscribe(who('jarvis', start + 7200000), f.subscription);
  assert.equal(renewed.id, first.id); assert.equal(Date.parse(renewed.refreshBefore), start + 7200000);
  const restarted = fixture(f.store.snapshot());
  const safe = await restarted.events.status(jarvis, {});
  assert.equal(safe.subscriptions[0].renewalCount, 2); assert.equal(safe.subscriptions[0].active, true);
  for (const secret of [f.subscription.delivery.url, f.subscription.delivery.secret, jarvis.principalKey]) assert.equal(JSON.stringify(safe).includes(secret), false);
  await assert.rejects(f.events.status(friday, {}), /insufficient_scope/);
  await f.store.transaction(s => { s.resourceDenials = { [jarvis.principalKey]: { status: 'denied' } }; });
  await assert.rejects(f.events.subscribe(who('jarvis', start + 10800000), f.subscription), /access_revoked/);
});

async function runtimeFixture(changes = {}) {
  let document = emptyState(), sends = [], failQueue = false, now = Date.now(), consumer;
  const posts = [];
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  class Pool { on() {} async connect() { return { release() {}, async query(sql, params) {
    if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(document) }] };
    if (sql.startsWith('UPDATE rn_bridge_runtime')) document = JSON.parse(params[0]);
    return { rows: [] };
  } }; } }
  const env = { BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture', BRIDGE_DELIVERY_ENABLED: 'true',
    BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
    DATABASE_URL: 'postgresql://fixture.neon.tech/neondb?sslmode=require',
    BRIDGE_DAILY_ENABLED: 'true', BRIDGE_DAILY_RECEIVER_POLICY: 'inbox-v1', FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true',
    FRIDAY_RECEIVER_ID: 'jarvis-friday-test-receiver', FRIDAY_WEBHOOK_URL: 'https://receiver.example.test/event', FRIDAY_WEBHOOK_KEY: 'FIXTURE_ONLY', ...changes };
  const rt = createRuntime({ env, Pool, keyResolver: publicKey, clock: () => now,
    queueClient: { async send(...args) { if (failQueue) throw Error('FIXTURE_PRIVATE'); sends.push(args); },
      handleCallback(fn) { consumer = fn; return fn; } },
    transportFactory: () => async (_url, req) => { const body = JSON.parse(req.body); posts.push(body);
      return { status: 200, body: JSON.stringify({ challenge: body.challenge }) }; } });
  const tokens = {};
  for (const role of ['jarvis', 'friday']) tokens[role] = await new SignJWT({ scope: Object.values(SCOPES[role]).join(' ') })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject('fixture').setAudience(resourceFor(role)).setIssuedAt().setExpirationTime('2h').sign(privateKey);
  const rpc = async (role, method, params) => {
    const response = await rt.handler(role)(new Request(resourceFor(role), { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tokens[role] },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })); return { status: response.status, body: await response.json() };
  };
  return { rpc, sends, posts, env, advance: n => { now += n; },
    async consume(payload) { rt.queueHandler(); return consumer(payload, { topicName: TOPIC, region: 'iad1', deliveryCount: 1 }); },
    document: () => document, setQueueFailure: value => { failQueue = value; },
    message: () => ({ protocol: MESSAGE_PROTOCOL, id: randomUUID(), from: 'jarvis', to: 'friday', kind: 'message', sentAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 3600000).toISOString(), threadId: randomUUID(), route: 'inbox', text: 'Fixture request data' }) };
}

test('real runtime daily gates require reviewed policy and contract independently of expired synthetic configuration', async () => {
  for (const env of [{ BRIDGE_DELIVERY_ENABLED: 'false' }, { BRIDGE_DAILY_RECEIVER_POLICY: '' }, { FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'false' }]) {
    const f = await runtimeFixture(env), m = f.message();
    const denied = await f.rpc('jarvis', 'tools/call', { name: 'bridge_message_send', arguments: m });
    assert.equal(denied.status, 503); assert.equal(Object.keys(f.document().messages).length, 0); assert.equal(f.sends.length, 0);
  }
  const f = await runtimeFixture({ FRIDAY_TEST_AUTHORIZED_UNTIL: '2020-01-01T00:00:00Z', FRIDAY_CONTRACT_PROBE_MESSAGE_ID: 'invalid' });
  const list = await f.rpc('jarvis', 'tools/list');
  assert.ok(list.body.result.tools.some(t => t.name === 'bridge_message_send'));
  assert.ok(list.body.result.tools.some(t => t.name === 'bridge_subscription_status'));
  const m = f.message(), sent = await f.rpc('jarvis', 'tools/call', { name: 'bridge_message_send', arguments: m });
  assert.equal(sent.status, 200); assert.equal(sent.body.result.structuredContent.scheduling, 'requested');
  assert.equal(f.sends[0][0], TOPIC); assert.deepEqual(Object.keys(f.sends[0][1]), ['cleanupMessageId']);
  assert.deepEqual(Object.keys(f.sends[1][1]), ['dispatchMessageId']);
  assert.deepEqual(Object.keys(f.sends[2][1]), ['jobId']);
  assert.equal((await f.rpc('jarvis', 'tools/call', { name: 'bridge_read', arguments: { messageId: m.id } })).status, 200);
  // A missing incoming message is an explicit MCP tool error, never a body leak.
  assert.equal((await f.rpc('jarvis', 'tools/call', { name: 'bridge_read', arguments: { messageId: m.id } })).body.result.isError, true);
  const read = await f.rpc('friday', 'tools/call', { name: 'bridge_read', arguments: { messageId: m.id } });
  assert.equal(read.body.result.structuredContent.envelope.text, m.text);
  assert.equal((await f.rpc('jarvis', 'tools/call', { name: 'bridge_send', arguments: {} })).status, 403);
});

test('daily prearmed queue failure stores no content; retry creates one identity and dispatch survives later scheduling failure', async () => {
  const f = await runtimeFixture(), m = f.message(); f.setQueueFailure(true);
  const response = await f.rpc('jarvis', 'tools/call', { name: 'bridge_message_send', arguments: m });
  assert.equal(response.status, 503);
  assert.equal(Object.keys(f.document().messages).length, 0); assert.equal(f.sends.length, 0);
  assert.equal(JSON.stringify(response).includes('FIXTURE_PRIVATE'), false);
  f.setQueueFailure(false);
  const retry = await f.rpc('jarvis', 'tools/call', { name: 'bridge_message_send', arguments: m });
  assert.equal(retry.body.result.structuredContent.duplicate, false); assert.equal(retry.body.result.structuredContent.scheduling, 'requested');
  assert.equal(Object.keys(f.document().messages).length, 1); assert.equal(Object.keys(f.document().jobs).length, 1); assert.equal(f.sends.length, 3);
});

test('prearmed native dispatcher survives an early callback/restart and queued cleanup removes idle content with delivery off', async () => {
  const { createQueueAdapter } = await import('../src/queue.mjs');
  const f = fixture(), published = [], m = f.message();
  const metadata = { topicName: TOPIC, region: 'iad1', deliveryCount: 1 };
  const adapter = createQueueAdapter({ store: f.store, clock: f.clock, enabled: true, maintenanceEnabled: true,
    client: { async send(...args) { published.push(args); } }, worker: { async run(id) { await f.store.transaction(s => { s.jobs[id].state = 'accepted'; }); } } });
  await adapter.prepareMessage(m.id);
  assert.equal(published[0][2].delaySeconds, 86400);
  assert.deepEqual(published[1][1], { dispatchMessageId: m.id });
  await assert.rejects(adapter.consume(published[1][1], metadata), /bridge_job_pending/);
  await f.bridge.sendMessage(jarvis, m);
  await adapter.consume(published[1][1], metadata);
  assert.equal(Object.values(f.store.snapshot().jobs)[0].state, 'accepted');
  f.advance(CONTENT_RETENTION_MS);
  let transport = 0;
  const restarted = createQueueAdapter({ store: new MemoryStore(f.store.snapshot()), clock: f.clock,
    enabled: false, maintenanceEnabled: true, client: { async send(...args) { published.push(args); } },
    worker: { async run() { transport++; } } });
  // Also exercise the actual original store so deletion is observable.
  const off = createQueueAdapter({ store: f.store, clock: f.clock, enabled: false, maintenanceEnabled: true,
    client: { async send(...args) { published.push(args); } }, worker: { async run() { transport++; } } });
  await restarted.consume({ cleanupMessageId: m.id }, metadata);
  await off.consume({ cleanupMessageId: m.id }, metadata);
  assert.equal(transport, 0); assert.equal(f.store.snapshot().messages[m.id], undefined);
  assert.ok(f.store.snapshot().messageIds[m.id]);
  assert.ok(published.at(-1)[2].delaySeconds > 5 * 86400);
  f.advance(IDEMPOTENCY_RETENTION_MS);
  await off.consume({ cleanupMessageId: m.id }, metadata);
  assert.equal(f.store.snapshot().messageIds[m.id], undefined);
  await assert.rejects(off.consume({ dispatchMessageId: m.id }, metadata), /queue_not_enabled/);
});

test('prearmed ACK dispatcher waits for atomic completion and ACK content shares the original retention deadline', async () => {
  const { createQueueAdapter } = await import('../src/queue.mjs');
  const f = fixture(); await f.events.subscribe(jarvis, f.subscription);
  const m = f.message(); await f.bridge.sendMessage(jarvis, m);
  const metadata = { topicName: TOPIC, region: 'iad1', deliveryCount: 1 };
  let published;
  const adapter = createQueueAdapter({ store: f.store, clock: f.clock, enabled: true,
    client: { async send(_topic, payload) { published = payload; } }, worker: { async run(id) {
      await f.store.transaction(s => { s.jobs[id].state = 'accepted'; });
    } } });
  await adapter.prepareReceipt(m.id);
  await assert.rejects(adapter.consume(published, metadata), /bridge_job_pending/);
  f.advance(1000);
  const claim = await f.bridge.claim(friday, { messageId: m.id });
  const done = await complete(f.bridge, friday, m.id, claim.claimId);
  await adapter.consume(published, metadata);
  const s = f.store.snapshot();
  assert.equal(s.messages[done.ackMessageId].retainUntil, s.messages[m.id].retainUntil);
  assert.equal(s.messageIds[done.ackMessageId].until, s.messageIds[m.id].until);
  assert.equal(s.jobs[s.messages[done.ackMessageId].jobIds[0]].state, 'accepted');
});

test('daily admission bounds prearmed queue work before publication, including failed publication retries', async () => {
  const f = fixture(); let publishes = 0;
  const bridge = new Bridge({ store: f.store, clock: f.clock, dailyEnabled: true,
    messagePolicyIds: { jarvis: policy, friday: policy }, prepareMessage: async () => { publishes++; throw Error('fixture publish failure'); } });
  for (let i = 0; i < 10; i++) await assert.rejects(bridge.sendMessage(jarvis, f.message()), /fixture publish failure/);
  await assert.rejects(bridge.sendMessage(jarvis, f.message()), /probe_rate_limited/);
  assert.equal(publishes, 10); assert.equal(Object.keys(f.store.snapshot().messages).length, 0);
  assert.equal(Object.keys(f.store.snapshot().messagePreparations).length, 10);
});

test('preparation dispatch keys rotate before a missing-commit retry budget can exhaust', async () => {
  const { createQueueAdapter } = await import('../src/queue.mjs');
  const f = fixture(), keys = [], id = randomUUID();
  const adapter = createQueueAdapter({ store: f.store, enabled: true, clock: f.clock,
    client: { async send(_topic, _payload, options) { keys.push(options.idempotencyKey); } } });
  await adapter.prepareMessage(id); await adapter.prepareReceipt(id);
  f.advance(120000);
  await adapter.prepareMessage(id); await adapter.prepareReceipt(id);
  assert.notEqual(keys[1], keys[4]); assert.notEqual(keys[2], keys[5]);
});

test('real runtime delivers daily source and native signed ACK, then retains cleanup access during a global shutdown', async () => {
  const f = await runtimeFixture();
  const subscription = await f.rpc('jarvis', 'events/subscribe', { name: 'bridge.message.received', arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  assert.ok(subscription.body.result.id);
  const m = f.message();
  await f.rpc('jarvis', 'tools/call', { name: 'bridge_message_send', arguments: m });
  await f.consume({ dispatchMessageId: m.id });
  assert.ok(f.posts.some(body => body.event === 'bridge.message.received' && body.data.messageId === m.id));
  const claim = await f.rpc('friday', 'tools/call', { name: 'bridge_receipt_claim', arguments: { messageId: m.id } });
  const done = await f.rpc('friday', 'tools/call', { name: 'bridge_receipt_complete', arguments: { messageId: m.id,
    claimId: claim.body.result.structuredContent.claimId, hostedEventId: null, hostedTurnId: null } });
  const ackId = done.body.result.structuredContent.ackMessageId;
  await f.consume({ dispatchReceiptOf: m.id });
  assert.ok(f.posts.some(body => body.name === 'bridge.message.received' && body.data.messageId === ackId));
  const status = await f.rpc('jarvis', 'tools/call', { name: 'bridge_subscription_status', arguments: {} });
  assert.equal(status.body.result.structuredContent.subscriptions[0].active, true);
  const before = f.posts.length;
  f.env.BRIDGE_DELIVERY_ENABLED = 'false';
  await assert.rejects(f.consume({ dispatchMessageId: m.id }), /delivery_not_enabled/);
  f.advance(CONTENT_RETENTION_MS + 1000);
  await f.consume({ cleanupMessageId: m.id });
  assert.equal(f.document().messages[m.id], undefined); assert.equal(f.document().messages[ackId], undefined);
  assert.equal(f.posts.length, before);
});

test('future-skew completion caps ACK lifetime while preserving the receiver JWT authority limit', async () => {
  const f = fixture(); await f.events.subscribe(jarvis, f.subscription);
  const m = f.message('jarvis', { sentAt: new Date(start + 60000).toISOString(), expiresAt: new Date(start + 3660000).toISOString() });
  const receiver = who('friday', start + 30000);
  await f.bridge.sendMessage(jarvis, m);
  const claim = await f.bridge.claim(receiver, { messageId: m.id });
  const done = await complete(f.bridge, receiver, m.id, claim.claimId);
  const ack = (await f.bridge.read(jarvis, { messageId: done.ackMessageId })).envelope;
  assert.equal(ack.sentAt, new Date(start).toISOString());
  assert.equal(ack.expiresAt, new Date(start + 3600000).toISOString());
  assert.ok(Date.parse(ack.expiresAt) <= Date.parse(m.expiresAt));
  assert.equal(f.store.snapshot().messages[ack.id].authorization.expiresAt, start + 30000);
  const ackClaim = await f.bridge.claim(jarvis, { messageId: ack.id });
  assert.equal((await complete(f.bridge, jarvis, ack.id, ackClaim.claimId)).ackMessageId, null);
});
