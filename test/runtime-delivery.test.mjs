import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { Webhook } from 'standardwebhooks';
import { createRuntime } from '../src/runtime.mjs';
import { emptyState } from '../src/store.mjs';
import { ISSUER, resourceFor } from '../src/resource.mjs';
import { SCOPES } from '../src/policy.mjs';
import { TOPIC } from '../src/queue.mjs';

// Fully offline native-protocol/crypto integration. FakePool and transports
// never connect; no provider token, endpoint or credential is used or printed.
const probeId = '00000000-0000-4000-8000-000000000021';
async function fixture(overrides = {}, initial = {}) {
  let time = Date.now(), document = structuredClone(initial.document || emptyState());
  const clock = () => time, queue = [], calls = [], key = initial.key || 'whsec_' + randomBytes(32).toString('base64');
  const env = { BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture-subject',
    BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'), BRIDGE_SUBSCRIPTIONS_ENABLED: 'true',
    BRIDGE_DELIVERY_ENABLED: 'true', DATABASE_URL: 'postgresql://fixture.neon.tech/neondb?sslmode=require',
    FRIDAY_WEBHOOK_URL: 'https://receiver.example.test/hook', FRIDAY_WEBHOOK_KEY: 'FIXTURE_NOT_A_REAL_KEY',
    FRIDAY_RECEIVER_ID: 'jarvis-friday-test-receiver', FRIDAY_TEST_AUTHORIZED_UNTIL: new Date(time + 3600000).toISOString(),
    FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'false', FRIDAY_CONTRACT_PROBE_MESSAGE_ID: probeId, ...overrides };
  class FakePool {
    on() {} async end() {}
    async connect() { return { release() {}, async query(sql, params) {
      if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(document) }] };
      if (sql.startsWith('UPDATE rn_bridge_runtime')) document = JSON.parse(params[0]);
      return { rows: [] };
    } }; }
  }
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const rt = createRuntime({ env, Pool: FakePool, clock, keyResolver: publicKey,
    queueClient: { async send(_topic, item) { queue.push(item.jobId); }, handleCallback: fn => fn },
    transportFactory: () => async (url, request) => {
      const body = JSON.parse(request.body);
      if (body.type === 'verification') return { status: 200, body: JSON.stringify({ challenge: body.challenge }) };
      if (url === env.FRIDAY_WEBHOOK_URL) {
        assert.equal(request.headers.authorization, 'Bearer ' + env.FRIDAY_WEBHOOK_KEY);
        const id = body.data?.messageId, envelope = document.messages[id]?.envelope;
        assert.deepEqual(body, { event: 'bridge.message.received', data: { messageId: id } });
        assert.equal(envelope?.to, 'friday');
        assert.equal(envelope.kind === 'probe' ? id : envelope.correlationId, env.FRIDAY_CONTRACT_PROBE_MESSAGE_ID);
      } else new Webhook(key).verify(request.body, request.headers);
      calls.push({ recipient: url === env.FRIDAY_WEBHOOK_URL ? 'friday' : 'jarvis', body });
      return { status: 202, body: '' };
    } });
  const tokens = {};
  for (const role of ['jarvis', 'friday']) tokens[role] = await new SignJWT({ scope: Object.values(SCOPES[role]).join(' ') })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setAudience(resourceFor(role)).setSubject('fixture-subject')
    .setIssuedAt(Math.floor(time / 1000)).setExpirationTime(Math.floor(time / 1000) + 86400).sign(privateKey);
  const rpc = async (role, method, params) => {
    const response = await rt.handler(role)(new Request(resourceFor(role), { method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tokens[role] },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
    return { status: response.status, ...(await response.json()) };
  };
  const tool = (role, name, args = {}) => rpc(role, 'tools/call', { name, arguments: args });
  const subscribe = () => rpc('jarvis', 'events/subscribe', { name: 'bridge.message.received',
    arguments: { recipient: 'jarvis' }, delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: key }, ttlMs: null });
  const probe = (extra = {}) => ({ id: probeId, testId: 'RN-JARVIS-FRIDAY-SYNTHETIC', from: 'jarvis', to: 'friday',
    kind: 'probe', sentAt: new Date(time).toISOString(), marker: 'RN-SYNTHETIC-NO-ACTIONS', ...extra });
  const consume = id => rt.queueHandler()({ jobId: id }, { topicName: TOPIC, region: 'iad1', deliveryCount: 1 });
  return { rt, env, clock, tokens, queue, calls, rpc, tool, subscribe, probe, consume, key,
    state: () => structuredClone(document), advance: ms => { time += ms; } };
}

test('real runtime wiring admits one declared probe and its single correlated ACK through both scoped native resources', async () => {
  const f = await fixture(); await f.subscribe();
  const health = (await f.tool('jarvis', 'bridge_health')).result.structuredContent.readiness;
  assert.equal(health.deliveryEnabled, true); assert.equal(health.fridayProbeModeConfigured, true);
  assert.equal(health.fridayContractVerified, false);
  const sent = await f.tool('jarvis', 'bridge_send', f.probe());
  assert.equal(sent.status, 200); assert.equal(f.queue.length, 1);
  await f.consume(f.queue[0]); assert.equal(f.calls[0].recipient, 'friday');
  const status = (await f.tool('jarvis', 'bridge_status', { messageId: probeId })).result.structuredContent;
  assert.equal(status.deliveries[0].firstTransportOutcome.status, 202);
  assert.equal(status.deliveries[0].transportAttempts, 1); assert.equal(status.wakeVerified, false);
  const read = (await f.tool('friday', 'bridge_read', { messageId: probeId })).result.structuredContent;
  assert.equal(read.envelope.id, probeId); assert.equal('authorization' in read, false);
  const claim = (await f.tool('friday', 'bridge_receipt_claim', { messageId: probeId })).result.structuredContent;
  const complete = (await f.tool('friday', 'bridge_receipt_complete', { messageId: probeId, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null })).result.structuredContent;
  assert.ok(complete.ackMessageId); assert.equal(f.queue.length, 2);
  await f.consume(f.queue[1]); assert.equal(f.calls[1].recipient, 'jarvis');
  assert.equal(f.calls[1].body.data.messageId, complete.ackMessageId);
  const ackClaim = (await f.tool('jarvis', 'bridge_receipt_claim', { messageId: complete.ackMessageId })).result.structuredContent;
  const terminal = (await f.tool('jarvis', 'bridge_receipt_complete', { messageId: complete.ackMessageId,
    claimId: ackClaim.claimId, hostedEventId: null, hostedTurnId: null })).result.structuredContent;
  assert.equal(terminal.ackMessageId, null); assert.equal(f.queue.length, 2);
  const state = f.state();
  assert.equal(state.messages[probeId].authorization.scope, 'bridge:send:friday');
  assert.equal(state.messages[complete.ackMessageId].authorization.scope, 'bridge:ack:friday');
  assert.notEqual(state.messages[probeId].authorization.policyId, state.messages[complete.ackMessageId].authorization.policyId);
  for (const token of Object.values(f.tokens)) assert.equal(JSON.stringify(state).includes(token), false);
});

test('restarting in probe mode blocks unrelated queued Jarvis probes and ACKs but delivers the pinned correlated ACK', async () => {
  const oldFridayId = '00000000-0000-4000-8000-000000000022';
  let previous = await fixture({ FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true',
    BRIDGE_TEST_PROBE_SENDER: 'friday', FRIDAY_CONTRACT_PROBE_MESSAGE_ID: oldFridayId });
  await previous.subscribe();
  const oldFridayProbe = await previous.tool('friday', 'bridge_send', previous.probe({
    id: oldFridayId, from: 'friday', to: 'jarvis' }));
  assert.equal(oldFridayProbe.status, 200);
  const unrelatedId = '00000000-0000-4000-8000-000000000023';
  const firstWindow = previous; await firstWindow.rt.close();
  previous = await fixture({ ...firstWindow.env, BRIDGE_TEST_PROBE_SENDER: 'jarvis',
    FRIDAY_CONTRACT_PROBE_MESSAGE_ID: unrelatedId }, { document: firstWindow.state(), key: firstWindow.key });
  assert.equal((await previous.tool('jarvis', 'bridge_send', previous.probe({ id: unrelatedId }))).status, 200);
  const oldClaim = (await previous.tool('friday', 'bridge_receipt_claim', { messageId: unrelatedId })).result.structuredContent;
  const oldAck = (await previous.tool('friday', 'bridge_receipt_complete', { messageId: unrelatedId,
    claimId: oldClaim.claimId, hostedEventId: null, hostedTurnId: null })).result.structuredContent;
  assert.ok(oldAck.ackMessageId);
  const snapshot = previous.state(); await previous.rt.close();

  // Existing valid message authority, callback protector and active native
  // lease survive deployment, but the new phase grants only the pinned pair.
  const f = await fixture({ ...previous.env, FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'false',
    FRIDAY_CONTRACT_PROBE_MESSAGE_ID: probeId },
    { document: snapshot, key: previous.key });
  const blocked = [...snapshot.messages['00000000-0000-4000-8000-000000000022'].jobIds,
    ...snapshot.messages[oldAck.ackMessageId].jobIds];
  for (const id of blocked) {
    assert.equal(snapshot.jobs[id].recipient, 'jarvis');
    await f.consume(id);
    assert.equal(f.state().jobs[id].state, 'dead');
    assert.equal(f.state().jobs[id].lastError, 'message_authorization_inactive');
  }
  assert.equal(f.calls.length, 0);

  await f.tool('jarvis', 'bridge_send', f.probe());
  await f.consume(f.queue[0]); assert.equal(f.calls[0].recipient, 'friday');
  const claim = (await f.tool('friday', 'bridge_receipt_claim', { messageId: probeId })).result.structuredContent;
  const ack = (await f.tool('friday', 'bridge_receipt_complete', { messageId: probeId,
    claimId: claim.claimId, hostedEventId: null, hostedTurnId: null })).result.structuredContent;
  assert.ok(ack.ackMessageId); await f.consume(f.queue[1]);
  assert.equal(f.calls[1].recipient, 'jarvis'); assert.equal(f.calls[1].body.data.messageId, ack.ackMessageId);
  assert.equal(f.state().jobs[f.queue[1]].state, 'accepted');
});

test('verified transport remains pinned in either direction and admits only its correlated ACK through the real runtime', async () => {
  for (const sender of ['friday', 'jarvis']) {
    const recipient = sender === 'friday' ? 'jarvis' : 'friday';
    const f = await fixture({ FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true', BRIDGE_TEST_PROBE_SENDER: sender });
    await f.subscribe();
    const health = (await f.tool('jarvis', 'bridge_health')).result.structuredContent.readiness;
    assert.equal(health.testDeliveryPinned, true); assert.equal(health.fridayContractVerified, true);
    for (const [role, input] of [[recipient, f.probe({ from: recipient, to: sender })],
      [sender, f.probe({ from: sender, to: recipient, id: '00000000-0000-4000-8000-000000000024' })]]) {
      const denied = await f.tool(role, 'bridge_send', input);
      assert.equal(denied.status, 403); assert.equal(denied.error.message, 'contract_probe_only');
    }
    assert.deepEqual(f.state().messages, {}); assert.equal(f.queue.length, 0);
    const sent = await f.tool(sender, 'bridge_send', f.probe({ from: sender, to: recipient }));
    assert.equal(sent.status, 200); await f.consume(f.queue[0]);
    assert.equal(f.calls[0].recipient, recipient);
    const read = (await f.tool(recipient, 'bridge_read', { messageId: probeId })).result.structuredContent;
    assert.equal(read.envelope.from, sender);
    const claim = (await f.tool(recipient, 'bridge_receipt_claim', { messageId: probeId })).result.structuredContent;
    const complete = (await f.tool(recipient, 'bridge_receipt_complete', { messageId: probeId,
      claimId: claim.claimId, hostedEventId: null, hostedTurnId: null })).result.structuredContent;
    assert.ok(complete.ackMessageId); await f.consume(f.queue[1]);
    assert.equal(f.calls[1].recipient, sender);
    const ack = f.state().messages[complete.ackMessageId].envelope;
    assert.equal(ack.kind, 'ack'); assert.equal(ack.correlationId, probeId); assert.equal(ack.to, sender);
    const ackClaim = (await f.tool(sender, 'bridge_receipt_claim', { messageId: ack.id })).result.structuredContent;
    const terminal = (await f.tool(sender, 'bridge_receipt_complete', { messageId: ack.id,
      claimId: ackClaim.claimId, hostedEventId: null, hostedTurnId: null })).result.structuredContent;
    assert.equal(terminal.ackMessageId, null); assert.equal(f.queue.length, 2);
  }
});

test('verified transport without a pin, invalid sender or unverified Friday-origin scope stays disabled', async () => {
  for (const extra of [
    { FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true', FRIDAY_CONTRACT_PROBE_MESSAGE_ID: '' },
    { FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true', BRIDGE_TEST_PROBE_SENDER: '' },
    { FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true', BRIDGE_TEST_PROBE_SENDER: 'other' },
    { FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'false', BRIDGE_TEST_PROBE_SENDER: 'friday' },
  ]) {
    const f = await fixture(extra);
    const health = (await f.tool('jarvis', 'bridge_health')).result.structuredContent.readiness;
    assert.equal(health.deliveryEnabled, false); assert.equal(health.testDeliveryPinned, false);
    assert.equal((await f.tool('jarvis', 'bridge_send', f.probe())).status, 503);
    assert.equal(f.queue.length, 0); assert.equal(f.calls.length, 0);
  }
});

test('probe phase rejects other new IDs and Friday-originated probes before any delivery', async () => {
  const f = await fixture();
  for (const [role, input] of [['jarvis', f.probe({ id: '00000000-0000-4000-8000-000000000022' })],
    ['friday', f.probe({ from: 'friday', to: 'jarvis' })]]) {
    const response = await f.tool(role, 'bridge_send', input);
    assert.equal(response.status, 403); assert.equal(response.error.message, 'contract_probe_only');
  }
  assert.deepEqual(f.state().messages, {}); assert.equal(f.queue.length, 0); assert.equal(f.calls.length, 0);
});

test('missing or overlong operator authority, wrong receiver or absent candidate keeps runtime delivery closed', async () => {
  for (const extra of [{ FRIDAY_RECEIVER_ID: 'other-receiver' }, { FRIDAY_TEST_AUTHORIZED_UNTIL: '' },
    { FRIDAY_TEST_AUTHORIZED_UNTIL: new Date(Date.now() + 7 * 3600000).toISOString() },
    { FRIDAY_CONTRACT_PROBE_MESSAGE_ID: '' }, { FRIDAY_WEBHOOK_KEY: 'bad\nkey' }]) {
    const f = await fixture(extra);
    assert.equal((await f.tool('jarvis', 'bridge_health')).result.structuredContent.readiness.deliveryEnabled, false);
    assert.equal((await f.tool('jarvis', 'bridge_send', f.probe())).status, 503);
    assert.equal(f.calls.length, 0); assert.equal(f.queue.length, 0);
  }
});

test('expiry or disabling global delivery stops queued callback dispatch before transport', async () => {
  for (const mode of ['expiry', 'flag']) {
    const f = await fixture(); await f.tool('jarvis', 'bridge_send', f.probe());
    if (mode === 'expiry') f.advance(3600001); else f.env.BRIDGE_DELIVERY_ENABLED = 'false';
    await assert.rejects(f.consume(f.queue[0]), e => e.code === 'delivery_not_enabled');
    assert.equal(f.calls.length, 0);
    assert.equal((await f.tool('jarvis', 'bridge_health')).result.structuredContent.readiness.subscriptionSetupEnabled, true);
  }
});
