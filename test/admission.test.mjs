import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { Bridge } from '../src/bridge.mjs';
import { MemoryStore } from '../src/store.mjs';
import { BridgeError, SCOPES, VERIFIED_AUTHORIZATION } from '../src/policy.mjs';
import { NativeEvents } from '../src/events.mjs';
import { createProtector } from '../src/webhook.mjs';
import { createMcpHandler } from './fixtures/rollback-mcp.mjs';

const start = Date.UTC(2026, 9, 19);
const policyId = 'c'.repeat(64);
const principal = role => Object.defineProperty({ role, scopes: Object.values(SCOPES[role]),
  principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64) }, VERIFIED_AUTHORIZATION,
  { value: { policyId, expiresAt: start + 86400000 } });
const jarvis = principal('jarvis'), friday = principal('friday');
const code = (name, status) => e => e instanceof BridgeError && e.code === name && e.status === status;
function fixture(snapshot) {
  let time = start;
  const store = new MemoryStore(snapshot), clock = () => time;
  return { store, clock, bridge: new Bridge({ store, clock, messagePolicyIds: { jarvis: policyId, friday: policyId } }), advance: ms => { time += ms; },
    probe: (role = 'jarvis', extra = {}) => ({ id: randomUUID(), testId: 'RN-JARVIS-FRIDAY-SYNTHETIC',
      from: role, to: role === 'jarvis' ? 'friday' : 'jarvis', kind: 'probe',
      sentAt: new Date(time).toISOString(), marker: 'RN-SYNTHETIC-NO-ACTIONS', ...extra }) };
}
async function subscribe(f) {
  const events = new NativeEvents({ store: f.store, clock: f.clock, policyId, enabled: true,
    protector: createProtector(randomBytes(32)), transport: async (_url, request) => ({ status: 200,
      body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) }) });
  await events.subscribe(jarvis, { name: 'bridge.message.received', arguments: { recipient: 'jarvis' },
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events',
      secret: 'whsec_' + randomBytes(32).toString('base64') } });
}
async function fill(f, who = jarvis) {
  const probes = Array.from({ length: 10 }, () => f.probe(who.role));
  for (const p of probes) await f.bridge.send(who, p);
  return probes;
}

test('concurrent fresh IDs share one durable budget across bridge instances and restart', async () => {
  const f = fixture();
  const other = new Bridge({ store: f.store, clock: f.clock });
  const outcomes = await Promise.allSettled(Array.from({ length: 40 }, (_, i) =>
    (i % 2 ? other : f.bridge).send(jarvis, f.probe())));
  assert.equal(outcomes.filter(x => x.status === 'fulfilled').length, 10);
  for (const x of outcomes.filter(x => x.status === 'rejected')) assert.ok(code('message_rate_limited', 429)(x.reason));
  const snapshot = f.store.snapshot();
  assert.equal(Object.keys(snapshot.messages).length, 10);
  assert.equal(Object.keys(snapshot.jobs).length, 10);
  assert.equal(snapshot.probeAdmissions.jarvis.length, 10);
  const restarted = fixture(snapshot);
  await assert.rejects(restarted.bridge.send(jarvis, restarted.probe()), code('message_rate_limited', 429));
});

test('rolling admission expires each entry at 60 seconds without a fixed-window double burst', async () => {
  const f = fixture();
  for (let i = 0; i < 5; i++) await f.bridge.send(jarvis, f.probe());
  f.advance(30000);
  for (let i = 0; i < 5; i++) await f.bridge.send(jarvis, f.probe());
  f.advance(29999);
  await assert.rejects(f.bridge.send(jarvis, f.probe()), code('message_rate_limited', 429));
  f.advance(1);
  for (let i = 0; i < 5; i++) await f.bridge.send(jarvis, f.probe());
  await assert.rejects(f.bridge.send(jarvis, f.probe()), code('message_rate_limited', 429));
  assert.equal(f.store.snapshot().probeAdmissions.jarvis.length, 10);
});

test('exact duplicates bypass a full budget, survive freshness expiry, and conflicts remain conflicts', async () => {
  const f = fixture(); const probes = await fill(f);
  const snapshot = f.store.snapshot();
  const reordered = Object.fromEntries(Object.entries(probes[0]).reverse());
  const duplicates = await Promise.all(Array.from({ length: 15 }, () => f.bridge.send(jarvis,
    { ...reordered, id: reordered.id.toUpperCase() })));
  assert.ok(duplicates.every(x => x.duplicate));
  await assert.rejects(f.bridge.send(jarvis, { ...probes[0], sentAt: new Date(start + 1).toISOString() }),
    code('message_id_conflict', 409));
  assert.deepEqual(f.store.snapshot(), snapshot);
  f.advance(300001);
  assert.equal((await f.bridge.send(jarvis, probes[0])).duplicate, true);
  assert.deepEqual(f.store.snapshot(), snapshot);
});

test('invalid envelopes and failed insertion do not spend admission or create jobs', async () => {
  const f = fixture();
  await assert.rejects(f.bridge.send(jarvis, f.probe('jarvis', { unexpected: 'data' })), code('invalid_envelope', 400));
  await assert.rejects(f.bridge.send({ ...jarvis, scopes: [] }, f.probe()), code('insufficient_scope', 403));
  await assert.rejects(f.bridge.send(friday, f.probe('friday')), code('recipient_subscription_required', 503));
  assert.equal(f.store.snapshot().probeAdmissions, undefined);
  assert.deepEqual(f.store.snapshot().messages, {});
  assert.deepEqual(f.store.snapshot().jobs, {});
  await fill(f);
});

test('sender roles have independent bounded budgets and receipt ACKs do not consume probe admission', async () => {
  const f = fixture(); await subscribe(f);
  const probes = await fill(f);
  await fill(f, friday);
  for (const who of [jarvis, friday]) {
    await assert.rejects(f.bridge.send(who, f.probe(who.role)), code('message_rate_limited', 429));
  }
  const budgets = f.store.snapshot().probeAdmissions;
  const claim = await f.bridge.claim(friday, { messageId: probes[0].id });
  const completed = await f.bridge.complete(friday, { messageId: probes[0].id, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null });
  assert.ok(completed.ackMessageId);
  assert.deepEqual(f.store.snapshot().probeAdmissions, budgets);
  const ackClaim = await f.bridge.claim(jarvis, { messageId: completed.ackMessageId });
  const ackReceipt = await f.bridge.complete(jarvis, { messageId: completed.ackMessageId,
    claimId: ackClaim.claimId, hostedEventId: null, hostedTurnId: null });
  assert.equal(ackReceipt.ackMessageId, null);
  assert.equal(Object.values(f.store.snapshot().messages).filter(m => m.envelope.kind === 'ack').length, 1);
  assert.deepEqual(Object.keys(budgets).sort(), ['friday', 'jarvis']);
});

test('authenticated MCP surfaces 429 without scheduling another job, and duplicate retry still succeeds', async () => {
  const f = fixture(); const probes = await fill(f); let schedules = 0;
  const handler = createMcpHandler({ enabled: true, verify: async () => jarvis, bridge: f.bridge, events: {},
    scheduleJobs: async () => { schedules++; } });
  const call = input => handler(new Request('https://bridge.example.test/mcp', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1,
      method: 'tools/call', params: { name: 'bridge_send', arguments: input } }) }));
  const limited = await call(f.probe());
  assert.equal(limited.status, 429);
  assert.equal((await limited.json()).error.message, 'message_rate_limited');
  assert.equal(schedules, 0);
  const duplicate = await call(probes[0]);
  assert.equal(duplicate.status, 200);
  assert.equal((await duplicate.json()).result.structuredContent.duplicate, true);
});
