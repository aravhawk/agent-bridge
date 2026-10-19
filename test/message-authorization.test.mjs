import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Bridge } from '../src/bridge.mjs';
import { MemoryStore } from '../src/store.mjs';
import { DeliveryWorker } from '../src/worker.mjs';
import { createFridaySender } from '../src/friday-sender.mjs';
import { VERIFIED_AUTHORIZATION } from '../src/policy.mjs';

const policyIds = { jarvis: 'c'.repeat(64), friday: 'd'.repeat(64) };
const error = code => e => e.code === code;
function fixture() {
  let time = 100000, calls = 0;
  const clock = () => time, store = new MemoryStore();
  const principal = (role, expiry = time + 1000) => Object.defineProperty({ role,
    principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64),
    scopes: role === 'jarvis' ? ['bridge:send:friday', 'bridge:ack:jarvis'] : ['bridge:send:jarvis', 'bridge:ack:friday'] },
  VERIFIED_AUTHORIZATION, { value: { policyId: policyIds[role], expiresAt: expiry } });
  const makeBridge = (options = {}) => new Bridge({ store, clock, messagePolicyIds: policyIds, ...options });
  const bridge = makeBridge(), sender = principal('jarvis'), receiver = principal('friday');
  const input = { id: randomUUID(), testId: 'RN-JARVIS-FRIDAY-SYNTHETIC', from: 'jarvis', to: 'friday',
    kind: 'probe', sentAt: new Date(time).toISOString(), marker: 'RN-SYNTHETIC-NO-ACTIONS' };
  const deny = () => store.transaction(s => { s.resourceDenials = { [sender.principalKey]: { status: 'denied' } }; });
  const worker = ({ duringTransport, ...options } = {}) => new DeliveryWorker({ store, clock, enabled: true,
    messagePolicyIds: policyIds, accessAllowed: async () => true,
    fridaySender: createFridaySender({ enabled: true, contractVerified: true,
      endpoint: 'https://receiver.example.test/hook', secret: 'FIXTURE_NOT_A_REAL_KEY',
      transport: async () => { calls++; await duringTransport?.(); return { status: 202 }; } }), ...options });
  return { store, clock, principal, sender, receiver, bridge, input, makeBridge, deny, worker,
    calls: () => calls, advance: ms => { time += ms; } };
}

test('missing or caller-shaped authorization cannot create a message, admission or delivery job', async () => {
  const f = fixture();
  for (const who of [{ ...f.sender }, { ...f.sender, VERIFIED_AUTHORIZATION: { policyId: policyIds.jarvis, expiresAt: 999999 } },
    Object.defineProperty({ ...f.sender }, Symbol('VERIFIED_AUTHORIZATION'), { value: { policyId: policyIds.jarvis, expiresAt: 999999 } })]) {
    await assert.rejects(f.bridge.send(who, f.input), error('message_authorization_required'));
    assert.deepEqual(f.store.snapshot().messages, {}); assert.deepEqual(f.store.snapshot().jobs, {});
    assert.equal(f.store.snapshot().probeAdmissions, undefined);
  }
});

test('expired, denied, legacy or mismatched source authority stops queued Friday work despite an allow-true adapter', async () => {
  for (const mutate of [
    (s, f) => f.advance(1001), (s, f) => { s.resourceDenials = { [f.sender.principalKey]: {} }; },
    s => { delete Object.values(s.messages)[0].authorization; },
    s => { Object.values(s.messages)[0].authorization.owner = 'invalid'; },
    s => { Object.values(s.messages)[0].authorization.role = 'friday'; },
    s => { Object.values(s.messages)[0].authorization.resource = 'https://unrelated.example.test'; },
    s => { Object.values(s.messages)[0].authorization.scope = 'bridge:send:jarvis'; },
    s => { Object.values(s.messages)[0].authorization.policyId = policyIds.friday; },
    s => { Object.values(s.messages)[0].authorization.expiresAt = 999999; },
    s => { Object.values(s.jobs)[0].recipient = 'jarvis'; },
    s => { Object.values(s.messages)[0].jobIds = []; },
  ]) {
    const f = fixture(), q = await f.bridge.send(f.sender, f.input);
    await f.store.transaction(s => mutate(s, f));
    assert.equal((await f.worker().run(q.jobIds[0])).attempted, false);
    const job = f.store.snapshot().jobs[q.jobIds[0]];
    assert.equal(job.state, 'dead'); assert.equal(job.lastError, 'message_authorization_inactive');
    assert.equal(f.calls(), 0); assert.equal(job.firstTransportOutcome, undefined);
  }
});

test('source expiry or durable denial during async access validation stops before transport', async () => {
  for (const mode of ['expiry', 'denial']) {
    const f = fixture(), q = await f.bridge.send(f.sender, f.input);
    const result = await f.worker({ accessAllowed: async () => {
      if (mode === 'expiry') f.advance(1001); else await f.deny(); return true;
    } }).run(q.jobIds[0]);
    assert.equal(result.transportAccepted, false); assert.equal(f.calls(), 0);
    assert.equal(f.store.snapshot().jobs[q.jobIds[0]].lastError, 'message_authorization_inactive');
  }
});

test('source expiry or denial in flight rejects acceptance while preserving the first HTTP evidence', async () => {
  for (const mode of ['expiry', 'denial']) {
    const f = fixture(), q = await f.bridge.send(f.sender, f.input);
    const result = await f.worker({ duringTransport: async () => {
      if (mode === 'expiry') f.advance(1001); else await f.deny();
    } }).run(q.jobIds[0]);
    const job = f.store.snapshot().jobs[q.jobIds[0]];
    assert.equal(result.transportAccepted, false); assert.equal(f.calls(), 1); assert.equal(job.state, 'dead');
    assert.equal(job.lastError, 'message_authorization_inactive'); assert.equal(job.transportAttempts, 1);
    assert.equal(job.firstTransportOutcome.status, 202); assert.equal(job.firstTransportOutcome.error, null);
  }
});

test('the original operator window caps source authority and duplicate fresh tokens cannot resurrect it', async () => {
  const f = fixture(), first = f.makeBridge({ deliveryUntil: f.clock() + 100 });
  const q = await first.send(f.sender, f.input), authorization = f.store.snapshot().messages[f.input.id].authorization;
  assert.equal(authorization.expiresAt, f.clock() + 100); assert.equal(authorization.tokenExpiresAt, f.clock() + 1000);
  f.advance(101);
  const later = f.makeBridge({ deliveryUntil: f.clock() + 10000 });
  assert.equal((await later.send(f.principal('jarvis', f.clock() + 10000), f.input)).duplicate, true);
  assert.deepEqual(f.store.snapshot().messages[f.input.id].authorization, authorization);
  assert.equal((await f.worker({ deliveryUntil: f.clock() + 10000 }).run(q.jobIds[0])).attempted, false);
  assert.equal(f.calls(), 0);
});

test('source expiry blocks receipt claim and completion without emitting a new ACK', async () => {
  for (const phase of ['claim', 'complete']) {
    const f = fixture(); await f.bridge.send(f.sender, f.input);
    const claim = phase === 'complete' ? await f.bridge.claim(f.receiver, { messageId: f.input.id }) : null;
    f.advance(1001);
    await assert.rejects(phase === 'claim' ? f.bridge.claim(f.receiver, { messageId: f.input.id })
      : f.bridge.complete(f.principal('friday'), { messageId: f.input.id, claimId: claim.claimId,
        hostedEventId: null, hostedTurnId: null }), error('message_authorization_inactive'));
    assert.equal(Object.keys(f.store.snapshot().messages).length, 1);
    assert.notEqual(f.store.snapshot().receipts[f.input.id]?.state, 'complete');
  }
});

test('one-probe mode blocks unrelated preexisting messages at read, claim and completion', async () => {
  const f = fixture(); await f.bridge.send(f.sender, f.input);
  const claim = await f.bridge.claim(f.receiver, { messageId: f.input.id });
  const scoped = f.makeBridge({ probeMessageId: randomUUID() });
  for (const operation of [() => scoped.read(f.receiver, { messageId: f.input.id }),
    () => scoped.claim(f.receiver, { messageId: f.input.id }),
    () => scoped.complete(f.receiver, { messageId: f.input.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null })])
    await assert.rejects(operation(), error('contract_probe_only'));
  assert.notEqual(f.store.snapshot().receipts[f.input.id].state, 'complete');
});

// Model an asynchronous pool/row-lock wait before acquiring the synchronous
// state transition. No storage callback itself is asynchronous.
function waitingTransaction(store) {
  let release, entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  return { waiting, release, transaction: async operation => {
    entered(); await gate; return store.transaction(operation);
  } };
}

test('claim and completion recheck source expiry after a transaction-acquisition wait and never emit a late ACK', async () => {
  for (const operation of ['claim', 'complete']) {
    const f = fixture(); await f.bridge.send(f.sender, f.input);
    const receiver = f.principal('friday', f.clock() + 120000);
    const claim = operation === 'complete' ? await f.bridge.claim(receiver, { messageId: f.input.id }) : null;
    const waiting = waitingTransaction(f.store);
    const bridge = f.makeBridge({ store: waiting });
    const pending = operation === 'claim' ? bridge.claim(receiver, { messageId: f.input.id })
      : bridge.complete(receiver, { messageId: f.input.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
    const rejected = assert.rejects(pending, error('message_authorization_inactive'));
    await waiting.waiting; f.advance(1001); waiting.release(); await rejected;
    assert.equal(Object.keys(f.store.snapshot().messages).length, 1);
    assert.notEqual(f.store.snapshot().receipts[f.input.id]?.state, 'complete');
    if (operation === 'claim') assert.equal(f.store.snapshot().receipts[f.input.id], undefined);
  }
});

test('receipt lease expiry is checked after acquiring the completion transaction', async () => {
  const f = fixture(), who = f.principal('friday', f.clock() + 120000);
  await f.bridge.send(f.principal('jarvis', f.clock() + 120000), f.input);
  const claim = await f.bridge.claim(who, { messageId: f.input.id });
  const waiting = waitingTransaction(f.store), bridge = f.makeBridge({ store: waiting });
  const rejected = assert.rejects(bridge.complete(who, { messageId: f.input.id, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null }), error('stale_receipt_claim'));
  await waiting.waiting; f.advance(60001); waiting.release(); await rejected;
  assert.equal(Object.keys(f.store.snapshot().messages).length, 1);
  assert.equal(f.store.snapshot().receipts[f.input.id].state, 'claimed');
});

test('new claim leases start at transaction acquisition after a valid wait', async () => {
  const f = fixture(); await f.bridge.send(f.sender, f.input);
  const waiting = waitingTransaction(f.store), bridge = f.makeBridge({ store: waiting });
  const pendingClaim = bridge.claim(f.receiver, { messageId: f.input.id });
  await waiting.waiting; f.advance(100); waiting.release(); const claim = await pendingClaim;
  assert.equal(Date.parse(claim.leaseUntil), f.clock() + 60000);
});
