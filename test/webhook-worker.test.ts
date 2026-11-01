import test from 'node:test';
import assert from 'node:assert/strict';
import { BridgeError, VERIFIED_AUTHORIZATION } from '../src/policy.ts';
import { Bridge } from '../src/bridge.ts';
import { createWebhookSender } from '../src/webhook-sender.ts';
import { DeliveryWorker } from '../src/worker.ts';
import { MemoryStore } from '../src/store.ts';
import { createQueueAdapter, TOPIC } from '../src/queue.ts';
import { digest } from '../src/events.ts';
import type { SenderTransport, WebhookSenderOptions } from '../src/webhook-sender.ts';
import type { QueueClient } from '../src/queue.ts';
import type { BridgeState, Principal, VerifiedPrincipal } from '../src/types.ts';

const messageId = '00000000-0000-4000-8000-000000000001';
const eventId = 'evt_' + digest(JSON.stringify([messageId, 'friday']));
const jobId = 'job_' + eventId.slice(4);
const policyId = 'c'.repeat(64);
const config = { enabled: true, endpoint: 'https://receiver.example.test/hook',
  secret: 'FIXTURE_NOT_A_REAL_KEY', contractVerified: false, probeMessageId: messageId };
function fixture(transport: SenderTransport, options: WebhookSenderOptions = {}, snapshot?: BridgeState) {
  let time = 100000;
  const store = new MemoryStore(snapshot);
  const sender = Object.defineProperty<Principal>({ role: 'jarvis', principalKey: 'a'.repeat(64), scopes: ['bridge:send:friday'] },
    VERIFIED_AUTHORIZATION, { value: { policyId, expiresAt: time + 3600000 } }) as VerifiedPrincipal;
  const seed = () => new Bridge({ store, clock: () => time }).send(sender, { id: messageId,
    testId: 'RN-JARVIS-FRIDAY-SYNTHETIC', from: 'jarvis', to: 'friday', kind: 'probe',
    sentAt: new Date(time).toISOString(), marker: 'RN-SYNTHETIC-NO-ACTIONS' });
  const makeWorker = (accessAllowed = async () => true) => new DeliveryWorker({ store, clock: () => time,
    enabled: true, policyId, accessAllowed, webhookSender: createWebhookSender({ ...config, ...options, transport }) });
  // This fixture authorizer is in-process only; no production access binding is supplied.
  return { store, seed, makeWorker, advance: (ms: number) => { time += ms; } };
}

test('one-shot 2xx/4xx/503/timeout outcomes remain terminal and immutable across queue callbacks and restart', async () => {
  for (const scenario of [{ status: 202, error: null }, { status: 400, error: 'permanent_http' },
    { status: 503, error: 'transient_http' }, { status: null, error: 'callback_timeout' },
    { status: null, error: 'friday_transport_failed', throwsRaw: true }]) {
    let calls = 0;
    const transport = async () => { calls++;
      if (scenario.status === null) {
        if (scenario.throwsRaw) throw new Error(config.secret);
        throw new BridgeError('callback_timeout', 503);
      }
      return { status: scenario.status };
    };
    const f = fixture(transport); await f.seed(); const worker = f.makeWorker();
    const adapter = createQueueAdapter({ client: {} as QueueClient, store: f.store, worker, enabled: true });
    for (let deliveryCount = 1; deliveryCount <= 3; deliveryCount++) {
      await adapter.consume({ jobId }, { topicName: TOPIC, region: 'iad1', deliveryCount });
      f.advance(60000);
    }
    const saved = f.store.snapshot(); const j = saved.jobs[jobId]!;
    assert.equal(calls, 1);
    assert.equal(j.attempts, 1); assert.equal(j.transportAttempts, 1);
    assert.equal(j.state, scenario.status === 202 ? 'accepted' : 'dead');
    assert.equal(j.lastStatus, scenario.status);
    assert.equal(JSON.stringify(saved).includes(config.secret), false);
    assert.deepEqual(j.firstTransportOutcome, { at: 100000, workerAttempt: 1,
      status: scenario.status, error: scenario.error, terminal: true });
    const restarted = fixture(transport, {}, saved);
    assert.deepEqual(await restarted.makeWorker().run(jobId), { attempted: false });
    assert.deepEqual(restarted.store.snapshot(), saved);
    // Even a reintroduced pending marker cannot erase a committed one-shot result.
    await restarted.store.transaction(s => { s.jobs[jobId]!.state = 'pending'; });
    restarted.advance(60000);
    await restarted.makeWorker().run(jobId);
    assert.deepEqual(restarted.store.snapshot(), saved);
    assert.equal(calls, 1);
  }
});

test('verified normal retry preserves first HTTP evidence separately from its later successful result', async () => {
  let calls = 0;
  const f = fixture(async () => ({ status: ++calls === 1 ? 503 : 202 }), { contractVerified: true });
  await f.seed(); const worker = f.makeWorker();
  const first = await worker.run(jobId);
  assert.ok(first.retryAt);
  const firstOutcome = f.store.snapshot().jobs[jobId]!.firstTransportOutcome!;
  f.advance(1001);
  const second = await worker.run(jobId);
  assert.equal(second.transportAccepted, true);
  const j = f.store.snapshot().jobs[jobId]!;
  assert.equal(j.attempts, 2); assert.equal(j.transportAttempts, 2);
  assert.equal(j.lastStatus, 202); assert.equal(j.lastError, null);
  assert.deepEqual(j.firstTransportOutcome, firstOutcome);
  assert.equal(firstOutcome.status, 503); assert.equal(firstOutcome.error, 'transient_http');
  assert.equal(firstOutcome.terminal, false);
});

test('a pre-transport denied worker attempt is not recorded as a transport attempt or HTTP outcome', async () => {
  let calls = 0;
  const f = fixture(async () => { calls++; return { status: 202 }; }); await f.seed();
  await f.makeWorker(async () => false).run(jobId);
  const j = f.store.snapshot().jobs[jobId]!;
  assert.equal(j.attempts, 1); assert.equal(calls, 0);
  assert.equal(j.transportAttempts, undefined); assert.equal(j.firstTransportOutcome, undefined);
  assert.equal(j.lastStatus, null); assert.equal(j.lastError, 'access_revoked');
});
