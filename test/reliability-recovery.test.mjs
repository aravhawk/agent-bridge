import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { Bridge } from '../src/bridge.mjs';
import { MemoryStore } from '../src/store.mjs';
import { NativeEvents } from '../src/events.mjs';
import { createProtector } from '../src/webhook.mjs';
import { VERIFIED_AUTHORIZATION, SCOPES, BridgeError } from '../src/policy.mjs';
import { DeliveryWorker } from '../src/worker.mjs';
import { createFridaySender } from '../src/friday-sender.mjs';
import { createQueueAdapter, TOPIC } from '../src/queue.mjs';

const start = Date.UTC(2026, 9, 21), hour = 3600000;
const policyIds = { jarvis: 'c'.repeat(64), friday: 'd'.repeat(64) };
const error = code => e => e.code === code;
function fixture() {
  let now = start, offline = false;
  const store = new MemoryStore(), protector = createProtector(randomBytes(32)), posts = [], published = [];
  const clock = () => now;
  const who = (role, expiresAt = start + 2 * hour) => Object.defineProperty({ role,
    scopes: Object.values(SCOPES[role]), principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64) },
  VERIFIED_AUTHORIZATION, { value: { policyId: policyIds[role], expiresAt } });
  const jarvis = who('jarvis'), friday = who('friday');
  const events = new NativeEvents({ store, protector, clock, enabled: true, policyId: policyIds.jarvis,
    transport: async (_url, req) => ({ status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  const subscription = { name: 'bridge.message.received', arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/FIXTURE', secret: 'whsec_' + randomBytes(32).toString('base64') } };
  const subscribe = (expiresAt = start + 2 * hour) => events.subscribe(who('jarvis', expiresAt), subscription);
  const bridge = new Bridge({ store, clock, dailyEnabled: true, messagePolicyIds: policyIds });
  const message = () => ({ protocol: 'jarvis-friday/1', id: randomUUID(), threadId: randomUUID(),
    from: 'jarvis', to: 'friday', kind: 'message', route: 'inbox', text: 'Local synthetic regression data.',
    sentAt: new Date(now).toISOString(), expiresAt: new Date(now + hour).toISOString() });
  const complete = (id, claimId) => bridge.complete(friday, { messageId: id, claimId, hostedEventId: null, hostedTurnId: null });
  const transport = async (_url, req) => { posts.push(JSON.parse(req.body)); return { status: 200 }; };
  function queue(activeStore = store, send = async (...args) => { published.push(args); }, enabled = true) {
    const faultingStore = { transaction: op => offline ? Promise.reject(Error('FIXTURE_DATABASE_OUTAGE')) : activeStore.transaction(op) };
    const worker = new DeliveryWorker({ store: faultingStore, clock, enabled: true, protector, transport,
      policyId: policyIds.jarvis, messagePolicyIds: policyIds, accessAllowed: async () => true,
      fridaySender: createFridaySender({ enabled: true, contractVerified: true,
        endpoint: 'https://receiver.example.test/FIXTURE', secret: 'FIXTURE_ONLY', transport }) });
    return createQueueAdapter({ store: faultingStore, worker, client: { send }, enabled, clock });
  }
  const metadata = (deliveryCount, extra = {}) => ({ topicName: TOPIC, region: 'iad1', deliveryCount,
    messageId: 'queue_FIXTURE_initial', createdAt: new Date(start), expiresAt: new Date(start + hour), ...extra });
  return { store, protector, bridge, jarvis, friday, who, subscribe, message, complete, clock, queue, metadata, posts, published,
    advance: ms => { now += ms; }, offline: value => { offline = value; } };
}

test('normal Jarvis callback records HTTP attempts separately from worker attempts and recipient completion', async () => {
  const f = fixture(); await f.subscribe();
  const m = { ...f.message(), from: 'friday', to: 'jarvis' };
  const sent = await f.bridge.sendMessage(f.friday, m);
  const calls = [];
  const options = { store: f.store, protector: f.protector, clock: f.clock, enabled: true,
    policyId: policyIds.jarvis, messagePolicyIds: policyIds,
    accessAllowed: async () => true, transport: async (_url, request) => {
      calls.push(request); return { status: calls.length === 1 ? 503 : 202 };
    } };
  const first = await new DeliveryWorker(options).run(sent.jobIds[0]);
  assert.equal(first.transportAccepted, false);
  let status = await f.bridge.status(f.jarvis, { messageId: m.id });
  assert.equal(status.deliveries[0].transportAttempts, 1);
  assert.deepEqual(status.deliveries[0].firstTransportOutcome, {
    at: start, workerAttempt: 1, status: 503, error: 'transient_http', terminal: false,
  });
  assert.equal(status.receiptCompleted, false); assert.equal(status.wakeVerified, false);
  assert.equal((await new DeliveryWorker(options).run(sent.jobIds[0])).attempted, false);
  f.advance(1000);
  assert.equal((await new DeliveryWorker(options).run(sent.jobIds[0])).transportAccepted, true);
  status = await f.bridge.status(f.jarvis, { messageId: m.id });
  assert.equal(status.deliveries[0].transportAttempts, 2);
  assert.equal(status.deliveries[0].attempts, 2);
  assert.equal(status.deliveries[0].lastStatus, 202);
  assert.equal(status.deliveries[0].firstTransportOutcome.status, 503);
  assert.equal(status.receiptCompleted, false); assert.equal(status.wakeVerified, false);
  assert.equal(calls[0].body, calls[1].body);
  assert.equal(calls[0].headers['webhook-id'], calls[1].headers['webhook-id']);
  await new DeliveryWorker(options).run(sent.jobIds[0]);
  assert.equal(calls.length, 2, 'accepted transport is never replayed to chase a missing receipt');
});

test('Jarvis callback timeout evidence survives restart, while pre-transport storage failures are not HTTP attempts', async () => {
  const f = fixture(); await f.subscribe();
  const m = { ...f.message(), from: 'friday', to: 'jarvis' };
  const sent = await f.bridge.sendMessage(f.friday, m);
  let checks = 0, calls = 0;
  const options = { store: f.store, protector: f.protector, clock: f.clock, enabled: true,
    policyId: policyIds.jarvis, messagePolicyIds: policyIds,
    accessAllowed: async () => {
      if (++checks === 1) throw new BridgeError('storage_unavailable', 503);
      return true;
    }, transport: async () => {
      if (++calls === 1) throw new BridgeError('callback_timeout', 503);
      return { status: 202 };
    } };
  await new DeliveryWorker(options).run(sent.jobIds[0]);
  let job = f.store.snapshot().jobs[sent.jobIds[0]];
  assert.equal(job.transportAttempts, undefined); assert.equal(job.firstTransportOutcome, undefined);
  f.advance(1000);
  await new DeliveryWorker(options).run(sent.jobIds[0]);
  job = f.store.snapshot().jobs[sent.jobIds[0]];
  assert.equal(job.transportAttempts, 1);
  assert.deepEqual(job.firstTransportOutcome, {
    at: start + 1000, workerAttempt: 2, status: null, error: 'transport_transient', terminal: false,
  });
  f.advance(2000);
  const restarted = new MemoryStore(f.store.snapshot());
  await new DeliveryWorker({ ...options, store: restarted }).run(sent.jobIds[0]);
  const saved = restarted.snapshot().jobs[sent.jobIds[0]];
  assert.equal(saved.state, 'accepted'); assert.equal(saved.transportAttempts, 2);
  assert.deepEqual(saved.firstTransportOutcome, job.firstTransportOutcome);
  assert.equal(saved.attempts, 3); assert.equal(calls, 2);
});

test('an accepted ACK can expire before hosted handling without retransmission or renewed receipt authority', async () => {
  const f = fixture(); await f.subscribe();
  const m = f.message(); await f.bridge.sendMessage(f.jarvis, m);
  f.advance(44000);
  const claim = await f.bridge.claim(f.friday, { messageId: m.id });
  const done = await f.complete(m.id, claim.claimId);
  const ackId = done.ackMessageId;
  const read = await f.bridge.read(f.jarvis, { messageId: ackId });
  assert.equal(read.receivedAt, new Date(start + 44000).toISOString(), 'receivedAt is server storage time');
  assert.equal(read.envelope.expiresAt, m.expiresAt); assert.equal(read.expired, false);
  await f.queue().consume({ dispatchReceiptOf: m.id }, f.metadata(1));
  let status = await f.bridge.status(f.jarvis, { messageId: ackId });
  assert.equal(status.deliveries[0].state, 'accepted');
  assert.equal(status.deliveries[0].transportAttempts, 1);
  assert.equal(status.receiptCompleted, false); assert.equal(status.wakeVerified, false);
  f.advance(hour + 1);
  const before = f.store.snapshot();
  assert.equal((await f.bridge.read(f.jarvis, { messageId: ackId })).expired, true);
  await assert.rejects(f.bridge.claim(f.jarvis, { messageId: ackId }), error('message_authorization_inactive'));
  await f.queue(new MemoryStore(before)).consume({ dispatchReceiptOf: m.id }, f.metadata(2));
  assert.equal(f.posts.length, 1);
  assert.equal(f.store.snapshot().receipts[ackId], undefined);
  assert.equal(Object.keys(f.store.snapshot().messages).length, 2);
  status = await f.bridge.status(f.jarvis, { messageId: m.id });
  assert.equal(status.receiptCompleted, true); assert.equal(status.ackMessageId, ackId);
});

test('missing, short, wrong-owner, stale-policy, revoked and expired return leases reject before publication or admission', async () => {
  for (const mode of ['missing', 'short', 'owner', 'policy', 'denied', 'unsubscribed', 'expired']) {
    const f = fixture();
    if (mode !== 'missing') {
      const sub = await f.subscribe(mode === 'short' ? start + 1000 : undefined);
      await f.store.transaction(s => {
        const a = s.subscriptions[sub.id];
        if (mode === 'owner') { a.owner = 'e'.repeat(64); a.authorization.owner = a.owner; }
        if (mode === 'policy') a.authorization.policyId = 'e'.repeat(64);
        if (mode === 'denied') s.resourceDenials = { [a.owner]: { status: 'denied' } };
        if (mode === 'unsubscribed') { a.active = false; a.status = 'unsubscribed'; }
        if (mode === 'expired') a.expiresAt = start;
      });
    }
    let publications = 0;
    const bridge = new Bridge({ store: f.store, clock: f.clock, dailyEnabled: true, messagePolicyIds: policyIds,
      prepareMessage: async () => { publications++; } });
    const before = f.store.snapshot();
    await assert.rejects(bridge.sendMessage(f.jarvis, f.message()), error('return_subscription_required'));
    assert.equal(publications, 0, mode); assert.deepEqual(f.store.snapshot(), before, mode);
  }
});

test('return path is rechecked after asynchronous queue preparation before source commit', async () => {
  const f = fixture(), sub = await f.subscribe(), m = f.message();
  const bridge = new Bridge({ store: f.store, clock: f.clock, dailyEnabled: true, messagePolicyIds: policyIds,
    prepareMessage: async () => f.store.transaction(s => { s.subscriptions[sub.id].expiresAt = start; }) });
  await assert.rejects(bridge.sendMessage(f.jarvis, m), error('return_subscription_required'));
  assert.deepEqual(f.store.snapshot().messages, {}); assert.deepEqual(f.store.snapshot().jobs, {});
});

test('return coverage follows immutable source authority rather than extending it to envelope expiry', async () => {
  const f = fixture(); await f.subscribe(start + 1000); const m = f.message();
  await f.bridge.sendMessage(f.who('jarvis', start + 500), m);
  assert.equal(f.store.snapshot().messages[m.id].authorization.expiresAt, start + 500);
  f.advance(500);
  await assert.rejects(f.bridge.claim(f.friday, { messageId: m.id }), error('message_authorization_inactive'));
  assert.deepEqual(f.store.snapshot().receipts, {});
});

test('claim rechecks return authority; same-registration renewal restores processing and exactly one ACK', async () => {
  const f = fixture(), sub = await f.subscribe(), m = f.message();
  await f.bridge.sendMessage(f.jarvis, m);
  await f.store.transaction(s => { s.subscriptions[sub.id].expiresAt = start; });
  await assert.rejects(f.bridge.claim(f.friday, { messageId: m.id }), error('return_subscription_required'));
  assert.deepEqual(f.store.snapshot().receipts, {});
  assert.equal((await f.bridge.sendMessage(f.jarvis, m)).duplicate, true, 'an exact committed replay does not create new work');
  assert.equal((await f.subscribe(start + 3 * hour)).id, sub.id);
  const claim = await f.bridge.claim(f.friday, { messageId: m.id });
  const first = await f.complete(m.id, claim.claimId), again = await f.complete(m.id, claim.claimId);
  assert.equal(again.ackMessageId, first.ackMessageId); assert.equal(again.duplicate, true);
  assert.equal(Object.keys(f.store.snapshot().messages).length, 2);
});

test('revocation after claim still rolls completion back; renewal never bypasses denial', async () => {
  const f = fixture(), sub = await f.subscribe(), m = f.message();
  await f.bridge.sendMessage(f.jarvis, m);
  const claim = await f.bridge.claim(f.friday, { messageId: m.id });
  await f.store.transaction(s => { s.resourceDenials = { [s.subscriptions[sub.id].owner]: { status: 'denied' } }; });
  // Immutable source authority also belongs to that Jarvis owner.
  await assert.rejects(f.complete(m.id, claim.claimId), error('message_authorization_inactive'));
  await assert.rejects(f.subscribe(start + 3 * hour), error('access_revoked'));
  assert.equal(f.store.snapshot().receipts[m.id].state, 'claimed');
  assert.equal(Object.keys(f.store.snapshot().messages).length, 1);
});

test('inactive or still-active shortened lease cannot commit an ACK; valid renewal recovers the original claim', async () => {
  for (const expiresAt of [start, start + 1000]) {
    const f = fixture(), sub = await f.subscribe(), m = f.message();
    await f.bridge.sendMessage(f.jarvis, m); const claim = await f.bridge.claim(f.friday, { messageId: m.id });
    await f.store.transaction(s => { s.subscriptions[sub.id].expiresAt = expiresAt; });
    await assert.rejects(f.complete(m.id, claim.claimId), error('return_subscription_required'));
    assert.equal(f.store.snapshot().receipts[m.id].state, 'claimed');
    assert.equal(Object.keys(f.store.snapshot().messages).length, 1);
    assert.equal((await f.subscribe(start + 3 * hour)).id, sub.id);
    const first = await f.complete(m.id, claim.claimId);
    assert.equal((await f.complete(m.id, claim.claimId)).ackMessageId, first.ackMessageId);
  }
});

test('completed-source claim and completion replays stay idempotent after return-lease loss', async () => {
  const f = fixture(), sub = await f.subscribe(), m = f.message();
  await f.bridge.sendMessage(f.jarvis, m); const claim = await f.bridge.claim(f.friday, { messageId: m.id });
  const first = await f.complete(m.id, claim.claimId);
  await f.store.transaction(s => { delete s.subscriptions[sub.id]; });
  assert.deepEqual(await f.bridge.claim(f.friday, { messageId: m.id }), {
    duplicate: true, completed: true, ackMessageId: first.ackMessageId,
  });
  const replay = await f.complete(m.id, claim.claimId);
  assert.equal(replay.duplicate, true); assert.equal(replay.ackMessageId, first.ackMessageId);
  assert.equal(Object.keys(f.store.snapshot().messages).length, 2);
});

test('terminal Jarvis-to-Friday ACK handling remains exempt after Jarvis subscription removal', async () => {
  const f = fixture(), sub = await f.subscribe(), source = { ...f.message(), from: 'friday', to: 'jarvis' };
  await f.bridge.sendMessage(f.friday, source);
  const claim = await f.bridge.claim(f.jarvis, { messageId: source.id });
  const ack = await f.bridge.complete(f.jarvis, { messageId: source.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
  await f.store.transaction(s => { delete s.subscriptions[sub.id]; });
  const terminal = await f.bridge.claim(f.friday, { messageId: ack.ackMessageId });
  const done = await f.complete(ack.ackMessageId, terminal.claimId);
  assert.equal(done.completed, true); assert.equal(done.ackMessageId, null);
  assert.equal(Object.keys(f.store.snapshot().messages).length, 2);
});

test('source authority and claim expiry during asynchronous receipt preparation still roll completion back', async () => {
  for (const phase of ['source', 'claim']) {
    const f = fixture(); await f.subscribe(); const m = f.message();
    await f.bridge.sendMessage(phase === 'source' ? f.who('jarvis', start + 1000) : f.jarvis, m);
    const claim = await f.bridge.claim(f.friday, { messageId: m.id });
    const bridge = new Bridge({ store: f.store, clock: f.clock, dailyEnabled: true, messagePolicyIds: policyIds,
      prepareReceipt: async () => { f.advance(phase === 'source' ? 1000 : 60000); } });
    await assert.rejects(bridge.complete(f.friday, { messageId: m.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null }),
      error(phase === 'source' ? 'message_authorization_inactive' : 'stale_receipt_claim'));
    assert.equal(f.store.snapshot().receipts[m.id].state, 'claimed');
    assert.equal(Object.keys(f.store.snapshot().messages).length, 1);
  }
});

for (const kind of ['dispatchMessageId', 'dispatchReceiptOf', 'jobId']) {
  test(`${kind}: infrastructure exhaustion hands off automatically and survives restart without duplicate transport`, async () => {
    const f = fixture(); await f.subscribe(); const m = f.message(), sent = await f.bridge.sendMessage(f.jarvis, m);
    let target = m.id, jobId = sent.jobIds[0];
    if (kind === 'dispatchReceiptOf') {
      const claim = await f.bridge.claim(f.friday, { messageId: m.id }), ack = await f.complete(m.id, claim.claimId);
      jobId = ack.jobIds[0];
    }
    if (kind === 'jobId') target = jobId;
    const payload = { [kind]: target }, queue = f.queue(); f.offline(true);
    for (let count = 1; count < 18; count++) {
      await assert.rejects(queue.consume(payload, f.metadata(count)), /FIXTURE_DATABASE_OUTAGE/);
      f.advance(60000);
    }
    await queue.consume(payload, f.metadata(18));
    assert.equal(f.published.length, 1); assert.equal(f.posts.length, 0);
    const [topic, continuation, options] = f.published[0];
    assert.equal(topic, TOPIC); assert.deepEqual(continuation, { ...payload, recoveryUntil: start + hour });
    assert.equal(options.delaySeconds, 60); assert.equal(options.region, 'iad1');
    assert.ok(options.retentionSeconds <= 2580);
    f.offline(false); f.advance(60000);
    const restartedStore = new MemoryStore(f.store.snapshot()), restarted = f.queue(restartedStore);
    await restarted.consume(continuation, f.metadata(1, { messageId: 'queue_FIXTURE_successor', createdAt: new Date(f.clock()) }));
    await restarted.consume(continuation, f.metadata(2));
    assert.equal(restartedStore.snapshot().jobs[jobId].state, 'accepted');
    assert.equal(f.posts.length, 1); assert.equal(f.published.length, 1);
  });
}

test('ambiguous handoff publish and lost callback ACK reuse one idempotent continuation', async () => {
  const f = fixture(); await f.subscribe(); const m = f.message(), sent = await f.bridge.sendMessage(f.jarvis, m);
  const accepted = new Map(), attempts = []; let fail = true;
  const queue = f.queue(f.store, async (_topic, payload, options) => {
    attempts.push(options.idempotencyKey); accepted.set(options.idempotencyKey, payload);
    if (fail) { fail = false; throw Error('FIXTURE_AMBIGUOUS_PUBLISH'); }
  });
  f.offline(true);
  await assert.rejects(queue.consume({ jobId: sent.jobIds[0] }, f.metadata(18)), /FIXTURE_AMBIGUOUS_PUBLISH/);
  await queue.consume({ jobId: sent.jobIds[0] }, f.metadata(19));
  await queue.consume({ jobId: sent.jobIds[0] }, f.metadata(19)); // Crash after publication, before callback ACK.
  assert.equal(new Set(attempts).size, 1); assert.equal(accepted.size, 1);
  f.offline(false); f.advance(60000);
  const restarted = f.queue(new MemoryStore(f.store.snapshot()));
  await restarted.consume([...accepted.values()][0], f.metadata(1));
  assert.equal(f.posts.length, 1);
});

test('continuations cannot extend the original absolute deadline, including across restarts and newer SDK expiry', async () => {
  const f = fixture(); await f.subscribe(); const sent = await f.bridge.sendMessage(f.jarvis, f.message());
  let payload = { jobId: sent.jobIds[0] }; f.offline(true);
  await f.queue().consume(payload, f.metadata(18));
  payload = f.published[0][1]; f.advance(60000);
  await f.queue(new MemoryStore(f.store.snapshot())).consume(payload, f.metadata(18, {
    messageId: 'queue_FIXTURE_successor', createdAt: new Date(f.clock()), expiresAt: new Date(f.clock() + hour),
  }));
  assert.equal(f.published[1][1].recoveryUntil, start + hour);
  f.advance(hour); await f.queue().consume(f.published[1][1], f.metadata(18));
  assert.equal(f.published.length, 2); assert.equal(f.posts.length, 0);
});

test('uncommitted sources/ACKs, malformed payloads and disabled delivery never spawn recovery', async () => {
  const f = fixture(), queue = f.queue();
  for (const kind of ['dispatchMessageId', 'dispatchReceiptOf'])
    await assert.rejects(queue.consume({ [kind]: randomUUID() }, f.metadata(18)), /bridge_job_pending/);
  const bad = [{ jobId: 'bad' }, { jobId: 'job_' + 'a'.repeat(64), body: 'forged' },
    { jobId: 'job_' + 'a'.repeat(64), recoveryUntil: 'forever' }];
  for (const payload of bad) await queue.consume(payload, f.metadata(18));
  await assert.rejects(f.queue(f.store, undefined, false).consume({ jobId: 'job_' + 'a'.repeat(64) }, f.metadata(18)), /queue_not_enabled/);
  assert.equal(f.published.length, 0); assert.equal(f.posts.length, 0);
});

test('expired or revoked source is fenced by the real worker, without handoff or transport', async () => {
  for (const mode of ['expiry', 'denial']) {
    const f = fixture(); await f.subscribe(); const m = f.message(), sent = await f.bridge.sendMessage(f.jarvis, m);
    if (mode === 'expiry') f.advance(hour);
    else await f.store.transaction(s => { s.resourceDenials = { [f.jarvis.principalKey]: {} }; });
    await f.queue().consume({ jobId: sent.jobIds[0] }, f.metadata(18));
    assert.equal(f.store.snapshot().jobs[sent.jobIds[0]].state, 'dead');
    assert.equal(f.posts.length, 0); assert.equal(f.published.length, 0);
  }
});

test('handoff requires SDK identity/deadline metadata and stops when too little recovery lifetime remains', async () => {
  const f = fixture(); await f.subscribe(); const sent = await f.bridge.sendMessage(f.jarvis, f.message());
  f.offline(true); const payload = { jobId: sent.jobIds[0] }, queue = f.queue();
  for (const extra of [{ createdAt: undefined }, { expiresAt: new Date(NaN) }, { messageId: '' }])
    await assert.rejects(queue.consume(payload, f.metadata(18, extra)), /queue_recovery_metadata_required/);
  f.advance(hour - 60000);
  await assert.rejects(queue.consume(payload, f.metadata(18)), /FIXTURE_DATABASE_OUTAGE/);
  assert.equal(f.published.length, 0); assert.equal(f.posts.length, 0);
});
