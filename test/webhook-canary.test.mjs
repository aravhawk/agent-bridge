import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { Webhook } from 'standardwebhooks';
import { createRuntime } from '../src/runtime.mjs';
import { CANARY_TEXT, CANARY_MAX_WINDOW_MS } from '../src/canary.mjs';
import { emptyState, PostgresStore } from '../src/store.mjs';
import { resourceFor } from '../src/resource.mjs';
import { SCOPES, BridgeError } from '../src/policy.mjs';
import { denyResourceAccess } from '../src/access.mjs';
import { MESSAGE_PROTOCOL } from '../src/messages.mjs';
import { TOPIC } from '../src/queue.mjs';
import { ISSUER } from './fixtures/provider.mjs';

// Offline only: injected keys, locking pool, queue client and transport. No
// native endpoint, credential, subscription or provider is contacted.
const FRIDAY_URL = 'https://receiver.example.test/hook/FIXTURE_URL_TOKEN', KEY = 'FIXTURE_NOT_A_REAL_KEY';
const PINNED = 'https://callback.example.test/pinned', OTHER = 'https://callback.example.test/other';
const SPENT_DIAGNOSTIC = '00000000-0000-4000-8000-0000000012b1';

// Serializes like SELECT ... FOR UPDATE; only COMMIT publishes the document.
function lockingDatabase(initial = emptyState()) {
  const db = { document: structuredClone(initial), failUpdates: 0, tail: Promise.resolve(),
    storageKey: randomBytes(32).toString('base64'),
    secrets: { [PINNED]: 'whsec_' + randomBytes(32).toString('base64'), [OTHER]: 'whsec_' + randomBytes(32).toString('base64') } };
  db.Pool = class {
    on() {} async end() {}
    async connect() {
      let release, pending;
      return { release() {}, async query(sql, params) {
        if (sql === 'BEGIN') { const previous = db.tail; db.tail = new Promise(r => { release = r; }); await previous; return {}; }
        if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(db.document) }] };
        if (sql.startsWith('UPDATE bridge_runtime_v1')) {
          if (db.failUpdates > 0) { db.failUpdates--; throw Error('FIXTURE_DB_DOWN'); }
          pending = JSON.parse(params[0]); return {};
        }
        if (sql === 'COMMIT') { if (pending) db.document = pending; release(); db.afterCommit?.(); return {}; }
        if (sql === 'ROLLBACK') { release?.(); return {}; }
        return {};
      } };
    }
  };
  return db;
}
// Deployed state: OAuth attested, subscriptions on, delivery and both
// unverified receiver flags off, saved Friday binding and receiver ID present.
const deployedEnv = db => ({ BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true',
  BRIDGE_ALLOWED_SUBJECT: 'fixture', BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_DELIVERY_ENABLED: 'false',
  BRIDGE_RECEIVER_POLICY: '', BRIDGE_SUBSCRIPTION_STORAGE_KEY: db.storageKey,
  DATABASE_URL: 'postgresql://fixture.neon.tech/neondb?sslmode=require', FRIDAY_RECEIVER_ID: 'jarvis-friday-bridge-inbox',
  FRIDAY_WEBHOOK_URL: FRIDAY_URL, FRIDAY_WEBHOOK_KEY: KEY, FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'false' });

async function fixture({ db = lockingDatabase(), env: changes = {}, now: start = Date.now(), respond } = {}) {
  let now = start;
  const posts = [], sends = [], env = { ...deployedEnv(db), ...changes };
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const rt = createRuntime({ env, Pool: db.Pool, keyResolver: publicKey, clock: () => now,
    queueClient: { async send(_topic, payload) { sends.push(payload); }, handleCallback: fn => fn },
    transportFactory: () => async (url, request) => {
      const body = JSON.parse(request.body);
      if (body.type === 'verification') return { status: 200, body: JSON.stringify({ challenge: body.challenge }) };
      if (url !== FRIDAY_URL) new Webhook(db.secrets[url]).verify(request.body, request.headers);
      posts.push({ url, headers: request.headers, body });
      return respond ? respond(url, body) : { status: 202, body: 'FIXTURE_RESPONSE_BODY' };
    } });
  const sign = (role, { scopes = Object.values(SCOPES[role]), expiresAt = Math.floor(Date.now() / 1000) + 7200 } = {}) =>
    new SignJWT({ scope: scopes.join(' ') }).setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject('fixture')
      .setAudience(resourceFor(role)).setIssuedAt(Math.floor(Date.now() / 1000) - 60).setExpirationTime(expiresAt).sign(privateKey);
  const tokens = { jarvis: await sign('jarvis'), friday: await sign('friday') };
  const rpc = async (role, method, params, token = tokens[role]) => {
    const response = await rt.handler(role)(new Request(resourceFor(role), { method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
    return { status: response.status, headers: response.headers, body: await response.json() };
  };
  const call = (role, name, args = {}, token) => rpc(role, 'tools/call', { name, arguments: args }, token);
  const ok = async (role, name, args) => {
    const r = await call(role, name, args);
    assert.equal(r.status, 200); assert.notEqual(r.body.result.isError, true, JSON.stringify(r.body));
    return r.body.result.structuredContent;
  };
  const toolError = async (role, name, args, token) => {
    const r = await call(role, name, args, token);
    assert.equal(r.status, 200); assert.equal(r.body.result.isError, true, JSON.stringify(r.body));
    return r.body.result.structuredContent.error;
  };
  const subscribe = async url => (await rpc('jarvis', 'events/subscribe', { name: 'bridge.message.received',
    arguments: { recipient: 'jarvis' }, delivery: { mode: 'webhook', url, secret: db.secrets[url] }, ttlMs: null })).body.result.id;
  const arm = (subscriptionId, { id = randomUUID(), from = now, until = now + CANARY_MAX_WINDOW_MS } = {}) => {
    Object.assign(env, { FRIDAY_CANARY_MESSAGE_ID: id, FRIDAY_CANARY_RETURN_SUBSCRIPTION_ID: subscriptionId,
      FRIDAY_CANARY_FROM: new Date(from).toISOString(), FRIDAY_CANARY_UNTIL: new Date(until).toISOString() });
    return id;
  };
  const canary = (overrides = {}) => ({ protocol: MESSAGE_PROTOCOL, id: env.FRIDAY_CANARY_MESSAGE_ID, from: 'jarvis',
    to: 'friday', kind: 'status', sentAt: new Date(now).toISOString(), expiresAt: env.FRIDAY_CANARY_UNTIL,
    threadId: env.FRIDAY_CANARY_MESSAGE_ID, route: 'inbox', text: CANARY_TEXT, ...overrides });
  const consume = payload => rt.queueHandler()(payload, { topicName: TOPIC, region: 'iad1', deliveryCount: 1 });
  const readiness = async () => (await ok('jarvis', 'bridge_health')).readiness;
  return { rt, env, db, posts, sends, tokens, sign, rpc, call, ok, toolError, subscribe, arm, canary, consume, readiness,
    clock: () => now, advance: ms => { now += ms; }, set: t => { now = t; } };
}
// Pinned + unrelated active return subscriptions, canary armed on the pinned one.
async function armed(options) {
  const f = await fixture(options);
  const pinned = await f.subscribe(PINNED), other = await f.subscribe(OTHER);
  assert.match(pinned, /^sub_[a-f0-9]{64}$/); assert.notEqual(pinned, other);
  return { ...f, pinned, other, id: f.arm(pinned) };
}
const fridayPosts = f => f.posts.filter(p => p.url === FRIDAY_URL);

test('exact canary: source -> Friday webhook -> read/claim/complete -> pinned signed ACK -> Jarvis quiet completion, delivery off', async () => {
  const marker = { messageId: SPENT_DIAGNOSTIC, receiverId: 'jarvis-friday-bridge-inbox', owner: 'e'.repeat(64),
    attemptedAt: 1, armedFrom: 0, armedUntil: 2, outcome: { status: 202, error: null, completedAt: 1 } };
  const f = await armed({ db: lockingDatabase({ ...emptyState(), fridayWebhookDiagnostic: marker }) });
  const health = await f.ok('jarvis', 'bridge_health');
  assert.equal(health.readiness.canaryArmed, true);
  for (const flag of ['deliveryEnabled', 'fridayContractVerified', 'receiverPolicyVerified', 'fridayWebhookDiagnosticArmed'])
    assert.equal(health.readiness[flag], false, flag);
  assert.equal(JSON.stringify(health).includes(f.id), false);
  assert.equal((await f.ok('friday', 'bridge_health')).caller.tools.length, 6, 'tool discovery unchanged');

  const sent = await f.ok('jarvis', 'bridge_message_send', f.canary());
  assert.equal(sent.duplicate, false); assert.equal(sent.scheduling, 'not_confirmed');
  assert.deepEqual(f.sends.map(Object.keys), [['cleanupMessageId'], ['dispatchMessageId']]);
  await f.consume(f.sends[1]);
  assert.equal(f.posts.length, 1);
  assert.deepEqual(f.posts[0], { url: FRIDAY_URL, headers: { 'content-type': 'application/json', authorization: 'Bearer ' + KEY },
    body: { event: 'bridge.message.received', data: { messageId: f.id } } });

  const read = await f.ok('friday', 'bridge_read', { messageId: f.id });
  assert.equal(read.envelope.text, CANARY_TEXT); assert.equal(read.authority, 'peer_data_requires_user_workflow');
  const claim = await f.ok('friday', 'bridge_receipt_claim', { messageId: f.id });
  const done = await f.ok('friday', 'bridge_receipt_complete', { messageId: f.id, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null });
  assert.match(done.ackMessageId, /^[a-f0-9-]{36}$/);
  assert.deepEqual(f.sends.at(-1), { dispatchReceiptOf: f.id });
  await f.consume(f.sends.at(-1));
  assert.equal(f.posts.length, 2, 'one ACK callback, no fan-out');
  const ack = f.posts[1];
  assert.equal(ack.url, PINNED); assert.equal(ack.headers['X-MCP-Subscription-Id'], f.pinned);
  assert.equal(ack.body.data.messageId, done.ackMessageId); assert.equal(ack.body.name, 'bridge.message.received');

  const ackRead = await f.ok('jarvis', 'bridge_read', { messageId: done.ackMessageId });
  assert.equal(ackRead.envelope.kind, 'ack'); assert.equal(ackRead.envelope.correlationId, f.id);
  const ackClaim = await f.ok('jarvis', 'bridge_receipt_claim', { messageId: done.ackMessageId });
  const quiet = await f.ok('jarvis', 'bridge_receipt_complete', { messageId: done.ackMessageId,
    claimId: ackClaim.claimId, hostedEventId: null, hostedTurnId: null });
  assert.equal(quiet.ackMessageId, null); assert.equal(quiet.scheduling, undefined);

  // Replayed queue items never send again.
  for (const payload of [{ dispatchMessageId: f.id }, { dispatchReceiptOf: f.id }]) await f.consume(payload);
  assert.equal(f.posts.length, 2);

  const source = await f.ok('jarvis', 'bridge_status', { messageId: f.id });
  assert.equal(source.deliveries.length, 1);
  assert.deepEqual({ ...source.deliveries[0], eventId: null, firstTransportOutcome: { ...source.deliveries[0].firstTransportOutcome, at: null } },
    { eventId: null, state: 'accepted', attempts: 1, transportAttempts: 1, lastStatus: 202, lastError: null,
      firstTransportOutcome: { at: null, workerAttempt: 1, status: 202, error: null, terminal: true } });
  assert.equal(source.receiptCompleted, true); assert.equal(source.ackMessageId, done.ackMessageId);
  assert.equal(source.wakeVerified, false);
  assert.deepEqual(source.canary.readObservations.map(r => [r.outcome, r.code]), [['success', 'ok']]);
  assert.equal(source.canary.evidenceStatus, 'server_operation_results_only_not_native_wake');
  const reply = await f.ok('friday', 'bridge_status', { messageId: done.ackMessageId });
  assert.deepEqual(reply.deliveries.map(d => [d.state, d.transportAttempts, d.lastStatus]), [['accepted', 1, 202]]);
  assert.equal(reply.receiptCompleted, true); assert.equal(reply.wakeVerified, false);
  assert.deepEqual(reply.canary.readObservations.map(r => r.code), ['ok']);

  const state = f.db.document;
  assert.deepEqual(state.fridayWebhookDiagnostic, marker, 'spent diagnostic marker untouched');
  assert.equal(state.messages[done.ackMessageId].jobIds.length, 1);
  assert.equal(state.jobs[state.messages[done.ackMessageId].jobIds[0]].subscriptionId, f.pinned);
  assert.deepEqual(Object.keys(state.fridayCanary).sort(), ['ackMessageId', 'ackReads', 'from', 'hash', 'messageId',
    'owner', 'reservedAt', 'sourceReads', 'subscriptionId', 'until']);
  const after = await f.readiness();
  assert.equal(after.deliveryEnabled, false); assert.equal(after.fridayContractVerified, false);
  const text = JSON.stringify(state);
  for (const secret of [KEY, FRIDAY_URL, PINNED, OTHER, ...Object.values(f.db.secrets), ...Object.values(f.tokens), 'FIXTURE_RESPONSE_BODY'])
    assert.equal(text.includes(secret), false);
});

test('closed by default; missing, malformed, reversed, overlong, future or expired configuration never arms', async () => {
  const f = await fixture(), pinned = await f.subscribe(PINNED), start = f.clock();
  const good = { FRIDAY_CANARY_MESSAGE_ID: randomUUID(), FRIDAY_CANARY_RETURN_SUBSCRIPTION_ID: pinned,
    FRIDAY_CANARY_FROM: new Date(start).toISOString(), FRIDAY_CANARY_UNTIL: new Date(start + CANARY_MAX_WINDOW_MS).toISOString() };
  const iso = ms => new Date(ms).toISOString();
  const cases = [{}, { FRIDAY_CANARY_MESSAGE_ID: '' }, { FRIDAY_CANARY_MESSAGE_ID: 'not-a-uuid' },
    { FRIDAY_CANARY_MESSAGE_ID: good.FRIDAY_CANARY_MESSAGE_ID.toUpperCase() },
    { FRIDAY_CANARY_RETURN_SUBSCRIPTION_ID: '' }, { FRIDAY_CANARY_RETURN_SUBSCRIPTION_ID: 'sub_other' },
    { FRIDAY_CANARY_FROM: '' }, { FRIDAY_CANARY_UNTIL: '' }, { FRIDAY_CANARY_FROM: 'soon' },
    { FRIDAY_CANARY_FROM: good.FRIDAY_CANARY_UNTIL, FRIDAY_CANARY_UNTIL: good.FRIDAY_CANARY_FROM },
    { FRIDAY_CANARY_UNTIL: iso(start + CANARY_MAX_WINDOW_MS + 1) },
    { FRIDAY_CANARY_FROM: iso(start + 1), FRIDAY_CANARY_UNTIL: iso(start + 60000) },
    { FRIDAY_CANARY_FROM: iso(start - 60000), FRIDAY_CANARY_UNTIL: iso(start) },
    { FRIDAY_RECEIVER_ID: 'jarvis-friday-test-receiver' }, { FRIDAY_WEBHOOK_KEY: 'bad\nkey' },
    { BRIDGE_SUBSCRIPTION_STORAGE_KEY: '' }];
  const base = { ...f.env };
  const reset = (...changes) => { for (const k of Object.keys(f.env)) delete f.env[k]; Object.assign(f.env, base, ...changes); };
  reset(good); assert.equal((await f.readiness()).canaryArmed, true, 'cases below differ from a valid arm by one field');
  for (const [index, change] of cases.entries()) {
    reset(index ? good : {}, change);
    assert.equal((await f.readiness()).canaryArmed, false, JSON.stringify(change));
    const body = f.canary({ id: good.FRIDAY_CANARY_MESSAGE_ID, threadId: good.FRIDAY_CANARY_MESSAGE_ID, expiresAt: good.FRIDAY_CANARY_UNTIL });
    assert.equal(await f.toolError('jarvis', 'bridge_message_send', body), 'receiver_readiness_required');
    assert.equal(await f.toolError('friday', 'bridge_receipt_claim', { messageId: good.FRIDAY_CANARY_MESSAGE_ID }), 'receiver_readiness_required');
    await assert.rejects(f.consume({ dispatchMessageId: good.FRIDAY_CANARY_MESSAGE_ID }), /delivery_not_enabled/);
  }
  // An overlong arm stays closed as its remaining time drops below the cap.
  reset(good, { FRIDAY_CANARY_UNTIL: iso(start + 2 * CANARY_MAX_WINDOW_MS) });
  for (let step = 0; step < 4; step++) { assert.equal((await f.readiness()).canaryArmed, false); f.advance(CANARY_MAX_WINDOW_MS / 2); }
  // A fully attested normal delivery configuration is not the canary.
  const normal = await fixture({ env: { ...good, BRIDGE_DELIVERY_ENABLED: 'true', BRIDGE_RECEIVER_POLICY: 'inbox-v1',
    FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true' } });
  assert.equal((await normal.readiness()).canaryArmed, false);
  assert.equal(f.db.document.fridayCanary, undefined); assert.deepEqual(f.db.document.messages, {});
  assert.equal(f.sends.length + f.posts.length, 0);
});

test('armed canary still requires pinned Jarvis role, send scope, unexpired JWT and undenied identity', async () => {
  const f = await armed();
  const wrongRole = await f.rpc('jarvis', 'tools/call', { name: 'bridge_message_send', arguments: f.canary() }, f.tokens.friday);
  assert.equal(wrongRole.status, 401);
  assert.equal(await f.toolError('friday', 'bridge_message_send', f.canary()), 'invalid_message');
  const ackOnly = await f.sign('jarvis', { scopes: [SCOPES.jarvis.ack] });
  assert.equal((await f.call('jarvis', 'bridge_message_send', f.canary(), ackOnly)).status, 403);
  const expired = await f.call('jarvis', 'bridge_message_send', f.canary(), await f.sign('jarvis', { expiresAt: Math.floor(Date.now() / 1000) - 10 }));
  assert.equal(expired.status, 401); assert.match(expired.headers.get('www-authenticate'), /^Bearer resource_metadata=/);
  const sendOnly = await f.sign('friday', { scopes: [SCOPES.friday.probe] });
  assert.equal((await f.call('friday', 'bridge_receipt_claim', { messageId: f.id }, sendOnly)).status, 403);
  // Operator-only durable denial through the same locking database.
  await denyResourceAccess(new PostgresStore(new f.db.Pool()), Object.values(f.db.document.subscriptions)[0].owner, f.clock());
  assert.equal(await f.toolError('jarvis', 'bridge_message_send', f.canary()), 'return_subscription_required');
  assert.equal(f.db.document.fridayCanary, undefined); assert.deepEqual(f.db.document.messages, {});
  assert.equal(f.sends.length + f.posts.length, 0);
});

test('only the exact source is admitted; arbitrary bodies, threads, directions, IDs and manual ACKs create nothing', async () => {
  const f = await armed();
  for (const [role, body, code] of [
    ['jarvis', f.canary({ id: randomUUID() }), 'friday_canary_only'],
    ['jarvis', f.canary({ text: CANARY_TEXT + ' Also do something.' }), 'friday_canary_only'],
    ['jarvis', f.canary({ threadId: randomUUID() }), 'friday_canary_only'],
    ['jarvis', f.canary({ kind: 'message' }), 'friday_canary_only'],
    ['jarvis', f.canary({ expiresAt: new Date(f.clock() + 60000).toISOString() }), 'friday_canary_only'],
    ['friday', f.canary({ from: 'friday', to: 'jarvis' }), 'friday_canary_only'],
    ['friday', { ...f.canary({ from: 'friday', to: 'jarvis', kind: 'ack', correlationId: f.id }), text: undefined }, 'use_receipt_complete_for_ack'],
  ]) assert.equal(await f.toolError(role, 'bridge_message_send', body), code, JSON.stringify(body));
  assert.equal(f.db.document.fridayCanary, undefined); assert.deepEqual(f.db.document.messages, {});
  assert.equal(f.sends.length, 0);
  await f.ok('jarvis', 'bridge_message_send', f.canary());
  for (const change of [{ text: 'changed' }, { sentAt: new Date(f.clock() + 1000).toISOString() }])
    assert.equal(await f.toolError('jarvis', 'bridge_message_send', f.canary(change)), 'message_id_conflict');
  assert.equal(Object.keys(f.db.document.messages).length, 1);
});

test('unrelated stored messages and queued jobs are neither delivered, claimed nor marked dead by canary processing', async () => {
  const db = lockingDatabase();
  const live = await fixture({ db, env: { BRIDGE_DELIVERY_ENABLED: 'true', BRIDGE_RECEIVER_POLICY: 'inbox-v1',
    FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true' } });
  const pinned = await live.subscribe(PINNED);
  const toFriday = { ...live.canary({ id: randomUUID(), threadId: randomUUID(), expiresAt: new Date(live.clock() + 3600000).toISOString() }), text: 'Unrelated' };
  const toJarvis = { ...toFriday, id: randomUUID(), from: 'friday', to: 'jarvis' };
  await live.ok('jarvis', 'bridge_message_send', toFriday); await live.ok('friday', 'bridge_message_send', toJarvis);
  await live.rt.close();
  const unrelatedJobs = Object.keys(db.document.jobs), before = structuredClone(db.document.jobs);
  assert.equal(unrelatedJobs.length, 2);

  const f = await fixture({ db }); const id = f.arm(pinned);
  for (const payload of [{ dispatchMessageId: toFriday.id }, { dispatchReceiptOf: toFriday.id }, { jobId: unrelatedJobs[0] },
    { jobId: unrelatedJobs[1] }, { dispatchMessageId: id, extra: 1 }])
    await assert.rejects(f.consume(payload), /delivery_not_enabled/);
  assert.equal(await f.toolError('friday', 'bridge_receipt_claim', { messageId: toFriday.id }), 'friday_canary_only');
  assert.equal(await f.toolError('jarvis', 'bridge_receipt_claim', { messageId: toJarvis.id }), 'friday_canary_only');
  assert.equal(await f.toolError('jarvis', 'bridge_message_send', { ...toFriday, id: randomUUID(), sentAt: new Date(f.clock()).toISOString() }),
    'friday_canary_only');

  await f.ok('jarvis', 'bridge_message_send', f.canary());
  await f.consume({ dispatchMessageId: id });
  const claim = await f.ok('friday', 'bridge_receipt_claim', { messageId: id });
  await f.ok('friday', 'bridge_receipt_complete', { messageId: id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
  await f.consume({ dispatchReceiptOf: id });
  assert.deepEqual(f.posts.map(p => p.url), [FRIDAY_URL, PINNED]);
  for (const job of unrelatedJobs) assert.deepEqual(f.db.document.jobs[job], before[job]);
  assert.deepEqual(f.db.document.receipts[toFriday.id], undefined);
});

test('one lifetime reservation: re-arming, changed settings, restarts and replays never authorize or extend another send', async () => {
  const f = await armed(), start = f.clock(), until = start + CANARY_MAX_WINDOW_MS, original = f.canary();
  await f.ok('jarvis', 'bridge_message_send', original);
  const reservation = structuredClone(f.db.document.fridayCanary), [jobId] = Object.keys(f.db.document.jobs);
  assert.deepEqual([reservation.messageId, reservation.until, reservation.subscriptionId], [f.id, until, f.pinned]);
  f.advance(1000);
  // Re-armed with a fresh UUID and window: no second source.
  f.arm(f.pinned, { id: randomUUID(), from: f.clock() });
  assert.equal(await f.toolError('jarvis', 'bridge_message_send', f.canary()), 'friday_canary_spent');
  // Same UUID, moved/extended window: neither a new body nor the old receipt path.
  f.arm(f.pinned, { id: f.id, from: f.clock() });
  assert.equal(await f.toolError('jarvis', 'bridge_message_send', f.canary()), 'message_id_conflict');
  assert.equal(await f.toolError('friday', 'bridge_receipt_claim', { messageId: f.id }), 'friday_canary_only');
  // Same UUID and window but another return subscription: exact replay refused,
  // and the original queued work cannot be driven under the changed settings.
  f.arm(f.other, { id: f.id, from: start, until });
  assert.equal(await f.toolError('jarvis', 'bridge_message_send', original), 'friday_canary_spent');
  await assert.rejects(f.consume({ dispatchMessageId: f.id }), /bridge_job_pending/);
  assert.equal(f.posts.length, 0); assert.equal(f.db.document.jobs[jobId].attempts, 0);
  assert.deepEqual(f.db.document.fridayCanary, reservation);

  // Restart with the original settings: an exact replay is idempotent and the
  // single queued source job sends once across repeated callbacks.
  await f.rt.close();
  const restarted = await fixture({ db: f.db, now: start + 2000 }); restarted.arm(f.pinned, { id: f.id, from: start, until });
  assert.equal((await restarted.ok('jarvis', 'bridge_message_send', original)).duplicate, true);
  assert.equal(Object.keys(restarted.db.document.messages).length, 1);
  await restarted.consume({ dispatchMessageId: f.id }); await restarted.consume({ dispatchMessageId: f.id });
  assert.equal(fridayPosts(restarted).length, 1);
  assert.deepEqual(restarted.db.document.fridayCanary, reservation);

  // The spent diagnostic UUID and an ID with a replay tombstone are never a canary.
  const diagnostic = { messageId: SPENT_DIAGNOSTIC, receiverId: 'jarvis-friday-bridge-inbox' };
  const tombstoned = randomUUID();
  for (const [id, code] of [[SPENT_DIAGNOSTIC, 'friday_canary_spent'], [tombstoned, 'message_id_conflict']]) {
    const g = await fixture({ db: lockingDatabase({ ...emptyState(), fridayWebhookDiagnostic: diagnostic,
      messageIds: { [tombstoned]: { hash: 'd'.repeat(64), kind: 'status', until: Date.now() + 86400000 } } }) });
    g.arm(await g.subscribe(PINNED), { id });
    assert.equal(await g.toolError('jarvis', 'bridge_message_send', g.canary()), code);
    assert.deepEqual(g.db.document.fridayWebhookDiagnostic, diagnostic);
    assert.equal(g.db.document.fridayCanary, undefined); assert.deepEqual(g.db.document.messages, {});
  }
});

test('concurrent sends and callbacks, timeouts, crashes and ACK failures make at most one transport attempt per job', async () => {
  const slow = await armed({ respond: async () => { await new Promise(r => setTimeout(r, 20)); return { status: 202 }; } });
  const results = await Promise.all(Array.from({ length: 10 }, () => slow.ok('jarvis', 'bridge_message_send', slow.canary())));
  assert.equal(results.filter(r => !r.duplicate).length, 1);
  assert.equal(Object.keys(slow.db.document.jobs).length, 1);
  const callbacks = await Promise.allSettled(Array.from({ length: 4 }, () => slow.consume({ dispatchMessageId: slow.id })));
  assert.equal(fridayPosts(slow).length, 1);
  assert.ok(callbacks.every(r => r.status === 'fulfilled' || r.reason.message === 'bridge_job_pending'));

  // Ambiguous timeout: recorded once, terminal, never retried.
  const timeout = await armed({ respond: async () => { throw new BridgeError('callback_timeout', 503); } });
  await timeout.ok('jarvis', 'bridge_message_send', timeout.canary());
  await timeout.consume({ dispatchMessageId: timeout.id });
  timeout.advance(120000); await timeout.consume({ dispatchMessageId: timeout.id });
  const timedOut = Object.values(timeout.db.document.jobs)[0];
  assert.equal(timedOut.state, 'dead'); assert.equal(timedOut.transportAttempts, 1);
  assert.deepEqual({ ...timedOut.firstTransportOutcome, at: 0 }, { at: 0, workerAttempt: 1, status: null, error: 'callback_timeout', terminal: true });
  assert.equal(timeout.posts.length, 1);

  // Crash after transport (outcome commit lost), lease expiry and restart.
  const db = lockingDatabase();
  const crash = await armed({ db, respond: async () => { db.failUpdates = 1; return { status: 202 }; } });
  await crash.ok('jarvis', 'bridge_message_send', crash.canary());
  await assert.rejects(crash.consume({ dispatchMessageId: crash.id }), /storage_unavailable/);
  assert.equal(Object.values(db.document.jobs)[0].state, 'leased');
  await assert.rejects(crash.consume({ dispatchMessageId: crash.id }), /bridge_job_pending/);
  await crash.rt.close();
  const settings = Object.fromEntries(Object.entries(crash.env).filter(([k]) => k.startsWith('FRIDAY_CANARY_')));
  const recovered = await fixture({ db, env: settings, now: crash.clock() + 31000 });
  await recovered.consume({ dispatchMessageId: crash.id });
  assert.deepEqual([Object.values(db.document.jobs)[0].state, Object.values(db.document.jobs)[0].lastError], ['dead', 'attempt_limit']);
  assert.equal(crash.posts.length + recovered.posts.length, 1);

  // A transient ACK callback result is terminal for the one-shot ACK job.
  const ackFail = await armed({ respond: async url => ({ status: url === PINNED ? 503 : 202 }) });
  await ackFail.ok('jarvis', 'bridge_message_send', ackFail.canary());
  await ackFail.consume({ dispatchMessageId: ackFail.id });
  const claim = await ackFail.ok('friday', 'bridge_receipt_claim', { messageId: ackFail.id });
  const done = await ackFail.ok('friday', 'bridge_receipt_complete', { messageId: ackFail.id, claimId: claim.claimId, hostedEventId: null, hostedTurnId: null });
  await ackFail.consume({ dispatchReceiptOf: ackFail.id });
  ackFail.advance(120000); await ackFail.consume({ dispatchReceiptOf: ackFail.id });
  assert.deepEqual(ackFail.posts.map(p => p.url), [FRIDAY_URL, PINNED]);
  const status = await ackFail.ok('friday', 'bridge_status', { messageId: done.ackMessageId });
  assert.deepEqual(status.deliveries.map(d => [d.state, d.attempts, d.transportAttempts, d.lastStatus]), [['dead', 1, 1, 503]]);
});

test('window expiry during a DB commit or access await suppresses transport; later callbacks stay closed', async () => {
  // Commits during a source dispatch: 1 job lookup, 2 lease, 3 access check, 4 state recheck.
  for (const commit of [3, 4]) {
    // A window ending 10s ahead: crossing it leaves the 30s worker lease valid.
    const f = await armed();
    f.arm(f.pinned, { id: f.id, from: f.clock() - CANARY_MAX_WINDOW_MS + 10000, until: f.clock() + 10000 });
    await f.ok('jarvis', 'bridge_message_send', f.canary());
    let commits = 0;
    f.db.afterCommit = () => { if (++commits === commit) f.set(Date.parse(f.env.FRIDAY_CANARY_UNTIL)); };
    await f.consume({ dispatchMessageId: f.id });
    delete f.db.afterCommit;
    const job = Object.values(f.db.document.jobs)[0];
    assert.equal(f.posts.length, 0, `commit ${commit}`);
    assert.deepEqual([job.state, job.lastError, job.transportAttempts], ['dead', 'message_authorization_inactive', undefined]);
    await assert.rejects(f.consume({ dispatchMessageId: f.id }), /delivery_not_enabled/);
    assert.equal(await f.toolError('friday', 'bridge_receipt_claim', { messageId: f.id }), 'receiver_readiness_required');
    assert.equal((await f.readiness()).canaryArmed, false);
  }
  // Expiry during the reservation COMMIT keeps the spend and stores nothing.
  const f = await armed();
  f.db.afterCommit = () => { delete f.db.afterCommit; f.set(Date.parse(f.env.FRIDAY_CANARY_UNTIL)); };
  assert.equal(await f.toolError('jarvis', 'bridge_message_send', f.canary()), 'invalid_message_lifetime');
  assert.deepEqual(f.db.document.messages, {}); assert.equal(f.db.document.fridayCanary.messageId, f.id);
  f.arm(f.pinned, { id: f.id });
  assert.equal(await f.toolError('jarvis', 'bridge_message_send', f.canary()), 'friday_canary_spent');
  assert.equal(f.posts.length, 0);
});
