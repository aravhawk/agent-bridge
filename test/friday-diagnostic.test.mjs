import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { createRuntime } from '../src/runtime.mjs';
import { diagnosticWindowOpen, DIAGNOSTIC_MAX_WINDOW_MS } from '../src/friday-diagnostic.mjs';
import { emptyState } from '../src/store.mjs';
import { resourceFor } from '../src/resource.mjs';
import { SCOPES, BridgeError } from '../src/policy.mjs';
import { ISSUER } from './fixtures/provider.mjs';

// Offline fixtures only: no native endpoint, credential or provider is used.
const URL_SECRET = 'https://receiver.example.test/hook/FIXTURE_URL_TOKEN';
const KEY = 'FIXTURE_NOT_A_REAL_KEY';
const DIAGNOSTIC = 'bridge_friday_webhook_diagnostic';
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

// Mirrors the deployed state at the time of the diagnostic: OAuth contract and
// subscription setup attested, delivery/receiver policy/Friday contract closed.
const deployedEnv = now => ({ BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true',
  BRIDGE_ALLOWED_SUBJECT: 'fixture', BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_DELIVERY_ENABLED: 'false',
  BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
  DATABASE_URL: 'postgresql://fixture.neon.tech/neondb?sslmode=require', FRIDAY_RECEIVER_ID: 'jarvis-friday-bridge-inbox',
  FRIDAY_WEBHOOK_URL: URL_SECRET, FRIDAY_WEBHOOK_KEY: KEY, FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'false',
  FRIDAY_WEBHOOK_DIAGNOSTIC_FROM: new Date(now).toISOString(),
  FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL: new Date(now + 3600000).toISOString() });

// Transactions serialize like the production row lock (SELECT ... FOR UPDATE)
// and only COMMIT publishes the document, so races and crashes are faithful.
function lockingDatabase(initial = emptyState()) {
  const db = { document: structuredClone(initial), failUpdates: 0, tail: Promise.resolve() };
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

async function fixture({ env: changes = {}, db = lockingDatabase(), respond, now: start = Date.now() } = {}) {
  let now = start;
  const posts = [];
  const env = { ...deployedEnv(now), ...changes };
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const rt = createRuntime({ env, Pool: db.Pool, keyResolver: publicKey, clock: () => now,
    queueClient: { async send() { assert.fail('diagnostic must not use the delivery queue'); }, handleCallback: fn => fn },
    transportFactory: () => async (url, request) => {
      if (url !== env.FRIDAY_WEBHOOK_URL) return { status: 200, body: '' };
      posts.push({ url, ...request });
      return respond ? respond(request) : { status: 202, body: 'FIXTURE_RESPONSE_BODY' };
    } });
  const sign = (role, scopes = Object.values(SCOPES[role])) => new SignJWT({ scope: scopes.join(' ') })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject('fixture').setAudience(resourceFor(role))
    .setIssuedAt().setExpirationTime('2h').sign(privateKey);
  const tokens = { jarvis: await sign('jarvis'), friday: await sign('friday') };
  const rpc = async (role, method, params, token = tokens[role]) => {
    const response = await rt.handler(role)(new Request(resourceFor(role), { method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
    return { status: response.status, body: await response.json() };
  };
  const names = async (role, token) => (await rpc(role, 'tools/list', undefined, token)).body.result.tools.map(t => t.name);
  const call = (role = 'jarvis', args = {}, token) => rpc(role, 'tools/call', { name: DIAGNOSTIC, arguments: args }, token);
  const health = async (role, token) => (await rpc(role, 'tools/call', { name: 'bridge_health', arguments: {} }, token)).body.result.structuredContent;
  return { rt, env, db, posts, sign, rpc, names, call, health, advance: ms => { now += ms; } };
}

test('deployed discovery offers Friday its scoped catalog, never health only, and health reports the server view', async () => {
  const f = await fixture();
  const six = ['bridge_health', 'bridge_read', 'bridge_receipt_claim', 'bridge_receipt_complete', 'bridge_status', 'bridge_message_send'];
  assert.deepEqual(await f.names('friday'), six);
  assert.deepEqual((await f.health('friday')).caller, { role: 'friday', sendScope: true, ackScope: true, tools: six });
  // Whatever subset of its two directional scopes Friday was granted, the
  // server still lists bridge_status: a health-only list is not server output.
  for (const [scopes, tools] of [[[SCOPES.friday.probe], ['bridge_health', 'bridge_status', 'bridge_message_send']],
    [[SCOPES.friday.ack], ['bridge_health', 'bridge_read', 'bridge_receipt_claim', 'bridge_receipt_complete', 'bridge_status']]]) {
    const token = await f.sign('friday', scopes);
    assert.deepEqual(await f.names('friday', token), tools);
    const caller = (await f.health('friday', token)).caller;
    assert.deepEqual(caller, { role: 'friday', sendScope: scopes.includes(SCOPES.friday.probe),
      ackScope: scopes.includes(SCOPES.friday.ack), tools });
  }
  // Only the pre-attestation bootstrap returns health alone.
  const bootstrap = await fixture({ env: { BRIDGE_OAUTH_CONTRACT_VERIFIED: 'false' } });
  assert.deepEqual(await bootstrap.names('friday'), ['bridge_health']);
  assert.equal(f.posts.length, 0);
});

test('armed diagnostic sends exactly one fixed synthetic event to the configured Friday receiver with delivery off', async () => {
  const f = await fixture();
  const readiness = (await f.health('jarvis')).readiness;
  assert.equal(readiness.fridayWebhookDiagnosticArmed, true); assert.equal(readiness.deliveryEnabled, false);
  assert.ok((await f.names('jarvis')).includes(DIAGNOSTIC));
  const response = await f.call();
  assert.equal(response.status, 200);
  const result = response.body.result.structuredContent;
  assert.match(result.messageId, uuid);
  assert.deepEqual({ ...result, messageId: null, attemptedAt: null }, { messageId: null, attemptedAt: null,
    receiverId: 'jarvis-friday-bridge-inbox', duplicate: false, transport: { status: 202, error: null },
    wakeVerified: false, evidenceRequired: 'native_friday_run_with_exact_messageId', recorded: true });
  assert.equal(f.posts.length, 1);
  assert.equal(f.posts[0].url, URL_SECRET);
  assert.deepEqual(f.posts[0].headers, { 'content-type': 'application/json', authorization: 'Bearer ' + KEY });
  assert.equal(f.posts[0].body, JSON.stringify({ event: 'bridge.message.received', data: { messageId: result.messageId } }));
  const saved = f.db.document.fridayWebhookDiagnostic;
  assert.equal(saved.messageId, result.messageId); assert.equal(saved.outcome.status, 202);
  // Transport only: no message, job, receipt or queue item exists, so Friday's
  // native read of the UUID reports message_not_found.
  assert.deepEqual([f.db.document.messages, f.db.document.jobs, f.db.document.receipts], [{}, {}, {}]);
  const read = await f.rpc('friday', 'tools/call', { name: 'bridge_read', arguments: { messageId: result.messageId } });
  assert.deepEqual(read.body.result.structuredContent, { error: 'message_not_found' });
  assert.equal(await f.call().then(r => r.body.result.structuredContent.duplicate), true);
  assert.equal(f.posts.length, 1);
});

test('wrong caller, missing send scope or caller-supplied arguments cannot spend or send', async () => {
  const f = await fixture();
  assert.equal((await f.names('friday')).includes(DIAGNOSTIC), false);
  assert.equal((await f.call('friday')).status, 403);
  const ackOnly = await f.sign('jarvis', [SCOPES.jarvis.ack]);
  assert.equal((await f.names('jarvis', ackOnly)).includes(DIAGNOSTIC), false);
  assert.equal((await f.call('jarvis', {}, ackOnly)).status, 403);
  for (const args of [{ url: 'https://attacker.example.test' }, { messageId: '00000000-0000-4000-8000-000000000001' }, { body: {} }]) {
    assert.equal((await f.call('jarvis', args)).status, 400);
  }
  assert.equal(f.posts.length, 0); assert.equal(f.db.document.fridayWebhookDiagnostic, undefined);
});

test('unarmed, expired, overlong, wrong receiver or unattested configuration keeps the diagnostic closed', async () => {
  const later = new Date(Date.now() + 3 * 3600000).toISOString();
  for (const env of [{ FRIDAY_WEBHOOK_DIAGNOSTIC_FROM: undefined }, { FRIDAY_WEBHOOK_DIAGNOSTIC_FROM: '' },
    { FRIDAY_WEBHOOK_DIAGNOSTIC_FROM: 'soon' }, { FRIDAY_WEBHOOK_DIAGNOSTIC_FROM: later },
    { FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL: '' }, { FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL: 'soon' },
    { FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL: '2020-01-01T00:00:00Z' }, { FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL: later },
    { FRIDAY_RECEIVER_ID: 'jarvis-friday-test-receiver' }, { FRIDAY_RECEIVER_ID: '' },
    { FRIDAY_WEBHOOK_URL: 'http://receiver.example.test/hook' }, { FRIDAY_WEBHOOK_KEY: 'bad\nkey' },
    { DATABASE_URL: '' }, { BRIDGE_OAUTH_CONTRACT_VERIFIED: 'false' }]) {
    const f = await fixture({ env });
    assert.equal((await f.health('jarvis')).readiness.fridayWebhookDiagnosticArmed, false, JSON.stringify(env));
    assert.equal((await f.names('jarvis')).includes(DIAGNOSTIC), false);
    assert.ok((await f.call()).status >= 400);
    assert.equal(f.posts.length, 0); assert.equal(f.db.document.fridayWebhookDiagnostic, undefined);
  }
  const f = await fixture(); f.advance(3600000);
  assert.equal((await f.names('jarvis')).includes(DIAGNOSTIC), false);
  assert.equal((await f.call()).status, 403); assert.equal(f.posts.length, 0);
});

test('fixed arm interval enforces start/end boundaries and a maximum total duration', () => {
  const start = Date.now(), from = new Date(start).toISOString();
  const until = new Date(start + DIAGNOSTIC_MAX_WINDOW_MS).toISOString();
  assert.equal(diagnosticWindowOpen(from, until, start - 1), false);
  assert.equal(diagnosticWindowOpen(from, until, start), true);
  assert.equal(diagnosticWindowOpen(from, until, start + DIAGNOSTIC_MAX_WINDOW_MS - 1), true);
  assert.equal(diagnosticWindowOpen(from, until, start + DIAGNOSTIC_MAX_WINDOW_MS), false);
  assert.equal(diagnosticWindowOpen(from, from, start), false);
  assert.equal(diagnosticWindowOpen(until, from, start), false);
});

test('overlong arm stays closed as time passes and after a new runtime starts', async () => {
  const start = Date.now();
  const env = { FRIDAY_WEBHOOK_DIAGNOSTIC_FROM: new Date(start).toISOString(),
    FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL: new Date(start + 3 * 3600000).toISOString() };
  const f = await fixture({ env, now: start });
  for (let hour = 0; hour <= 3; hour++) {
    assert.equal((await f.health('jarvis')).readiness.fridayWebhookDiagnosticArmed, false);
    assert.equal((await f.names('jarvis')).includes(DIAGNOSTIC), false);
    assert.equal((await f.call()).status, 403);
    f.advance(3600000);
  }
  await f.rt.close();
  const restarted = await fixture({ env, db: f.db, now: start + 3600000 });
  assert.equal((await restarted.health('jarvis')).readiness.fridayWebhookDiagnosticArmed, false);
  assert.equal((await restarted.call()).status, 403);
  assert.equal(f.db.document.fridayWebhookDiagnostic, undefined);
  assert.equal(f.posts.length + restarted.posts.length, 0);
});

test('expiry during spend COMMIT suppresses transport and keeps the attempt spent across restart/re-arming', async () => {
  const f = await fixture();
  // Publish the marker while still armed, but finish COMMIT at the exact end.
  f.db.afterCommit = () => { delete f.db.afterCommit; f.advance(3600000); };
  const response = await f.call();
  assert.equal(response.status, 200);
  const result = response.body.result.structuredContent;
  assert.equal(result.duplicate, false); assert.equal(result.recorded, true);
  assert.deepEqual(result.transport, { status: null, error: 'friday_diagnostic_expired' });
  assert.match(result.messageId, uuid);
  assert.equal(f.posts.length, 0);
  assert.equal(f.db.document.fridayWebhookDiagnostic.messageId, result.messageId);
  assert.deepEqual(f.db.document.fridayWebhookDiagnostic.outcome.error, 'friday_diagnostic_expired');
  assert.equal((await f.health('jarvis')).readiness.deliveryEnabled, false);
  assert.deepEqual([f.db.document.messages, f.db.document.jobs, f.db.document.receipts], [{}, {}, {}]);
  await f.rt.close();
  const restarted = await fixture({ db: f.db });
  const duplicate = (await restarted.call()).body.result.structuredContent;
  assert.equal(duplicate.duplicate, true); assert.equal(duplicate.messageId, result.messageId);
  assert.deepEqual(duplicate.transport, result.transport);
  assert.equal(restarted.posts.length, 0);
});

test('concurrent calls commit one spend marker and one POST; the rest return that attempt', async () => {
  const f = await fixture({ respond: async () => { await new Promise(r => setTimeout(r, 20)); return { status: 204 }; } });
  const results = await Promise.all(Array.from({ length: 12 }, () => f.call()));
  const outputs = results.map(r => r.body.result.structuredContent);
  assert.equal(f.posts.length, 1);
  assert.equal(outputs.filter(o => !o.duplicate).length, 1);
  assert.equal(new Set(outputs.map(o => o.messageId)).size, 1);
});

test('restart, re-arming or a lost outcome never re-sends; ambiguous results are recorded, not retried', async () => {
  const first = await fixture({ respond: async () => { throw new BridgeError('callback_timeout', 503); } });
  const spent = (await first.call()).body.result.structuredContent;
  assert.deepEqual(spent.transport, { status: null, error: 'callback_timeout' });
  assert.equal(first.posts.length, 1);
  await first.rt.close();
  // A new instance with a fresh window still sees the durable marker.
  const restarted = await fixture({ db: first.db });
  const again = (await restarted.call()).body.result.structuredContent;
  assert.equal(again.duplicate, true); assert.equal(again.messageId, spent.messageId);
  assert.deepEqual(again.transport, { status: null, error: 'callback_timeout' });
  assert.equal(restarted.posts.length, 0);

  // Outcome commit fails after the POST: the attempt stays spent and unresolved.
  const db = lockingDatabase();
  const lost = await fixture({ db, respond: async () => { db.failUpdates = 1; return { status: 500 }; } });
  const reported = (await lost.call()).body.result.structuredContent;
  assert.equal(reported.recorded, false); assert.deepEqual(reported.transport, { status: 500, error: null });
  const later = (await lost.call()).body.result.structuredContent;
  assert.equal(later.duplicate, true); assert.equal(later.messageId, reported.messageId);
  assert.deepEqual(later.transport, { status: null, error: 'outcome_not_recorded' });
  assert.equal(lost.posts.length, 1);

  // A failed spend commit sends nothing and leaves the diagnostic unspent.
  const closedDb = lockingDatabase(); closedDb.failUpdates = 1;
  const closed = await fixture({ db: closedDb });
  assert.equal((await closed.call()).status, 503);
  assert.equal(closed.posts.length, 0); assert.equal(closedDb.document.fridayWebhookDiagnostic, undefined);
});

test('responses, stored evidence and failures never contain the receiver URL, key or response body', async () => {
  const thrown = await fixture({ respond: async () => { throw new Error(KEY + ' ' + URL_SECRET); } });
  const failed = await thrown.call();
  assert.deepEqual(failed.body.result.structuredContent.transport, { status: null, error: 'friday_transport_failed' });
  const ok = await fixture();
  const success = await ok.call();
  for (const output of [failed, success, thrown.db.document, ok.db.document, await ok.health('jarvis')]) {
    const text = JSON.stringify(output);
    for (const secret of [KEY, URL_SECRET, 'FIXTURE_URL_TOKEN', 'receiver.example.test', 'FIXTURE_RESPONSE_BODY']) {
      assert.equal(text.includes(secret), false, secret);
    }
  }
});
