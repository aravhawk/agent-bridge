import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { generateKeyPair, SignJWT } from 'jose';
import { emptyState } from '../src/store.ts';
import { SCOPES } from '../src/policy.ts';
import { MESSAGE_PROTOCOL } from '../src/messages.ts';
import { EVENT_NAME } from '../src/events.ts';
import { createRuntime, OUTBOX_RECONCILE_GRACE_MS } from '../src/runtime.ts';
import { resourceFor } from '../src/resource.ts';
import { TOPIC } from '../src/queue.ts';
import { ISSUER } from './fixtures/provider.ts';
import { qstashConfig, verifyQStashTick, boundedBody, tickSeen, recordTick, QSTASH_TICK_BODY, MAX_TICK_BODY_BYTES,
  createQStashFailureDiagnostic, projectQStashJoseFailure, MAX_DIAGNOSTIC_BYTES } from '../src/qstash.ts';
import type { BridgeError } from '../src/policy.ts';
import type { RuntimePoolConstructor, RuntimeQueueClient } from '../src/runtime.ts';
import type { QueueClient } from '../src/queue.ts';
import type { TransportRequest, TransportResponse } from '../src/webhook.ts';
import type { BridgeState, JsonObject } from '../src/types.ts';
import type { RpcResponse, ToolCallResult } from './types.ts';
import type { BatchPresentation, ClaimResult, CompleteResult, ReadResult, SendResult, StatusResult } from '../src/bridge.ts';

/** bridge_health output as these tests read it. */
type HealthView = { readiness: { wakeSync: { flushScheduleConfigured: boolean } } };
/** A message draft built by sync(); deleting `class` makes it a WAKE. */
type Draft = { id: string; class?: string; [field: string]: unknown };

interface SignOptions { at?: number; key?: string; body?: string; claims?: Record<string, unknown>; omit?: string[]; alg?: string }
type SendArgs = Parameters<QueueClient['send']>;
type Consumer = (payload: unknown, metadata: object) => Promise<unknown>;
/** The cron route's JSON report (runtime.ts cronHandler), as these tests read it. */
type CronReport = { [field: string]: unknown; status?: string; flushed?: number; dispatched?: number; dispatchPending?: number; error?: string };

// Offline only: fake signing keys and real HS256 crypto (jose). No network.
const HOUR = 3600000, MINUTE = 60000;
const start = Date.UTC(2026, 9, 19, 15, 30), noon = Date.UTC(2026, 9, 19, 17);
const iso = (ms: number) => new Date(ms).toISOString();
const DEST = 'https://bridge.example.test/api/cron';
const CURRENT = 'sig_FAKECURRENTKEYFORTESTS0001', NEXT = 'sig_FAKENEXTKEYFORTESTS000002', OLD = 'sig_FAKEWITHDRAWNKEY00000003';
const QSTASH = { QSTASH_CURRENT_SIGNING_KEY: CURRENT, QSTASH_NEXT_SIGNING_KEY: NEXT, BRIDGE_QSTASH_DESTINATION_URL: DEST };
const bodyHash = (body: string) => createHash('sha256').update(body).digest('base64url');
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
async function sign({ at, key = CURRENT, body = QSTASH_TICK_BODY, claims = {}, omit = [], alg = 'HS256' }: SignOptions = {}) {
  const now = Math.floor(at! / 1000); // Every call supplies the signing time.
  const payload: Record<string, unknown> = { iss: 'Upstash', sub: DEST, iat: now, nbf: now, exp: now + 300, jti: 'jwt_' + randomUUID().replaceAll('-', ''),
    body: bodyHash(body), ...claims };
  for (const k of omit) delete payload[k];
  return new SignJWT(payload).setProtectedHeader({ alg, typ: 'JWT' }).sign(new TextEncoder().encode(key));
}
const verify = (signature: string, { body = QSTASH_TICK_BODY, now = start, env = QSTASH as Record<string, string | undefined> }:
  { body?: string; now?: number; env?: Record<string, string | undefined> } = {}) =>
  verifyQStashTick({ config: qstashConfig(env), signature, body: Buffer.from(body), now });
const refused = (promise: Promise<unknown>, code = 'scheduler_signature_invalid') => assert.rejects(promise, (e: BridgeError) => e.code === code || assert.fail(`expected ${code}, got ${e.code}`));

test('qstash config: exact https destination /api/cron and both keys, else not valid', () => {
  assert.deepEqual(qstashConfig(QSTASH), { valid: true, current: CURRENT, next: NEXT, destination: DEST });
  for (const change of [{ QSTASH_CURRENT_SIGNING_KEY: undefined }, { QSTASH_NEXT_SIGNING_KEY: '' }, { QSTASH_CURRENT_SIGNING_KEY: 'short' },
    { BRIDGE_QSTASH_DESTINATION_URL: undefined }, { BRIDGE_QSTASH_DESTINATION_URL: 'http://bridge.example.test/api/cron' },
    { BRIDGE_QSTASH_DESTINATION_URL: DEST + '/' }, { BRIDGE_QSTASH_DESTINATION_URL: DEST + '?x=1' },
    { BRIDGE_QSTASH_DESTINATION_URL: 'https://bridge.example.test:8443/api/cron' }, { BRIDGE_QSTASH_DESTINATION_URL: 'https://u:p@bridge.example.test/api/cron' },
    { BRIDGE_QSTASH_DESTINATION_URL: 'https://bridge.example.test/api/index' }, { BRIDGE_QSTASH_DESTINATION_URL: 'https://BRIDGE.example.test/api/cron' }]) {
    assert.deepEqual(qstashConfig({ ...QSTASH, ...change }), { valid: false }, JSON.stringify(change));
  }
});

test('qstash signature: current or next key; body, destination, algorithm, issuer and every claim are enforced', async () => {
  const ok = await verify(await sign({ at: start }));
  assert.equal(ok.key, CURRENT); assert.match(ok.jti, /^jwt_/);
  assert.equal((await verify(await sign({ at: start, key: NEXT }))).key, NEXT, 'rotation: next key accepted');
  await refused(verify(await sign({ at: start, key: OLD })));
  // Body binding: any other raw body, even semantically equal JSON, fails.
  await refused(verify(await sign({ at: start }), { body: '{"v":1,"kind":"bridge.scheduled-tick"}' }), 'scheduler_body_invalid');
  await refused(verify(await sign({ at: start }), { body: QSTASH_TICK_BODY + ' ' }), 'scheduler_body_invalid');
  // A correctly signed body that is not the static control body is refused too (no content via schedules).
  const content = '{"kind":"bridge.scheduled-tick","v":1,"text":"hi"}';
  await refused(verify(await sign({ at: start, body: content }), { body: content }), 'scheduler_body_invalid');
  // Padded body hash is accepted, as by the official receiver.
  assert.ok(await verify(await sign({ at: start, claims: { body: bodyHash(QSTASH_TICK_BODY) + '=' } })));
  for (const [name, options] of ([
    ['destination', { claims: { sub: 'https://other.example.test/api/cron' } }],
    ['destination trailing slash', { claims: { sub: DEST + '/' } }],
    ['issuer', { claims: { iss: 'upstash' } }],
    ['algorithm HS512', { alg: 'HS512' }],
    ['algorithm HS384', { alg: 'HS384' }],
    ['not yet valid', { claims: { nbf: Math.floor(start / 1000) + 60 } }],
    ['expired', { claims: { exp: Math.floor(start / 1000) - 60 } }],
    ['issued in the future', { claims: { iat: Math.floor(start / 1000) + 60, nbf: Math.floor(start / 1000) + 60 } }],
    ['lifetime too long', { claims: { exp: Math.floor(start / 1000) + 3600 } }],
    ['bad jti', { claims: { jti: 'x'.repeat(200) } }],
    ['numeric jti', { claims: { jti: 7 } }],
    ['bad body claim', { claims: { body: 'not-a-hash' } }],
    ...['iss', 'sub', 'exp', 'nbf', 'iat', 'jti', 'body'].map(claim => [`missing ${claim}`, { omit: [claim] }]),
  ] as [string, Partial<SignOptions>][])) {
    await assert.rejects(verify(await sign({ at: start, ...options })), (e: BridgeError) => ['scheduler_signature_invalid', 'scheduler_body_invalid'].includes(e.code), name);
  }
  // Unsigned / malformed tokens.
  const now = Math.floor(start / 1000);
  const claims = { iss: 'Upstash', sub: DEST, iat: now, nbf: now, exp: now + 300, jti: 'jwt_x', body: bodyHash(QSTASH_TICK_BODY) };
  await refused(verify(`${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims)}.xx`));
  await refused(verify(`${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims)}.`));
  await refused(verify('a.b'));
  await refused(verify('x'.repeat(5000) + '.a.b'));
  const good = await sign({ at: start });
  await refused(verify(good.slice(0, -2) + (good.endsWith('AA') ? 'BB' : 'AA')));
  // Clock: valid within its lifetime (small tolerance), not after.
  assert.ok(await verify(good, { now: start + 4 * MINUTE }));
  await refused(verify(good, { now: start + 6 * MINUTE }));
  // No configuration: refused as unconfigured.
  await refused(verify(good, { env: {} }), 'scheduler_not_configured');
});

// --- Runtime route ------------------------------------------------------------
async function fixture(changes: Record<string, string | undefined> = {}) {
  let document: BridgeState = emptyState(), now = start, consumer!: Consumer, connects = 0;
  const sends: SendArgs[] = [], posts: JsonObject[] = [], faults: { send: ((args: SendArgs) => unknown) | null } = { send: null };
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  class Pool { on() {} async connect() { connects++; return { release() {}, async query(sql: string, params: string[]) {
    if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(document) }] };
    if (sql.startsWith('UPDATE bridge_runtime_v1')) document = JSON.parse(params[0]!);
    return { rows: [] };
  } }; } }
  const env: Record<string, string | undefined> = { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture', BRIDGE_DELIVERY_ENABLED: 'true',
    BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
    DATABASE_URL: 'postgresql://fixture.neon.tech/neondb?sslmode=require', BRIDGE_RECEIVER_POLICY: 'inbox-v1',
    FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true', FRIDAY_RECEIVER_ID: 'jarvis-friday-bridge-inbox',
    FRIDAY_WEBHOOK_URL: 'https://receiver.example.test/event', FRIDAY_WEBHOOK_KEY: 'FIXTURE_ONLY',
    BRIDGE_WAKE_SYNC_RECIPIENTS: 'friday', ...QSTASH, ...changes };
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete env[k];
  const rt = createRuntime({ env, Pool: Pool as unknown as RuntimePoolConstructor, keyResolver: publicKey, clock: () => now,
    queueClient: { async send(...args: SendArgs) { if (faults.send?.(args)) throw Error('FIXTURE_QUEUE_FAULT'); sends.push(args); },
      handleCallback(fn: Consumer) { consumer = fn; return fn; } } as unknown as RuntimeQueueClient, // Captures the consumer.
    transportFactory: () => async (_url: string, req: TransportRequest): Promise<TransportResponse> => { const body = JSON.parse(req.body); posts.push(body);
      return { status: 200, body: JSON.stringify({ challenge: body.challenge }) }; } });
  const tokens: Record<string, string> = {};
  for (const role of ['jarvis', 'friday']) tokens[role] = await new SignJWT({ scope: Object.values(SCOPES[role]!).join(' ') })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject('fixture').setAudience(resourceFor(role)).setIssuedAt().setExpirationTime('30d').sign(privateKey);
  const rpc = async (role: string, method: string, params: object): Promise<RpcResponse<ToolCallResult<Record<string, unknown>>>> => (await (await rt.handler(role)(new Request(resourceFor(role), { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tokens[role] },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }))).json() as RpcResponse<ToolCallResult<Record<string, unknown>>>);
  const call = async <T = Record<string, unknown>>(role: string, name: string, args?: object): Promise<T> =>
    (await rpc(role, 'tools/call', { name, arguments: args })).result.structuredContent as T;
  await rpc('jarvis', 'events/subscribe', { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  // A QStash-style delivery: the request URL is whatever the platform says;
  // only the configured destination is trusted.
  const deliver = async ({ signature, body = QSTASH_TICK_BODY, method = 'POST', headers = {} }:
    { signature?: string; body?: string | ReadableStream<Uint8Array>; method?: string; headers?: Record<string, string> } = {}) =>
    rt.cronHandler()(new Request('https://internal-proxy.example.invalid/api/cron', { method,
      headers: { 'upstash-signature': signature ?? await sign({ at: now }), 'content-type': 'application/json',
        'upstash-message-id': 'msg_unsigned', 'upstash-retried': '0', ...headers },
      ...(method === 'GET' || method === 'HEAD' ? {} : { body, duplex: 'half' }) } as RequestInit));
  const sync = (extra: Record<string, unknown> = {}): Draft => ({ protocol: MESSAGE_PROTOCOL, id: randomUUID(), from: 'jarvis', to: 'friday', kind: 'status', sentAt: iso(now),
    expiresAt: iso(now + 6 * HOUR), threadId: randomUUID(), route: 'inbox', text: 'Fixture runtime status', class: 'sync', ...extra });
  return { rt, env, call, deliver, sends, posts, faults, document: () => document, connects: () => connects, sync,
    set: (ms: number) => { now = ms; }, now: () => now,
    async consume(payload: unknown) { rt.queueHandler(); return consumer(payload, { topicName: TOPIC, region: 'iad1', deliveryCount: 1 }); } };
}
const dispatched = (f: { sends: SendArgs[] }) => f.sends.map(a => a[1]).filter(p => p.dispatchMessageId);

test('qstash route: a verified tick runs the flush; bad requests fail closed before storage with non-retryable 489', async () => {
  const f = await fixture();
  for (const subject of ['A', 'B']) assert.equal((await f.call<SendResult>('jarvis', 'bridge_message_send', f.sync({ subject }))).delivery, 'batched');
  f.set(noon + 5 * MINUTE); f.sends.length = 0;
  const before = f.connects();
  for (const [name, request, status, code] of [
    ['wrong key', { signature: await sign({ at: noon + 5 * MINUTE, key: OLD }) }, 489, 'scheduler_signature_invalid'],
    ['wrong body', { body: '{"kind":"bridge.scheduled-tick","v":2}' }, 489, 'scheduler_body_invalid'],
    ['oversize declared', { body: 'x'.repeat(MAX_TICK_BODY_BYTES + 1) }, 489, 'scheduler_body_too_large'],
    ['oversize streamed', { body: new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(600)); } }), headers: {} }, 489, 'scheduler_body_too_large'],
    ['wrong destination', { signature: await sign({ at: noon + 5 * MINUTE, claims: { sub: 'https://internal-proxy.example.invalid/api/cron' } }) }, 489, 'scheduler_signature_invalid'],
    ['GET', { method: 'GET' }, 405, 'method_not_allowed'],
    ['PUT', { method: 'PUT' }, 405, 'method_not_allowed'],
    ['DELETE', { method: 'DELETE' }, 405, 'method_not_allowed'],
    ['empty signature', { signature: '' }, 489, 'scheduler_signature_invalid'],
  ] as [string, Parameters<typeof f.deliver>[0], number, string][]) {
    const response = await f.deliver(request);
    assert.equal(response.status, status, name);
    assert.deepEqual(await response.json(), { error: code }, name);
    if (status === 489) assert.equal(response.headers.get('upstash-nonretryable-error'), 'true', name);
  }
  assert.equal(f.connects(), before, 'no storage access for any refused delivery');
  assert.equal(dispatched(f).length, 0);
  // A valid tick, signed with the next key (rotation), flushes exactly as the bearer route does.
  const response = await f.deliver({ signature: await sign({ at: noon + 5 * MINUTE, key: NEXT }) });
  assert.equal(response.status, 200);
  const out = await response.json() as CronReport;
  assert.deepEqual([out.status, out.flushed, out.dispatched], ['ok', 1, 1]);
  assert.equal(JSON.stringify(out).includes('msg_unsigned'), false, 'unsigned headers are never echoed or used');
  assert.equal(dispatched(f).length, 1);
});

test('qstash route: unconfigured keys, destination or a key withdrawn during the await are 503 before storage', async () => {
  for (const change of [{ QSTASH_NEXT_SIGNING_KEY: undefined }, { BRIDGE_QSTASH_DESTINATION_URL: undefined }]) {
    const f = await fixture(change), before = f.connects();
    const response = await f.deliver();
    assert.deepEqual([response.status, await response.json()], [503, { error: 'scheduler_not_configured' }]);
    assert.equal(f.connects(), before);
  }
  // The verifying key is withdrawn (rotated out) while the body is still being read.
  const f = await fixture(), before = f.connects();
  const signature = await sign({ at: start });
  let sent = false;
  const body = new ReadableStream({ pull(c) {
    if (sent) { c.close(); return; }
    sent = true; f.env.QSTASH_CURRENT_SIGNING_KEY = OLD; c.enqueue(Buffer.from(QSTASH_TICK_BODY));
  } });
  const response = await f.rt.cronHandler()(new Request(DEST, { method: 'POST', body, duplex: 'half', headers: { 'upstash-signature': signature } }));
  assert.deepEqual([response.status, await response.json()], [503, { error: 'scheduler_not_configured' }]);
  assert.equal(f.connects(), before, 'no storage access');
  // The same delivery after the rotation completes is refused outright.
  const again = await f.deliver({ signature });
  assert.equal(again.status, 489);
});

test('qstash route: a replayed delivery is a no-op; overlapping ticks wake once', async () => {
  const f = await fixture();
  await f.call<SendResult>('jarvis', 'bridge_message_send', f.sync({ subject: 'A' }));
  f.set(noon + 5 * MINUTE); f.sends.length = 0;
  const signature = await sign({ at: noon + 5 * MINUTE });
  const [a, b] = await Promise.all([f.deliver({ signature: await sign({ at: noon + 5 * MINUTE }) }), f.deliver({ signature })]);
  assert.deepEqual([a.status, b.status], [200, 200]);
  assert.equal(dispatched(f).length, 1, 'overlapping ticks: one flush, one wake');
  // Replaying the exact accepted delivery within its token lifetime does nothing.
  const replay = await f.deliver({ signature });
  assert.deepEqual(await replay.json(), { status: 'duplicate_tick' });
  assert.equal(dispatched(f).length, 1);
  // The replay record is bounded by token expiry and holds no content.
  const ticks = f.document().schedulerTicks as Record<string, number>;
  assert.ok(Object.values(ticks).every(until => until <= noon + 10 * MINUTE + 1000));
  assert.equal(JSON.stringify(ticks).includes(DEST), false);
});

test('qstash route: after a long outage one tick catches up every pending item and overdue outbox job; caps unchanged', async () => {
  const f = await fixture();
  const ids: string[] = [];
  for (let i = 0; i < 6; i++) { const m = f.sync({ subject: `s${i}` }); ids.push(m.id); await f.call<SendResult>('jarvis', 'bridge_message_send', m); f.set(f.now() + 7 * MINUTE); }
  // A direct WAKE (Friday -> Jarvis) whose immediate dispatch was lost: its job stays pending in the outbox.
  const wake = { ...f.sync({ from: 'friday', to: 'jarvis', subject: 'urgent' }), expiresAt: iso(f.now() + HOUR) };
  delete wake.class;
  const sent = await f.call<SendResult>('friday', 'bridge_message_send', wake);
  const jobId = f.document().messages[sent.messageId]!.jobIds[0];
  assert.equal(f.document().jobs[jobId!]!.state, 'pending');
  f.sends.length = 0;
  // Nine hours without any tick (scheduler outage), then one delivery.
  f.set(noon + 9 * HOUR + 5 * MINUTE);
  const out = await (await f.deliver()).json() as CronReport;
  assert.equal(out.status, 'ok');
  assert.equal(out.flushed, 1);
  const batchId = dispatched(f)[0]!.dispatchMessageId;
  const batch = f.document().messages[batchId as string]!.syncBatch!;
  assert.deepEqual([...batch.itemIds].sort(), [...ids].sort(), 'every queued item in one batch, none collapsed or dropped');
  assert.ok((out.outboxRescheduled as number) >= 1, 'the stranded WAKE job is re-offered');
  assert.ok(f.sends.some(args => args[1].jobId === jobId));
  assert.equal(f.document().syncQueues!.friday!.flushCount, 1, 'one daily-cap slot used');
  assert.ok(OUTBOX_RECONCILE_GRACE_MS >= 5 * MINUTE);
});

test('qstash readiness: one boolean; no key, destination or token is ever reported', async () => {
  const f = await fixture();
  const health = await f.call<HealthView>('friday', 'bridge_health', {});
  assert.equal(health.readiness.wakeSync.flushScheduleConfigured, true);
  const text = JSON.stringify(health);
  for (const secret of [CURRENT, NEXT, DEST]) assert.equal(text.includes(secret), false);
  const g = await fixture({ QSTASH_NEXT_SIGNING_KEY: undefined });
  assert.equal((await g.call<HealthView>('friday', 'bridge_health', {})).readiness.wakeSync.flushScheduleConfigured, false);
});

test('qstash replay cache: every accepted jti is representable, including reserved object keys', async () => {
  for (const jti of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf', 'jwt_ok']) {
    const state = {} as BridgeState; // An empty document: the replay cache section is created on demand.
    assert.equal(tickSeen(state, jti, start), false, jti);
    recordTick(state, jti, start + 300000, start);
    assert.equal(tickSeen(state, jti, start), true, jti);
    assert.equal(tickSeen(state, jti, start + 300000), false, `${jti} expires`);
    assert.equal(Object.getPrototypeOf(state.schedulerTicks), Object.prototype, 'prototype untouched');
    assert.deepEqual(JSON.parse(JSON.stringify(state)).schedulerTicks, { ['j:' + jti]: start + 300000 }, 'survives a JSON round trip');
  }
  // End to end: a signed tick whose jti is '__proto__' is replay-suppressed like any other.
  const f = await fixture();
  f.set(noon + 5 * MINUTE);
  const signature = await sign({ at: noon + 5 * MINUTE, claims: { jti: '__proto__' } });
  assert.equal((await (await f.deliver({ signature })).json() as CronReport).status, 'ok');
  assert.deepEqual(await (await f.deliver({ signature })).json(), { status: 'duplicate_tick' });
});

test('qstash body read: bounded in total time; a stalled or slow-drip body is cancelled before storage (408, retryable)', async () => {
  let cancelled = false;
  const stalled = new Request(DEST, { method: 'POST', duplex: 'half', body: new ReadableStream({ pull() { return new Promise(() => {}); },
    cancel() { cancelled = true; } }) });
  await assert.rejects(boundedBody(stalled, MAX_TICK_BODY_BYTES, 50), (e: BridgeError) => e.code === 'scheduler_body_timeout' && e.status === 408);
  assert.equal(cancelled, true);
  // Each chunk arrives quickly, but the total exceeds the deadline.
  const drip = new Request(DEST, { method: 'POST', duplex: 'half', body: new ReadableStream({
    async pull(c) { await new Promise(r => setTimeout(r, 20)); c.enqueue(new Uint8Array(1)); } }) });
  await assert.rejects(boundedBody(drip, MAX_TICK_BODY_BYTES, 100), /scheduler_body_timeout/);
  assert.deepEqual(await boundedBody(new Request(DEST, { method: 'POST', body: QSTASH_TICK_BODY }), MAX_TICK_BODY_BYTES, 1000),
    Buffer.from(QSTASH_TICK_BODY));
});

test('qstash route: a failing outbox job is isolated (the ACK behind it is still offered) and the run is a 503', async () => {
  const f = await fixture();
  // A Jarvis -> Friday WAKE and a Friday -> Jarvis ACK, both with lost dispatch, long overdue.
  const w = { ...f.sync({ subject: 'w' }), expiresAt: iso(f.now() + HOUR) }; delete w.class;
  const sent = await f.call<SendResult>('jarvis', 'bridge_message_send', w);
  const read = await f.call<ReadResult>('friday', 'bridge_read', { messageId: sent.messageId });
  assert.ok(read.envelope);
  const claim = await f.call<ClaimResult>('friday', 'bridge_receipt_claim', { messageId: sent.messageId });
  const done = await f.call<CompleteResult>('friday', 'bridge_receipt_complete', { messageId: sent.messageId, claimId: claim.claimId,
    hostedEventId: null, hostedTurnId: null });
  const wakeJob = f.document().messages[sent.messageId]!.jobIds[0]!, ackJob = f.document().messages[done.ackMessageId!]!.jobIds[0]!;
  f.set(f.now() + 20 * MINUTE); f.sends.length = 0;
  f.faults.send = args => args[1].jobId === wakeJob;
  // Unsigned provider headers cannot choose identity or priority.
  const response = await f.deliver({ headers: { 'upstash-message-id': ackJob, 'upstash-schedule-id': 'x', 'upstash-retried': '9',
    'upstash-priority': 'batch-first', 'upstash-forward-job': wakeJob } });
  const out = await response.json() as CronReport;
  assert.equal(response.status, 503); assert.equal(out.status, 'outbox_pending');
  assert.deepEqual([out.outboxRescheduled, out.outboxFailed], [1, 1]);
  assert.deepEqual(f.sends.map(a => a[1].jobId).filter(Boolean), [ackJob], 'the ACK was offered first and despite the failure');
  // The next tick retries the failed job (rotated), the ACK is not starved either.
  f.faults.send = null; f.sends.length = 0; f.set(f.now() + 5 * MINUTE);
  assert.equal((await f.deliver()).status, 200);
  assert.deepEqual(f.sends.map(a => a[1].jobId).filter(Boolean).sort(), [wakeJob, ackJob].sort());
});

// --- Dry-run schedule plan (never creates anything) ----------------------------
test('schedule plan: dry run only, no network, no token, static control body, bounded retries and budget', () => {
  const script = new URL('../scripts/qstash-schedule-plan.ts', import.meta.url);
  const refused = spawnSync(process.execPath, [script.pathname], { encoding: 'utf8', env: {} });
  assert.equal(refused.status, 2, 'refuses without --dry-run');
  const out = execFileSync(process.execPath, [script.pathname, '--dry-run', '--destination', DEST], { encoding: 'utf8',
    env: { QSTASH_TOKEN: 'FAKE_TOKEN_MUST_NOT_APPEAR', QSTASH_CURRENT_SIGNING_KEY: CURRENT } });
  assert.equal(out.includes('FAKE_TOKEN_MUST_NOT_APPEAR'), false); assert.equal(out.includes(CURRENT), false);
  const plan = JSON.parse(out);
  assert.equal(plan.dryRun, true);
  assert.equal(plan.request.headers['Upstash-Cron'], '*/5 * * * *');
  assert.equal(plan.request.body, QSTASH_TICK_BODY);
  assert.equal(plan.request.headers['Upstash-Retries'], '2');
  assert.equal(plan.request.headers.Authorization, 'Bearer $QSTASH_TOKEN');
  assert.ok(!Object.keys(plan.request.headers).some(h => /^Upstash-Forward-/i.test(h)), 'no forwarded secrets');
  assert.deepEqual(plan.budget, { ticksPerDay: 288, ticksPer30Days: 8640, maxAttemptsPerDay: 864, maxAttemptsPer30Days: 25920,
    usdPer100kAttempts: 1, maxUsdPer30Days: 0.26 });
  const source = readFileSync(script, 'utf8');
  assert.equal(/\bfetch\s*\(|node:https?|node:net|child_process/.test(source), false, 'the plan script cannot make requests');
  // Destination must be the exact https /api/cron URL.
  assert.equal(spawnSync(process.execPath, [script.pathname, '--dry-run', '--destination', 'http://x.test/api/cron'], { encoding: 'utf8' }).status, 2);
});

test('schedule plan: a shell-active destination is refused; the template single-quotes the destination (never run here)', () => {
  const script = new URL('../scripts/qstash-schedule-plan.ts', import.meta.url).pathname;
  // Only parsed and handed to the plan script as an argv string; no shell is involved anywhere.
  const run = (destination: string) => spawnSync(process.execPath, [script, '--dry-run', '--destination', destination], { encoding: 'utf8', env: {} });
  const hostile = ['https://$(id)/api/cron', 'https://`id`/api/cron', 'https://a$b.example.test/api/cron', 'https://a!b.example.test/api/cron',
    "https://a'b.example.test/api/cron", 'https://a&b.example.test/api/cron', 'https://a;b.example.test/api/cron', 'https://a(b).example.test/api/cron'];
  // WHATWG URL accepts the first two unchanged, so URL parsing alone was not a sufficient check.
  for (const destination of hostile.slice(0, 2)) assert.equal(new URL(destination).href, destination);
  for (const destination of [...hostile, 'https://127.0.0.1/api/cron', 'https://Bridge.example.test/api/cron', 'https://localhost/api/cron',
    'https://bridge.example.test:443/api/cron', 'https://bridge.example.test/api/cron?x', 'https://u@bridge.example.test/api/cron', '']) {
    const refused = run(destination);
    assert.equal(refused.status, 2, destination);
    assert.equal(refused.stdout, '', `nothing printed for ${destination}`);
  }
  const ok = run(DEST);
  assert.equal(ok.status, 0);
  const { curl } = JSON.parse(ok.stdout);
  // Every double-quoted span is one of the two intended expansions; the destination is never inside one.
  assert.deepEqual([...new Set(curl.match(/"[^"']*"(?=\s|'|$)/g))].sort(),
    ['"$QSTASH_URL/v2/schedules/"', '"Authorization: Bearer $QSTASH_TOKEN"']);
  const lines = curl.split('\n');
  assert.equal(lines.at(-1), `  "$QSTASH_URL/v2/schedules/"'${DEST}'`, 'the destination is a separate single-quoted word');
  // Continuations are a backslash followed by a real newline, never a literal "\n".
  assert.equal(curl.includes('\\n'), false);
  assert.ok(lines.length > 10);
  for (const line of lines.slice(0, -1)) assert.match(line, / \\$/);
  for (const line of lines.slice(1)) assert.match(line, /^  \S/);
});

test('qstash diagnostics: only literal categories/claims survive untrusted errors, getters and proxies; one bounded deterministic event', () => {
  const poison = 'SYNTHETIC_PRIVATE_ERROR_URL_HEADER_PAYLOAD_MUST_NOT_APPEAR';
  for (const [error, category, claim] of [
    [{code:'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',message:poison},'signature_mismatch',null],
    [{code:'ERR_JWT_EXPIRED',claim:'exp',cause:poison},'expired','exp'],
    [{code:'ERR_JWT_CLAIM_VALIDATION_FAILED',claim:'sub',reason:'check_failed',payload:{secret:poison}},'subject_invalid','sub'],
    [{code:'ERR_JWT_CLAIM_VALIDATION_FAILED',claim:'iat',reason:'missing',stack:poison},'required_claim_missing','iat'],
    [{code:'ERR_JWT_CLAIM_VALIDATION_FAILED',claim:'nbf'},'time_invalid','nbf'],
    [{code:'ERR_JWT_CLAIM_VALIDATION_FAILED',claim:'iss'},'issuer_invalid','iss'],
    [{code:'ERR_JOSE_ALG_NOT_ALLOWED',claim:poison},'algorithm_disallowed',null],
    [{code:'ERR_JWS_INVALID',claim:poison},'token_invalid',null],
    [{code:'ERR_JWT_CLAIM_VALIDATION_FAILED',claim:poison,reason:poison},'claim_invalid',null],
    [{code:poison,claim:'exp',message:poison},'unknown',null],
    [null,'unknown',null],
    [Object.create({code:'ERR_JWT_EXPIRED',claim:'exp'}),'unknown',null],
    [new Proxy({}, {getOwnPropertyDescriptor(){throw Error(poison);}}),'unknown',null],
  ] as [unknown,string,string|null][]) {
    assert.deepEqual(projectQStashJoseFailure(error),{category,claim});
    const lines:string[]=[]; const d=createQStashFailureDiagnostic(line=>lines.push(line));
    d.stage('jose_verification'); d.failed('current',error); d.failed('next',error); d.emit(); d.emit();
    assert.equal(lines.length,1); assert.ok(Buffer.byteLength(lines[0]!)<=MAX_DIAGNOSTIC_BYTES);
    assert.equal(lines[0]!.includes(poison),false);
    const second:string[]=[]; const e=createQStashFailureDiagnostic(line=>second.push(line));
    e.stage('jose_verification'); e.failed('current',error); e.failed('next',error); e.emit();
    assert.equal(lines[0],second[0]);
    assert.deepEqual(Object.keys(JSON.parse(lines[0]!)),['event','stage','current','next']);
  }
  let getters=0;
  const evil=Object.defineProperties({toJSON(){throw Error(poison);}},Object.fromEntries(
    ['code','claim','reason','message','stack','cause','payload'].map(k=>[k,{get(){getters++;throw Error(poison);}}])));
  assert.deepEqual(projectQStashJoseFailure(evil),{category:'unknown',claim:null}); assert.equal(getters,0);
});

test('qstash diagnostics: real synthetic JWT outcomes/next-key fallback unchanged; claim and lifetime categories are precise', async () => {
  const inspect = async (signature:string,body=QSTASH_TICK_BODY) => {
    const lines:string[]=[];const diagnostic=createQStashFailureDiagnostic(line=>lines.push(line));
    let code:string|null=null;
    try { await verifyQStashTick({config:qstashConfig(QSTASH),signature,body:Buffer.from(body),now:start,diagnostic}); }
    catch(error){code=(error as BridgeError).code;diagnostic.emit();diagnostic.emit();}
    return {code,lines,event:lines.length?JSON.parse(lines[0]!):null};
  };
  for (const key of [CURRENT,NEXT]) assert.deepEqual((await inspect(await sign({at:start,key}))).lines,[]);
  const subject=await inspect(await sign({at:start,claims:{sub:'https://other.example.test/api/cron'}}));
  assert.equal(subject.code,'scheduler_signature_invalid'); assert.equal(subject.event.current.category,'subject_invalid');
  assert.equal(subject.event.current.claim,'sub'); assert.equal(subject.event.next.category,'signature_mismatch');
  const missing=await inspect(await sign({at:start,omit:['iat']}));
  assert.equal(missing.event.current.category,'required_claim_missing'); assert.equal(missing.event.current.claim,'iat');
  const future=await inspect(await sign({at:start,claims:{nbf:Math.floor(start/1000)+60}}));
  assert.equal(future.event.current.category,'time_invalid'); assert.equal(future.event.current.claim,'nbf');
  const expired=await inspect(await sign({at:start,claims:{exp:Math.floor(start/1000)-60}}));
  assert.equal(expired.event.current.category,'expired');
  const lifetime=await inspect(await sign({at:start,claims:{exp:Math.floor(start/1000)+901}}));
  assert.equal(lifetime.code,'scheduler_signature_invalid'); assert.equal(lifetime.event.stage,'claim_bounds');
  assert.deepEqual(lifetime.event.current,{category:'token_lifetime_exceeded',claim:'exp'});
  const shape=await inspect('not-a-JWT'); assert.equal(shape.event.stage,'signature_shape');
  const body=await inspect(await sign({at:start}),QSTASH_TICK_BODY+' ');
  assert.equal(body.code,'scheduler_body_invalid'); assert.equal(body.event.stage,'body_validation');
  assert.deepEqual(body.event.current,{category:'body_mismatch',claim:'body'});
  for(const output of [subject,missing,future,expired,lifetime,shape,body]) {
    assert.equal(output.lines.length,1);assert.ok(Buffer.byteLength(output.lines[0]!)<=512);
    assert.equal(output.lines[0]!.includes(DEST),false);assert.equal(output.lines[0]!.includes(CURRENT),false);
    assert.equal(output.lines[0]!.includes(NEXT),false);
  }
});

test('qstash diagnostic route: unchanged HTTP rejection/body/headers, no pre-auth data access; logger failure is contained', async t => {
  const lines:string[]=[];t.mock.method(console,'warn',(line:string)=>lines.push(line));
  const f=await fixture(),before={connects:f.connects(),sends:f.sends.length,posts:f.posts.length};
  const bad=await sign({at:start,key:OLD});
  const response=await f.deliver({signature:bad});
  assert.equal(response.status,489);assert.deepEqual(await response.json(),{error:'scheduler_signature_invalid'});
  assert.equal(response.headers.get('upstash-nonretryable-error'),'true');
  assert.equal(lines.length,1);assert.equal(JSON.parse(lines[0]!).current.category,'signature_mismatch');
  assert.deepEqual({connects:f.connects(),sends:f.sends.length,posts:f.posts.length},before);
  const poison='SYNTHETIC_UNTRUSTED_BODY_ERROR';
  const broken=new ReadableStream<Uint8Array>({pull(){throw Error(poison);}});
  const bodyFailure=await f.deliver({body:broken});
  assert.equal(bodyFailure.status,489);assert.deepEqual(await bodyFailure.json(),{error:'scheduler_signature_invalid'});
  assert.equal(lines.length,2);assert.equal(JSON.parse(lines[1]!).stage,'body_read');assert.equal(lines[1]!.includes(poison),false);
  assert.deepEqual({connects:f.connects(),sends:f.sends.length,posts:f.posts.length},before);
  const valid=await f.deliver();assert.equal(valid.status,200);assert.equal(lines.length,2,'accepted deliveries do not emit failure events');
  t.mock.method(console,'warn',()=>{throw Error(poison);});
  const ignored=await f.deliver({signature:bad});assert.equal(ignored.status,489);
  assert.deepEqual(await ignored.json(),{error:'scheduler_signature_invalid'});
});
