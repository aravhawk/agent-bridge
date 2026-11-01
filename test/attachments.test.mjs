import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, truncateSync, openSync, writeSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { generateKeyPair, SignJWT } from 'jose';
import { Bridge } from '../src/bridge.mjs';
import { MemoryStore, emptyState } from '../src/store.mjs';
import { BridgeError, VERIFIED_AUTHORIZATION, SCOPES } from '../src/policy.mjs';
import { MESSAGE_PROTOCOL, validateMessage } from '../src/messages.mjs';
import { createProtector } from '../src/webhook.mjs';
import { NativeEvents, EVENT_NAME } from '../src/events.mjs';
import { createRuntime } from '../src/runtime.mjs';
import { resourceFor } from '../src/resource.mjs';
import { ISSUER } from './fixtures/provider.mjs';
import { attachmentConfig, createBlobProvider, checkUploadUrl, uploadHeaders } from '../src/blob.mjs';
import { createAttachments, admitAttachments, MAX_ATTACHMENT_BYTES, DEFAULT_MAX_ATTACHMENT_BYTES, MAX_LIVE_PER_SENDER, CLEANUP_PER_RUN,
  ATTACHMENT_TTL_MS, UPLOAD_WINDOW_MS, DELETE_RECHECK_MS, TOMBSTONE_MS, RATE_PER_MINUTE, MAX_RESERVED_BYTES,
  MAX_GET_URLS, MIN_RANGE_BYTES, DOWNLOAD_RATE_PER_MINUTE, validRetentionPolicy } from '../src/attachments.mjs';
import { describeFile, uploadFile, downloadFile, hashStream, writeFully, resumeOffset, discardPartial, partialPaths,
  MAX_TRANSFER_MS } from '../src/attachment-client.mjs';
import { gzipSync } from 'node:zlib';
import { Readable } from 'node:stream';
import { createFakeBlob } from './fixtures/fake-blob.mjs';

// Fake provider and fake credentials only: no network, no real bucket.
const MINUTE = 60000, HOUR = 3600000, DAY = 86400000, policy = 'c'.repeat(64);
const start = Date.UTC(2026, 9, 19, 15, 30);
const policyIds = { jarvis: policy, friday: policy };
// A fake store ID only (an identifier, not a credential); no token exists.
const FAKE = { BRIDGE_ATTACHMENTS_ENABLED: 'true', BLOB_STORE_ID: 'store_FakeStore00000001' };
const iso = ms => new Date(ms).toISOString();
function who(role, until = start + 7 * DAY) {
  return Object.defineProperty({ role, scopes: Object.values(SCOPES[role]), principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64) },
    VERIFIED_AUTHORIZATION, { value: { policyId: policy, expiresAt: until } });
}
const jarvis = who('jarvis'), friday = who('friday');
const fakeR2 = (clock, options = {}) => createFakeBlob({ storeId: FAKE.BLOB_STORE_ID, clock, ...options });
const tmp = () => mkdtempSync(path.join(tmpdir(), 'bridge-attachment-test-'));
function file(bytes) { const dir = tmp(), p = path.join(dir, 'input.bin'); writeFileSync(p, bytes); return p; }

// An owner-approved retention policy, supplied only by tests that exercise
// the (otherwise inert) physical cleanup scaffolding.
const APPROVED = Object.freeze({ physicalDelete: true, approvedBy: 'test owner', approvedAt: '2026-10-31T00:00:00Z' });
async function fixture({ env = { ...FAKE }, retention } = {}) {
  let now = start;
  const clock = () => now, store = new MemoryStore(), r2 = fakeR2(clock);
  const config = () => attachmentConfig(env);
  // Hooks run inside the provider await, to change the world mid-operation.
  const hooks = {};
  const providerFor = c => {
    const p = createBlobProvider({ config: c, sdk: r2.sdk, clock, timeoutMs: 5000 });
    return { ...p,
      async presignUpload(o) { await hooks.put?.(); return p.presignUpload(o); },
      async presignGet(o) { await hooks.get?.(); return p.presignGet(o); },
      async head(k) { await hooks.head?.(); return p.head(k); },
      async delete(k) { return hooks.delete ? hooks.delete(k, p) : p.delete(k); } };
  };
  // hooks.lock runs before a capability transaction gets the store, like time spent waiting for the row lock.
  const db = { transaction: async fn => { const wait = hooks.lock; hooks.lock = null; await wait?.(); return store.transaction(fn); } };
  const att = () => createAttachments({ store: db, clock, policyIds, config: config(), provider: providerFor(config()), configNow: config, retention });
  const bridge = new Bridge({ store, clock, dailyEnabled: true, messagePolicyIds: policyIds,
    admitAttachments: (state, envelope, principal, at) => {
      const c = config();
      if (!c.valid) throw new BridgeError('attachments_not_enabled', 503);
      admitAttachments(state, envelope, principal, at, { namespace: c.namespace, policyIds, maxBytes: c.maxBytes });
    } });
  const events = new NativeEvents({ store, protector: createProtector(randomBytes(32)), clock, policyId: policy, enabled: true,
    transport: async (_url, req) => ({ status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  await events.subscribe(who('jarvis', start + 7 * DAY), { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  const message = (extra = {}) => ({ protocol: MESSAGE_PROTOCOL, id: randomUUID(), from: 'jarvis', to: 'friday', kind: 'message',
    sentAt: iso(now), expiresAt: iso(now + HOUR), threadId: randomUUID(), route: 'inbox', text: 'See attached.', ...extra });
  // Upload one file end to end; returns the finalized attachment and the file.
  const uploaded = async (bytes = randomBytes(64 * 1024), as = jarvis) => {
    const p = file(bytes), d = await describeFile(p);
    const begun = await att().begin(as, { name: 'report.txt', ...d });
    await uploadFile(p, begun, d, { fetchImpl: r2.fetch, now: clock });
    const done = await att().finalize(as, { id: begun.attachmentId });
    return { ...done, bytes, d };
  };
  return { store, clock, r2, env, hooks, att, bridge, message, uploaded, snapshot: () => store.snapshot(),
    set: ms => { now = ms; }, advance: ms => { now += ms; } };
}
// Visible files only; partial state is dot-prefixed (quarantined).
const visible = dir => readdirSync(dir).filter(n => !n.startsWith('.')).sort();
const rejects = (promise, code) => assert.rejects(promise, e => e.code === code || assert.fail(`expected ${code}, got ${e.code}`));

// --- Configuration and signing -----------------------------------------------
test('config: off unless the flag is exactly true; the parser requires a store ID and does not inspect SDK auth', () => {
  assert.deepEqual(attachmentConfig({}), { configured: false, enabled: false, valid: false });
  assert.deepEqual(attachmentConfig({ BRIDGE_ATTACHMENTS_ENABLED: 'yes', BLOB_STORE_ID: 'x' }), { configured: true, enabled: false, valid: false });
  for (const change of [{ BLOB_STORE_ID: undefined }, { BLOB_STORE_ID: '' }, { BLOB_STORE_ID: 'short' }, { BLOB_STORE_ID: 'store_bad id!' },
    { BLOB_STORE_ID: 'https://evil.example' }, { BLOB_STORE_ID: 'a'.repeat(65) }]) {
    assert.equal(attachmentConfig({ ...FAKE, ...change }).valid, false, JSON.stringify(change));
  }
  const a = attachmentConfig(FAKE), b = attachmentConfig({ ...FAKE, BLOB_STORE_ID: 'store_OtherStore000001' });
  assert.deepEqual([a.valid, a.provider, a.storeId], [true, 'vercel-blob', 'FakeStore00000001']);
  assert.match(a.namespace, /^[a-f0-9]{64}$/); assert.notEqual(a.namespace, b.namespace);
  assert.equal(attachmentConfig({ ...FAKE, BLOB_STORE_ID: 'FakeStore00000001' }).namespace, a.namespace, 'store_ prefix is optional');
  // attachmentConfig itself reads no credential. Provider calls use an
  // injected fake SDK here, so this does not test the real SDK's OIDC-first
  // resolution or its BLOB_READ_WRITE_TOKEN fallback.
  const env = new Proxy({ ...FAKE }, { get(t, k) { if (k === 'BLOB_READ_WRITE_TOKEN' || k === 'VERCEL_OIDC_TOKEN') throw Error('read ' + k); return t[k]; } });
  assert.equal(attachmentConfig(env).valid, true);
});

test('capability: the private upload capability is scoped to one pathname, size, content type, no overwrite; GET is private, uncached', async () => {
  let now = start; const clock = () => now, blob = fakeR2(clock);
  const provider = createBlobProvider({ config: attachmentConfig(FAKE), sdk: blob.sdk, clock });
  const body = Buffer.from('exact bytes'), key = 'att/' + randomUUID();
  const up = await provider.presignUpload({ key, size: body.length, validUntil: now + 60000 });
  const url = new URL(up.url), q = url.searchParams;
  assert.equal(url.origin + url.pathname, 'https://vercel.com/api/blob/');
  assert.deepEqual([q.get('pathname'), q.get('vercel-blob-maximum-size-in-bytes'), q.get('vercel-blob-allow-overwrite'),
    q.get('vercel-blob-add-random-suffix'), q.get('vercel-blob-allowed-content-types')], [key, String(body.length), 'false', 'false', 'application/octet-stream']);
  assert.equal(new URL(up.multipartUrl).pathname, '/api/blob/mpu');
  assert.deepEqual(up.headers, uploadHeaders('FakeStore00000001'));
  assert.ok(checkUploadUrl(up.url, { key, size: body.length }));
  // The delegation's client signing key never appears in what is returned.
  const issued = [];
  const spy = createBlobProvider({ config: attachmentConfig(FAKE), clock, sdk: { ...blob.sdk,
    issueSignedToken: async o => { const t = await blob.sdk.issueSignedToken(o); issued.push(t.clientSigningToken); return t; } } });
  const up2 = await spy.presignUpload({ key, size: body.length, validUntil: now + 60000 });
  assert.equal(JSON.stringify(up2).includes(issued[0]), false);
  const put = (u = up.url, b = body, h = up.headers) => blob.fetch(u, { method: 'PUT', headers: h, body: b });
  // Any change to the signed scope is refused.
  for (const [name, value] of [['pathname', 'att/' + randomUUID()], ['vercel-blob-maximum-size-in-bytes', '1000000'],
    ['vercel-blob-allow-overwrite', 'true'], ['vercel-blob-allowed-content-types', 'text/html'], ['vercel-blob-valid-until', String(now + 3600000)]]) {
    const changed = new URL(up.url); changed.searchParams.set(name, value);
    assert.equal((await put(changed.href)).status, 403, name);
  }
  assert.equal((await put(up.url, Buffer.alloc(body.length + 1))).status, 400, 'larger than the signed maximum');
  assert.equal((await put(up.url, body, { ...up.headers, 'x-content-type': 'text/html' })).status, 400, 'content type');
  assert.equal((await put()).status, 200);
  assert.equal((await put()).status, 400, 'no overwrite');
  now += 61000;
  assert.equal((await put()).status, 403, 'expired');
  // GET: private store host, this pathname only, cache bypassed.
  const get = await provider.presignGet({ key, validUntil: now + 60000 });
  const g = new URL(get.url);
  assert.equal(g.hostname, 'fakestore00000001.private.blob.vercel-storage.com'); assert.equal(g.pathname, '/' + key);
  assert.equal(g.searchParams.get('cache'), '0');
  assert.equal((await blob.fetch(get.url)).status, 200);
  const other = new URL(get.url); other.pathname = '/att/' + randomUUID();
  assert.equal((await blob.fetch(other.href)).status, 403);
  // HEAD: size and an opaque ETag; never a content check.
  assert.deepEqual(await provider.head(key), { status: 200, size: body.length, etag: blob.objects.get(key).etag });
  assert.deepEqual(await provider.head('att/' + randomUUID()), { status: 404, size: null, etag: null });
  await assert.rejects(provider.head('../escape'), /attachment_key_invalid/);
  await assert.rejects(provider.presignUpload({ key, size: 1, validUntil: now - 1 }), /attachment_url_window_closed/);
  await assert.rejects(provider.presignUpload({ key, size: 1, validUntil: 1.5 }), /attachment_url_window_invalid/);
  await assert.rejects(provider.presignUpload({ key, size: MAX_ATTACHMENT_BYTES + 1, validUntil: now + 60000 }), /attachment_upload_invalid/);
  // SDK failures are sanitized (no message, token or URL leaks out).
  const failing = createBlobProvider({ config: attachmentConfig(FAKE), clock, sdk: { ...blob.sdk,
    issueSignedToken: async () => { throw new Error('upstream said: secret-material'); } } });
  await assert.rejects(failing.presignUpload({ key, size: 1, validUntil: now + 60000 }),
    e => e.code === 'attachment_provider_unavailable' && !String(e.message).includes('secret-material'));
});

// --- Default off --------------------------------------------------------------
async function runtimeFixture(changes = {}) {
  let document = emptyState(), now = start, factoryCalls = 0, sends = [];
  const r2 = fakeR2(() => now);
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  class Pool { on() {} async connect() { return { release() {}, async query(sql, params) {
    if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(document) }] };
    if (sql.startsWith('UPDATE bridge_runtime_v1')) document = JSON.parse(params[0]);
    return { rows: [] };
  } }; } }
  const env = { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture', BRIDGE_DELIVERY_ENABLED: 'true',
    BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
    DATABASE_URL: 'postgresql://fixture.neon.tech/neondb?sslmode=require', BRIDGE_RECEIVER_POLICY: 'inbox-v1',
    FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true', FRIDAY_RECEIVER_ID: 'jarvis-friday-bridge-inbox',
    FRIDAY_WEBHOOK_URL: 'https://receiver.example.test/event', FRIDAY_WEBHOOK_KEY: 'FIXTURE_ONLY', CRON_SECRET: 'fixture-cron-secret-value', ...changes };
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete env[k];
  const rt = createRuntime({ env, Pool, keyResolver: publicKey, clock: () => now,
    queueClient: { async send(...args) { sends.push(args); }, handleCallback(fn) { return fn; } },
    transportFactory: () => async (_url, req) => ({ status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }),
    attachmentProviderFactory: config => { factoryCalls++; return createBlobProvider({ config, sdk: r2.sdk, clock: () => now }); } });
  const tokens = {};
  for (const role of ['jarvis', 'friday']) tokens[role] = await new SignJWT({ scope: Object.values(SCOPES[role]).join(' ') })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject('fixture').setAudience(resourceFor(role)).setIssuedAt().setExpirationTime('30d').sign(privateKey);
  const rpc = async (role, method, params) => (await (await rt.handler(role)(new Request(resourceFor(role), { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tokens[role] },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }))).json());
  const call = async (role, name, args) => (await rpc(role, 'tools/call', { name, arguments: args })).result;
  const cron = () => rt.cronHandler()(new Request('https://deployment.example.test/api/cron', { method: 'POST',
    headers: { authorization: 'Bearer fixture-cron-secret-value' } }));
  await rpc('jarvis', 'events/subscribe', { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  return { rpc, call, cron, r2, env, document: () => document, factoryCalls: () => factoryCalls, set: ms => { now = ms; } };
}

test('default off: no tools, no schema field, no readiness key, no state, no provider; attachment sends are refused', async () => {
  const off = await runtimeFixture(), on = await runtimeFixture(FAKE);
  const names = async (f, role) => (await f.rpc(role, 'tools/list', {})).result.tools;
  for (const role of ['jarvis', 'friday']) {
    const tools = await names(off, role);
    assert.equal(tools.some(t => t.name.startsWith('bridge_attachment_')), false);
    assert.equal('attachmentIds' in tools.find(t => t.name === 'bridge_message_send').inputSchema.properties, false);
  }
  assert.equal('attachments' in (await off.call('jarvis', 'bridge_health', {})).structuredContent.readiness, false);
  const m = { protocol: MESSAGE_PROTOCOL, id: randomUUID(), from: 'jarvis', to: 'friday', kind: 'message', sentAt: iso(start),
    expiresAt: iso(start + HOUR), threadId: randomUUID(), route: 'inbox', text: 'x', attachmentIds: [randomUUID()] };
  assert.deepEqual((await off.call('jarvis', 'bridge_message_send', m)).structuredContent, { error: 'attachments_not_enabled' });
  assert.equal((await off.rpc('jarvis', 'tools/call', { name: 'bridge_attachment_begin', arguments: {} })).error.message, 'tool_not_available');
  const offCron = await off.cron();
  assert.equal(offCron.status, 200); assert.equal('attachments' in await offCron.json(), false);
  assert.equal(off.document().attachments, undefined); assert.equal(off.factoryCalls(), 0);
  assert.equal(Object.keys(off.document().messages).length, 0);
  // Enabled: tools for the right scopes, readiness booleans only (never secrets).
  const jt = (await names(on, 'jarvis')).map(t => t.name);
  for (const n of ['bridge_attachment_begin', 'bridge_attachment_finalize', 'bridge_attachment_download']) assert.ok(jt.includes(n), n);
  assert.deepEqual(jt.filter(n => n.startsWith('bridge_attachment_')).sort(), ['bridge_attachment_begin', 'bridge_attachment_download', 'bridge_attachment_finalize']);
  const tools = await names(on, 'jarvis'), beginTool = tools.find(t => t.name === 'bridge_attachment_begin');
  assert.deepEqual(beginTool.inputSchema.properties.mode, { enum: ['single', 'multipart'] });
  assert.equal('md5' in beginTool.inputSchema.properties, false);
  assert.deepEqual(beginTool.inputSchema.required, ['name', 'size', 'sha256']);
  assert.deepEqual(tools.find(t => t.name === 'bridge_attachment_finalize').inputSchema.required, ['id']);
  const ready = (await on.call('friday', 'bridge_health', {})).structuredContent.readiness.attachments;
  assert.deepEqual(ready, { enabled: true, configured: true });
  assert.equal(JSON.stringify(await on.call('friday', 'bridge_health', {})).includes('fake-oidc-token-must-never-appear'), false);
  const onCron = await on.cron();
  assert.equal(onCron.status, 200);
  assert.deepEqual((await onCron.json()).attachments, { retention: 'not_approved', deleted: 0, live: 0, accessExpired: 0,
    rejected: 0, reservedBytes: 0, otherNamespace: 0 });
});

test('default off reads nothing else: no size limit or credential is read until the flag is exactly true', () => {
  const read = [];
  const spy = values => new Proxy(values, { get: (t, k) => { read.push(k); return t[k]; } });
  for (const flag of [undefined, 'false', 'TRUE', '1']) {
    read.length = 0;
    attachmentConfig(spy({ ...FAKE, BRIDGE_ATTACHMENT_MAX_BYTES: 'garbage', BRIDGE_ATTACHMENTS_ENABLED: flag }));
    assert.deepEqual(read, ['BRIDGE_ATTACHMENTS_ENABLED'], String(flag));
  }
});

// --- End to end ---------------------------------------------------------------
test('end to end: reserve, upload directly, finalize, send IDs, recipient downloads and verifies; bytes never in state', async () => {
  const f = await fixture();
  const a = await f.uploaded(randomBytes(200 * 1024));
  assert.equal(a.state, 'available'); assert.equal(a.size, 200 * 1024);
  const m = f.message({ attachmentIds: [a.attachmentId] });
  await f.bridge.sendMessage(jarvis, m);
  const read = await f.bridge.read(friday, { messageId: m.id });
  assert.deepEqual(read.envelope.attachmentIds, [a.attachmentId]);
  const grant = await f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId });
  assert.deepEqual(Object.keys(grant.download.headers), ['if-match']);
  const dir = tmp(), dest = path.join(dir, 'received.bin');
  await downloadFile(grant, dest, { fetchImpl: f.r2.fetch, now: f.clock });
  assert.deepEqual(readFileSync(dest), a.bytes);
  assert.deepEqual(readdirSync(dir), ['received.bin'], 'no temp file left');
  const state = JSON.stringify(f.snapshot());
  assert.equal(state.includes(a.bytes.subarray(0, 32).toString('base64')), false);
  for (const secret of ['vercel-blob-signature', 'vercel-blob-delegation', 'vercel.com/api/blob', 'blob.vercel-storage.com']) assert.equal(state.includes(secret), false, 'no URL or capability is stored');
  // Batch views carry the IDs through the normal envelope.
  assert.equal(validateMessage(m, jarvis, start).envelope.attachmentIds[0], a.attachmentId);
});

test('validation: size bounds, digests, names, kind and message ID lists', async () => {
  const f = await fixture();
  const ok = { name: 'a.txt', size: 1, sha256: 'a'.repeat(64) };
  for (const bad of [{ size: 0 }, { size: 1.5 }, { sha256: 'z'.repeat(64) }, { md5: 'A'.repeat(22) + '==' }, { mode: 'resumable' },
    { name: '' }, { name: 'a\nb' }, { name: 'x'.repeat(201) }, { id: 'not-a-uuid' }, { extra: 1 }, { kind: 'archive' }, { kind: 'TEXT' }]) {
    await assert.rejects(f.att().begin(jarvis, { ...ok, ...bad }), /invalid_attachment|invalid_params/, JSON.stringify(bad));
  }
  // Decimal bytes: the default 500 MB maximum is exact.
  assert.equal(DEFAULT_MAX_ATTACHMENT_BYTES, 500000000); assert.equal(MAX_ATTACHMENT_BYTES, 1000000000);
  assert.equal(new URL((await f.att().begin(jarvis, { ...ok, size: DEFAULT_MAX_ATTACHMENT_BYTES })).upload.url).searchParams.get('vercel-blob-maximum-size-in-bytes'), '500000000');
  for (const size of [DEFAULT_MAX_ATTACHMENT_BYTES + 1, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_BYTES + 1, 2 * 1024 ** 3]) {
    await rejects(f.att().begin(jarvis, { ...ok, size }), 'attachment_too_large');
  }
  assert.equal((await f.att().begin(jarvis, { ...ok, kind: 'code', name: 'big.mjs' })).kind, 'code');
  const m = f.message();
  for (const ids of [[], Array.from({ length: 5 }, () => randomUUID()), ['x'], [m.id.replace(/^(.{14})./, '$11'), m.id]]) {
    assert.throws(() => validateMessage({ ...m, attachmentIds: ids }, jarvis, start), /invalid_message/, JSON.stringify(ids));
  }
  const id = randomUUID();
  assert.throws(() => validateMessage({ ...m, attachmentIds: [id, id.toUpperCase()] }, jarvis, start), /invalid_message/);
});

// --- Review findings ------------------------------------------------------------
test('review 1: a URL whose signing await outlasted its window is never returned (PUT and GET)', async () => {
  const f = await fixture();
  const d = { name: 'x', size: 10, sha256: 'a'.repeat(64) };
  f.hooks.put = () => { f.advance(16 * MINUTE); }; // token still valid for days
  await rejects(f.att().begin(jarvis, d), 'attachment_url_window_closed');
  f.hooks.put = null;
  const a = await f.uploaded();
  const m = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
  f.hooks.get = () => { f.advance(16 * MINUTE); };
  await rejects(f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId }), 'attachment_url_window_closed');
  // Upload window bound: a URL is never valid past uploadUntil.
  f.hooks.get = null;
  const g = await fixture();
  const begun = await g.att().begin(jarvis, d);
  g.set(start + UPLOAD_WINDOW_MS - 30000);
  const late = await g.att().begin(jarvis, { ...d, id: begun.attachmentId });
  assert.equal(Date.parse(late.upload.expiresAt), start + UPLOAD_WINDOW_MS);
  g.set(start + UPLOAD_WINDOW_MS - 500);
  await rejects(g.att().begin(jarvis, { ...d, id: begun.attachmentId }), 'attachment_url_window_closed');
});

test('review 2: finalize never makes an attachment available across its fixed expiry', async () => {
  const f = await fixture();
  const p = file(randomBytes(1000)), d = await describeFile(p);
  const begun = await f.att().begin(jarvis, { name: 'x', ...d });
  await uploadFile(p, begun, d, { fetchImpl: f.r2.fetch, now: f.clock });
  f.hooks.head = () => { f.advance(ATTACHMENT_TTL_MS); };
  await rejects(f.att().finalize(jarvis, { id: begun.attachmentId }), 'attachment_expired');
  assert.equal(f.snapshot().attachments.records[begun.attachmentId].state, 'reserved');
  // The idempotent branch checks expiry too.
  const g = await fixture(), a = await g.uploaded();
  g.advance(ATTACHMENT_TTL_MS);
  await rejects(g.att().finalize(jarvis, { id: a.attachmentId }), 'attachment_expired');
  await rejects(g.att().begin(jarvis, { name: 'report.txt', ...a.d, id: a.attachmentId }), 'attachment_expired');
});

test('retention default (no approved policy): expiry or rejection never deletes or releases quota, across every clock advance and restart', async () => {
  const f = await fixture();
  const p = file(randomBytes(1000)), d = await describeFile(p);
  const begun = await f.att().begin(jarvis, { name: 'x', ...d });
  // Something other than the declared bytes appears under the key.
  f.r2.objects.set('att/' + begun.attachmentId, { body: Buffer.from('other'), etag: '"0123456789abcdef0123456789abcdef"' });
  await rejects(f.att().finalize(jarvis, { id: begun.attachmentId }), 'attachment_verification_failed');
  const rec = id => f.snapshot().attachments.records[id];
  assert.equal(rec(begun.attachmentId).state, 'rejected');
  await rejects(f.att().begin(jarvis, { name: 'x', ...d, id: begun.attachmentId }), 'attachment_closed');
  f.advance(MINUTE);
  const good = await f.uploaded(randomBytes(2000));
  const deletes = () => f.r2.calls.filter(c => c.method === 'DELETE').length;
  for (const step of [0, MINUTE, UPLOAD_WINDOW_MS, ATTACHMENT_TTL_MS, DELETE_RECHECK_MS, TOMBSTONE_MS, 365 * DAY]) {
    f.advance(step);
    // A fresh capability per run, as after a cold start or restart.
    const report = await f.att().cleanup();
    assert.equal(report.retention, 'not_approved'); assert.equal(report.deleted, 0); assert.equal(report.live, 2);
  }
  assert.equal(deletes(), 0, 'no DELETE ever');
  assert.ok(f.r2.objects.has('att/' + begun.attachmentId)); assert.ok(f.r2.objects.has('att/' + good.attachmentId));
  assert.deepEqual([rec(begun.attachmentId).state, rec(good.attachmentId).state], ['rejected', 'available']);
  assert.deepEqual(await f.att().cleanup(), { retention: 'not_approved', deleted: 0, live: 2, accessExpired: 2, rejected: 1,
    reservedBytes: 3000, otherNamespace: 0 });
  // Access ended: reported, no new URL; the quota stays reserved.
  const later = who('jarvis', f.clock() + DAY);
  assert.equal((await f.att().begin(later, { name: 'report.txt', ...good.d, id: good.attachmentId }).catch(e => e)).code, 'attachment_expired');
  const view = await f.att().finalize(later, { id: good.attachmentId }).catch(e => e);
  assert.equal(view.code, 'attachment_expired');
});

test('retention policy: only a trusted constructor-supplied approval enables deletion; env and malformed policies cannot', async () => {
  assert.equal(validRetentionPolicy(APPROVED), true);
  for (const bad of [undefined, null, {}, { ...APPROVED, physicalDelete: 'true' }, { ...APPROVED, extra: 1 },
    { physicalDelete: true, approvedBy: 'x' }, { ...APPROVED, approvedBy: '' }, { ...APPROVED, approvedAt: 'soon' }, [APPROVED]]) {
    assert.equal(validRetentionPolicy(bad), false, JSON.stringify(bad));
  }
  const f = await fixture({ retention: { ...APPROVED, physicalDelete: 1 } }).catch(e => e);
  await assert.rejects(async () => f.att(), /attachment_retention_policy_invalid/);
  assert.throws(() => createRuntime({ env: {}, attachmentRetention: { approved: true } }), /attachment_retention_policy_invalid/);
  // No environment variable invents an approval.
  const rt = await runtimeFixture({ ...FAKE, BRIDGE_ATTACHMENT_RETENTION: 'approved', BRIDGE_ATTACHMENT_PHYSICAL_DELETE: 'true' });
  assert.equal((await (await rt.cron()).json()).attachments.retention, 'not_approved');
});

test('review 4: non-plain or array-shaped stored metadata fails closed with no URL and no provider call', async () => {
  const good = await fixture(), a = await good.uploaded();
  const base = good.snapshot().attachments;
  const shapes = [
    s => { s.attachments = { records: {}, rate: [] }; },
    s => { s.attachments = { records: [], rate: {} }; },
    s => { s.attachments = []; },
    s => { s.attachments = structuredClone(base); s.attachments.records[a.attachmentId].issued = [0, 0, 0]; },
    s => { s.attachments = structuredClone(base); s.attachments.records[a.attachmentId].cleanup = []; },
    s => { s.attachments = structuredClone(base); s.attachments.rate.jarvis = []; },
    s => { s.attachments = structuredClone(base); s.attachments.records[a.attachmentId].size = MAX_ATTACHMENT_BYTES + 1; },
  ];
  for (const shape of shapes) {
    const f = await fixture();
    await f.store.transaction(shape);
    const calls = f.r2.calls.length, before = JSON.stringify(f.snapshot());
    await rejects(f.att().begin(jarvis, { name: 'x', size: 1, sha256: 'a'.repeat(64) }), 'attachment_storage_invalid');
    await rejects(f.att().cleanup(), 'attachment_storage_invalid');
    assert.equal(JSON.stringify(f.snapshot()), before, 'no mutation'); assert.equal(f.r2.calls.length, calls);
  }
});

test('approved policy (scaffolding): a rejected object is not deleted before every upload URL has expired', async () => {
  const f = await fixture({ retention: APPROVED });
  const p = file(randomBytes(1000)), d = await describeFile(p);
  const begun = await f.att().begin(jarvis, { name: 'x', ...d });
  f.r2.objects.set('att/' + begun.attachmentId, { body: Buffer.from('other'), etag: '"0123456789abcdef0123456789abcdef"' });
  await rejects(f.att().finalize(jarvis, { id: begun.attachmentId }), 'attachment_verification_failed');
  const record = () => f.snapshot().attachments.records[begun.attachmentId];
  assert.equal(record().state, 'rejected');
  f.advance(MINUTE);
  assert.deepEqual(await f.att().cleanup(), { retention: 'approved', deleted: 0, rechecked: 0, pending: 1, failed: 0, namespaceMismatch: 0 });
  assert.ok(f.r2.objects.has('att/' + begun.attachmentId), 'not deleted while an upload URL may still be valid');
  f.set(record().uploadUntil);
  assert.equal((await f.att().cleanup()).deleted, 1);
  assert.equal(record().state, 'deleted');
});

test('approved policy (scaffolding): cleanup is bounded per run, concurrent and time-boxed; failures back off without releasing quota', async () => {
  const f = await fixture({ retention: APPROVED });
  const ids = [];
  // Two charged operations per upload (begin, finalize): space them under the per-role rate.
  for (let i = 0; i < 6; i++) { ids.push((await f.uploaded(randomBytes(100 + i))).attachmentId); f.advance(30000); }
  f.advance(ATTACHMENT_TTL_MS);
  let inFlight = 0, peak = 0;
  f.hooks.delete = async (key, p) => { inFlight++; peak = Math.max(peak, inFlight); await new Promise(r => setTimeout(r, 5)); inFlight--; return p.delete(key); };
  const first = await f.att().cleanup();
  assert.equal(first.deleted, CLEANUP_PER_RUN); assert.equal(peak, CLEANUP_PER_RUN, 'concurrent, bounded');
  const second = await f.att().cleanup();
  assert.equal(second.deleted, 2);
  // Failure: quota held, backoff prevents an immediate retry.
  const g = await fixture({ retention: APPROVED }), b = await g.uploaded();
  g.advance(ATTACHMENT_TTL_MS);
  g.hooks.delete = async () => ({ status: 503 });
  assert.equal((await g.att().cleanup()).failed, 1);
  assert.equal(g.snapshot().attachments.records[b.attachmentId].state, 'deleting');
  assert.equal((await g.att().cleanup()).failed, 0, 'backoff: no provider call yet');
  g.hooks.delete = null; g.advance(10 * MINUTE);
  assert.equal((await g.att().cleanup()).deleted, 1);
  // Recheck DELETE for a late in-flight PUT, then the tombstone is pruned.
  g.advance(DELETE_RECHECK_MS);
  assert.equal((await g.att().cleanup()).rechecked, 1);
  g.advance(TOMBSTONE_MS);
  await g.att().cleanup();
  assert.equal(g.snapshot().attachments.records[b.attachmentId], undefined);
});

// --- Authority during awaits ------------------------------------------------------
test('revocation, policy change or disabling during an await returns no URL and changes nothing', async () => {
  const d = { name: 'x', size: 10, sha256: 'a'.repeat(64) };
  for (const [name, change] of [
    ['sender denied', f => f.store.transaction(s => { s.resourceDenials = { [jarvis.principalKey]: {} }; })],
    ['flag off', f => { f.env.BRIDGE_ATTACHMENTS_ENABLED = 'false'; }],
    ['bucket changed', f => { f.env.BLOB_STORE_ID = 'store_OtherStore000001'; }],
  ]) {
    const f = await fixture();
    f.hooks.put = () => change(f);
    await assert.rejects(f.att().begin(jarvis, d), /attachment_authorization_inactive|attachments_not_enabled|attachment_namespace_mismatch/, name);
  }
  for (const [, change, code] of [
    ['recipient denied', f => f.store.transaction(s => { s.resourceDenials = { [friday.principalKey]: {} }; }), 'attachment_authorization_inactive'],
    ['sender denied', f => f.store.transaction(s => { s.resourceDenials = { [jarvis.principalKey]: {} }; }), 'message_authorization_inactive'],
  ]) {
    const f = await fixture(), a = await f.uploaded();
    const m = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
    f.hooks.get = () => change(f);
    await rejects(f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId }), code);
  }
  const f = await fixture();
  const p = file(randomBytes(100)), dd = await describeFile(p);
  const begun = await f.att().begin(jarvis, { name: 'x', ...dd });
  await uploadFile(p, begun, dd, { fetchImpl: f.r2.fetch, now: f.clock });
  f.hooks.head = () => f.store.transaction(s => { s.resourceDenials = { [jarvis.principalKey]: {} }; });
  await rejects(f.att().finalize(jarvis, { id: begun.attachmentId }), 'attachment_authorization_inactive');
  assert.equal(f.snapshot().attachments.records[begun.attachmentId].state, 'reserved');
});

test('send admission: only the sender\'s own available attachments for this recipient, checked again at insertion', async () => {
  const f = await fixture(), a = await f.uploaded();
  const reserved = await f.att().begin(jarvis, { name: 'x', size: 5, sha256: 'b'.repeat(64) });
  f.advance(10000);
  const fromFriday = await f.uploaded(randomBytes(10), friday);
  for (const ids of [[reserved.attachmentId], [randomUUID()]]) {
    await rejects(f.bridge.sendMessage(jarvis, f.message({ attachmentIds: ids })), 'attachment_unavailable');
  }
  // Friday's attachment is addressed to Jarvis; Jarvis cannot forward it, Friday cannot send it back to itself.
  await rejects(f.bridge.sendMessage(jarvis, f.message({ attachmentIds: [fromFriday.attachmentId] })), 'attachment_unavailable');
  // Revoked between preparation and insertion: nothing is stored.
  const m = f.message({ attachmentIds: [a.attachmentId] });
  await f.bridge.prepareMessageSend(jarvis, m);
  await f.store.transaction(s => { s.attachments.records[a.attachmentId].state = 'deleting'; });
  await assert.rejects(f.store.transaction(s => f.bridge.stageMessage(s, jarvis, m)), /attachment_unavailable/);
  assert.equal(f.snapshot().messages[m.id], undefined);
  // Sender durable denial blocks an attachment send (the existing return-path
  // check refuses first; admission itself also checks the caller).
  const g = await fixture(), b = await g.uploaded();
  await g.store.transaction(s => { s.resourceDenials = { [jarvis.principalKey]: {} }; });
  await assert.rejects(g.bridge.sendMessage(jarvis, g.message({ attachmentIds: [b.attachmentId] })));
  const envelope = validateMessage(g.message({ attachmentIds: [b.attachmentId] }), jarvis, start).envelope;
  await assert.rejects(g.store.transaction(s => admitAttachments(s, envelope, jarvis, start, {
    namespace: attachmentConfig(FAKE).namespace, policyIds })), /attachment_authorization_inactive/);
  await assert.rejects(g.store.transaction(s => admitAttachments(s, envelope, who('jarvis', start - 1), start, {
    namespace: attachmentConfig(FAKE).namespace, policyIds })), /attachment_authorization_inactive/);
});

test('download is bound to the recipient, the referencing message and current authority; URLs are capped', async () => {
  const f = await fixture(), a = await f.uploaded();
  const m = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
  const plain = f.message(); await f.bridge.sendMessage(jarvis, plain);
  await rejects(f.att().download(jarvis, { messageId: m.id, attachmentId: a.attachmentId }), 'attachment_not_found');
  await rejects(f.att().download(friday, { messageId: plain.id, attachmentId: a.attachmentId }), 'attachment_not_found');
  // Capped by the recipient token.
  const short = await f.att().download(who('friday', start + 90000), { messageId: m.id, attachmentId: a.attachmentId });
  assert.equal(Date.parse(short.download.expiresAt), start + 90000);
  // Under one second left: refused, never rounded up.
  await rejects(f.att().download(who('friday', start + 500), { messageId: m.id, attachmentId: a.attachmentId }), 'attachment_url_window_closed');
  // Capped by the message's authority: after it lapses, no download.
  f.advance(HOUR);
  await rejects(f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId }), 'message_authorization_inactive');
});

test('quotas, issuance limits and idempotent retries are bounded and cannot move ownership or expiry', async () => {
  const f = await fixture();
  const d = n => ({ name: `f${n}`, size: 10, sha256: 'a'.repeat(64) });
  for (let i = 0; i < MAX_LIVE_PER_SENDER; i++) { await f.att().begin(jarvis, d(i)); f.advance(6100); }
  await rejects(f.att().begin(jarvis, d(99)), 'attachment_quota_exceeded');
  // Reserved bytes (configured 1 GB maximum): 15 + 5 one-GB files reach 20 GB; held quota is backpressure.
  const g = await fixture({ env: { ...FAKE, BRIDGE_ATTACHMENT_MAX_BYTES: '1000000000' } });
  assert.equal(MAX_RESERVED_BYTES, 20 * MAX_ATTACHMENT_BYTES);
  for (let i = 0; i < 20; i++) { await g.att().begin(i < 15 ? jarvis : friday, { ...d(i), size: MAX_ATTACHMENT_BYTES }); g.advance(6100); }
  await rejects(g.att().begin(friday, d(21)), 'attachment_quota_exceeded');
  // Expiry releases nothing without an approved policy.
  g.advance(ATTACHMENT_TTL_MS * 30);
  await g.att().cleanup();
  await rejects(g.att().begin(who('friday', g.clock() + DAY), d(22)), 'attachment_quota_exceeded');
  // Per-role rate: 10 per minute, no caller-chosen keys; per-attachment URL budget.
  const h = await fixture();
  for (let i = 0; i < RATE_PER_MINUTE; i++) await h.att().begin(jarvis, d(i));
  await rejects(h.att().begin(jarvis, d(50)), 'attachment_rate_limited');
  await rejects(h.att().begin(friday, d(51)).then(() => { throw new BridgeError('separate_role_budget', 200); }), 'separate_role_budget');
  const j = await fixture(), one = await j.att().begin(jarvis, d(0));
  for (let i = 1; i < 5; i++) { j.advance(1000); await j.att().begin(jarvis, { ...d(0), id: one.attachmentId }); }
  await rejects(j.att().begin(jarvis, { ...d(0), id: one.attachmentId }), 'attachment_issue_budget_exhausted');
  // Retries: same id and body -> same reservation; changed body or other owner -> refused.
  const k = await fixture(), r = await k.att().begin(jarvis, d(0));
  const again = await k.att().begin(jarvis, { ...d(0), id: r.attachmentId });
  assert.deepEqual([again.attachmentId, again.expiresAt], [r.attachmentId, r.expiresAt]);
  await rejects(k.att().begin(jarvis, { ...d(0), size: 11, id: r.attachmentId }), 'attachment_id_conflict');
  await rejects(k.att().begin(friday, { ...d(0), id: r.attachmentId }), 'attachment_not_found');
  await rejects(k.att().begin(who('jarvis', start + 2 * DAY), { ...d(0), id: r.attachmentId }).then(x => {
    assert.equal(x.expiresAt, r.expiresAt, 'a newer token never extends expiry'); throw new BridgeError('ok', 200);
  }), 'ok');
  assert.equal(Object.keys(k.snapshot().attachments.records).length, 1);
});

test('namespace change fails closed: no HEAD, URL or DELETE against another bucket', async () => {
  const f = await fixture(), a = await f.uploaded();
  f.env.BLOB_STORE_ID = 'store_OtherStore000001';
  const calls = f.r2.calls.length;
  await rejects(f.att().finalize(jarvis, { id: a.attachmentId }), 'attachment_namespace_mismatch');
  f.advance(ATTACHMENT_TTL_MS);
  // The report shows the record under another namespace; nothing is touched.
  assert.deepEqual(await f.att().cleanup(), { retention: 'not_approved', deleted: 0, live: 1, accessExpired: 1, rejected: 0,
    reservedBytes: a.size, otherNamespace: 1 });
  // Even under an approved policy, cleanup reports the mismatch and never deletes elsewhere.
  const g = await fixture({ retention: APPROVED }), b = await g.uploaded();
  g.env.BLOB_STORE_ID = 'store_OtherStore000001'; g.advance(ATTACHMENT_TTL_MS);
  const before = g.r2.calls.length;
  assert.deepEqual(await g.att().cleanup(), { retention: 'approved', deleted: 0, rechecked: 0, pending: 1, failed: 0, namespaceMismatch: 1 });
  assert.equal(g.snapshot().attachments.records[b.attachmentId].state, 'available');
  assert.equal(f.r2.calls.length, calls); assert.equal(g.r2.calls.length, before);
});

// --- Client helper ------------------------------------------------------------
test('client helper: hashes, uploads with exact headers, refuses redirects and credential headers', async () => {
  const f = await fixture();
  const p = file(Buffer.from('hello attachment')), d = await describeFile(p);
  assert.equal(d.size, 16); assert.match(d.sha256, /^[a-f0-9]{64}$/); assert.deepEqual(Object.keys(d).sort(), ['sha256', 'size']);
  const begun = await f.att().begin(jarvis, { name: 'h', ...d });
  const withUpload = upload => ({ ...begun, upload: { ...begun.upload, ...upload } });
  await assert.rejects(uploadFile(p, withUpload({ headers: { ...begun.upload.headers, authorization: 'x' } }), d, { fetchImpl: f.r2.fetch, now: f.clock }), /invalid_grant/);
  await assert.rejects(uploadFile(p, withUpload({ url: begun.upload.url.replace('https:', 'http:') }), d, { fetchImpl: f.r2.fetch, now: f.clock }), /invalid_grant/);
  await assert.rejects(uploadFile(p, begun, d, { now: f.clock, fetchImpl: async () => new Response(null, { status: 302, headers: { location: 'https://elsewhere.test/' } }) }), /redirect_refused/);
  const done = await uploadFile(p, begun, d, { fetchImpl: f.r2.fetch, now: f.clock });
  assert.equal(done.etag, f.r2.objects.get('att/' + begun.attachmentId).etag, 'the opaque ETag is the completion evidence');
  // No overwrite: a second upload to the same pathname is refused by storage.
  await assert.rejects(uploadFile(p, begun, d, { fetchImpl: f.r2.fetch, now: f.clock }), /upload_rejected/);
  await assert.rejects(describeFile(path.dirname(p)), /not_a_regular_file/);
});

test('client helper: single upload binds the grant digest and verifies the bytes actually sent', async () => {
  const f = await fixture();
  const p = file(Buffer.from('aaaa')), expected = await describeFile(p);
  const begun = await f.att().begin(jarvis, { name: 'h', ...expected });
  let requests = 0;
  const drain = async (_url, init) => {
    requests++;
    await new Response(init.body).arrayBuffer();
    return new Response(JSON.stringify({ pathname: 'att/' + begun.attachmentId, etag: '"opaque-etag"' }), { status: 200 });
  };
  await assert.rejects(uploadFile(p, { ...begun, sha256: 'b'.repeat(64) }, expected,
    { fetchImpl: drain, now: f.clock }), /invalid_grant/);
  assert.equal(requests, 0, 'metadata mismatch is rejected before dispatch');
  writeFileSync(p, 'bbbb'); // same length as the file describeFile hashed
  await assert.rejects(uploadFile(p, begun, expected, { fetchImpl: drain, now: f.clock }), /file_changed_while_reading/);
  assert.equal(requests, 1, 'a provider may receive bytes before the post-stream digest is known; success is never claimed');
});

test('client helper: download verifies length and SHA-256, never clobbers, never uses remote names, cleans up', async () => {
  const f = await fixture(), a = await f.uploaded(Buffer.from('trusted content'));
  const m = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
  const grant = await f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId });
  const dir = tmp();
  const serve = body => async () => new Response(body, { status: 200 });
  await assert.rejects(downloadFile(grant, path.join(dir, 'a.bin'), { now: f.clock, fetchImpl: serve('tampered!!!!!!!') }), /sha256_mismatch/);
  await assert.rejects(downloadFile(grant, path.join(dir, 'b.bin'), { now: f.clock, fetchImpl: serve('trusted content plus more') }), /size_mismatch/);
  await assert.rejects(downloadFile(grant, path.join(dir, 'd.bin'), { now: f.clock, fetchImpl: async () => new Response(null, { status: 307, headers: { location: 'file:///etc/passwd' } }) }), /redirect_refused/);
  await assert.rejects(downloadFile(grant, 'relative.bin', { fetchImpl: f.r2.fetch, now: f.clock }), /destination_must_be_absolute/);
  assert.deepEqual(readdirSync(dir), [], 'integrity failures and empty attempts leave nothing behind');
  // An early end of stream is an interruption: its ordered prefix is kept, quarantined, for a resume.
  await assert.rejects(downloadFile(grant, path.join(dir, 'c.bin'), { now: f.clock, fetchImpl: serve('short') }), /transfer_incomplete/);
  assert.deepEqual(visible(dir), []);
  assert.equal(await resumeOffset(path.join(dir, 'c.bin'), grant), 5);
  await discardPartial(path.join(dir, 'c.bin'), grant.attachmentId);
  assert.deepEqual(readdirSync(dir), []);
  const existing = path.join(dir, 'keep.bin'); writeFileSync(existing, 'mine');
  await assert.rejects(downloadFile(grant, existing, { fetchImpl: f.r2.fetch, now: f.clock }), /destination_exists/);
  assert.equal(readFileSync(existing, 'utf8'), 'mine');
  const tricked = { ...grant, name: '../../evil.sh' };
  const dest = path.join(dir, 'safe.bin');
  assert.deepEqual(await downloadFile(tricked, dest, { fetchImpl: f.r2.fetch, now: f.clock }),
    { complete: true, path: dest, size: a.size, sha256: a.sha256 });
  assert.equal(readFileSync(dest, 'utf8'), 'trusted content');
  assert.equal(existsSync(path.join(dir, '..', '..', 'evil.sh')), false);
  assert.deepEqual(readdirSync(dir).sort(), ['keep.bin', 'safe.bin'], 'no partial state left after success');
  rmSync(dir, { recursive: true, force: true });
});

test('client helper: grants must be complete and exact private Blob capabilities with sane expiry; metadata is bounded', async () => {
  const f = await fixture();
  const p = file(randomBytes(500)), d = await describeFile(p);
  const begun = await f.att().begin(jarvis, { name: 'h', ...d });
  const up = (upload, expected = d, extra = {}) => uploadFile(p, { ...begun, ...extra, upload: { ...begun.upload, ...upload } }, expected,
    { fetchImpl: f.r2.fetch, now: f.clock });
  const { 'x-allow-overwrite': _, ...missing } = begun.upload.headers;
  const swap = (name, value) => { const u = new URL(begun.upload.url); u.searchParams.set(name, value); return u.href; };
  for (const [upload, extra] of [
    [{ headers: missing }], [{ headers: { ...begun.upload.headers, 'x-vercel-blob-access': 'public' } }],
    [{ headers: { ...begun.upload.headers, 'x-vercel-blob-store-id': 'OtherStore000001' } }],
    [{ url: begun.upload.url.replace('https://vercel.com', 'https://evil.example') }],
    [{ url: begun.upload.url.replace('/api/blob/', '/api/blob/mpu') }],
    [{ url: swap('pathname', 'att/' + randomUUID()) }], [{ url: swap('vercel-blob-maximum-size-in-bytes', '501') }],
    [{ url: swap('vercel-blob-allow-overwrite', 'true') }], [{ url: swap('vercel-blob-add-random-suffix', 'true') }],
    [{ url: begun.upload.url + '&extra=1' }], [{ url: begun.upload.url + '&pathname=att/x' }],
    [{ multipartUrl: begun.upload.url }], [{ expiresAt: 'soon' }], [{ method: 'POST' }],
    [{}, { attachmentId: randomUUID() }], [{}, { size: 499 }],
  ]) await assert.rejects(up(upload, d, extra), /invalid_grant/, JSON.stringify(upload).slice(0, 100));
  await assert.rejects(up({ expiresAt: iso(start - 1) }), /grant_expired/);
  await assert.rejects(up({}, { ...d, size: MAX_ATTACHMENT_BYTES + 1 }), /invalid_expected/);
  await assert.rejects(up({}, { ...d, sha256: 'x' }), /invalid_expected/);
  // File changed after describe: refused before any transfer.
  writeFileSync(p, randomBytes(501));
  await assert.rejects(up({}), /file_changed_while_reading/);
  // Download grants: a bounded opaque ETag (printable, no spaces or controls), bounded size.
  const g = await fixture(), a = await g.uploaded();
  const m = g.message({ attachmentIds: [a.attachmentId] }); await g.bridge.sendMessage(jarvis, m);
  const grant = await g.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId });
  const dir = tmp(), down = (x, n) => downloadFile(x, path.join(dir, n), { fetchImpl: g.r2.fetch, now: g.clock });
  await assert.rejects(down({ ...grant, download: { ...grant.download, headers: { 'if-match': 'bad etag\n' } } }, 'a'), /invalid_grant/);
  await assert.rejects(down({ ...grant, download: { ...grant.download, headers: {} } }, 'b'), /invalid_grant/);
  await assert.rejects(down({ ...grant, size: MAX_ATTACHMENT_BYTES + 1 }, 'c'), /invalid_grant/);
  await assert.rejects(down({ ...grant, sha256: 'x' }, 'd'), /invalid_grant/);
  // Bound to an attachment and message; a range must be signed and declared together.
  await assert.rejects(down({ ...grant, attachmentId: undefined }, 'e'), /invalid_grant/);
  await assert.rejects(down({ ...grant, messageId: 'x' }, 'f'), /invalid_grant/);
  await assert.rejects(down({ ...grant, download: { ...grant.download, headers: { ...grant.download.headers, range: 'bytes=0-9' } } }, 'g'), /invalid_grant/);
  await assert.rejects(down({ ...grant, download: { ...grant.download, range: { start: 0, end: 9 } } }, 'h'), /invalid_grant/);
  await assert.rejects(down({ ...grant, download: { ...grant.download, headers: { ...grant.download.headers, range: 'bytes=0-' } } }, 'i'), /invalid_grant/);
  assert.deepEqual(readdirSync(dir), []);
});

test('client helper: transfers are bounded in time; stalls and caller aborts fail cleanly', async () => {
  const f = await fixture(), a = await f.uploaded(Buffer.from('slow content'));
  const m = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
  const grant = await f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId });
  const dir = tmp();
  const stalled = async () => new Response(new ReadableStream({ pull() { return new Promise(() => {}); } }), { status: 200 });
  await assert.rejects(downloadFile(grant, path.join(dir, 'x.bin'), { fetchImpl: stalled, now: f.clock, timeoutMs: 50 }), /transfer_timeout/);
  const hung = () => new Promise(() => {});
  await assert.rejects(downloadFile(grant, path.join(dir, 'y.bin'), { fetchImpl: hung, now: f.clock, timeoutMs: 50 }), /transfer_timeout/);
  const controller = new AbortController(); setTimeout(() => controller.abort(), 20);
  await assert.rejects(downloadFile(grant, path.join(dir, 'z.bin'), { fetchImpl: stalled, now: f.clock, signal: controller.signal }), /transfer_aborted/);
  assert.deepEqual(readdirSync(dir), [], 'temp files removed');
  for (const timeoutMs of [0, MAX_TRANSFER_MS + 1]) {
    await assert.rejects(downloadFile(grant, path.join(dir, 'w.bin'), { fetchImpl: f.r2.fetch, now: f.clock, timeoutMs }), /invalid_timeout/);
  }
  // Upload: a hung server times out, and an early rejection leaves the file stream closed.
  const p = file(randomBytes(300)), d = await describeFile(p);
  const begun = await f.att().begin(jarvis, { name: 'u', ...d });
  await assert.rejects(uploadFile(p, begun, d, { fetchImpl: hung, now: f.clock, timeoutMs: 50 }), /transfer_timeout/);
  let body;
  await assert.rejects(uploadFile(p, begun, d, { now: f.clock, fetchImpl: async (_u, init) => { body = init.body; return new Response(null, { status: 403 }); } }), /upload_rejected/);
  const after = await body.getReader().read().catch(() => ({ done: true }));
  assert.equal(after.done, true, 'stream ended, not left open');
});

test('client helper: byte bounds, partial writes, destination races and opaque compressed bytes', async () => {
  // Hash exactly the stated size: a source that grows past it is refused.
  await assert.rejects(hashStream(Readable.from([Buffer.alloc(10), Buffer.alloc(10)]), 15), /file_changed_while_reading/);
  await assert.rejects(hashStream(Readable.from([Buffer.alloc(10)]), 15), /file_changed_while_reading/);
  assert.equal((await hashStream(Readable.from([Buffer.alloc(15)]), 15)).size, 15);
  // Partial writes are completed; zero progress is an error.
  const written = [];
  await writeFully({ write: async (chunk, offset, length) => { written.push(chunk.subarray(offset, offset + Math.min(2, length))); return { bytesWritten: Math.min(2, length) }; } },
    Buffer.from('abcdefg'), AbortSignal.timeout(1000));
  assert.equal(Buffer.concat(written).toString(), 'abcdefg');
  await assert.rejects(writeFully({ write: async () => ({ bytesWritten: 0 }) }, Buffer.from('x'), AbortSignal.timeout(1000)), /write_stalled/);
  // Compressed files are opaque bytes: stored and returned unchanged, never decoded.
  const f = await fixture(), gz = gzipSync(Buffer.from('compressed payload '.repeat(100)));
  const a = await f.uploaded(gz);
  const m = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
  const grant = await f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId });
  const dir = tmp(), dest = path.join(dir, 'archive.gz');
  await downloadFile(grant, dest, { fetchImpl: f.r2.fetch, now: f.clock });
  assert.deepEqual(readFileSync(dest), gz);
  // A response that declares an encoding is refused (it would be decoded in transit).
  await assert.rejects(downloadFile(grant, path.join(dir, 'e.bin'), { now: f.clock,
    fetchImpl: async () => new Response(gz, { status: 200, headers: { 'content-encoding': 'gzip' } }) }), /unexpected_content_encoding/);
  // Destination created by someone else during the transfer: not clobbered;
  // the verified bytes stay quarantined until the caller discards them.
  const race = path.join(dir, 'race.bin');
  await assert.rejects(downloadFile(grant, race, { now: f.clock, fetchImpl: async (u, init) => {
    writeFileSync(race, 'theirs'); return f.r2.fetch(u, init);
  } }), /destination_exists/);
  assert.equal(readFileSync(race, 'utf8'), 'theirs');
  assert.deepEqual(visible(dir), ['archive.gz', 'race.bin']);
  await discardPartial(race, grant.attachmentId);
  assert.deepEqual(readdirSync(dir).sort(), ['archive.gz', 'race.bin']);
});

test('time is read after the storage lock: authority and expiry are judged when the transaction runs', async () => {
  const d = { name: 'x', size: 10, sha256: 'a'.repeat(64) };
  // begin: the token expires while waiting for the lock -> no reservation.
  const f = await fixture();
  f.hooks.lock = () => { f.advance(2 * MINUTE); };
  await rejects(f.att().begin(who('jarvis', start + MINUTE), d), 'attachment_authorization_inactive');
  assert.equal(f.snapshot().attachments, undefined);
  // finalize (reserved): token expires in the lock wait -> no HEAD is sent.
  const g = await fixture();
  const p = file(randomBytes(100)), dd = await describeFile(p);
  const begun = await g.att().begin(who('jarvis', start + 10 * MINUTE), { name: 'x', ...dd });
  await uploadFile(p, begun, dd, { fetchImpl: g.r2.fetch, now: g.clock });
  const heads = () => g.r2.calls.filter(c => c.method === 'HEAD').length, before = heads();
  g.hooks.lock = () => { g.advance(11 * MINUTE); };
  await rejects(g.att().finalize(who('jarvis', start + 10 * MINUTE), { id: begun.attachmentId }), 'attachment_authorization_inactive');
  assert.equal(heads(), before, 'no provider call after authority ended');
  // finalize (already available): the record expires in the lock wait -> no success.
  const h = await fixture(), a = await h.uploaded();
  h.hooks.lock = () => { h.advance(ATTACHMENT_TTL_MS); };
  await rejects(h.att().finalize(jarvis, { id: a.attachmentId }), 'attachment_expired');
  // download: the referencing message's authority lapses in the lock wait -> no URL.
  const k = await fixture(), b = await k.uploaded();
  const m = k.message({ attachmentIds: [b.attachmentId] }); await k.bridge.sendMessage(jarvis, m);
  k.hooks.lock = () => { k.advance(HOUR); };
  await rejects(k.att().download(friday, { messageId: m.id, attachmentId: b.attachmentId }), 'message_authorization_inactive');
  // A URL issued after a lock wait is bounded from the time the transaction ran.
  const q = await fixture();
  q.hooks.lock = () => { q.advance(5 * MINUTE); };
  const late = await q.att().begin(who('jarvis', start + 12 * MINUTE), d);
  assert.equal(Date.parse(late.upload.expiresAt), start + 12 * MINUTE, 'capped by the token, measured after the wait');
});

test('client helper: an aborted transfer never starts work and leaves no unhandled rejection', async () => {
  const unhandled = [];
  const onUnhandled = reason => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    const f = await fixture(), a = await f.uploaded(Buffer.from('abort me'));
    const m = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
    const grant = await f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId });
    const dir = tmp();
    let fetches = 0;
    const rejecting = async () => { fetches++; throw Error('FAKE_FETCH_REJECTED'); };
    const aborted = AbortSignal.abort();
    // Pre-aborted: fetch, read and write are never invoked.
    await assert.rejects(downloadFile(grant, path.join(dir, 'a.bin'), { fetchImpl: rejecting, now: f.clock, signal: aborted }), /transfer_aborted/);
    const p = file(randomBytes(64)), d = await describeFile(p);
    const begun = await f.att().begin(jarvis, { name: 'u', ...d });
    await assert.rejects(uploadFile(p, begun, d, { fetchImpl: rejecting, now: f.clock, signal: aborted }), /transfer_aborted/);
    await assert.rejects(describeFile(p, { signal: aborted }), /transfer_aborted/);
    let writes = 0;
    await assert.rejects(writeFully({ write: async () => { writes++; return { bytesWritten: 1 }; } }, Buffer.from('x'), aborted), /transfer_aborted/);
    assert.equal(fetches, 0, 'fetch never invoked'); assert.equal(writes, 0, 'write never invoked');
    // Aborted mid-flight, then the fetch rejects later: still no unhandled rejection.
    const controller = new AbortController();
    const late = () => new Promise((_, reject) => setTimeout(() => reject(Error('FAKE_FETCH_REJECTED_LATE')), 30));
    setTimeout(() => controller.abort(), 5);
    await assert.rejects(downloadFile(grant, path.join(dir, 'b.bin'), { fetchImpl: late, now: f.clock, signal: controller.signal }), /transfer_aborted/);
    await new Promise(resolve => setTimeout(resolve, 60));
    assert.deepEqual(readdirSync(dir), [], 'temp files removed');
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
  assert.deepEqual(unhandled.map(String), []);
});

test('client helper: an abort during transfer startup is never lost (late failure or a promise that never settles)', async () => {
  const unhandled = [];
  const onUnhandled = reason => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    const f = await fixture(), a = await f.uploaded(Buffer.from('startup abort'));
    const m = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
    const grant = await f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId });
    const dir = tmp();
    for (const [name, pending] of [
      ['late failure', () => new Promise((_, reject) => setTimeout(() => reject(Error('FAKE_LATE_AFTER_STARTUP_ABORT')), 25))],
      ['never settles', () => new Promise(() => {})],
    ]) {
      const controller = new AbortController();
      // fetch aborts synchronously while starting, then returns pending work.
      const fetchImpl = () => { controller.abort(); return pending(); };
      const started = Date.now();
      await assert.rejects(downloadFile(grant, path.join(dir, `${name}.bin`), { fetchImpl, now: f.clock, signal: controller.signal,
        timeoutMs: 2000 }), /transfer_aborted/, name);
      assert.ok(Date.now() - started < 1000, `${name}: settled by the abort, not by the work or the 2 s timeout`);
      const p = file(randomBytes(32)), d = await describeFile(p);
      const begun = await f.att().begin(jarvis, { name: 'u', ...d });
      const up = new AbortController();
      await assert.rejects(uploadFile(p, begun, d, { now: f.clock, signal: up.signal, timeoutMs: 2000,
        fetchImpl: () => { up.abort(); return pending(); } }), /transfer_aborted/, `upload ${name}`);
      f.advance(10000);
    }
    await new Promise(resolve => setTimeout(resolve, 60));
    assert.deepEqual(readdirSync(dir), [], 'temp files removed');
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
  assert.deepEqual(unhandled.map(String), []);
});

// --- Resumable downloads, chunks, budgets and size boundaries -----------------
// A stream that delivers the first `n` bytes of `body`, then fails (connection drop).
const dropAfter = (body, n) => { let sent = false; return new ReadableStream({ pull(c) {
  if (sent) c.error(Error('FAKE_CONNECTION_RESET')); else { sent = true; c.enqueue(body.subarray(0, n)); } } }); };
async function sentAttachment(f, bytes) {
  const a = await f.uploaded(bytes);
  const m = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
  return { a, m, grant: range => f.att().download(friday, { messageId: m.id, attachmentId: a.attachmentId, ...range }) };
}

test('resume: an interrupted download keeps its ordered prefix and resumes with an exact signed Range; 206 and the whole SHA-256 are checked', async () => {
  const f = await fixture(), bytes = randomBytes(300 * 1024), { a, grant } = await sentAttachment(f, bytes);
  const dir = tmp(), dest = path.join(dir, 'big.bin'), first = await grant();
  assert.equal('range' in first.download.headers, false, 'no range: the whole object in one grant');
  await assert.rejects(downloadFile(first, dest, { now: f.clock,
    fetchImpl: async (u, init) => { const res = await f.r2.fetch(u, init); await res.body.cancel();
      return new Response(dropAfter(bytes, 100 * 1024), { status: 200, headers: { 'content-length': String(bytes.length) } }); } }), /transfer_failed/);
  assert.deepEqual(visible(dir), [], 'nothing at the destination yet');
  const offset = await resumeOffset(dest, first);
  assert.equal(offset, 100 * 1024);
  // A grant for any other offset is refused before any request.
  const stale = await grant({ rangeStart: 0, rangeEnd: bytes.length - 1 });
  assert.equal('range' in stale.download, false, 'a whole-object range is a plain grant');
  await assert.rejects(downloadFile(stale, dest, { fetchImpl: f.r2.fetch, now: f.clock }), /range_mismatch/);
  const resume = await grant({ rangeStart: offset });
  assert.deepEqual(resume.download.range, { start: offset, end: bytes.length - 1 });
  assert.equal(resume.download.headers.range, `bytes=${offset}-${bytes.length - 1}`);
  // The Range and If-Match headers are not part of a Blob signature: the client checks the response itself.
  assert.equal(new URL(resume.download.url).searchParams.has('range'), false);
  // Storage answering a ranged grant with the wrong Content-Range: this attempt's bytes are dropped, the prefix kept.
  await assert.rejects(downloadFile(resume, dest, { now: f.clock, fetchImpl: async (_u, init) => new Response(bytes.subarray(offset),
    { status: 206, headers: { 'content-range': `bytes ${offset + 1}-${bytes.length}/${bytes.length}`, etag: init.headers['if-match'] } }) }), /content_range_mismatch/);
  // A full 200 to a ranged request (Range ignored): refused before any byte is written; progress retained.
  await assert.rejects(downloadFile(resume, dest, { now: f.clock, fetchImpl: async () => new Response('x', { status: 200 }) }), /range_not_honored/);
  // A 206 without the recorded ETag (If-Match possibly ignored): refused, nothing appended.
  await assert.rejects(downloadFile(resume, dest, { now: f.clock, fetchImpl: async () => new Response(bytes.subarray(offset),
    { status: 206, headers: { 'content-range': `bytes ${offset}-${bytes.length - 1}/${bytes.length}` } }) }), /object_changed/);
  assert.equal(await resumeOffset(dest, first).catch(e => e.code), 0, 'a changed object version discards the partial state');
  // Re-download the prefix (a fresh whole-object grant interrupted at the same offset) and resume again.
  const whole = await grant();
  await assert.rejects(downloadFile(whole, dest, { now: f.clock, fetchImpl: async () => new Response(dropAfter(bytes, offset), { status: 200 }) }), /transfer_failed|transfer_incomplete/);
  assert.equal(await resumeOffset(dest, first), offset);
  // A 429 or a 503: rejected, progress retained.
  for (const status of [429, 503]) {
    await assert.rejects(downloadFile(resume, dest, { now: f.clock, fetchImpl: async () => new Response('x', { status }) }), /download_rejected/);
  }
  assert.equal(await resumeOffset(dest, first), offset);
  assert.deepEqual(await downloadFile(resume, dest, { fetchImpl: f.r2.fetch, now: f.clock }),
    { complete: true, path: dest, size: a.size, sha256: a.sha256 });
  assert.deepEqual(readFileSync(dest), bytes);
  assert.deepEqual(readdirSync(dir), ['big.bin'], 'partial state removed after publish');
});

test('resume: partial state is bound to the same attachment, message, size, SHA-256 and object version', async () => {
  const f = await fixture(), bytes = randomBytes(64 * 1024);
  bytes[10] = 0x58; // The old constant-'X' corruption was a deterministic no-op for this byte.
  const { a, m, grant } = await sentAttachment(f, bytes);
  const dir = tmp(), dest = path.join(dir, 'f.bin'), first = await grant();
  await assert.rejects(downloadFile(first, dest, { now: f.clock,
    fetchImpl: async () => new Response(dropAfter(bytes, 1000), { status: 200 }) }), /transfer_failed/);
  // The same attachment referenced by another message: different context, refused.
  const m2 = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m2);
  const other = await f.att().download(friday, { messageId: m2.id, attachmentId: a.attachmentId, rangeStart: 1000 });
  await assert.rejects(downloadFile(other, dest, { fetchImpl: f.r2.fetch, now: f.clock }), /partial_mismatch/);
  await assert.rejects(resumeOffset(dest, { ...first, messageId: m2.id }), /partial_mismatch/);
  await assert.rejects(resumeOffset(dest, { ...first, sha256: 'b'.repeat(64) }), /partial_mismatch/);
  await assert.rejects(resumeOffset(dest, { ...first, size: first.size + 1 }), /partial_mismatch/);
  const resume = await grant({ rangeStart: 1000 });
  await assert.rejects(downloadFile({ ...resume, download: { ...resume.download, headers: { ...resume.download.headers,
    'if-match': '"' + 'f'.repeat(32) + '"' } } }, dest, { fetchImpl: f.r2.fetch, now: f.clock }), /partial_mismatch/, 'another object version');
  // A partial file replaced by a symlink is never followed.
  const { data } = partialPaths(dest, a.attachmentId);
  rmSync(data);
  (await import('node:fs')).symlinkSync('/etc/hosts', data);
  await assert.rejects(downloadFile(resume, dest, { fetchImpl: f.r2.fetch, now: f.clock }), /partial_mismatch/);
  await discardPartial(dest, a.attachmentId);
  // Corrupted partial bytes are caught by the whole-file SHA-256, and everything is discarded.
  await assert.rejects(downloadFile(first, dest, { now: f.clock,
    fetchImpl: async () => new Response(dropAfter(bytes, 1000), { status: 200 }) }), /transfer_failed/);
  const original = readFileSync(data)[10]; assert.equal(original, 0x58);
  const changed = original ^ 0xff; assert.notEqual(changed, original);
  const fd = openSync(data, 'r+'); writeSync(fd, Buffer.from([changed]), 0, 1, 10); closeSync(fd);
  await assert.rejects(downloadFile(resume, dest, { fetchImpl: f.r2.fetch, now: f.clock }), /sha256_mismatch/);
  assert.deepEqual(readdirSync(dir), []);
  assert.equal(m.id !== m2.id, true);
});

test('chunks and budgets: whole remaining range by default, 16 MiB minimum chunks, charged attempts, separate download rate', async () => {
  const f = await fixture();
  // A large available record (metadata only; no bytes needed to check ranges and budgets).
  const size = DEFAULT_MAX_ATTACHMENT_BYTES;
  const begun = await f.att().begin(jarvis, { name: 'big', size, sha256: 'a'.repeat(64) });
  await f.store.transaction(s => Object.assign(s.attachments.records[begun.attachmentId], { state: 'available', etag: '"' + '0'.repeat(32) + '"' }));
  const m = f.message({ attachmentIds: [begun.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
  const get = range => f.att().download(friday, { messageId: m.id, attachmentId: begun.attachmentId, ...range });
  for (const bad of [{ rangeStart: size }, { rangeStart: -1 }, { rangeStart: 5, rangeEnd: 4 }, { rangeStart: 0, rangeEnd: MIN_RANGE_BYTES - 2 },
    { rangeStart: 0, rangeEnd: size }, { rangeStart: 1.5 }, { rangeStart: '0' }]) {
    await rejects(get(bad), 'invalid_range');
  }
  const issued = () => f.snapshot().attachments.records[begun.attachmentId].issued.get;
  assert.equal(issued(), 0, 'invalid ranges are refused before any charge');
  assert.equal((await get({ rangeStart: 0, rangeEnd: MIN_RANGE_BYTES - 1 })).download.headers.range, `bytes=0-${MIN_RANGE_BYTES - 1}`);
  assert.equal((await get({ rangeStart: size - 10 })).download.headers.range, `bytes=${size - 10}-${size - 1}`, 'a short tail is fine');
  assert.equal((await get({ rangeStart: size - 10, rangeEnd: size - 1 })).download.range.end, size - 1);
  // A failed attempt after the charge (here: signing) is still charged; nothing is refunded.
  f.hooks.get = () => { throw Error('FAKE_SIGNING_FAILURE'); };
  await assert.rejects(get({}), /FAKE_SIGNING_FAILURE/);
  f.hooks.get = null;
  assert.equal(issued(), 4);
  // Per-role download rate: 20 per minute; 429 leaves the receiver's progress untouched, and uploads are a separate bucket.
  for (let i = issued(); i < DOWNLOAD_RATE_PER_MINUTE; i++) await get({});
  await rejects(get({}), 'attachment_rate_limited');
  await f.att().begin(jarvis, { name: 'other', size: 10, sha256: 'b'.repeat(64) });
  // Per-attachment budget: 80 grants (1 GB in 16 MiB chunks is 60; in 64 MiB chunks 15).
  assert.equal(Math.ceil(MAX_ATTACHMENT_BYTES / MIN_RANGE_BYTES), 60); assert.equal(Math.ceil(MAX_ATTACHMENT_BYTES / (64 * 1024 * 1024)), 15);
  f.advance(MINUTE);
  while (issued() < MAX_GET_URLS) { f.advance(3100); await get({}); }
  f.advance(3100);
  await rejects(get({}), 'attachment_issue_budget_exhausted');
});

test('size limit: decimal 500 MB default and 1 GB hard cap; trusted configuration within range, read per use, fails closed', async () => {
  const cfg = max => attachmentConfig({ ...FAKE, BRIDGE_ATTACHMENT_MAX_BYTES: max });
  assert.equal(attachmentConfig(FAKE).maxBytes, 500000000);
  assert.equal(cfg('500000000').maxBytes, 500000000); assert.equal(cfg('1000000000').maxBytes, 1000000000);
  for (const bad of ['499999999', '1000000001', '5e8', '0500000000', ' 500000000', '', '1073741824', '2147483648']) {
    assert.deepEqual(cfg(bad), { configured: true, enabled: true, valid: false }, bad);
  }
  const f = await fixture({ env: { ...FAKE, BRIDGE_ATTACHMENT_MAX_BYTES: '1000000000' } });
  const d = size => ({ name: 'x', size, sha256: 'a'.repeat(64) });
  const big = await f.att().begin(jarvis, d(MAX_ATTACHMENT_BYTES));
  assert.equal(new URL(big.upload.url).searchParams.get('vercel-blob-maximum-size-in-bytes'), '1000000000');
  await rejects(f.att().begin(jarvis, d(MAX_ATTACHMENT_BYTES + 1)), 'attachment_too_large');
  // Lowered while in flight: new upload URLs and new message references above it are refused.
  f.env.BRIDGE_ATTACHMENT_MAX_BYTES = '500000000';
  await rejects(f.att().begin(jarvis, { ...d(MAX_ATTACHMENT_BYTES), id: big.attachmentId }), 'attachment_too_large');
  await f.store.transaction(s => Object.assign(s.attachments.records[big.attachmentId], { state: 'available', etag: '"' + '0'.repeat(32) + '"' }));
  await rejects(f.bridge.sendMessage(jarvis, f.message({ attachmentIds: [big.attachmentId] })), 'attachment_too_large');
  // Invalid configuration closes everything, including a capability already constructed.
  const att = f.att();
  f.env.BRIDGE_ATTACHMENT_MAX_BYTES = '2000000000';
  await rejects(att.begin(jarvis, d(10)), 'attachments_not_enabled');
  await rejects(f.bridge.sendMessage(jarvis, f.message({ attachmentIds: [big.attachmentId] })), 'attachments_not_enabled');
  // The MCP schema advertises the current maximum, matching the core.
  for (const [max, expected] of [[undefined, 500000000], ['1000000000', 1000000000]]) {
    const rt = await runtimeFixture({ ...FAKE, ...(max ? { BRIDGE_ATTACHMENT_MAX_BYTES: max } : {}) });
    const tools = (await rt.rpc('jarvis', 'tools/list', {})).result.tools;
    assert.equal(tools.find(t => t.name === 'bridge_attachment_begin').inputSchema.properties.size.maximum, expected);
    assert.deepEqual(tools.find(t => t.name === 'bridge_attachment_download').inputSchema.required, ['messageId', 'attachmentId']);
  }
  const off = await runtimeFixture({ ...FAKE, BRIDGE_ATTACHMENT_MAX_BYTES: 'bogus' });
  assert.equal((await off.rpc('jarvis', 'tools/list', {})).result.tools.some(t => t.name.startsWith('bridge_attachment_')), false);
  // The helper agrees on the hard cap.
  const sparse = path.join(tmp(), 'sparse.bin'); writeFileSync(sparse, ''); truncateSync(sparse, MAX_ATTACHMENT_BYTES + 1);
  await assert.rejects(describeFile(sparse), /attachment_size_out_of_range/);
  await assert.rejects(uploadFile(sparse, big, { size: MAX_ATTACHMENT_BYTES + 1, sha256: 'a'.repeat(64) }), /invalid_expected/);
});

test('streaming at the 1 GB cap: the helper uploads and downloads exactly 1,000,000,000 bytes without buffering the payload', async () => {
  const f = await fixture({ env: { ...FAKE, BRIDGE_ATTACHMENT_MAX_BYTES: '1000000000' } });
  const dir = tmp(), src = path.join(dir, 'zeros.bin');
  writeFileSync(src, ''); truncateSync(src, MAX_ATTACHMENT_BYTES); // sparse: 1 GB of zeros, no disk use
  const baseline = process.memoryUsage().rss;
  let peak = baseline;
  const sample = () => { peak = Math.max(peak, process.memoryUsage().rss); };
  const d = await describeFile(src);
  assert.equal(d.size, MAX_ATTACHMENT_BYTES);
  const begun = await f.att().begin(jarvis, { name: 'zeros.bin', ...d });
  let uploaded = 0;
  await uploadFile(src, begun, d, { now: f.clock, fetchImpl: async (_u, init) => {
    for await (const chunk of init.body) { uploaded += chunk.length; sample(); }
    return Response.json({ pathname: 'att/' + begun.attachmentId, etag: '"opaque-1gb-etag"' });
  } });
  assert.equal(uploaded, MAX_ATTACHMENT_BYTES);
  // Download: a generated 1 GB 200 response, consumed chunk by chunk to disk.
  await f.store.transaction(s => Object.assign(s.attachments.records[begun.attachmentId], { state: 'available', etag: '"opaque-1gb-etag"' }));
  const m = f.message({ attachmentIds: [begun.attachmentId] }); await f.bridge.sendMessage(jarvis, m);
  const grant = await f.att().download(friday, { messageId: m.id, attachmentId: begun.attachmentId });
  const block = Buffer.alloc(1 << 20);
  const zeros = () => { let left = MAX_ATTACHMENT_BYTES; return new ReadableStream({ pull(c) {
    if (!left) { c.close(); return; } const n = Math.min(left, block.length); left -= n; sample(); c.enqueue(block.subarray(0, n)); } }); };
  const out = await downloadFile(grant, path.join(dir, 'copy.bin'), { now: f.clock,
    fetchImpl: async () => new Response(zeros(), { status: 200, headers: { 'content-length': String(MAX_ATTACHMENT_BYTES) } }) });
  assert.deepEqual([out.complete, out.size, out.sha256], [true, MAX_ATTACHMENT_BYTES, d.sha256]);
  assert.ok(peak - baseline < 256 * 1024 * 1024, `RSS grew ${(peak - baseline) / 1e6} MB; the 1 GB payload was not buffered`);
  rmSync(dir, { recursive: true, force: true });
});

// --- Concurrent writers on one partial (repro) ---------------------------------
// A 206 body the test controls: push() enqueues the chunk, end() closes it.
function controlled(chunk) {
  let ctrl, fetched = false;
  const stream = new ReadableStream({ start(c) { ctrl = c; } });
  return { fetched: () => fetched, push: () => ctrl.enqueue(Buffer.from(chunk)), end: () => ctrl.close(),
    fetchImpl: async (_u, init) => { fetched = true; return new Response(stream, { status: 206, headers: { 'content-range': 'bytes 3-5/6', etag: init.headers['if-match'] } }); } };
}
const until = async (cond, what) => {
  for (let i = 0; i < 400 && !cond(); i++) await new Promise(r => setTimeout(r, 5));
  assert.ok(cond(), what);
};
async function seededResume() {
  const f = await fixture(), bytes = Buffer.from('abcdef'), { a, grant } = await sentAttachment(f, bytes);
  const dir = tmp(), dest = path.join(dir, 'x.bin'), first = await grant();
  await assert.rejects(downloadFile(first, dest, { now: f.clock, fetchImpl: async () => new Response(dropAfter(bytes, 3), { status: 200 }) }), /transfer_failed/);
  assert.equal(await resumeOffset(dest, first), 3);
  const { data } = partialPaths(dest, a.attachmentId);
  assert.equal(readFileSync(data, 'utf8'), 'abc');
  return { f, a, dir, dest, data, resume: await grant({ rangeStart: 3 }) };
}

test('concurrent resume (repro): two writers on one partial can never publish bytes other than the verified SHA-256', async () => {
  const { f, dir, dest, data, resume } = await seededResume();
  const A = controlled('def'), B = controlled('XXX');
  const pA = downloadFile(resume, dest, { now: f.clock, fetchImpl: A.fetchImpl }).then(v => v, e => e);
  const pB = downloadFile(resume, dest, { now: f.clock, fetchImpl: B.fetchImpl }).then(v => v, e => e);
  await until(() => A.fetched() && B.fetched(), 'both opened the same partial and requested the range');
  A.push(); await until(() => readFileSync(data, 'utf8') === 'abcdef', 'A wrote def');
  B.push(); await until(() => readFileSync(data, 'utf8') === 'abcXXX', 'B overwrote the same inode');
  A.end(); B.end();
  const [ra, rb] = await Promise.all([pA, pB]);
  assert.equal(ra.code, 'sha256_mismatch', 'A verifies the bytes it publishes, not its input stream');
  assert.equal(rb.code, 'sha256_mismatch');
  assert.equal(existsSync(dest), false, 'nothing published');
  assert.deepEqual(readdirSync(dir), [], 'no partial, sidecar or snapshot left');
});

test('concurrent resume: a stale writer after publication cannot change the published file', async () => {
  const { f, dir, dest, resume } = await seededResume();
  const A = controlled('def'), B = controlled('XXX');
  const pA = downloadFile(resume, dest, { now: f.clock, fetchImpl: A.fetchImpl });
  const pB = downloadFile(resume, dest, { now: f.clock, fetchImpl: B.fetchImpl }).then(v => v, e => e);
  await until(() => A.fetched() && B.fetched(), 'both opened the same partial');
  A.push(); A.end();
  assert.deepEqual(await pA, { complete: true, path: dest, size: 6, sha256: resume.sha256 });
  // B still holds a descriptor to the old partial inode and writes through it.
  B.push(); B.end();
  assert.equal((await pB).code, 'sha256_mismatch');
  assert.equal(readFileSync(dest, 'utf8'), 'abcdef', 'the published snapshot is a different, private inode');
  assert.deepEqual(readdirSync(dir), ['x.bin']);
});

test('concurrent resume: discardPartial during a transfer never corrupts what the transfer publishes', async () => {
  const { f, a, dir, dest, data, resume } = await seededResume();
  const C = controlled('def');
  const pC = downloadFile(resume, dest, { now: f.clock, fetchImpl: C.fetchImpl });
  await until(() => C.fetched(), 'transfer started');
  C.push(); await until(() => readFileSync(data, 'utf8') === 'abcdef', 'C wrote def');
  await discardPartial(dest, a.attachmentId);
  assert.equal(existsSync(data), false);
  C.end();
  assert.equal((await pC).complete, true, 'published from its own verified handle');
  assert.equal(readFileSync(dest, 'utf8'), 'abcdef');
  assert.deepEqual(readdirSync(dir), ['x.bin']);
});

// --- Complete partials: local finalization (crash after the last byte) ----------
test('complete partial (repro): stopped after the last byte, it finalizes locally with a fresh whole-object grant, no request', async () => {
  const { f, a, dir, dest, data, resume } = await seededResume();
  // The final bytes are persisted, then the process stops before publishing (here: aborted).
  const C = controlled('def'), stop = new AbortController();
  const pC = downloadFile(resume, dest, { now: f.clock, fetchImpl: C.fetchImpl, signal: stop.signal }).then(v => v, e => e);
  await until(() => C.fetched(), 'transfer started');
  C.push(); await until(() => readFileSync(data, 'utf8') === 'abcdef', 'last byte persisted');
  stop.abort();
  assert.equal((await pC).code, 'transfer_aborted');
  assert.equal(existsSync(dest), false);
  assert.equal(await resumeOffset(dest, resume), 6, 'complete, but not published');
  // The bridge never grants a range starting at the size (gate unchanged)...
  await rejects(f.att().download(friday, { messageId: resume.messageId, attachmentId: a.attachmentId, rangeStart: 6 }), 'invalid_range');
  // ...and a ranged grant does not finalize either.
  await assert.rejects(downloadFile(resume, dest, { now: f.clock, fetchImpl: C.fetchImpl }), /range_mismatch/);
  // A fresh whole-object grant for the same binding finalizes locally.
  const fresh = await f.att().download(friday, { messageId: resume.messageId, attachmentId: a.attachmentId });
  const noNetwork = async () => { throw Error('NO_REQUEST_EXPECTED'); };
  assert.deepEqual(await downloadFile(fresh, dest, { now: f.clock, fetchImpl: noNetwork }),
    { complete: true, path: dest, size: 6, sha256: a.sha256 });
  assert.equal(readFileSync(dest, 'utf8'), 'abcdef');
  assert.deepEqual(readdirSync(dir), ['x.bin']);
});

test('complete partial: wrong bytes are never published; binding, expiry and destination rules still apply', async () => {
  const { f, a, dir, dest, data } = await seededResume();
  const m2 = f.message({ attachmentIds: [a.attachmentId] }); await f.bridge.sendMessage(jarvis, m2);
  writeFileSync(data, 'abcXYZ'); // full size, wrong content (e.g. a torn or tampered write)
  const noNetwork = async () => { throw Error('NO_REQUEST_EXPECTED'); };
  const messageId = JSON.parse(readFileSync(partialPaths(dest, a.attachmentId).meta, 'utf8')).messageId;
  const fresh = await f.att().download(friday, { messageId, attachmentId: a.attachmentId });
  // Another message's grant does not match the binding; an expired grant is refused before anything.
  const other = await f.att().download(friday, { messageId: m2.id, attachmentId: a.attachmentId });
  await assert.rejects(downloadFile(other, dest, { now: f.clock, fetchImpl: noNetwork }), /partial_mismatch/);
  await assert.rejects(downloadFile(fresh, dest, { now: () => Date.parse(fresh.download.expiresAt) + 1, fetchImpl: noNetwork }), /grant_expired/);
  // A destination that already exists is never replaced, and the complete bytes are kept.
  writeFileSync(dest, 'theirs');
  await assert.rejects(downloadFile(fresh, dest, { now: f.clock, fetchImpl: noNetwork }), /destination_exists/);
  assert.equal(readFileSync(data, 'utf8'), 'abcXYZ');
  rmSync(dest);
  // Wrong SHA-256: refused, nothing published, the untrusted bytes discarded (a fresh download starts over).
  await assert.rejects(downloadFile(fresh, dest, { now: f.clock, fetchImpl: noNetwork }), /sha256_mismatch/);
  assert.equal(existsSync(dest), false);
  assert.deepEqual(readdirSync(dir), []);
  assert.equal(await resumeOffset(dest, fresh), 0);
});
