import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { writeFileSync, readFileSync, rmSync, truncateSync, statSync, openSync, readSync, writeSync, closeSync, readdirSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { presignUrl as realPresignUrl } from '@vercel/blob';
import { Bridge } from '../src/bridge.ts';
import { MemoryStore } from '../src/store.ts';
import { VERIFIED_AUTHORIZATION, SCOPES } from '../src/policy.ts';
import { MESSAGE_PROTOCOL } from '../src/messages.ts';
import { attachmentConfig, createBlobProvider } from '../src/blob.ts';
import { createAttachments, admitAttachments, MAX_HEAD_CALLS, MAX_MULTIPART_UPLOAD_GRANTS, ATTACHMENT_TTL_MS, FINALIZE_LEASE_MS,
  MAX_ATTACHMENT_BYTES } from '../src/attachments.ts';
import { planMultipart, createCheckpoint, uploadMultipart, multipartProgress, breakCheckpointLock, downloadFile, describeFile,
  uploadFile, MAX_PART_ATTEMPTS, MAX_SESSIONS, MAX_PART_CONCURRENCY } from '../src/attachment-client.ts';
import { createFakeBlob } from './fixtures/fake-blob.ts';
import type { FakeBlobOptions, Fault } from './fixtures/fake-blob.ts';
import type { BridgeError } from '../src/policy.ts';
import type { AttachmentConfig, BlobSdk, ValidAttachmentConfig } from '../src/blob.ts';
import type { BeginResult } from '../src/attachments.ts';
import type { FetchInit, MultipartCheckpoint, MultipartOptions, UploadBegun } from '../src/attachment-client.ts';
import type { AttachmentRecord } from '../src/types.ts';
import type { TransportRequest, TransportResponse } from '../src/webhook.ts';
import type { Principal, VerifiedPrincipal } from '../src/types.ts';

/** bridge_attachment_begin's result. */
type Begun = BeginResult;

// Fake private Blob store, fake store ID, memory store: no network, no
// credential, no live service. Behaviour not documented for private signed
// URLs (Range/If-Match on GET, multipart completion limits) is an assumption
// of the fake, exercised both ways where it matters.
const MIB = 1024 * 1024, MINUTE = 60000, HOUR = 3600000, policy = 'c'.repeat(64);
const start = Date.UTC(2026, 9, 31, 12);
const FAKE = { BRIDGE_ATTACHMENTS_ENABLED: 'true', BLOB_STORE_ID: 'store_FakeStore00000001' };
const iso = (ms: number) => new Date(ms).toISOString();
const PART = 16 * MIB, SIZE = 2 * PART + 4321; // three parts
const SHARED = randomBytes(SIZE);
function who(role: string, until = start + 7 * 24 * HOUR) {
  return Object.defineProperty<Principal>({ role, scopes: Object.values(SCOPES[role]!), principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64) },
    VERIFIED_AUTHORIZATION, { value: { policyId: policy, expiresAt: until } }) as VerifiedPrincipal;
}
const jarvis = who('jarvis'), friday = who('friday');
const rejects = (promise: Promise<unknown>, code: string) => assert.rejects(promise, (e: BridgeError) => e.code === code || assert.fail(`expected ${code}, got ${e.code} ${e.stack}`));

async function fixture({ env = { ...FAKE }, lean = false, blobOptions = {} }:
  { env?: Record<string, string | undefined>; lean?: boolean; blobOptions?: Partial<FakeBlobOptions> } = {}) {
  let now = start;
  const clock = () => now, store = new MemoryStore(), policyIds = { jarvis: policy, friday: policy };
  const blob = createFakeBlob({ storeId: env.BLOB_STORE_ID!, clock, lean, ...blobOptions });
  const config = () => attachmentConfig(env), hooks: { head?: (() => unknown) | null } = {};
  const providerFor = (c: AttachmentConfig) => {
    // The fake implements the SDK surface the provider uses.
    const p = createBlobProvider({ config: c, sdk: blob.sdk as unknown as BlobSdk, clock, timeoutMs: 5000 });
    return { ...p, async head(k: string) { await hooks.head?.(); return p.head(k); } };
  };
  const att = () => createAttachments({ store, clock, policyIds, config: config(), provider: providerFor(config()), configNow: config });
  const bridge = new Bridge({ store, clock, dailyEnabled: true, messagePolicyIds: policyIds,
    admitAttachments: (state, envelope, principal, at) => {
      const c = config() as ValidAttachmentConfig; admitAttachments(state, envelope, principal, at, { namespace: c.namespace, policyIds, maxBytes: c.maxBytes });
    } });
  // The recipient's return subscription (needed to send to it).
  const { NativeEvents, EVENT_NAME } = await import('../src/events.ts');
  const { createProtector } = await import('../src/webhook.ts');
  const events = new NativeEvents({ store, protector: createProtector(randomBytes(32)), clock, policyId: policy, enabled: true,
    transport: async (_url: string, req: TransportRequest): Promise<TransportResponse> => ({ status: 200, body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  await events.subscribe(jarvis, { name: EVENT_NAME, arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  const dir = mkdtempSync(path.join(tmpdir(), 'bridge-blob-multipart-'));
  const prepare = async ({ bytes = SHARED, as = jarvis }: { bytes?: Buffer; as?: VerifiedPrincipal } = {}) => {
    const src = path.join(dir, `src-${randomUUID()}.bin`); writeFileSync(src, bytes);
    const plan = await planMultipart(src, { partSize: PART });
    const body = { name: 'big.bin', size: plan.size, sha256: plan.sha256, mode: 'multipart' };
    const begun = await att().begin(as, body);
    const cp = path.join(dir, `.${begun.attachmentId}.checkpoint.json`);
    await createCheckpoint(cp, { attachmentId: begun.attachmentId, plan });
    return { src, plan, body: { ...body, id: begun.attachmentId }, begun, id: begun.attachmentId, cp };
  };
  const run = (u: { cp: string; begun: Begun }, begun: UploadBegun | null | undefined = u.begun, options: MultipartOptions = {}) => uploadMultipart(u.cp, begun, { fetchImpl: blob.fetch, now: clock, ...options });
  const record = (id: string) => store.snapshot().attachments!.records[id]!;
  const ops = (op: string) => blob.calls.filter(c => c.op === op).length;
  const message = (extra: Record<string, unknown> = {}) => ({ protocol: MESSAGE_PROTOCOL, id: randomUUID(), from: 'jarvis', to: 'friday', kind: 'message',
    sentAt: iso(now), expiresAt: iso(now + HOUR), threadId: randomUUID(), route: 'inbox', text: 'See attached.', ...extra });
  const receive = async (id: string, name = 'copy.bin') => {
    const m = message({ attachmentIds: [id] }); await bridge.sendMessage(jarvis, m);
    const dl = await att().download(friday, { messageId: m.id, attachmentId: id });
    return downloadFile(dl, path.join(dir, name), { fetchImpl: blob.fetch, now: clock });
  };
  return { store, clock, blob, env, hooks, policyIds, att, bridge, dir, prepare, run, record, ops, receive, message,
    set: (ms: number) => { now = ms; }, advance: (ms: number) => { now += ms; } };
}

test('multipart end to end: native create/upload/complete with a private capability; HEAD makes it available; recipient verifies SHA-256', async () => {
  const f = await fixture(), u = await f.prepare();
  assert.equal(u.begun.mode, 'multipart');
  assert.equal(new URL(u.begun.upload!.multipartUrl!).pathname, '/api/blob/mpu');
  const out = await f.run(u);
  assert.equal(out.complete, true);
  assert.equal(out.etag, f.blob.objects.get('att/' + u.id)!.etag);
  assert.deepEqual([f.ops('create'), f.ops('upload'), f.ops('complete')], [1, 3, 1]);
  const done = await f.att().finalize(jarvis, { id: u.id, etag: out.etag });
  assert.deepEqual([done.state, f.record(u.id).etag], ['available', out.etag]);
  const got = await f.receive(u.id);
  assert.deepEqual([got.complete, got.sha256], [true, u.plan.sha256]);
  assert.ok(readFileSync(got.path!).equals(SHARED));
  // No capability, signature, delegation or URL in the bridge state or the checkpoint; checkpoint is 0600.
  const state = JSON.stringify(f.store.snapshot()), cp = readFileSync(u.cp, 'utf8');
  for (const secret of ['vercel-blob-signature', 'vercel-blob-delegation', 'vercel.com/api/blob', 'blob.vercel-storage.com']) {
    assert.equal(state.includes(secret), false, secret); assert.equal(cp.includes(secret), false, secret);
  }
  assert.equal(statSync(u.cp).mode & 0o777, 0o600);
  assert.equal(existsSync(u.cp + '.lock'), false, 'the owner lock is released');
  assert.equal(f.blob.calls.some(c => c.method === 'DELETE'), false);
});

test('resume across wakes: a fresh capability per wake continues the same session; the reservation times never move', async () => {
  const f = await fixture(), u = await f.prepare();
  const times = (r: AttachmentRecord) => [r.createdAt, r.uploadUntil, r.expiresAt];
  const fixed = times(f.record(u.id));
  // Wake 1: the capability expires after part 1.
  const fetchImpl = async (url: string, init: FetchInit) => {
    const res = await f.blob.fetch(url, init);
    if ((init.headers as Record<string, string>)['x-mpu-part-number'] === '1') f.set(Date.parse(u.begun.upload!.expiresAt));
    return res;
  };
  await rejects(f.run(u, u.begun, { fetchImpl, concurrency: 1 }), 'grant_expired');
  assert.deepEqual((await multipartProgress(u.cp)).sent, [1]);
  // Wake 2, two hours later: a new process, a new token, begin again with the same body.
  f.set(start + 2 * HOUR);
  const later = who('jarvis', start + 2 * HOUR + 30 * MINUTE);
  const renewed = await f.att().begin(later, u.body);
  assert.notEqual(renewed.upload!.url, u.begun.upload!.url, 'a fresh capability');
  assert.ok(Date.parse(renewed.upload!.expiresAt) <= start + 2 * HOUR + 15 * MINUTE);
  assert.deepEqual(times(f.record(u.id)), fixed, 'createdAt, uploadUntil and expiresAt are fixed');
  const out = await f.run(u, renewed);
  assert.equal(out.complete, true);
  assert.deepEqual([f.ops('create'), f.ops('complete')], [1, 1], 'one session across wakes');
  assert.equal(readFileSync(u.cp, 'utf8').includes(renewed.upload!.url), false);
  assert.equal((await f.att().finalize(later, { id: u.id })).state, 'available');
  // Capabilities stop at the fixed expiry, and their number is bounded.
  const g = await fixture(), w = await g.prepare();
  for (let i = 1; i < MAX_MULTIPART_UPLOAD_GRANTS; i++) await g.att().begin(jarvis, w.body).catch(e => { if (e.code !== 'attachment_rate_limited') throw e; g.advance(MINUTE); return g.att().begin(jarvis, w.body); });
  await rejects(g.att().begin(jarvis, w.body), 'attachment_issue_budget_exhausted');
  g.set(start + ATTACHMENT_TTL_MS);
  await rejects(g.att().begin(jarvis, w.body), 'attachment_expired');
  assert.deepEqual(times(g.record(w.id)), [start, start + ATTACHMENT_TTL_MS, start + ATTACHMENT_TTL_MS]);
});

test('creation: a lost create response stays creation_unknown and is never silently re-sent; a new session needs explicit consent, bounded', async () => {
  const f = await fixture(), u = await f.prepare();
  f.blob.lost.create = true;
  await rejects(f.run(u), 'session_creation_unknown');
  assert.equal((await multipartProgress(u.cp)).phase, 'creation_unknown');
  await rejects(f.run(u), 'session_creation_unknown');
  assert.equal(f.ops('create'), 1, 'not re-sent');
  assert.equal(f.blob.sessions.size, 1, 'the provider holds a session the client never learned');
  const out = await f.run(u, u.begun, { allowNewSession: true });
  assert.equal(out.complete, true);
  const progress = await multipartProgress(u.cp);
  assert.deepEqual([progress.sessions, progress.abandonedSessions, f.ops('create')], [2, 1, 2]);
  assert.equal(f.blob.sessions.size, 1, 'the abandoned session is left alone (no abort, no cleanup)');
  // A stop between recording the intent and learning the outcome is unknown too.
  const g = await fixture(), w = await g.prepare();
  const cp = JSON.parse(readFileSync(w.cp, 'utf8')); cp.phase = 'creating'; cp.creates = 1; writeFileSync(w.cp, JSON.stringify(cp));
  await rejects(g.run(w), 'session_creation_unknown');
  assert.equal(g.ops('create'), 0);
  // Bounded: at most MAX_SESSIONS sessions per checkpoint.
  const h = await fixture(), x = await h.prepare();
  h.blob.lost.create = MAX_SESSIONS + 1;
  for (let i = 0; i < MAX_SESSIONS; i++) await rejects(h.run(x, x.begun, { allowNewSession: true }), 'session_creation_unknown');
  await rejects(h.run(x, x.begun, { allowNewSession: true }), 'session_budget_exhausted');
  assert.equal(h.ops('create'), MAX_SESSIONS);
});

test('ownership (repro): concurrent uploaders on one checkpoint never both create; a stale lock needs explicit removal', async () => {
  const f = await fixture(), u = await f.prepare();
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const fetchImpl = async (url: string, init: FetchInit) => { if ((init.headers as Record<string, string>)['x-mpu-action'] === 'create') await gate; return f.blob.fetch(url, init); };
  const first = f.run(u, u.begun, { fetchImpl });
  for (let i = 0; i < 50 && !existsSync(u.cp + '.lock'); i++) await new Promise(r => setTimeout(r, 5));
  const second = f.run(u, u.begun, { fetchImpl });
  await rejects(second, 'checkpoint_busy');
  release!();
  assert.equal((await first).complete, true);
  assert.equal(f.ops('create'), 1, 'exactly one session');
  // Same-process Promise.all from scratch: one wins, the other is refused; never two sessions.
  const g = await fixture(), w = await g.prepare();
  const results = await Promise.allSettled([g.run(w), g.run(w), g.run(w)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.ok(results.filter(r => r.status === 'rejected').every(r => r.reason.code === 'checkpoint_busy'));
  assert.equal(g.ops('create'), 1);
  // A lock left by a stopped process is not taken over automatically.
  const h = await fixture(), x = await h.prepare();
  writeFileSync(x.cp + '.lock', '{}');
  await rejects(h.run(x), 'checkpoint_busy');
  assert.equal(h.ops('create'), 0);
  await breakCheckpointLock(x.cp);
  assert.equal((await h.run(x)).complete, true);
});

test('multipart grant metadata is bound to the checkpoint before any provider request', async () => {
  const f = await fixture(), u = await f.prepare();
  const calls = f.blob.calls.length;
  await rejects(f.run(u, { ...u.begun, sha256: 'b'.repeat(64) }), 'invalid_grant');
  assert.equal(f.blob.calls.length, calls);
  assert.deepEqual(await multipartProgress(u.cp), { attachmentId: u.id, phase: 'new', partCount: 3, sessions: 0,
    abandonedSessions: 0, completes: 0, etag: null, sent: [], pending: [1, 2, 3] });
});

test('parts (repro): the per-part attempt budget is recorded before each send and holds across restarts', async () => {
  const f = await fixture(), u = await f.prepare();
  // Upload faults always receive the request headers.
  f.blob.faults.upload = ((_p: unknown, { headers }: { headers: Headers }) => headers.get('x-mpu-part-number') === '2' ? new Response('{"error":{"code":"unknown_error"}}', { status: 500 }) : null) as Fault;
  const sends = () => f.blob.calls.filter(c => c.op === 'upload').length;
  await rejects(f.run(u, u.begun, { concurrency: 1 }), 'part_budget_exhausted');
  const afterFirst = sends();
  assert.equal(afterFirst, 1 + MAX_PART_ATTEMPTS, 'part 1 once, part 2 up to the budget; the failure stops the run before part 3');
  for (let i = 0; i < 3; i++) await rejects(f.run(u, u.begun, { concurrency: 1 }), 'part_budget_exhausted');
  assert.equal(sends(), afterFirst, 'restarts send nothing more for an exhausted part');
  const cp = JSON.parse(readFileSync(u.cp, 'utf8')) as MultipartCheckpoint;
  assert.deepEqual(cp.parts.map(p => p.attempts), [1, MAX_PART_ATTEMPTS, 0]);
  // A failed checkpoint write before a send means no send.
  const g = await fixture(), w = await g.prepare();
  await g.run(w, w.begun, { fetchImpl: async (url: string, init: FetchInit) => {
    if ((init.headers as Record<string, string>)['x-mpu-action'] === 'create') { const res = await g.blob.fetch(url, init); writeFileSync(w.cp, 'not json'); return res; }
    return g.blob.fetch(url, init);
  } }).catch(e => assert.equal(e.code, 'checkpoint_invalid'));
  assert.equal(g.ops('upload'), 0);
});

test('parts: a lost part response is re-sent (same bytes); completion uses the latest opaque ETags; concurrency is bounded', async () => {
  const f = await fixture(), u = await f.prepare();
  f.blob.lost.upload = 1;
  let active = 0, peak = 0;
  const fetchImpl = async (url: string, init: FetchInit) => {
    if ((init.headers as Record<string, string>)['x-mpu-action'] !== 'upload') return f.blob.fetch(url, init);
    active++; peak = Math.max(peak, active);
    try { return await f.blob.fetch(url, init); } finally { active--; }
  };
  const out = await f.run(u, u.begun, { fetchImpl });
  assert.equal(out.complete, true);
  assert.equal(f.ops('upload'), 4, 'one part sent twice');
  assert.ok(peak <= MAX_PART_CONCURRENCY);
  assert.equal((await f.att().finalize(jarvis, { id: u.id, etag: out.etag })).state, 'available');
  assert.equal((await f.receive(u.id)).sha256, u.plan.sha256);
});

test('completion (repro): a lost complete response that succeeded is reconciled by finalize HEAD; the client never learned the ETag', async () => {
  const f = await fixture(), u = await f.prepare();
  f.blob.lost.complete = 1;
  await rejects(f.run(u), 'completion_unknown');
  assert.equal((await multipartProgress(u.cp)).phase, 'complete_unknown');
  // The retry finds no session (the earlier completion consumed it).
  await rejects(f.run(u), 'session_gone_check_finalize');
  assert.equal(f.ops('complete'), 2);
  // Wrong completion evidence changes nothing; finalize without evidence uses HEAD (exact size, opaque ETag).
  await rejects(f.att().finalize(jarvis, { id: u.id, etag: '"not-the-etag"' }), 'attachment_upload_mismatch');
  assert.equal(f.record(u.id).state, 'reserved');
  assert.equal((await f.att().finalize(jarvis, { id: u.id })).state, 'available');
  // HEAD is not content proof: the recipient's SHA-256 decides.
  assert.equal((await f.receive(u.id)).sha256, u.plan.sha256);
  // Retries of an unknown completion are bounded.
  const g = await fixture(), w = await g.prepare();
  g.blob.faults.complete = () => new Response('{"error":{"code":"internal_server_error"}}', { status: 500 });
  for (let i = 0; i < 3; i++) await rejects(g.run(w), 'completion_unknown');
  await rejects(g.run(w), 'completion_unknown');
  assert.equal(g.ops('complete'), 3);
});

test('finalize: late HEAD results after a lease takeover never undo newer state; every HEAD is charged before it is made', async () => {
  const f = await fixture(), u = await f.prepare();
  await f.run(u);
  const object = f.blob.objects.get('att/' + u.id);
  // Finalize A sees nothing yet and is held; B takes over after the lease; the object then appears.
  f.blob.objects.delete('att/' + u.id);
  let releaseA;
  const heldA = new Promise(resolve => { releaseA = resolve; });
  f.hooks.head = () => heldA;
  const a = f.att().finalize(jarvis, { id: u.id });
  await new Promise(r => setTimeout(r, 10));
  f.hooks.head = null;
  f.advance(FINALIZE_LEASE_MS + 1);
  f.blob.objects.set('att/' + u.id, object!);
  assert.equal((await f.att().finalize(jarvis, { id: u.id })).state, 'available', 'B');
  releaseA!();
  assert.equal((await a).state, 'available', 'A, late, reports the newer state and does not undo it');
  // A stale caller may observe the newer state, but must not receive success
  // after its own authority expired while HEAD was in flight.
  const expired = await fixture(), z = await expired.prepare();
  await expired.run(z);
  let releaseExpired;
  const heldExpired = new Promise(resolve => { releaseExpired = resolve; });
  expired.hooks.head = () => heldExpired;
  const stale = expired.att().finalize(who('jarvis', start + FINALIZE_LEASE_MS), { id: z.id });
  await new Promise(r => setTimeout(r, 10));
  expired.hooks.head = null;
  expired.advance(FINALIZE_LEASE_MS + 1);
  assert.equal((await expired.att().finalize(who('jarvis', start + HOUR), { id: z.id })).state, 'available');
  releaseExpired!();
  await rejects(stale, 'attachment_authorization_inactive');
  // An exact HEAD seen by a superseded finalize is still accepted (an uncertain completion landed late).
  const g = await fixture(), w = await g.prepare();
  await g.run(w);
  let releaseC;
  const heldC = new Promise(resolve => { releaseC = resolve; });
  g.hooks.head = () => heldC;
  const c = g.att().finalize(jarvis, { id: w.id });
  await new Promise(r => setTimeout(r, 10));
  g.hooks.head = null;
  g.advance(FINALIZE_LEASE_MS + 1);
  g.blob.faults.head = () => new Error('unavailable');
  await rejects(g.att().finalize(jarvis, { id: w.id }), 'attachment_provider_unavailable');
  g.blob.faults.head = null;
  releaseC!();
  assert.equal((await c).state, 'available');
  // HEAD accounting: each attempt charged; bounded.
  const h = await fixture(), x = await h.prepare();
  h.blob.faults.head = () => new Error('unavailable');
  let attempts = 0;
  for (; attempts < MAX_HEAD_CALLS; attempts++) {
    h.advance(MINUTE);
    await rejects(h.att().finalize(jarvis, { id: x.id }), 'attachment_provider_unavailable');
    assert.equal(h.blob.calls.filter(k => k.op === 'head').length, h.record(x.id).issued.head);
  }
  await rejects(h.att().finalize(jarvis, { id: x.id }), 'attachment_issue_budget_exhausted');
  assert.equal(h.blob.calls.filter(k => k.op === 'head').length, MAX_HEAD_CALLS);
});

test('integrity: a wrong-size object is rejected (store stays valid); same-size corrupted bytes pass HEAD but fail the recipient SHA-256', async () => {
  const f = await fixture(), u = await f.prepare();
  f.blob.objects.set('att/' + u.id, { body: Buffer.alloc(10), size: 10, etag: '"short"' });
  await rejects(f.att().finalize(jarvis, { id: u.id }), 'attachment_verification_failed');
  assert.equal(f.record(u.id).state, 'rejected');
  const other = await f.prepare();
  assert.equal(other.begun.state, 'reserved', 'other reservations still work');
  // Same size, different bytes: available by HEAD, never published by the recipient.
  await f.run(other);
  const object = f.blob.objects.get('att/' + other.id);
  object!.body = Buffer.from(object!.body!); object!.body[PART + 7]! ^= 1;
  assert.equal((await f.att().finalize(jarvis, { id: other.id })).state, 'available');
  await assert.rejects(f.receive(other.id, 'corrupt.bin'), /sha256_mismatch/);
  assert.equal(readdirSync(f.dir).includes('corrupt.bin'), false);
});

test('client: a changed source fails closed (source_changed) and records nothing', async () => {
  const f = await fixture(), u = await f.prepare();
  const fd = openSync(u.src, 'r+'), changed = Buffer.alloc(1);
  readSync(fd, changed, 0, 1, 5); changed[0]! ^= 0xff;
  writeSync(fd, changed, 0, 1, 5); closeSync(fd);
  await rejects(f.run(u), 'source_changed');
  const cp = JSON.parse(readFileSync(u.cp, 'utf8')) as MultipartCheckpoint;
  assert.deepEqual(cp.parts.map(p => p.etag), [null, null, null]);
  assert.equal(f.ops('upload'), 0, 'nothing sent from a changed source');
  // Changed while sending: detected after the bytes go; nothing recorded.
  const g = await fixture(), w = await g.prepare();
  let touched = false;
  const fetchImpl = async (url: string, init: FetchInit) => {
    if ((init.headers as Record<string, string>)['x-mpu-action'] === 'upload' && !touched) {
      touched = true;
      const reader = (init.body as ReadableStream<Uint8Array>).getReader(), chunks = [];
      for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value);
        if (chunks.length === 1) { const d = openSync(w.src, 'r+'); writeSync(d, Buffer.alloc(1024, 9), 0, 1024, 8 * MIB); closeSync(d); } }
      return g.blob.fetch(url, { ...init, body: Buffer.concat(chunks) });
    }
    return g.blob.fetch(url, init);
  };
  await rejects(g.run(w, w.begun, { fetchImpl, concurrency: 1 }), 'source_changed');
  assert.ok((JSON.parse(readFileSync(w.cp, 'utf8')) as MultipartCheckpoint).parts.every(p => p.etag === null));
});

test('downloads: if storage ignores Range or If-Match, nothing unverified is appended; a whole download still verifies SHA-256', async () => {
  for (const blobOptions of [{ rangeSupport: false }, { ifMatchSupport: false, etagHeader: false }]) {
    const f = await fixture({ blobOptions }), u = await f.prepare();
    await f.run(u); await f.att().finalize(jarvis, { id: u.id });
    const m = f.message({ attachmentIds: [u.id] }); await f.bridge.sendMessage(jarvis, m);
    const dest = path.join(f.dir, 'out.bin');
    const ranged = await f.att().download(friday, { messageId: m.id, attachmentId: u.id, rangeStart: 0, rangeEnd: PART - 1 });
    await assert.rejects(downloadFile(ranged, dest, { fetchImpl: f.blob.fetch, now: f.clock }), /range_not_honored|object_changed/);
    assert.equal(existsSync(dest), false);
    const whole = await f.att().download(friday, { messageId: m.id, attachmentId: u.id });
    const out = await downloadFile(whole, path.join(f.dir, 'whole.bin'), { fetchImpl: f.blob.fetch, now: f.clock });
    assert.equal(out.sha256, u.plan.sha256);
  }
});

test('SDK boundary: URLs signed by the real @vercel/blob 2.8.2 presignUrl satisfy this verifier and the client checks (no network)', async () => {
  const clock = Date.now, blob = createFakeBlob({ storeId: FAKE.BLOB_STORE_ID, clock });
  const provider = createBlobProvider({ config: attachmentConfig(FAKE), clock, sdk: { ...blob.sdk, presignUrl: realPresignUrl } as unknown as BlobSdk });
  const key = 'att/' + randomUUID(), body = Buffer.from('signed by the real SDK');
  const up = await provider.presignUpload({ key, size: body.length, validUntil: clock() + 5 * MINUTE });
  assert.equal((await blob.fetch(up.url, { method: 'PUT', headers: up.headers, body })).status, 200);
  const tampered = new URL(up.url); tampered.searchParams.set('vercel-blob-maximum-size-in-bytes', '999999');
  assert.equal((await blob.fetch(tampered.href, { method: 'PUT', headers: up.headers, body })).status, 403);
  const create = await blob.fetch(up.multipartUrl, { method: 'POST', headers: { ...up.headers, 'x-mpu-action': 'create' } });
  assert.equal(create.status, 400, 'no overwrite of the existing pathname, also for a new session');
  const get = await provider.presignGet({ key, validUntil: clock() + 5 * MINUTE });
  const res = await blob.fetch(get.url);
  assert.equal(res.status, 200); assert.equal(Buffer.from(await res.arrayBuffer()).toString(), body.toString());
});

test('limits: decimal 500 MB default and 1 GB hard cap for multipart; part counts bounded by the helper', async () => {
  const f = await fixture();
  await rejects(f.att().begin(jarvis, { name: 'x', size: 500000001, sha256: 'a'.repeat(64), mode: 'multipart' }), 'attachment_too_large');
  const g = await fixture({ env: { ...FAKE, BRIDGE_ATTACHMENT_MAX_BYTES: '1000000000' } });
  assert.equal((await g.att().begin(jarvis, { name: 'x', size: MAX_ATTACHMENT_BYTES, sha256: 'a'.repeat(64), mode: 'multipart' })).mode, 'multipart');
  await rejects(g.att().begin(jarvis, { name: 'x', size: MAX_ATTACHMENT_BYTES + 1, sha256: 'a'.repeat(64), mode: 'multipart' }), 'attachment_too_large');
  const small = path.join(f.dir, 'small.bin'); writeFileSync(small, randomBytes(1000));
  await assert.rejects(planMultipart(small), /multipart_part_count_invalid/);
  await assert.rejects(planMultipart(small, { partSize: 5 * MIB }), /invalid_part_size/);
  // Single and multipart reservations are distinct identities.
  const d = await describeFile(small);
  const single = await f.att().begin(jarvis, { name: 's', ...d });
  await rejects(f.att().begin(jarvis, { name: 's', ...d, id: single.attachmentId, mode: 'multipart' }), 'attachment_id_conflict');
  assert.equal(single.upload!.multipartUrl, undefined, 'a single reservation gets no multipart URL');
  await uploadFile(small, single, d, { fetchImpl: f.blob.fetch, now: f.clock });
});

test('streaming at the 1 GB cap: 15 native parts of 64 MiB uploaded and completed without buffering the payload', async () => {
  const f = await fixture({ env: { ...FAKE, BRIDGE_ATTACHMENT_MAX_BYTES: '1000000000' }, lean: true });
  const src = path.join(f.dir, 'zeros.bin'); writeFileSync(src, ''); truncateSync(src, MAX_ATTACHMENT_BYTES);
  const baseline = process.memoryUsage().rss; let peak = baseline;
  const sample = setInterval(() => { peak = Math.max(peak, process.memoryUsage().rss); }, 20);
  try {
    const plan = await planMultipart(src);
    assert.deepEqual([plan.parts.length, plan.parts.at(-1)!.size], [15, MAX_ATTACHMENT_BYTES - 14 * 64 * MIB]);
    const begun = await f.att().begin(jarvis, { name: 'zeros.bin', size: plan.size, sha256: plan.sha256, mode: 'multipart' });
    const cp = path.join(f.dir, 'zeros.checkpoint.json');
    await createCheckpoint(cp, { attachmentId: begun.attachmentId, plan });
    const out = await uploadMultipart(cp, begun, { fetchImpl: f.blob.fetch, now: f.clock });
    assert.equal(out.complete, true);
    assert.equal(f.blob.objects.get('att/' + begun.attachmentId)!.size, MAX_ATTACHMENT_BYTES);
    assert.equal((await f.att().finalize(jarvis, { id: begun.attachmentId, etag: out.etag })).state, 'available');
  } finally { clearInterval(sample); }
  assert.ok(peak - baseline < 400 * 1024 * 1024, `RSS grew ${(peak - baseline) / 1e6} MB`);
  rmSync(f.dir, { recursive: true, force: true });
});
