import { createReadStream, promises as fs, constants as fsc } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import path from 'node:path';

// Small Node helper for bridge attachments (private Vercel Blob). It talks
// only to the URLs in a grant the caller got from its own bridge session,
// checks that each URL is exactly the private artifact capability expected
// (host, path, pathname, size, flags), sends no credentials, refuses
// redirects and content encodings, bounds every transfer in bytes and time,
// and never takes a path or name from remote metadata. Bytes go to disk,
// never to a model's context. Nothing is opened, rendered, extracted or
// executed.
//
// Uploads: one PUT, or the provider's native multipart upload driven from a
// local checkpoint (see "Multipart uploads" below). Downloads accumulate in a
// quarantined partial file next to the caller-chosen destination, bound to
// one attachment, message, size, SHA-256 and opaque ETag, and resume by exact
// byte range across calls (and wakes); the destination appears only after the
// whole size and SHA-256 match, and an existing destination is never
// replaced; what appears there is a private snapshot whose bytes were hashed
// as they were written, never the shared partial file. Provider ETags are
// opaque: compared for equality only, never treated as content proof.
import { checkUploadUrl, checkGetUrl, uploadHeaders, OPAQUE_ETAG } from './blob.ts';
import type { BigIntStats, Stats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';

// Parameter types document the bridge grant / checkpoint contracts; every
// value is still checked at runtime (callers may be plain JavaScript).
export type FetchInit = RequestInit & { duplex?: 'half' };
export type FetchImpl = (url: string, init: FetchInit) => Promise<Response>;
export interface TransferOptions { signal?: AbortSignal | undefined; timeoutMs?: number; fetchImpl?: FetchImpl; now?: () => number }
export interface MultipartOptions extends TransferOptions { allowNewSession?: boolean; concurrency?: number; partSize?: number }
export interface FileDigest { size: number; sha256: string }
/** File identity as decimal strings (dev, inode, size, mtime in ns). */
export interface FileIdentity { dev: string; ino: string; size: string; mtimeNs: string }
/** The result of bridge_attachment_begin. */
export interface UploadBegun {
  attachmentId?: string; size?: number; sha256?: string; mode?: string;
  upload?: { method: string; url: string; multipartUrl?: string | undefined; headers: Record<string, string>; expiresAt: string };
}
/** The result of bridge_attachment_download (or the same metadata fields for resumeOffset). */
export interface DownloadGrant {
  attachmentId: string; messageId: string; size: number; sha256: string;
  download?: { method: string; url: string; headers: Record<string, string | null | undefined>; expiresAt: string; range?: { start: number; end: number } | undefined };
}
/** Non-secret identity from the referencing message and finalized metadata. */
export interface AttachmentRequest { attachmentId: string; messageId: string; size: number; sha256: string }
export interface DownloadRequest { attachmentId: string; messageId: string; rangeStart?: number; rangeEnd?: number }
/** Host-owned authenticated MCP binding. It must not log/serialize the returned capability. */
export type AcquireDownload = (request: DownloadRequest, options: { signal: AbortSignal }) => Promise<DownloadGrant>;
export interface ConsumerOptions extends TransferOptions { chunkBytes?: number; maxBytes?: number }
export interface ConsumerResult extends AttachmentRequest { disposition: 'partial' | 'verified'; received: number }
/** What partial download bytes belong to (the .part.json file). */
export interface PartialBinding { v: number; attachmentId: string; messageId: string; size: number; sha256: string; etag?: string }
export interface PartialPaths { data: string; meta: string }
/** A bounded provider JSON response. */
interface ProviderResult {
  ok: boolean; status: number; code: string | null;
  body: { pathname?: unknown; etag?: string; key?: string; uploadId?: string; error?: { code?: unknown } } | null;
}
export interface MultipartPlan {
  size: number; sha256: string; partSize: number; parts: FileDigest[]; source: { path: string } & FileIdentity;
}
/** The local multipart checkpoint (v2), validated on every read and write. */
export interface MultipartCheckpoint {
  v: 2; attachmentId: string; source: { path: string } & FileIdentity; size: number; sha256: string; partSize: number;
  parts: { sha256: string; etag: string | null; attempts: number }[]; phase: string;
  session: { key: string; uploadId: string } | null; creates: number; completes: number; abandoned: number;
  result: { etag: string } | null;
}

export const MAX_ATTACHMENT_BYTES = 1000000000;   // hard cap, decimal bytes
export const MAX_TRANSFER_MS = 3600000;          // default and maximum per transfer
export class AttachmentClientError extends Error {
  declare code: string;
  constructor(code: string) { super(code); this.code = code; }
}
// Explicitly typed so a bare fail(...) statement narrows control flow.
const fail: (code: string) => never = code => { throw new AttachmentClientError(code); };
const SHA256 = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const UUID_V4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const RANGE = /^bytes=(0|[1-9][0-9]{0,9})-(0|[1-9][0-9]{0,9})$/;
const STORE_HOST = /^([a-z0-9]{8,64})\.private\.blob\.vercel-storage\.com$/;
const validSize = (size: unknown): size is number => Number.isSafeInteger(size) && (size as number) >= 1 && (size as number) <= MAX_ATTACHMENT_BYTES;
const MIB = 1024 * 1024;
const identity = (info: Pick<BigIntStats, 'dev' | 'ino' | 'size' | 'mtimeNs'> | FileIdentity): FileIdentity => ({ dev: String(info.dev), ino: String(info.ino), size: String(info.size), mtimeNs: String(info.mtimeNs) });
const sameIdentity = (a: FileIdentity, b: FileIdentity): boolean => a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeNs === b.mtimeNs;

// One deadline for the whole transfer: the caller's signal or the timeout.
/** @param {{ signal?: AbortSignal, timeoutMs?: number }} [options] */
function deadline({ signal, timeoutMs = MAX_TRANSFER_MS }: TransferOptions = {}): AbortSignal {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TRANSFER_MS) fail('invalid_timeout');
  const timer = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, timer]) : timer;
}
const abortCode = (signal: AbortSignal): string => signal.reason?.name === 'TimeoutError' ? 'transfer_timeout' : 'transfer_aborted';
// Run `start` (a function returning the work) unless the deadline has already
// passed, then settle with the work or the deadline, whichever comes first,
// even if the underlying fetch or stream ignores the signal. The abort
// listener is installed before `start` runs, so an abort during startup
// (even a synchronous one) is never missed; the work's own settlement is
// always observed, so a late rejection is never unhandled.
function bounded<T>(start: () => T | PromiseLike<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new AttachmentClientError(abortCode(signal)));
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = <V>(settle: (value: V) => void, value: V): void => {
      if (settled) return;
      settled = true; signal.removeEventListener('abort', onAbort); settle(value);
    };
    const onAbort = () => finish(reject, new AttachmentClientError(abortCode(signal)));
    signal.addEventListener('abort', onAbort, { once: true });
    let work: Promise<T>;
    try { work = Promise.resolve(start()); } catch (error) { finish(reject, error); return; }
    work.then(value => finish(resolve, value), error => finish(reject, error));
    if (signal.aborted) onAbort();
  });
}

// Size and SHA-256 (hex) of a regular file.
// Reads at most the size seen at the start; a file that changes while being
// read (grows, shrinks or is replaced) is refused.
export async function describeFile(filePath: string, options: TransferOptions = {}): Promise<FileDigest> {
  const signal = deadline(options);
  const info = await fs.lstat(filePath);
  if (!info.isFile()) fail('not_a_regular_file');
  if (!validSize(info.size)) fail('attachment_size_out_of_range');
  const stream = createReadStream(filePath, { start: 0, end: info.size - 1 });
  let digest: FileDigest;
  try { digest = await hashStream(stream, info.size, signal); } finally { stream.destroy(); }
  const after = await fs.lstat(filePath);
  if (after.size !== info.size || after.mtimeMs !== info.mtimeMs || after.ino !== info.ino) fail('file_changed_while_reading');
  return digest;
}
// Hash exactly `size` bytes from a Node readable: more or fewer is refused,
// and reading stops at the first byte past the bound.
export async function hashStream(readable: Readable, size: number, signal = deadline()): Promise<FileDigest> {
  const sha256 = createHash('sha256');
  const reader = Readable.toWeb(readable).getReader();
  let count = 0;
  try {
    for (;;) {
      const { done, value } = await bounded(() => reader.read(), signal);
      if (done) break;
      count += value.length;
      if (count > size) fail('file_changed_while_reading');
      sha256.update(value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  if (count !== size) fail('file_changed_while_reading');
  return { size, sha256: sha256.digest('hex') };
}

// Grant URLs must be exactly the expected private artifact capability.
// The store comes from the GET host, or (uploads) from the delegation's own
// public payload, and must match the store header the client is told to send.
function delegationStore(url: string): string | null {
  const delegation = new URL(url).searchParams.get('vercel-blob-delegation') || '';
  try {
    const payload = JSON.parse(Buffer.from(delegation.slice(0, delegation.indexOf('.')), 'base64url').toString('utf8'));
    return typeof payload?.storeId === 'string' ? payload.storeId.replace(/^store_/, '') : null;
  } catch { return null; }
}
function checkUpload(value: unknown, key: string, size: number, multipart: boolean): string {
  if (typeof value !== 'string' || !checkUploadUrl(value, { key, size, multipart })) fail('invalid_grant');
  return value;
}
function checkGet(value: unknown, key: string): string {
  let url: URL;
  try { url = new URL(value as string); } catch { fail('invalid_grant'); }
  const store = STORE_HOST.exec(url.hostname)?.[1];
  if (!store || !checkGetUrl(value as string, { key, storeId: store })) fail('invalid_grant');
  return url.href;
}
const keyOf = (attachmentId: string): string => 'att/' + attachmentId;
function exactHeaders(headers: unknown, wanted: Record<string, string>): void {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) fail('invalid_grant');
  const keys = Object.keys(headers).sort(), want = Object.keys(wanted).sort();
  if (keys.length !== want.length || keys.some((k, n) => k !== want[n] || (headers as Record<string, unknown>)[k] !== wanted[k])) fail('invalid_grant');
}
function checkExpiry(expiresAt: unknown, now: () => number): void {
  // Date.parse coerces a non-string; the typeof check below refuses it.
  const at = Date.parse(expiresAt as string);
  if (typeof expiresAt !== 'string' || !Number.isSafeInteger(at)) fail('invalid_grant');
  if (at <= now()) fail('grant_expired');
}

async function send(fetchImpl: FetchImpl, url: string, init: FetchInit, signal: AbortSignal): Promise<Response> {
  let response: Response;
  try { response = await bounded(() => fetchImpl(url, { ...init, redirect: 'manual', signal }), signal); }
  catch (error) { if (error instanceof AttachmentClientError) throw error; fail('transfer_failed'); }
  if (response.status >= 300 && response.status < 400) { await response.body?.cancel().catch(() => {}); fail('redirect_refused'); }
  return response;
}

// The upload capability from bridge_attachment_begin, checked exactly:
// attachment pathname, mode, size, SHA-256, flags, store and the SDK's
// request headers.
function checkUploadGrant(begun: UploadBegun | null | undefined, expected: FileDigest, multipart: boolean):
  { url: string; key: string; store: string; headers: Record<string, string> } {
  const grant = begun?.upload;
  if (!UUID_V4.test(begun?.attachmentId || '') || grant?.method !== 'PUT' || begun!.size !== expected.size ||
      begun!.sha256 !== expected.sha256 || begun!.mode !== (multipart ? 'multipart' : 'single')) fail('invalid_grant');
  const key = keyOf(begun!.attachmentId!); // Checked above, with the grant.
  const url = checkUpload(grant.url, key, expected.size, false);
  const store = delegationStore(url);
  if (!store || !/^[A-Za-z0-9]{8,64}$/.test(store)) fail('invalid_grant');
  exactHeaders(grant.headers, uploadHeaders(store));
  if (multipart) {
    checkUpload(grant.multipartUrl, key, expected.size, true);
    if (delegationStore(grant.multipartUrl as string) !== store) fail('invalid_grant');
  } else if (grant.multipartUrl !== undefined) fail('invalid_grant');
  return { url, key, store, headers: { ...grant.headers } };
}
// A provider JSON response, bounded; { ok, status, body, code }.
async function providerJson(response: Response): Promise<ProviderResult> {
  const reader = response.body?.getReader(), chunks: Buffer[] = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 64 * 1024) { reader.cancel().catch(() => {}); return { ok: false, status: response.status, body: null, code: 'oversized' }; }
      chunks.push(Buffer.from(value));
    }
  }
  let body = null;
  try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { body = null; }
  const code = typeof body?.error?.code === 'string' ? body.error.code : null;
  return { ok: response.status >= 200 && response.status < 300 && body !== null && code === null, status: response.status, body, code };
}

// PUT the file with the result of bridge_attachment_begin (mode single).
// `expected` is the describeFile result used for that begin; at most
// expected.size bytes are sent. One request, no resume: a failed upload
// restarts with a fresh capability (up to five per attachment). The response
// must name this pathname and carry an opaque ETag; pass it to
// bridge_attachment_finalize as completion evidence.
export async function uploadFile(filePath: string, begun: UploadBegun | null | undefined, expected: FileDigest | null | undefined,
  options: TransferOptions = {}): Promise<{ status: number; etag: string }> {
  const { fetchImpl = fetch, now = Date.now } = options;
  if (!expected || !validSize(expected.size) || !SHA256.test(expected.sha256 || '')) fail('invalid_expected');
  const { url, key, headers } = checkUploadGrant(begun, expected, false);
  checkExpiry(begun!.upload!.expiresAt, now); // checkUploadGrant accepted begun.
  const signal = deadline(options);
  let handle!: FileHandle, body: ReadableStream<Uint8Array> | undefined;
  try { handle = await fs.open(filePath, fsc.O_RDONLY | fsc.O_NOFOLLOW); } catch { fail('file_changed_while_reading'); }
  try {
    const info = await handle.stat({ bigint: true }), named = await fs.lstat(filePath, { bigint: true }).catch(() => null);
    if (!info.isFile() || Number(info.size) !== expected.size || !named ||
        !sameIdentity(identity(info), identity(named))) fail('file_changed_while_reading');
    const buffer = Buffer.allocUnsafe(Math.min(MIB, expected.size)), sha256 = createHash('sha256');
    let sent = 0;
    body = new ReadableStream<Uint8Array>({ async pull(controller) {
      if (sent >= expected.size) { controller.close(); return; }
      let read;
      try { read = await bounded(() => handle.read(buffer, 0, Math.min(buffer.length, expected.size - sent), sent), signal); }
      catch (error) { controller.error(error); return; }
      if (!(read.bytesRead > 0)) { controller.error(new AttachmentClientError('file_changed_while_reading')); return; }
      const chunk = Buffer.from(buffer.subarray(0, read.bytesRead));
      sha256.update(chunk); sent += read.bytesRead; controller.enqueue(chunk);
    } });
    const response = await send(fetchImpl, url, { method: 'PUT', headers: { ...headers, 'content-length': String(expected.size) },
      body, duplex: 'half' }, signal);
    const out = await bounded(() => providerJson(response), signal);
    if (!out.ok) fail(out.status >= 400 && out.status < 500 ? 'upload_rejected' : 'upload_outcome_unknown');
    // ok implies a parsed body.
    if (out.body!.pathname !== key || !OPAQUE_ETAG.test(out.body!.etag || '')) fail('upload_outcome_unknown');
    const after = await handle.stat({ bigint: true }).catch(() => null), current = await fs.lstat(filePath, { bigint: true }).catch(() => null);
    if (sent !== expected.size || !after || !current || !sameIdentity(identity(info), identity(after)) ||
        !sameIdentity(identity(info), identity(current)) || sha256.digest('hex') !== expected.sha256) fail('file_changed_while_reading');
    return { status: out.status, etag: out.body!.etag as string };
  } finally {
    await body?.cancel().catch(() => {});
    await handle.close().catch(() => {});
  }
}

// Write a whole chunk (at `position` in the file when given), looping over
// partial writes; no progress is an error.
export async function writeFully(handle: FileHandle, chunk: Uint8Array, signal: AbortSignal, position?: number): Promise<void> {
  let offset = 0;
  while (offset < chunk.length) {
    const at = position === undefined ? null : position + offset;
    const { bytesWritten } = await bounded(() => handle.write(chunk, offset, chunk.length - offset, at), signal);
    if (!Number.isSafeInteger(bytesWritten) || bytesWritten <= 0) fail('write_stalled');
    offset += bytesWritten;
  }
}

// --- Downloads: resumable by exact byte range -----------------------------------
// Partial state lives beside the destination, dot-prefixed (quarantined):
//   .<name>.<attachmentId>.part       the bytes received so far, in order
//   .<name>.<attachmentId>.part.json  what they belong to (binding below)
// Both are created exclusively with mode 0600 and never followed as symlinks.
export function partialPaths(destinationPath: string, attachmentId: string | undefined): PartialPaths {
  if (typeof destinationPath !== 'string' || !path.isAbsolute(destinationPath)) fail('destination_must_be_absolute');
  if (!UUID_V4.test(attachmentId || '')) fail('invalid_grant');
  const dir = path.dirname(destinationPath), base = path.basename(destinationPath);
  return { data: path.join(dir, `.${base}.${attachmentId}.part`), meta: path.join(dir, `.${base}.${attachmentId}.part.json`) };
}
const missing = (error: unknown): boolean => (error as { code?: unknown } | null | undefined)?.code === 'ENOENT';
const BINDING: (keyof PartialBinding)[] = ['v', 'attachmentId', 'messageId', 'size', 'sha256', 'etag'];
const ETAG = OPAQUE_ETAG;
async function readBinding(file: string): Promise<PartialBinding | null> {
  let handle: FileHandle;
  try { handle = await fs.open(file, fsc.O_RDONLY | fsc.O_NOFOLLOW); } catch (error) { if (missing(error)) return null; fail('partial_mismatch'); }
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > 1024) fail('partial_mismatch');
    const value = JSON.parse(await handle.readFile('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join() !== [...BINDING].sort().join()) fail('partial_mismatch');
    return value;
  } catch (error) { if (error instanceof AttachmentClientError) throw error; fail('partial_mismatch'); }
  finally { await handle.close().catch(() => {}); }
}
// Current partial state for this attachment and message: the byte count to
// resume from, or 0. Partial bytes that belong to anything else (another
// message, size, SHA-256 or object version), or an orphaned or non-regular
// file, are refused with partial_mismatch, never reused; discardPartial
// removes them.
async function partialState(paths: PartialPaths, expect: PartialBinding):
  Promise<{ offset: number; binding: PartialBinding | null; exists: boolean }> {
  const binding = await readBinding(paths.meta);
  let info: Stats | null = null;
  try { info = await fs.lstat(paths.data); } catch (error) { if (!missing(error)) throw error; }
  if (!binding) { if (info) fail('partial_mismatch'); return { offset: 0, binding: null, exists: false }; }
  for (const key of BINDING) {
    if (key === 'etag' && expect.etag === undefined) continue;
    if (binding[key] !== expect[key]) fail('partial_mismatch');
  }
  if (info && (!info.isFile() || info.size > expect.size)) fail('partial_mismatch');
  return { offset: info ? info.size : 0, binding, exists: !!info };
}
function expectation(download: DownloadGrant | null | undefined, etag?: string): PartialBinding {
  const { attachmentId, messageId, size, sha256 } = download || {} as Partial<DownloadGrant>;
  if (!UUID_V4.test(attachmentId || '') || !UUID.test(messageId || '') || !validSize(size) || !SHA256.test(sha256 || '')) fail('invalid_grant');
  // Each field was checked above.
  return { v: 1, attachmentId: attachmentId as string, messageId: messageId as string, size, sha256: sha256 as string,
    ...(etag !== undefined ? { etag } : {}) };
}
// Where to resume: pass this as rangeStart to bridge_attachment_download.
// `download` needs attachmentId, messageId, size and sha256 (from an earlier
// grant for this attachment, or the same fields from the message context).
export async function resumeOffset(destinationPath: string, download: DownloadGrant | null | undefined): Promise<number> {
  return (await partialState(partialPaths(destinationPath, download?.attachmentId), expectation(download))).offset;
}
export async function discardPartial(destinationPath: string, attachmentId: string): Promise<void> {
  const paths = partialPaths(destinationPath, attachmentId);
  await fs.unlink(paths.data).catch(error => { if (!missing(error)) throw error; });
  await fs.unlink(paths.meta).catch(error => { if (!missing(error)) throw error; });
}
// The grant must be complete and exact: the bridge's metadata, a GET pinned
// to one ETag, and either the whole object or one byte range.
function checkDownloadGrant(download: DownloadGrant | null | undefined) {
  const grant = download?.download;
  if (grant?.method !== 'GET' || !grant.headers || typeof grant.headers !== 'object') fail('invalid_grant');
  const etag = grant.headers['if-match'];
  if (!ETAG.test(etag || '')) fail('invalid_grant');
  const expect = expectation(download, etag as string); // Matched the ETag pattern above.
  const url = checkGet(grant.url, keyOf(expect.attachmentId));
  let start = 0, end = expect.size - 1, ranged = false;
  if (grant.headers.range !== undefined) {
    const m = RANGE.exec(grant.headers.range || '');
    if (!m) fail('invalid_grant');
    [start, end, ranged] = [Number(m![1]), Number(m![2]), true];
    if (start > end || end >= expect.size || grant.range?.start !== start || grant.range?.end !== end) fail('invalid_grant');
  } else if (grant.range !== undefined) fail('invalid_grant');
  // Both checked above (ETag pattern; Range pattern when ranged).
  exactHeaders(grant.headers, { 'if-match': etag as string, ...(ranged ? { range: grant.headers.range as string } : {}) });
  return { url, expect, start, end, ranged };
}
// Publication never trusts the shared partial file or a hash of the incoming
// stream. The bytes are copied from this call's own open handle into a new,
// exclusively created snapshot; exactly the buffers written to it are hashed;
// only a snapshot whose SHA-256 and size match is synced, closed and linked to
// the destination. No other writer ever holds a descriptor to that inode, so
// a concurrent or stale writer on the partial cannot change what is
// published: at worst the check fails and nothing is published.
async function publishVerified(file: FileHandle, paths: PartialPaths, expect: PartialBinding, destinationPath: string,
  signal: AbortSignal): Promise<boolean> {
  const snapshot = path.join(path.dirname(paths.data), `.${path.basename(destinationPath)}.${expect.attachmentId}.${randomBytes(8).toString('hex')}.verify`);
  const out = await fs.open(snapshot, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600);
  let linked = false;
  try {
    const hash = createHash('sha256'), buffer = Buffer.allocUnsafe(Math.min(1 << 20, expect.size));
    let position = 0;
    while (position < expect.size) {
      const { bytesRead } = await bounded(() => file.read(buffer, 0, Math.min(buffer.length, expect.size - position), position), signal);
      if (!(bytesRead > 0)) fail('sha256_mismatch');
      const chunk = buffer.subarray(0, bytesRead);
      await writeFully(out, chunk, signal, position);
      hash.update(chunk); position += bytesRead;
    }
    if (hash.digest('hex') !== expect.sha256) fail('sha256_mismatch');
    await out.sync(); await out.close();
    const info = await fs.lstat(snapshot);
    if (!info.isFile() || info.size !== expect.size) fail('sha256_mismatch');
    // link() fails if the destination now exists: never clobber, even on a race.
    try { await fs.link(snapshot, destinationPath); linked = true; } catch (error) { fail((error as { code?: unknown } | null | undefined)?.code === 'EEXIST' ? 'destination_exists' : 'publish_failed'); }
  } finally {
    await out.close().catch(() => {});
    await fs.unlink(snapshot).catch(() => {});
  }
  return linked;
}
// Remove partial state only if the data file is still this call's own inode,
// so one writer never deletes another writer's newer state.
async function discardOwn(paths: PartialPaths, identity: { ino: number; dev: number }): Promise<void> {
  let info: Stats | null = null;
  try { info = await fs.lstat(paths.data); } catch (error) { if (!missing(error)) return; }
  if (info && (info.ino !== identity.ino || info.dev !== identity.dev)) return;
  await fs.unlink(paths.data).catch(() => {});
  await fs.unlink(paths.meta).catch(() => {});
}
// Errors after which the partial bytes cannot be trusted at all.
const DISCARD_ALL = ['sha256_mismatch', 'object_changed'];
// Errors from a response that broke the grant's contract: this attempt's
// bytes are dropped, earlier (already ordered and bounded) bytes are kept.
const DISCARD_ATTEMPT = ['size_mismatch', 'content_range_mismatch', 'unexpected_content_encoding'];

// GET with the result of bridge_attachment_download into destinationPath
// (absolute, caller-chosen, must not exist). The grant must start where the
// partial state ends (resumeOffset); an interrupted transfer (network error,
// timeout, abort, early end of stream, refused or rate-limited request) keeps
// its progress for a later grant. A grant that ends before the last byte
// returns { complete: false, received }. When the last byte arrives, size and
// SHA-256 of the whole file are checked before it appears at destinationPath.
// If the partial state already holds every byte (the process stopped after
// the last byte but before publishing: resumeOffset equals size), a fresh
// whole-object grant for the same binding finalizes it locally with no
// request: the same verified snapshot, or sha256_mismatch and the bytes are
// discarded.
export async function downloadFile(download: DownloadGrant | null | undefined, destinationPath: string, options: TransferOptions = {}) {
  const { fetchImpl = fetch, now = Date.now } = options;
  const { url, expect, start, end, ranged } = checkDownloadGrant(download);
  const grant = download!.download!; // checkDownloadGrant accepted it.
  checkExpiry(grant.expiresAt, now);
  const paths = partialPaths(destinationPath, expect.attachmentId);
  if (await fs.lstat(destinationPath).then(() => true, () => false)) fail('destination_exists');
  const signal = deadline(options);
  const current = await partialState(paths, expect);
  const finished = current.exists && current.offset === expect.size;
  if (finished ? ranged : current.offset !== start) fail('range_mismatch');
  if (!current.binding) {
    let meta: FileHandle;
    try { meta = await fs.open(paths.meta, 'wx', 0o600); } catch { fail('partial_mismatch'); }
    try { await meta.writeFile(JSON.stringify(expect)); await meta.sync(); } finally { await meta.close(); }
  }
  let file: FileHandle;
  try {
    file = current.exists ? await fs.open(paths.data, fsc.O_RDWR | fsc.O_NOFOLLOW)
      : await fs.open(paths.data, fsc.O_RDWR | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600);
  } catch { fail('partial_mismatch'); }
  let closed = false, reader: ReadableStreamDefaultReader<Uint8Array> | undefined, written = finished ? expect.size : start,
    identity: { ino: number; dev: number } | null = null;
  try {
    const info = await file.stat();
    identity = { ino: info.ino, dev: info.dev };
    if (!info.isFile() || info.size !== (finished ? expect.size : start)) fail('partial_mismatch');
    if (finished) {
      await publishVerified(file, paths, expect, destinationPath, signal);
      await file.close(); closed = true;
      await discardOwn(paths, identity);
      return { complete: true, path: destinationPath, size: expect.size, sha256: expect.sha256 };
    }
    // exactHeaders accepted exactly these string headers.
    const response = await send(fetchImpl, url, { method: 'GET', headers: { ...grant.headers } as Record<string, string> }, signal);
    if (response.status === 412) { await response.body?.cancel().catch(() => {}); fail('object_changed'); }
    // A ranged request answered with the whole object (Range ignored) is
    // refused before any byte is written: never appended, never trusted.
    if (ranged && response.status === 200) { await response.body?.cancel().catch(() => {}); fail('range_not_honored'); }
    if (response.status !== (ranged ? 206 : 200)) { await response.body?.cancel().catch(() => {}); fail('download_rejected'); }
    // The object version must be the recorded one (If-Match may not be
    // enforced by the server): a ranged response must carry exactly that
    // ETag; a whole response, if it carries one, must match it.
    const tag = response.headers.get('etag');
    if (ranged ? tag !== expect.etag : tag !== null && tag !== expect.etag) { await response.body?.cancel().catch(() => {}); fail('object_changed'); }
    const encoding = response.headers.get('content-encoding');
    if (encoding !== null && encoding.toLowerCase() !== 'identity') { await response.body?.cancel().catch(() => {}); fail('unexpected_content_encoding'); }
    const length = end - start + 1, declared = response.headers.get('content-length'), contentRange = response.headers.get('content-range');
    if (ranged ? contentRange !== `bytes ${start}-${end}/${expect.size}` : contentRange !== null) {
      await response.body?.cancel().catch(() => {}); fail('content_range_mismatch');
    }
    if ((declared !== null && declared !== String(length)) || !response.body) { await response.body?.cancel().catch(() => {}); fail('size_mismatch'); }
    reader = response.body.getReader();
    for (;;) {
      const { done, value } = await bounded(() => reader!.read(), signal);
      if (done) break;
      if (written + value.length > end + 1) fail('size_mismatch');
      await writeFully(file, value, signal, written);
      written += value.length;
    }
    if (written !== end + 1) fail('transfer_incomplete');
    await file.sync();
    if (end < expect.size - 1) {
      await file.close(); closed = true;
      return { complete: false, attachmentId: expect.attachmentId, received: written, size: expect.size };
    }
    await publishVerified(file, paths, expect, destinationPath, signal);
    await file.close(); closed = true;
    await discardOwn(paths, identity);
    return { complete: true, path: destinationPath, size: expect.size, sha256: expect.sha256 };
  } catch (error) {
    await reader?.cancel().catch(() => {});
    const code = error instanceof AttachmentClientError ? error.code : 'transfer_failed';
    if (DISCARD_ATTEMPT.includes(code) && !closed) await file.truncate(start).catch(() => {});
    if (!closed) await file.close().catch(() => {});
    // Nothing worth resuming (no byte ever written) leaves nothing behind.
    if (identity && (DISCARD_ALL.includes(code) || (start === 0 && (written === 0 || DISCARD_ATTEMPT.includes(code))))) {
      await discardOwn(paths, identity);
    }
    if (error instanceof AttachmentClientError) throw error;
    fail('transfer_failed');
  }
}

// One bounded recipient-side step. The host supplies its EXISTING authenticated
// binding and a caller-chosen quarantine path; no URL, token, remote filename or
// file bytes cross this interface. Acquisition and streaming share one deadline.
// This deliberately neither claims nor completes a receipt: transport integrity
// and workflow handling are distinct. After a lost lease the host must reconcile
// its existing run / acquire a fresh claim before continuing workflow handling.
export async function consumeAttachment(request: AttachmentRequest, destinationPath: string, acquire: AcquireDownload,
  options: ConsumerOptions = {}): Promise<ConsumerResult> {
  const { chunkBytes = 16 * MIB, maxBytes = 500000000, timeoutMs = 45000, now = Date.now } = options;
  // Validate before filesystem access or authenticated grant acquisition.
  expectation(request);
  if (!validSize(maxBytes) || request.size > maxBytes) fail('consumer_size_limit');
  if (!Number.isSafeInteger(chunkBytes) || chunkBytes < 16 * MIB || chunkBytes > 64 * MIB) fail('invalid_chunk_size');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 55000) fail('invalid_timeout');
  if (typeof acquire !== 'function') fail('grant_unavailable');
  const signal = deadline({ signal: options.signal, timeoutMs });
  try {
    if (signal.aborted) fail(abortCode(signal));
    const offset = await bounded(() => resumeOffset(destinationPath, request), signal);
    if (signal.aborted) fail(abortCode(signal));
    const end = Math.min(offset + chunkBytes, request.size) - 1;
    const ranged = offset < request.size && (offset > 0 || end < request.size - 1);
    // An already-complete partial needs a fresh whole-object binding for local
    // verification only. downloadFile sends no GET in that recovery case.
    const args: DownloadRequest = { attachmentId: request.attachmentId, messageId: request.messageId,
      ...(ranged ? { rangeStart: offset, rangeEnd: end } : {}) };
    let grant: DownloadGrant;
    try { grant = await bounded(() => acquire(args, { signal }), signal); }
    catch { fail(signal.aborted ? abortCode(signal) : 'grant_unavailable'); }
    if (signal.aborted) fail(abortCode(signal));
    // Both the authenticated response and the partial must bind to the exact
    // referencing message / attachment, not merely another valid capability.
    if (grant.attachmentId !== request.attachmentId || grant.messageId !== request.messageId ||
      grant.size !== request.size || grant.sha256 !== request.sha256) fail('grant_binding_mismatch');
    const checked = checkDownloadGrant(grant);
    if (checked.ranged !== ranged || checked.start !== (ranged ? offset : 0) || checked.end !== (ranged ? end : request.size - 1)) fail('range_mismatch');
    const result = await downloadFile(grant, destinationPath, { ...options, now, signal, timeoutMs });
    return { attachmentId: request.attachmentId, messageId: request.messageId, size: request.size, sha256: request.sha256,
      disposition: result.complete ? 'verified' : 'partial', received: result.complete ? request.size : result.received! };
  } catch (error) {
    // A host callback/fetch implementation can throw an Error containing a URL,
    // response body or token. Expose only this static, capability-free vocabulary.
    const safe = ['grant_unavailable', 'grant_binding_mismatch', 'invalid_grant', 'range_mismatch', 'partial_mismatch',
      'destination_exists', 'sha256_mismatch', 'object_changed', 'size_mismatch', 'content_range_mismatch',
      'unexpected_content_encoding', 'transfer_incomplete', 'grant_expired', 'transfer_timeout', 'transfer_aborted'];
    fail(error instanceof AttachmentClientError && safe.includes(error.code) ? error.code : 'transfer_failed');
  }
}

// --- Multipart uploads (native Vercel Blob multipart, client-driven) -----------
// The provider has no "list parts" or "list sessions": this local checkpoint
// is the authoritative record of the CLIENT's progress, and each step is
// persisted before the next one starts:
//   planMultipart     reads the file once: size, whole SHA-256 and a SHA-256
//                     per fixed-size part (to detect a changed source)
//   createCheckpoint  writes the plan, the source's identity and the
//                     attachment ID (mode 0600, exclusive; replaced
//                     atomically on update; never a URL, signature, token or
//                     credential)
//   uploadMultipart   with a multipart capability from bridge_attachment_begin
//                     (re-issued per wake by calling begin again with the
//                     same id and body): creates one session (intent recorded
//                     first), uploads the parts it has no ETag for (bounded
//                     concurrency; the same part is re-sent, bounded, when a
//                     response is lost), then completes with the recorded
//                     part ETags. Returns the provider's opaque ETag; pass it
//                     to bridge_attachment_finalize.
// One uploader per checkpoint: uploadMultipart holds an exclusive lock file
// (<checkpoint>.lock, created exclusively, mode 0600) for its whole run; a
// second uploader (same or another process) fails with checkpoint_busy, and
// every phase change is a compare-and-set on the recorded phase. A lock left
// by a stopped process is never taken over automatically (its requests may
// still be in flight): breakCheckpointLock removes it, explicitly, once the
// owner is known to have stopped. Each part's send attempts are recorded
// before the request, so the per-part budget holds across restarts.
// An unknown session-creation outcome (lost response, timeout, 5xx) is
// recorded as creation_unknown and never silently retried: the provider
// cannot be asked whether a session exists. Starting another session needs
// an explicit allowNewSession, is bounded, and counts the earlier session as
// abandoned (never completed or cleaned up by this helper). An unknown
// completion is retried on the same session with the same parts (bounded).
// If a lost completion had in fact succeeded, the retry finds no session
// (session_gone_check_finalize) and the client never learns the ETag: call
// bridge_attachment_finalize without one; its HEAD (exact size and an opaque
// ETag on the fixed, no-overwrite pathname) decides availability. That is
// evidence the object exists, not proof of content: the recipient's SHA-256
// check still decides.
// ETags are opaque; the recipient's SHA-256 check is the content proof.
export const PART_SIZES = [16 * MIB, 32 * MIB, 64 * MIB];
export const DEFAULT_PART_SIZE = 64 * MIB;
export const MAX_PARTS = Math.ceil(MAX_ATTACHMENT_BYTES / PART_SIZES[0]!);
export const MAX_PART_CONCURRENCY = 4, MAX_PART_ATTEMPTS = 5, MAX_SESSIONS = 3, MAX_COMPLETES = 3;
const PHASES = ['new', 'creating', 'creation_unknown', 'open', 'completing', 'complete_unknown', 'completed'];
const OPAQUE = /^[\x21-\x7e]{1,1024}$/;
const MAX_CHECKPOINT_BYTES = 64 * 1024;
// Explicit refusals (the request was rejected before any session or object
// was created); anything else is an unknown outcome.
const REFUSALS = ['forbidden', 'bad_request', 'store_not_found', 'store_suspended', 'file_too_large', 'content_type_not_allowed',
  'client_token_expired', 'client_token_pathname_mismatch', 'oidc_environment_not_allowed'];
const refused = (out: ProviderResult): boolean => out.status >= 400 && out.status < 500 && REFUSALS.includes(out.code as string);
const partSize = (cp: MultipartCheckpoint, n: number): number => n < cp.parts.length ? cp.partSize : cp.size - cp.partSize * (cp.parts.length - 1);

export async function planMultipart(filePath: string, options: MultipartOptions = {}): Promise<MultipartPlan> {
  const { partSize: size = DEFAULT_PART_SIZE } = options;
  if (!PART_SIZES.includes(size)) fail('invalid_part_size');
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)) fail('source_must_be_absolute');
  const signal = deadline(options);
  const handle = await fs.open(filePath, fsc.O_RDONLY | fsc.O_NOFOLLOW).catch(() => fail('not_a_regular_file'));
  try {
    const info = await handle.stat({ bigint: true });
    if (!info.isFile()) fail('not_a_regular_file');
    const total = Number(info.size);
    if (!validSize(total)) fail('attachment_size_out_of_range');
    const count = Math.ceil(total / size);
    if (count < 2 || count > MAX_PARTS) fail('multipart_part_count_invalid');
    const whole = createHash('sha256'), parts: FileDigest[] = [], buffer = Buffer.allocUnsafe(Math.min(MIB, total));
    let position = 0, sha = createHash('sha256'), inPart = 0;
    while (position < total) {
      const want = Math.min(buffer.length, total - position, size - inPart);
      const { bytesRead } = await bounded(() => handle.read(buffer, 0, want, position), signal);
      if (!(bytesRead > 0)) fail('file_changed_while_reading');
      const chunk = buffer.subarray(0, bytesRead);
      whole.update(chunk); sha.update(chunk);
      position += bytesRead; inPart += bytesRead;
      if (inPart === size || position === total) { parts.push({ size: inPart, sha256: sha.digest('hex') }); sha = createHash('sha256'); inPart = 0; }
    }
    const after = await handle.stat({ bigint: true }), named = await fs.lstat(filePath, { bigint: true });
    if (!sameIdentity(identity(info), identity(after)) || !sameIdentity(identity(info), identity(named))) fail('file_changed_while_reading');
    return { size: total, sha256: whole.digest('hex'), partSize: size, parts, source: { path: filePath, ...identity(info) } };
  } finally { await handle.close().catch(() => {}); }
}

const CHECKPOINT_KEYS = ['abandoned', 'attachmentId', 'completes', 'creates', 'partSize', 'parts', 'phase', 'result', 'session', 'sha256',
  'size', 'source', 'v'].sort();
function validCheckpoint(cp: MultipartCheckpoint): MultipartCheckpoint {
  const obj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
  const count = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
  if (!obj(cp) || Object.keys(cp).sort().join() !== CHECKPOINT_KEYS.join() || cp.v !== 2 || !UUID_V4.test(cp.attachmentId || '') ||
      !validSize(cp.size) || !SHA256.test(cp.sha256 || '') || !PART_SIZES.includes(cp.partSize) || !Array.isArray(cp.parts) ||
      cp.parts.length !== Math.ceil(cp.size / cp.partSize) || cp.parts.length < 2 || cp.parts.length > MAX_PARTS ||
      !PHASES.includes(cp.phase) || !count(cp.creates) || !count(cp.completes) || !count(cp.abandoned) ||
      cp.creates > MAX_SESSIONS || cp.completes > MAX_COMPLETES ||
      !(cp.session === null || (obj(cp.session) && Object.keys(cp.session).sort().join() === 'key,uploadId' &&
        OPAQUE.test(cp.session.key || '') && OPAQUE.test(cp.session.uploadId || ''))) ||
      ['open', 'completing', 'complete_unknown', 'completed'].includes(cp.phase) !== (cp.session !== null) ||
      !(cp.result === null || (obj(cp.result) && Object.keys(cp.result).join() === 'etag' && OPAQUE_ETAG.test(cp.result.etag || ''))) ||
      (cp.phase === 'completed') !== (cp.result !== null) || !obj(cp.source) ||
      Object.keys(cp.source).sort().join() !== 'dev,ino,mtimeNs,path,size' || typeof cp.source.path !== 'string' ||
      !path.isAbsolute(cp.source.path) || cp.source.size !== String(cp.size) ||
      !['dev', 'ino', 'mtimeNs'].every(k => /^[0-9]{1,30}$/.test(cp.source[k as keyof FileIdentity])) ||
      !cp.parts.every(p => obj(p) && Object.keys(p).sort().join() === 'attempts,etag,sha256' && SHA256.test(p.sha256 || '') &&
        (p.etag === null || OPAQUE_ETAG.test(p.etag)) && count(p.attempts) && p.attempts <= MAX_PART_ATTEMPTS)) fail('checkpoint_invalid');
  return cp;
}
async function readCheckpoint(checkpointPath: string): Promise<MultipartCheckpoint> {
  if (typeof checkpointPath !== 'string' || !path.isAbsolute(checkpointPath)) fail('checkpoint_must_be_absolute');
  let handle: FileHandle;
  try { handle = await fs.open(checkpointPath, fsc.O_RDONLY | fsc.O_NOFOLLOW); } catch { fail('checkpoint_invalid'); }
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > MAX_CHECKPOINT_BYTES) fail('checkpoint_invalid');
    let value: MultipartCheckpoint; // Parsed JSON, validated next.
    try { value = JSON.parse(await handle.readFile('utf8')); } catch { fail('checkpoint_invalid'); }
    return validCheckpoint(value);
  } finally { await handle.close().catch(() => {}); }
}
// Write a new file exclusively (mode 0600), fsync it, then either keep it at
// `target` (exclusive create) or rename it over `target` (atomic replace).
async function writeDurably(target: string, value: MultipartCheckpoint, replace: boolean): Promise<void> {
  const data = JSON.stringify(validCheckpoint(value));
  const temp = replace ? path.join(path.dirname(target), `.${path.basename(target)}.${randomBytes(8).toString('hex')}.tmp`) : target;
  const out = await fs.open(temp, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600)
    .catch(error => fail(error?.code === 'EEXIST' ? 'checkpoint_exists' : 'checkpoint_write_failed'));
  try { await out.writeFile(data); await out.sync(); } catch { await out.close().catch(() => {}); await fs.unlink(temp).catch(() => {}); fail('checkpoint_write_failed'); }
  await out.close();
  if (replace) {
    try { await fs.rename(temp, target); } catch { await fs.unlink(temp).catch(() => {}); fail('checkpoint_write_failed'); }
  }
  const dir = await fs.open(path.dirname(target), fsc.O_RDONLY).catch(() => null);
  await dir?.sync().catch(() => {}); await dir?.close().catch(() => {});
}
// Updates to one checkpoint are serialized within this process (a second
// process on the same checkpoint at once is not supported: run one uploader
// per checkpoint).
const checkpointLocks = new Map<string, Promise<unknown>>();
async function updateCheckpoint(checkpointPath: string, change: (cp: MultipartCheckpoint) => void): Promise<MultipartCheckpoint> {
  const previous = checkpointLocks.get(checkpointPath) || Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>(resolve => { release = resolve; });
  const chained = previous.then(() => mine);
  checkpointLocks.set(checkpointPath, chained);
  await previous;
  try {
    const cp = await readCheckpoint(checkpointPath);
    change(cp);
    await writeDurably(checkpointPath, cp, true);
    return cp;
  } finally {
    release();
    if (checkpointLocks.get(checkpointPath) === chained) checkpointLocks.delete(checkpointPath);
  }
}
export async function createCheckpoint(checkpointPath: string, { attachmentId, plan }: { attachmentId: string; plan: MultipartPlan }): Promise<void> {
  if (typeof checkpointPath !== 'string' || !path.isAbsolute(checkpointPath)) fail('checkpoint_must_be_absolute');
  if (!UUID_V4.test(attachmentId || '')) fail('invalid_grant');
  await writeDurably(checkpointPath, { v: 2, attachmentId, source: plan.source, size: plan.size, sha256: plan.sha256,
    partSize: plan.partSize, parts: plan.parts.map(p => ({ sha256: p.sha256, etag: null, attempts: 0 })), phase: 'new', session: null,
    creates: 0, completes: 0, abandoned: 0, result: null }, false);
}
// Local progress (authoritative for the client; the provider cannot be asked).
export async function multipartProgress(checkpointPath: string) {
  const cp = await readCheckpoint(checkpointPath);
  return { attachmentId: cp.attachmentId, phase: cp.phase, partCount: cp.parts.length, sessions: cp.creates,
    abandonedSessions: cp.abandoned, completes: cp.completes, etag: cp.result?.etag ?? null,
    sent: cp.parts.flatMap((p, i) => p.etag ? [i + 1] : []), pending: cp.parts.flatMap((p, i) => p.etag ? [] : [i + 1]) };
}

// Exclusive ownership of one checkpoint for a whole uploadMultipart run.
async function lockCheckpoint(checkpointPath: string): Promise<() => Promise<void>> {
  const lockPath = checkpointPath + '.lock';
  let handle: FileHandle;
  try { handle = await fs.open(lockPath, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600); }
  catch (error) { fail((error as { code?: unknown } | null | undefined)?.code === 'EEXIST' ? 'checkpoint_busy' : 'checkpoint_lock_failed'); }
  let mine!: Stats;
  try { await handle.writeFile(JSON.stringify({ pid: process.pid, at: new Date().toISOString() })); await handle.sync(); mine = await handle.stat(); }
  finally { await handle.close().catch(() => {}); }
  return async () => {
    const info = await fs.lstat(lockPath).catch(() => null);
    if (info && info.ino === mine.ino && info.dev === mine.dev) await fs.unlink(lockPath).catch(() => {});
  };
}
// Explicit only: remove a lock left by an uploader that is known to have stopped.
export async function breakCheckpointLock(checkpointPath: string): Promise<void> {
  if (typeof checkpointPath !== 'string' || !path.isAbsolute(checkpointPath)) fail('checkpoint_must_be_absolute');
  await fs.unlink(checkpointPath + '.lock').catch(error => { if (!missing(error)) throw error; });
}

export async function uploadMultipart(checkpointPath: string, begun: UploadBegun | null | undefined,
  options: MultipartOptions = {}): Promise<{ complete: true; etag: string }> {
  if (typeof checkpointPath !== 'string' || !path.isAbsolute(checkpointPath)) fail('checkpoint_must_be_absolute');
  const release = await lockCheckpoint(checkpointPath);
  try { return await runMultipart(checkpointPath, begun, options); } finally { await release(); }
}
async function runMultipart(checkpointPath: string, begun: UploadBegun | null | undefined,
  options: MultipartOptions): Promise<{ complete: true; etag: string }> {
  const { fetchImpl = fetch, now = Date.now, allowNewSession = false } = options;
  const concurrency = Math.min(MAX_PART_CONCURRENCY, Math.max(1, options.concurrency ?? MAX_PART_CONCURRENCY));
  let cp = await readCheckpoint(checkpointPath);
  if (begun?.attachmentId !== cp.attachmentId) fail('invalid_grant');
  const { key, headers } = checkUploadGrant(begun, { size: cp.size, sha256: cp.sha256 }, true);
  // checkUploadGrant accepted begun, including its multipart URL.
  const mpu = begun!.upload!.multipartUrl as string;
  checkExpiry(begun!.upload!.expiresAt, now);
  const signal = deadline(options);
  // Compare-and-set on the recorded phase (from: one phase or a list).
  const update = (change: (c: MultipartCheckpoint) => void, from: string | string[] | null = null) => updateCheckpoint(checkpointPath, c => {
    if (from !== null && !([] as string[]).concat(from).includes(c.phase)) fail('checkpoint_conflict');
    change(c);
  });
  const expired = () => Date.parse(begun!.upload!.expiresAt) <= now();
  const post = (action: string, extra: Record<string, string>, init: FetchInit = {}) => send(fetchImpl, mpu, { method: 'POST', headers: { ...headers, 'x-mpu-action': action, ...extra }, ...init }, signal);
  const call = async (action: string, extra: Record<string, string>, init?: FetchInit) => bounded(async () => providerJson(await post(action, extra, init)), signal);
  if (cp.phase === 'completed') return { complete: true, etag: cp.result!.etag };
  // A process that stopped mid-request never learned the outcome.
  if (cp.phase === 'creating') cp = await update(c => { c.phase = 'creation_unknown'; }, 'creating');
  if (cp.phase === 'completing') cp = await update(c => { c.phase = 'complete_unknown'; }, 'completing');
  if (cp.phase === 'creation_unknown') {
    if (!allowNewSession) fail('session_creation_unknown');
    if (cp.creates >= MAX_SESSIONS) fail('session_budget_exhausted');
    // Explicit: any session the unknown request created is abandoned (never
    // completed or aborted by this helper).
    cp = await update(c => { c.abandoned++; c.phase = 'new'; }, 'creation_unknown');
  }
  if (cp.phase === 'new') {
    if (cp.creates >= MAX_SESSIONS) fail('session_budget_exhausted');
    // Durable intent first: if this write fails, nothing is sent.
    cp = await update(c => { c.phase = 'creating'; c.creates++; }, 'new');
    let out: ProviderResult;
    try { out = await call('create', {}); } catch { await update(c => { c.phase = 'creation_unknown'; }, 'creating'); fail('session_creation_unknown'); }
    // ok implies a parsed body; both IDs were checked.
    if (out.ok && OPAQUE.test(out.body!.key || '') && OPAQUE.test(out.body!.uploadId || '')) {
      cp = await update(c => { c.session = { key: out.body!.key as string, uploadId: out.body!.uploadId as string }; c.phase = 'open'; }, 'creating');
    } else if (refused(out)) {
      await update(c => { c.phase = 'new'; }, 'creating'); fail('upload_rejected');
    } else {
      await update(c => { c.phase = 'creation_unknown'; }, 'creating'); fail('session_creation_unknown');
    }
  }
  if (cp.phase === 'open') {
    const session = cp.session!, pending = cp.parts.flatMap((p, i) => p.etag ? [] : [i + 1]);
    let failure: string | null = null, next = 0;
    const sendPart = async (n: number): Promise<string> => {
      let handle: FileHandle;
      try { handle = await fs.open(cp.source.path, fsc.O_RDONLY | fsc.O_NOFOLLOW); } catch { fail('source_changed'); }
      const size = partSize(cp, n), start = (n - 1) * cp.partSize, sha = createHash('sha256');
      let sent = 0;
      try {
        const changed = async () => {
          const a = await handle.stat({ bigint: true }).catch(() => null), b = await fs.lstat(cp.source.path, { bigint: true }).catch(() => null);
          return !a || !b || !sameIdentity(identity(a), cp.source) || !sameIdentity(identity(b), cp.source);
        };
        if (await changed()) fail('source_changed');
        const buffer = Buffer.allocUnsafe(Math.min(MIB, size));
        const body = new ReadableStream<Uint8Array>({ async pull(controller) {
          if (sent >= size) { controller.close(); return; }
          const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, size - sent), start + sent);
          if (!(bytesRead > 0)) { controller.error(new AttachmentClientError('source_changed')); return; }
          const chunk = Buffer.from(buffer.subarray(0, bytesRead));
          sha.update(chunk); sent += bytesRead; controller.enqueue(chunk);
        } });
        let out: ProviderResult;
        try {
          out = await call('upload', { 'x-mpu-key': encodeURIComponent(session.key), 'x-mpu-upload-id': session.uploadId,
            'x-mpu-part-number': String(n), 'content-length': String(size) }, { body, duplex: 'half' });
        } catch (error) { if (await changed()) fail('source_changed'); throw error; }
        // A provider error may come before the whole body was read: that is a
        // failed attempt (or a refusal), unless the source itself changed.
        if (!out.ok || !OPAQUE_ETAG.test(out.body?.etag || '')) {
          if (await changed()) fail('source_changed');
          fail(refused(out) ? 'upload_rejected' : 'part_outcome_unknown');
        }
        // Accepted: the bytes sent must be exactly the planned part.
        if (sent !== size || sha.digest('hex') !== cp.parts[n - 1]!.sha256 || await changed()) fail('source_changed');
        return out.body!.etag as string; // Checked above.
      } finally { await handle.close().catch(() => {}); }
    };
    const worker = async () => {
      while (!failure && next < pending.length) {
        const n = pending[next++]!;
        for (;;) {
          if (failure) return;
          if (expired()) { failure ||= 'grant_expired'; return; }
          // Record the attempt before sending it: the budget is durable
          // across restarts, and a failed write sends nothing.
          try {
            await update(c => {
              if (c.parts[n - 1]!.attempts >= MAX_PART_ATTEMPTS) fail('part_budget_exhausted');
              c.parts[n - 1]!.attempts++;
            }, 'open');
          } catch (error) { failure ||= error instanceof AttachmentClientError ? error.code : 'checkpoint_write_failed'; return; }
          try {
            const etag = await sendPart(n);
            await update(c => { c.parts[n - 1]!.etag = etag; }, 'open');
            break;
          } catch (error) {
            const code = error instanceof AttachmentClientError ? error.code : 'transfer_failed';
            // Lost or failed responses: re-send the same part (same bytes),
            // within the durable budget. A changed source, a refusal, the
            // deadline or a checkpoint conflict stop everything.
            if (['source_changed', 'upload_rejected', 'transfer_timeout', 'transfer_aborted', 'redirect_refused',
              'checkpoint_conflict', 'checkpoint_write_failed', 'checkpoint_invalid'].includes(code)) { failure ||= code; return; }
          }
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(concurrency, pending.length || 1) }, worker));
    if (failure) fail(failure);
    cp = await readCheckpoint(checkpointPath);
  }
  if (cp.phase === 'complete_unknown' || (cp.phase === 'open' && cp.parts.every(p => p.etag))) {
    if (cp.completes >= MAX_COMPLETES) fail('completion_unknown');
    if (expired()) fail('grant_expired');
    cp = await update(c => { c.phase = 'completing'; c.completes++; }, ['open', 'complete_unknown']);
    const parts = cp.parts.map((p, i) => ({ etag: p.etag, partNumber: i + 1 }));
    let out: ProviderResult;
    try {
      // These phases always have a recorded session (validCheckpoint).
      out = await call('complete', { 'content-type': 'application/json', 'x-mpu-upload-id': cp.session!.uploadId,
        'x-mpu-key': encodeURIComponent(cp.session!.key) }, { body: JSON.stringify(parts) });
    } catch { await update(c => { c.phase = 'complete_unknown'; }, 'completing'); fail('completion_unknown'); }
    if (out.ok && out.body!.pathname === key && OPAQUE_ETAG.test(out.body!.etag || '')) {
      await update(c => { c.phase = 'completed'; c.result = { etag: out.body!.etag as string }; }, 'completing');
      return { complete: true, etag: out.body!.etag as string };
    }
    await update(c => { c.phase = 'complete_unknown'; }, 'completing');
    // The session is gone: an earlier, lost completion may have succeeded.
    if (out.status === 404 && out.code === 'not_found' && cp.completes > 1) fail('session_gone_check_finalize');
    fail('completion_unknown');
  }
  fail('checkpoint_invalid');
}
