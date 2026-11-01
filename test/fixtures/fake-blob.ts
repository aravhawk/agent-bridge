import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// Test-only stand-in for a PRIVATE Vercel Blob store: the SDK surface the
// bridge server uses (issueSignedToken, presignUrl, head, del) and the HTTP
// endpoints a client uses with a presigned capability (single PUT and native
// multipart create/upload/complete on the Blob API; GET on the private store
// host). No network is used.
//
// It independently verifies what @vercel/blob 2.8.2 signs: the delegation
// (its own server MAC), and the URL signature, an HMAC-SHA256 (base64url),
// keyed by the delegation's client signing key, over the sorted lines
// operation=..., pathname=... and every vercel-blob-* presign parameter.
// It then enforces the delegation and URL scope: pathname, operation, expiry,
// maximum size, content type, no overwrite, no random suffix. Behaviour that
// is NOT documented for private signed URLs is modelled here as assumptions,
// configurable for tests (Range and If-Match honoured on GET by default;
// equal non-final parts of at least 5 MiB; maximum size and no-overwrite also
// enforced at multipart completion).
// `lean: true` keeps only sizes and digests (1 GB streaming tests).
/** One stored object; `lean` keeps only its size and digest. */
export interface FakeObject { size?: number; body: Buffer | null; etag: string; sha256?: string | null }
export interface FakeSession { key: string; pathname: string; parts: Map<number, FakeObject> }
export interface FakeCall { op: string | null; method: string; pathname?: string; operations?: string[]; host?: string; path?: string }
/** A test-installed fault: return/throw a value to replace the operation's normal outcome. */
export type Fault = (subject: unknown, context?: { headers: Headers }) => unknown;
export interface FakeBlobOptions {
  storeId: string; clock: () => number; lean?: boolean; rangeSupport?: boolean; ifMatchSupport?: boolean; etagHeader?: boolean;
}
interface IssueOptions {
  pathname: string; operations: string[]; validUntil: number; storeId: string; maximumSizeInBytes?: number;
  allowedContentTypes?: string[]; abortSignal?: AbortSignal;
}
interface PresignOptions {
  operation: string; pathname: string; validUntil?: number; allowedContentTypes?: string[]; maximumSizeInBytes?: number;
  addRandomSuffix?: boolean; allowOverwrite?: boolean; useCache?: boolean; access?: string;
}
interface DelegationScope {
  storeId: string; pathname: string; operations: string[]; validUntil: number; maximumSizeInBytes?: number; allowedContentTypes?: string[];
}
const b64u = (value: string | Uint8Array): string => Buffer.from(value).toString('base64url');
const sha256 = (data: string | Uint8Array): string => createHash('sha256').update(data).digest('hex');
const PRESIGN_KEYS = ['vercel-blob-add-random-suffix', 'vercel-blob-allow-overwrite', 'vercel-blob-allowed-content-types',
  'vercel-blob-cache-control-max-age', 'vercel-blob-callback-token-payload', 'vercel-blob-callback-url', 'vercel-blob-if-match',
  'vercel-blob-maximum-size-in-bytes', 'vercel-blob-valid-until'];
const MIN_PART = 5 * 1024 * 1024;
const json = (body: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
const error = (code: string, status: number, message = code) => json({ error: { code, message } }, status);
export const canonical = (operation: string, pathname: string, entries: [string, string | null][]): string =>
  [`operation=${operation}`, `pathname=${pathname}`, ...entries.map(([k, v]) => `${k}=${v}`)].sort().join('\n');

export function createFakeBlob({ storeId, clock, lean = false, rangeSupport = true, ifMatchSupport = true, etagHeader = true }: FakeBlobOptions) {
  const id = storeId.replace(/^store_/, ''), host = `${id.toLowerCase()}.private.blob.vercel-storage.com`;
  const serverKey = randomBytes(32), objects = new Map<string, FakeObject>(), sessions = new Map<string, FakeSession>(), calls: FakeCall[] = [];
  const faults: Record<string, Fault | null | undefined> = {}, lost: Record<string, number | boolean> = {}, options = { rangeSupport, ifMatchSupport, etagHeader };
  const tag = () => `"${randomBytes(12).toString('hex')}"`;
  const signingKey = (segment: string): string => b64u(createHmac('sha256', serverKey).update('sign:' + segment).digest());
  const reply = <T>(op: string, effect: () => T): T => {
    const out = effect();
    if (lost[op]) { lost[op] = lost[op] === true ? 0 : (lost[op] as number) - 1; throw new TypeError('fake: response lost'); }
    return out;
  };
  class BlobNotFoundError extends Error {}
  const sdk = {
    BlobNotFoundError,
    async issueSignedToken(o: IssueOptions) {
      calls.push({ op: 'issueSignedToken', method: 'POST', pathname: o.pathname, operations: o.operations });
      const fault = faults.issue?.(o); if (fault) throw fault;
      const payload = { storeId: o.storeId, pathname: o.pathname, operations: o.operations, validUntil: o.validUntil,
        ...(o.maximumSizeInBytes !== undefined ? { maximumSizeInBytes: o.maximumSizeInBytes } : {}),
        ...(o.allowedContentTypes ? { allowedContentTypes: o.allowedContentTypes } : {}) };
      const segment = b64u(JSON.stringify(payload));
      return { delegationToken: `${segment}.${b64u(createHmac('sha256', serverKey).update(segment).digest())}`,
        clientSigningToken: signingKey(segment), validUntil: o.validUntil };
    },
    // Same URL shapes and canonical string as @vercel/blob 2.8.2 presignUrl
    // (a dedicated test checks the real SDK against this verifier).
    async presignUrl(token: { delegationToken: string; clientSigningToken: string }, o: PresignOptions) {
      const payload: DelegationScope = JSON.parse(Buffer.from(token.delegationToken.split('.')[0]!, 'base64url').toString('utf8'));
      const entries: [string, string][] = [];
      if (o.validUntil !== undefined && o.validUntil < payload.validUntil) entries.push(['vercel-blob-valid-until', String(o.validUntil)]);
      if (o.operation === 'put') {
        if (o.allowedContentTypes) entries.push(['vercel-blob-allowed-content-types', [...o.allowedContentTypes].sort().join(',')]);
        if (o.maximumSizeInBytes !== undefined) entries.push(['vercel-blob-maximum-size-in-bytes', String(o.maximumSizeInBytes)]);
        if (o.addRandomSuffix !== undefined) entries.push(['vercel-blob-add-random-suffix', String(o.addRandomSuffix)]);
        if (o.allowOverwrite !== undefined) entries.push(['vercel-blob-allow-overwrite', String(o.allowOverwrite)]);
      }
      const signature = b64u(createHmac('sha256', token.clientSigningToken).update(canonical(o.operation, o.pathname, entries)).digest());
      const url = o.operation === 'get' ? new URL(`https://${host}/${o.pathname}`) : new URL('https://vercel.com/api/blob/');
      if (o.operation === 'get' && o.useCache === false) url.searchParams.set('cache', '0');
      if (o.operation !== 'get') url.searchParams.set('pathname', o.pathname);
      for (const [k, v] of entries) url.searchParams.set(k, v);
      url.searchParams.set('vercel-blob-delegation', token.delegationToken);
      url.searchParams.set('vercel-blob-signature', signature);
      return { presignedUrl: url.toString() };
    },
    async head(pathname: string) {
      calls.push({ op: 'head', method: 'HEAD', pathname });
      const fault = faults.head?.(pathname); if (fault) { if (fault instanceof Error) throw fault; return fault; }
      const object = objects.get(pathname);
      if (!object) throw new BlobNotFoundError('not found');
      return { pathname, size: object.size ?? object.body!.length, etag: object.etag, url: `https://${host}/${pathname}`,
        contentType: 'application/octet-stream', uploadedAt: new Date(clock()) };
    },
    async del(pathname: string) {
      calls.push({ op: 'delete', method: 'DELETE', pathname });
      const fault = faults.delete?.(pathname); if (fault) throw fault;
      if (!objects.has(pathname)) throw new BlobNotFoundError('not found');
      objects.delete(pathname);
    },
  };
  // Returns the verified scope or an error Response.
  function verify(url: URL, operation: string, pathname: string) {
    const q = url.searchParams, delegation = q.get('vercel-blob-delegation') || '', [segment, mac] = delegation.split('.');
    const expected = segment ? b64u(createHmac('sha256', serverKey).update(segment).digest()) : '';
    if (!mac || mac.length !== expected.length || !timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return error('forbidden', 403);
    // A verified MAC implies a non-empty segment.
    const scope: DelegationScope = JSON.parse(Buffer.from(segment!, 'base64url').toString('utf8'));
    const entries = PRESIGN_KEYS.filter(k => q.has(k)).map((k): [string, string | null] => [k, q.get(k)]);
    const want = b64u(createHmac('sha256', signingKey(segment!)).update(canonical(operation, pathname, entries)).digest());
    const got = q.get('vercel-blob-signature') || '';
    if (got.length !== want.length || !timingSafeEqual(Buffer.from(got), Buffer.from(want))) return error('forbidden', 403);
    if (scope.storeId !== id || (scope.pathname !== '*' && scope.pathname !== pathname) || !scope.operations.includes(operation)) return error('forbidden', 403);
    const until = Math.min(scope.validUntil, q.has('vercel-blob-valid-until') ? Number(q.get('vercel-blob-valid-until')) : Infinity);
    if (clock() > until) return error('forbidden', 403, 'expired');
    const max = Math.min(scope.maximumSizeInBytes ?? Infinity, q.has('vercel-blob-maximum-size-in-bytes') ? Number(q.get('vercel-blob-maximum-size-in-bytes')) : Infinity);
    const types = q.get('vercel-blob-allowed-content-types')?.split(',') ?? scope.allowedContentTypes ?? null;
    return { scope, max, types, overwrite: q.get('vercel-blob-allow-overwrite') !== 'false', suffix: q.get('vercel-blob-add-random-suffix') === 'true' };
  }
  async function consume(body: unknown, limit: number, keep = !lean) {
    const hash = createHash('sha256'), chunks: Buffer[] = [];
    let size = 0;
    if (body) {
      const source = typeof body === 'string' || body instanceof Uint8Array ? [Buffer.from(body)] : body as AsyncIterable<Uint8Array>;
      for await (const chunk of source) {
        const b = Buffer.from(chunk); size += b.length;
        if (size > limit) return { tooLarge: true as const };
        hash.update(b); if (keep) chunks.push(b);
      }
    }
    return { size, sha256: hash.digest('hex'), body: keep ? Buffer.concat(chunks) : null };
  }
  async function fetch(input: string | URL, init: RequestInit & { duplex?: 'half' } = {}): Promise<Response> {
    const url = new URL(input), method = init.method || 'GET', headers = new Headers(init.headers || {});
    const call: FakeCall = { method, host: url.host, path: url.pathname, op: null };
    calls.push(call);
    if (url.host === 'vercel.com' && (url.pathname === '/api/blob/' || url.pathname === '/api/blob/mpu')) {
      const pathname = url.searchParams.get('pathname');
      const mpu = url.pathname === '/api/blob/mpu', action = mpu ? headers.get('x-mpu-action') : 'put';
      call.op = mpu ? action : 'put';
      if ((mpu ? method !== 'POST' : method !== 'PUT') || !pathname) return error('bad_request', 400);
      const scope = verify(url, 'put', pathname);
      if (scope instanceof Response) return scope;
      if (scope.suffix || headers.get('x-vercel-blob-access') !== 'private' || headers.get('x-vercel-blob-store-id') !== id) return error('bad_request', 400);
      if (scope.types && !scope.types.includes(headers.get('x-content-type') as string)) return error('content_type_not_allowed', 400, 'contentType is not allowed');
      const fault = faults[call.op as string]?.(pathname, { headers }); if (fault) return fault as Response;
      if (call.op === 'put' || call.op === 'create') {
        if (!scope.overwrite && objects.has(pathname)) return error('bad_request', 400, 'This blob already exists');
      }
      if (call.op === 'put') {
        const got = await consume(init.body, scope.max);
        if (got.tooLarge) return error('file_too_large', 400, 'the file length cannot be greater than ' + scope.max);
        return reply('put', () => {
          if (!scope.overwrite && objects.has(pathname)) return error('bad_request', 400, 'This blob already exists');
          const object = { ...got, etag: tag() }; objects.set(pathname, object);
          return json({ url: `https://${host}/${pathname}`, downloadUrl: `https://${host}/${pathname}?download=1`, pathname,
            contentType: 'application/octet-stream', contentDisposition: 'attachment', etag: object.etag });
        });
      }
      if (call.op === 'create') return reply('create', () => {
        const uploadId = 'up_' + randomBytes(9).toString('hex'), key = 'k_' + randomBytes(9).toString('hex');
        sessions.set(uploadId, { key, pathname, parts: new Map() });
        return json({ key, uploadId });
      });
      const session = sessions.get(headers.get('x-mpu-upload-id') || '');
      if (!session || session.pathname !== pathname || session.key !== decodeURIComponent(headers.get('x-mpu-key') || '')) return error('not_found', 404);
      if (call.op === 'upload') {
        const n = Number(headers.get('x-mpu-part-number'));
        if (!Number.isSafeInteger(n) || n < 1 || n > 10000) return error('bad_request', 400);
        const got = await consume(init.body, scope.max);
        if (got.tooLarge) { session.parts.delete(n); return error('file_too_large', 400); }
        return reply('upload', () => { const part = { ...got, etag: tag() }; session.parts.set(n, part); return json({ etag: part.etag }); });
      }
      if (call.op === 'complete') {
        const raw = await consume(init.body, 1 << 20, true);
        let list: { partNumber: number; etag: string }[];
        try { list = JSON.parse(raw.body?.toString('utf8') ?? ''); } catch { return error('bad_request', 400); }
        if (!Array.isArray(list) || !list.length || list.some((p, i) => i > 0 && p.partNumber <= list[i - 1]!.partNumber)) return error('bad_request', 400);
        const parts = list.map(p => ({ ...p, part: session.parts.get(p.partNumber) }));
        if (parts.some(p => !p.part || p.part.etag !== p.etag)) return error('bad_request', 400, 'invalid part');
        // Every part was found above.
        if (parts.slice(0, -1).some(p => p.part!.size! < MIN_PART || p.part!.size !== parts[0]!.part!.size)) return error('bad_request', 400, 'part size');
        const size = parts.reduce((n, p) => n + p.part!.size!, 0);
        if (size > scope.max) return error('file_too_large', 400);
        if (!scope.overwrite && objects.has(pathname)) return error('bad_request', 400, 'This blob already exists');
        return reply('complete', () => {
          const object = { size, body: lean ? null : Buffer.concat(parts.map(p => p.part!.body!)), etag: tag(),
            sha256: lean ? null : sha256(Buffer.concat(parts.map(p => p.part!.body!))) };
          objects.set(pathname, object); sessions.delete(headers.get('x-mpu-upload-id') as string);
          return json({ url: `https://${host}/${pathname}`, downloadUrl: `https://${host}/${pathname}?download=1`, pathname,
            contentType: 'application/octet-stream', contentDisposition: 'attachment', etag: object.etag });
        });
      }
      return error('bad_request', 400);
    }
    if (url.host === host && method === 'GET') {
      call.op = 'get';
      const pathname = url.pathname.slice(1), scope = verify(url, 'get', pathname);
      if (scope instanceof Response) return scope;
      const fault = faults.get?.(pathname, { headers }); if (fault) return fault as Response;
      const object = objects.get(pathname);
      if (!object) return error('not_found', 404);
      if (options.ifMatchSupport && headers.has('if-match') && headers.get('if-match') !== object.etag) return new Response(null, { status: 412 });
      // A non-lean object keeps its body.
      const size = object.size ?? object.body!.length, et = options.etagHeader ? { etag: object.etag } : {};
      const m = /^bytes=(\d+)-(\d+)$/.exec(headers.get('range') || '');
      if (options.rangeSupport && m) {
        const first = +m[1]!, last = Math.min(+m[2]!, size - 1);
        if (first > last) return new Response(null, { status: 416, headers: { 'content-range': `bytes */${size}` } });
        const body = object.body!.subarray(first, last + 1);
        return new Response(body, { status: 206, headers: { 'content-length': String(body.length), 'content-range': `bytes ${first}-${last}/${size}`, ...et } });
      }
      return new Response(object.body, { status: 200, headers: { 'content-length': String(size), ...et } });
    }
    return error('not_found', 404);
  }
  return { fetch, sdk, objects, sessions, calls, faults, lost, options, host, storeId: id };
}
