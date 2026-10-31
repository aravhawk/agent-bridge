import { createHash } from 'node:crypto';
import { BridgeError } from './policy.mjs';

// Private Vercel Blob provider for attachments.
//
// Provider contract used by attachments.mjs (no provider-specific digest or
// ETag math in the core):
//   namespace                                  non-secret identity of the store
//   presignUpload({ key, size, validUntil })   artifact-scoped upload capability
//   presignGet({ key, validUntil })            artifact-scoped private GET URL
//   head(key)        -> { status: 200, size, etag } | { status: 404 }   (etag opaque)
//   delete(key)      -> { status }   (used only under an approved retention policy)
//
// Vercel Signed URLs (documented: /docs/vercel-blob/vercel-signed-urls): the
// server asks the Blob control API for a short-lived delegation scoped to one
// pathname, operation set, expiry, maximum size and content types
// (issueSignedToken, intended to authenticate with the deployment's OIDC token
// and store ID), then signs a URL locally (presignUrl, HMAC). @vercel/blob
// resolves OIDC first but can read BLOB_READ_WRITE_TOKEN as its standard
// fallback when OIDC is unavailable; this provider does not configure or pass
// that fallback. The client signing key in
// that delegation never leaves this module: it is used once and dropped; it
// is never stored, logged or returned. A 'put' capability covers a single PUT
// and the native multipart POSTs for that pathname; its scope is the whole
// ARTIFACT (pathname, maximum size, content type, no overwrite, no random
// suffix, expiry), not a part, a session or a byte range. It is reusable by
// whoever holds it until it expires.
//
// SDK: @vercel/blob 2.8.2 (pinned), imported only when a provider is created
// (never while attachments are disabled). Tests inject a fake `sdk`.

const fail = (code, status = 503) => { throw new BridgeError(code, status); };
// Store IDs, as created by Vercel ('store_<id>' or '<id>'); never a secret.
const STORE_ID = /^(?:store_)?([A-Za-z0-9]{8,64})$/;
export const ATTACHMENT_KEY = /^att\/[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
// Opaque provider ETag as recorded and echoed: printable ASCII, bounded.
export const OPAQUE_ETAG = /^[\x21-\x7e]{1,256}$/;
export const BLOB_API_ORIGIN = 'https://vercel.com';
export const BLOB_PUT_PATH = '/api/blob/';
export const BLOB_MPU_PATH = '/api/blob/mpu';
export const BLOB_API_VERSION = '13';               // @vercel/blob 2.8.2 BLOB_API_VERSION
export const CONTENT_TYPE = 'application/octet-stream';
export const SIGNED_PARAMS = ['vercel-blob-delegation', 'vercel-blob-signature', 'vercel-blob-valid-until'];
const UPLOAD_PARAMS = ['pathname', 'vercel-blob-maximum-size-in-bytes', 'vercel-blob-allowed-content-types',
  'vercel-blob-add-random-suffix', 'vercel-blob-allow-overwrite', ...SIGNED_PARAMS];
const GET_PARAMS = ['cache', ...SIGNED_PARAMS];

// Per-file maximum in decimal bytes: 500 MB unless trusted configuration
// (BRIDGE_ATTACHMENT_MAX_BYTES, digits only) sets a value from 500 MB to 1 GB.
export const DEFAULT_MAX_BYTES = 500000000, HARD_MAX_BYTES = 1000000000;
function maxBytes(value) {
  if (value === undefined) return DEFAULT_MAX_BYTES;
  const n = typeof value === 'string' && /^[1-9][0-9]{0,9}$/.test(value) ? Number(value) : NaN;
  return n >= DEFAULT_MAX_BYTES && n <= HARD_MAX_BYTES ? n : null;
}
// Read per invocation. Disabled unless BRIDGE_ATTACHMENTS_ENABLED is exactly
// 'true'; nothing else is read while disabled. Enabled needs BLOB_STORE_ID
// (added by Vercel when a store is connected; an identifier, not a secret)
// and a valid size limit; anything invalid leaves the capability off. The
// intended credential is the deployment's OIDC token, resolved inside the
// SDK. Supplying storeId does not disable the SDK's BLOB_READ_WRITE_TOKEN
// fallback when OIDC is absent, so operators must not configure that fallback
// for this deployment. The namespace is a digest of the store, recorded on
// every attachment, so a changed store fails closed.
export function attachmentConfig(env) {
  const flag = env.BRIDGE_ATTACHMENTS_ENABLED;
  if (flag !== 'true') return { configured: flag !== undefined, enabled: false, valid: false };
  const store = STORE_ID.exec(typeof env.BLOB_STORE_ID === 'string' ? env.BLOB_STORE_ID : '');
  const limit = maxBytes(env.BRIDGE_ATTACHMENT_MAX_BYTES);
  if (!store || limit === null) return { configured: true, enabled: true, valid: false };
  const storeId = store[1];
  return { configured: true, enabled: true, valid: true, provider: 'vercel-blob', storeId, maxBytes: limit,
    namespace: createHash('sha256').update(JSON.stringify(['vercel-blob', storeId.toLowerCase()])).digest('hex') };
}
export const blobHost = storeId => `${storeId.toLowerCase()}.private.blob.vercel-storage.com`;
// Request headers a client sends with the upload capability (not secret, not
// signed): the SDK's own headers for a private, non-overwriting,
// non-suffixed octet-stream upload.
export const uploadHeaders = storeId => ({ 'x-api-version': BLOB_API_VERSION, 'x-vercel-blob-store-id': storeId,
  'x-vercel-blob-access': 'private', 'x-content-type': CONTENT_TYPE, 'x-add-random-suffix': '0', 'x-allow-overwrite': '0' });

// Settle with the work or, at the deadline, with `late()`, even if the work
// ignores its AbortSignal; its own late settlement is observed, never awaited.
export function withDeadline(work, ms, late) {
  let timer;
  const settled = Promise.resolve().then(work);
  settled.catch(() => {});
  return Promise.race([settled, new Promise((resolve, reject) => {
    timer = setTimeout(() => { try { resolve(late()); } catch (error) { reject(error); } }, ms);
  })]).finally(() => clearTimeout(timer));
}

// Exactly the upload URL the bridge asked for: Blob API host and path, this
// pathname, maximum size, content type, no overwrite, no random suffix, a
// delegation and signature, and nothing else.
export function checkUploadUrl(value, { key, size, multipart = false }) {
  let url;
  try { url = new URL(value); } catch { return false; }
  const q = url.searchParams, keys = [...q.keys()];
  return url.origin === BLOB_API_ORIGIN && !url.username && !url.password && !url.hash &&
    url.pathname === (multipart ? BLOB_MPU_PATH : BLOB_PUT_PATH) && keys.length === new Set(keys).size &&
    keys.every(k => UPLOAD_PARAMS.includes(k)) && q.get('pathname') === key &&
    q.get('vercel-blob-maximum-size-in-bytes') === String(size) && q.get('vercel-blob-allowed-content-types') === CONTENT_TYPE &&
    q.get('vercel-blob-add-random-suffix') === 'false' && q.get('vercel-blob-allow-overwrite') === 'false' &&
    !!q.get('vercel-blob-delegation') && !!q.get('vercel-blob-signature');
}
export function checkGetUrl(value, { key, storeId }) {
  let url;
  try { url = new URL(value); } catch { return false; }
  const q = url.searchParams, keys = [...q.keys()];
  return url.protocol === 'https:' && url.hostname === blobHost(storeId) && !url.port && !url.username && !url.password &&
    !url.hash && url.pathname === '/' + key && keys.length === new Set(keys).size && keys.every(k => GET_PARAMS.includes(k)) &&
    q.get('cache') === '0' && !!q.get('vercel-blob-delegation') && !!q.get('vercel-blob-signature');
}

export function createBlobProvider({ config, sdk, clock = Date.now, timeoutMs = 10000 }) {
  if (!config?.valid || config.provider !== 'vercel-blob') fail('attachments_not_configured');
  let loaded = null;
  const load = () => (loaded ||= sdk ? Promise.resolve(sdk) : import('@vercel/blob'));
  const unavailable = () => fail('attachment_provider_unavailable');
  // One bounded provider step; any SDK error (including its own retries
  // running out) is unavailable unless the caller maps it.
  const step = (work, map = null) => withDeadline(async () => {
    const s = await load();
    try { return await work(s, AbortSignal.timeout(timeoutMs)); }
    catch (error) { const mapped = map?.(error, s); if (mapped) return mapped; throw error; }
  }, timeoutMs + 1000, unavailable).catch(error => { if (error instanceof BridgeError) throw error; return unavailable(); });
  const key = value => { if (!ATTACHMENT_KEY.test(value || '')) fail('attachment_key_invalid', 500); return value; };
  // An expiry already past (time spent waiting before signing) is a closed
  // window, never signed; a malformed one is a programming error.
  const until = validUntil => {
    if (!Number.isSafeInteger(validUntil)) fail('attachment_url_window_invalid', 500);
    if (validUntil - clock() < 1000) fail('attachment_url_window_closed', 409);
    return validUntil;
  };
  // A delegation for exactly one pathname and operation; its signing key is
  // used here and dropped.
  async function sign(operation, pathname, validUntil, urlOptions, delegation = {}) {
    return step(async (s, abortSignal) => {
      const token = await s.issueSignedToken({ pathname, operations: [operation], validUntil, storeId: config.storeId,
        abortSignal, ...delegation });
      const { presignedUrl } = await s.presignUrl(token, { operation, pathname, access: 'private', validUntil, ...urlOptions });
      if (typeof presignedUrl !== 'string' || presignedUrl.includes(token.clientSigningToken)) fail('attachment_provider_unavailable');
      return presignedUrl;
    });
  }
  return {
    namespace: config.namespace,
    kind: 'vercel-blob',
    async presignUpload({ key: pathname, size, validUntil }) {
      key(pathname); until(validUntil);
      if (!Number.isSafeInteger(size) || size < 1 || size > HARD_MAX_BYTES) fail('attachment_upload_invalid', 500);
      const shape = { maximumSizeInBytes: size, allowedContentTypes: [CONTENT_TYPE] };
      const url = await sign('put', pathname, validUntil, { ...shape, addRandomSuffix: false, allowOverwrite: false }, shape);
      if (!checkUploadUrl(url, { key: pathname, size })) fail('attachment_provider_unavailable');
      const multipartUrl = new URL(url); multipartUrl.pathname = BLOB_MPU_PATH;
      return { method: 'PUT', url, multipartUrl: multipartUrl.href, headers: uploadHeaders(config.storeId) };
    },
    async presignGet({ key: pathname, validUntil }) {
      key(pathname); until(validUntil);
      const url = await sign('get', pathname, validUntil, { useCache: false });
      if (!checkGetUrl(url, { key: pathname, storeId: config.storeId })) fail('attachment_provider_unavailable');
      return { method: 'GET', url };
    },
    // Server-side metadata (SDK head, OIDC). Size and an opaque ETag only.
    async head(pathname) {
      key(pathname);
      const out = await step((s, abortSignal) => s.head(pathname, { storeId: config.storeId, abortSignal }),
        (error, s) => error instanceof s.BlobNotFoundError ? { notFound: true } : null);
      if (out.notFound) return { status: 404, size: null, etag: null };
      if (out?.pathname !== pathname || !Number.isSafeInteger(out.size) || out.size < 0 || !OPAQUE_ETAG.test(out.etag || '')) {
        return { status: 0, size: null, etag: null };
      }
      return { status: 200, size: out.size, etag: out.etag };
    },
    async delete(pathname) {
      key(pathname);
      const out = await step(async (s, abortSignal) => { await s.del(pathname, { storeId: config.storeId, abortSignal }); return { ok: true }; },
        (error, s) => error instanceof s.BlobNotFoundError ? { notFound: true } : null);
      return { status: out.notFound ? 404 : 204 };
    },
  };
}
