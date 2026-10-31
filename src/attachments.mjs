import { randomBytes, randomUUID } from 'node:crypto';
import { BridgeError, SCOPES, VERIFIED_AUTHORIZATION } from './policy.mjs';
import { messageAccessAllowed, resourceDenied } from './access.mjs';
import { dailyMessage } from './messages.mjs';
import { ownKeys } from './events.mjs';
import { PEER_IDS, counterpart } from './config.mjs';

// Private temporary file transfer between the two peers (disabled by
// default). Not a general cloud drive. Bytes never pass through the bridge:
// the sender uploads directly to private storage with a short-lived,
// artifact-scoped upload capability (one PUT, or the provider's native
// multipart upload, resumed by the client across processes and wakes), and
// the recipient downloads directly with a short private GET URL. The bridge
// keeps bounded metadata in its state row and decides who may get which
// capability. This module is provider-neutral: the provider contract is
// documented in blob.mjs; ETags are opaque and never derived here.
//
// Integrity: the bridge verifies size and records the provider's opaque ETag
// (HEAD). That is evidence that an object exists, not proof of its content.
// The recipient's streamed SHA-256 over the exact size, against the sender's
// declared digest, gates use of the file.
//
// Quotas below are RESERVED LOGICAL quotas over this metadata: how many
// capabilities and provider calls the bridge issues and how much it promises
// to store. They are not a storage bill, a bandwidth limit, a bound on the
// physical requests a capability holder makes (a capability is a bearer
// credential reusable until it expires, and the provider's own limits and
// billing apply to every request made with it), or proof of erasure.
//
// Fixed reservation: createdAt, uploadUntil and expiresAt are set once and
// never move. Only the short-lived capability (and the caller's own
// authorization) is renewed; nothing extends access, retention or quota.
//
// Retention: ACCESS expiry is not deletion. Without a trusted, owner-approved
// retention policy (constructor-only; never from env or a request) the bridge
// never sends DELETE and never releases quota: expired or rejected records
// keep their metadata and reserved quota, are reported, and new reservations
// meet backpressure instead of anything being discarded. The bridge never
// aborts or cleans up provider multipart sessions.

// Sizes are decimal bytes. The configured maximum (BRIDGE_ATTACHMENT_MAX_BYTES,
// trusted configuration) must lie within [DEFAULT, HARD]; see blob.mjs.
export const DEFAULT_MAX_ATTACHMENT_BYTES = 500000000;     // 500 MB
export const MAX_ATTACHMENT_BYTES = 1000000000;            // 1 GB hard cap
export const MAX_LIVE_PER_SENDER = 20;
export const MAX_LIVE_TOTAL = 50;
export const MAX_RESERVED_BYTES = 20000000000;             // 20 GB reserved across live records
export const MAX_RECORDS = 400;                             // live + tombstones, bounds the state row
export const MAX_ATTACHMENT_IDS = 4;                        // per message
export const ATTACHMENT_TTL_MS = 24 * 3600000;              // access window from reservation; never extended
export const UPLOAD_WINDOW_MS = 3600000;                    // single upload: capabilities only within this window
export const URL_TTL_MS = 15 * 60000;                       // any single capability or URL
// Upload modes. single: one PUT within an hour (token-capped at reservation).
// multipart: the provider's native multipart upload, driven and resumed by
// the client; a fresh capability may be issued (fresh authority each time)
// until the fixed access expiry set at reservation, never later.
export const UPLOAD_MODES = ['single', 'multipart'];
// Upload side (begin capabilities and finalize HEADs), per role.
export const RATE_PER_MINUTE = 10;
export const RATE_PER_DAY = 100;
// Download grants, per role (a separate bucket).
export const DOWNLOAD_RATE_PER_MINUTE = 20;
export const DOWNLOAD_RATE_PER_DAY = 400;
// Per attachment. Upload capabilities: 5 for a single PUT; 40 for multipart
// (15-minute capabilities re-issued across wakes). HEADs (one per finalize
// attempt), download grants (80 covers 16 MiB chunks of 1 GB with retries).
// Every attempt counts, including ones that fail after being charged.
export const MAX_PUT_URLS = 5, MAX_MULTIPART_UPLOAD_GRANTS = 40, MAX_HEAD_CALLS = 10, MAX_GET_URLS = 80;
// Byte ranges: any start; a bounded end (chunking) must leave at least this
// many bytes in the chunk unless it reaches the end of the object.
export const MIN_RANGE_BYTES = 16 * 1024 * 1024;
export const RECOMMENDED_CHUNK_BYTES = 64 * 1024 * 1024;
// Opaque content hint: never changes how bytes are stored, served or handled.
export const ATTACHMENT_KINDS = ['file', 'text', 'code'];
// A finalize holds this lease (with a fence) around its HEAD.
export const FINALIZE_LEASE_MS = 30000;
// Physical cleanup scaffolding, used ONLY with an approved retention policy.
export const CLEANUP_PER_RUN = 4;
export const DELETE_RECHECK_MS = 24 * 3600000;              // second DELETE after a late in-flight upload
export const TOMBSTONE_MS = 7 * 86400000;
const BACKOFF_MS = 5 * 60000, MAX_BACKOFF_MS = 6 * 3600000;

const fail = (code, status = 400) => { throw new BridgeError(code, status); };
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const UUID_V4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const FENCE = /^[a-f0-9]{32}$/;
// Opaque provider ETag: printable ASCII, bounded; compared only for equality.
const OPAQUE_ETAG = /^[\x21-\x7e]{1,256}$/;
// rejected: the stored object did not match (quota held). deleting/deleted
// exist only under an approved retention policy.
const STATES = ['reserved', 'available', 'rejected', 'deleting', 'deleted'];
const LIVE = ['reserved', 'available', 'rejected', 'deleting'];
const int = value => Number.isSafeInteger(value) && value >= 0;
// Only plain JSON objects (no arrays, no other prototypes) survive a JSONB round trip intact.
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const snapshot = value => structuredClone(value);
const uploadBudget = r => r.mode === 'multipart' ? MAX_MULTIPART_UPLOAD_GRANTS : MAX_PUT_URLS;

// --- Stored metadata: validated on every use, fail closed --------------------
function validRecord(id, r) {
  const c = r?.cleanup, i = r?.issued, l = r?.lease;
  return plain(r) && plain(i) && plain(c) && r.id === id && UUID_V4.test(id) && r.key === 'att/' + id &&
    HEX64.test(r.namespace || '') && PEER_IDS.includes(r.from) && r.to === counterpart(r.from) &&
    HEX64.test(r.owner || '') && HEX64.test(r.policyId || '') && validName(r.name) && ATTACHMENT_KINDS.includes(r.kind) &&
    UPLOAD_MODES.includes(r.mode) && Number.isSafeInteger(r.size) && r.size >= 1 && r.size <= MAX_ATTACHMENT_BYTES &&
    HEX64.test(r.sha256 || '') && STATES.includes(r.state) &&
    (r.etag === null || OPAQUE_ETAG.test(r.etag || '')) && (r.state !== 'available' || r.etag !== null) &&
    int(r.createdAt) && int(r.uploadUntil) && int(r.expiresAt) && r.createdAt <= r.uploadUntil &&
    r.uploadUntil <= r.expiresAt && r.expiresAt === r.createdAt + ATTACHMENT_TTL_MS &&
    (r.mode === 'multipart' ? r.uploadUntil === r.expiresAt : r.uploadUntil <= r.createdAt + UPLOAD_WINDOW_MS) &&
    (l === null || (plain(l) && FENCE.test(l.fence || '') && int(l.until) && r.state === 'reserved')) &&
    plain(i) && int(i.put) && int(i.head) && int(i.get) && int(c.attempts) && int(c.nextAt) &&
    (c.deletedAt === null || int(c.deletedAt)) && typeof c.rechecked === 'boolean';
}
function validName(name) {
  return typeof name === 'string' && name.length >= 1 && name.length <= 200 && !/[\u0000-\u001f\u007f]/.test(name);
}
const validRate = (rate, perMinute) => plain(rate) && Object.entries(rate).every(([role, r]) => PEER_IDS.includes(role) &&
  plain(r) && Array.isArray(r.minute) && r.minute.length <= perMinute && r.minute.every(int) && int(r.day) && int(r.dayCount));
function store(state) {
  const a = state.attachments;
  if (a === undefined) return null;
  if (!plain(a) || !plain(a.records) || !validRate(a.rate, RATE_PER_MINUTE) ||
      (a.getRate !== undefined && !validRate(a.getRate, DOWNLOAD_RATE_PER_MINUTE)) ||
      Object.keys(a.records).length > MAX_RECORDS || Object.entries(a.records).some(([id, r]) => !validRecord(id, r))) {
    fail('attachment_storage_invalid', 503);
  }
  return a;
}
const storeFor = state => store(state) || (state.attachments = { records: {}, rate: {} });
// A trusted, owner-approved retention policy enabling physical deletion.
// Constructor-only (see createRuntime); no environment variable, setting or
// request can supply one. Exact shape, or it is refused.
export function validRetentionPolicy(policy) {
  return plain(policy) && Object.keys(policy).sort().join() === 'approvedAt,approvedBy,physicalDelete' &&
    policy.physicalDelete === true && validName(policy.approvedBy) && !!policy.approvedBy.trim() &&
    typeof policy.approvedAt === 'string' && Number.isSafeInteger(Date.parse(policy.approvedAt));
}
const live = records => Object.values(records).filter(r => LIVE.includes(r.state));

// --- Authority: re-evaluated in every transaction ----------------------------
// The caller's verified token, its current policy, its scope and durable
// denial of its own principal. Message and sender authority is checked by
// messageAccessAllowed at download (the existing admission rule).
function caller(state, principal, policyIds, scope, now) {
  const a = principal?.[VERIFIED_AUTHORIZATION];
  if (!PEER_IDS.includes(principal?.role) || !HEX64.test(principal.principalKey || '') ||
      !principal.scopes?.includes(SCOPES[principal.role][scope]) || !HEX64.test(policyIds?.[principal.role] || '') ||
      a?.policyId !== policyIds[principal.role] || !Number.isSafeInteger(a.expiresAt) || a.expiresAt <= now ||
      resourceDenied(state, principal.principalKey)) fail('attachment_authorization_inactive', 403);
  return a.expiresAt;
}
// Fixed role slots; no caller-chosen keys. Every attempt is charged when it
// is made, before signing or any provider call, and is never refunded.
const UPLOAD_LIMITS = [RATE_PER_MINUTE, RATE_PER_DAY], DOWNLOAD_LIMITS = [DOWNLOAD_RATE_PER_MINUTE, DOWNLOAD_RATE_PER_DAY];
function limiter(rate, role, now, [perMinute, perDay], take) {
  const day = Math.floor(now / 86400000), r = rate[role] || { minute: [], day, dayCount: 0 };
  const minute = r.minute.filter(at => at > now - 60000), count = r.day === day ? r.dayCount : 0;
  if (minute.length >= perMinute || count >= perDay) fail('attachment_rate_limited', 429);
  if (take) rate[role] = { minute: [...minute, now], day, dayCount: count + 1 };
}
const charge = (a, role, now) => limiter(a.rate, role, now, UPLOAD_LIMITS, true);
const chargeDownload = (a, role, now) => limiter(a.getRate ||= {}, role, now, DOWNLOAD_LIMITS, true);
// Whole seconds strictly inside every bound; under one second is refused, never rounded up.
function urlSeconds(now, ...limits) {
  const seconds = Math.floor((Math.min(now + URL_TTL_MS, ...limits) - now) / 1000);
  if (seconds < 1) fail('attachment_url_window_closed', 409);
  return seconds;
}
function owned(a, id, principal) {
  const r = a.records[id];
  if (!r || r.owner !== principal.principalKey || r.from !== principal.role) fail('attachment_not_found', 404);
  return r;
}
function sameNamespace(r, namespace) { if (r.namespace !== namespace) fail('attachment_namespace_mismatch', 503); }

function validBegin(params) {
  ownKeys(params, ['id', 'name', 'size', 'sha256', 'kind', 'mode'], ['name', 'size', 'sha256']);
  const id = params.id === undefined ? undefined : typeof params.id === 'string' ? params.id.toLowerCase() : null;
  if (id === null || (id !== undefined && !UUID_V4.test(id)) || !validName(params.name) ||
      !Number.isSafeInteger(params.size) || params.size < 1 ||
      typeof params.sha256 !== 'string' || !HEX64.test(params.sha256.toLowerCase()) ||
      (params.kind !== undefined && !ATTACHMENT_KINDS.includes(params.kind)) ||
      (params.mode !== undefined && !UPLOAD_MODES.includes(params.mode))) fail('invalid_attachment');
  return { id, name: params.name, size: params.size, sha256: params.sha256.toLowerCase(), kind: params.kind ?? 'file',
    mode: params.mode ?? 'single' };
}
// Retry identity: the same reservation body exactly (the SHA-256 is the
// collision-resistant content identity).
const sameInput = (r, input) => r.name === input.name && r.size === input.size && r.sha256 === input.sha256 &&
  r.kind === input.kind && r.mode === input.mode;
// The configured maximum, read per use; a size above it is refused for new
// uploads and new message references (never above the hard cap).
function withinMax(size, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < DEFAULT_MAX_ATTACHMENT_BYTES || maxBytes > MAX_ATTACHMENT_BYTES) {
    fail('attachments_not_enabled', 503);
  }
  if (size > maxBytes) fail('attachment_too_large', 413);
}
// Optional byte range for a download grant: { start, end } inclusive, or null
// for the whole object.
function validRange(params, size) {
  const { rangeStart: start = 0, rangeEnd } = params;
  if (!Number.isSafeInteger(start) || start < 0 || start >= size) fail('invalid_range', 416);
  if (rangeEnd === undefined) return start === 0 ? null : { start, end: size - 1 };
  if (!Number.isSafeInteger(rangeEnd) || rangeEnd < start || rangeEnd >= size ||
      (rangeEnd < size - 1 && rangeEnd - start + 1 < MIN_RANGE_BYTES)) fail('invalid_range', 416);
  return start === 0 && rangeEnd === size - 1 ? null : { start, end: rangeEnd };
}

// Send-time admission, inside the message transactions (preparation and final
// insertion): only the sender's own available attachments for exactly this
// recipient, under the current policy and storage namespace, unexpired.
export function admitAttachments(state, envelope, principal, now, { namespace, policyIds, maxBytes }) {
  if (!envelope.attachmentIds) return;
  caller(state, principal, policyIds, 'probe', now);
  const a = store(state);
  for (const id of envelope.attachmentIds) {
    const r = a?.records[id];
    if (!r || r.state !== 'available' || r.from !== envelope.from || r.owner !== principal?.principalKey ||
        r.to !== envelope.to || r.namespace !== namespace || r.policyId !== policyIds?.[r.from] || r.expiresAt <= now) {
      fail('attachment_unavailable', 409);
    }
    withinMax(r.size, maxBytes);
  }
}

// configNow: re-read in every transaction (after the storage lock is held),
// so disabling the flag or changing the store stops work that was waiting.
// retention: a trusted owner-approved policy (validRetentionPolicy) or
// undefined. Undefined (the default, and production) means no DELETE ever.
export function createAttachments({ store: db, clock = Date.now, policyIds, config, provider, configNow = () => config, retention }) {
  if (!config?.valid || !provider || provider.namespace !== config.namespace) fail('attachments_not_configured', 503);
  if (retention !== undefined && !validRetentionPolicy(retention)) fail('attachment_retention_policy_invalid', 503);
  const namespace = config.namespace;
  // Re-read per transaction; returns the current configured maximum.
  const guard = () => {
    const current = configNow();
    if (!current?.valid) fail('attachments_not_enabled', 503);
    if (current.namespace !== namespace) fail('attachment_namespace_mismatch', 503);
    return current.maxBytes;
  };
  // Run fn in a transaction; a returned { error } is committed, then thrown.
  const tx = async fn => {
    const out = await db.transaction(state => fn(state, guard()));
    if (out?.error) fail(out.error, out.status);
    return out;
  };
  // After an await the URL must still be usable for at least one second and
  // inside every fixed bound it was computed from (bounds never move).
  const stillValid = (at, urlExpiresAt, ...limits) => {
    if (urlExpiresAt - at < 1000 || limits.some(limit => limit <= at)) fail('attachment_url_window_closed', 409);
  };
  // Authority after an await without discarding facts recorded in the same
  // transaction: returns an { error } to commit-then-throw, or null.
  const authority = (state, principal, r, at) => {
    try { caller(state, principal, policyIds, 'probe', at); } catch (error) { return { error: error.code, status: error.status }; }
    if (r.policyId !== policyIds[r.from]) return { error: 'attachment_authorization_inactive', status: 403 };
    if (r.expiresAt <= at) return { error: 'attachment_expired', status: 409 };
    return null;
  };
  return {
    // Reserve (durably, before signing) and return one upload capability. A
    // retry with the same id and identical body issues a fresh capability for
    // the same reservation (multipart: across wakes); it can never change
    // owner, recipient, size, digest, mode, or any of the reservation's times.
    async begin(principal, params) {
      const input = validBegin(params);
      // Time is read after the storage lock is held; the same instant bounds the capability.
      const reserved = await tx((state, maxBytes) => {
        const now = clock(), tokenExpiresAt = caller(state, principal, policyIds, 'probe', now);
        withinMax(input.size, maxBytes);
        const a = storeFor(state);
        let r = input.id && a.records[input.id];
        if (r) {
          if (r.owner !== principal.principalKey || r.from !== principal.role) fail('attachment_not_found', 404);
          if (!sameInput(r, input)) fail('attachment_id_conflict', 409);
          sameNamespace(r, namespace);
          if (r.policyId !== policyIds[r.from]) fail('attachment_authorization_inactive', 403);
          if (r.expiresAt <= now) fail('attachment_expired', 409);
          if (r.state === 'available') return { available: snapshot(r), now };
          if (r.state !== 'reserved') fail('attachment_closed', 409);
        } else {
          const open = live(a.records);
          if (Object.keys(a.records).length >= MAX_RECORDS) fail('attachment_capacity_reached', 429);
          if (open.filter(x => x.owner === principal.principalKey).length >= MAX_LIVE_PER_SENDER ||
              open.length >= MAX_LIVE_TOTAL ||
              open.reduce((n, x) => n + x.size, 0) + input.size > MAX_RESERVED_BYTES) fail('attachment_quota_exceeded', 429);
          const id = input.id || randomUUID(), expiresAt = now + ATTACHMENT_TTL_MS;
          r = a.records[id] = { id, key: 'att/' + id, namespace, from: principal.role, to: counterpart(principal.role),
            owner: principal.principalKey, policyId: policyIds[principal.role], name: input.name, kind: input.kind, size: input.size,
            sha256: input.sha256, mode: input.mode, etag: null, state: 'reserved', createdAt: now,
            uploadUntil: input.mode === 'multipart' ? expiresAt : Math.min(now + UPLOAD_WINDOW_MS, tokenExpiresAt), expiresAt,
            lease: null, issued: { put: 0, head: 0, get: 0 }, cleanup: { attempts: 0, nextAt: 0, deletedAt: null, rechecked: false } };
        }
        if (r.issued.put >= uploadBudget(r)) fail('attachment_issue_budget_exhausted', 429);
        const expiresIn = urlSeconds(now, tokenExpiresAt, r.uploadUntil, r.expiresAt);
        charge(a, principal.role, now); r.issued.put++;
        return { record: snapshot(r), expiresIn, now };
      });
      if (reserved.available) return view(reserved.available, reserved.now);
      const { record, expiresIn, now } = reserved;
      const upload = await provider.presignUpload({ key: record.key, size: record.size, validUntil: urlExpiryMs(now, expiresIn) });
      // Recheck after the await: authority, denial, policy, state, namespace,
      // size limit and that the capability is still inside its fixed bounds.
      await tx((state, maxBytes) => {
        const at = clock(), tokenExpiresAt = caller(state, principal, policyIds, 'probe', at);
        const r = owned(store(state) || fail('attachment_not_found', 404), record.id, principal);
        sameNamespace(r, namespace);
        if (r.state !== 'reserved' || r.policyId !== policyIds[r.from]) fail('attachment_closed', 409);
        withinMax(r.size, maxBytes);
        stillValid(at, urlExpiryMs(now, expiresIn), tokenExpiresAt, r.uploadUntil, r.expiresAt);
      });
      const { multipartUrl, ...single } = upload;
      return { ...view(record, now), upload: { ...single, ...(record.mode === 'multipart' ? { multipartUrl } : {}),
        expiresAt: urlExpiry(now, expiresIn) } };
    },
    // Verify that the object exists with the exact declared size (HEAD; the
    // ETag is recorded opaquely) and make the attachment available. Content
    // is NOT verified here: the recipient's SHA-256 check is mandatory.
    // `etag` (optional) is the client's completion evidence: if given and
    // different from the stored object's, nothing changes.
    // Under a fenced lease, each HEAD charged before it is made. A HEAD that
    // shows the exact size is accepted even if a newer finalize took the
    // lease over (an earlier, uncertain completion may land late); a late
    // result never undoes a newer state.
    async finalize(principal, params) {
      ownKeys(params, ['id', 'etag'], ['id']);
      const id = typeof params.id === 'string' ? params.id.toLowerCase() : '';
      if (!UUID_V4.test(id) || (params.etag !== undefined && (typeof params.etag !== 'string' || !OPAQUE_ETAG.test(params.etag)))) {
        fail('invalid_attachment');
      }
      const pending = await tx(state => {
        const now = clock();
        caller(state, principal, policyIds, 'probe', now);
        const a = store(state) || fail('attachment_not_found', 404), r = owned(a, id, principal);
        sameNamespace(r, namespace);
        if (r.policyId !== policyIds[r.from]) fail('attachment_authorization_inactive', 403);
        if (r.expiresAt <= now) fail('attachment_expired', 409);
        if (r.state === 'available') return { available: snapshot(r), now };
        if (r.state !== 'reserved') fail('attachment_closed', 409);
        if (r.lease !== null && r.lease.until > now) fail('attachment_upload_busy', 409);
        if (r.issued.head >= MAX_HEAD_CALLS) fail('attachment_issue_budget_exhausted', 429);
        charge(a, principal.role, now); r.issued.head++;
        r.lease = { fence: randomBytes(16).toString('hex'), until: now + FINALIZE_LEASE_MS };
        return { key: r.key, fence: r.lease.fence };
      });
      if (pending.available) return view(pending.available, pending.now);
      const head = await provider.head(pending.key).catch(() => ({ status: 0 }));
      const done = await tx(state => {
        const at = clock(), a = store(state) || fail('attachment_not_found', 404), r = owned(a, id, principal);
        sameNamespace(r, namespace);
        const mine = r.lease?.fence === pending.fence;
        if (mine) r.lease = null;
        const denied = authority(state, principal, r, at);
        if (denied) return denied;
        if (r.state === 'available') return { record: snapshot(r), at };
        if (r.state !== 'reserved') return { error: 'attachment_closed', status: 409 };
        if (head.status === 200 && head.size === r.size && OPAQUE_ETAG.test(head.etag || '')) {
          if (params.etag !== undefined && params.etag !== head.etag) return { error: 'attachment_upload_mismatch', status: 409 };
          Object.assign(r, { state: 'available', etag: head.etag, lease: null });
          return { record: snapshot(r), at };
        }
        if (!mine) return { error: 'attachment_upload_busy', status: 409 };
        if (head.status === 200) {
          // Not the declared size: closed, never downloadable, quota held.
          // Nothing is deleted without an approved retention policy.
          r.state = 'rejected';
          return { error: 'attachment_verification_failed', status: 409 };
        }
        if (head.status === 404) return { error: 'attachment_not_uploaded', status: 409 };
        return { error: 'attachment_provider_unavailable', status: 503 };
      });
      return view(done.record, done.at);
    },
    // Recipient download URL, bound to the current recipient, the referencing
    // message (existing admission rule, including sender denial and policy)
    // and the recipient's own token/policy/denial. The response carries the
    // headers the client must send (If-Match: the recorded opaque ETag; and
    // for a resume or a chunk, one exact Range); they are not part of the
    // signature, so the client checks the response (206, Content-Range, ETag,
    // size) itself. Every grant is checked and charged on its own.
    async download(principal, params) {
      ownKeys(params, ['messageId', 'attachmentId', 'rangeStart', 'rangeEnd'], ['messageId', 'attachmentId']);
      const ids = [params.messageId, params.attachmentId].map(v => typeof v === 'string' ? v.toLowerCase() : '');
      if (!UUID.test(ids[0]) || !UUID_V4.test(ids[1])) fail('invalid_attachment');
      const [messageId, id] = ids;
      const check = (state, at) => {
        const tokenExpiresAt = caller(state, principal, policyIds, 'ack', at);
        const m = state.messages[messageId];
        if (!m || !dailyMessage(m.envelope) || m.envelope.to !== principal.role || !m.envelope.attachmentIds?.includes(id)) {
          fail('attachment_not_found', 404);
        }
        if (!messageAccessAllowed(state, m, policyIds, at)) fail('message_authorization_inactive', 403);
        const a = store(state), r = a?.records[id];
        if (!r || r.to !== principal.role || r.from !== m.envelope.from || r.owner !== m.authorization.owner) {
          fail('attachment_not_found', 404);
        }
        sameNamespace(r, namespace);
        if (r.state !== 'available' || r.expiresAt <= at || r.policyId !== policyIds[r.from]) fail('attachment_unavailable', 409);
        return { a, r, limits: [tokenExpiresAt, r.expiresAt, m.authorization.expiresAt] };
      };
      const issued = await tx(state => {
        const now = clock(), { a, r, limits } = check(state, now);
        const range = validRange(params, r.size);
        if (r.issued.get >= MAX_GET_URLS) fail('attachment_issue_budget_exhausted', 429);
        const expiresIn = urlSeconds(now, ...limits);
        chargeDownload(a, principal.role, now); r.issued.get++;
        return { record: snapshot(r), expiresIn, now, range };
      });
      const { record, expiresIn, now, range } = issued;
      const download = await provider.presignGet({ key: record.key, validUntil: urlExpiryMs(now, expiresIn) });
      // Recheck after signing: the same object version, still inside every bound.
      await tx(state => {
        const at = clock(), { r, limits } = check(state, at);
        stillValid(at, urlExpiryMs(now, expiresIn), ...limits);
        if (r.etag !== record.etag) fail('attachment_unavailable', 409);
      });
      return { ...view(record, now), messageId, download: { ...download,
        headers: { 'if-match': record.etag, ...(range ? { range: `bytes=${range.start}-${range.end}` } : {}) },
        expiresAt: urlExpiry(now, expiresIn), ...(range ? { range } : {}) } };
    },
    // From the scheduled trigger. Without an approved retention policy (the
    // default): a read-only report; no DELETE, no state change, no quota
    // released. With one: bounded physical cleanup of records whose access
    // expired, or whose object was rejected, at most CLEANUP_PER_RUN provider
    // calls with per-record backoff; quota is released only after a confirmed
    // DELETE, and a second DELETE DELETE_RECHECK_MS later removes an object a
    // late in-flight upload may have committed. Provider multipart sessions
    // are never aborted. Records outside the configured namespace are never
    // touched (fail closed). Tombstones are pruned after TOMBSTONE_MS.
    async cleanup() {
      if (!retention) return db.transaction(state => {
        guard();
        const now = clock(), a = store(state), open = a ? live(a.records) : [];
        return { retention: 'not_approved', deleted: 0, live: open.length,
          accessExpired: open.filter(r => r.expiresAt <= now).length, rejected: open.filter(r => r.state === 'rejected').length,
          reservedBytes: open.reduce((n, r) => n + r.size, 0), otherNamespace: open.filter(r => r.namespace !== namespace).length };
      });
      const due = await db.transaction(state => {
        guard();
        const now = clock();
        const a = store(state);
        if (!a) return { work: [], namespaceMismatch: 0 };
        for (const [id, r] of Object.entries(a.records)) {
          if (r.state === 'deleted' && r.cleanup.rechecked && r.cleanup.deletedAt + DELETE_RECHECK_MS + TOMBSTONE_MS <= now) delete a.records[id];
        }
        let namespaceMismatch = 0;
        const work = Object.values(a.records).filter(r => {
          // A first DELETE waits until uploadUntil: every upload capability
          // expires by then. An upload already accepted may still commit
          // later; the recheck DELETE covers that.
          const wanted = (((r.state === 'reserved' || r.state === 'available') && r.expiresAt <= now) ||
            r.state === 'rejected' || r.state === 'deleting') && r.uploadUntil <= now ||
            (r.state === 'deleted' && !r.cleanup.rechecked && r.cleanup.deletedAt + DELETE_RECHECK_MS <= now);
          if (!wanted || r.cleanup.nextAt > now) return false;
          if (r.namespace !== namespace) { namespaceMismatch++; return false; }
          return true;
        }).sort((x, y) => x.expiresAt - y.expiresAt || (x.id < y.id ? -1 : 1)).slice(0, CLEANUP_PER_RUN);
        for (const r of work) {
          if (r.state !== 'deleted') { r.state = 'deleting'; r.lease = null; }
          r.cleanup.attempts++;
          r.cleanup.nextAt = now + Math.min(MAX_BACKOFF_MS, BACKOFF_MS * 2 ** Math.min(r.cleanup.attempts - 1, 10));
        }
        return { work: work.map(r => ({ id: r.id, key: r.key, state: r.state })), namespaceMismatch };
      });
      const outcomes = await Promise.allSettled(due.work.map(item => provider.delete(item.key)));
      const confirmed = due.work.filter((_, n) => outcomes[n].status === 'fulfilled' &&
        ((outcomes[n].value.status >= 200 && outcomes[n].value.status < 300) || outcomes[n].value.status === 404));
      const failed = due.work.length - confirmed.length;
      const result = await db.transaction(state => {
        guard();
        const a = store(state), at = clock();
        let deleted = 0, rechecked = 0;
        for (const item of confirmed) {
          const r = a?.records[item.id];
          if (!r || r.namespace !== namespace || r.state !== item.state) continue;
          if (r.state === 'deleting') { Object.assign(r, { state: 'deleted' }); r.cleanup.deletedAt = at; r.cleanup.nextAt = 0; deleted++; }
          else { r.cleanup.rechecked = true; rechecked++; }
        }
        const overdue = a ? live(a.records).filter(r => r.expiresAt <= at || r.state === 'deleting' || r.state === 'rejected').length : 0;
        return { deleted, rechecked, pending: overdue };
      });
      return { retention: 'approved', ...result, failed, namespaceMismatch: due.namespaceMismatch };
    },
  };
}
const urlExpiryMs = (now, seconds) => Math.floor(now / 1000) * 1000 + seconds * 1000;
const urlExpiry = (now, seconds) => new Date(urlExpiryMs(now, seconds)).toISOString();
// accessExpired: past its access window (no new URLs); the record and its
// reserved quota remain unless an approved retention policy deletes them.
function view(r, now) {
  return { attachmentId: r.id, state: r.state, name: r.name, kind: r.kind, size: r.size, sha256: r.sha256, mode: r.mode,
    expiresAt: new Date(r.expiresAt).toISOString(), accessExpired: r.expiresAt <= now };
}
