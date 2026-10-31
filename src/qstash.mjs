import { createHash } from 'node:crypto';
import { jwtVerify } from 'jose';
import { BridgeError } from './policy.mjs';

// Upstash QStash scheduled trigger for POST /api/cron (provider-specific
// authentication; the flush route itself stays scheduler-neutral and still
// accepts the CRON_SECRET bearer). Implemented with the existing `jose`
// dependency instead of the QStash SDK, following its Receiver semantics
// (current key, then next key; issuer "Upstash"; `sub` equal to the
// destination URL; `body` = SHA-256 of the raw body, unpadded base64url),
// and stricter: HS256 only, every claim required and bounded, the
// destination always checked against trusted configuration (never derived
// from the request URL, which a proxy can change), no development keys, and
// an exact static control body. Upstash-Message-Id, Upstash-Schedule-Id and
// Upstash-Retried are unsigned and never used for any decision.

// The only body a schedule may carry: static control metadata, no content.
export const QSTASH_TICK_BODY = '{"kind":"bridge.scheduled-tick","v":1}';
export const MAX_TICK_BODY_BYTES = 1024;
export const MAX_SIGNATURE_BYTES = 4096;
export const CLOCK_TOLERANCE_S = 5;
// QStash tokens last 5 minutes by default; anything claiming longer is refused.
export const MAX_TOKEN_LIFETIME_S = 15 * 60;
const KEY = /^[\x21-\x7e]{16,256}$/;
const JWS = /^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}$/;
const JTI = /^[A-Za-z0-9_.:-]{1,128}$/;
const BODY_HASH = /^[A-Za-z0-9_-]{43}=?$/;
const reject = code => { throw new BridgeError(code, 401); };

// Trusted configuration, read per invocation: the current and next signing
// keys (QSTASH_CURRENT_SIGNING_KEY / QSTASH_NEXT_SIGNING_KEY) and the exact
// public destination URL the schedule targets (BRIDGE_QSTASH_DESTINATION_URL,
// https, path /api/cron, nothing else). Missing or malformed: not valid, and
// signed requests are refused before any storage access.
export function qstashConfig(env) {
  const current = env.QSTASH_CURRENT_SIGNING_KEY, next = env.QSTASH_NEXT_SIGNING_KEY;
  const destination = env.BRIDGE_QSTASH_DESTINATION_URL;
  let url = null;
  try { url = new URL(destination); } catch { /* invalid below */ }
  const valid = KEY.test(current || '') && KEY.test(next || '') && !!url && url.href === destination &&
    url.protocol === 'https:' && !url.username && !url.password && !url.port && !url.search && !url.hash &&
    url.pathname === '/api/cron';
  return valid ? { valid, current, next, destination } : { valid: false };
}

const base64url = bytes => Buffer.from(bytes).toString('base64url');
const int = value => Number.isSafeInteger(value) && value >= 0;

// Verify one delivery. `body` is the raw request bytes (a Buffer). Returns
// { key, jti, expiresAt } (key: the signing key that verified, to recheck
// after any later await). Throws BridgeError 401 on any failure; never
// touches storage.
export async function verifyQStashTick({ config, signature, body, now }) {
  if (!config?.valid) throw new BridgeError('scheduler_not_configured', 503);
  if (typeof signature !== 'string' || Buffer.byteLength(signature) > MAX_SIGNATURE_BYTES || !JWS.test(signature)) {
    reject('scheduler_signature_invalid');
  }
  if (!Buffer.isBuffer(body) || body.length > MAX_TICK_BODY_BYTES) reject('scheduler_body_invalid');
  let payload = null, key = null;
  for (const candidate of [config.current, config.next]) {
    try {
      ({ payload } = await jwtVerify(signature, new TextEncoder().encode(candidate), {
        algorithms: ['HS256'], issuer: 'Upstash', subject: config.destination, clockTolerance: CLOCK_TOLERANCE_S,
        requiredClaims: ['iss', 'sub', 'exp', 'nbf', 'iat', 'jti', 'body'], currentDate: new Date(now) }));
      key = candidate; break;
    } catch { /* try the next key */ }
  }
  if (!payload) reject('scheduler_signature_invalid');
  const seconds = Math.floor(now / 1000), { iat, nbf, exp, jti } = payload;
  if (!int(iat) || !int(nbf) || !int(exp) || exp <= nbf || nbf < iat - CLOCK_TOLERANCE_S ||
      exp - iat > MAX_TOKEN_LIFETIME_S || iat > seconds + CLOCK_TOLERANCE_S ||
      typeof jti !== 'string' || !JTI.test(jti) || typeof payload.body !== 'string' || !BODY_HASH.test(payload.body)) {
    reject('scheduler_signature_invalid');
  }
  const digest = base64url(createHash('sha256').update(body).digest());
  if (payload.body.replace(/=+$/, '') !== digest) reject('scheduler_body_invalid');
  if (body.toString('utf8') !== QSTASH_TICK_BODY) reject('scheduler_body_invalid');
  return { key, jti, expiresAt: exp * 1000 };
}

// Total time allowed to receive the (tiny) body, whatever the platform does.
export const BODY_READ_TIMEOUT_MS = 5000;
// Raw request bytes, bounded in size (declared and streamed) and in total
// time. Oversize is refused without reading further; a slow or stalled body
// is cancelled at the deadline (408, retryable), before any storage access.
export async function boundedBody(request, limit = MAX_TICK_BODY_BYTES, timeoutMs = BODY_READ_TIMEOUT_MS) {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^\d{1,10}$/.test(declared) || Number(declared) > limit)) reject('scheduler_body_too_large');
  const reader = request.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const deadline = Date.now() + timeoutMs, chunks = []; let size = 0;
  try {
    for (;;) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new BridgeError('scheduler_body_timeout', 408);
      let timer;
      const read = reader.read();
      read.catch(() => {});
      const { done, value } = await Promise.race([read, new Promise((_, fail) => {
        timer = setTimeout(() => fail(new BridgeError('scheduler_body_timeout', 408)), remaining);
      })]).finally(() => clearTimeout(timer));
      if (done) break;
      size += value.length;
      if (size > limit) reject('scheduler_body_too_large');
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    reader.cancel().catch(() => {});
    throw error;
  }
  return Buffer.concat(chunks);
}

// Accepted tick IDs (jti) are remembered until their token expires, so a
// captured delivery replayed within its lifetime is a no-op. This is replay
// suppression only: QStash's own 10-minute publish deduplication and the
// unsigned message ID are not business identity, and every flush, outbox
// job and receipt stays idempotent on its own durable IDs.
// Keys are prefixed, so every accepted jti (including '__proto__' or
// 'constructor') is an ordinary own property, never an inherited one.
const MAX_TICKS = 512, tickKey = jti => 'j:' + jti;
export function tickSeen(state, jti, now) {
  const ticks = state.schedulerTicks, key = tickKey(jti);
  return !!ticks && typeof ticks === 'object' && Object.hasOwn(ticks, key) && Number(ticks[key]) > now;
}
export function recordTick(state, jti, expiresAt, now) {
  const ticks = state.schedulerTicks && typeof state.schedulerTicks === 'object' && !Array.isArray(state.schedulerTicks)
    ? state.schedulerTicks : {};
  for (const [id, until] of Object.entries(ticks)) if (!id.startsWith('j:') || !(Number(until) > now)) delete ticks[id];
  const ids = Object.keys(ticks);
  if (ids.length >= MAX_TICKS) for (const id of ids.sort((a, b) => ticks[a] - ticks[b]).slice(0, ids.length - MAX_TICKS + 1)) delete ticks[id];
  Object.defineProperty(ticks, tickKey(jti), { value: expiresAt, enumerable: true, writable: true, configurable: true });
  state.schedulerTicks = ticks;
}
