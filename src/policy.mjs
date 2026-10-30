import { createHash } from 'node:crypto';
import { jwtVerify } from 'jose';
import { CONFIG, PEER_IDS } from './config.mjs';

// Resource-server verification only. The OAuth provider owns PKCE, consent,
// issuance and refresh. No authorization server, signing key or token issuer exists here.
export class BridgeError extends Error {
  constructor(code, status) { super(code); this.code = code; this.status = status; }
}
const reject = (code, status = 400) => { throw new BridgeError(code, status); };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLES = PEER_IDS;
// Per peer: probe = bridge:send:<counterpart>, ack = bridge:ack:<self>.
export const SCOPES = CONFIG.scopes;
// Fixed wire markers of the synthetic probe envelope (kind probe/ack). They are
// constants, not deployment identity, so stored probes stay verifiable.
export const SYNTHETIC_TEST_ID = 'RN-JARVIS-FRIDAY-SYNTHETIC';
export const SYNTHETIC_MARKER = 'RN-SYNTHETIC-NO-ACTIONS';
export const VERIFIED_AUTHORIZATION = Symbol('verified bridge authorization');
// Internal adapter evidence; JSON requests and HTTP bodies cannot supply it.
export const DELIVERY_TRANSPORT_OUTCOME = Symbol('delivery transport outcome');
export function authorizationPolicyId({ issuer, audience, subject, subjectHash, role, scopeClaim = 'scope', algorithms = ['RS256'] }) {
  const pin = subject ? createHash('sha256').update(subject).digest('hex') : subjectHash;
  return createHash('sha256').update(JSON.stringify([issuer, audience, pin, role, scopeClaim, algorithms])).digest('hex');
}

// JWT audience and scope-claim settings must be confirmed against the provider's
// actual issued test token via safe SDK output before enabling a live route. Values in
// the caller's request cannot choose issuer, key source, audience or role.
export function createAccessVerifier({ issuer, audience, subject, subjectHash, role, keyResolver,
  scopeClaim = 'scope', algorithms = ['RS256'], currentDate, observeTiming }) {
  const hashValid = typeof subjectHash === 'string' && /^[a-f0-9]{64}$/.test(subjectHash);
  if (!issuer || !audience || (!subject && !hashValid) || (subject && subjectHash) ||
      !ROLES.includes(role) || !keyResolver || !['scope', 'scp', 'scopes'].includes(scopeClaim)) {
    reject('provider_configuration_required', 503);
  }
  const u = new URL(issuer);
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) {
    reject('invalid_provider_configuration', 503);
  }
  return async request => {
    const header = request.headers.get('authorization') || '';
    if (!/^Bearer [A-Za-z0-9_.-]+$/.test(header) || header.length > 16384) reject('unauthorized', 401);
    let payload;
    try {
      ({ payload } = await jwtVerify(header.slice(7), keyResolver, {
        issuer, audience, algorithms, requiredClaims: ['exp', 'iat', 'sub'],
        clockTolerance: 5, ...(currentDate ? { currentDate } : {}),
      }));
    } catch { reject('unauthorized', 401); }
    // Retain the verifier's other skew checks, but never admit an expired
    // access token as a principal. Hard expiry must produce the existing 401
    // resource-metadata challenge, not a later 403 from a domain lease fence.
    const expiresAt = payload.exp * 1000;
    const checkedAt = currentDate ? currentDate.getTime() : Date.now();
    if (!Number.isSafeInteger(expiresAt) || !Number.isSafeInteger(checkedAt) || expiresAt <= checkedAt) reject('unauthorized', 401);
    if (typeof payload.sub !== 'string' || (subject ? payload.sub !== subject
      : createHash('sha256').update(payload.sub).digest('hex') !== subjectHash)) reject('forbidden_subject', 403);
    const granted = payload[scopeClaim];
    const scopes = typeof granted === 'string' ? granted.split(/\s+/).filter(Boolean)
      : Array.isArray(granted) && granted.every(x => typeof x === 'string') ? granted : [];
    if (!scopes.length) reject('insufficient_scope', 403);
    // Optional temporary timing evidence only, after full policy verification.
    // Never pass tokens, identity, arbitrary claims or request values to logs.
    if (typeof observeTiming === 'function' && Number.isSafeInteger(payload.iat) &&
        Number.isSafeInteger(payload.exp) && payload.exp > payload.iat) {
      try { observeTiming(Object.freeze({ role, issuedAt: payload.iat, expiresAt: payload.exp })); }
      catch {} // Diagnostic failures cannot change authorization behavior.
    }
    // Return minimal verified policy context, never the token or full claims.
    const principalKey = createHash('sha256').update(JSON.stringify([issuer, audience, payload.sub, role])).digest('hex');
    const principal = { role, scopes: Object.freeze([...new Set(scopes)]), principalKey };
    // Internal expiry only. Hard subscription deadlines never inherit tolerance.
    Object.defineProperty(principal, VERIFIED_AUTHORIZATION, { value: Object.freeze({ expiresAt,
      policyId: authorizationPolicyId({ issuer, audience, subject, subjectHash, role, scopeClaim, algorithms }) }) });
    return Object.freeze(principal);
  };
}

// Temporary bootstrap observation only. Every request remains503: no principal,
// tool call, DB access, callback or token is returned. Only verified policy facts
// and a subject digest can reach the supplied allowlisted telemetry sink.
export function createContractObserver({ issuer, audience, role, keyResolver, emit = () => {} }) {
  return async request => {
    const header = request.headers.get('authorization') || '';
    if (header.length <= 16384 && /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(header)) {
      try {
        const { payload } = await jwtVerify(header.slice(7), keyResolver, { issuer, audience,
          algorithms: ['RS256'], requiredClaims: ['exp', 'iat', 'sub'], clockTolerance: 5 });
        if (typeof payload.sub === 'string' && ROLES.includes(role)) {
          const claims = ['scope', 'scp', 'scopes'].map(name => {
            const value = payload[name];
            const validArray = Array.isArray(value) && value.every(x => typeof x === 'string');
            const values = typeof value === 'string' ? value.split(/\s+/) : validArray ? value : [];
            return { name, form: typeof value === 'string' ? 'string' : validArray ? 'array' : 'absent_or_other',
              probeScope: values.includes(SCOPES[role].probe), ackScope: values.includes(SCOPES[role].ack),
              offlineScope: values.includes('offline_access') };
          });
          emit({ verified: true, role, issuerMatched: true, audienceMatched: true,
            subjectDigest: createHash('sha256').update(payload.sub).digest('hex'), claims });
        }
      } catch (error) {
        const safeClaim = ['iss', 'aud', 'exp', 'iat', 'sub', 'nbf'].includes(error?.claim) ? error.claim : 'signature_or_format';
        emit({ verified: false, role, rejectedCheck: safeClaim });
      }
    }
    return Response.json({ error: 'bridge_configuration_required' }, { status: 503,
      headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
  };
}

export function validateEnvelope(input, principal, now = Date.now()) {
  if (!input || Array.isArray(input) || typeof input !== 'object' || !principal ||
      !ROLES.includes(principal.role) || !Array.isArray(principal.scopes)) reject('invalid_envelope');
  const keys = ['id', 'testId', 'from', 'to', 'kind', 'sentAt', 'correlationId', 'marker'];
  if (Object.keys(input).some(k => !keys.includes(k)) || !UUID.test(input.id || '') ||
      input.testId !== SYNTHETIC_TEST_ID || input.from !== principal.role ||
      !ROLES.includes(input.to) || input.to === input.from ||
      !['probe', 'ack'].includes(input.kind) || input.marker !== SYNTHETIC_MARKER) {
    reject('invalid_envelope');
  }
  const time = Date.parse(input.sentAt);
  if (!Number.isFinite(time) || Math.abs(now - time) > 5 * 60 * 1000) reject('stale_or_future_message');
  if (input.kind === 'ack' ? !UUID.test(input.correlationId || '') : input.correlationId !== undefined) {
    reject('invalid_correlation');
  }
  if (!principal.scopes.includes(SCOPES[principal.role][input.kind])) reject('insufficient_scope', 403);
  const envelope = { id: input.id.toLowerCase(), testId: input.testId, from: input.from,
    to: input.to, kind: input.kind, sentAt: new Date(time).toISOString(),
    ...(input.kind === 'ack' ? { correlationId: input.correlationId.toLowerCase() } : {}),
    marker: input.marker };
  return Object.freeze({ envelope, hash: createHash('sha256').update(JSON.stringify(envelope)).digest('hex') });
}

