import { createHash } from 'node:crypto';
import { jwtVerify } from 'jose';
import type { JWTPayload, JWTVerifyGetKey } from 'jose';
import { CONFIG, PEER_IDS } from './config.ts';
import type { PeerScopes } from './config.ts';
import type { JsonObject, Principal, ProbeEnvelope, ProbeKind, Role, VerifiedAuthorization, VerifiedPrincipal } from './types.ts';

// Resource-server verification only. The OAuth provider owns PKCE, consent,
// issuance and refresh. No authorization server, signing key or token issuer exists here.
export type BridgeErrorDetails = Readonly<Record<string, unknown>>;
export class BridgeError extends Error {
  declare code: string;
  declare status: number;
  declare details: BridgeErrorDetails | undefined;
  // Set only on the events callback verification error (JSON-RPC mapping).
  declare rpcCode?: number;
  declare reason?: string;
  // details: optional fixed ID fields for conflicts that redirect the caller.
  constructor(code: string, status: number, details: BridgeErrorDetails | undefined = undefined) { super(code); this.code = code; this.status = status; this.details = details; }
}
// Explicitly typed so a bare reject(...) statement narrows control flow.
const reject: (code: string, status?: number) => never = (code, status = 400) => { throw new BridgeError(code, status); };
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
export interface PolicyIdentity {
  issuer: string; audience: string; subject?: string | undefined; subjectHash?: string | undefined; role: Role;
  scopeClaim?: string; algorithms?: string[];
}
export function authorizationPolicyId({ issuer, audience, subject, subjectHash, role, scopeClaim = 'scope', algorithms = ['RS256'] }: PolicyIdentity): string {
  const pin = subject ? createHash('sha256').update(subject).digest('hex') : subjectHash;
  return createHash('sha256').update(JSON.stringify([issuer, audience, pin, role, scopeClaim, algorithms])).digest('hex');
}

// JWT audience and scope-claim settings must be confirmed against the provider's
// actual issued test token via safe SDK output before enabling a live route. Values in
// the caller's request cannot choose issuer, key source, audience or role.
/**
 * The verification key source passed to jose's jwtVerify: a JWKS resolver in
 * production, a public key in tests. jose's overloads type each form
 * separately; its runtime accepts every form, so the two call sites assert
 * the resolver overload (localized SDK interop).
 */
export type KeyResolver = JWTVerifyGetKey | Parameters<typeof jwtVerify>[1];
export interface TimingObservation { readonly role: Role; readonly issuedAt: number; readonly expiresAt: number }
export interface AccessVerifierOptions extends PolicyIdentity {
  keyResolver: KeyResolver;
  currentDate?: Date | undefined;
  observeTiming?: ((observation: TimingObservation) => void) | undefined;
}
export type AccessVerifier = (request: Request) => Promise<VerifiedPrincipal>;
export function createAccessVerifier({ issuer, audience, subject, subjectHash, role, keyResolver,
  scopeClaim = 'scope', algorithms = ['RS256'], currentDate, observeTiming }: AccessVerifierOptions): AccessVerifier {
  const hashValid = typeof subjectHash === 'string' && /^[a-f0-9]{64}$/.test(subjectHash);
  if (!issuer || !audience || (!subject && !hashValid) || (subject && subjectHash) ||
      !ROLES.includes(role) || !keyResolver || !['scope', 'scp', 'scopes'].includes(scopeClaim)) {
    reject('provider_configuration_required', 503);
  }
  const u = new URL(issuer);
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) {
    reject('invalid_provider_configuration', 503);
  }
  return async (request: Request): Promise<VerifiedPrincipal> => {
    const header = request.headers.get('authorization') || '';
    if (!/^Bearer [A-Za-z0-9_.-]+$/.test(header) || header.length > 16384) reject('unauthorized', 401);
    let payload!: JWTPayload;
    try {
      ({ payload } = await jwtVerify(header.slice(7), keyResolver as JWTVerifyGetKey, {
        issuer, audience, algorithms, requiredClaims: ['exp', 'iat', 'sub'],
        clockTolerance: 5, ...(currentDate ? { currentDate } : {}),
      }));
    } catch { reject('unauthorized', 401); }
    // Retain the verifier's other skew checks, but never admit an expired
    // access token as a principal. Hard expiry must produce the existing 401
    // resource-metadata challenge, not a later 403 from a domain lease fence.
    // requiredClaims makes jose reject a token without a numeric exp.
    const expiresAt = (payload.exp as number) * 1000;
    const checkedAt = currentDate ? currentDate.getTime() : Date.now();
    if (!Number.isSafeInteger(expiresAt) || !Number.isSafeInteger(checkedAt) || expiresAt <= checkedAt) reject('unauthorized', 401);
    if (typeof payload.sub !== 'string' || (subject ? payload.sub !== subject
      : createHash('sha256').update(payload.sub).digest('hex') !== subjectHash)) reject('forbidden_subject', 403);
    const granted = payload[scopeClaim];
    const scopes: string[] = typeof granted === 'string' ? granted.split(/\s+/).filter(Boolean)
      : Array.isArray(granted) && granted.every((x): x is string => typeof x === 'string') ? granted : [];
    if (!scopes.length) reject('insufficient_scope', 403);
    // Optional temporary timing evidence only, after full policy verification.
    // Never pass tokens, identity, arbitrary claims or request values to logs.
    if (typeof observeTiming === 'function' && Number.isSafeInteger(payload.iat) &&
        Number.isSafeInteger(payload.exp) && (payload.exp as number) > (payload.iat as number)) {
      // Both were just checked to be safe integers.
      try { observeTiming(Object.freeze({ role, issuedAt: payload.iat as number, expiresAt: payload.exp as number })); }
      catch {} // Diagnostic failures cannot change authorization behavior.
    }
    // Return minimal verified policy context, never the token or full claims.
    const principalKey = createHash('sha256').update(JSON.stringify([issuer, audience, payload.sub, role])).digest('hex');
    const principal: Principal = { role, scopes: Object.freeze([...new Set(scopes)]), principalKey };
    // Internal expiry only. Hard subscription deadlines never inherit tolerance.
    Object.defineProperty(principal, VERIFIED_AUTHORIZATION, { value: Object.freeze({ expiresAt,
      policyId: authorizationPolicyId({ issuer, audience, subject, subjectHash, role, scopeClaim, algorithms }) }) });
    // The verified authorization was attached on the line above (the only place it is).
    return Object.freeze(principal as VerifiedPrincipal);
  };
}

// Temporary bootstrap observation only. Every request remains503: no principal,
// tool call, DB access, callback or token is returned. Only verified policy facts
// and a subject digest can reach the supplied allowlisted telemetry sink.
export interface ContractObserverOptions {
  issuer: string; audience: string; role: Role; keyResolver: KeyResolver;
  emit?: (observation: Readonly<Record<string, unknown>>) => void;
}
type ClaimError = { claim?: string } | null | undefined;
export function createContractObserver({ issuer, audience, role, keyResolver, emit = () => {} }: ContractObserverOptions) {
  return async (request: Request): Promise<Response> => {
    const header = request.headers.get('authorization') || '';
    if (header.length <= 16384 && /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(header)) {
      try {
        const { payload } = await jwtVerify(header.slice(7), keyResolver as JWTVerifyGetKey, { issuer, audience,
          algorithms: ['RS256'], requiredClaims: ['exp', 'iat', 'sub'], clockTolerance: 5 });
        if (typeof payload.sub === 'string' && ROLES.includes(role)) {
          const claims = ['scope', 'scp', 'scopes'].map(name => {
            const value = payload[name];
            const validArray = Array.isArray(value) && value.every((x): x is string => typeof x === 'string');
            const values: string[] = typeof value === 'string' ? value.split(/\s+/) : validArray ? value : [];
            // ROLES.includes(role) was checked above, so SCOPES[role] exists.
            return { name, form: typeof value === 'string' ? 'string' : validArray ? 'array' : 'absent_or_other',
              probeScope: values.includes((SCOPES[role] as PeerScopes).probe), ackScope: values.includes((SCOPES[role] as PeerScopes).ack),
              offlineScope: values.includes('offline_access') };
          });
          emit({ verified: true, role, issuerMatched: true, audienceMatched: true,
            subjectDigest: createHash('sha256').update(payload.sub).digest('hex'), claims });
        }
      } catch (error) {
        // jose's JWTClaimValidationFailed carries `claim`; anything else lacks it.
        const safeClaim = ['iss', 'aud', 'exp', 'iat', 'sub', 'nbf'].includes((error as ClaimError)?.claim as string)
          ? (error as { claim?: string }).claim : 'signature_or_format';
        emit({ verified: false, role, rejectedCheck: safeClaim });
      }
    }
    return Response.json({ error: 'bridge_configuration_required' }, { status: 503,
      headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
  };
}

export interface ValidatedProbe { readonly envelope: ProbeEnvelope; readonly hash: string }
/**
 * The untrusted probe body after the object check. Field types are what the
 * checks below establish; the JavaScript expressions (and their coercions and
 * TypeErrors on unexpected input) are unchanged from the original.
 */
interface ProbeInput { id: string; testId: string; from: Role; to: Role; kind: ProbeKind; sentAt: string; correlationId: string; marker: string }
type In = ProbeInput & JsonObject;
export function validateEnvelope(input: unknown, principal: Principal | null | undefined, now = Date.now()): ValidatedProbe {
  if (!input || Array.isArray(input) || typeof input !== 'object' || !principal ||
      !ROLES.includes(principal.role) || !Array.isArray(principal.scopes)) reject('invalid_envelope');
  const keys = ['id', 'testId', 'from', 'to', 'kind', 'sentAt', 'correlationId', 'marker'];
  if (Object.keys(input as In).some(k => !keys.includes(k)) || !UUID.test((input as In).id || '') ||
      (input as In).testId !== SYNTHETIC_TEST_ID || (input as In).from !== principal.role ||
      !ROLES.includes((input as In).to) || (input as In).to === (input as In).from ||
      !['probe', 'ack'].includes((input as In).kind) || (input as In).marker !== SYNTHETIC_MARKER) {
    reject('invalid_envelope');
  }
  const time = Date.parse((input as In).sentAt);
  if (!Number.isFinite(time) || Math.abs(now - time) > 5 * 60 * 1000) reject('stale_or_future_message');
  if ((input as In).kind === 'ack' ? !UUID.test((input as In).correlationId || '') : (input as In).correlationId !== undefined) {
    reject('invalid_correlation');
  }
  if (!principal.scopes.includes((SCOPES[principal.role] as PeerScopes)[(input as In).kind])) reject('insufficient_scope', 403);
  const envelope: ProbeEnvelope = { id: (input as In).id.toLowerCase(), testId: (input as In).testId, from: (input as In).from,
    to: (input as In).to, kind: (input as In).kind, sentAt: new Date(time).toISOString(),
    ...((input as In).kind === 'ack' ? { correlationId: (input as In).correlationId.toLowerCase() } : {}),
    marker: (input as In).marker };
  return Object.freeze({ envelope, hash: createHash('sha256').update(JSON.stringify(envelope)).digest('hex') });
}

