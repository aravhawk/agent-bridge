import { dailyMessage, messageScope } from './messages.ts';
import { BridgeError, SCOPES, VERIFIED_AUTHORIZATION } from './policy.ts';
import { resourceFor } from './resource.ts';
import { EVENTS_PEER, PEER_IDS, counterpart } from './config.ts';
import type { PeerScopes } from './config.ts';
import type { BridgeState, Envelope, LeaseAuthorization, MessageAuthorization, Millis, PolicyIds, Principal, Role, Store,
  StoredMessage, Subscription, VerifiedAuthorization } from './types.ts';

/** The only state section the access checks read (the worker passes a recheck snapshot). */
export interface DenialView { readonly resourceDenials?: BridgeState['resourceDenials'] | undefined }
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function testEnvelopeAllowed(envelope: Envelope | null | undefined, probeId: string | null | undefined, sender: Role = EVENTS_PEER): boolean {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(probeId || '') ||
      !PEER_IDS.includes(sender)) return false;
  const recipient = counterpart(sender);
  return !!envelope && ((envelope.kind === 'probe' && envelope.id === probeId &&
      envelope.from === sender && envelope.to === recipient) ||
    (envelope.kind === 'ack' && envelope.correlationId === probeId &&
      envelope.from === recipient && envelope.to === sender));
}
export function verifiedMessageAuthorization(principal: Principal | null | undefined, envelope: Envelope, now: Millis,
  deliveryUntil = Infinity): MessageAuthorization {
  const a = principal?.[VERIFIED_AUTHORIZATION];
  // Math.min of undefined is NaN, which the safe-integer check below refuses.
  const expiresAt = Math.min(a?.expiresAt as number, deliveryUntil, dailyMessage(envelope) ? Date.parse(envelope.expiresAt) : Infinity);
  const scope = messageScope(principal?.role, envelope.kind);
  // A defined scope implies a principal with a role (messageScope of undefined is undefined).
  if (!scope || envelope.from !== (principal as Principal).role || !(principal as Principal).scopes?.includes(scope) ||
      !hash((principal as Principal).principalKey) || !hash(a?.policyId) ||
      !Number.isSafeInteger((a as VerifiedAuthorization).expiresAt) || !Number.isSafeInteger(expiresAt) || expiresAt <= now) {
    throw new BridgeError('message_authorization_required', 403);
  }
  // Both checked above.
  return { owner: principal!.principalKey, role: principal!.role, resource: resourceFor(principal!.role),
    scope, policyId: a!.policyId, tokenExpiresAt: a!.expiresAt, expiresAt };
}
// `!!a` (message?.authorization) implies the message is present.
export function messageAccessAllowed(state: DenialView, message: StoredMessage | null | undefined, policyIds: PolicyIds | null | undefined,
  now: Millis): message is StoredMessage {
  const a = message?.authorization, e = message?.envelope;
  return !!a && PEER_IDS.includes(e?.from as Role) && (dailyMessage(e) ? ['message', 'status', 'handoff_request', 'ack'].includes(e.kind) : ['probe', 'ack'].includes(e?.kind as string)) &&
    a.role === e!.from && hash(a.owner) && hash(policyIds?.[e!.from]) && a.policyId === policyIds![e!.from] &&
    a.resource === resourceFor(e!.from) && a.scope === messageScope(e!.from, e!.kind) &&
    Number.isSafeInteger(message!.storedAt) && Number.isSafeInteger(a.tokenExpiresAt) && Number.isSafeInteger(a.expiresAt) &&
    a.expiresAt <= a.tokenExpiresAt && (!dailyMessage(e) || a.expiresAt <= Date.parse(e.expiresAt)) && a.expiresAt > message!.storedAt && a.expiresAt > now && !resourceDenied(state, a.owner);
}
export function verifiedLease(principal: Principal | null | undefined, policyId: string, now: Millis): LeaseAuthorization {
  const authorization = principal?.[VERIFIED_AUTHORIZATION];
  // authorization?.policyId === policyId (a valid hash) implies authorization is present.
  if (!hash(policyId) || authorization?.policyId !== policyId ||
      !Number.isSafeInteger(authorization!.expiresAt) || authorization!.expiresAt <= now ||
      principal?.role !== EVENTS_PEER || !hash(principal.principalKey) ||
      !principal.scopes?.includes((SCOPES[EVENTS_PEER] as PeerScopes).ack)) throw new BridgeError('authorization_lease_required', 403);
  return { owner: principal.principalKey, recipient: EVENTS_PEER, resource: resourceFor(EVENTS_PEER),
    scope: (SCOPES[EVENTS_PEER] as PeerScopes).ack, policyId, tokenExpiresAt: authorization!.expiresAt };
}
export function resourceDenied(state: DenialView, owner: string): boolean {
  if (state.resourceDenials !== undefined && (!state.resourceDenials || typeof state.resourceDenials !== 'object' || Array.isArray(state.resourceDenials))) return true;
  return Object.hasOwn(state.resourceDenials || {}, owner);
}
/** A subscription whose lease metadata validated: authorization and expiry are present. */
export type ActiveSubscription = Subscription & { authorization: LeaseAuthorization; expiresAt: Millis };
// `!!a` (subscription?.authorization) implies subscription is present for the rest.
export function validLeaseMetadata(subscription: Subscription | null | undefined, policyId: string | undefined): subscription is ActiveSubscription {
  const a = subscription?.authorization;
  return !!a && hash(policyId) && a.policyId === policyId && hash(subscription!.owner) &&
    /^sub_[a-f0-9]{64}$/.test(subscription!.id || '') && subscription!.name === 'bridge.message.received' &&
    subscription!.arguments?.recipient === EVENTS_PEER && Object.keys(subscription!.arguments).length === 1 &&
    a.owner === subscription!.owner && a.recipient === EVENTS_PEER && subscription!.recipient === EVENTS_PEER &&
    a.resource === resourceFor(EVENTS_PEER) && a.scope === (SCOPES[EVENTS_PEER] as PeerScopes).ack &&
    Number.isSafeInteger(a.tokenExpiresAt) && Number.isSafeInteger(subscription!.expiresAt) &&
    (subscription!.expiresAt as Millis) <= a.tokenExpiresAt;
}
export function subscriptionAccessAllowed(state: DenialView, subscription: Subscription | null | undefined, policyId: string | undefined,
  now: Millis): subscription is ActiveSubscription {
  return validLeaseMetadata(subscription, policyId) && subscription.status === 'active' &&
    subscription.active === true && !resourceDenied(state, subscription.owner) &&
    subscription.expiresAt > now && subscription.authorization.tokenExpiresAt > now;
}
// Operator-only application API. Never exposed through MCP or request fields.
// Denial is durable, resource/owner scoped, and no renewal path deletes it.
export async function denyResourceAccess(store: Store, owner: string, now = Date.now()): Promise<void> {
  if (!hash(owner)) throw new BridgeError('invalid_resource_owner', 400);
  await store.transaction(state => {
    state.resourceDenials ||= {};
    state.resourceDenials[owner] = { resource: resourceFor(EVENTS_PEER), recipient: EVENTS_PEER, status: 'denied', deniedAt: now };
    for (const sub of Object.values(state.subscriptions)) {
      if (sub.owner === owner && sub.recipient === EVENTS_PEER) { sub.active = false; sub.status = 'denied'; }
    }
  });
}
