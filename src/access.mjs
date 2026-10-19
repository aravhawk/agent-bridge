import { dailyMessage, messageScope } from './messages.mjs';
import { BridgeError, SCOPES, VERIFIED_AUTHORIZATION } from './policy.mjs';
import { resourceFor } from './resource.mjs';

const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function testEnvelopeAllowed(envelope, probeId, sender = 'jarvis') {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(probeId || '') ||
      !['jarvis', 'friday'].includes(sender)) return false;
  const recipient = sender === 'jarvis' ? 'friday' : 'jarvis';
  return !!envelope && ((envelope.kind === 'probe' && envelope.id === probeId &&
      envelope.from === sender && envelope.to === recipient) ||
    (envelope.kind === 'ack' && envelope.correlationId === probeId &&
      envelope.from === recipient && envelope.to === sender));
}
export function verifiedMessageAuthorization(principal, envelope, now, deliveryUntil = Infinity) {
  const a = principal?.[VERIFIED_AUTHORIZATION];
  const expiresAt = Math.min(a?.expiresAt, deliveryUntil, dailyMessage(envelope) ? Date.parse(envelope.expiresAt) : Infinity);
  const scope = messageScope(principal?.role, envelope.kind);
  if (!scope || envelope.from !== principal.role || !principal.scopes?.includes(scope) ||
      !hash(principal.principalKey) || !hash(a?.policyId) ||
      !Number.isSafeInteger(a.expiresAt) || !Number.isSafeInteger(expiresAt) || expiresAt <= now) {
    throw new BridgeError('message_authorization_required', 403);
  }
  return { owner: principal.principalKey, role: principal.role, resource: resourceFor(principal.role),
    scope, policyId: a.policyId, tokenExpiresAt: a.expiresAt, expiresAt };
}
export function messageAccessAllowed(state, message, policyIds, now) {
  const a = message?.authorization, e = message?.envelope;
  return !!a && ['jarvis', 'friday'].includes(e?.from) && (dailyMessage(e) ? ['message', 'status', 'handoff_request', 'ack'].includes(e.kind) : ['probe', 'ack'].includes(e?.kind)) &&
    a.role === e.from && hash(a.owner) && hash(policyIds?.[e.from]) && a.policyId === policyIds[e.from] &&
    a.resource === resourceFor(e.from) && a.scope === messageScope(e.from, e.kind) &&
    Number.isSafeInteger(message.storedAt) && Number.isSafeInteger(a.tokenExpiresAt) && Number.isSafeInteger(a.expiresAt) &&
    a.expiresAt <= a.tokenExpiresAt && (!dailyMessage(e) || a.expiresAt <= Date.parse(e.expiresAt)) && a.expiresAt > message.storedAt && a.expiresAt > now && !resourceDenied(state, a.owner);
}
export function verifiedLease(principal, policyId, now) {
  const authorization = principal?.[VERIFIED_AUTHORIZATION];
  if (!hash(policyId) || authorization?.policyId !== policyId ||
      !Number.isSafeInteger(authorization.expiresAt) || authorization.expiresAt <= now ||
      principal?.role !== 'jarvis' || !hash(principal.principalKey) ||
      !principal.scopes?.includes(SCOPES.jarvis.ack)) throw new BridgeError('authorization_lease_required', 403);
  return { owner: principal.principalKey, recipient: 'jarvis', resource: resourceFor('jarvis'),
    scope: SCOPES.jarvis.ack, policyId, tokenExpiresAt: authorization.expiresAt };
}
export function resourceDenied(state, owner) {
  if (state.resourceDenials !== undefined && (!state.resourceDenials || typeof state.resourceDenials !== 'object' || Array.isArray(state.resourceDenials))) return true;
  return Object.hasOwn(state.resourceDenials || {}, owner);
}
export function validLeaseMetadata(subscription, policyId) {
  const a = subscription?.authorization;
  return !!a && hash(policyId) && a.policyId === policyId && hash(subscription.owner) &&
    /^sub_[a-f0-9]{64}$/.test(subscription.id || '') && subscription.name === 'bridge.message.received' &&
    subscription.arguments?.recipient === 'jarvis' && Object.keys(subscription.arguments).length === 1 &&
    a.owner === subscription.owner && a.recipient === 'jarvis' && subscription.recipient === 'jarvis' &&
    a.resource === resourceFor('jarvis') && a.scope === SCOPES.jarvis.ack &&
    Number.isSafeInteger(a.tokenExpiresAt) && Number.isSafeInteger(subscription.expiresAt) &&
    subscription.expiresAt <= a.tokenExpiresAt;
}
export function subscriptionAccessAllowed(state, subscription, policyId, now) {
  return validLeaseMetadata(subscription, policyId) && subscription.status === 'active' &&
    subscription.active === true && !resourceDenied(state, subscription.owner) &&
    subscription.expiresAt > now && subscription.authorization.tokenExpiresAt > now;
}
// Operator-only application API. Never exposed through MCP or request fields.
// Denial is durable, resource/owner scoped, and no renewal path deletes it.
export async function denyResourceAccess(store, owner, now = Date.now()) {
  if (!hash(owner)) throw new BridgeError('invalid_resource_owner', 400);
  await store.transaction(state => {
    state.resourceDenials ||= {};
    state.resourceDenials[owner] = { resource: resourceFor('jarvis'), recipient: 'jarvis', status: 'denied', deniedAt: now };
    for (const sub of Object.values(state.subscriptions)) {
      if (sub.owner === owner && sub.recipient === 'jarvis') { sub.active = false; sub.status = 'denied'; }
    }
  });
}
