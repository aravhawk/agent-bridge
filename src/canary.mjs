import { BridgeError } from './policy.mjs';
import { MESSAGE_PROTOCOL } from './messages.mjs';
import { diagnosticWindowOpen } from './webhook-diagnostic.mjs';
import { EVENTS_PEER, WEBHOOK_PEER, NAMES, peerCode, webhookPeerSettings } from './config.mjs';
import { SERVICE_NAME } from './release.mjs';

// Refusals are tool execution errors, not authentication/permission failures.
const fail = (code, status = 409) => { throw new BridgeError(code, status); };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export const CANARY_MAX_WINDOW_MS = 30 * 60000;
// The only admissible canary body. Nonpersonal status data; it asks for nothing.
export const CANARY_TEXT = `${SERVICE_NAME} canary: one-time status data only. No action is requested.`;

// One stored-message canary while normal delivery stays off. Every value is
// trusted server configuration; no request field selects an ID, target or
// window. Validate the full fixed interval, never its remaining lifetime.
export function canaryConfiguration(env, now) {
  const peer = webhookPeerSettings(env);
  const messageId = peer.canaryMessageId, subscriptionId = peer.canaryReturnSubscriptionId;
  if (!uuid.test(messageId || '') || !/^sub_[a-f0-9]{64}$/.test(subscriptionId || '') ||
      !diagnosticWindowOpen(peer.canaryFrom, peer.canaryUntil, now, CANARY_MAX_WINDOW_MS)) return null;
  return Object.freeze({ messageId, subscriptionId,
    from: Date.parse(peer.canaryFrom), until: Date.parse(peer.canaryUntil) });
}
// Exact events-peer -> webhook-peer status source: ID, thread, text and expiry are fixed.
export function canaryEnvelope(envelope, config) {
  if (envelope.protocol !== MESSAGE_PROTOCOL || envelope.id !== config.messageId || envelope.from !== EVENTS_PEER ||
      envelope.to !== WEBHOOK_PEER || envelope.kind !== 'status' || envelope.threadId !== config.messageId ||
      envelope.route !== 'inbox' || envelope.text !== CANARY_TEXT || envelope.correlationId !== undefined ||
      envelope.expiresAt !== new Date(config.until).toISOString()) fail(peerCode('canary_only'));
}
const bound = (r, config) => !!r && !!config && r.messageId === config.messageId &&
  r.subscriptionId === config.subscriptionId && r.from === config.from && r.until === config.until;

// One durable reservation for the deployment lifetime, separate from the spent
// webhook diagnostic marker. It commits with the first admitted preparation,
// before queue publication or transport, and nothing clears or rebinds it:
// another UUID, window, return subscription, owner or body stays refused.
export function reserveCanary(state, config, principal, hash, prior, now) {
  if (state[NAMES.diagnosticState]?.messageId === config.messageId) fail(peerCode('canary_spent'), 409);
  const r = state[NAMES.canaryState];
  if (r) {
    if (!bound(r, config) || r.owner !== principal.principalKey || r.hash !== hash) fail(peerCode('canary_spent'), 409);
    return;
  }
  if (prior) fail('message_id_conflict', 409);
  state[NAMES.canaryState] = { messageId: config.messageId, owner: principal.principalKey, from: config.from,
    until: config.until, subscriptionId: config.subscriptionId, hash, reservedAt: now, ackMessageId: null };
}
// The reserved source (to the webhook peer) or its server-created ACK (to the
// events peer on the pinned return subscription). Everything else is outside the exception.
export function canaryTarget(state, config, { messageId, recipient, subscriptionId }) {
  const r = state[NAMES.canaryState], message = state.messages[messageId];
  if (!bound(r, config) || !message) return false;
  return recipient === WEBHOOK_PEER
    ? messageId === r.messageId && message.hash === r.hash && subscriptionId == null
    : recipient === EVENTS_PEER && !!r.ackMessageId && messageId === r.ackMessageId &&
      subscriptionId === r.subscriptionId && message.envelope.correlationId === r.messageId;
}
export function canaryReceipt(state, config, principal, messageId) {
  const r = state[NAMES.canaryState];
  if (!canaryTarget(state, config, { messageId, recipient: principal.role,
      subscriptionId: principal.role === EVENTS_PEER ? r?.subscriptionId : null }) ||
      (principal.role === EVENTS_PEER && principal.principalKey !== r.owner)) fail(peerCode('canary_only'));
}
// Canary jobs carry a durable one-attempt limit from creation.
export const canaryJob = (state, config, job) => job?.maxAttempts === 1 && canaryTarget(state, config, job);
// Private queue work admitted in canary mode: only this source's dispatch or
// its receipt's ACK dispatch. Direct job IDs and every other payload stay closed.
export function canaryDispatch(payload, config) {
  const keys = payload && typeof payload === 'object' && !Array.isArray(payload) ? Object.keys(payload) : [];
  const work = keys.filter(k => k !== 'recoveryUntil');
  return work.length === 1 && ['dispatchMessageId', 'dispatchReceiptOf'].includes(work[0]) &&
    payload[work[0]] === config.messageId;
}
