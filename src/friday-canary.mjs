import { BridgeError } from './policy.mjs';
import { MESSAGE_PROTOCOL } from './messages.mjs';
import { diagnosticWindowOpen } from './friday-diagnostic.mjs';

// Refusals are tool execution errors, not authentication/permission failures.
const fail = (code, status = 409) => { throw new BridgeError(code, status); };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export const CANARY_MAX_WINDOW_MS = 30 * 60000;
// The only admissible canary body. Nonpersonal status data; it asks for nothing.
export const CANARY_TEXT = 'Jarvis Friday Bridge canary: one-time status data only. No action is requested.';

// One stored-message canary while normal delivery stays off. Every value is
// trusted server configuration; no request field selects an ID, target or
// window. Validate the full fixed interval, never its remaining lifetime.
export function canaryConfiguration(env, now) {
  const messageId = env.FRIDAY_CANARY_MESSAGE_ID, subscriptionId = env.FRIDAY_CANARY_RETURN_SUBSCRIPTION_ID;
  if (!uuid.test(messageId || '') || !/^sub_[a-f0-9]{64}$/.test(subscriptionId || '') ||
      !diagnosticWindowOpen(env.FRIDAY_CANARY_FROM, env.FRIDAY_CANARY_UNTIL, now, CANARY_MAX_WINDOW_MS)) return null;
  return Object.freeze({ messageId, subscriptionId,
    from: Date.parse(env.FRIDAY_CANARY_FROM), until: Date.parse(env.FRIDAY_CANARY_UNTIL) });
}
// Exact Jarvis -> Friday status source: ID, thread, text and expiry are fixed.
export function canaryEnvelope(envelope, config) {
  if (envelope.protocol !== MESSAGE_PROTOCOL || envelope.id !== config.messageId || envelope.from !== 'jarvis' ||
      envelope.to !== 'friday' || envelope.kind !== 'status' || envelope.threadId !== config.messageId ||
      envelope.route !== 'inbox' || envelope.text !== CANARY_TEXT || envelope.correlationId !== undefined ||
      envelope.expiresAt !== new Date(config.until).toISOString()) fail('friday_canary_only');
}
const bound = (r, config) => !!r && !!config && r.messageId === config.messageId &&
  r.subscriptionId === config.subscriptionId && r.from === config.from && r.until === config.until;

// One durable reservation for the deployment lifetime, separate from the spent
// webhook diagnostic marker. It commits with the first admitted preparation,
// before queue publication or transport, and nothing clears or rebinds it:
// another UUID, window, return subscription, owner or body stays refused.
export function reserveCanary(state, config, principal, hash, prior, now) {
  if (state.fridayWebhookDiagnostic?.messageId === config.messageId) fail('friday_canary_spent', 409);
  const r = state.fridayCanary;
  if (r) {
    if (!bound(r, config) || r.owner !== principal.principalKey || r.hash !== hash) fail('friday_canary_spent', 409);
    return;
  }
  if (prior) fail('message_id_conflict', 409);
  state.fridayCanary = { messageId: config.messageId, owner: principal.principalKey, from: config.from,
    until: config.until, subscriptionId: config.subscriptionId, hash, reservedAt: now, ackMessageId: null };
}
// The reserved source (to Friday) or its server-created ACK (to Jarvis on the
// pinned return subscription). Everything else is outside the exception.
export function canaryTarget(state, config, { messageId, recipient, subscriptionId }) {
  const r = state.fridayCanary, message = state.messages[messageId];
  if (!bound(r, config) || !message) return false;
  return recipient === 'friday'
    ? messageId === r.messageId && message.hash === r.hash && subscriptionId == null
    : recipient === 'jarvis' && !!r.ackMessageId && messageId === r.ackMessageId &&
      subscriptionId === r.subscriptionId && message.envelope.correlationId === r.messageId;
}
export function canaryReceipt(state, config, principal, messageId) {
  const r = state.fridayCanary;
  if (!canaryTarget(state, config, { messageId, recipient: principal.role,
      subscriptionId: principal.role === 'jarvis' ? r?.subscriptionId : null }) ||
      (principal.role === 'jarvis' && principal.principalKey !== r.owner)) fail('friday_canary_only');
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
