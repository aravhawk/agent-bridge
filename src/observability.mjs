import { BridgeError, SCOPES } from './policy.mjs';
import { RECEIVER_ID } from './release.mjs';

export const OBSERVATION_LIMIT = 8;
export const OBSERVATION_TTL_MS = 24 * 3600000;
export const DIAGNOSTIC_READ_WINDOW_MS = 30 * 60000;
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
const time = value => Number.isSafeInteger(value) && value >= 0 && value <= 8640000000000000;
const relations = new Set(['new', 'same', 'later', 'earlier', 'unknown']);
const codes = new Set(['ok', 'invalid_params', 'events_not_enabled', 'authorization_lease_required',
  'access_revoked', 'subscription_inactive', 'stale_authorization', 'subscription_expired',
  'callback_endpoint_error', 'storage_configuration_required', 'storage_unavailable',
  'storage_version_mismatch', 'bridge_store_capacity_reached', 'message_not_found',
  'contract_probe_only', 'bridge_unavailable']);
function result(error, failed) {
  const code = failed ? error instanceof BridgeError && codes.has(error.code) && error.code !== 'ok'
    ? error.code : 'bridge_unavailable' : 'ok';
  return { outcome: failed ? 'error' : 'success', code,
    ...(code === 'callback_endpoint_error' && ['timeout', 'challenge_failed'].includes(error.reason) ? { reason: error.reason } : {}) };
}
// Project stored data as well as writes: never echo unexpected fields/codes.
function records(raw, now, kind) {
  if (!Array.isArray(raw) || !time(now)) return [];
  return raw.slice(-OBSERVATION_LIMIT).filter(r => r && time(r.at) && r.at <= now && r.at > now - OBSERVATION_TTL_MS &&
    ['success', 'error'].includes(r.outcome) && codes.has(r.code) &&
    (r.outcome === 'success' ? r.code === 'ok' : r.code !== 'ok') &&
    (kind === 'renewal' ? relations.has(r.authorityExpiry) && (r.refreshBefore === null || time(r.refreshBefore)) : hash(r.owner)))
    .map(r => ({ at: r.at, outcome: r.outcome, code: r.code,
      ...(r.code === 'callback_endpoint_error' && ['timeout', 'challenge_failed'].includes(r.reason) ? { reason: r.reason } : {}),
      ...(kind === 'renewal' ? { authorityExpiry: r.authorityExpiry, refreshBefore: r.refreshBefore } : { owner: r.owner }) }));
}
const view = r => ({ ...r, at: new Date(r.at).toISOString(),
  ...(Object.hasOwn(r, 'refreshBefore') ? { refreshBefore: r.refreshBefore === null ? null : new Date(r.refreshBefore).toISOString() } : {}) });
export function renewalObservations(subscription, now) {
  subscription.renewalObservations = records(subscription.renewalObservations, now, 'renewal');
  return subscription.renewalObservations.map(view);
}
// Separate transactions preserve failure observations after the operation's
// rollback. Recording is best effort: no retry, network, authorization or replay.
export async function observeRenewal({ store, principal, id, facts, response, error, failed = false, clock }) {
  try {
    await store.transaction(state => {
      const sub = state.subscriptions[id], now = clock();
      if (!time(now) || !sub || !hash(principal?.principalKey) || sub.owner !== principal.principalKey) return;
      const authorityExpiry = !facts.checked ? 'unknown' : !facts.existing ? 'new'
        : !time(facts.previousExpiry) || !time(facts.expiry) ? 'unknown'
          : facts.expiry === facts.previousExpiry ? 'same' : facts.expiry > facts.previousExpiry ? 'later' : 'earlier';
      const refreshBefore = response && Date.parse(response.refreshBefore);
      sub.renewalObservations = [...records(sub.renewalObservations, now, 'renewal'), {
        at: now, ...result(error, failed), authorityExpiry, refreshBefore: time(refreshBefore) ? refreshBefore : null,
      }].slice(-OBSERVATION_LIMIT);
    });
  } catch { /* Cannot replace a successful result or the original error. */ }
}
function fridayReader(principal) {
  return principal?.role === 'friday' && hash(principal.principalKey) && principal.scopes?.includes(SCOPES.friday.ack);
}
export function diagnosticReadCandidate(state, principal, messageId, now) {
  const marker = state.fridayWebhookDiagnostic;
  return fridayReader(principal) && uuid(messageId) && marker?.messageId === messageId &&
    marker.receiverId === RECEIVER_ID && time(marker.attemptedAt) && time(marker.armedUntil) && time(now) &&
    marker.attemptedAt <= now && now < Math.min(marker.armedUntil, marker.attemptedAt + DIAGNOSTIC_READ_WINDOW_MS);
}
export async function observeDiagnosticRead({ store, principal, messageId, error, failed = false, clock }) {
  try {
    await store.transaction(state => {
      const now = clock();
      if (!diagnosticReadCandidate(state, principal, messageId, now)) return;
      const previous = state.diagnosticReadObservations;
      state.diagnosticReadObservations = { messageId, records: [
        ...records(previous?.messageId === messageId ? previous.records : [], now, 'read'),
        { at: now, ...result(error, failed), owner: principal.principalKey }].slice(-OBSERVATION_LIMIT) };
    });
  } catch { /* A failed observation never repeats or changes the read. */ }
}
export function diagnosticReadStatus(state, principal, messageId, now) {
  const marker = state.fridayWebhookDiagnostic;
  if (!uuid(messageId) || marker?.messageId !== messageId || marker.receiverId !== RECEIVER_ID || !hash(principal?.principalKey)) return;
  const operator = principal.role === 'jarvis' && principal.scopes?.includes(SCOPES.jarvis.ack) && marker.owner === principal.principalKey;
  if (!operator && !fridayReader(principal)) return;
  const journal = state.diagnosticReadObservations;
  const recent = records(journal?.messageId === messageId ? journal.records : [], now, 'read');
  if (journal?.messageId === messageId) state.diagnosticReadObservations = { messageId, records: recent };
  const own = recent.filter(r => operator || r.owner === principal.principalKey);
  // An ownerless legacy marker grants no new operator access. Friday only sees
  // its own already-observed calls; unknown callers cannot probe marker existence.
  if (!operator && !own.length) return;
  return { messageId, messageStored: false, readObservations: own.map(({ owner, ...r }) => view(r)),
    evidenceStatus: 'server_read_result_only_not_native_wake', wakeVerified: false };
}
