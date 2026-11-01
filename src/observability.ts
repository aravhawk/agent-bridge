import { BridgeError, SCOPES } from './policy.ts';
import { RECEIVER_ID } from './release.ts';
import { EVENTS_PEER, WEBHOOK_PEER, NAMES } from './config.ts';
import type { PeerScopes } from './config.ts';
import type { BridgeState, CanaryReservation, DiagnosticRecord, Millis, Observation, Principal, Store, Subscription } from './types.ts';

/** What #subscribe learned about the authority being renewed (events.ts). */
export interface RenewalFacts { checked?: boolean; existing?: boolean; previousExpiry?: Millis | undefined; expiry?: Millis }
/** A successful subscribe response, as recorded here. */
export interface SubscribeResponse { id: string; refreshBefore: string; cursor: null; truncated: boolean }
interface ReadJournal { messageId: string; records: Observation[] }

export const OBSERVATION_LIMIT = 8;
export const OBSERVATION_TTL_MS = 24 * 3600000;
export const DIAGNOSTIC_READ_WINDOW_MS = 30 * 60000;
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const uuid = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
const time = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= 8640000000000000;
const relations = new Set(['new', 'same', 'later', 'earlier', 'unknown']);
const skipObservation = Symbol('no matching observation');
const codes = new Set(['ok', 'invalid_params', 'events_not_enabled', 'authorization_lease_required',
  'access_revoked', 'subscription_inactive', 'stale_authorization', 'subscription_expired',
  'callback_endpoint_error', 'storage_configuration_required', 'storage_unavailable',
  'storage_version_mismatch', 'bridge_store_capacity_reached', 'message_not_found',
  'contract_probe_only', 'bridge_unavailable']);
function result(error: unknown, failed: boolean): Pick<Observation, 'outcome' | 'code' | 'reason'> {
  const code = failed ? error instanceof BridgeError && codes.has(error.code) && error.code !== 'ok'
    ? error.code : 'bridge_unavailable' : 'ok';
  return { outcome: failed ? 'error' : 'success', code,
    // code is callback_endpoint_error only for a BridgeError (checked above).
    ...(code === 'callback_endpoint_error' && ['timeout', 'challenge_failed'].includes((error as BridgeError).reason as string)
      ? { reason: (error as BridgeError).reason as string } : {}) };
}
// Project stored data as well as writes: never echo unexpected fields/codes.
// Stored records are re-validated field by field; anything else is dropped.
function records(raw: unknown, now: Millis, kind: 'renewal' | 'read'): Observation[] {
  if (!Array.isArray(raw) || !time(now)) return [];
  return (raw as Observation[]).slice(-OBSERVATION_LIMIT).filter(r => r && time(r.at) && r.at <= now && r.at > now - OBSERVATION_TTL_MS &&
    ['success', 'error'].includes(r.outcome) && codes.has(r.code) &&
    (r.outcome === 'success' ? r.code === 'ok' : r.code !== 'ok') &&
    (kind === 'renewal' ? relations.has(r.authorityExpiry as string) && (r.refreshBefore === null || time(r.refreshBefore)) : hash(r.owner)))
    .map(r => ({ at: r.at, outcome: r.outcome, code: r.code,
      ...(r.code === 'callback_endpoint_error' && ['timeout', 'challenge_failed'].includes(r.reason as string) ? { reason: r.reason } : {}),
      ...(kind === 'renewal' ? { authorityExpiry: r.authorityExpiry, refreshBefore: r.refreshBefore } : { owner: r.owner }) }));
}
const view = (r: Partial<Observation> & { at: Millis }) => ({ ...r, at: new Date(r.at).toISOString(),
  ...(Object.hasOwn(r, 'refreshBefore') ? { refreshBefore: r.refreshBefore === null ? null : new Date(r.refreshBefore as Millis).toISOString() } : {}) });
export function renewalObservations(subscription: Subscription, now: Millis) {
  subscription.renewalObservations = records(subscription.renewalObservations, now, 'renewal');
  return (subscription.renewalObservations as Observation[]).map(view);
}
// Separate transactions preserve failure observations after the operation's
// rollback. Recording is best effort: no retry, network, authorization or replay.
export interface RenewalObservation {
  store: Store; principal: Principal; id: string; facts: RenewalFacts; response?: SubscribeResponse;
  error?: unknown; failed?: boolean; clock: () => Millis;
}
export async function observeRenewal({ store, principal, id, facts, response, error, failed = false, clock }: RenewalObservation): Promise<void> {
  try {
    await store.transaction(state => {
      const sub = state.subscriptions[id], now = clock();
      // Abort rather than commit an unchanged document: PostgresStore would
      // otherwise UPDATE its row even when no caller-owned binding matched.
      if (!time(now) || !sub || !hash(principal?.principalKey) || sub.owner !== principal.principalKey) throw skipObservation;
      const authorityExpiry = !facts.checked ? 'unknown' : !facts.existing ? 'new'
        : !time(facts.previousExpiry) || !time(facts.expiry) ? 'unknown'
          : facts.expiry === facts.previousExpiry ? 'same' : (facts.expiry as Millis) > (facts.previousExpiry as Millis) ? 'later' : 'earlier';
      const refreshBefore = response && Date.parse(response.refreshBefore);
      sub.renewalObservations = [...records(sub.renewalObservations, now, 'renewal'), {
        at: now, ...result(error, failed), authorityExpiry, refreshBefore: time(refreshBefore) ? refreshBefore : null,
      }].slice(-OBSERVATION_LIMIT);
    });
  } catch { /* Cannot replace a successful result or the original error. */ }
}
function webhookReader(principal: Principal | null | undefined): boolean {
  return principal?.role === WEBHOOK_PEER && hash(principal.principalKey) && principal.scopes?.includes((SCOPES[WEBHOOK_PEER] as PeerScopes).ack);
}
export function diagnosticReadCandidate(state: BridgeState, principal: Principal | null | undefined, messageId: unknown, now: Millis): boolean {
  const marker = state[NAMES.diagnosticState] as DiagnosticRecord | undefined;
  return webhookReader(principal) && uuid(messageId) && marker?.messageId === messageId &&
    marker!.receiverId === RECEIVER_ID && time(marker!.attemptedAt) && time(marker!.armedUntil) && time(now) &&
    marker!.attemptedAt <= now && now < Math.min(marker!.armedUntil, marker!.attemptedAt + DIAGNOSTIC_READ_WINDOW_MS);
}
export interface ReadObservation { store: Store; principal: Principal; messageId: string; error?: unknown; failed?: boolean; clock: () => Millis }
export async function observeDiagnosticRead({ store, principal, messageId, error, failed = false, clock }: ReadObservation): Promise<void> {
  try {
    await store.transaction(state => {
      const now = clock();
      if (!diagnosticReadCandidate(state, principal, messageId, now)) return;
      const previous = state.diagnosticReadObservations as ReadJournal | undefined;
      state.diagnosticReadObservations = { messageId, records: [
        ...records(previous?.messageId === messageId ? previous.records : [], now, 'read'),
        { at: now, ...result(error, failed), owner: principal.principalKey }].slice(-OBSERVATION_LIMIT) };
    });
  } catch { /* A failed observation never repeats or changes the read. */ }
}
export function diagnosticReadStatus(state: BridgeState, principal: Principal | null | undefined, messageId: unknown, now: Millis) {
  const marker = state[NAMES.diagnosticState] as DiagnosticRecord | undefined;
  if (!uuid(messageId) || marker?.messageId !== messageId || marker.receiverId !== RECEIVER_ID || !hash(principal?.principalKey)) return;
  // A hashed principalKey implies a principal.
  const operator = principal!.role === EVENTS_PEER && principal!.scopes?.includes((SCOPES[EVENTS_PEER] as PeerScopes).ack) && marker.owner === principal!.principalKey;
  if (!operator && !webhookReader(principal)) return;
  const journal = state.diagnosticReadObservations as ReadJournal | undefined;
  const recent = records(journal?.messageId === messageId ? journal.records : [], now, 'read');
  if (journal?.messageId === messageId) state.diagnosticReadObservations = { messageId, records: recent };
  const own = recent.filter(r => operator || r.owner === principal!.principalKey);
  // An ownerless legacy marker grants no new operator access. The webhook peer only sees
  // its own already-observed calls; unknown callers cannot probe marker existence.
  if (!operator && !own.length) return;
  return { messageId, messageStored: false, readObservations: own.map(({ owner, ...r }) => view(r)),
    evidenceStatus: 'server_read_result_only_not_native_wake', wakeVerified: false };
}
// Stored-message canary reads live in its own durable reservation, never the
// spent diagnostic marker: the webhook peer reading the source, the reserving
// events-peer owner reading the server-created ACK. Capture ends 30 minutes after UNTIL.
function canaryReadField(state: BridgeState, principal: Principal | null | undefined, messageId: unknown, now: Millis): 'sourceReads' | 'ackReads' | undefined {
  const r = state[NAMES.canaryState] as CanaryReservation | undefined;
  if (!r || !uuid(messageId) || !hash(principal?.principalKey) || !time(now) || !time(r.reservedAt) ||
      !time(r.until) || now < r.reservedAt || now >= r.until + DIAGNOSTIC_READ_WINDOW_MS) return;
  const role = messageId === r.messageId ? WEBHOOK_PEER : r.ackMessageId && messageId === r.ackMessageId ? EVENTS_PEER : null;
  // A hashed principalKey (checked above) implies a principal.
  if (!role || principal!.role !== role || !principal!.scopes?.includes((SCOPES[role] as PeerScopes).ack) ||
      (role === EVENTS_PEER && principal!.principalKey !== r.owner)) return;
  return role === WEBHOOK_PEER ? 'sourceReads' : 'ackReads';
}
export const canaryReadCandidate = (state: BridgeState, principal: Principal | null | undefined, messageId: unknown, now: Millis): boolean => !!canaryReadField(state, principal, messageId, now);
export async function observeCanaryRead({ store, principal, messageId, error, failed = false, clock }: ReadObservation): Promise<void> {
  try {
    await store.transaction(state => {
      const now = clock(), field = canaryReadField(state, principal, messageId, now);
      if (!field) throw skipObservation;
      // canaryReadField found the reservation.
      (state[NAMES.canaryState] as CanaryReservation)[field] = [...records((state[NAMES.canaryState] as CanaryReservation)[field], now, 'read'),
        { at: now, ...result(error, failed), owner: principal.principalKey }].slice(-OBSERVATION_LIMIT);
    });
  } catch { /* A failed observation never repeats or changes the read. */ }
}
export function canaryReadStatus(state: BridgeState, messageId: unknown, now: Millis) {
  const r = state[NAMES.canaryState] as CanaryReservation | undefined;
  const field = !r || !uuid(messageId) ? null : messageId === r.messageId ? 'sourceReads'
    : r.ackMessageId && messageId === r.ackMessageId ? 'ackReads' : null;
  if (!field) return;
  // A field is only chosen when the reservation exists.
  return { readObservations: records(r![field], now, 'read').map(({ owner, ...x }) => view(x)),
    evidenceStatus: 'server_operation_results_only_not_native_wake' };
}
