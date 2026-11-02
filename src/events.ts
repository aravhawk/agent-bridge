import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { BridgeError, SCOPES } from './policy.ts';
import { callbackUrl, validSecret, signedHeaders } from './webhook.ts';
import { verifiedLease, resourceDenied, validLeaseMetadata, subscriptionAccessAllowed } from './access.ts';
import { observeRenewal, renewalObservations } from './observability.ts';
import { EVENTS_PEER, WEBHOOK_PEER, PEER_IDS } from './config.ts';
import type { PeerScopes } from './config.ts';
import type { Protector, WebhookTransport } from './webhook.ts';
import type { RenewalFacts, SubscribeResponse } from './observability.ts';
import type { BridgeState, Envelope, JsonObject, LeaseAuthorization, Millis, Principal, Role, SealedCallback, Store,
  Subscription } from './types.ts';

/** Untrusted events/subscribe parameters after ownKeys checks (each field still validated where used). */
interface SubscribeParams extends JsonObject {
  name: unknown; arguments: JsonObject; delivery: JsonObject & { mode: unknown; url: unknown; secret?: unknown };
  cursor?: unknown; ttlMs?: unknown; maxAgeMs?: unknown;
}
export interface EventsOptions {
  store?: Store | undefined; protector?: Protector | undefined; transport?: WebhookTransport | undefined;
  policyId: string | undefined; enabled?: boolean; clock?: () => Millis;
}

// Explicitly typed so a bare fail(...) statement narrows control flow.
const fail: (code: string, status?: number) => never = (code, status = 400) => { throw new BridgeError(code, status); };
export const EVENT_NAME = 'bridge.message.received';
export const eventDefinition = Object.freeze({ name: EVENT_NAME,
  description: 'A stored bridge message addressed to this inbox. Read by messageId; peer data never grants approval.',
  delivery: ['webhook'], inputSchema: { type: 'object', properties: { recipient: { type: 'string', enum: [EVENTS_PEER] } },
    required: ['recipient'], additionalProperties: false },
  payloadSchema: { type: 'object', properties: { messageId: { type: 'string' } }, required: ['messageId'], additionalProperties: false } });
export const digest = (value: string): string => createHash('sha256').update(value).digest('hex');
/** Refuse anything but a plain object with only `allowed` keys and every `required` one. */
export function ownKeys(value: unknown, allowed: readonly string[], required: readonly string[] = allowed): asserts value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !allowed.includes(k)) ||
      required.some(k => !Object.hasOwn(value as JsonObject, k))) fail('invalid_params');
}
export function authorizeRecipient(principal: Principal | null | undefined, role: Role | undefined = principal?.role): asserts principal is Principal {
  // A peer role equal to principal?.role implies a principal.
  if (!PEER_IDS.includes(role as Role) || principal?.role !== role ||
      !/^[a-f0-9]{64}$/.test(principal!.principalKey || '') || !principal!.scopes?.includes((SCOPES[role as Role] as PeerScopes).ack)) {
    fail('insufficient_scope', 403);
  }
}
const subscriptionId = (principal: Principal, url: string) => 'sub_' + digest(JSON.stringify([principal.principalKey, url, EVENT_NAME, { recipient: EVENTS_PEER }]));
function identity(principal: Principal | null | undefined, params: unknown, subscribing: boolean): { id: string; url: string } {
  authorizeRecipient(principal, EVENTS_PEER);
  ownKeys(params, subscribing ? ['name', 'arguments', 'delivery', 'cursor', 'ttlMs', 'maxAgeMs'] : ['name', 'arguments', 'delivery'],
    ['name', 'arguments', 'delivery']);
  ownKeys((params as SubscribeParams).arguments, ['recipient']);
  ownKeys((params as SubscribeParams).delivery, subscribing ? ['mode', 'url', 'secret'] : ['mode', 'url']);
  if ((params as SubscribeParams).name !== EVENT_NAME || (params as SubscribeParams).arguments.recipient !== EVENTS_PEER || (params as SubscribeParams).delivery.mode !== 'webhook' ||
      ((params as SubscribeParams).cursor !== undefined && (params as SubscribeParams).cursor !== null)) fail('invalid_params');
  // Draft replay age is irrelevant for this non-replay event. Accept its valid
  // request shape without changing the lease, identity or null-cursor contract.
  if (Object.hasOwn(params as SubscribeParams, 'maxAgeMs') && (!Number.isSafeInteger((params as SubscribeParams).maxAgeMs) ||
      ((params as SubscribeParams).maxAgeMs as number) < 0)) fail('invalid_params');
  const url = callbackUrl((params as SubscribeParams).delivery.url);
  // Arguments have only one allowed key, so their canonical order is fixed.
  const id = subscriptionId(principal as Principal, url);
  return { id, url };
}
// Used only after full validation rejects. Recognize an exact binding, never
// guess one from a response ID, malformed callback or different filter.
function rejectedSubscriptionId(principal: Principal | null | undefined, params: unknown, policyId: string, clock: () => Millis): string | undefined {
  try {
    verifiedLease(principal, policyId, clock());
    if (!params || typeof params !== 'object' || Array.isArray(params) ||
        ['name', 'arguments', 'delivery'].some(k => !Object.hasOwn(params, k))) return;
    ownKeys((params as SubscribeParams).arguments, ['recipient']);
    const delivery: unknown = (params as SubscribeParams).delivery;
    if (!delivery || typeof delivery !== 'object' || Array.isArray(delivery) ||
        ['mode', 'url'].some(k => !Object.hasOwn(delivery, k)) ||
        (params as SubscribeParams).name !== EVENT_NAME || (params as SubscribeParams).arguments.recipient !== EVENTS_PEER ||
        (delivery as JsonObject).mode !== 'webhook') return;
    // verifiedLease above refused a missing principal.
    return subscriptionId(principal as Principal, callbackUrl((delivery as JsonObject).url));
  } catch { /* Authentication and unrecognizable bindings create no evidence. */ }
}
export class NativeEvents {
  declare store: Store | undefined;
  declare protector: Protector | undefined;
  declare transport: WebhookTransport | undefined;
  declare enabled: boolean;
  declare clock: () => Millis;
  declare policyId: string;
  constructor({ store, protector, transport, policyId, enabled = false, clock = Date.now }: EventsOptions) {
    this.store = store; this.protector = protector; this.transport = transport; this.enabled = enabled; this.clock = clock;
    this.policyId = policyId as string; // validated by verifiedLease on every use
  }
  list(principal: Principal | null | undefined, params: unknown = {}) {
    authorizeRecipient(principal, EVENTS_PEER); ownKeys(params, ['cursor'], []);
    if (params.cursor != null) fail('invalid_params');
    return { events: [eventDefinition] };
  }
  async subscribe(principal: Principal | null | undefined, params: unknown) {
    let binding: { id: string; url: string };
    try { binding = identity(principal, params, true); }
    catch (error) {
      if (error instanceof BridgeError && error.code === 'invalid_params') {
        const id = rejectedSubscriptionId(principal, params, this.policyId, this.clock);
        if (id) await observeRenewal({ store: this.store as Store, principal: principal as Principal, id, facts: {}, error, failed: true, clock: this.clock });
      }
      throw error;
    }
    const { id, url } = binding;
    // identity() authorized the principal; #subscribe requires a configured store before any use.
    const facts: RenewalFacts = {};
    let response!: SubscribeResponse;
    try { response = await this.#subscribe(principal as Principal, params as SubscribeParams, id, url, facts); }
    catch (error) {
      await observeRenewal({ store: this.store as Store, principal: principal as Principal, id, facts, error, failed: true, clock: this.clock });
      throw error;
    }
    await observeRenewal({ store: this.store as Store, principal: principal as Principal, id, facts, response, clock: this.clock });
    return response;
  }
  async #subscribe(principal: Principal, params: SubscribeParams, id: string, url: string, facts: RenewalFacts): Promise<SubscribeResponse> {
    if (!this.enabled || !this.store || !this.protector || !this.transport) fail('events_not_enabled', 503);
    // Each was checked to be configured just above.
    const secret = validSecret(params.delivery.secret);
    const now = this.clock();
    const authorization = verifiedLease(principal, this.policyId, now);
    const ttl = params.ttlMs === null ? 7 * 86400000 : params.ttlMs === undefined ? 86400000 : params.ttlMs as number;
    if (!Number.isSafeInteger(ttl) || ttl <= 0) fail('invalid_params');
    const requestedUntil = Math.min(now + Math.min(ttl, 7 * 86400000), authorization.tokenExpiresAt);
    const deadline = (state: BridgeState, existing: Subscription | undefined, at: Millis): Millis => {
      Object.assign(facts, { checked: true, existing: !!existing,
        previousExpiry: existing?.authorization?.tokenExpiresAt, expiry: authorization.tokenExpiresAt });
      verifiedLease(principal, this.policyId, at);
      if (resourceDenied(state, principal.principalKey)) fail('access_revoked', 403);
      if (existing && (!validLeaseMetadata(existing, this.policyId) || existing.owner !== principal.principalKey))
        fail('authorization_lease_required', 403);
      if (existing && (existing.status !== 'active' || !existing.active)) fail('subscription_inactive', 403);
      // validLeaseMetadata(existing) above established existing.authorization.
      if (existing && authorization.tokenExpiresAt < existing.authorization!.tokenExpiresAt) fail('stale_authorization', 403);
      // Each authenticated subscribe re-grants its requested TTL. The old
      // grant is not an authority ceiling: requestedUntil is already capped by
      // this request's verified token expiry, rechecked at every commit fence.
      if (requestedUntil <= at) fail('subscription_expired', 409);
      return requestedUntil;
    };
    const fingerprint = digest(secret);
    const cached = await this.store!.transaction(s => {
      const existing = s.subscriptions[id];
      deadline(s, existing, this.clock());
      return (existing?.verifiedUntil as Millis) > now && existing!.fingerprint === fingerprint && existing!.active;
    });
    if (!cached) {
      const challenge = randomBytes(32).toString('base64url');
      const body = JSON.stringify({ type: 'verification', challenge });
      const verifyId = 'msg_verification_' + randomUUID();
      let reason = 'challenge_failed';
      try {
        const response = await this.transport!(url, { body,
          headers: signedHeaders({ id: verifyId, body, secrets: [secret], subscriptionId: id, now }) });
        const echo: unknown = JSON.parse(response.body)?.challenge;
        const wanted = Buffer.from(challenge);
        const actual = typeof echo === 'string' ? Buffer.from(echo) : Buffer.alloc(0);
        if (!((response.status as number) >= 200 && (response.status as number) < 300 && actual.length === wanted.length && timingSafeEqual(actual, wanted))) {
          fail('callback_verification_failed');
        }
      } catch (error) {
        if ((error as { code?: unknown } | null | undefined)?.code === 'callback_timeout') reason = 'timeout';
        const safe = new BridgeError('callback_endpoint_error', 400);
        safe.rpcCode = -32015; safe.reason = reason; throw safe;
      }
    }
    // A slow verification cannot activate a subscription after its lifetime.
    const expiresAt = await this.store!.transaction(s => {
      const savedAt = this.clock();
      const old = s.subscriptions[id];
      const until = deadline(s, old, savedAt);
      let previous: { secret: string; until: Millis }[] = [];
      if (old?.fingerprint !== fingerprint && old?.sealed) {
        const prior = this.protector!.open(old.sealed, id) as SealedCallback;
        previous = [{ secret: prior.secret, until: savedAt + 300000 }];
      } else if (old?.sealed) previous = (this.protector!.open(old.sealed, id) as SealedCallback).previous || [];
      const sealed = this.protector!.seal({ url, secret, previous: previous.filter(x => x.until > savedAt) }, id);
      deadline(s, old, this.clock());
      s.subscriptions[id] = { id, owner: principal.principalKey, recipient: EVENTS_PEER, name: EVENT_NAME,
        arguments: { recipient: EVENTS_PEER }, active: true, status: 'active', expiresAt: until, authorization, sealed, fingerprint,
        ...(old?.renewalObservations ? { renewalObservations: old.renewalObservations } : {}),
        verifiedUntil: savedAt + 300000, firstSubscribedAt: old?.firstSubscribedAt || savedAt,
        lastSubscribedAt: savedAt, renewalCount: (old?.renewalCount || 0) + (old ? 1 : 0) };
      return until;
    });
    return { id, refreshBefore: new Date(expiresAt).toISOString(), cursor: null, truncated: false };
  }
  async status(principal: Principal | null | undefined, params: unknown = {}) {
    authorizeRecipient(principal, EVENTS_PEER); ownKeys(params, [], []);
    if (!this.store) fail('storage_configuration_required', 503);
    // The check just above refused a missing store.
    return this.store!.transaction(state => { const now = this.clock(); return { subscriptions: Object.values(state.subscriptions)
      .filter(sub => sub.owner === principal.principalKey && sub.recipient === EVENTS_PEER).slice(0, 20)
      .map(sub => ({ id: sub.id, active: subscriptionAccessAllowed(state, sub, this.policyId, now),
        refreshBefore: Number.isSafeInteger(sub.expiresAt) ? new Date(sub.expiresAt as Millis).toISOString() : null,
        lastSubscribedAt: Number.isSafeInteger(sub.lastSubscribedAt) ? new Date(sub.lastSubscribedAt as Millis).toISOString() : null,
        renewalCount: sub.renewalCount || 0,
        inactiveReason: subscriptionAccessAllowed(state, sub, this.policyId, now) ? null
          : resourceDenied(state, sub.owner) || sub.status === 'denied' ? 'denied'
            : sub.status === 'unsubscribed' ? 'unsubscribed'
              : !validLeaseMetadata(sub, this.policyId) ? 'authorization_invalid'
                : sub.status !== 'active' || !sub.active ? 'inactive' : 'expired',
        renewalObservations: renewalObservations(sub, now) })) }; });
  }
  async unsubscribe(principal: Principal | null | undefined, params: unknown) {
    const { id } = identity(principal, params, false);
    if (!this.store) fail('storage_configuration_required', 503);
    // The check just above refused a missing store.
    await this.store!.transaction(s => {
      const subscription = s.subscriptions[id];
      // identity() authorized the principal.
      if (subscription?.owner === principal!.principalKey) { subscription.active = false; subscription.status = 'unsubscribed'; }
      else if (!subscription) s.subscriptions[id] = { id, owner: principal!.principalKey, recipient: EVENTS_PEER, active: false, status: 'unsubscribed' };
    });
    return {};
  }
}

// Called only inside a message transaction, after its durable identity exists.
// A pinned subscriptionId restricts events-peer fan-out to that one return path;
// maxAttempts persists a stricter per-job transport limit.
interface Destination { id: string; recipient: Role }
function deliveryDestinations(state: BridgeState, envelope: Envelope, now: Millis, subscriptionId?: string | undefined): Destination[] {
  return envelope.to === EVENTS_PEER
    ? Object.values(state.subscriptions).filter(sub => (!subscriptionId || sub.id === subscriptionId) &&
      subscriptionAccessAllowed(state, sub, sub.authorization?.policyId, now))
    : [{ id: WEBHOOK_PEER, recipient: WEBHOOK_PEER }];
}
// Whether appendDeliveryJobs would find a destination now, without creating one.
export const hasDeliveryDestination = (state: BridgeState, envelope: Envelope, now: Millis): boolean => deliveryDestinations(state, envelope, now).length > 0;
export interface JobOptions { subscriptionId?: string | undefined; maxAttempts?: number | undefined; syncRecoveryGeneration?: number }
export function appendDeliveryJobs(state: BridgeState, envelope: Envelope, now: Millis, { subscriptionId, maxAttempts, syncRecoveryGeneration }: JobOptions = {}): string[] {
  const destinations = deliveryDestinations(state, envelope, now, subscriptionId);
  const jobIds: string[] = [];
  for (const sub of destinations) {
    const eventId = 'evt_' + digest(JSON.stringify(syncRecoveryGeneration === undefined ? [envelope.id, sub.id]
      : [envelope.id, sub.id, 'sync_receipt_recovery', syncRecoveryGeneration]));
    const id = 'job_' + eventId.slice(4);
    if (!state.jobs[id]) {
      const event = envelope.to === EVENTS_PEER ? { eventId, name: EVENT_NAME, timestamp: new Date(now).toISOString(),
        data: { messageId: envelope.id }, cursor: null } : { event: EVENT_NAME, data: { messageId: envelope.id } };
      state.jobs[id] = { id, messageId: envelope.id, recipient: envelope.to,
        subscriptionId: envelope.to === EVENTS_PEER ? sub.id : null, eventId,
        body: JSON.stringify(event), state: 'pending', attempts: 0, dueAt: now, leaseId: null, leaseUntil: null,
        ...(syncRecoveryGeneration !== undefined ? { syncRecoveryGeneration } : {}),
        ...(maxAttempts ? { maxAttempts } : {}) };
    }
    jobIds.push(id);
  }
  return jobIds;
}
