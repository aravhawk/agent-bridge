import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { BridgeError, SCOPES } from './policy.mjs';
import { callbackUrl, validSecret, signedHeaders } from './webhook.mjs';
import { verifiedLease, resourceDenied, validLeaseMetadata, subscriptionAccessAllowed } from './access.mjs';
import { observeRenewal, renewalObservations } from './observability.mjs';

const fail = (code, status = 400) => { throw new BridgeError(code, status); };
export const EVENT_NAME = 'bridge.message.received';
export const eventDefinition = Object.freeze({ name: EVENT_NAME,
  description: 'A stored bridge message addressed to Jarvis. Read by messageId; peer data never grants approval.',
  delivery: ['webhook'], inputSchema: { type: 'object', properties: { recipient: { type: 'string', enum: ['jarvis'] } },
    required: ['recipient'], additionalProperties: false },
  payloadSchema: { type: 'object', properties: { messageId: { type: 'string' } }, required: ['messageId'], additionalProperties: false } });
export const digest = value => createHash('sha256').update(value).digest('hex');
export function ownKeys(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !allowed.includes(k)) ||
      required.some(k => !Object.hasOwn(value, k))) fail('invalid_params');
}
export function authorizeRecipient(principal, role = principal?.role) {
  if (!['jarvis', 'friday'].includes(role) || principal?.role !== role ||
      !/^[a-f0-9]{64}$/.test(principal.principalKey || '') || !principal.scopes?.includes(SCOPES[role].ack)) {
    fail('insufficient_scope', 403);
  }
}
function identity(principal, params, subscribing) {
  authorizeRecipient(principal, 'jarvis');
  ownKeys(params, subscribing ? ['name', 'arguments', 'delivery', 'cursor', 'ttlMs', 'maxAgeMs'] : ['name', 'arguments', 'delivery'],
    ['name', 'arguments', 'delivery']);
  ownKeys(params.arguments, ['recipient']);
  ownKeys(params.delivery, subscribing ? ['mode', 'url', 'secret'] : ['mode', 'url']);
  if (params.name !== EVENT_NAME || params.arguments.recipient !== 'jarvis' || params.delivery.mode !== 'webhook' ||
      (params.cursor !== undefined && params.cursor !== null)) fail('invalid_params');
  // Draft replay age is irrelevant for this non-replay event. Accept its valid
  // request shape without changing the lease, identity or null-cursor contract.
  if (Object.hasOwn(params, 'maxAgeMs') && (!Number.isSafeInteger(params.maxAgeMs) || params.maxAgeMs < 0)) fail('invalid_params');
  const url = callbackUrl(params.delivery.url);
  // Arguments have only one allowed key, so their canonical order is fixed.
  const id = 'sub_' + digest(JSON.stringify([principal.principalKey, url, EVENT_NAME, { recipient: 'jarvis' }]));
  return { id, url };
}
export class NativeEvents {
  constructor({ store, protector, transport, policyId, enabled = false, clock = Date.now }) {
    this.store = store; this.protector = protector; this.transport = transport; this.enabled = enabled; this.clock = clock;
    this.policyId = policyId;
  }
  list(principal, params = {}) {
    authorizeRecipient(principal, 'jarvis'); ownKeys(params, ['cursor'], []);
    if (params.cursor != null) fail('invalid_params');
    return { events: [eventDefinition] };
  }
  async subscribe(principal, params) {
    const { id, url } = identity(principal, params, true);
    const facts = {};
    let response;
    try { response = await this.#subscribe(principal, params, id, url, facts); }
    catch (error) {
      await observeRenewal({ store: this.store, principal, id, facts, error, failed: true, clock: this.clock });
      throw error;
    }
    await observeRenewal({ store: this.store, principal, id, facts, response, clock: this.clock });
    return response;
  }
  async #subscribe(principal, params, id, url, facts) {
    if (!this.enabled || !this.store || !this.protector || !this.transport) fail('events_not_enabled', 503);
    const secret = validSecret(params.delivery.secret);
    const now = this.clock();
    const authorization = verifiedLease(principal, this.policyId, now);
    const ttl = params.ttlMs === null ? 7 * 86400000 : params.ttlMs === undefined ? 86400000 : params.ttlMs;
    if (!Number.isSafeInteger(ttl) || ttl <= 0) fail('invalid_params');
    const requestedUntil = Math.min(now + Math.min(ttl, 7 * 86400000), authorization.tokenExpiresAt);
    const deadline = (state, existing, at) => {
      Object.assign(facts, { checked: true, existing: !!existing,
        previousExpiry: existing?.authorization?.tokenExpiresAt, expiry: authorization.tokenExpiresAt });
      verifiedLease(principal, this.policyId, at);
      if (resourceDenied(state, principal.principalKey)) fail('access_revoked', 403);
      if (existing && (!validLeaseMetadata(existing, this.policyId) || existing.owner !== principal.principalKey))
        fail('authorization_lease_required', 403);
      if (existing && (existing.status !== 'active' || !existing.active)) fail('subscription_inactive', 403);
      if (existing && authorization.tokenExpiresAt < existing.authorization.tokenExpiresAt) fail('stale_authorization', 403);
      const until = existing && authorization.tokenExpiresAt === existing.authorization.tokenExpiresAt
        ? Math.min(requestedUntil, existing.expiresAt) : requestedUntil;
      if (until <= at) fail('subscription_expired', 409);
      return until;
    };
    const fingerprint = digest(secret);
    const cached = await this.store.transaction(s => {
      const existing = s.subscriptions[id];
      deadline(s, existing, this.clock());
      return existing?.verifiedUntil > now && existing.fingerprint === fingerprint && existing.active;
    });
    if (!cached) {
      const challenge = randomBytes(32).toString('base64url');
      const body = JSON.stringify({ type: 'verification', challenge });
      const verifyId = 'msg_verification_' + randomUUID();
      let reason = 'challenge_failed';
      try {
        const response = await this.transport(url, { body,
          headers: signedHeaders({ id: verifyId, body, secrets: [secret], subscriptionId: id, now }) });
        const echo = JSON.parse(response.body)?.challenge;
        const wanted = Buffer.from(challenge);
        const actual = typeof echo === 'string' ? Buffer.from(echo) : Buffer.alloc(0);
        if (!(response.status >= 200 && response.status < 300 && actual.length === wanted.length && timingSafeEqual(actual, wanted))) {
          fail('callback_verification_failed');
        }
      } catch (error) {
        if (error?.code === 'callback_timeout') reason = 'timeout';
        const safe = new BridgeError('callback_endpoint_error', 400);
        safe.rpcCode = -32015; safe.reason = reason; throw safe;
      }
    }
    // A slow verification cannot activate a subscription after its lifetime.
    const expiresAt = await this.store.transaction(s => {
      const savedAt = this.clock();
      const old = s.subscriptions[id];
      const until = deadline(s, old, savedAt);
      let previous = [];
      if (old?.fingerprint !== fingerprint && old?.sealed) {
        const prior = this.protector.open(old.sealed, id);
        previous = [{ secret: prior.secret, until: savedAt + 300000 }];
      } else if (old?.sealed) previous = this.protector.open(old.sealed, id).previous || [];
      const sealed = this.protector.seal({ url, secret, previous: previous.filter(x => x.until > savedAt) }, id);
      deadline(s, old, this.clock());
      s.subscriptions[id] = { id, owner: principal.principalKey, recipient: 'jarvis', name: EVENT_NAME,
        arguments: { recipient: 'jarvis' }, active: true, status: 'active', expiresAt: until, authorization, sealed, fingerprint,
        ...(old?.renewalObservations ? { renewalObservations: old.renewalObservations } : {}),
        verifiedUntil: savedAt + 300000, firstSubscribedAt: old?.firstSubscribedAt || savedAt,
        lastSubscribedAt: savedAt, renewalCount: (old?.renewalCount || 0) + (old ? 1 : 0) };
      return until;
    });
    return { id, refreshBefore: new Date(expiresAt).toISOString(), cursor: null, truncated: false };
  }
  async status(principal, params = {}) {
    authorizeRecipient(principal, 'jarvis'); ownKeys(params, [], []);
    if (!this.store) fail('storage_configuration_required', 503);
    return this.store.transaction(state => { const now = this.clock(); return { subscriptions: Object.values(state.subscriptions)
      .filter(sub => sub.owner === principal.principalKey && sub.recipient === 'jarvis').slice(0, 20)
      .map(sub => ({ id: sub.id, active: subscriptionAccessAllowed(state, sub, this.policyId, now),
        refreshBefore: Number.isSafeInteger(sub.expiresAt) ? new Date(sub.expiresAt).toISOString() : null,
        lastSubscribedAt: Number.isSafeInteger(sub.lastSubscribedAt) ? new Date(sub.lastSubscribedAt).toISOString() : null,
        renewalCount: sub.renewalCount || 0,
        inactiveReason: subscriptionAccessAllowed(state, sub, this.policyId, now) ? null
          : resourceDenied(state, sub.owner) || sub.status === 'denied' ? 'denied'
            : sub.status === 'unsubscribed' ? 'unsubscribed'
              : !validLeaseMetadata(sub, this.policyId) ? 'authorization_invalid'
                : sub.status !== 'active' || !sub.active ? 'inactive' : 'expired',
        renewalObservations: renewalObservations(sub, now) })) }; });
  }
  async unsubscribe(principal, params) {
    const { id } = identity(principal, params, false);
    if (!this.store) fail('storage_configuration_required', 503);
    await this.store.transaction(s => {
      const subscription = s.subscriptions[id];
      if (subscription?.owner === principal.principalKey) { subscription.active = false; subscription.status = 'unsubscribed'; }
      else if (!subscription) s.subscriptions[id] = { id, owner: principal.principalKey, recipient: 'jarvis', active: false, status: 'unsubscribed' };
    });
    return {};
  }
}

// Called only inside a message transaction, after its durable identity exists.
export function appendDeliveryJobs(state, envelope, now) {
  const destinations = envelope.to === 'jarvis'
    ? Object.values(state.subscriptions).filter(sub => subscriptionAccessAllowed(state, sub, sub.authorization?.policyId, now))
    : [{ id: 'friday', recipient: 'friday' }];
  const jobIds = [];
  for (const sub of destinations) {
    const eventId = 'evt_' + digest(JSON.stringify([envelope.id, sub.id]));
    const id = 'job_' + eventId.slice(4);
    if (!state.jobs[id]) {
      const event = envelope.to === 'jarvis' ? { eventId, name: EVENT_NAME, timestamp: new Date(now).toISOString(),
        data: { messageId: envelope.id }, cursor: null } : { event: EVENT_NAME, data: { messageId: envelope.id } };
      state.jobs[id] = { id, messageId: envelope.id, recipient: envelope.to,
        subscriptionId: envelope.to === 'jarvis' ? sub.id : null, eventId,
        body: JSON.stringify(event), state: 'pending', attempts: 0, dueAt: now, leaseId: null, leaseUntil: null };
    }
    jobIds.push(id);
  }
  return jobIds;
}
