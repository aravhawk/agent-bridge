import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { BridgeError, SCOPES } from './policy.mjs';
import { callbackUrl, validSecret, signedHeaders } from './webhook.mjs';

const fail = (code, status = 400) => { throw new BridgeError(code, status); };
export const EVENT_NAME = 'bridge.message.received';
export const eventDefinition = Object.freeze({ name: EVENT_NAME,
  description: 'A stored synthetic bridge message addressed to Jarvis. Read it by messageId.',
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
  ownKeys(params, subscribing ? ['name', 'arguments', 'delivery', 'cursor', 'ttlMs'] : ['name', 'arguments', 'delivery'],
    ['name', 'arguments', 'delivery']);
  ownKeys(params.arguments, ['recipient']);
  ownKeys(params.delivery, subscribing ? ['mode', 'url', 'secret'] : ['mode', 'url']);
  if (params.name !== EVENT_NAME || params.arguments.recipient !== 'jarvis' || params.delivery.mode !== 'webhook' ||
      (params.cursor !== undefined && params.cursor !== null)) fail('invalid_params');
  const url = callbackUrl(params.delivery.url);
  // Arguments have only one allowed key, so their canonical order is fixed.
  const id = 'sub_' + digest(JSON.stringify([principal.principalKey, url, EVENT_NAME, { recipient: 'jarvis' }]));
  return { id, url };
}
export function isActive(subscription, now) {
  return subscription?.active && (subscription.expiresAt === null || now < subscription.expiresAt);
}

export class NativeEvents {
  constructor({ store, protector, transport, enabled = false, clock = Date.now }) {
    this.store = store; this.protector = protector; this.transport = transport; this.enabled = enabled; this.clock = clock;
  }
  list(principal, params = {}) {
    authorizeRecipient(principal, 'jarvis'); ownKeys(params, ['cursor'], []);
    if (params.cursor != null) fail('invalid_params');
    return { events: [eventDefinition] };
  }
  async subscribe(principal, params) {
    const { id, url } = identity(principal, params, true);
    if (!this.enabled || !this.store || !this.protector || !this.transport) fail('events_not_enabled', 503);
    const secret = validSecret(params.delivery.secret);
    const now = this.clock();
    const ttl = params.ttlMs === null ? null : params.ttlMs === undefined ? 86400000 : params.ttlMs;
    if (ttl !== null && (!Number.isSafeInteger(ttl) || ttl <= 0)) fail('invalid_params');
    const expiresAt = ttl === null ? null : now + Math.max(60000, Math.min(ttl, 7 * 86400000));
    const fingerprint = digest(secret);
    const cached = await this.store.transaction(s => {
      const existing = s.subscriptions[id];
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
    const savedAt = this.clock();
    if (expiresAt !== null && expiresAt <= savedAt) fail('subscription_expired', 409);
    await this.store.transaction(s => {
      const old = s.subscriptions[id];
      let previous = [];
      if (old?.fingerprint !== fingerprint && old?.sealed) {
        const prior = this.protector.open(old.sealed, id);
        previous = [{ secret: prior.secret, until: savedAt + 300000 }];
      } else if (old?.sealed) previous = this.protector.open(old.sealed, id).previous || [];
      const sealed = this.protector.seal({ url, secret, previous: previous.filter(x => x.until > savedAt) }, id);
      s.subscriptions[id] = { id, owner: principal.principalKey, recipient: 'jarvis', name: EVENT_NAME,
        arguments: { recipient: 'jarvis' }, active: true, expiresAt, sealed, fingerprint,
        verifiedUntil: savedAt + 300000 };
    });
    return { id, refreshBefore: expiresAt === null ? null : new Date(expiresAt).toISOString(), cursor: null, truncated: false };
  }
  async unsubscribe(principal, params) {
    const { id } = identity(principal, params, false);
    if (!this.store) fail('storage_configuration_required', 503);
    await this.store.transaction(s => {
      const subscription = s.subscriptions[id];
      if (subscription?.owner === principal.principalKey) subscription.active = false;
    });
    return {};
  }
}

// Called only inside a message transaction, after its durable identity exists.
export function appendDeliveryJobs(state, envelope, now) {
  const destinations = envelope.to === 'jarvis'
    ? Object.values(state.subscriptions).filter(sub => sub.recipient === 'jarvis' && isActive(sub, now))
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
