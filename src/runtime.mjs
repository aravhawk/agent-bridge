import pg from 'pg';
import { createRemoteJWKSet } from 'jose';
import { QueueClient } from '@vercel/queue';
import { createAccessVerifier, BridgeError, authorizationPolicyId } from './policy.mjs';
import { PostgresStore } from './store.mjs';
import { Bridge } from './bridge.mjs';
import { NativeEvents, authorizeRecipient } from './events.mjs';
import { createProtector, createPublicWebhookTransport, decodeStorageKey } from './webhook.mjs';
import { DeliveryWorker } from './worker.mjs';
import { createMcpHandler } from './mcp.mjs';
import { createQueueAdapter } from './queue.mjs';
import { resourceFor, metadataFor, providerConfiguration } from './resource.mjs';
import { messageAccessAllowed, subscriptionAccessAllowed } from './access.mjs';
import { dailyMessage } from './messages.mjs';
import { createFridaySender, fridaySenderConfigured } from './friday-sender.mjs';
import { VERSION, RECEIVER_ID } from './release.mjs';

// Resource server only. The approved production provider owns consent,
// credentials, issuance and refresh. Secrets are injected by Vercel, never pulled.
export function createRuntime({ env = process.env, Pool = pg.Pool, keyResolver,
  queueClient, accessAllowed, fridaySender, clock = Date.now, transportFactory = createPublicWebhookTransport } = {}) {
  const provider = providerConfiguration(env.BRIDGE_OAUTH_ISSUER);
  const identityConfigured = !!provider &&
    (!!env.BRIDGE_ALLOWED_SUBJECT || /^[a-f0-9]{64}$/.test(env.BRIDGE_ALLOWED_SUBJECT_SHA256 || ''));
  const contractReady = identityConfigured && env.BRIDGE_OAUTH_CONTRACT_VERIFIED === 'true';
  let pool, store, bridge, events, queue;
  const resolver = keyResolver || (provider ? createRemoteJWKSet(new URL(provider.jwks), { timeoutDuration: 5000 }) : undefined);
  const client = queueClient || new QueueClient({ region: 'iad1', telemetry: { isEnabled: false } });
  const policyIds = Object.fromEntries(['jarvis', 'friday'].map(role => [role, identityConfigured
    ? authorizationPolicyId({ issuer: provider.issuer, audience: resourceFor(role), role,
      subject: env.BRIDGE_ALLOWED_SUBJECT, subjectHash: env.BRIDGE_ALLOWED_SUBJECT_SHA256,
      scopeClaim: env.BRIDGE_OAUTH_SCOPE_CLAIM || 'scope' }) : null]));
  function readiness() {
    const callbackProtectorConfigured = !!decodeStorageKey(env.BRIDGE_SUBSCRIPTION_STORAGE_KEY);
    const base = contractReady && callbackProtectorConfigured && !!env.DATABASE_URL;
    const senderConfigured = fridaySenderConfigured({ endpoint: env.FRIDAY_WEBHOOK_URL, secret: env.FRIDAY_WEBHOOK_KEY });
    const receiverPolicyVerified = env.BRIDGE_RECEIVER_POLICY === 'inbox-v1' && env.FRIDAY_RECEIVER_ID === RECEIVER_ID;
    const fridayContractVerified = env.FRIDAY_WEBHOOK_CONTRACT_VERIFIED === 'true';
    return { storageConfigured: !!env.DATABASE_URL, callbackProtectorConfigured,
      currentAccessCheckConfigured: !!policyIds.jarvis,
      subscriptionSetupEnabled: !!base && env.BRIDGE_SUBSCRIPTIONS_ENABLED === 'true',
      fridaySenderConfigured: senderConfigured, receiverPolicyVerified, fridayContractVerified,
      deliveryEnabled: !!base && env.BRIDGE_DELIVERY_ENABLED === 'true' &&
        senderConfigured && receiverPolicyVerified && fridayContractVerified };
  }
  function configure() {
    if (store) return;
    if (!env.DATABASE_URL) throw new BridgeError('storage_configuration_required', 503);
    const db = new URL(env.DATABASE_URL);
    if (!['postgres:', 'postgresql:'].includes(db.protocol) || !db.hostname.endsWith('.neon.tech') ||
        !['require', 'verify-full'].includes(db.searchParams.get('sslmode')) ||
        [...db.searchParams.keys()].some(k => ['sslrootcert', 'sslkey', 'sslcert'].includes(k))) {
      throw new BridgeError('storage_tls_configuration_required', 503);
    }
    db.searchParams.set('sslmode', 'verify-full'); db.searchParams.delete('uselibpqcompat');
    pool = new Pool({ connectionString: db.href, max: 2, connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 10000, query_timeout: 10000 });
    pool.on('error', () => {});
    store = new PostgresStore(pool);
    const ready = readiness(), delivery = ready.deliveryEnabled;
    const key = decodeStorageKey(env.BRIDGE_SUBSCRIPTION_STORAGE_KEY);
    const protector = key ? createProtector(key) : undefined;
    const transport = ready.subscriptionSetupEnabled || delivery ? transportFactory({ enabled: true }) : undefined;
    events = new NativeEvents({ store, protector, transport, policyId: policyIds.jarvis, clock, enabled: ready.subscriptionSetupEnabled });
    const nativeSender = delivery ? fridaySender || createFridaySender({ enabled: true, contractVerified: true,
      endpoint: env.FRIDAY_WEBHOOK_URL, secret: env.FRIDAY_WEBHOOK_KEY, transport }) : undefined;
    const nativeAccess = async input => store.transaction(state => {
      const message = state.messages[input.messageId];
      if (!dailyMessage(message?.envelope) || !messageAccessAllowed(state, message, policyIds, clock()) || message.envelope.to !== input.recipient) return false;
      if (input.recipient === 'jarvis') {
        const sub = state.subscriptions[input.subscriptionId];
        return sub?.owner === input.owner && subscriptionAccessAllowed(state, sub, policyIds.jarvis, clock());
      }
      return input.recipient === 'friday' && readiness().deliveryEnabled;
    });
    const authorize = async input => (await nativeAccess(input)) && (!accessAllowed || await accessAllowed(input));
    const worker = new DeliveryWorker({ store, protector, transport, policyId: policyIds.jarvis,
      messagePolicyIds: policyIds, clock, accessAllowed: authorize, fridaySender: nativeSender, enabled: delivery });
    queue = createQueueAdapter({ client, store, worker, clock, enabled: delivery, maintenanceEnabled: true });
    bridge = new Bridge({ store, clock, messagePolicyIds: policyIds, dailyEnabled: true,
      prepareMessage: id => queue.prepareMessage(id), prepareReceipt: id => queue.prepareReceipt(id) });
  }
  return {
    handler(role) {
      if (!identityConfigured) throw new BridgeError('provider_contract_verification_required', 503);
      const verify = createAccessVerifier({ issuer: provider.issuer, audience: resourceFor(role),
        subject: env.BRIDGE_ALLOWED_SUBJECT, subjectHash: env.BRIDGE_ALLOWED_SUBJECT_SHA256,
        scopeClaim: env.BRIDGE_OAUTH_SCOPE_CLAIM || 'scope', role, keyResolver: resolver });
      const run = method => async (...args) => {
        if (['sendMessage', 'claim', 'complete'].includes(method) && !readiness().deliveryEnabled)
          throw new BridgeError('receiver_readiness_required', 503);
        configure(); return bridge[method](...args);
      };
      const operations = Object.fromEntries(['sendMessage', 'claim', 'complete', 'read', 'status'].map(m => [m, run(m)]));
      const nativeEvents = {
        list: (...args) => new NativeEvents({}).list(...args),
        subscribe: async (...args) => {
          authorizeRecipient(args[0], 'jarvis');
          if (!readiness().subscriptionSetupEnabled) throw new BridgeError('events_not_enabled', 503);
          configure(); return events.subscribe(...args);
        },
        unsubscribe: async (...args) => { configure(); return events.unsubscribe(...args); },
        status: async (...args) => { configure(); return events.status(...args); },
      };
      return createMcpHandler({ enabled: true, verify, bridge: operations, events: nativeEvents,
        dailyEnabled: true, healthOnly: !contractReady,
        health: () => ({ status: 'ok', authenticated: true, serverVersion: VERSION, readiness: readiness() }),
        scheduleJobs: async ids => {
          if (!readiness().deliveryEnabled) throw new BridgeError('queue_not_enabled', 503);
          configure(); return queue.scheduleJobs(ids);
        }, resourceMetadataUrl: metadataFor(role) });
    },
    queueHandler() {
      configure();
      return client.handleCallback(async (...args) => {
        const payload = args[0];
        const cleanup = payload && Object.keys(payload).length === 1 &&
          /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(payload.cleanupMessageId || '');
        if (!readiness().deliveryEnabled && !cleanup) throw new BridgeError('delivery_not_enabled', 503);
        return queue.consume(...args);
      }, { visibilityTimeoutSeconds: 60, retry: queue.retry });
    },
    async close() { await pool?.end(); },
  };
}
export const runtime = createRuntime();
