import pg from 'pg';
import { createRemoteJWKSet } from 'jose';
import { QueueClient } from '@vercel/queue';
import { createAccessVerifier, createContractObserver, BridgeError, authorizationPolicyId } from './policy.mjs';
import { PostgresStore } from './store.mjs';
import { Bridge } from './bridge.mjs';
import { NativeEvents, authorizeRecipient } from './events.mjs';
import { createProtector, createPublicWebhookTransport, decodeStorageKey } from './webhook.mjs';
import { DeliveryWorker } from './worker.mjs';
import { createMcpHandler } from './mcp.mjs';
import { createQueueAdapter } from './queue.mjs';
import { ISSUER, JWKS, resourceFor, metadataFor } from './resource.mjs';
import { messageAccessAllowed, subscriptionAccessAllowed, testEnvelopeAllowed } from './access.mjs';
import { createFridaySender, fridaySenderConfigured } from './friday-sender.mjs';

// No environment pull or local credential copy is needed. Vercel injects the
// native Neon Production Secret only in this project's production runtime.
export function createRuntime({ env = process.env, Pool = pg.Pool, keyResolver,
  queueClient, accessAllowed, fridaySender, clock = Date.now, transportFactory = createPublicWebhookTransport } = {}) {
  const contractReady = env.BRIDGE_OAUTH_CONTRACT_VERIFIED === 'true' &&
    (!!env.BRIDGE_ALLOWED_SUBJECT || /^[a-f0-9]{64}$/.test(env.BRIDGE_ALLOWED_SUBJECT_SHA256 || ''));
  let pool, store, bridge, events, queue;
  const lastObservedTiming = new Map();
  const resolver = keyResolver || createRemoteJWKSet(new URL(JWKS), { timeoutDuration: 5000 });
  const client = queueClient || new QueueClient({ region: 'iad1', telemetry: { isEnabled: false } });
  const messagePolicyIds = Object.fromEntries(['jarvis', 'friday'].map(role => [role, contractReady
    ? authorizationPolicyId({ issuer: ISSUER, audience: resourceFor(role), role,
      subject: env.BRIDGE_ALLOWED_SUBJECT, subjectHash: env.BRIDGE_ALLOWED_SUBJECT_SHA256,
      scopeClaim: env.BRIDGE_OAUTH_SCOPE_CLAIM || 'scope' }) : null]));
  const policyId = messagePolicyIds.jarvis;
  function fridayConfiguration() {
    const until = Date.parse(env.FRIDAY_TEST_AUTHORIZED_UNTIL);
    // Operator-approved finite test authority, never a request-supplied grant.
    const authorized = env.FRIDAY_RECEIVER_ID === 'jarvis-friday-test-receiver' &&
      Number.isSafeInteger(until) && until > clock() && until - clock() <= 6 * 3600000;
    const senderConfigured = fridaySenderConfigured({ endpoint: env.FRIDAY_WEBHOOK_URL, secret: env.FRIDAY_WEBHOOK_KEY });
    const contractVerified = env.FRIDAY_WEBHOOK_CONTRACT_VERIFIED === 'true';
    const probeId = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(env.FRIDAY_CONTRACT_PROBE_MESSAGE_ID || '')
      ? env.FRIDAY_CONTRACT_PROBE_MESSAGE_ID : undefined;
    const probeSender = env.BRIDGE_TEST_PROBE_SENDER ?? 'jarvis';
    return { until, authorized, senderConfigured, contractVerified, probeId, probeSender,
      ready: authorized && senderConfigured && !!probeId && ['jarvis', 'friday'].includes(probeSender) &&
        (contractVerified || probeSender === 'jarvis'),
      probeOnly: !contractVerified && !!probeId };
  }
  function readiness() {
    const callbackProtectorConfigured = !!decodeStorageKey(env.BRIDGE_SUBSCRIPTION_STORAGE_KEY);
    const base = contractReady && callbackProtectorConfigured && !!policyId && !!env.DATABASE_URL;
    const friday = fridayConfiguration();
    return { storageConfigured: !!env.DATABASE_URL, callbackProtectorConfigured,
      currentAccessCheckConfigured: !!policyId,
      subscriptionSetupEnabled: !!base && env.BRIDGE_SUBSCRIPTIONS_ENABLED === 'true',
      fridaySenderConfigured: friday.senderConfigured, fridayTestAuthorizationConfigured: friday.authorized,
      fridayContractVerified: friday.contractVerified, fridayProbeModeConfigured: friday.ready && friday.probeOnly,
      testDeliveryPinned: friday.ready,
      deliveryEnabled: !!base && env.BRIDGE_DELIVERY_ENABLED === 'true' && friday.ready };
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
    db.searchParams.set('sslmode', 'verify-full');
    db.searchParams.delete('uselibpqcompat');
    pool = new Pool({ connectionString: db.href, max: 2, connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 10000, query_timeout: 10000 });
    pool.on('error', () => {}); // Never emit a credential-bearing connection error.
    store = new PostgresStore(pool);
    const friday = fridayConfiguration();
    bridge = new Bridge({ store, clock, messagePolicyIds, deliveryUntil: friday.authorized ? friday.until : 0,
      probeMessageId: friday.probeId, probeSender: friday.probeSender });
    const storageKey = decodeStorageKey(env.BRIDGE_SUBSCRIPTION_STORAGE_KEY);
    const protector = storageKey ? createProtector(storageKey) : undefined;
    const baseReady = contractReady && !!protector && !!policyId;
    const subscriptionSetup = baseReady && env.BRIDGE_SUBSCRIPTIONS_ENABLED === 'true';
    const delivery = readiness().deliveryEnabled;
    const transport = subscriptionSetup || delivery ? transportFactory({ enabled: true }) : undefined;
    // A signed verification challenge is setup, not an application event. The
    // native subscription must be verifiable BEFORE event sends are enabled.
    events = new NativeEvents({ store, protector, transport, policyId, clock, enabled: subscriptionSetup });
    const nativeSender = delivery ? fridaySender || createFridaySender({ enabled: true,
      contractVerified: friday.contractVerified, probeMessageId: friday.probeId,
      endpoint: env.FRIDAY_WEBHOOK_URL, secret: env.FRIDAY_WEBHOOK_KEY, transport }) : undefined;
    const nativeAccess = async input => store.transaction(state => {
      const message = state.messages[input.messageId];
      if (clock() >= friday.until || !messageAccessAllowed(state, message, messagePolicyIds, clock()) ||
          message.envelope.to !== input.recipient) return false;
      // Verification controls transport mode, never whether scope is enforced.
      if (!testEnvelopeAllowed(message.envelope, friday.probeId, friday.probeSender)) return false;
      if (input.recipient === 'jarvis') {
        const sub = state.subscriptions[input.subscriptionId];
        return sub?.owner === input.owner && subscriptionAccessAllowed(state, sub, policyId, clock());
      }
      return input.recipient === 'friday' && friday.ready;
    });
    const authorize = async input => (await nativeAccess(input)) && (!accessAllowed || await accessAllowed(input));
    const worker = new DeliveryWorker({ store, protector, transport, policyId, messagePolicyIds,
      probeMessageId: friday.probeId, probeSender: friday.probeSender,
      clock, deliveryUntil: friday.until, accessAllowed: authorize, fridaySender: nativeSender, enabled: delivery });
    queue = createQueueAdapter({ client, store, worker, clock, enabled: delivery });
  }
  return {
    handler(role) {
      if (!contractReady) {
        if (env.BRIDGE_AUTH_DIAGNOSTIC === 'true') return createContractObserver({ issuer: ISSUER,
          audience: resourceFor(role), role, keyResolver: resolver,
          emit: facts => console.info('RN_BRIDGE_AUTH_CONTRACT ' + JSON.stringify(facts)) });
        throw new BridgeError('provider_contract_verification_required', 503);
      }
      const verify = createAccessVerifier({ issuer: ISSUER, audience: resourceFor(role),
        subject: env.BRIDGE_ALLOWED_SUBJECT, subjectHash: env.BRIDGE_ALLOWED_SUBJECT_SHA256,
        scopeClaim: env.BRIDGE_OAUTH_SCOPE_CLAIM || 'scope', role, keyResolver: resolver,
        observeTiming: env.BRIDGE_AUTH_TIMING_DIAGNOSTIC === 'true' ? facts => {
          const key = `${facts.issuedAt}:${facts.expiresAt}`;
          if (lastObservedTiming.get(role) === key) return;
          lastObservedTiming.set(role, key);
          console.info('RN_BRIDGE_AUTH_TIMING ' + JSON.stringify(facts));
        } : undefined });
      // No writes before the receiver/delivery contract is ready, even when an
      // otherwise valid token can discover the resource's scoped tools.
      const blocked = async () => { throw new BridgeError('receiver_readiness_required', 503); };
      const run = method => async (...args) => {
        if (['send', 'claim', 'complete'].includes(method) && !readiness().deliveryEnabled) return blocked();
        configure(); return bridge[method](...args);
      };
      const operations = Object.fromEntries(['send', 'claim', 'complete', 'read', 'status'].map(m => [m, run(m)]));
      const lazyEvents = {
        list: (...args) => new NativeEvents({}).list(...args),
        subscribe: async (...args) => {
          authorizeRecipient(args[0], 'jarvis');
          if (!readiness().subscriptionSetupEnabled) throw new BridgeError('events_not_enabled', 503);
          configure(); return events.subscribe(...args);
        },
        unsubscribe: async (...args) => { configure(); return events.unsubscribe(...args); },
      };
      return createMcpHandler({ enabled: true, verify, bridge: operations, events: lazyEvents,
        health: () => ({ status: 'ok', authenticated: true, serverVersion: '0.1.0', readiness: readiness() }),
        scheduleJobs: async ids => {
          if (!readiness().deliveryEnabled) throw new BridgeError('queue_not_enabled', 503);
          configure(); return queue.scheduleJobs(ids);
        }, resourceMetadataUrl: metadataFor(role),
        observeValidationFailure: role === 'friday' && env.BRIDGE_RPC_SHAPE_DIAGNOSTIC === 'true'
          ? facts => console.info('RN_BRIDGE_RPC_SHAPE ' + JSON.stringify(facts)) : undefined });
    },
    queueHandler() {
      configure();
      return client.handleCallback(async (...args) => {
        if (!readiness().deliveryEnabled) throw new BridgeError('delivery_not_enabled', 503);
        return queue.consume(...args);
      }, { visibilityTimeoutSeconds: 60, retry: queue.retry });
    },
    async close() { await pool?.end(); },
  };
}
export const runtime = createRuntime();
