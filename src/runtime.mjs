import pg from 'pg';
import { createRemoteJWKSet } from 'jose';
import { QueueClient } from '@vercel/queue';
import { createAccessVerifier, createContractObserver, BridgeError } from './policy.mjs';
import { PostgresStore } from './store.mjs';
import { Bridge } from './bridge.mjs';
import { NativeEvents, authorizeRecipient } from './events.mjs';
import { createProtector, createPublicWebhookTransport } from './webhook.mjs';
import { DeliveryWorker } from './worker.mjs';
import { createMcpHandler } from './mcp.mjs';
import { createQueueAdapter } from './queue.mjs';
import { ISSUER, JWKS, resourceFor, metadataFor } from './resource.mjs';
import { createJarvisAccessAllowed } from './access.mjs';

// No environment pull or local credential copy is needed. Vercel injects the
// native Neon Production Secret only in this project's production runtime.
export function createRuntime({ env = process.env, Pool = pg.Pool, keyResolver,
  queueClient, accessAllowed, readCurrentGrant, fridaySender, transportFactory = createPublicWebhookTransport } = {}) {
  const contractReady = env.BRIDGE_OAUTH_CONTRACT_VERIFIED === 'true' &&
    (!!env.BRIDGE_ALLOWED_SUBJECT || /^[a-f0-9]{64}$/.test(env.BRIDGE_ALLOWED_SUBJECT_SHA256 || ''));
  let pool, store, bridge, events, queue;
  const lastObservedTiming = new Map();
  const resolver = keyResolver || createRemoteJWKSet(new URL(JWKS), { timeoutDuration: 5000 });
  const client = queueClient || new QueueClient({ region: 'iad1', telemetry: { isEnabled: false } });
  const authorizeAccess = accessAllowed || createJarvisAccessAllowed({ subject: env.BRIDGE_ALLOWED_SUBJECT,
    subjectHash: env.BRIDGE_ALLOWED_SUBJECT_SHA256, readCurrentGrant });
  const accessConfigured = typeof authorizeAccess === 'function' && authorizeAccess.configured !== false;
  function readiness() {
    const encoded = env.BRIDGE_SUBSCRIPTION_STORAGE_KEY || '';
    const callbackProtectorConfigured = /^[A-Za-z0-9+/]{43}=$/.test(encoded) &&
      Buffer.from(encoded, 'base64').toString('base64') === encoded;
    const base = contractReady && callbackProtectorConfigured && accessConfigured;
    return { storageConfigured: !!env.DATABASE_URL, callbackProtectorConfigured,
      currentAccessCheckConfigured: accessConfigured,
      subscriptionSetupEnabled: !!base && env.BRIDGE_SUBSCRIPTIONS_ENABLED === 'true',
      deliveryEnabled: !!base && env.BRIDGE_DELIVERY_ENABLED === 'true' && typeof fridaySender === 'function' };
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
    store = new PostgresStore(pool); bridge = new Bridge({ store });
    let protector;
    const encoded = env.BRIDGE_SUBSCRIPTION_STORAGE_KEY || '';
    if (/^[A-Za-z0-9+/]{43}=$/.test(encoded)) protector = createProtector(Buffer.from(encoded, 'base64'));
    const baseReady = contractReady && !!protector && accessConfigured;
    const subscriptionSetup = baseReady && env.BRIDGE_SUBSCRIPTIONS_ENABLED === 'true';
    const delivery = baseReady && env.BRIDGE_DELIVERY_ENABLED === 'true' && typeof fridaySender === 'function';
    const transport = subscriptionSetup || delivery ? transportFactory({ enabled: true }) : undefined;
    // A signed verification challenge is setup, not an application event. The
    // native subscription must be verifiable BEFORE event sends are enabled.
    events = new NativeEvents({ store, protector, transport, enabled: subscriptionSetup });
    const worker = new DeliveryWorker({ store, protector, transport, accessAllowed: authorizeAccess, fridaySender, enabled: delivery });
    queue = createQueueAdapter({ client, store, worker, enabled: delivery });
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
          // Check the current grant before callback verification or storage.
          if (!(await authorizeAccess({ owner: args[0].principalKey, recipient: 'jarvis' })))
            throw new BridgeError('access_revoked', 403);
          configure(); return events.subscribe(...args);
        },
        unsubscribe: async (...args) => { configure(); return events.unsubscribe(...args); },
      };
      return createMcpHandler({ enabled: true, verify, bridge: operations, events: lazyEvents,
        health: () => ({ status: 'ok', authenticated: true, serverVersion: '0.1.0', readiness: readiness() }),
        scheduleJobs: async ids => { configure(); return queue.scheduleJobs(ids); }, resourceMetadataUrl: metadataFor(role),
        observeValidationFailure: role === 'friday' && env.BRIDGE_RPC_SHAPE_DIAGNOSTIC === 'true'
          ? facts => console.info('RN_BRIDGE_RPC_SHAPE ' + JSON.stringify(facts)) : undefined });
    },
    queueHandler() {
      configure();
      return client.handleCallback(queue.consume, { visibilityTimeoutSeconds: 60, retry: queue.retry });
    },
    async close() { await pool?.end(); },
  };
}
export const runtime = createRuntime();
