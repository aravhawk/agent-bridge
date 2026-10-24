import pg from 'pg';
import { createRemoteJWKSet } from 'jose';
import { QueueClient } from '@vercel/queue';
import { createAccessVerifier, BridgeError, authorizationPolicyId, DELIVERY_TRANSPORT_OUTCOME } from './policy.mjs';
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
import { createFridayDiagnostic, diagnosticWindowOpen } from './friday-diagnostic.mjs';
import { canaryConfiguration, canaryTarget, canaryJob, canaryDispatch } from './friday-canary.mjs';
import { VERSION, RECEIVER_ID } from './release.mjs';
import { createTaskCapability, validateTaskCapabilityOptions } from './task-capability.mjs';
import { createTaskAccess } from './task-access.mjs';

// Canary callbacks are one-shot: every invocation is recorded as a terminal
// outcome, so no ambiguous result is retried. Response bodies are dropped.
function terminalTransport(transport) {
  const mark = (value, error = null) => Object.defineProperty(value, DELIVERY_TRANSPORT_OUTCOME,
    { value: Object.freeze({ terminal: true, error }) });
  return async (...args) => {
    let response;
    try { response = await transport(...args); } catch (error) {
      const code = error instanceof BridgeError ? error.code : 'callback_transport_failed';
      throw mark(new BridgeError(code, 503), code);
    }
    return mark({ status: response?.status });
  };
}

// Resource server only. The approved production provider owns consent,
// credentials, issuance and refresh. Secrets are injected by Vercel, never pulled.
export function createRuntime({ env = process.env, Pool = pg.Pool, keyResolver,
  queueClient, accessAllowed, fridaySender, clock = Date.now, transportFactory = createPublicWebhookTransport,
  taskData } = {}) {
  // Constructor-only opt-in. No environment variable or request can enable it;
  // the exported production instance below deliberately supplies no option.
  if (taskData !== undefined && (!taskData || typeof taskData !== 'object' || Array.isArray(taskData)))
    throw new BridgeError('task_runtime_configuration_required', 503);
  const taskOptions = taskData === undefined ? null : structuredClone(taskData);
  if (taskOptions && ((taskOptions.purgeEnabled !== undefined && taskOptions.purgeEnabled !== false) ||
      taskOptions.retention !== undefined)) throw new BridgeError('task_purge_not_enabled', 503);
  if (taskOptions && (Object.keys(taskOptions).some(key => !['enabled', 'leaseMs', 'linkRetentionMs', 'limits',
    'maxLinks', 'maxLinksPerTask', 'purgeEnabled', 'retention'].includes(key)) ||
    (taskOptions.enabled !== undefined && typeof taskOptions.enabled !== 'boolean')))
    throw new BridgeError('task_runtime_configuration_required', 503);
  const taskOptedIn = taskOptions?.enabled === true;
  if (taskOptedIn && [taskOptions.leaseMs, taskOptions.linkRetentionMs].some(value => !Number.isSafeInteger(value) || value <= 0))
    throw new BridgeError('task_runtime_configuration_required', 503);
  if (taskOptedIn) validateTaskCapabilityOptions(taskOptions);
  const provider = providerConfiguration(env.BRIDGE_OAUTH_ISSUER);
  const identityConfigured = !!provider &&
    (!!env.BRIDGE_ALLOWED_SUBJECT || /^[a-f0-9]{64}$/.test(env.BRIDGE_ALLOWED_SUBJECT_SHA256 || ''));
  const contractReady = identityConfigured && env.BRIDGE_OAUTH_CONTRACT_VERIFIED === 'true';
  let pool, store, bridge, events, queue, diagnostic, transport, protector, authorize, taskCapability;
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
    // Independent of delivery: one operator-armed transport check only.
    const fridayWebhookDiagnosticArmed = contractReady && !!env.DATABASE_URL && senderConfigured &&
      env.FRIDAY_RECEIVER_ID === RECEIVER_ID && diagnosticWindowOpen(
        env.FRIDAY_WEBHOOK_DIAGNOSTIC_FROM, env.FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL, clock());
    const deliveryEnabled = !!base && env.BRIDGE_DELIVERY_ENABLED === 'true' &&
      senderConfigured && receiverPolicyVerified && fridayContractVerified;
    // Stored-message canary: only while normal delivery is off. Its ID is never
    // reported; a durable reservation (not this flag) decides whether it is spent.
    const canaryArmed = base && senderConfigured && env.FRIDAY_RECEIVER_ID === RECEIVER_ID &&
      !deliveryEnabled && !!canaryConfiguration(env, clock());
    return { storageConfigured: !!env.DATABASE_URL, callbackProtectorConfigured,
      currentAccessCheckConfigured: !!policyIds.jarvis,
      subscriptionSetupEnabled: !!base && env.BRIDGE_SUBSCRIPTIONS_ENABLED === 'true',
      fridaySenderConfigured: senderConfigured, receiverPolicyVerified, fridayContractVerified, fridayWebhookDiagnosticArmed,
      canaryArmed, deliveryEnabled };
  }
  const taskPolicy = { issuer: provider?.issuer, subject: env.BRIDGE_ALLOWED_SUBJECT,
    subjectHash: env.BRIDGE_ALLOWED_SUBJECT_SHA256, scopeClaim: env.BRIDGE_OAUTH_SCOPE_CLAIM || 'scope' };
  const tasksReady = () => taskOptedIn && contractReady && env.BRIDGE_OAUTH_CONTRACT_VERIFIED === 'true' && readiness().deliveryEnabled;
  if (taskOptedIn) {
    if (!tasksReady()) throw new BridgeError('task_runtime_policy_required', 503);
    createTaskAccess(taskPolicy); // Validate trusted policy before advertising any task tool.
  }
  const armedCanary = () => readiness().canaryArmed ? canaryConfiguration(env, clock()) : null;
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
    protector = key ? createProtector(key) : undefined;
    transport = ready.subscriptionSetupEnabled || delivery ? transportFactory({ enabled: true }) : undefined;
    events = new NativeEvents({ store, protector, transport, policyId: policyIds.jarvis, clock, enabled: ready.subscriptionSetupEnabled });
    const nativeSender = delivery ? fridaySender || createFridaySender({ enabled: true, contractVerified: true,
      endpoint: env.FRIDAY_WEBHOOK_URL, secret: env.FRIDAY_WEBHOOK_KEY, transport }) : undefined;
    // With a canary configuration, only its reserved source/ACK on the pinned
    // return subscription passes, and only while the canary is still armed.
    const nativeAccess = async (input, canary) => store.transaction(state => {
      const message = state.messages[input.messageId];
      if (!dailyMessage(message?.envelope) || !messageAccessAllowed(state, message, policyIds, clock()) || message.envelope.to !== input.recipient) return false;
      if (canary && !(canaryTarget(state, canary, input) && readiness().canaryArmed)) return false;
      if (input.recipient === 'jarvis') {
        const sub = state.subscriptions[input.subscriptionId];
        return sub?.owner === input.owner && subscriptionAccessAllowed(state, sub, policyIds.jarvis, clock());
      }
      return input.recipient === 'friday' && (!!canary || readiness().deliveryEnabled);
    });
    authorize = async (input, canary) => (await nativeAccess(input, canary)) && (!accessAllowed || await accessAllowed(input));
    const worker = new DeliveryWorker({ store, protector, transport, policyId: policyIds.jarvis,
      messagePolicyIds: policyIds, clock, accessAllowed: authorize, fridaySender: nativeSender, enabled: delivery });
    queue = createQueueAdapter({ client, store, worker, clock, enabled: delivery, maintenanceEnabled: true });
    diagnostic = createFridayDiagnostic({ store, endpoint: env.FRIDAY_WEBHOOK_URL, secret: env.FRIDAY_WEBHOOK_KEY,
      transport: transport || transportFactory({ enabled: true }), from: env.FRIDAY_WEBHOOK_DIAGNOSTIC_FROM,
      until: env.FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL, clock });
    bridge = new Bridge({ store, clock, messagePolicyIds: policyIds, dailyEnabled: true,
      prepareMessage: id => queue.prepareMessage(id), prepareReceipt: id => queue.prepareReceipt(id) });
  }
  // Built per use from the current armed configuration. The Friday sender's
  // unverified probe mode permits one first-attempt job for this source only;
  // canary jobs also persist a one-attempt limit, so no ambiguous send repeats.
  function canaryParts(config) {
    const post = transport || transportFactory({ enabled: true });
    const worker = new DeliveryWorker({ store, protector, transport: terminalTransport(post), policyId: policyIds.jarvis, messagePolicyIds: policyIds, clock,
      accessAllowed: input => authorize(input, config), enabled: true, maxAttempts: 1, deliveryUntil: config.until,
      fridaySender: createFridaySender({ enabled: true, probeMessageId: config.messageId,
        endpoint: env.FRIDAY_WEBHOOK_URL, secret: env.FRIDAY_WEBHOOK_KEY, transport: post }),
      jobAllowed: (state, job) => canaryJob(state, config, job) });
    const canaryQueue = createQueueAdapter({ client, store, worker, clock, enabled: true });
    return { queue: canaryQueue, bridge: new Bridge({ store, clock, messagePolicyIds: policyIds, dailyEnabled: true,
      deliveryUntil: config.until, canary: config,
      prepareMessage: id => canaryQueue.prepareMessage(id), prepareReceipt: id => canaryQueue.prepareReceipt(id) }) };
  }
  const taskOperations = taskOptedIn ? {
    get enabled() { return tasksReady(); },
    ...Object.fromEntries(['apply', 'get', 'getByMessageId'].map(method => [method, async (...args) => {
      if (!tasksReady()) throw new BridgeError('task_runtime_policy_required', 503);
      configure();
      taskCapability ||= createTaskCapability({ ...taskOptions, enabled: true, store, bridge, policy: taskPolicy, clock });
      return taskCapability[method](...args);
    }])),
  } : undefined;
  return {
    handler(role) {
      if (!identityConfigured) throw new BridgeError('provider_contract_verification_required', 503);
      const verify = createAccessVerifier({ issuer: provider.issuer, audience: resourceFor(role),
        subject: env.BRIDGE_ALLOWED_SUBJECT, subjectHash: env.BRIDGE_ALLOWED_SUBJECT_SHA256,
        scopeClaim: env.BRIDGE_OAUTH_SCOPE_CLAIM || 'scope', role, keyResolver: resolver });
      const run = method => async (...args) => {
        if (['sendMessage', 'claim', 'complete'].includes(method) && !readiness().deliveryEnabled) {
          // Narrow server-armed exception: the fixed canary source and its ACK only.
          const canary = armedCanary();
          if (!canary) throw new BridgeError('receiver_readiness_required', 503);
          configure(); return canaryParts(canary).bridge[method](...args);
        }
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
      const fridayDiagnostic = { run: async principal => {
        if (!readiness().fridayWebhookDiagnosticArmed) throw new BridgeError('friday_diagnostic_not_armed', 503);
        configure(); return diagnostic(principal);
      } };
      return createMcpHandler({ enabled: true, verify, bridge: operations, events: nativeEvents,
        dailyEnabled: true, healthOnly: !contractReady, fridayDiagnostic, tasks: taskOperations,
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
        if (readiness().deliveryEnabled || cleanup) return queue.consume(...args);
        // Canary mode admits only its own source/ACK dispatch items; direct job
        // IDs and all other queued work stay closed and untouched.
        const canary = armedCanary();
        if (canary && canaryDispatch(payload, canary)) return canaryParts(canary).queue.consume(...args);
        throw new BridgeError('delivery_not_enabled', 503);
      }, { visibilityTimeoutSeconds: 60, retry: queue.retry });
    },
    async close() { await pool?.end(); },
  };
}
export const runtime = createRuntime();
