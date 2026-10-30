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
import { createWebhookSender, webhookSenderConfigured } from './webhook-sender.mjs';
import { createWebhookDiagnostic, diagnosticWindowOpen } from './webhook-diagnostic.mjs';
import { canaryConfiguration, canaryTarget, canaryJob, canaryDispatch } from './canary.mjs';
import { VERSION, RECEIVER_ID, QUEUE_REGION } from './release.mjs';
import { CONFIG, EVENTS_PEER, WEBHOOK_PEER, PEER_IDS, NAMES, peerCode, webhookPeerSettings } from './config.mjs';
import { createTaskCapability, validateTaskCapabilityOptions } from './task-capability.mjs';
import { createTaskAccess } from './task-access.mjs';
import { wakeSyncRecipients, WAKE_SYNC_FLAG } from './sync.mjs';
import { timingSafeEqual } from 'node:crypto';

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
// credentials, issuance and refresh. Secrets are injected by the platform, never pulled.
export function createRuntime({ env = process.env, Pool = pg.Pool, keyResolver,
  queueClient, accessAllowed, webhookSender, clock = Date.now, transportFactory = createPublicWebhookTransport,
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
  // Webhook peer settings: BRIDGE_PEER_<ID>_* with FRIDAY_* fallbacks. Read per
  // use, like every other readiness input, so withdrawn settings close at once.
  const peerSettings = () => webhookPeerSettings(env);
  const destination = () => { const peer = peerSettings(); return { endpoint: peer.url, secret: peer.secret, auth: peer.auth }; };
  // Wake/sync rollout flag, read per use so flipping it rolls back at once.
  const wakeSync = () => wakeSyncRecipients(env[WAKE_SYNC_FLAG]).recipients;
  let pool, store, bridge, events, queue, diagnostic, transport, protector, authorize, taskCapability;
  const resolver = keyResolver || (provider ? createRemoteJWKSet(new URL(provider.jwks), { timeoutDuration: 5000 }) : undefined);
  const client = queueClient || new QueueClient({ region: QUEUE_REGION, telemetry: { isEnabled: false } });
  const policyIds = Object.fromEntries(PEER_IDS.map(role => [role, identityConfigured
    ? authorizationPolicyId({ issuer: provider.issuer, audience: resourceFor(role), role,
      subject: env.BRIDGE_ALLOWED_SUBJECT, subjectHash: env.BRIDGE_ALLOWED_SUBJECT_SHA256,
      scopeClaim: env.BRIDGE_OAUTH_SCOPE_CLAIM || 'scope' }) : null]));
  // Reported only once the flag is set, so the v1 health shape is unchanged.
  function wakeSyncReadiness() {
    const parsed = wakeSyncRecipients(env[WAKE_SYNC_FLAG]);
    return parsed.configured ? { wakeSync: { valid: parsed.valid, recipients: parsed.recipients,
      flushScheduleConfigured: !!env.CRON_SECRET } } : {};
  }
  function readiness() {
    const callbackProtectorConfigured = !!decodeStorageKey(env.BRIDGE_SUBSCRIPTION_STORAGE_KEY);
    const base = contractReady && callbackProtectorConfigured && !!env.DATABASE_URL;
    const peer = peerSettings();
    const senderConfigured = webhookSenderConfigured(destination());
    const receiverPolicyVerified = env.BRIDGE_RECEIVER_POLICY === 'inbox-v1' && peer.receiverId === RECEIVER_ID;
    const webhookContractVerified = peer.contractVerified === 'true';
    // Independent of delivery: one operator-armed transport check only.
    const webhookDiagnosticArmed = contractReady && !!env.DATABASE_URL && senderConfigured &&
      peer.receiverId === RECEIVER_ID && diagnosticWindowOpen(peer.diagnosticFrom, peer.diagnosticUntil, clock());
    const deliveryEnabled = !!base && env.BRIDGE_DELIVERY_ENABLED === 'true' &&
      senderConfigured && receiverPolicyVerified && webhookContractVerified;
    // Stored-message canary: only while normal delivery is off. Its ID is never
    // reported; a durable reservation (not this flag) decides whether it is spent.
    const canaryArmed = base && senderConfigured && peer.receiverId === RECEIVER_ID &&
      !deliveryEnabled && !!canaryConfiguration(env, clock());
    return { storageConfigured: !!env.DATABASE_URL, callbackProtectorConfigured,
      currentAccessCheckConfigured: !!policyIds[EVENTS_PEER],
      subscriptionSetupEnabled: !!base && env.BRIDGE_SUBSCRIPTIONS_ENABLED === 'true',
      [NAMES.senderConfigured]: senderConfigured, receiverPolicyVerified,
      [NAMES.contractVerified]: webhookContractVerified, [NAMES.diagnosticArmed]: webhookDiagnosticArmed,
      canaryArmed, deliveryEnabled, ...wakeSyncReadiness() };
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
    // Any PostgreSQL with a publicly trusted TLS certificate; an optional
    // BRIDGE_DATABASE_HOST_SUFFIX pins the provider (compatibility: .neon.tech).
    if (!['postgres:', 'postgresql:'].includes(db.protocol) ||
        (CONFIG.databaseHostSuffix && !db.hostname.endsWith(CONFIG.databaseHostSuffix)) ||
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
    events = new NativeEvents({ store, protector, transport, policyId: policyIds[EVENTS_PEER], clock, enabled: ready.subscriptionSetupEnabled });
    const nativeSender = delivery ? webhookSender || createWebhookSender({ enabled: true, contractVerified: true,
      ...destination(), transport, clock }) : undefined;
    // With a canary configuration, only its reserved source/ACK on the pinned
    // return subscription passes, and only while the canary is still armed.
    const nativeAccess = async (input, canary) => store.transaction(state => {
      const message = state.messages[input.messageId];
      if (!dailyMessage(message?.envelope) || !messageAccessAllowed(state, message, policyIds, clock()) || message.envelope.to !== input.recipient) return false;
      if (canary && !(canaryTarget(state, canary, input) && readiness().canaryArmed)) return false;
      if (input.recipient === EVENTS_PEER) {
        const sub = state.subscriptions[input.subscriptionId];
        return sub?.owner === input.owner && subscriptionAccessAllowed(state, sub, policyIds[EVENTS_PEER], clock());
      }
      return input.recipient === WEBHOOK_PEER && (!!canary || readiness().deliveryEnabled);
    });
    authorize = async (input, canary) => (await nativeAccess(input, canary)) && (!accessAllowed || await accessAllowed(input));
    const worker = new DeliveryWorker({ store, protector, transport, policyId: policyIds[EVENTS_PEER],
      messagePolicyIds: policyIds, clock, accessAllowed: authorize, webhookSender: nativeSender, enabled: delivery });
    queue = createQueueAdapter({ client, store, worker, clock, enabled: delivery, maintenanceEnabled: true });
    const peer = peerSettings();
    diagnostic = createWebhookDiagnostic({ store, ...destination(),
      transport: transport || transportFactory({ enabled: true }), from: peer.diagnosticFrom,
      until: peer.diagnosticUntil, clock });
    bridge = new Bridge({ store, clock, messagePolicyIds: policyIds, dailyEnabled: true, wakeSync,
      prepareMessage: id => queue.prepareMessage(id), prepareReceipt: id => queue.prepareReceipt(id) });
  }
  // Built per use from the current armed configuration. The webhook sender's
  // unverified probe mode permits one first-attempt job for this source only;
  // canary jobs also persist a one-attempt limit, so no ambiguous send repeats.
  function canaryParts(config) {
    const post = transport || transportFactory({ enabled: true });
    const worker = new DeliveryWorker({ store, protector, transport: terminalTransport(post), policyId: policyIds[EVENTS_PEER], messagePolicyIds: policyIds, clock,
      accessAllowed: input => authorize(input, config), enabled: true, maxAttempts: 1, deliveryUntil: config.until,
      webhookSender: createWebhookSender({ enabled: true, probeMessageId: config.messageId,
        ...destination(), transport: post, clock }),
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
      const operations = Object.fromEntries(['sendMessage', 'claim', 'complete', 'read', 'status', 'inboxRead'].map(m => [m, run(m)]));
      const nativeEvents = {
        list: (...args) => new NativeEvents({}).list(...args),
        subscribe: async (...args) => {
          authorizeRecipient(args[0], EVENTS_PEER);
          if (!readiness().subscriptionSetupEnabled) throw new BridgeError('events_not_enabled', 503);
          configure(); return events.subscribe(...args);
        },
        unsubscribe: async (...args) => { configure(); return events.unsubscribe(...args); },
        status: async (...args) => { configure(); return events.status(...args); },
      };
      const webhookDiagnostic = { run: async principal => {
        if (!readiness()[NAMES.diagnosticArmed]) throw new BridgeError(peerCode('diagnostic_not_armed'), 503);
        configure(); return diagnostic(principal);
      } };
      return createMcpHandler({ enabled: true, verify, bridge: operations, events: nativeEvents,
        dailyEnabled: true, healthOnly: !contractReady, webhookDiagnostic, tasks: taskOperations, wakeSync,
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
    // Hourly scheduled trigger (GitHub Actions POST, or any GET/POST caller with
    // `Authorization: Bearer $CRON_SECRET`). Each run flushes a recipient only
    // when due (see flushDue: America/Chicago even hour, the 2h elapsed maximum,
    // or expiry); otherwise it is a 200 no-op. Without CRON_SECRET the route
    // stays closed. No request input besides the bearer is used.
    cronHandler() {
      const reply = (body, status = 200) => Response.json(body, { status, headers: { 'cache-control': 'no-store' } });
      return async request => {
        if (!['GET', 'POST'].includes(request.method)) return reply({ error: 'method_not_allowed' }, 405);
        const secret = env.CRON_SECRET;
        if (typeof secret !== 'string' || secret.length < 16) return reply({ error: 'cron_not_configured' }, 503);
        const wanted = Buffer.from('Bearer ' + secret), actual = Buffer.from(request.headers.get('authorization') || '');
        if (actual.length !== wanted.length || !timingSafeEqual(actual, wanted)) return reply({ error: 'unauthorized' }, 401);
        if (!readiness().deliveryEnabled) return reply({ status: 'skipped', reason: 'delivery_not_enabled' });
        configure();
        const { boundary, results, dispatch } = await bridge.flushSync();
        const published = [];
        // Publish after commit; anything unpublished is re-offered by the next run
        // (including the workflow's curl retries of this one).
        for (const id of dispatch) { try { await queue.prepareMessage(id); published.push(id); } catch { /* retried next run */ } }
        if (published.length) await bridge.markSyncDispatched(published);
        return reply({ status: 'ok', boundary: new Date(boundary).toISOString(),
          flushed: results.filter(r => r.outcome === 'flushed').length, capped: results.filter(r => r.outcome === 'daily_cap').length,
          redeliveredNative: results.filter(r => r.outcome === 'native').reduce((n, r) => n + r.items, 0),
          dispatched: published.length, dispatchPending: dispatch.length - published.length });
      };
    },
    async close() { await pool?.end(); },
  };
}
export const runtime = createRuntime();
