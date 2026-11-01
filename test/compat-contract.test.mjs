import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { CONFIG, webhookPeerSettings } from '../src/config.mjs';
import { SCOPES } from '../src/policy.mjs';
import { MESSAGE_PROTOCOL, validateMessage } from '../src/messages.mjs';
import { createResourceRouter, providerConfiguration, resourceFor, ORIGIN } from '../src/resource.mjs';
import { createRuntime } from '../src/runtime.mjs';
import { createWebhookSender } from '../src/webhook-sender.mjs';
import { digest } from '../src/events.mjs';
import { CANARY_TEXT } from '../src/canary.mjs';
import { QUEUE_REGION, QUEUE_TOPIC, RECEIVER_ID, SERVER_NAME, SERVICE_NAME } from '../src/release.mjs';
import { VERIFIED_AUTHORIZATION } from '../src/policy.mjs';
import { ISSUER } from './fixtures/provider.mjs';

// Compatibility mode is what the existing production deployment runs: no
// BRIDGE_PUBLIC_ORIGIN, BRIDGE_PEERS or other new variable is set. These tests
// pin its externally visible contract so the generalization changes nothing.
const PRODUCTION_ORIGIN = 'https://jarvis-friday-bridge.aravhawk.com';

test('compatibility mode keeps the original deployment identity exactly', () => {
  assert.equal(CONFIG.compat, true);
  assert.equal(ORIGIN, PRODUCTION_ORIGIN);
  assert.deepEqual(CONFIG.peerIds, ['jarvis', 'friday']);
  assert.deepEqual(SCOPES, {
    jarvis: { probe: 'bridge:send:friday', ack: 'bridge:ack:jarvis' },
    friday: { probe: 'bridge:send:jarvis', ack: 'bridge:ack:friday' },
  });
  assert.equal(MESSAGE_PROTOCOL, 'jarvis-friday/1');
  assert.equal(SERVICE_NAME, 'Jarvis Friday Bridge'); assert.equal(SERVER_NAME, 'jarvis-friday-bridge');
  assert.equal(RECEIVER_ID, 'jarvis-friday-bridge-inbox');
  assert.equal(QUEUE_TOPIC, 'jarvis-friday-bridge-v1'); assert.equal(QUEUE_REGION, 'iad1');
  const vercel = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url)));
  assert.deepEqual(vercel.regions, [QUEUE_REGION]);
  assert.equal(vercel.functions['api/queue.mjs'].experimentalTriggers[0].topic, QUEUE_TOPIC);
  assert.equal(CONFIG.requireIssuerUnderOrigin, true); assert.equal(CONFIG.databaseHostSuffix, '.neon.tech');
  assert.deepEqual(CONFIG.names, { prefix: 'friday', diagnosticTool: 'bridge_friday_webhook_diagnostic',
    senderConfigured: 'fridaySenderConfigured', contractVerified: 'fridayContractVerified',
    diagnosticArmed: 'fridayWebhookDiagnosticArmed', diagnosticState: 'fridayWebhookDiagnostic', canaryState: 'fridayCanary' });
  assert.equal(CANARY_TEXT, 'Jarvis Friday Bridge canary: one-time status data only. No action is requested.');
});

test('public health, metadata and challenges match the live production responses byte for byte', async () => {
  const router = createResourceRouter({ getHandler: () => () => Response.json({}), getProvider: () => providerConfiguration(ISSUER) });
  assert.equal(await (await router(new Request(ORIGIN + '/health'))).text(),
    '{"status":"ok","service":"Jarvis Friday Bridge","version":"1.0.0","authenticationRequired":true}');
  for (const [role, scopes] of [['jarvis', '["bridge:send:friday","bridge:ack:jarvis"]'], ['friday', '["bridge:send:jarvis","bridge:ack:friday"]']]) {
    const path = `/bridge/${role}/mcp`, metadata = `/.well-known/oauth-protected-resource${path}`;
    assert.equal(await (await router(new Request(ORIGIN + metadata))).text(),
      `{"resource":"${PRODUCTION_ORIGIN}${path}","authorization_servers":["${ISSUER}"],"bearer_methods_supported":["header"],` +
      `"scopes_supported":${scopes},"resource_name":"Jarvis Friday Bridge — ${role}"}`);
    const challenge = await router(new Request(ORIGIN + path, { method: 'POST' }));
    assert.equal(challenge.status, 401);
    assert.equal(challenge.headers.get('www-authenticate'), `Bearer resource_metadata="${PRODUCTION_ORIGIN}${metadata}"`);
  }
});

test('compatibility mode still requires the issuer beneath the origin and pins Neon storage', async () => {
  assert.equal(providerConfiguration('https://clerk.' + new URL(PRODUCTION_ORIGIN).hostname).issuer,
    'https://clerk.' + new URL(PRODUCTION_ORIGIN).hostname);
  assert.equal(providerConfiguration('https://auth.identity-provider.example'), null);
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const rt = createRuntime({ env: { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture-subject',
    DATABASE_URL: 'postgresql:' + '//fixture:fixture@db.postgres-provider.example/app?sslmode=require' },
    Pool: class { constructor() { assert.fail('a non-Neon host must be rejected before a pool exists'); } },
    keyResolver: publicKey, queueClient: {} });
  const token = await new SignJWT({ scope: 'bridge:ack:friday bridge:send:jarvis' }).setProtectedHeader({ alg: 'RS256' })
    .setIssuer(ISSUER).setSubject('fixture-subject').setAudience(resourceFor('friday')).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const response = await rt.handler('friday')(new Request(resourceFor('friday'), { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'bridge_status', arguments: { messageId: '00000000-0000-4000-8000-000000000001' } } }) }));
  assert.deepEqual((await response.json()).result.structuredContent, { error: 'storage_tls_configuration_required' });
});

test('existing FRIDAY_* variables keep driving the webhook peer with bearer authentication', async () => {
  const legacy = { FRIDAY_WEBHOOK_URL: 'https://receiver.example.test/hook', FRIDAY_WEBHOOK_KEY: 'legacy-shared-key',
    FRIDAY_RECEIVER_ID: 'jarvis-friday-bridge-inbox', FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true',
    FRIDAY_WEBHOOK_DIAGNOSTIC_FROM: 'a', FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL: 'b', FRIDAY_CANARY_MESSAGE_ID: 'c',
    FRIDAY_CANARY_RETURN_SUBSCRIPTION_ID: 'd', FRIDAY_CANARY_FROM: 'e', FRIDAY_CANARY_UNTIL: 'f' };
  assert.equal(CONFIG.webhookEnvPrefix, 'BRIDGE_PEER_FRIDAY_');
  assert.deepEqual({ ...webhookPeerSettings(legacy) }, { url: legacy.FRIDAY_WEBHOOK_URL, receiverId: legacy.FRIDAY_RECEIVER_ID,
    contractVerified: 'true', diagnosticFrom: 'a', diagnosticUntil: 'b', canaryMessageId: 'c',
    canaryReturnSubscriptionId: 'd', canaryFrom: 'e', canaryUntil: 'f', secret: 'legacy-shared-key', auth: 'bearer' });
  // Per-peer names take precedence and select Standard Webhooks signing.
  const override = webhookPeerSettings({ ...legacy, BRIDGE_PEER_FRIDAY_WEBHOOK_URL: 'https://new.example.test/hook',
    BRIDGE_PEER_FRIDAY_WEBHOOK_SECRET: 'whsec_x' });
  assert.equal(override.url, 'https://new.example.test/hook'); assert.equal(override.secret, 'whsec_x');
  assert.equal(override.auth, 'standard-webhooks'); assert.equal(override.receiverId, legacy.FRIDAY_RECEIVER_ID);
  const routine = webhookPeerSettings({ BRIDGE_PEER_FRIDAY_WEBHOOK_URL: 'https://routine.example.test/hook',
    BRIDGE_PEER_FRIDAY_WEBHOOK_SECRET: 'routine-shared-key', BRIDGE_PEER_FRIDAY_WEBHOOK_AUTH: 'bearer' });
  assert.equal(routine.auth, 'bearer'); assert.equal(routine.secret, 'routine-shared-key');

  const posts = [], messageId = randomUUID(), eventId = 'evt_' + digest(JSON.stringify([messageId, 'friday']));
  const settings = webhookPeerSettings(legacy);
  const send = createWebhookSender({ enabled: true, contractVerified: true, endpoint: settings.url, secret: settings.secret,
    auth: settings.auth, transport: async (url, request) => { posts.push({ url, ...request }); return { status: 200 }; } });
  await send({ id: 'job_' + eventId.slice(4), eventId, messageId, recipient: 'friday', attempts: 1,
    body: JSON.stringify({ event: 'bridge.message.received', data: { messageId } }) });
  assert.deepEqual(posts, [{ url: legacy.FRIDAY_WEBHOOK_URL, body: `{"event":"bridge.message.received","data":{"messageId":"${messageId}"}}`,
    headers: { 'content-type': 'application/json', authorization: 'Bearer legacy-shared-key' } }]);
});

test('the generic protocol ID is accepted as an alias and stored under the legacy ID', () => {
  const now = Date.now();
  const jarvis = Object.defineProperty({ role: 'jarvis', scopes: Object.values(SCOPES.jarvis), principalKey: 'a'.repeat(64) },
    VERIFIED_AUTHORIZATION, { value: { policyId: 'c'.repeat(64), expiresAt: now + 60000 } });
  const input = { id: randomUUID(), from: 'jarvis', to: 'friday', kind: 'message', sentAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 60000).toISOString(), threadId: randomUUID(), route: 'inbox', text: 'data' };
  const legacy = validateMessage({ ...input, protocol: 'jarvis-friday/1' }, jarvis, now);
  const alias = validateMessage({ ...input, protocol: 'agent-inbox/1' }, jarvis, now);
  assert.equal(alias.envelope.protocol, 'jarvis-friday/1');
  assert.deepEqual(alias, legacy);
  assert.throws(() => validateMessage({ ...input, protocol: 'other/1' }, jarvis, now), /invalid_message/);
});
