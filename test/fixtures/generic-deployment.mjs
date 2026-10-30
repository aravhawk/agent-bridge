// Child-process scenario for test/generic-deployment.test.mjs. Deployment
// identity is read once at import, so this runs under its own environment:
// BRIDGE_PUBLIC_ORIGIN=https://bridge.example.com, BRIDGE_PEERS=alice:events,bob:webhook,
// BRIDGE_QUEUE_TOPIC=inbox-test-v1, BRIDGE_QUEUE_REGION=sfo1. Exits non-zero on failure.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { Webhook } from 'standardwebhooks';
import { CONFIG, loadConfig } from '../../src/config.mjs';
import { SCOPES } from '../../src/policy.mjs';
import { createRuntime } from '../../src/runtime.mjs';
import { createResourceRouter, providerConfiguration, resourceFor } from '../../src/resource.mjs';
import { emptyState } from '../../src/store.mjs';

const ORIGIN = 'https://bridge.example.com';
const ISSUER = 'https://auth.identity-provider.example'; // Deliberately NOT under ORIGIN.
assert.equal(CONFIG.compat, false);
assert.equal(CONFIG.origin, ORIGIN);
assert.deepEqual(CONFIG.peerIds, ['alice', 'bob']);
assert.deepEqual(SCOPES, { alice: { probe: 'bridge:send:bob', ack: 'bridge:ack:alice' },
  bob: { probe: 'bridge:send:alice', ack: 'bridge:ack:bob' } });
assert.equal(CONFIG.protocol, 'agent-inbox/1');
assert.deepEqual(CONFIG.acceptedProtocols, ['agent-inbox/1', 'jarvis-friday/1']);

// Issuer-under-origin is opt-in outside compatibility mode.
assert.equal(providerConfiguration(ISSUER).issuer, ISSUER);
assert.equal(providerConfiguration(ISSUER, { requireUnderOrigin: true }), null);
assert.equal(providerConfiguration('https://login.bridge.example.com', { requireUnderOrigin: true }).issuer, 'https://login.bridge.example.com');
assert.equal(loadConfig({ ...process.env, BRIDGE_REQUIRE_ISSUER_UNDER_ORIGIN: 'true' }).requireIssuerUnderOrigin, true);
for (const unsafe of ['http://auth.example', 'https://127.0.0.1', 'https://auth.example/path', 'https://idp.localhost'])
  assert.equal(providerConfiguration(unsafe), null, unsafe);

// Public routing follows the configured origin and peers only.
const router = createResourceRouter({ getHandler: () => () => Response.json({}), getProvider: () => providerConfiguration(ISSUER) });
assert.deepEqual(await (await router(new Request(ORIGIN + '/health'))).json(),
  { status: 'ok', service: 'Agent Inbox Bridge', version: '1.0.0', authenticationRequired: true });
assert.deepEqual(await (await router(new Request(ORIGIN + '/.well-known/oauth-protected-resource/bridge/alice/mcp'))).json(), {
  resource: ORIGIN + '/bridge/alice/mcp', authorization_servers: [ISSUER], bearer_methods_supported: ['header'],
  scopes_supported: ['bridge:send:bob', 'bridge:ack:alice'], resource_name: 'Agent Inbox Bridge — alice' });
for (const path of ['/bridge/jarvis/mcp', '/bridge/friday/mcp']) assert.equal((await router(new Request(ORIGIN + path, { method: 'POST' }))).status, 404);
assert.equal((await router(new Request('https://jarvis-friday-bridge.aravhawk.com/bridge/alice/mcp', { method: 'POST' }))).status, 404);

// Full runtime: any TLS Postgres host, Standard Webhooks peer, env-driven queue.
const { publicKey, privateKey } = await generateKeyPair('RS256');
const peerSecret = 'whsec_' + randomBytes(32).toString('base64');
let document = emptyState(), connectionString;
class FakePool {
  constructor(options) { connectionString = options.connectionString; }
  on() {}
  async end() {}
  async connect() { return { release() {}, async query(sql, params) {
    if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(document) }] };
    if (sql.startsWith('UPDATE bridge_runtime_v1')) document = JSON.parse(params[0]);
    return { rows: [] };
  } }; }
}
const published = [], posts = [];
const queueClient = {
  async send(topic, payload, options) { published.push({ topic, payload, region: options.region }); },
  handleCallback: consume => consume,
};
const env = { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture-subject',
  BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_DELIVERY_ENABLED: 'true', BRIDGE_RECEIVER_POLICY: 'inbox-v1',
  BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
  // Split so repository audits do not mistake the fixture for a credential URL.
  DATABASE_URL: 'postgresql:' + '//fixture:fixture@db.postgres-provider.example/app?sslmode=require',
  BRIDGE_PEER_BOB_WEBHOOK_URL: 'https://bob.example.net/hooks/bridge', BRIDGE_PEER_BOB_WEBHOOK_SECRET: peerSecret,
  BRIDGE_PEER_BOB_RECEIVER_ID: 'agent-inbox-bridge', BRIDGE_PEER_BOB_WEBHOOK_CONTRACT_VERIFIED: 'true' };
const rt = createRuntime({ env, Pool: FakePool, keyResolver: publicKey, queueClient,
  transportFactory: () => async (url, request) => {
    if (url === 'https://alice.example.net/events') {
      return { status: 200, body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) };
    }
    posts.push({ url, ...request }); return { status: 202, body: '' };
  } });
const token = (peer, scope) => new SignJWT({ scope }).setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER)
  .setSubject('fixture-subject').setAudience(resourceFor(peer)).setIssuedAt().setExpirationTime('5m').sign(privateKey);
const tokens = { alice: await token('alice', 'bridge:ack:alice bridge:send:bob'), bob: await token('bob', 'bridge:ack:bob bridge:send:alice') };
const rpc = async (peer, method, params = {}) => {
  const response = await rt.handler(peer)(new Request(resourceFor(peer), { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tokens[peer] },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
  return response.json();
};
const call = async (peer, name, args = {}) => {
  const { result, error } = await rpc(peer, 'tools/call', { name, arguments: args });
  assert.equal(error, undefined, JSON.stringify(error)); assert.notEqual(result.isError, true, JSON.stringify(result));
  return result.structuredContent;
};

assert.equal((await rpc('alice', 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'fixture', version: '1' } }))
  .result.serverInfo.name, 'agent-inbox-bridge');
const aliceTools = (await rpc('alice', 'tools/list')).result.tools;
assert.ok(aliceTools.some(t => t.name === 'bridge_webhook_diagnostic'));
assert.ok(aliceTools.some(t => t.name === 'bridge_subscription_status'));
const sendTool = aliceTools.find(t => t.name === 'bridge_message_send');
assert.deepEqual(sendTool.inputSchema.properties.protocol, { const: 'agent-inbox/1' });
assert.deepEqual(sendTool.inputSchema.properties.to, { enum: ['alice', 'bob'] });
assert.equal(JSON.stringify(aliceTools).toLowerCase().includes('jarvis'), false);
assert.equal(JSON.stringify(aliceTools).toLowerCase().includes('friday'), false);
const health = await call('alice', 'bridge_health');
assert.deepEqual(Object.keys(health.readiness), ['storageConfigured', 'callbackProtectorConfigured',
  'currentAccessCheckConfigured', 'subscriptionSetupEnabled', 'webhookSenderConfigured', 'receiverPolicyVerified',
  'webhookContractVerified', 'webhookDiagnosticArmed', 'canaryArmed', 'deliveryEnabled']);
assert.equal(health.readiness.deliveryEnabled, true);
assert.deepEqual(health.caller, { role: 'alice', sendScope: true, ackScope: true, tools: aliceTools.map(t => t.name) });

// The events peer registers its return path, then sends with the legacy protocol alias.
const subscribed = await rpc('alice', 'events/subscribe', { name: 'bridge.message.received', arguments: { recipient: 'alice' },
  delivery: { mode: 'webhook', url: 'https://alice.example.net/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
assert.match(subscribed.result.id, /^sub_[a-f0-9]{64}$/);
assert.equal(new URL(connectionString).hostname, 'db.postgres-provider.example');
assert.equal(new URL(connectionString).searchParams.get('sslmode'), 'verify-full');
const now = Date.now(), id = randomUUID();
const sent = await call('alice', 'bridge_message_send', { protocol: 'jarvis-friday/1', id, from: 'alice', to: 'bob', kind: 'message',
  sentAt: new Date(now).toISOString(), expiresAt: new Date(now + 3600000).toISOString(), threadId: randomUUID(),
  route: 'inbox', text: 'Status data for the receiving assistant.' });
assert.equal(sent.messageId, id);
assert.ok(published.length > 0 && published.every(p => p.topic === 'inbox-test-v1' && p.region === 'sfo1'));
const dispatch = published.find(p => p.payload.dispatchMessageId === id);
assert.ok(dispatch, 'message preparation publishes a dispatch item');

// The private queue consumer delivers one Standard Webhooks request to the webhook peer.
await rt.queueHandler()(dispatch.payload, { topicName: 'inbox-test-v1', region: 'sfo1', deliveryCount: 1 });
assert.equal(posts.length, 1);
const [post] = posts;
assert.equal(post.url, 'https://bob.example.net/hooks/bridge');
assert.equal('authorization' in post.headers, false);
assert.deepEqual(new Webhook(peerSecret).verify(post.body, post.headers), { event: 'bridge.message.received', data: { messageId: id } });
assert.equal(post.headers['webhook-id'], document.jobs[document.messages[id].jobIds[0]].eventId);
assert.equal(document.jobs[document.messages[id].jobIds[0]].state, 'accepted');

// The webhook peer reads the stored data; the alias was normalized to the canonical ID.
const read = await call('bob', 'bridge_read', { messageId: id });
assert.equal(read.envelope.protocol, 'agent-inbox/1');
assert.equal(read.envelope.from, 'alice'); assert.equal(read.authority, 'peer_data_requires_user_workflow');
await rt.close();
console.log('generic deployment scenario passed');
