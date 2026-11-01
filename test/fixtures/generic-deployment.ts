// Child-process scenario for test/generic-deployment.test.ts. Deployment
// identity is read once at import, so this runs under its own environment:
// BRIDGE_PUBLIC_ORIGIN=https://bridge.example.com, BRIDGE_PEERS=alice:events,bob:webhook,
// BRIDGE_QUEUE_TOPIC=inbox-test-v1, BRIDGE_QUEUE_REGION=sfo1. Exits non-zero on failure.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { Webhook } from 'standardwebhooks';
import { CONFIG, loadConfig } from '../../src/config.ts';
import { SCOPES } from '../../src/policy.ts';
import { createRuntime } from '../../src/runtime.ts';
import { createResourceRouter, providerConfiguration, resourceFor } from '../../src/resource.ts';
import { emptyState } from '../../src/store.ts';
import { wakeSyncRecipients } from '../../src/sync.ts';
import type { BatchPresentation, ClaimResult, CompleteResult, ReadResult, SendResult } from '../../src/bridge.ts';
import type { RuntimePoolConstructor, RuntimeQueueClient } from '../../src/runtime.ts';
import type { TransportRequest } from '../../src/webhook.ts';
import type { BridgeState } from '../../src/types.ts';
import type { ListedTool, RpcResponse } from '../types.ts';

type Consume = (payload: unknown, metadata: object) => Promise<unknown>;

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
assert.equal(providerConfiguration(ISSUER)!.issuer, ISSUER);
assert.equal(providerConfiguration(ISSUER, { requireUnderOrigin: true }), null);
assert.equal(providerConfiguration('https://login.bridge.example.com', { requireUnderOrigin: true })!.issuer, 'https://login.bridge.example.com');
assert.equal(loadConfig({ ...process.env, BRIDGE_REQUIRE_ISSUER_UNDER_ORIGIN: 'true' }).requireIssuerUnderOrigin, true);
for (const unsafe of ['http://auth.example', 'https://127.0.0.1', 'https://auth.example/path', 'https://idp.localhost'])
  assert.equal(providerConfiguration(unsafe), null, unsafe);

// Public routing follows the configured origin and peers only.
const router = createResourceRouter({ getHandler: () => () => Response.json({}), getProvider: () => providerConfiguration(ISSUER) });
assert.deepEqual(await (await router(new Request(ORIGIN + '/health'))).json(),
  { status: 'ok', service: 'Agent Bridge', version: '1.0.0', authenticationRequired: true });
assert.deepEqual(await (await router(new Request(ORIGIN + '/.well-known/oauth-protected-resource/bridge/alice/mcp'))).json(), {
  resource: ORIGIN + '/bridge/alice/mcp', authorization_servers: [ISSUER], bearer_methods_supported: ['header'],
  scopes_supported: ['bridge:send:bob', 'bridge:ack:alice'], resource_name: 'Agent Bridge — alice' });
for (const path of ['/bridge/jarvis/mcp', '/bridge/friday/mcp']) assert.equal((await router(new Request(ORIGIN + path, { method: 'POST' }))).status, 404);
assert.deepEqual(wakeSyncRecipients('friday'), { configured: true, valid: false, recipients: [] });
assert.equal((await router(new Request('https://jarvis-friday-bridge.aravhawk.com/bridge/alice/mcp', { method: 'POST' }))).status, 404);

// Full runtime: any TLS Postgres host, Standard Webhooks peer, env-driven queue.
const { publicKey, privateKey } = await generateKeyPair('RS256');
const peerSecret = 'whsec_' + randomBytes(32).toString('base64');
let document: BridgeState = emptyState(), connectionString: string | undefined;
class FakePool {
  constructor(options: { connectionString: string }) { connectionString = options.connectionString; }
  on() {}
  async end() {}
  async connect() { return { release() {}, async query(sql: string, params: string[]) {
    if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(document) }] };
    if (sql.startsWith('UPDATE bridge_runtime_v1')) document = JSON.parse(params[0]!);
    return { rows: [] };
  } }; }
}
const published: { topic: string; payload: Record<string, unknown>; region: string }[] = [], posts: ({ url: string } & TransportRequest)[] = [];
const queueClient = {
  async send(topic: string, payload: Record<string, unknown>, options: { region: string }) { published.push({ topic, payload, region: options.region }); },
  // The fake returns the consumer itself, so tests invoke it with (payload, metadata).
  handleCallback: (consume: unknown) => consume,
} as unknown as RuntimeQueueClient;
const env = { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: 'fixture-subject',
  BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_DELIVERY_ENABLED: 'true', BRIDGE_RECEIVER_POLICY: 'inbox-v1',
  BRIDGE_WAKE_SYNC_RECIPIENTS: 'bob',
  BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
  // Split so repository audits do not mistake the fixture for a credential URL.
  DATABASE_URL: 'postgresql:' + '//fixture:fixture@db.postgres-provider.example/app?sslmode=require',
  BRIDGE_PEER_BOB_WEBHOOK_URL: 'https://bob.example.net/hooks/bridge', BRIDGE_PEER_BOB_WEBHOOK_SECRET: peerSecret,
  BRIDGE_PEER_BOB_RECEIVER_ID: 'agent-inbox-bridge', BRIDGE_PEER_BOB_WEBHOOK_CONTRACT_VERIFIED: 'true' };
const rt = createRuntime({ env, Pool: FakePool as unknown as RuntimePoolConstructor, keyResolver: publicKey, queueClient,
  transportFactory: () => async (url, request) => {
    if (url === 'https://alice.example.net/events') {
      return { status: 200, body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) };
    }
    posts.push({ url, ...request }); return { status: 202, body: '' };
  } });
const token = (peer: string, scope: string) => new SignJWT({ scope }).setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER)
  .setSubject('fixture-subject').setAudience(resourceFor(peer)).setIssuedAt().setExpirationTime('15m').sign(privateKey);
const tokens: Record<string, string> = { alice: await token('alice', 'bridge:ack:alice bridge:send:bob'), bob: await token('bob', 'bridge:ack:bob bridge:send:alice') };
const rpc = async <R = Record<string, unknown>>(peer: string, method: string, params: object = {}): Promise<RpcResponse<R>> => {
  const response = await rt.handler(peer)(new Request(resourceFor(peer), { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tokens[peer] },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
  return response.json() as Promise<RpcResponse<R>>;
};
const call = async <T = Record<string, unknown>>(peer: string, name: string, args: object = {}): Promise<T> => {
  const { result, error } = await rpc<{ isError: boolean; structuredContent: T }>(peer, 'tools/call', { name, arguments: args });
  assert.equal(error, undefined, JSON.stringify(error)); assert.notEqual(result.isError, true, JSON.stringify(result));
  return result.structuredContent;
};

assert.equal((await rpc<{ serverInfo: { name: string } }>('alice', 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'fixture', version: '1' } }))
  .result.serverInfo.name, 'agent-inbox-bridge');
const aliceTools = (await rpc<{ tools: ListedTool[] }>('alice', 'tools/list')).result.tools;
const bobTools = (await rpc<{ tools: ListedTool[] }>('bob', 'tools/list')).result.tools;
assert.ok(aliceTools.some(t => t.name === 'bridge_webhook_diagnostic'));
assert.ok(aliceTools.some(t => t.name === 'bridge_subscription_status'));
assert.equal(aliceTools.some(t => t.name === 'bridge_inbox_read'), false);
assert.ok(bobTools.some(t => t.name === 'bridge_inbox_read'));
const sendTool = aliceTools.find(t => t.name === 'bridge_message_send');
assert.deepEqual(sendTool!.inputSchema.properties.protocol, { const: 'agent-inbox/1' });
assert.deepEqual(sendTool!.inputSchema.properties.to, { enum: ['alice', 'bob'] });
assert.equal(JSON.stringify(aliceTools).toLowerCase().includes('jarvis'), false);
assert.equal(JSON.stringify(aliceTools).toLowerCase().includes('friday'), false);
const health = await call<{ readiness: Record<string, unknown>; caller: unknown }>('alice', 'bridge_health');
assert.deepEqual(Object.keys(health.readiness), ['storageConfigured', 'callbackProtectorConfigured',
  'currentAccessCheckConfigured', 'subscriptionSetupEnabled', 'webhookSenderConfigured', 'receiverPolicyVerified',
  'webhookContractVerified', 'webhookDiagnosticArmed', 'canaryArmed', 'deliveryEnabled', 'wakeSync']);
assert.equal(health.readiness.deliveryEnabled, true);
assert.deepEqual(health.readiness.wakeSync, { valid: true, recipients: ['bob'], flushScheduleConfigured: false });
assert.deepEqual(health.caller, { role: 'alice', sendScope: true, ackScope: true, tools: aliceTools.map(t => t.name) });

// The events peer registers its return path, then sends with the legacy protocol alias.
const subscribed = await rpc<{ id: string }>('alice', 'events/subscribe', { name: 'bridge.message.received', arguments: { recipient: 'alice' },
  delivery: { mode: 'webhook', url: 'https://alice.example.net/events', secret: 'whsec_' + randomBytes(32).toString('base64') } });
assert.match(subscribed.result.id, /^sub_[a-f0-9]{64}$/);
assert.equal(new URL(connectionString!).hostname, 'db.postgres-provider.example');
assert.equal(new URL(connectionString!).searchParams.get('sslmode'), 'verify-full');
const now = Date.now(), id = randomUUID();
const sent = await call<SendResult>('alice', 'bridge_message_send', { protocol: 'jarvis-friday/1', id, from: 'alice', to: 'bob', kind: 'message',
  sentAt: new Date(now).toISOString(), expiresAt: new Date(now + 3600000).toISOString(), threadId: randomUUID(),
  route: 'inbox', text: 'Status data for the receiving assistant.' });
assert.equal(sent.messageId, id);
assert.ok(published.length > 0 && published.every(p => p.topic === 'inbox-test-v1' && p.region === 'sfo1'));
const dispatch = published.find(p => p.payload.dispatchMessageId === id);
assert.ok(dispatch, 'message preparation publishes a dispatch item');

// The private queue consumer delivers one Standard Webhooks request to the webhook peer.
// The fake handleCallback returned the consumer: (payload, metadata).
await (rt.queueHandler() as unknown as Consume)(dispatch!.payload, { topicName: 'inbox-test-v1', region: 'sfo1', deliveryCount: 1 });
assert.equal(posts.length, 1);
const [post] = posts;
assert.equal(post!.url, 'https://bob.example.net/hooks/bridge');
assert.equal('authorization' in post!.headers, false);
assert.deepEqual(new Webhook(peerSecret).verify(post!.body, post!.headers), { event: 'bridge.message.received', data: { messageId: id } });
assert.equal(post!.headers['webhook-id'], document.jobs[document.messages[id]!.jobIds[0]!]!.eventId);
assert.equal(document.jobs[document.messages[id]!.jobIds[0]!]!.state, 'accepted');

// The webhook peer reads the stored data; the alias was normalized to the canonical ID.
const read = await call<ReadResult>('bob', 'bridge_read', { messageId: id });
assert.equal(read.envelope.protocol, 'agent-inbox/1');
assert.equal(read.envelope.from, 'alice'); assert.equal(read.authority, 'peer_data_requires_user_workflow');

// The same arbitrary peer IDs work for the optional wake/sync path. The SYNC
// item creates no recipient delivery job, appears in one inbox batch, and
// gets one terminal correlated ACK only after that non-empty batch is completed.
const syncId = randomUUID(), beforeSyncPublications = published.length;
const synced = await call<SendResult>('alice', 'bridge_message_send', { protocol: 'agent-inbox/1', id: syncId,
  from: 'alice', to: 'bob', kind: 'status', sentAt: new Date(now).toISOString(),
  expiresAt: new Date(now + 6 * 3600000).toISOString(), threadId: randomUUID(), route: 'inbox',
  text: 'Generic queued status data.', class: 'sync', subject: 'Deployment status' });
assert.equal(synced.delivery, 'batched');
assert.deepEqual(document.messages[syncId]!.jobIds, []);
const preparedSyncDispatch = published.slice(beforeSyncPublications).find(p => p.payload.dispatchMessageId === syncId);
assert.ok(preparedSyncDispatch, 'internal pre-arm exists for commit-loss recovery');
const postsBeforeSyncDispatch = posts.length;
await (rt.queueHandler() as unknown as Consume)(preparedSyncDispatch!.payload, { topicName: 'inbox-test-v1', region: 'sfo1', deliveryCount: 1 });
assert.equal(posts.length, postsBeforeSyncDispatch, 'queued SYNC creates no recipient wake');
const inbox = await call<{ syncBatches: BatchPresentation[] }>('bob', 'bridge_inbox_read');
assert.equal(inbox.syncBatches.length, 1);
assert.deepEqual(inbox.syncBatches[0]!.items.map(item => item.messageId), [syncId]);
const batchId = inbox.syncBatches[0]!.messageId;
const claim = await call<ClaimResult>('bob', 'bridge_receipt_claim', { messageId: batchId });
const completed = await call<CompleteResult>('bob', 'bridge_receipt_complete', { messageId: batchId, claimId: claim.claimId,
  hostedEventId: null, hostedTurnId: null, syncBatchIds: [batchId] });
assert.ok(completed.ackMessageId); assert.deepEqual(completed.syncBatchesAcked, [batchId]);
await rt.close();
console.log('generic deployment scenario passed');
