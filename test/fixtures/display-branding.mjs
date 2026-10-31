// Child-process regression for display branding. Deployment identity is fixed
// at import, so each mode runs with a clean BRIDGE_* environment.
import assert from 'node:assert/strict';
import { CANARY_TEXT } from '../../src/canary.mjs';
import { CONFIG } from '../../src/config.mjs';
import { createMcpHandler } from '../../src/mcp.mjs';
import { createResourceRouter, resourceFor } from '../../src/resource.mjs';

const expectedName = process.env.EXPECTED_SERVICE_NAME;
const compat = process.env.EXPECTED_MODE === 'compat';
const peer = CONFIG.eventsPeer;
const expectedServerName = compat ? 'jarvis-friday-bridge' : 'agent-inbox-bridge';
const expectedProtocol = compat ? 'jarvis-friday/1' : 'agent-inbox/1';
const expectedReceiverId = compat ? 'jarvis-friday-bridge-inbox' : 'agent-inbox-bridge';
const expectedPeers = compat ? ['jarvis', 'friday'] : ['alice', 'bob'];
const expectedOrigin = compat ? 'https://jarvis-friday-bridge.aravhawk.com' : 'https://bridge.example.com';
const expectedScopes = compat ? {
  jarvis: { probe: 'bridge:send:friday', ack: 'bridge:ack:jarvis' },
  friday: { probe: 'bridge:send:jarvis', ack: 'bridge:ack:friday' },
} : {
  alice: { probe: 'bridge:send:bob', ack: 'bridge:ack:alice' },
  bob: { probe: 'bridge:send:alice', ack: 'bridge:ack:bob' },
};

assert.equal(CONFIG.compat, compat);
assert.equal(CONFIG.serviceName, expectedName);
assert.equal(CONFIG.serverName, expectedServerName);
assert.equal(CONFIG.protocol, expectedProtocol);
assert.equal(CONFIG.receiverId, expectedReceiverId);
assert.equal(CONFIG.origin, expectedOrigin);
assert.deepEqual(CONFIG.peerIds, expectedPeers);
assert.deepEqual(CONFIG.scopes, expectedScopes);
assert.equal(CANARY_TEXT, `${expectedName} canary: one-time status data only. No action is requested.`);

const router = createResourceRouter({ getHandler: () => () => Response.json({}),
  getProvider: () => ({ issuer: 'https://identity.example' }) });
for (const path of ['/', '/health']) {
  assert.deepEqual(await (await router(new Request(CONFIG.origin + path))).json(),
    { status: 'ok', service: expectedName, version: '1.0.0', authenticationRequired: true });
}
for (const expectedPeer of expectedPeers) {
  const expectedResource = `${expectedOrigin}/bridge/${expectedPeer}/mcp`;
  assert.equal(resourceFor(expectedPeer), expectedResource);
  const metadata = await (await router(new Request(
    `${expectedOrigin}/.well-known/oauth-protected-resource/bridge/${expectedPeer}/mcp`))).json();
  assert.equal(metadata.resource, expectedResource);
  assert.equal(metadata.resource_name, `${expectedName} — ${expectedPeer}`);
  assert.deepEqual(metadata.scopes_supported, Object.values(expectedScopes[expectedPeer]));
}

const principal = { role: peer, scopes: Object.values(CONFIG.scopes[peer]), principalKey: 'a'.repeat(64) };
const handler = createMcpHandler({ enabled: true, verify: async () => principal, bridge: {}, events: {},
  scheduleJobs: async () => {}, resourceMetadataUrl: '' });
const initialized = await (await handler(new Request(resourceFor(peer), { method: 'POST',
  headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1,
    method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {},
      clientInfo: { name: 'fixture', version: '1' } } }) }))).json();
assert.equal(initialized.result.serverInfo.name, expectedServerName);
assert.equal(initialized.result.serverInfo.version, '1.0.0');
console.log('display branding scenario passed');
