import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CONFIG, loadConfig, parsePeers, ConfigurationError } from '../src/config.mjs';

// Deployment identity is fixed at import, so generic deployments run in a child
// process with their own environment. Inherited BRIDGE_* values are dropped.
function runGeneric(script, extra = {}) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('BRIDGE_')));
  return spawnSync(process.execPath, [fileURLToPath(new URL(script, import.meta.url))], {
    env: { ...env, BRIDGE_PUBLIC_ORIGIN: 'https://bridge.example.com', BRIDGE_PEERS: 'alice:events,bob:webhook',
      BRIDGE_QUEUE_TOPIC: 'inbox-test-v1', BRIDGE_QUEUE_REGION: 'sfo1', ...extra }, encoding: 'utf8' });
}

test('a generic deployment routes configured peers end to end: derived scopes, any TLS Postgres, Standard Webhooks, env queue', () => {
  const result = runGeneric('./fixtures/generic-deployment.mjs');
  assert.equal(result.status, 0, result.stderr + result.stdout);
  assert.match(result.stdout, /generic deployment scenario passed/);
});

test('this test process runs in compatibility mode', () => {
  assert.equal(CONFIG.compat, true);
  assert.deepEqual(loadConfig({}), CONFIG);
});

test('generic configuration requires an HTTPS origin and exactly one events and one webhook peer', () => {
  const generic = extra => loadConfig({ BRIDGE_PUBLIC_ORIGIN: 'https://bridge.example.com', BRIDGE_PEERS: 'a:events,b:webhook', ...extra });
  assert.throws(() => loadConfig({ BRIDGE_PUBLIC_ORIGIN: 'https://bridge.example.com' }), ConfigurationError);
  for (const origin of ['http://bridge.example.com', 'https://bridge.example.com/', 'https://bridge.example.com/x',
    'https://bridge.example.com:8443', 'not a url', '']) {
    assert.throws(() => generic({ BRIDGE_PUBLIC_ORIGIN: origin }), ConfigurationError, origin);
  }
  for (const peers of ['', 'a:events', 'a:events,b:events', 'a:webhook,b:webhook', 'a:events,a:webhook',
    'a:events,b:webhook,c:webhook', 'A:events,b:webhook', 'a_b:events,c:webhook', 'a:events,b:relay', 'a:events:x,b:webhook',
    '-a:events,b:webhook', 'a-:events,b:webhook']) {
    assert.throws(() => parsePeers(peers), ConfigurationError, peers);
  }
  assert.deepEqual(parsePeers(' ops-bot:webhook , desk:events ').map(p => p.id), ['desk', 'ops-bot']);
  const config = generic({ BRIDGE_PEERS: 'desk:events,ops-bot:webhook' });
  assert.deepEqual(config.scopes, { desk: { probe: 'bridge:send:ops-bot', ack: 'bridge:ack:desk' },
    'ops-bot': { probe: 'bridge:send:desk', ack: 'bridge:ack:ops-bot' } });
  assert.equal(config.webhookEnvPrefix, 'BRIDGE_PEER_OPS_BOT_');
  assert.equal(config.requireIssuerUnderOrigin, false); assert.equal(config.databaseHostSuffix, '');
  assert.equal(config.names.diagnosticTool, 'bridge_webhook_diagnostic');
  for (const [name, value] of [['BRIDGE_REQUIRE_ISSUER_UNDER_ORIGIN', 'yes'], ['BRIDGE_MESSAGE_PROTOCOL', 'other/1'],
    ['BRIDGE_QUEUE_REGION', 'us-east'], ['BRIDGE_QUEUE_TOPIC', 'a b'], ['BRIDGE_DATABASE_HOST_SUFFIX', 'neon.tech'],
    ['BRIDGE_RECEIVER_ID', 'Upper'], ['BRIDGE_SERVICE_NAME', '']]) {
    assert.throws(() => generic({ [name]: value }), ConfigurationError, name);
  }
  assert.equal(generic({ BRIDGE_MESSAGE_PROTOCOL: 'jarvis-friday/1' }).protocol, 'jarvis-friday/1');
  assert.equal(generic({ BRIDGE_DATABASE_HOST_SUFFIX: '.neon.tech' }).databaseHostSuffix, '.neon.tech');
});

test('a misconfigured generic deployment fails at startup instead of serving', () => {
  const result = runGeneric('../api/index.mjs', { BRIDGE_PEERS: 'alice:events' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ConfigurationError: BRIDGE_PEERS must name exactly two distinct peers/);
});
