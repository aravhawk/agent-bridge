import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPair, SignJWT } from 'jose';
import { createRuntime } from '../src/runtime.mjs';
import { createResourceRouter, providerConfiguration, resourceFor, ORIGIN } from '../src/resource.mjs';
import { VERSION, RECEIVER_ID, STATE_TABLE, QUEUE_TOPIC } from '../src/release.mjs';
import { ISSUER } from './fixtures/provider.mjs';
import { createMcpHandler } from '../src/mcp.mjs';

const request = (url, body, token) => new Request(url, { method: 'POST', headers: {
  'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}),
}, body: JSON.stringify(body) });

test('v1 issuer has no development fallback and is an explicit service-namespace HTTPS origin', () => {
  assert.equal(providerConfiguration(ISSUER).issuer, ISSUER);
  for (const value of [undefined, '', 'https://old.clerk.accounts.dev', 'https://clerk.unrelated.example',
    ISSUER.replace('https:', 'http:'), ISSUER + '/', ISSUER + '/path', ISSUER + '?key=x', ISSUER + '#fragment',
    ISSUER.replace('https://', 'https://user:pass@'), ISSUER + ':443', 'https://127.0.0.1', ' ' + ISSUER]) {
    assert.equal(providerConfiguration(value), null, String(value));
  }
});
test('canonical routing rejects old aliases, legacy routes and unset provider metadata', async () => {
  let calls = 0;
  const handler = createResourceRouter({ getHandler: () => { calls++; return () => Response.json({}); }, getProvider: () => null });
  for (const path of ['/mcp', '/oauth-diag/public/mcp', '/oauth-diag/dcr/token']) assert.equal((await handler(request(ORIGIN + path, {}))).status, 404);
  assert.equal((await handler(request('https://old-project.vercel.app/bridge/jarvis/mcp', {}))).status, 404);
  assert.equal((await handler(new Request(ORIGIN + '/.well-known/oauth-protected-resource/bridge/jarvis/mcp'))).status, 503);
  assert.equal((await handler(request(resourceFor('jarvis'), {}))).status, 401); assert.equal(calls, 0);
  const health = await (await handler(new Request(ORIGIN + '/'))).json(); assert.equal(health.version, VERSION);
});

test('new verified identity can bootstrap through health only before OAuth-contract attestation, without any data/event access', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const rt = createRuntime({ env: { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_ALLOWED_SUBJECT: 'fixture-user',
    BRIDGE_OAUTH_CONTRACT_VERIFIED: 'false', BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_DELIVERY_ENABLED: 'true' },
    keyResolver: publicKey, queueClient: {}, Pool: class { constructor() { assert.fail('bootstrap must not access DB'); } },
    transportFactory() { assert.fail('bootstrap must not prepare transport'); } });
  const token = await new SignJWT({ scope: 'bridge:ack:jarvis bridge:send:friday' }).setProtectedHeader({ alg: 'RS256' })
    .setIssuer(ISSUER).setSubject('fixture-user').setAudience(resourceFor('jarvis')).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const rpc = async (method, params) => {
    const response = await rt.handler('jarvis')(request(resourceFor('jarvis'), { jsonrpc: '2.0', id: 1, method, params }, token));
    return { status: response.status, body: await response.json() };
  };
  assert.deepEqual((await rpc('tools/list')).body.result.tools.map(t => t.name), ['bridge_health']);
  const health = (await rpc('tools/call', { name: 'bridge_health', arguments: {} })).body.result.structuredContent;
  assert.equal(health.authenticated, true); assert.equal(health.serverVersion, '1.0.0');
  assert.equal(health.readiness.deliveryEnabled, false); assert.equal(health.readiness.subscriptionSetupEnabled, false);
  assert.equal((await rpc('events/list', {})).status, 503);
  assert.equal((await rpc('events/subscribe', {})).status, 503);
  assert.equal((await rpc('tools/call', { name: 'bridge_read', arguments: {} })).status, 403);
  assert.equal((await rpc('tools/call', { name: 'bridge_message_send', arguments: {} })).status, 403);
  assert.deepEqual((await rpc('server/discover')).body.result.capabilities, { tools: {} });
});

test('active release, queue, store and env contract contain no old live identity or test receiver binding', () => {
  assert.equal(VERSION, '1.0.0'); assert.equal(RECEIVER_ID, 'jarvis-friday-bridge-inbox');
  assert.equal(STATE_TABLE, 'bridge_runtime_v1'); assert.equal(QUEUE_TOPIC, 'jarvis-friday-bridge-v1');
  const config = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url)));
  assert.equal(config.functions['api/queue.mjs'].experimentalTriggers[0].topic, QUEUE_TOPIC);
  for (const name of ['runtime.mjs', 'resource.mjs', 'release.mjs', 'mcp.mjs']) {
    const source = readFileSync(new URL('../src/' + name, import.meta.url), 'utf8');
    for (const old of ['RN-JARVIS', 'jarvis-friday-test-receiver', '0.2.0']) assert.equal(source.includes(old), false, name + ': ' + old);
  }
  const env = readFileSync(new URL('../.env.example', import.meta.url), 'utf8');
  assert.equal(env.includes('FRIDAY_TEST_'), false); assert.equal(env.includes('BRIDGE_DAILY_'), false);
});

test('v1 JWT bootstrap rejects an old issuer or audience even with the same signing key', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const rt = createRuntime({ env: { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_ALLOWED_SUBJECT: 'fixture-user' }, keyResolver: publicKey });
  for (const [issuer, audience] of [
    ['https://old.clerk.accounts.dev', resourceFor('jarvis')],
    [ISSUER, 'https://old-project.vercel.app/bridge/jarvis/mcp'],
    [ISSUER, resourceFor('friday')],
  ]) {
    const token = await new SignJWT({ scope: 'bridge:ack:jarvis bridge:send:friday' })
      .setProtectedHeader({ alg: 'RS256' }).setIssuer(issuer).setSubject('fixture-user')
      .setAudience(audience).setIssuedAt().setExpirationTime('5m').sign(privateKey);
    const response = await rt.handler('jarvis')(request(resourceFor('jarvis'),
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'bridge_health', arguments: {} } }, token));
    assert.equal(response.status, 401);
  }
});

test('health-only discovery still honors authenticated native unsubscribe', async () => {
  let withdrawn;
  const handler = createMcpHandler({ enabled: true, healthOnly: true,
    bridge: {}, scheduleJobs: async () => { assert.fail('withdrawal cannot schedule delivery'); },
    verify: async () => ({ role: 'jarvis', scopes: ['bridge:ack:jarvis'], principalKey: 'a'.repeat(64) }),
    events: { unsubscribe: async (principal, params) => { withdrawn = { principal, params }; return {}; } },
  });
  const params = { subscriptionId: 'FIXTURE_SUBSCRIPTION' };
  const response = await handler(request(resourceFor('jarvis'), { jsonrpc: '2.0', id: 1, method: 'events/unsubscribe', params }, 'FIXTURE'));
  assert.equal(response.status, 200); assert.deepEqual(withdrawn.params, params);
  assert.equal(withdrawn.principal.role, 'jarvis');
});
