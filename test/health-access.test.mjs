import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { createRuntime } from '../src/runtime.mjs';
import { ISSUER, resourceFor } from '../src/resource.mjs';
import { decodeStorageKey, createProtector } from '../src/webhook.mjs';

const digest = value => createHash('sha256').update(value).digest('hex');
const subject = 'fixture-jarvis-subject';
const owner = digest(JSON.stringify([ISSUER, resourceFor('jarvis'), subject, 'jarvis']));
const headers = { 'content-type': 'application/json' };
const rpc = (token, name = 'bridge_health', args = {}) => new Request(resourceFor('jarvis'), {
  method: 'POST', headers: { ...headers, authorization: 'Bearer ' + token },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
});
async function fixture(extra = {}) {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const env = { BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: subject, ...extra };
  const rt = createRuntime({ env, keyResolver: publicKey,
    Pool: class { constructor() { assert.fail('health must not create a pool'); } },
    queueClient: { send() { assert.fail('health must not enqueue'); } },
    transportFactory() { assert.fail('health must not create an outbound transport'); } });
  const sign = (claims = {}, overrides = {}) => new SignJWT({ scope: 'bridge:ack:jarvis', ...claims })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(overrides.issuer || ISSUER)
    .setSubject(overrides.subject || subject).setAudience(overrides.audience || resourceFor('jarvis'))
    .setIssuedAt().setExpirationTime(overrides.expiration || '5m').sign(privateKey);
  return { handler: rt.handler('jarvis'), sign, env };
}
test('authenticated health succeeds with no storage, network transport, queue or secret output', async () => {
  const { handler, sign } = await fixture();
  const token = await sign({ email: 'private-health@example.test', extra: 'private-claim' });
  const response = await handler(rpc(token));
  assert.equal(response.status, 200);
  const result = (await response.json()).result;
  assert.notEqual(result.isError, true);
  assert.deepEqual(JSON.parse(result.content[0].text), { status: 'ok', authenticated: true, serverVersion: '0.1.0',
    readiness: { storageConfigured: false, callbackProtectorConfigured: false, currentAccessCheckConfigured: true,
      subscriptionSetupEnabled: false, deliveryEnabled: false } });
  const output = JSON.stringify(result);
  for (const value of [token, subject, owner, 'private-health@example.test', 'private-claim']) assert.equal(output.includes(value), false);
  const discovery = await handler(new Request(resourceFor('jarvis'), { method: 'POST',
    headers: { ...headers, authorization: 'Bearer ' + token },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) }));
  const tool = (await discovery.json()).result.tools.find(t => t.name === 'bridge_health');
  assert.deepEqual(tool.inputSchema, { type: 'object', properties: {}, required: [], additionalProperties: false });
  assert.deepEqual(tool.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
});
test('health rejects wrong issuer, audience, subject, expired token, unrelated scopes and arguments', async () => {
  const { handler, sign } = await fixture();
  for (const overrides of [{ issuer: 'https://other.example.test' }, { audience: resourceFor('friday') },
    { subject: 'other-subject' }, { expiration: '-1m' }]) {
    assert.ok((await handler(rpc(await sign({}, overrides)))).status >= 400);
  }
  assert.equal((await handler(rpc(await sign({ scope: 'profile' })))).status, 403);
  assert.equal((await handler(rpc(await sign(), 'bridge_health', { messageId: 'ignored' }))).status, 400);
  assert.equal((await handler(rpc('FIXTURE_INVALID_NOT_A_TOKEN'))).status, 401);
});
test('gate flags alone cannot report subscription or delivery ready', async () => {
  const { handler, sign } = await fixture({ BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_DELIVERY_ENABLED: 'true',
    BRIDGE_SUBSCRIPTION_STORAGE_KEY: Buffer.alloc(32, 7).toString('base64') });
  const out = JSON.parse((await (await handler(rpc(await sign()))).json()).result.content[0].text);
  assert.equal(out.readiness.callbackProtectorConfigured, true);
  assert.equal(out.readiness.currentAccessCheckConfigured, true);
  assert.equal(out.readiness.subscriptionSetupEnabled, false); assert.equal(out.readiness.deliveryEnabled, false);
  const token = await sign();
  const denied = await handler(new Request(resourceFor('jarvis'), { method: 'POST',
    headers: { ...headers, authorization: 'Bearer ' + token },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'events/subscribe', params: {} }) }));
  assert.equal(denied.status, 503); assert.equal((await denied.json()).error.message, 'events_not_enabled');
});
test('outer secret-entry whitespace normalizes consistently without accepting malformed or wrong-length keys', async () => {
  const canonical = Buffer.alloc(32, 17).toString('base64');
  for (const value of [canonical, canonical + '\n', ' \r\n' + canonical + '\r\n ']) {
    const key = decodeStorageKey(value); assert.equal(key.length, 32);
    const protector = createProtector(key), sealed = protector.seal({ fixture: true }, 'fixture-context');
    assert.deepEqual(protector.open(sealed, 'fixture-context'), { fixture: true });
    const { handler, sign } = await fixture({ BRIDGE_SUBSCRIPTION_STORAGE_KEY: value });
    const out = JSON.parse((await (await handler(rpc(await sign()))).json()).result.content[0].text);
    assert.equal(out.readiness.callbackProtectorConfigured, true);
    assert.equal(out.readiness.subscriptionSetupEnabled, false); assert.equal(out.readiness.deliveryEnabled, false);
    assert.equal(JSON.stringify(out).includes(canonical), false);
  }
  for (const value of [undefined, '', 7, 'not-base64', Buffer.alloc(31).toString('base64'),
    Buffer.alloc(33).toString('base64'), canonical.slice(0, 10) + '\n' + canonical.slice(10),
    canonical.slice(0, -2) + 'B=']) assert.equal(decodeStorageKey(value), undefined);
});
