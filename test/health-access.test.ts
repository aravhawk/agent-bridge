import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { createRuntime } from '../src/runtime.ts';
import { resourceFor } from '../src/resource.ts';
import { ISSUER } from './fixtures/provider.ts';
import { decodeStorageKey, createProtector } from '../src/webhook.ts';
import type { RuntimePoolConstructor } from '../src/runtime.ts';
import type { ListedTool, RpcResponse, ToolCallResult, ToolResponse } from './types.ts';

const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const subject = 'fixture-jarvis-subject';
const owner = digest(JSON.stringify([ISSUER, resourceFor('jarvis'), subject, 'jarvis']));
const headers = { 'content-type': 'application/json' };
const rpc = (token: string, name = 'bridge_health', args: object = {}) => new Request(resourceFor('jarvis'), {
  method: 'POST', headers: { ...headers, authorization: 'Bearer ' + token },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
});
async function fixture(extra: Record<string, string> = {}) {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const env = { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_ALLOWED_SUBJECT: subject, ...extra };
  const rt = createRuntime({ env, keyResolver: publicKey,
    Pool: class { constructor() { assert.fail('health must not create a pool'); } } as unknown as RuntimePoolConstructor, // Never constructed.
    queueClient: { send() { assert.fail('health must not enqueue'); } },
    transportFactory() { assert.fail('health must not create an outbound transport'); } });
  const sign = (claims: Record<string, unknown> = {}, overrides: { issuer?: string; subject?: string; audience?: string; expiration?: string } = {}) => new SignJWT({ scope: 'bridge:ack:jarvis', ...claims })
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
  const result = (await response.json() as ToolResponse).result;
  assert.notEqual(result.isError, true);
  assert.deepEqual(JSON.parse(result.content[0]!.text), { status: 'ok', authenticated: true, serverVersion: '1.0.0',
    readiness: { storageConfigured: false, callbackProtectorConfigured: false, currentAccessCheckConfigured: true,
      fridaySenderConfigured: false, receiverPolicyVerified: false, fridayContractVerified: false,
      fridayWebhookDiagnosticArmed: false, canaryArmed: false, subscriptionSetupEnabled: false, deliveryEnabled: false },
    caller: { role: 'jarvis', sendScope: false, ackScope: true, tools: ['bridge_health', 'bridge_read',
      'bridge_receipt_claim', 'bridge_receipt_complete', 'bridge_status', 'bridge_subscription_status'] } });
  const output = JSON.stringify(result);
  for (const value of [token, subject, owner, 'private-health@example.test', 'private-claim']) assert.equal(output.includes(value), false);
  const discovery = await handler(new Request(resourceFor('jarvis'), { method: 'POST',
    headers: { ...headers, authorization: 'Bearer ' + token },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) }));
  const tool = (await discovery.json() as RpcResponse<{ tools: ListedTool[] }>).result.tools.find(t => t.name === 'bridge_health')!;
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
  const badArguments = await handler(rpc(await sign(), 'bridge_health', { messageId: 'ignored' }));
  assert.equal(badArguments.status, 200);
  const rejected = (await badArguments.json() as RpcResponse<ToolCallResult>).result;
  assert.equal(rejected.isError, true); assert.deepEqual(rejected.structuredContent, { error: 'invalid_params' });
  assert.equal((await handler(rpc('FIXTURE_INVALID_NOT_A_TOKEN'))).status, 401);
});
test('authenticated health exposes only a valid operator assigned bridge identity', async () => {
  const instanceId = '67c078e5-5be1-4949-964d-42b64fba8392';
  const { handler, sign } = await fixture({ BRIDGE_INSTANCE_ID: instanceId });
  const response = await handler(rpc(await sign({ instanceId: 'caller-identity-must-not-win' })));
  assert.equal((await response.json() as RpcResponse<ToolCallResult<Record<string, unknown>>>)
    .result.structuredContent.instanceId, instanceId);
  const denied = await handler(rpc(await sign({}, { subject: 'different-subject' })));
  assert.equal(denied.status, 403);
  assert.doesNotMatch(await denied.text(), new RegExp(instanceId));

  const invalidValue = 'not-an-instance-id-or-safe-to-echo';
  const invalid = await fixture({ BRIDGE_INSTANCE_ID: invalidValue });
  const result = (await (await invalid.handler(rpc(await invalid.sign()))).json() as
    RpcResponse<ToolCallResult<Record<string, unknown>>>).result;
  assert.equal(Object.hasOwn(result.structuredContent, 'instanceId'), false);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(invalidValue));
});
test('receiver calls reject a changed bridge route before opening storage', async () => {
  const expectedInstanceId = '67c078e5-5be1-4949-964d-42b64fba8392';
  const otherInstanceId = '525afcc2-1cb9-4ccc-927e-d3aa7d9f2c90';
  const messageId = '84e850bb-3688-4ba5-b3b0-2df14260088e';
  const intended = await fixture({ BRIDGE_INSTANCE_ID: expectedInstanceId });
  const routedElsewhere = await fixture({ BRIDGE_INSTANCE_ID: otherInstanceId });
  const unconfigured = await fixture();
  const healthy = (await (await intended.handler(rpc(await intended.sign()))).json() as ToolResponse).result;
  assert.equal(healthy.structuredContent.instanceId, expectedInstanceId);
  for (const target of [routedElsewhere, unconfigured]) {
    const token = await target.sign();
    for (const tool of ['bridge_read', 'bridge_receipt_claim', 'bridge_receipt_complete']) {
      const response = await target.handler(rpc(token, tool, { messageId, expectedInstanceId }));
      const result = (await response.json() as ToolResponse).result;
      assert.equal(result.isError, true);
      assert.deepEqual(result.structuredContent, { error: 'bridge_instance_mismatch' });
    }
  }
  const matching = (await (await intended.handler(rpc(await intended.sign(), 'bridge_read',
    { messageId, expectedInstanceId }))).json() as ToolResponse).result;
  assert.deepEqual(matching.structuredContent, { error: 'storage_configuration_required' });
});
test('gate flags alone cannot report subscription or delivery ready', async () => {
  const { handler, sign } = await fixture({ BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_DELIVERY_ENABLED: 'true',
    BRIDGE_SUBSCRIPTION_STORAGE_KEY: Buffer.alloc(32, 7).toString('base64') });
  const out = JSON.parse((await (await handler(rpc(await sign()))).json() as ToolResponse).result.content[0]!.text);
  assert.equal(out.readiness.callbackProtectorConfigured, true);
  assert.equal(out.readiness.currentAccessCheckConfigured, true);
  assert.equal(out.readiness.subscriptionSetupEnabled, false); assert.equal(out.readiness.deliveryEnabled, false);
  const token = await sign();
  const denied = await handler(new Request(resourceFor('jarvis'), { method: 'POST',
    headers: { ...headers, authorization: 'Bearer ' + token },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'events/subscribe', params: {} }) }));
  assert.equal(denied.status, 503); assert.equal((await denied.json() as RpcResponse).error.message, 'events_not_enabled');
});
test('outer secret-entry whitespace normalizes consistently without accepting malformed or wrong-length keys', async () => {
  const canonical = Buffer.alloc(32, 17).toString('base64');
  for (const value of [canonical, canonical + '\n', ' \r\n' + canonical + '\r\n ']) {
    const key = decodeStorageKey(value); assert.equal(key!.length, 32);
    const protector = createProtector(key), sealed = protector.seal({ fixture: true }, 'fixture-context');
    assert.deepEqual(protector.open(sealed, 'fixture-context'), { fixture: true });
    const { handler, sign } = await fixture({ BRIDGE_SUBSCRIPTION_STORAGE_KEY: value });
    const out = JSON.parse((await (await handler(rpc(await sign()))).json() as ToolResponse).result.content[0]!.text);
    assert.equal(out.readiness.callbackProtectorConfigured, true);
    assert.equal(out.readiness.subscriptionSetupEnabled, false); assert.equal(out.readiness.deliveryEnabled, false);
    assert.equal(JSON.stringify(out).includes(canonical), false);
  }
  for (const value of [undefined, '', 7, 'not-base64', Buffer.alloc(31).toString('base64'),
    Buffer.alloc(33).toString('base64'), canonical.slice(0, 10) + '\n' + canonical.slice(10),
    canonical.slice(0, -2) + 'B=']) assert.equal(decodeStorageKey(value), undefined);
});
