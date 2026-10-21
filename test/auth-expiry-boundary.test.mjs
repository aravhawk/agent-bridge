import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import { createAccessVerifier, SCOPES, VERIFIED_AUTHORIZATION } from '../src/policy.mjs';
import { createMcpHandler } from '../src/mcp.mjs';
import { resourceFor, metadataFor } from '../src/resource.mjs';
import { ISSUER } from './fixtures/provider.mjs';
import { verifiedLease } from '../src/access.mjs';

const { publicKey, privateKey } = await generateKeyPair('RS256');
const expiry = 2000000000, expiresAt = expiry * 1000;
const sign = (role = 'jarvis', extra = {}) => new SignJWT({ scope: SCOPES[role].ack, ...extra })
  .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject('fixture-expiry')
  .setAudience(resourceFor(role)).setIssuedAt(expiry - 60).setExpirationTime(expiry).sign(privateKey);
const options = (role, when, changes = {}) => ({ issuer: ISSUER, audience: resourceFor(role),
  subject: 'fixture-expiry', role, keyResolver: publicKey,
  ...(when === undefined ? {} : { currentDate: new Date(when) }), ...changes });
const authRequest = (role, token) => new Request(resourceFor(role), { headers: { authorization: 'Bearer ' + token } });
const unauthorized = error => error.code === 'unauthorized' && error.status === 401;

function handler(verify, calls, now) {
  return createMcpHandler({ enabled: true, verify, bridge: {}, scheduleJobs: async () => assert.fail('no queue'),
    events: { subscribe: async principal => {
      verifiedLease(principal, principal[VERIFIED_AUTHORIZATION].policyId, now);
      calls.push('subscribe'); return {};
    },
      list: () => { calls.push('list'); return { events: [] }; } },
    resourceMetadataUrl: metadataFor('jarvis'), health: () => { calls.push('health'); return {}; } });
}
const rpc = (token, method) => new Request(resourceFor('jarvis'), { method: 'POST', headers: {
  'content-type': 'application/json', authorization: 'Bearer ' + token }, body: JSON.stringify({ jsonrpc: '2.0',
  id: 1, method, params: method === 'tools/call' ? { name: 'bridge_health', arguments: {} } : {} }) });

test('every expired-token boundary returns401/challenge before events or tools execute', async () => {
  const token = await sign();
  for (const delta of [0, 1, 1000, 4999, 5000, 5001]) {
    const calls = [], verify = createAccessVerifier(options('jarvis', expiresAt + delta));
    const run = handler(verify, calls, expiresAt + delta);
    for (const method of ['events/subscribe', 'events/list', 'tools/call']) {
      const response = await run(rpc(token, method)), result = await response.json();
      assert.equal(response.status, 401, `${method} at exp+${delta}ms`);
      assert.equal(result.error.code, -32001); assert.equal(result.error.message, 'unauthorized');
      assert.equal(response.headers.get('www-authenticate'), `Bearer resource_metadata="${metadataFor('jarvis')}"`);
      assert.equal(JSON.stringify(result).includes(token), false);
    }
    assert.deepEqual(calls, []);
  }
});

test('valid token1ms before expiry preserves principal identity and unmodified hard-expiry metadata for both roles', async () => {
  for (const role of ['jarvis', 'friday']) {
    const token = await sign(role);
    const a = await createAccessVerifier(options(role, expiresAt - 1000))(authRequest(role, token));
    const b = await createAccessVerifier(options(role, expiresAt - 1))(authRequest(role, token));
    assert.deepEqual(a, b); assert.equal(b[VERIFIED_AUTHORIZATION].expiresAt, expiresAt);
    assert.equal(JSON.stringify(b).includes(token), false); assert.equal(JSON.stringify(b).includes('expiresAt'), false);
    await assert.rejects(createAccessVerifier(options(role, expiresAt))(authRequest(role, token)), unauthorized);
  }
});

test('strict expiry runs after signature resolution and rejects a token crossing expiry while awaiting a key', async context => {
  const token = await sign();
  context.mock.timers.enable({ apis: ['Date'], now: expiresAt - 1 });
  const verify = createAccessVerifier(options('jarvis', undefined, { keyResolver: async () => {
    context.mock.timers.setTime(expiresAt + 1); return publicKey;
  } }));
  await assert.rejects(verify(authRequest('jarvis', token)), unauthorized);
});

test('strict expiry retains existing signature, issuer, audience, pinned-subject and scope rejection', async () => {
  const token = await sign(), request = authRequest('jarvis', token);
  for (const changes of [{ issuer: 'https://other.example.test' }, { audience: resourceFor('friday') }])
    await assert.rejects(createAccessVerifier(options('jarvis', expiresAt - 1, changes))(request), unauthorized);
  await assert.rejects(createAccessVerifier(options('jarvis', expiresAt - 1, { subject: 'other-fixture' }))(request),
    error => error.code === 'forbidden_subject' && error.status === 403);
  const empty = await sign('jarvis', { scope: '' });
  await assert.rejects(createAccessVerifier(options('jarvis', expiresAt - 1))(authRequest('jarvis', empty)),
    error => error.code === 'insufficient_scope' && error.status === 403);
  const { publicKey: wrongKey } = await generateKeyPair('RS256');
  await assert.rejects(createAccessVerifier(options('jarvis', expiresAt - 1, { keyResolver: wrongKey }))(request), unauthorized);
});

test('existing future-not-before tolerance is preserved while an expired token never reaches timing observations', async () => {
  const observations = [], nbf = expiry - 1;
  const token = await sign('jarvis', { nbf });
  const a = await createAccessVerifier(options('jarvis', (nbf - 4) * 1000))(authRequest('jarvis', token));
  assert.equal(a.role, 'jarvis');
  await assert.rejects(createAccessVerifier(options('jarvis', (nbf - 6) * 1000))(authRequest('jarvis', token)), unauthorized);
  const verify = createAccessVerifier(options('jarvis', expiresAt, { observeTiming: x => observations.push(x) }));
  await assert.rejects(verify(authRequest('jarvis', token)), unauthorized);
  assert.deepEqual(observations, []);
});
