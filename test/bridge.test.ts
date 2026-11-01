import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import { createAccessVerifier, validateEnvelope, BridgeError } from '../src/policy.ts';
import { createFixedEventSender } from '../src/delivery.ts';
import { PostgresStore } from '../src/store.ts';
import type { StorePool } from '../src/store.ts';
import type { Principal, ProbeEnvelope } from '../src/types.ts';

// Ephemeral, in-process test fixtures. These keys/tokens authorize no provider,
// account, endpoint or grant, are never persisted, and are never printed.
const { publicKey, privateKey } = await generateKeyPair('RS256');
const now = Math.floor(Date.now() / 1000);
const issuer = 'https://isolated-test.clerk.accounts.dev';
const audience = 'synthetic-public-client';
const subject = 'synthetic-subject';
async function token({ claims = {}, iss = issuer, aud = audience, sub = subject, exp = now + 60, nbf }:
  { claims?: Record<string, unknown>; iss?: string; aud?: string; sub?: string; exp?: number; nbf?: number } = {}) {
  let jwt = new SignJWT({ scope: 'bridge:send:jarvis bridge:ack:friday', ...claims })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(iss).setAudience(aud)
    .setSubject(sub).setIssuedAt(now).setExpirationTime(exp);
  if (nbf) jwt = jwt.setNotBefore(nbf);
  return jwt.sign(privateKey);
}
const verifier = createAccessVerifier({ issuer, audience, subject, role: 'friday', keyResolver: publicKey });
const request = (t: string) => new Request('https://bridge.test/mcp', { headers: { authorization: 'Bearer ' + t } });
const errorCode = (code: string, status?: number) => (e: unknown) => e instanceof BridgeError && e.code === code && (!status || e.status === status);
const envelope = {
  id: 'f765a442-ac07-4442-a8cf-95783b0d77df', testId: 'RN-JARVIS-FRIDAY-SYNTHETIC',
  from: 'friday', to: 'jarvis', kind: 'probe', sentAt: new Date().toISOString(), marker: 'RN-SYNTHETIC-NO-ACTIONS',
} as ProbeEnvelope;

test('valid signature, exact provider/audience/subject and custom scope authorize only synthetic envelope', async () => {
  const principal = await verifier(request(await token()));
  const saved = validateEnvelope(envelope, principal);
  assert.equal(saved.envelope.from, 'friday');
  assert.match(saved.hash, /^[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(principal), ['role', 'scopes', 'principalKey']);
  assert.match(principal.principalKey, /^[a-f0-9]{64}$/);
});
test('reject wrong issuer, audience, expired/future tokens and invalid signatures', async () => {
  for (const options of [{ iss: 'https://wrong.test' }, { aud: 'other-client' },
    { exp: now - 60 }, { nbf: now + 60 }]) {
    await assert.rejects(verifier(request(await token(options))), errorCode('unauthorized', 401));
  }
  const t = await token();
  const pieces = t.split('.');
  pieces[1] = Buffer.from(JSON.stringify({ sub: subject, scope: 'bridge:send:jarvis' })).toString('base64url');
  await assert.rejects(verifier(request(pieces.join('.'))), errorCode('unauthorized', 401));
});
test('reject other users, identity tokens without scopes, and missing bearer input', async () => {
  await assert.rejects(verifier(request(await token({ sub: 'other-user' }))),
    errorCode('forbidden_subject', 403));
  await assert.rejects(verifier(request(await token({ claims: { scope: undefined } }))),
    errorCode('insufficient_scope', 403));
  await assert.rejects(verifier(new Request('https://bridge.test/mcp')), errorCode('unauthorized', 401));
});
test('reject sender spoofing, excess fields, wrong scope, stale messages and invalid correlations', () => {
  // Deliberately incomplete principals: validation reads only role and scopes.
  const p = { role: 'friday', scopes: ['bridge:send:jarvis'] } as unknown as Principal;
  for (const input of [{ ...envelope, from: 'jarvis', to: 'friday' },
    { ...envelope, url: 'https://unapproved.test' }, { ...envelope, marker: 'do arbitrary work' },
    { ...envelope, sentAt: '2020-01-01T00:00:00Z' }, { ...envelope, correlationId: envelope.id }]) {
    assert.throws(() => validateEnvelope(input, p), BridgeError);
  }
  assert.throws(() => validateEnvelope(envelope, { role: 'friday', scopes: ['bridge:send:friday'] } as unknown as Principal),
    errorCode('insufficient_scope', 403));
});
test('canonical serialization makes equivalent envelopes match while changed content conflicts', () => {
  const p = { role: 'friday', scopes: ['bridge:send:jarvis'] } as unknown as Principal;
  const a = validateEnvelope(envelope, p);
  const b = validateEnvelope(Object.fromEntries(Object.entries(envelope).reverse()), p);
  assert.equal(a.hash, b.hash);
  assert.notEqual(a.hash, validateEnvelope({ ...envelope, sentAt: new Date(Date.now() - 1000).toISOString() }, p).hash);
});
test('delivery disabled or unapproved URLs fail before any outbound request', () => {
  assert.throws(() => createFixedEventSender({}), errorCode('delivery_not_enabled', 503));
  for (const endpoint of ['http://receiver.test/event', 'https://user:pass@receiver.test/event',
    'https://receiver.test/event?key=synthetic', 'https://unapproved.test/event']) {
    assert.throws(() => createFixedEventSender({ enabled: true, endpoint, approvedOrigin: 'https://receiver.test',
      authHeader: 'Authorization', secret: 'SYNTHETIC_TEST_ONLY' }), errorCode('delivery_configuration_required', 503));
  }
});
test('sender pins destination, forbids redirect forwarding, and returns only transport evidence', async () => {
  let options: (RequestInit & { headers: Record<string, string> }) | undefined;
  const send = createFixedEventSender({ enabled: true, endpoint: 'https://receiver.test/event',
    approvedOrigin: 'https://receiver.test', authHeader: 'Authorization', authPrefix: 'Bearer ',
    secret: 'SYNTHETIC_TEST_ONLY', fetchImpl: async (url, opts) => {
      assert.equal(url, 'https://receiver.test/event'); options = opts as typeof options;
      return new Response('SYNTHETIC_RESPONSE_NOT_READ', { status: 202 });
    } });
  const result = await send(envelope);
  assert.equal(options!.redirect, 'error');
  assert.equal(options!.headers.Authorization, 'Bearer SYNTHETIC_TEST_ONLY');
  assert.deepEqual(result, { messageId: envelope.id, transportAccepted: true, status: 202 });
  assert.equal('wakeVerified' in result, false);
});
test('transport/storage errors do not propagate raw secret-bearing error text', async () => {
  const send = createFixedEventSender({ enabled: true, endpoint: 'https://receiver.test/event',
    approvedOrigin: 'https://receiver.test', authHeader: 'Authorization', secret: 'SYNTHETIC_TEST_ONLY',
    fetchImpl: async () => { throw Error('SYNTHETIC_TEST_ONLY'); } });
  await assert.rejects(send(envelope), errorCode('delivery_transport_failed', 503));
  await assert.rejects(new PostgresStore({ connect: async () => { throw Error('SYNTHETIC_TEST_ONLY'); } } as StorePool).transaction(() => {}),
    errorCode('storage_unavailable', 503));
});
