import test from 'node:test';
import assert from 'node:assert/strict';
import { handle } from '../legacy/index.mjs';
import { callbackMetadata } from '../legacy/diagnostic.mjs';
const origin = 'https://rn-jarvis-friday-discovery-20261018.vercel.app';
const request = (path, init) => handle(new Request(origin + path, init));

test('both modes advertise exact protected resource and reject every bearer', async () => {
  for (const mode of ['dcr', 'cimd']) {
    const path = '/oauth-diag/' + mode;
    const r = await request(path + '/mcp', { headers: { authorization: 'Bearer SYNTHETIC_NEVER_LOG' } });
    assert.equal(r.status, 401);
    assert.match(r.headers.get('www-authenticate'), /resource_metadata=/);
    const prm = await (await request('/.well-known/oauth-protected-resource' + path + '/mcp')).json();
    assert.deepEqual(prm.authorization_servers, [origin + path]);
    const as = await (await request('/.well-known/oauth-authorization-server' + path)).json();
    assert.equal(as.issuer, origin + path);
    assert.equal(as.client_id_metadata_document_supported, mode === 'cimd');
    assert.deepEqual(as.code_challenge_methods_supported, ['S256']);
  }
});
test('DCR rejects, creates no credentials, and logs only public allowlisted metadata', async () => {
  const lines = [], log = console.log;
  console.log = value => lines.push(value);
  try {
    const r = await request('/oauth-diag/dcr/register?client_secret=SYNTHETIC_NEVER_LOG', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: 'SYNTHETIC_NEVER_LOG' },
      body: JSON.stringify({ redirect_uris: ['https://www.cursor.com/agents/mcp/oauth/callback' + '?' +
        new URLSearchParams({ state: 'SYNTHETIC_NEVER_LOG' }) + '#SYNTHETIC_NEVER_LOG'],
        client_secret: 'SYNTHETIC_NEVER_LOG', client_name: 'SYNTHETIC_NEVER_LOG',
        grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'none' }),
    });
    assert.equal(r.status, 400);
    const body = await r.json();
    assert.equal(body.error, 'invalid_client_metadata');
    assert.equal(body.client_id, undefined);
    assert.equal(JSON.stringify(lines).includes('SYNTHETIC_NEVER_LOG'), false);
    const event = JSON.parse(lines[0].slice('RN_OAUTH_DIAG '.length));
    assert.deepEqual(event.callbacks, [{ origin: 'https://www.cursor.com', path: '/agents/mcp/oauth/callback' }]);
    assert.equal(event.tokenEndpointAuthMethod, 'none');
  } finally { console.log = log; }
});
test('authorize and token always refuse without redirects, echoes, consent, or outgoing calls', async () => {
  const fetch = globalThis.fetch, log = console.log, lines = [];
  globalThis.fetch = () => { throw new Error('outbound forbidden'); };
  console.log = value => lines.push(value);
  try {
    for (const name of ['authorize', 'token']) {
      const r = await request('/oauth-diag/cimd/' + name + '?state=SYNTHETIC_NEVER_LOG&code_challenge=SYNTHETIC_NEVER_LOG',
        { method: 'POST', body: 'client_secret=SYNTHETIC_NEVER_LOG' });
      assert.equal(r.status, 400);
      assert.equal(r.headers.get('location'), null);
      assert.equal((await r.text()).includes('SYNTHETIC_NEVER_LOG'), false);
    }
    assert.equal(JSON.stringify(lines).includes('SYNTHETIC_NEVER_LOG'), false);
  } finally { globalThis.fetch = fetch; console.log = log; }
});
test('callback sanitization and malformed registration never leak raw input', async () => {
  assert.deepEqual(callbackMetadata('https://u:p@example.com/callback'), { classification: 'unrecognized' });
  assert.deepEqual(callbackMetadata('invalid'), { classification: 'invalid' });
  for (const body of ['{', 'null', 'x'.repeat(9000)]) {
    const r = await request('/oauth-diag/dcr/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body });
    assert.equal(r.status, 400);
  }
});
test('authorization records callback and PKCE method without state/challenge or credentials', async () => {
  const log = console.log, lines = [];
  console.log = value => lines.push(value);
  try {
    const params = new URLSearchParams({ redirect_uri: 'https://www.cursor.com/agents/mcp/oauth/callback',
      response_type: 'code', client_id: 'https://cursor.com/oauth/mcp-client.json',
      state: 'SYNTHETIC_NEVER_LOG', code_challenge: 'SYNTHETIC_NEVER_LOG', code_challenge_method: 'S256' });
    const r = await request('/oauth-diag/cimd/authorize?' + params);
    assert.equal(r.status, 400);
    const event = JSON.parse(lines[0].slice('RN_OAUTH_DIAG '.length));
    assert.equal(event.pkceMethod, 'S256');
    assert.equal(event.clientIdClassification, 'https-metadata-url');
    assert.equal(event.statePresent, true);
    assert.equal(event.challengePresent, true);
    assert.equal(event.sensitiveParameterPresent, false);
    assert.equal(JSON.stringify(lines).includes('SYNTHETIC_NEVER_LOG'), false);
  } finally { console.log = log; }
});
test('public-client diagnostic needs no registration and cannot issue a grant or token', async () => {
  const as = await (await request('/.well-known/oauth-authorization-server/oauth-diag/public')).json();
  assert.equal(as.registration_endpoint, undefined);
  assert.equal(as.client_id_metadata_document_supported, false);
  assert.deepEqual(as.token_endpoint_auth_methods_supported, ['none']);
  const r = await request('/oauth-diag/public/authorize?client_id=RN-REJECT-ONLY&response_type=code');
  assert.equal(r.status, 400);
  assert.equal(r.headers.get('location'), null);
  assert.equal((await r.json()).error, 'access_denied');
});
