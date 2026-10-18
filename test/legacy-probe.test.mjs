import test from 'node:test';
import assert from 'node:assert/strict';
import { handle } from '../legacy/index.mjs';

const base = 'https://probe.example';
const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
const post = (body, extra = {}) => handle(new Request(base + '/mcp', {
  method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(body),
}));
const rpc = (method, params) => ({ jsonrpc: '2.0', id: 1, method, params });

test('public health discloses only fixed synthetic readiness', async () => {
  const r = await handle(new Request(base + '/health?token=synthetic-never-echo'));
  assert.equal(r.status, 200);
  const body = await r.text();
  assert.equal(body.includes('synthetic-never-echo'), false);
  assert.equal(JSON.parse(body).messageDelivery, false);
  assert.equal(r.headers.get('cache-control'), 'no-store');
});
test('MCP initialize, initialized, list and harmless call', async () => {
  const init = await (await post(rpc('initialize', { protocolVersion: '2025-06-18' }))).json();
  assert.equal(init.result.protocolVersion, '2025-06-18');
  assert.deepEqual(Object.keys(init.result.capabilities), ['tools']);
  const initialized = await post({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(initialized.status, 202);
  const list = await (await post(rpc('tools/list'))).json();
  assert.deepEqual(list.result.tools.map(t => t.name), ['probe_health']);
  const call = await (await post(rpc('tools/call', { name: 'probe_health', arguments: {} }))).json();
  assert.equal(JSON.parse(call.result.content[0].text).events, false);
});
test('all delivery, event and subscription operations unavailable, including bearer input', async () => {
  for (const method of ['send_message', 'events/subscribe', 'subscribe', 'resources/subscribe']) {
    const body = await (await post(rpc(method, { payload: 'synthetic' }), { authorization: 'Bearer SYNTHETIC' })).json();
    assert.equal(body.error.code, -32601);
  }
  for (const name of ['send_message', 'subscribe', 'trigger_agent', 'probe_health']) {
    const body = await (await post(rpc('tools/call', { name, arguments: { payload: 'synthetic' } }))).json();
    assert.equal(body.error.code, -32602);
  }
});
test('OAuth discovery and protected endpoint explicitly unavailable; no fake grants', async () => {
  for (const path of ['/protected/mcp', '/.well-known/oauth-protected-resource', '/.well-known/oauth-authorization-server']) {
    const r = await handle(new Request(base + path));
    assert.equal(r.status, 503);
    assert.equal((await r.json()).error, 'oauth_not_configured');
  }
  for (const path of ['/oauth/authorize', '/oauth/register', '/oauth/token', '/subscriptions', '/send']) {
    assert.equal((await handle(new Request(base + path))).status, 404);
  }
});
test('reject browser cross-origin, unsupported transport and malformed requests', async () => {
  assert.equal((await post(rpc('ping'), { origin: 'https://unrelated.example' })).status, 403);
  assert.equal((await handle(new Request(base + '/mcp'))).status, 405);
  assert.equal((await post(rpc('ping'), { accept: 'application/json' })).status, 406);
  assert.equal((await post(rpc('ping'), { 'content-type': 'text/plain' })).status, 415);
  assert.equal((await post(rpc('ping'), { 'mcp-protocol-version': 'bad' })).status, 400);
  assert.equal((await post([rpc('ping')])).status, 400);
  assert.equal((await post(rpc('ping', { padding: 'x'.repeat(8192) }))).status, 413);
  const malformed = new Request(base + '/mcp', { method: 'POST', headers, body: '{' });
  assert.equal((await handle(malformed)).status, 400);
});
test('no outbound requests can occur during exercised protocol paths', async () => {
  const original = globalThis.fetch;
  let attempts = 0;
  globalThis.fetch = () => { attempts++; throw new Error('outbound disabled'); };
  try {
    await post(rpc('initialize'));
    await post(rpc('tools/call', { name: 'probe_health' }));
    await post(rpc('events/subscribe'));
    assert.equal(attempts, 0);
  } finally { globalThis.fetch = original; }
});
