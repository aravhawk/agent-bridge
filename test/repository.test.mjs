import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resourceFor } from '../src/resource.mjs';
import { SCOPES } from '../src/policy.mjs';

test('registered plugin uses only the Jarvis resource and public directional OAuth contract', () => {
  const read = path => JSON.parse(readFileSync(new URL('../plugin/' + path, import.meta.url)));
  const manifest = read('plugin.json');
  assert.equal(manifest.extensions['com.openai'].interface.displayName, 'Jarvis Friday Bridge');
  assert.ok(manifest.extensions['com.openai'].interface.shortDescription.length <= 30);
  const server = read('mcp.json').mcpServers['jarvis-friday-bridge'];
  assert.equal(server.type, 'streamable-http');
  assert.equal(server.url, resourceFor('jarvis'));
  const auth = server.extensions['com.openai'].auth;
  assert.deepEqual(auth.client, { mode: 'provided', clientId: 'f58dfaNi1qX2vtdx', tokenEndpointAuthMethod: 'none' });
  assert.equal(auth.resource, resourceFor('jarvis'));
  assert.deepEqual(new Set(auth.baseScopes), new Set([SCOPES.jarvis.ack, SCOPES.jarvis.probe, 'offline_access']));
  assert.deepEqual(auth.defaultScopes, []);
  assert.equal(auth.oidcEnabled, false);
  assert.deepEqual(read('.mcp.json').mcpServers['jarvis-friday-bridge'].extensions, server.extensions);
  assert.equal(read('.codex-plugin/plugin.json').name, manifest.name);
});
