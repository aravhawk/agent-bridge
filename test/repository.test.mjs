import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resourceFor } from '../src/resource.mjs';
import { SCOPES } from '../src/policy.mjs';
import { VERSION } from '../src/release.mjs';
import { ISSUER } from './fixtures/provider.mjs';

test('v1 portable template has clean identity/canonical audiences and no old or guessed live client metadata', () => {
  const read = name => JSON.parse(readFileSync(new URL('../plugin/' + name, import.meta.url)));
  const manifest = read('plugin.json');
  assert.equal(manifest.name, 'jarvis-friday-bridge'); assert.equal(manifest.version, VERSION);
  assert.equal(manifest.extensions['com.openai'].interface.displayName, 'Jarvis Friday Bridge');
  const server = read('mcp.template.json').mcpServers['jarvis-friday-bridge'];
  assert.equal(server.url, resourceFor('jarvis'));
  const auth = server.extensions['com.openai'].auth;
  assert.deepEqual(auth.client, { mode: 'provided', clientId: '{{JARVIS_CLIENT_ID}}', tokenEndpointAuthMethod: 'none' });
  assert.equal(auth.authorizationServerBase, '{{OAUTH_ISSUER}}'); assert.equal(auth.resource, resourceFor('jarvis'));
  assert.deepEqual(new Set(auth.baseScopes), new Set([SCOPES.jarvis.ack, SCOPES.jarvis.probe, 'offline_access']));
  assert.equal(auth.oidcEnabled, false); assert.equal(read('.codex-plugin/plugin.json').version, VERSION);
});
test('packaging requires actual public metadata and rejects old provider targets before creating an archive', () => {
  const cwd = new URL('..', import.meta.url);
  assert.notEqual(spawnSync('python3', ['scripts/package_plugin.py'], { cwd }).status, 0);
  assert.notEqual(spawnSync('python3', ['scripts/package_plugin.py', '--issuer', 'https://old.clerk.accounts.dev', '--jarvis-client-id', 'FIXTURE_PUBLIC_CLIENT'], { cwd }).status, 0);
  const result = spawnSync('python3', ['scripts/package_plugin.py', '--issuer', ISSUER, '--jarvis-client-id', 'FIXTURE_PUBLIC_CLIENT'], { cwd });
  assert.equal(result.status, 0, result.stderr.toString());
});
