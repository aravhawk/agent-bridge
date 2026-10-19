import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
test('packaging fixture stays temporary and preserves any prepared release artifact', () => {
  const cwd = new URL('..', import.meta.url);
  const release = new URL('../.reports/plugin-' + VERSION + '.zip', import.meta.url);
  const fingerprint = () => existsSync(release) ? createHash('sha256').update(readFileSync(release)).digest('hex') : null;
  const before = fingerprint();
  const temporary = mkdtempSync(join(tmpdir(), 'jarvis-friday-package-test-'));
  const output = join(temporary, 'fixture.zip');
  const run = args => spawnSync('python3', ['scripts/package_plugin.py', '--output', output, ...args], { cwd });
  try {
    assert.notEqual(run([]).status, 0);
    assert.notEqual(run(['--issuer', 'https://old.clerk.accounts.dev', '--jarvis-client-id', 'FIXTURE_PUBLIC_CLIENT']).status, 0);
    assert.equal(existsSync(output), false);
    const result = run(['--issuer', ISSUER, '--jarvis-client-id', 'FIXTURE_PUBLIC_CLIENT']);
    assert.equal(result.status, 0, result.stderr.toString());
    assert.equal(existsSync(output), true);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
  assert.equal(existsSync(temporary), false);
  assert.equal(fingerprint(), before, 'tests must never create or overwrite the default release ZIP');
});
