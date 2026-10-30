import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { resourceFor, ORIGIN } from '../src/resource.mjs';
import { SCOPES } from '../src/policy.mjs';
import { VERSION } from '../src/release.mjs';
import { ISSUER } from './fixtures/provider.mjs';

test('portable template is neutral, versioned and has no live origin, issuer or client metadata', () => {
  const read = name => JSON.parse(readFileSync(new URL('../plugin/' + name, import.meta.url)));
  const manifest = read('plugin.json'), codex = read('.codex-plugin/plugin.json');
  assert.equal(manifest.name, 'agent-inbox-bridge'); assert.equal(manifest.version, VERSION);
  assert.equal(manifest.extensions['com.openai'].interface.displayName, 'Agent Inbox Bridge');
  assert.equal(manifest.author.name, 'aravhawk'); assert.equal(codex.author.name, 'aravhawk');
  assert.equal(codex.interface.developerName, 'aravhawk'); assert.equal(codex.version, VERSION);
  const server = read('mcp.template.json').mcpServers['agent-inbox-bridge'];
  assert.equal(server.url, '{{RESOURCE}}');
  const auth = server.extensions['com.openai'].auth;
  assert.deepEqual(auth.client, { mode: 'provided', clientId: '{{CLIENT_ID}}', tokenEndpointAuthMethod: 'none' });
  assert.equal(auth.authorizationServerBase, '{{OAUTH_ISSUER}}'); assert.equal(auth.resource, '{{RESOURCE}}');
  assert.deepEqual(auth.baseScopes, ['{{ACK_SCOPE}}', '{{SEND_SCOPE}}', 'offline_access']);
  assert.equal(auth.oidcEnabled, false);
});
test('packaging fixture stays temporary and preserves any prepared release artifact', () => {
  const cwd = new URL('..', import.meta.url);
  const release = new URL('../.reports/plugin-' + VERSION + '.zip', import.meta.url);
  const fingerprint = () => existsSync(release) ? createHash('sha256').update(readFileSync(release)).digest('hex') : null;
  const before = fingerprint();
  const temporary = mkdtempSync(join(tmpdir(), 'agent-inbox-package-test-'));
  const output = join(temporary, 'fixture.zip');
  const run = args => spawnSync('python3', ['scripts/package_plugin.py', '--output', output, ...args],
    { cwd, env: { ...process.env, BRIDGE_PUBLIC_ORIGIN: ORIGIN } });
  const client = ['--client-id', 'FIXTURE_PUBLIC_CLIENT'];
  try {
    assert.notEqual(run([]).status, 0);
    assert.notEqual(run(['--issuer', 'https://issuer.example/path', ...client]).status, 0);
    assert.notEqual(run(['--issuer', 'https://old.clerk.accounts.dev', '--require-issuer-under-origin', ...client]).status, 0);
    assert.notEqual(run(['--issuer', ISSUER, '--peer', 'jarvis', '--counterpart', 'jarvis', ...client]).status, 0);
    assert.equal(existsSync(output), false);
    const result = run(['--issuer', ISSUER, '--require-issuer-under-origin', ...client]);
    assert.equal(result.status, 0, result.stderr.toString());
    assert.equal(existsSync(output), true);
    const rendered = JSON.parse(execFileSync('python3', ['-c',
      'import sys,zipfile;print(zipfile.ZipFile(sys.argv[1]).read("agent-inbox-bridge/mcp.json").decode())', output]));
    const server = rendered.mcpServers['agent-inbox-bridge'], auth = server.extensions['com.openai'].auth;
    assert.equal(server.url, resourceFor('jarvis')); assert.equal(auth.resource, resourceFor('jarvis'));
    assert.equal(auth.authorizationServerBase, ISSUER); assert.equal(auth.client.clientId, 'FIXTURE_PUBLIC_CLIENT');
    assert.deepEqual(auth.baseScopes, [SCOPES.jarvis.ack, SCOPES.jarvis.probe, 'offline_access']);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
  assert.equal(existsSync(temporary), false);
  assert.equal(fingerprint(), before, 'tests must never create or overwrite the default release ZIP');
});
