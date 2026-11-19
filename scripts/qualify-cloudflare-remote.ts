import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { checkTransfer, keyIdentity, makeTransfer, serialize } from '../cloudflare/sqlite-store.ts';
import { PUBLIC_ORIGIN } from '../src/release.ts';
import { emptyState } from '../src/store.ts';

async function qualify() {
  const [endpoint, secretFile] = process.argv.slice(2);
  if (!endpoint || !secretFile ||
      !/^https:\/\/agent-bridge-cf-qualification\.[a-z0-9-]+\.workers\.dev$/.test(endpoint)) {
    throw new Error('synthetic_target_required');
  }
  const identity = 'cf:agent-bridge-cf-qualification:bridge-runtime-v1';
  const returnTarget = 'synthetic:local-return';
  const { GATEWAY_KEY, MIGRATION_KEY, RUNTIME_ENV } = JSON.parse(await readFile(secretFile, 'utf8')) as Record<string, string>;
  assert.match(GATEWAY_KEY ?? '', /^[a-f0-9]{64}$/);
  assert.match(MIGRATION_KEY ?? '', /^[a-f0-9]{64}$/);
  assert.notEqual(GATEWAY_KEY, MIGRATION_KEY);
  const runtime = JSON.parse(RUNTIME_ENV!) as Record<string, string>;
  const fingerprint = keyIdentity(Buffer.from(runtime.BRIDGE_SUBSCRIPTION_STORAGE_KEY!, 'base64'));
  const post = (path: string, key: string | undefined, body: object | undefined, headers = {}) =>
    fetch(endpoint + path, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(12000),
      headers: { ...(key ? { authorization: 'Bearer ' + key } : {}),
        ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
      ...(body ? { body: JSON.stringify(body) } : {}) });
  const migrate = async (command: object) => {
    const response = await post('/migration', MIGRATION_KEY, command);
    assert.equal(response.status, 200);
    return await response.json() as Record<string, unknown>;
  };
  assert.equal((await post('/migration', undefined, { operation: 'status' })).status, 401);
  assert.equal((await post('/migration', GATEWAY_KEY, { operation: 'status' })).status, 401);
  assert.equal((await post('/invoke', MIGRATION_KEY, undefined)).status, 401);
  assert.equal((await migrate({ operation: 'status' })).mode, 'dormant');
  const health = await post('/invoke', GATEWAY_KEY, undefined, {
    'x-bridge-url': PUBLIC_ORIGIN + '/health', 'x-bridge-method': 'GET',
  });
  assert.equal(health.status, 200);
  assert.equal((await health.json() as { status?: string }).status, 'ok');
  const badOrigin = await post('/invoke', GATEWAY_KEY, undefined, {
    'x-bridge-url': 'https://unrelated.invalid/health', 'x-bridge-method': 'GET',
  });
  assert.equal(badOrigin.status, 400);
  const document = serialize({ ...emptyState(), qualificationFixture: randomBytes(42000).toString('hex') });
  const transfer = makeTransfer(document, 1, randomUUID(), fingerprint, identity);
  const invalidImport = await post('/migration', MIGRATION_KEY, { operation: 'import',
    transfer: { ...transfer, checksum: '0'.repeat(64) } });
  assert.equal(invalidImport.status, 503);
  assert.equal((await migrate({ operation: 'status' })).mode, 'dormant');
  const imported = await migrate({ operation: 'import', transfer });
  assert.equal(imported.mode, 'frozen');
  assert.equal(imported.revision, 1);
  assert.equal(imported.keyId, fingerprint);
  assert.deepEqual(await migrate({ operation: 'import', transfer }), imported);
  const active = await migrate({ operation: 'activate', handoff: transfer.handoff, revision: 1 });
  assert.equal(active.mode, 'active');
  assert.equal(active.revision, 2);
  const inspected = await migrate({ operation: 'inspect', revision: 2 });
  assert.equal(inspected.document, document);
  const stale = await post('/migration', MIGRATION_KEY, { operation: 'freeze', revision: 1, target: returnTarget });
  assert.equal(stale.status, 503);
  const freeze = { operation: 'freeze', revision: 2, target: returnTarget };
  const exported = checkTransfer(await migrate(freeze), fingerprint, returnTarget);
  assert.equal(exported.document, document);
  assert.deepEqual(await migrate(freeze), exported);
  assert.equal((await migrate({ operation: 'status' })).mode, 'exported');
  console.log(JSON.stringify({ status: 'passed', scope: 'synthetic-workers-dev', bytes: Buffer.byteLength(document),
    revision: 2, finalState: 'exported' }));
}

try { await qualify(); }
catch { console.error('Synthetic Cloudflare qualification failed; no credentials or response data printed.'); process.exitCode = 1; }
