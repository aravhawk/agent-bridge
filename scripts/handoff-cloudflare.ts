import { randomUUID } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import pg from 'pg';
import { handoff } from '../cloudflare/handoff.ts';
import { FencedPostgresStore } from '../cloudflare/postgres-migration.ts';
import { bounded, MAX_TRANSFER_BYTES } from '../cloudflare/protocol.ts';
import { checkTransfer, keyIdentity, serialize } from '../cloudflare/sqlite-store.ts';
import { BridgeError } from '../src/policy.ts';
import { PUBLIC_ORIGIN, STATE_TABLE } from '../src/release.ts';
import { decodeStorageKey } from '../src/webhook.ts';
import type { AuthorityStatus, MigrationControl } from '../cloudflare/handoff.ts';
import type { Transfer } from '../cloudflare/sqlite-store.ts';
import type { BridgeState } from '../src/types.ts';

const fields = ['databaseUrl', 'postgresIdentity', 'cloudflareOrigin', 'cloudflareIdentity',
  'migrationKey', 'subscriptionKey'] as const;
type Config = Record<typeof fields[number], string>;
function code(error: string): never { throw new BridgeError(error, 503); }

async function load(file: string): Promise<Config> {
  const info = await stat(file);
  if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > 8192) code('private_config_required');
  const data = JSON.parse(await readFile(file, 'utf8')) as Partial<Config>;
  if (!data || Object.keys(data).length !== fields.length || fields.some(key => typeof data[key] !== 'string')) {
    code('handoff_configuration_invalid');
  }
  return data as Config;
}

async function run() {
  const [operation, file, requestedRevision] = process.argv.slice(2);
  if (!file || !['status', 'prepare', 'cutover', 'rollback'].includes(operation ?? '')) {
    code('handoff_command_invalid');
  }
  const config = await load(file);
  const origin = new URL(config.cloudflareOrigin);
  const db = new URL(config.databaseUrl);
  const encryptionKey = decodeStorageKey(config.subscriptionKey);
  const id = /^[a-z0-9:_-]{3,128}$/;
  if (!encryptionKey || origin.protocol !== 'https:' || origin.origin !== config.cloudflareOrigin ||
      !/^postgres(?:ql)?:$/.test(db.protocol) || !db.hostname.includes('.') || !db.password ||
      !id.test(config.postgresIdentity) || !id.test(config.cloudflareIdentity) ||
      config.postgresIdentity === config.cloudflareIdentity || !/^[a-f0-9]{64}$/.test(config.migrationKey)) {
    code('handoff_configuration_invalid');
  }
  const fingerprint = keyIdentity(encryptionKey);
  if ([...db.searchParams.keys()].some(k => !['sslmode', 'channel_binding'].includes(k))) code('database_parameters_invalid');
  db.searchParams.set('sslmode', 'verify-full');
  const pool = new pg.Pool({ connectionString: db.href, connectionTimeoutMillis: 6000, statement_timeout: 12000, max: 1 });
  const control = async <T>(command: object): Promise<T> => {
    const body = JSON.stringify(command);
    if (Buffer.byteLength(body) > MAX_TRANSFER_BYTES) code('migration_command_too_large');
    const response = await fetch(origin.href + 'migration', { method: 'POST', redirect: 'error',
      signal: AbortSignal.timeout(20000), headers: { authorization: 'Bearer ' + config.migrationKey,
        'content-type': 'application/json' }, body });
    const answer = JSON.parse(await bounded(response, MAX_TRANSFER_BYTES)) as Record<string, unknown>;
    if (!response.ok) {
      const remoteCode = answer.error;
      if (typeof remoteCode === 'string' && /^(migration_[a-z_]+|backend_[a-z_]+)$/.test(remoteCode)) code(remoteCode);
      code('migration_remote_unavailable');
    }
    return answer as T;
  };
  const cloud: MigrationControl = {
    identity: config.cloudflareIdentity,
    status: () => control<AuthorityStatus>({ operation: 'status' }),
    inspect: revision => control({ operation: 'inspect', revision }),
    validateCapacity: async document => { serialize(JSON.parse(document) as BridgeState); },
    freeze: async (revision, target) => checkTransfer(await control({ operation: 'freeze', revision, target }),
      fingerprint, target),
    importFrozen: (transfer: Transfer) => control({ operation: 'import', transfer }),
    activate: (handoffId, revision) => control({ operation: 'activate', handoff: handoffId, revision }),
  };
  try {
    const actualIdentity = await control<{ identity?: string }>({ operation: 'identity' });
    if (actualIdentity.identity !== cloud.identity) code('migration_identity_invalid');
    const cloudState = await cloud.status();
    const row = (await pool.query<{ revision: string; fenced: boolean }>(
      `SELECT revision, to_regclass('bridge_authority') IS NOT NULL AS fenced FROM ${STATE_TABLE} WHERE id=1`)).rows[0];
    if (!row || !Number.isSafeInteger(Number(row.revision))) code('storage_version_mismatch');
    const postgres = new FencedPostgresStore(pool, config.postgresIdentity, fingerprint);
    if (operation === 'status') {
      const state = row.fenced ? await postgres.status() : { mode: 'unfenced', revision: Number(row.revision) };
      console.log(JSON.stringify({ postgres: { mode: state.mode, revision: state.revision },
        cloudflare: { mode: cloudState.mode, revision: cloudState.revision },
        cloudflareKeyMatches: cloudState.keyId ? cloudState.keyId === fingerprint : null }));
      return;
    }
    if (!requestedRevision || !/^\d+$/.test(requestedRevision) ||
        !Number.isSafeInteger(Number(requestedRevision))) code('expected_revision_required');
    const revision = Number(requestedRevision);
    const pause = await fetch(PUBLIC_ORIGIN + '/health', { redirect: 'error', signal: AbortSignal.timeout(10000) });
    if (pause.status !== 503 || (await pause.json() as { error?: string }).error !== 'bridge_migration_paused') {
      code('live_bridge_not_paused');
    }
    if (operation === 'prepare') {
      if (row.fenced || cloudState.mode !== 'dormant') code('migration_initial_state_invalid');
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const locked = (await client.query<{revision: string}>(
          `SELECT revision FROM ${STATE_TABLE} WHERE id=1 FOR UPDATE`)).rows[0];
        if (Number(locked?.revision) !== revision) code('migration_revision_conflict');
        await client.query(await readFile(new URL('../cloudflare/authority-schema.sql', import.meta.url), 'utf8'));
        await client.query("INSERT INTO bridge_authority (id, identity, mode, epoch, key_id) VALUES (1,$1,'active',$2,$3)",
          [config.postgresIdentity, randomUUID(), fingerprint]);
        await client.query('COMMIT');
      } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
      finally { client.release(); }
      console.log(JSON.stringify({ status: 'fence_installed', revision }));
      return;
    }
    if (!row.fenced) code('postgres_fence_required');
    const result = operation === 'cutover' ? await handoff(postgres, cloud, revision) : await handoff(cloud, postgres, revision);
    const after = await Promise.all([postgres.status(), cloud.status()]);
    const expected = operation === 'cutover' ? ['exported', 'active'] : ['active', 'exported'];
    if (after[0].mode !== expected[0] || after[1].mode !== expected[1]) code('migration_authority_unconfirmed');
    console.log(JSON.stringify({ status: 'transferred', operation, revision: result.revision,
      postgres: after[0].mode, cloudflare: after[1].mode }));
  } finally { await pool.end(); }
}

try { await run(); }
catch (error) {
  console.error(error instanceof BridgeError ? error.code : 'migration_operator_failed');
  process.exitCode = 1;
}
