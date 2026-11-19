import { createHash, randomUUID } from 'node:crypto';
import { BridgeError } from '../src/policy.ts';
import type { BridgeState, Store, Transition } from '../src/types.ts';

export const MAX_STATE_BYTES = 4 * 1024 * 1024;
export interface SqlStorage {
  exec(sql: string, ...values: (string | number | null)[]): { toArray(): Record<string, unknown>[] };
}
export interface TransactionStorage { sql: SqlStorage; transactionSync<T>(fn: () => T): T }
type Row = { document: string; revision: number; mode: string; epoch: string; key_id: string; handoff: string | null; export_target: string | null };
export interface Transfer {
  format: 'bridge-transfer/1'; document: string; revision: number; epoch: string; keyId: string; target: string; handoff: string; checksum: string;
}
const fail = (code: string): never => { throw new BridgeError(code, 503); };
export function serialize(state: BridgeState): string {
  if (!state || state.version !== 1 || ['messages', 'subscriptions', 'jobs', 'receipts'].some(k => {
    const v = state[k as keyof BridgeState]; return !v || typeof v !== 'object' || Array.isArray(v);
  })) fail('storage_version_mismatch');
  const text = JSON.stringify(state);
  if (Buffer.byteLength(text) > MAX_STATE_BYTES) fail('bridge_store_capacity_reached');
  return text;
}
export function keyIdentity(key: Uint8Array): string { return createHash('sha256').update(key).digest('hex'); }
function checksum(value: Omit<Transfer, 'checksum'>): string { return createHash('sha256').update(JSON.stringify([value.format, value.document, value.revision, value.epoch, value.keyId, value.target, value.handoff])).digest('hex'); }
export function makeTransfer(document: string, revision: number, epoch: string, keyId: string, target: string, handoff: string = randomUUID()): Transfer {
  const value: Omit<Transfer, 'checksum'> = { format: 'bridge-transfer/1', document, revision, epoch, keyId, target, handoff };
  const transfer = { ...value, checksum: checksum(value) };
  return checkTransfer(transfer, keyId, target);
}
export function checkTransfer(input: unknown, keyId: string, target: string): Transfer {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return fail('migration_invalid');
  const v = input as Partial<Transfer>;
  if (Object.keys(v).sort().join(',') !== 'checksum,document,epoch,format,handoff,keyId,revision,target' || v.format !== 'bridge-transfer/1' ||
    typeof v.document !== 'string' || Buffer.byteLength(v.document) > MAX_STATE_BYTES || !Number.isSafeInteger(v.revision) || v.revision! < 0 || !/^[a-z0-9:_-]{3,128}$/.test(target) ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v.epoch || '') ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v.handoff || '') || !/^[a-f0-9]{64}$/.test(keyId) || (v.keyId !== keyId || v.target !== target)) return fail('migration_invalid');
  const { checksum: supplied, ...rest } = v as Transfer;
  if (supplied !== checksum(rest)) return fail('migration_checksum_mismatch');
  let state: BridgeState; try { state = JSON.parse(v.document); } catch { return fail('migration_invalid'); }
  serialize(state); return v as Transfer;
}
/** Single SQLite row; all user transitions and revision changes run inside the DO's synchronous transaction. */
export class SQLiteStore implements Store {
  readonly storage: TransactionStorage;
  readonly identity: string;
  constructor(storage: TransactionStorage, identity: string) {
    this.storage = storage; this.identity = identity;
    if (!/^[a-z0-9:_-]{3,128}$/.test(identity)) fail('migration_identity_invalid');
  }
  private initialize() {
    this.storage.sql.exec(`CREATE TABLE IF NOT EXISTS bridge_state (id INTEGER PRIMARY KEY CHECK(id=1), document TEXT NOT NULL,
      revision INTEGER NOT NULL, mode TEXT NOT NULL, epoch TEXT NOT NULL, key_id TEXT NOT NULL, handoff TEXT, export_target TEXT)`);
  }
  private row(): Row | undefined { this.initialize(); return this.storage.sql.exec('SELECT document,revision,mode,epoch,key_id,handoff,export_target FROM bridge_state WHERE id=1').toArray()[0] as Row | undefined; }
  status() { const r = this.row(); return r ? { revision: r.revision, mode: r.mode, epoch: r.epoch, keyId: r.key_id, handoff: r.handoff } : { mode: 'dormant' }; }
  inspect(revision:number) { return this.storage.transactionSync(()=>{
    const row=this.row();if(!row||row.mode!=='active'||row.revision!==revision)return fail('migration_revision_conflict');
    return {document:row.document,revision};
  }); }
  async validateCapacity(document:string) { let state:BridgeState;try{state=JSON.parse(document);}catch{fail('migration_invalid');}serialize(state!); }
  async transaction<T>(operation: Transition<T>): Promise<T> {
    return this.storage.transactionSync(() => {
      const row = this.row(); if (!row || row.mode !== 'active') return fail('storage_writer_frozen');
      const state = JSON.parse(row.document) as BridgeState;
      const output = operation(state);
      if ((output as { then?: unknown } | null)?.then) return fail('async_storage_operation_forbidden');
      if (row.revision >= Number.MAX_SAFE_INTEGER) return fail('storage_revision_exhausted');
      this.storage.sql.exec('UPDATE bridge_state SET document=?,revision=revision+1 WHERE id=1', serialize(state));
      return structuredClone(output);
    });
  }
  /** Local/test genesis only. Deployed objects start dormant; only a frozen transfer may import. */
  seedForTest(state: BridgeState, revision: number, keyId: string) {
    this.storage.transactionSync(() => {
      if (this.row() || !Number.isSafeInteger(revision) || revision < 0) fail('migration_destination_not_empty');
      this.storage.sql.exec('INSERT INTO bridge_state VALUES(1,?,?,\'active\',?,?,NULL,NULL)', serialize(state), revision, randomUUID(), keyId);
    });
  }
  freeze(expectedRevision: number, target: string): Transfer {
    if (target === this.identity || !/^[a-z0-9:_-]{3,128}$/.test(target)) fail('migration_identity_invalid');
    return this.storage.transactionSync(() => {
      const row = this.row();
      if (row?.mode === 'exported' && row.revision === expectedRevision && row.export_target === target && row.handoff)
        return makeTransfer(row.document, row.revision, row.epoch, row.key_id, target, row.handoff);
      if (!row || row.mode !== 'active' || row.revision !== expectedRevision) return fail('migration_revision_conflict');
      const state = JSON.parse(row.document) as BridgeState;
      if (Object.values(state.jobs).some(j => j.state === 'leased' && (j.leaseUntil || 0) > Date.now()) ||
          Object.values(state.receipts).some(r => r.state === 'claimed' && (r.leaseUntil || 0) > Date.now())) fail('migration_active_leases');
      const transfer = makeTransfer(row.document, row.revision, row.epoch, row.key_id, target);
      this.storage.sql.exec("UPDATE bridge_state SET mode='exported',handoff=?,export_target=? WHERE id=1", transfer.handoff, target);
      return transfer;
    });
  }
  importFrozen(input: unknown, keyId: string) {
    const v = checkTransfer(input, keyId, this.identity);
    return this.storage.transactionSync(() => {
      const row = this.row();
      if (row?.mode === 'frozen' && row.handoff === v.handoff && row.document === v.document && row.revision === v.revision && row.key_id === keyId) return this.status();
      // Reverse rollback is allowed only into a frozen prior writer, at a strictly newer revision.
      if (row && (row.mode !== 'exported' || v.revision <= row.revision || v.epoch === row.epoch)) fail('migration_destination_not_frozen');
      this.storage.sql.exec("INSERT INTO bridge_state VALUES(1,?,?,'frozen',?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET document=excluded.document,revision=excluded.revision,mode=excluded.mode,epoch=excluded.epoch,key_id=excluded.key_id,handoff=excluded.handoff,export_target=NULL",
        v.document, v.revision, randomUUID(), keyId, v.handoff);
      return this.status();
    });
  }
  activate(handoff: string, expectedRevision: number) {
    return this.storage.transactionSync(() => {
      const row = this.row();
      if (!row || row.mode !== 'frozen' || row.handoff !== handoff || row.revision !== expectedRevision || row.revision >= Number.MAX_SAFE_INTEGER) fail('migration_activation_conflict');
      this.storage.sql.exec("UPDATE bridge_state SET mode='active',revision=revision+1,export_target=NULL WHERE id=1");
      return this.status();
    });
  }
}
