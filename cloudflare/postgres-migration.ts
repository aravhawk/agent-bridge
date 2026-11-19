import { randomUUID } from 'node:crypto';
import { BridgeError } from '../src/policy.ts';
import { STATE_TABLE } from '../src/release.ts';
import { serialize, checkTransfer, makeTransfer } from './sqlite-store.ts';
import type { StorePool, StoreClient } from '../src/store.ts';
import type { BridgeState, Store, Transition } from '../src/types.ts';
import type { Transfer } from './sqlite-store.ts';
/** Prepared fencing adapter. NOT wired into production. Apply authority-schema.sql explicitly first. */
export class FencedPostgresStore implements Store {
  constructor(readonlyPool: StorePool, identity: string, keyId: string) { this.pool=readonlyPool;this.identity=identity;this.keyId=keyId; if(!/^[a-z0-9:_-]{3,128}$/.test(identity)||!/^[a-f0-9]{64}$/.test(keyId)) throw new BridgeError('migration_identity_invalid',503); }
  readonly pool: StorePool; readonly identity: string; readonly keyId: string;
  private async locked<T>(operation: (db: StoreClient, row: {document:BridgeState;revision:string}, authority:{mode:string;epoch:string;handoff:string|null;export_target:string|null;import_checksum:string|null})=>Promise<T>):Promise<T> {
    const db=await this.pool.connect();
    try {
      await db.query('BEGIN');await db.query("SET LOCAL lock_timeout = '5s'");
      // Match legacy PostgresStore: document lock first, authority second.
      const d=await db.query<{document:BridgeState;revision:string}>(`SELECT document,revision FROM ${STATE_TABLE} WHERE id=1 FOR UPDATE`);const row=d.rows[0];
      const a=await db.query<{mode:string;epoch:string;handoff:string|null;export_target:string|null;import_checksum:string|null;key_id:string;identity:string}>('SELECT * FROM bridge_authority WHERE id=1 FOR UPDATE');
      const authority=a.rows[0];if(!authority || authority.identity!==this.identity || authority.key_id!==this.keyId) throw new BridgeError('migration_identity_invalid',503);
      if(!row || !Number.isSafeInteger(Number(row.revision))) throw new BridgeError('storage_version_mismatch',503);
      const result=await operation(db,row,authority);await db.query('COMMIT');return result;
    } catch(e){await db.query('ROLLBACK').catch(()=>{});throw e instanceof BridgeError?e:new BridgeError('storage_unavailable',503);}finally{db.release();}
  }
  status() { return this.locked(async(_db,row,a)=>({mode:a.mode,revision:Number(row.revision),epoch:a.epoch,keyId:this.keyId,handoff:a.handoff})); }
  inspect(revision:number) { return this.locked(async(_db,row,a)=>{
    if(a.mode!=='active'||Number(row.revision)!==revision)throw new BridgeError('migration_revision_conflict',503);
    return {document:serialize(row.document),revision};
  }); }
  validateCapacity(document:string) { return this.locked(async(db)=>{
    if(Buffer.byteLength(document)>4194304)throw new BridgeError('bridge_store_capacity_reached',503);
    const r=await db.query<{bytes:number}>('SELECT octet_length($1::jsonb::text) AS bytes',[document]);
    if(!r.rows[0]||r.rows[0].bytes>4194304)throw new BridgeError('bridge_store_capacity_reached',503);
  }); }
  transaction<T>(operation:Transition<T>):Promise<T> {
    return this.locked(async(db,row,a)=>{
      if(a.mode!=='active')throw new BridgeError('storage_writer_frozen',503);
      const result=operation(row.document);if((result as {then?:unknown}|null)?.then)throw new BridgeError('async_storage_operation_forbidden',503);
      if(Number(row.revision)>=Number.MAX_SAFE_INTEGER)throw new BridgeError('storage_revision_exhausted',503);
      await db.query(`UPDATE ${STATE_TABLE} SET document=$1,revision=revision+1 WHERE id=1`,[serialize(row.document)]);return result;
    });
  }
  freeze(expectedRevision:number,target:string):Promise<Transfer> {
    return this.locked(async(db,row,a)=>{
      if(a.mode==='exported'&&Number(row.revision)===expectedRevision&&a.export_target===target&&a.handoff) return makeTransfer(serialize(row.document),expectedRevision,a.epoch,this.keyId,target,a.handoff);
      if(a.mode!=='active'||Number(row.revision)!==expectedRevision||target===this.identity)throw new BridgeError('migration_revision_conflict',503);
      if(Object.values(row.document.jobs).some(j=>j.state==='leased'&&(j.leaseUntil||0)>Date.now())||Object.values(row.document.receipts).some(r=>r.state==='claimed'&&(r.leaseUntil||0)>Date.now()))throw new BridgeError('migration_active_leases',503);
      const transfer=makeTransfer(serialize(row.document),expectedRevision,a.epoch,this.keyId,target);
      await db.query("UPDATE bridge_authority SET mode='exported',handoff=$1,export_target=$2,import_checksum=NULL WHERE id=1",[transfer.handoff,target]);return transfer;
    });
  }
  importFrozen(input:unknown):Promise<void> {
    const v=checkTransfer(input,this.keyId,this.identity);
    return this.locked(async(db,row,a)=>{
      if(a.mode==='frozen'&&a.handoff===v.handoff&&a.import_checksum===v.checksum&&Number(row.revision)===v.revision) return;
      if(a.mode!=='exported'||v.revision<=Number(row.revision)||v.epoch===a.epoch)throw new BridgeError('migration_destination_not_frozen',503);
      const capacity=await db.query<{bytes:number}>('SELECT octet_length($1::jsonb::text) AS bytes',[v.document]);
      if(!capacity.rows[0]||capacity.rows[0].bytes>4194304)throw new BridgeError('bridge_store_capacity_reached',503);
      // The document lock excludes all legacy writers. This temporary mode is
      // invisible outside this transaction; the trigger permits only this update.
      await db.query("UPDATE bridge_authority SET mode='active' WHERE id=1");
      await db.query(`UPDATE ${STATE_TABLE} SET document=$1,revision=$2 WHERE id=1`,[v.document,v.revision]);
      await db.query("UPDATE bridge_authority SET mode='frozen',epoch=$1,handoff=$2,export_target=NULL,import_checksum=$3 WHERE id=1",[randomUUID(),v.handoff,v.checksum]);
    });
  }
  activate(handoff:string,revision:number):Promise<void> {
    return this.locked(async(db,row,a)=>{
      if(a.mode!=='frozen'||a.handoff!==handoff||Number(row.revision)!==revision||revision>=Number.MAX_SAFE_INTEGER)throw new BridgeError('migration_activation_conflict',503);
      await db.query("UPDATE bridge_authority SET mode='active',export_target=NULL,import_checksum=NULL WHERE id=1");await db.query(`UPDATE ${STATE_TABLE} SET revision=revision+1 WHERE id=1`);
    });
  }
}
