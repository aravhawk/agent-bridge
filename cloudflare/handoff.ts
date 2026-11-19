import { BridgeError } from '../src/policy.ts';
import type { Transfer } from './sqlite-store.ts';
export interface AuthorityStatus {mode:string;revision?:number;epoch?:string;keyId?:string;handoff?:string|null}
export interface MigrationControl {
 identity:string;
 status():AuthorityStatus|Promise<AuthorityStatus>;
 inspect(revision:number):{document:string;revision:number}|Promise<{document:string;revision:number}>;
 validateCapacity(document:string):Promise<void>;
 freeze(revision:number,target:string):Transfer|Promise<Transfer>;
 importFrozen(transfer:Transfer):unknown|Promise<unknown>;
 activate(handoff:string,revision:number):unknown|Promise<unknown>;
}
// Private operator-process coordinator. Never logs, persists or returns document
// bytes to a public route. Lost replies retry only the same immutable operation.
export async function handoff(source:MigrationControl,target:MigrationControl,revision:number) {
 const before=await source.status();
 if(before.mode==='active') {
  const preview=await source.inspect(revision);await target.validateCapacity(preview.document);
 }
 const transfer=await source.freeze(revision,target.identity);
 const prior=await target.status();
 if(prior.mode==='active'&&prior.handoff===transfer.handoff&&prior.keyId===transfer.keyId&&prior.revision!==undefined&&prior.revision>=revision+1)
  return {revision:prior.revision,checksum:transfer.checksum,handoff:transfer.handoff};
 await target.validateCapacity(transfer.document);
 // An ambiguous import is safe to replay, but an unavailable target never
 // permits old-source activation or automatic fallback.
 try{await target.importFrozen(transfer);}catch{await target.importFrozen(transfer);}
 const staged=await target.status();
 if(staged.mode!=='frozen'||staged.revision!==revision||staged.keyId!==transfer.keyId||staged.handoff!==transfer.handoff)
  throw new BridgeError('migration_destination_not_frozen',503);
 try{await target.activate(transfer.handoff,revision);}catch{
  const actual=await target.status();
  if(actual.mode!=='active'||actual.revision!==revision+1||actual.epoch!==staged.epoch||actual.handoff!==transfer.handoff)
   throw new BridgeError('migration_activation_uncertain',503);
 }
 return {revision:revision+1,checksum:transfer.checksum,handoff:transfer.handoff};
}
