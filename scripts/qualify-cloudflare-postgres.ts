// Explicit local qualification only; never imports a production connection URL.
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { Miniflare, convertV4MiniflareOptions, Response as MFResponse } from 'miniflare';
import { build } from 'esbuild';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { FencedPostgresStore } from '../cloudflare/postgres-migration.ts';
import { handoff } from '../cloudflare/handoff.ts';
import type { MigrationControl, AuthorityStatus } from '../cloudflare/handoff.ts';
import { keyIdentity } from '../cloudflare/sqlite-store.ts';
import type { Transfer } from '../cloudflare/sqlite-store.ts';
import { PostgresStore } from '../src/store.ts';
import { SCOPES } from '../src/policy.ts';
import { resourceFor } from '../src/resource.ts';
import { createProtector } from '../src/webhook.ts';
import type { StorePool, StoreClient } from '../src/store.ts';

const root=resolve(process.argv[2]||'');
assert.match(root,/\/bridge-pg17\.12-[A-Za-z0-9_-]+$/);
assert.equal(JSON.parse(readFileSync(join(root,'provenance.json'),'utf8')).version,'17.12');
assert.equal(statSync(join(root,'socket')).mode&0o777,0o700);
const db='bridge_cf_'+randomUUID().replaceAll('-','');
const connect=(database=db)=>new pg.Pool({host:join(root,'socket'),database,max:2,connectionTimeoutMillis:3000,query_timeout:10000});
const admin=connect('postgres');await admin.query('CREATE DATABASE '+db);await admin.end();
let a=connect(),b=connect();a.on('error',()=>{});b.on('error',()=>{});
const aes=randomBytes(32),keyId=keyIdentity(aes),checks:string[]=[];
let source=new FencedPostgresStore(a,'local:postgres',keyId);
let mf:Miniflare|undefined;
const gateway='1'.repeat(64),migration='2'.repeat(64),effect='3'.repeat(64);
function poolFault(pool:pg.Pool):StorePool {
 let remaining=true;
 return {async connect(){const client=await pool.connect();return new Proxy(client,{get(target,property){
  if(property==='query')return async(...args:Parameters<StoreClient['query']>)=>{
   const result=await Reflect.apply(target.query,target,args);
   if(args[0]==='COMMIT'&&remaining){remaining=false;throw Error('synthetic_reply_loss');}return result;
  };
  const value=Reflect.get(target,property);return typeof value==='function'?value.bind(target):value;
 }}) as StoreClient;}};
}
try {
 await a.query(readFileSync('schema.sql','utf8'));await a.query(readFileSync('cloudflare/authority-schema.sql','utf8'));
 await a.query("INSERT INTO bridge_authority(id,identity,mode,epoch,key_id) VALUES(1,$1,'active',$2,$3)",['local:postgres',randomUUID(),keyId]);
 for(const name of ['fsync','synchronous_commit','full_page_writes'])assert.equal((await a.query('SHOW '+name)).rows[0][name],'on');
 assert.equal((await a.query('SHOW listen_addresses')).rows[0].listen_addresses,'');checks.push('durable_socket_only_server');
 const sealed=createProtector(aes).seal({url:'https://fixture.example.test/events',secret:'synthetic'},'fixture-subscription');
 await source.transaction(s=>{s.schedulerTicks={counter:0};s.subscriptions.fixture={id:'fixture',owner:'synthetic',recipient:'jarvis',status:'active',active:false,sealed};s.opaque={tasks:['preserve'],pendingJobIdentity:randomUUID()};s.jobs['job_'+'a'.repeat(64)]={id:'job_'+'a'.repeat(64),messageId:randomUUID(),recipient:'friday',subscriptionId:null,eventId:randomUUID(),body:'{}',state:'pending',attempts:1,dueAt:Date.now(),leaseId:null,leaseUntil:null,firstTransportOutcome:{at:Date.now(),workerAttempt:1,status:503,error:null,terminal:false}};});
 const peer=new FencedPostgresStore(b,'local:postgres',keyId);
 await Promise.all(Array.from({length:40},(_,i)=>(i%2?source:peer).transaction(s=>{const ticks=s.schedulerTicks as {counter:number};ticks.counter++;})));
 assert.equal(await source.transaction(s=>(s.schedulerTicks as {counter:number}).counter),40);checks.push('two_pool_no_lost_updates');
 const saved=(await source.status()).revision;
 await assert.rejects(source.transaction(s=>{s.messages={};throw Error('synthetic_rollback');}));assert.equal((await source.status()).revision,saved);checks.push('transaction_rollback');
 const holder=await a.connect();await holder.query('BEGIN');await holder.query('SELECT * FROM bridge_runtime_v1 WHERE id=1 FOR UPDATE');
 let finished=false;const waiting=peer.transaction(s=>{s.schedulerTicks={counter:41};}).then(()=>{finished=true;});
 await new Promise(r=>setTimeout(r,50));assert.equal(finished,false);await holder.query('COMMIT');holder.release();await waiting;checks.push('actual_row_lock_serialization');
 const env={BRIDGE_OAUTH_ISSUER:'https://identity.jarvis-friday-bridge.aravhawk.com',BRIDGE_ALLOWED_SUBJECT:'fixture',BRIDGE_OAUTH_CONTRACT_VERIFIED:'true',BRIDGE_SUBSCRIPTION_STORAGE_KEY:aes.toString('base64'),BRIDGE_DELIVERY_ENABLED:'false'};
 const pair=await generateKeyPair('RS256'),jwk=await exportJWK(pair.publicKey);jwk.kid='fixture';
 const built=await build({entryPoints:['cloudflare/worker.ts'],write:false,bundle:true,format:'esm',platform:'node',external:['node:*','cloudflare:workers'],alias:{pg:'./cloudflare/no-postgres.ts'},banner:{js:"import {createRequire} from 'node:module';const require=createRequire('/worker.js');"}});
 mf=new Miniflare({...convertV4MiniflareOptions({modules:true,script:built.outputFiles[0]!.text,compatibilityDate:'2026-11-16',compatibilityFlags:['nodejs_compat','enable_nodejs_http_modules'],cf:false,host:'127.0.0.1',inspectorHost:'127.0.0.1',durableObjects:{BRIDGE:{className:'BridgeObject',useSQLite:true}},bindings:{GATEWAY_KEY:gateway,MIGRATION_KEY:migration,EFFECT_KEY:effect,EFFECT_ENDPOINT:'https://effects.example.test/api/bridge-effects',STORE_IDENTITY:'local:cloudflare',RUNTIME_ENV:JSON.stringify(env)},outboundService:async req=>{assert.equal(req.url,env.BRIDGE_OAUTH_ISSUER+'/.well-known/jwks.json');return new MFResponse(JSON.stringify({keys:[jwk]}),{headers:{'content-type':'application/json'}});}}),enableDevRegistry:false,telemetry:{enabled:false}});
 async function control<T>(command:unknown):Promise<T>{const r=await mf!.dispatchFetch('https://gateway.example.test/migration',{method:'POST',headers:{authorization:'Bearer '+migration},body:JSON.stringify(command)});assert.equal(r.status,200);return await r.json() as T;}
 const target:MigrationControl={identity:'local:cloudflare',status:()=>control<AuthorityStatus>({operation:'status'}),inspect:revision=>control({operation:'inspect',revision}),validateCapacity:async document=>{assert.ok(Buffer.byteLength(document)<=4194304);},freeze:(revision,target)=>control<Transfer>({operation:'freeze',revision,target}),importFrozen:transfer=>control({operation:'import',transfer}),activate:(handoff,revision)=>control({operation:'activate',handoff,revision})};
 const receipt=randomUUID();await source.transaction(s=>{s.receipts[receipt]={state:'claimed',leaseUntil:Date.now()+60000};});
 await assert.rejects(source.freeze((await source.status()).revision,target.identity),/migration_active_leases/);
 await source.transaction(s=>{delete s.receipts[receipt];});checks.push('postgres_active_receipt_blocks_export');
 await source.transaction(s=>{const job=s.jobs['job_'+'a'.repeat(64)]!;job.state='leased';job.leaseId=randomUUID();job.leaseUntil=Date.now()+60000;});
 await assert.rejects(source.freeze((await source.status()).revision,target.identity),/migration_active_leases/);
 await source.transaction(s=>{const job=s.jobs['job_'+'a'.repeat(64)]!;job.state='pending';job.leaseId=null;job.leaseUntil=null;});checks.push('postgres_job_lease_blocks_export');
 const old=await b.connect();await old.query('BEGIN');await old.query('SELECT * FROM bridge_runtime_v1 WHERE id=1 FOR UPDATE');
 const prior=(await a.query('SELECT revision FROM bridge_runtime_v1 WHERE id=1')).rows[0].revision;
 const racing=source.freeze(Number(prior),target.identity);const rejectedRace=assert.rejects(racing,/migration_revision_conflict/);
 await new Promise(r=>setTimeout(r,30));await old.query('UPDATE bridge_runtime_v1 SET revision=revision+1 WHERE id=1');await old.query('COMMIT');old.release();await rejectedRace;
 assert.equal((await source.status()).mode,'active');checks.push('legacy_inflight_commit_invalidates_stale_freeze');
 const revision=(await source.status()).revision;
 let releaseEffect!:()=>void;let externalAccepted=0;
 const effectWait=new Promise<void>(r=>{releaseEffect=r;});
 const lateEffect=(async()=>{await effectWait;externalAccepted++;await source.transaction(s=>{s.opaque={late:true};});})();
 const lateRejected=assert.rejects(lateEffect,/storage_writer_frozen/);
 const uncertain=new FencedPostgresStore(poolFault(a),'local:postgres',keyId);await assert.rejects(uncertain.freeze(revision,target.identity));
 releaseEffect();await lateRejected;assert.equal(externalAccepted,1);checks.push('synthetic_inflight_effect_not_cancelled_but_late_pg_write_fenced');
 assert.equal((await source.status()).mode,'exported');const transfer=await source.freeze(revision,target.identity);
 await assert.rejects(new PostgresStore(b).transaction(s=>{s.schedulerTicks={counter:999};}));checks.push('ambiguous_commit_and_legacy_writer_fenced');
 let dropImport=true,dropActivation=true;
 const lossy={...target,importFrozen:async(t:Transfer)=>{await target.importFrozen(t);if(dropImport){dropImport=false;throw Error('lost_import_reply');}},activate:async(h:string,r:number)=>{await target.activate(h,r);if(dropActivation){dropActivation=false;throw Error('lost_activation_reply');}}};
 await handoff(source,lossy,revision);await handoff(source,target,revision);checks.push('real_pg_to_workerd_lost_reply_reconciliation');
 const token=await new SignJWT({scope:Object.values(SCOPES.jarvis!).join(' ')}).setProtectedHeader({alg:'RS256',kid:'fixture'}).setIssuer(env.BRIDGE_OAUTH_ISSUER).setSubject('fixture').setAudience(resourceFor('jarvis')).setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
 const r=await mf.dispatchFetch('https://gateway.example.test/invoke',{method:'POST',headers:{authorization:'Bearer '+gateway,'x-bridge-url':resourceFor('jarvis'),'x-bridge-method':'POST','x-bridge-original-authorization':'Bearer '+token,'x-bridge-original-content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'bridge_subscription_status',arguments:{}}})});assert.equal(r.status,200);const rpc=await r.json() as {result?:{isError?:boolean}};assert.equal(rpc.result?.isError,false);checks.push('oauth_runtime_on_real_do');
 const preview=await target.inspect((await target.status()).revision!);const reverseRevision=preview.revision;
 let reverseLost=true;
 const reverseUncertain=new FencedPostgresStore(poolFault(a),'local:postgres',keyId);
 await handoff(target,{identity:source.identity,status:()=>source.status(),inspect:r=>source.inspect(r),validateCapacity:d=>source.validateCapacity(d),freeze:(r,t)=>source.freeze(r,t),importFrozen:t=>reverseUncertain.importFrozen(t),activate:async(h,r)=>{await source.activate(h,r);if(reverseLost){reverseLost=false;throw Error('lost_reverse_activation');}}},reverseRevision);
 assert.equal((await target.status()).mode,'exported');assert.equal((await source.status()).mode,'active');
 const result=await source.transaction(s=>s);assert.deepEqual(result,JSON.parse(preview.document));assert.deepEqual(createProtector(aes).open(result.subscriptions.fixture!.sealed!,'fixture-subscription'),{url:'https://fixture.example.test/events',secret:'synthetic'});checks.push('real_workerd_to_pg_exact_state_key_identity');
 const tooBig={version:1,messages:{},subscriptions:{},jobs:{},receipts:{},padding:'',many:Array.from({length:10000},()=>0)};tooBig.padding='x'.repeat(4194304-Buffer.byteLength(JSON.stringify(tooBig)));assert.equal(Buffer.byteLength(JSON.stringify(tooBig)),4194304);await assert.rejects(source.validateCapacity(JSON.stringify(tooBig)));checks.push('actual_jsonb_capacity_rejected');
 let froze=false;await assert.rejects(handoff({...target,status:()=>({mode:'active',revision:0}),inspect:()=>({document:JSON.stringify(tooBig),revision:0}),freeze:()=>{froze=true;throw Error('must_not_freeze');}},
 {identity:source.identity,status:()=>source.status(),inspect:r=>source.inspect(r),validateCapacity:d=>source.validateCapacity(d),freeze:(r,t)=>source.freeze(r,t),importFrozen:t=>source.importFrozen(t),activate:(h,r)=>source.activate(h,r)},0));assert.equal(froze,false);checks.push('destination_preflight_precedes_source_freeze');
 const status=await source.status();await a.end();await b.end();
 execFileSync(join(root,'prefix/bin/pg_ctl'),['-D',join(root,'data'),'-m','fast','-w','restart'],{stdio:'ignore'});
 a=connect();b=connect();a.on('error',()=>{});b.on('error',()=>{});source=new FencedPostgresStore(a,'local:postgres',keyId);assert.deepEqual(await source.status(),status);checks.push('postgres_durable_restart');
 console.log(JSON.stringify({postgres:'17.12',checks,passed:checks.length,syntheticDatabase:db,neonTLSQualified:false},null,2));
} finally {if(mf)await mf.dispose();await a.end();await b.end();}
