import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFakeBlob } from './fixtures/fake-blob.ts';
import { createBlobProvider } from '../src/blob.ts';
import type { BlobSdk } from '../src/blob.ts';
import type { BeginResult, DownloadResult } from '../src/attachments.ts';
import type { TaskToolOutput } from './types.ts';
import { Webhook } from 'standardwebhooks';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { NativeEvents, EVENT_NAME } from '../src/events.ts';
import { createProtector } from '../src/webhook.ts';
import { createAccessVerifier, authorizationPolicyId } from '../src/policy.ts';
import { resourceFor } from '../src/resource.ts';
import { createCloudflareFrontend } from '../cloudflare/frontend.ts';
import { routeStateRequest } from '../cloudflare/vercel.ts';
import { createEffectHandler } from '../cloudflare/effects.ts';
import { QSTASH_TICK_BODY } from '../src/qstash.ts';
import { TOPIC } from '../src/queue.ts';
import type { RpcResponse, ToolCallResult } from './types.ts';
import type { QueuePayload, QueueMetadata } from '../src/queue.ts';
import type { Fetcher } from '../cloudflare/protocol.ts';
import { Miniflare, convertV4MiniflareOptions, Response as MFResponse } from 'miniflare';
import { build } from 'esbuild';
import { SQLiteStore, keyIdentity, MAX_STATE_BYTES } from '../cloudflare/sqlite-store.ts';
import type { TransactionStorage } from '../cloudflare/sqlite-store.ts';
import { emptyState, MemoryStore } from '../src/store.ts';
import { Bridge } from '../src/bridge.ts';
import { VERIFIED_AUTHORIZATION, SCOPES } from '../src/policy.ts';
import { MESSAGE_PROTOCOL } from '../src/messages.ts';
import type { VerifiedPrincipal, Store } from '../src/types.ts';

test('Vercel routes paused and unavailable Cloudflare deployments without a Postgres fallback', async () => {
  const original = 'https://bridge.example.test/api/cron';
  const request = () => new Request(original, { method: 'POST', body: '{"synthetic":true}',
    headers: { 'upstash-signature': 'fixture-signature' } });
  let postgresCalls = 0;
  const postgres = async () => { postgresCalls++; return new Response('postgres'); };
  const disabledFetch = async () => { assert.fail('this mode must not invoke Cloudflare'); };
  assert.equal(await (await routeStateRequest(request(), postgres, {}, disabledFetch)).text(), 'postgres');
  for (const backend of ['paused', 'unknown']) {
    assert.equal((await routeStateRequest(request(), postgres, { BRIDGE_STATE_BACKEND: backend }, disabledFetch)).status, 503);
  }
  const key = 'a'.repeat(64);
  const env = { BRIDGE_STATE_BACKEND: 'cloudflare', BRIDGE_CLOUDFLARE_ORIGIN: 'https://worker.example.test',
    BRIDGE_CLOUDFLARE_GATEWAY_KEY: key };
  const reply = await routeStateRequest(request(), postgres, env, async forwarded => {
    assert.equal(forwarded.url, 'https://worker.example.test/invoke');
    assert.equal(forwarded.headers.get('authorization'), 'Bearer ' + key);
    assert.equal(forwarded.headers.get('x-bridge-url'), original);
    assert.equal(forwarded.headers.get('x-bridge-original-upstash-signature'), 'fixture-signature');
    assert.equal(await forwarded.text(), '{"synthetic":true}');
    return new Response('unavailable', { status: 503 });
  });
  assert.equal(reply.status, 503);
  assert.equal(postgresCalls, 1);
});

function sqlite(file = ':memory:') {
  const db = new DatabaseSync(file);
  const storage: TransactionStorage = { sql: { exec(sql, ...values) {
    const statement = db.prepare(sql);
    if (/^\s*(SELECT|PRAGMA)/i.test(sql)) return { toArray: () => statement.all(...values) };
    statement.run(...values); return { toArray: () => [] };
  } }, transactionSync(fn) { db.exec('BEGIN IMMEDIATE');try { const out = fn(); db.exec('COMMIT');return out; } catch (e) { db.exec('ROLLBACK');throw e; } } };
  return { db, store: new SQLiteStore(storage, 'test:postgres') };
}
const keyId = keyIdentity(randomBytes(32));
test('Cloudflare SQLite: atomic revisions, rollback, async/poison/size refusal, concurrent writes and restart', async () => {
  const path = join(await mkdtemp(join(tmpdir(), 'bridge-cf-sqlite-')), 'state.sqlite');
  let { db, store } = sqlite(path); store.seedForTest(emptyState(), 33731, keyId);
  await Promise.all(Array.from({length:100}, () => store.transaction(s => { s.schedulerTicks ??= {}; (s.schedulerTicks as Record<string, number>).counter = ((s.schedulerTicks as Record<string, number>).counter || 0) + 1; })));
  assert.equal(await store.transaction(s => (s.schedulerTicks as Record<string, number> | undefined)?.counter), 100);
  assert.equal(store.status().revision, 33832);
  await assert.rejects(store.transaction(s => { s.messages = {}; throw Error('rollback'); }));
  await assert.rejects(store.transaction(s => { s.schedulerTicks = { bad: 1 }; return Promise.resolve() as never; }));
  await assert.rejects(store.transaction(s => { s.version = 2 as never; }));
  await assert.rejects(store.transaction(s => { s.schedulerTicks = { [ 'x'.repeat(MAX_STATE_BYTES) ]: 1 }; }));
  assert.equal(store.status().revision, 33832);
  db.close(); ({db, store} = sqlite(path));
  assert.equal(await store.transaction(s => (s.schedulerTicks as Record<string, number> | undefined)?.counter), 100); db.close();
});
test('Cloudflare transfer: frozen source cannot resume; checksum/key/target/revision fences, reverse rollback preserves all objects', async () => {
  const a = sqlite(), b = sqlite();
  // Two independent SQLite databases represent the two physical backends.
  const target = new SQLiteStore({ sql: { exec(sql,...v) { const s=b.db.prepare(sql); if (/^SELECT/i.test(sql)) return {toArray:()=>s.all(...v)};s.run(...v);return {toArray:()=>[]}; } },
    transactionSync(fn) { b.db.exec('BEGIN');try {const r=fn();b.db.exec('COMMIT');return r;}catch(e){b.db.exec('ROLLBACK');throw e;} } }, 'test:cloudflare');
  const state = emptyState(); state.schedulerTicks = { marker: 42 };
  a.store.seedForTest(state, 33731, keyId);
  const transfer=a.store.freeze(33731,'test:cloudflare');
  assert.deepEqual(a.store.freeze(33731,'test:cloudflare'),transfer);
  assert.throws(()=>a.store.freeze(33731,'wrong:target'));
  await assert.rejects(a.store.transaction(s=>s));
  assert.throws(()=>a.store.activate(transfer.handoff,33731));
  assert.throws(()=>target.importFrozen({...transfer,document:transfer.document+' '},keyId));
  assert.throws(()=>target.importFrozen(transfer,'0'.repeat(64)));
  assert.throws(()=>a.store.importFrozen(transfer,keyId));
  target.importFrozen(transfer,keyId);target.importFrozen(transfer,keyId);await assert.rejects(target.transaction(s=>s));
  target.activate(transfer.handoff,33731);assert.equal(target.status().revision,33732);
  assert.throws(()=>target.importFrozen(transfer,keyId));
  await target.transaction(s=>{(s.schedulerTicks as Record<string, number>).marker=43;});
  const back=target.freeze(33733,'test:postgres');a.store.importFrozen(back,keyId);a.store.activate(back.handoff,33733);
  assert.equal(await a.store.transaction(s=>(s.schedulerTicks as Record<string, number> | undefined)?.marker),43);
  await assert.rejects(target.transaction(s=>s));a.db.close();b.db.close();
});

const gatewayKey = '1'.repeat(64), migrationKey = '2'.repeat(64), effectKey = '3'.repeat(64);
const storageKey = randomBytes(32);
const environment = { BRIDGE_SUBSCRIPTION_STORAGE_KEY: storageKey.toString('base64'), BRIDGE_OAUTH_ISSUER: 'https://identity.jarvis-friday-bridge.aravhawk.com',
  BRIDGE_ALLOWED_SUBJECT:'fixture',BRIDGE_OAUTH_CONTRACT_VERIFIED:'true',BRIDGE_DELIVERY_ENABLED:'true',BRIDGE_SUBSCRIPTIONS_ENABLED:'true',
  FRIDAY_WEBHOOK_URL:'https://receiver.example.test/events',FRIDAY_WEBHOOK_KEY:'fixture-webhook-key',FRIDAY_WEBHOOK_CONTRACT_VERIFIED:'true',
  FRIDAY_RECEIVER_ID:'jarvis-friday-bridge-inbox',BRIDGE_RECEIVER_POLICY:'inbox-v1',BRIDGE_ATTACHMENTS_ENABLED:'true',BLOB_STORE_ID:'store_FakeStore00000001',BRIDGE_WAKE_SYNC_RECIPIENTS:'jarvis,friday',QSTASH_CURRENT_SIGNING_KEY:'sig_SYNTHETIC_CURRENT_123456',QSTASH_NEXT_SIGNING_KEY:'sig_SYNTHETIC_NEXT_123456',BRIDGE_QSTASH_DESTINATION_URL:'https://jarvis-friday-bridge.aravhawk.com/api/cron' };
let bundle: string;
async function worker(persist?: string, outbound?: Fetcher, runtimeEnvironment: Record<string, string> = environment) {
  if (!bundle) {
    const out=await build({entryPoints:['cloudflare/worker.ts'],bundle:true,write:false,format:'esm',platform:'node',target:'es2024',external:['node:*','cloudflare:workers'],alias:{pg:'./cloudflare/no-postgres.ts'},banner:{js:"import { createRequire } from 'node:module'; const require = createRequire('/worker.js');"}});
    bundle=out.outputFiles[0]!.text;
  }
  const options=convertV4MiniflareOptions({ modules:true, script:bundle, compatibilityDate:'2026-11-16', compatibilityFlags:['nodejs_compat','enable_nodejs_http_modules'],cf:false,host:'127.0.0.1',inspectorHost:'127.0.0.1',
    durableObjects:{BRIDGE:{className:'BridgeObject',useSQLite:true}}, ...(persist?{durableObjectsPersist:persist}:{}),
    bindings:{GATEWAY_KEY:gatewayKey,MIGRATION_KEY:migrationKey,EFFECT_KEY:effectKey,EFFECT_ENDPOINT:'https://effects.example.test/api/bridge-effects',STORE_IDENTITY:'test:cloudflare',RUNTIME_ENV:JSON.stringify(runtimeEnvironment)},
    outboundService:async request => { if (!outbound) return new MFResponse(null,{status:503}); const r=await outbound(request as unknown as Request); return new MFResponse(await r.text(),{status:r.status,headers:Object.fromEntries(r.headers)}); } });
  return new Miniflare({...options, ...(persist?{resourcePersistencePath:join(persist,'shared'),isolatedResourcePersistencePath:join(persist,'isolated')}:{}),enableDevRegistry:false,telemetry:{enabled:false}});
}
async function admin(mf:Miniflare, command:unknown) {return mf.dispatchFetch('https://gateway.example.test/migration',{method:'POST',headers:{authorization:'Bearer '+migrationKey},body:JSON.stringify(command)});}
test('Cloudflare real workerd: gateway auth before DO, SQLite import/activation/freeze and durable eviction/restart', async()=>{
 const directory=await mkdtemp(join(tmpdir(),'bridge-cf-workerd-'));let mf=await worker(directory);
 try {
  assert.equal((await mf.dispatchFetch('https://gateway.example.test/migration',{method:'POST',body:'malformed'})).status,401);
  const a=sqlite();a.store.seedForTest(emptyState(),33731,keyIdentity(storageKey));const transfer=a.store.freeze(33731,'test:cloudflare');
  assert.equal((await admin(mf,{operation:'import',transfer})).status,200);
  assert.equal((await admin(mf,{operation:'activate',handoff:transfer.handoff,revision:33731})).status,200);
  await mf.dispose();mf=await worker(directory);
  const status=await (await admin(mf,{operation:'status'})).json() as {revision:number;mode:string};
  assert.equal(status.revision,33732);assert.equal(status.mode,'active');
  const frozen=await (await admin(mf,{operation:'freeze',revision:33732,target:'test:postgres'})).json() as {document:string};
  assert.deepEqual(JSON.parse(frozen.document),emptyState());
  await mf.dispose();mf=await worker(directory);
  assert.deepEqual(await (await admin(mf,{operation:'freeze',revision:33732,target:'test:postgres'})).json(),frozen);a.db.close();
 } finally {await mf.dispose();}
});

test('Cloudflare real workerd: delivery-off fallback keeps migration available and omits task tools', async()=>{
 const {publicKey,privateKey}=await generateKeyPair('RS256');const jwk=await exportJWK(publicKey);jwk.kid='fallback';jwk.alg='RS256';
 let requests=0;
 const mf=await worker(undefined,async request=>{
  requests++;assert.equal(request.url,environment.BRIDGE_OAUTH_ISSUER+'/.well-known/jwks.json');return Response.json({keys:[jwk]});
 },{...environment,BRIDGE_DELIVERY_ENABLED:'false'});
 const source=sqlite();
 try {
  const status=await admin(mf,{operation:'status'});assert.equal(status.status,200);assert.deepEqual(await status.json(),{mode:'dormant'});
  source.store.seedForTest(emptyState(),1,keyIdentity(storageKey));const transfer=source.store.freeze(1,'test:cloudflare');
  assert.equal((await admin(mf,{operation:'import',transfer})).status,200);
  assert.equal((await admin(mf,{operation:'activate',handoff:transfer.handoff,revision:1})).status,200);
  assert.equal(requests,0,'migration never acquires OAuth/provider data');
  const token=await new SignJWT({scope:Object.values(SCOPES.jarvis!).join(' ')})
   .setProtectedHeader({alg:'RS256',kid:'fallback'}).setIssuer(environment.BRIDGE_OAUTH_ISSUER).setSubject('fixture')
   .setAudience(resourceFor('jarvis')).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const frontend=createCloudflareFrontend({endpoint:'https://gateway.example.test',key:gatewayKey,fetcher:async request=>{
   const r=await mf.dispatchFetch(request.url,{method:request.method,headers:Object.fromEntries(request.headers),body:await request.text()});
   return new Response(await r.text(),{status:r.status,headers:Object.fromEntries(r.headers)});
  }});
  const result=await frontend.fetch(new Request(resourceFor('jarvis'),{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},
   body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list',params:{}})}));
  assert.equal(result.status,200);const output=await result.json() as {result:{tools:{name:string}[]}};
  assert.ok(output.result.tools.some(t=>t.name==='bridge_health'));
  assert.equal(output.result.tools.some(t=>t.name.startsWith('bridge_task_')),false);
  assert.equal(requests,1,'only synthetic JWKS lookup is needed');
 } finally {source.db.close();await mf.dispose();}
});

test('Cloudflare real workerd story: OAuth/MCP, scheduled SYNC, WAKE, queue retry, receipt fencing, lost completion and terminal ACK', async()=>{
 const {publicKey,privateKey}=await generateKeyPair('RS256');const jwk=await exportJWK(publicKey);jwk.kid='synthetic';jwk.alg='RS256';
 const issuer=environment.BRIDGE_OAUTH_ISSUER;const now=Date.now();const start=now-3*3600000;
 const tokens:Record<string,string>={};
 for(const role of ['jarvis','friday']) tokens[role]=await new SignJWT({scope:Object.values(SCOPES[role]!).join(' ')})
  .setProtectedHeader({alg:'RS256',kid:'synthetic'}).setIssuer(issuer).setSubject('fixture').setAudience(resourceFor(role)).setIssuedAt().setExpirationTime(Math.floor(now/1000)+86400).sign(privateKey);
 const policies=Object.fromEntries(['jarvis','friday'].map(role=>[role,authorizationPolicyId({issuer,audience:resourceFor(role),role,subject:'fixture'})]));
 const principals:Record<string,VerifiedPrincipal>={};
 for(const role of ['jarvis','friday'])principals[role]=await createAccessVerifier({issuer,audience:resourceFor(role),role,subject:'fixture',keyResolver:()=>Promise.resolve(publicKey)})(new Request(resourceFor(role),{headers:{authorization:'Bearer '+tokens[role]}}));
 const source=sqlite();const bridge=new Bridge({store:source.store,clock:()=>start,messagePolicyIds:policies,dailyEnabled:true,wakeSync:()=>['jarvis','friday']});
 source.store.seedForTest(emptyState(),33731,keyIdentity(storageKey));
 const secret='whsec_'+randomBytes(32).toString('base64');
 const events=new NativeEvents({store:source.store,protector:createProtector(storageKey),policyId:policies.jarvis,clock:()=>start,enabled:true,
  transport:async(_url,r)=>({status:200,body:JSON.stringify({challenge:JSON.parse(r.body).challenge})})});
 await events.subscribe(principals.jarvis!,{name:EVENT_NAME,arguments:{recipient:'jarvis'},delivery:{mode:'webhook',url:'https://callback.example.test/events',secret},ttlMs:null});
 const syncId=randomUUID();const threadId=randomUUID();
 await bridge.sendMessage(principals.jarvis!,{protocol:MESSAGE_PROTOCOL,id:syncId,from:'jarvis',to:'friday',kind:'status',class:'sync',subject:'routine',route:'inbox',threadId,
  text:'Synthetic dependency-free FYI',sentAt:new Date(start).toISOString(),expiresAt:new Date(start+6*3600000).toISOString()});
 const publications:{payload:QueuePayload;options:unknown}[]=[];const notifications:{messageId:string;headers:Record<string,string>}[]=[];
 const fakeBlob=createFakeBlob({storeId:environment.BLOB_STORE_ID,clock:Date.now});
 const effects=createEffectHandler({blob:config=>createBlobProvider({config,sdk:fakeBlob.sdk as unknown as BlobSdk}),key:effectKey,env:environment,queue:{send:async(_topic,payload,options)=>{publications.push({payload,options});}},
  transport:async(url,r)=>{if(url==='https://callback.example.test/events')new Webhook(secret).verify(r.body,r.headers);else assert.equal(new Headers(r.headers).get('authorization'),'Bearer fixture-webhook-key');const body=JSON.parse(r.body);notifications.push({messageId:body.data?.messageId||body.messageId,headers:r.headers});return {status:200,body:''};}});
 let unexpected=0;const effectErrors:{status:number;code:unknown}[]=[];
 const outbound:Fetcher=async request=>{
  const u=new URL(request.url);
  if(u.origin===issuer&&u.pathname==='/.well-known/jwks.json')return Response.json({keys:[jwk]});
  if(u.origin==='https://effects.example.test'&&u.pathname==='/api/bridge-effects'){const r=await effects(request);if(!r.ok)effectErrors.push({status:r.status,code:(await r.clone().json() as {error:unknown}).error});return r;}
  unexpected++;return new Response(null,{status:503});
 };
 const mf=await worker(undefined,outbound);
 const frontend=createCloudflareFrontend({endpoint:'https://gateway.example.test',key:gatewayKey,fetcher:async request=>{
  const r=await mf.dispatchFetch(request.url,{method:request.method,headers:Object.fromEntries(request.headers),body:await request.text()});
  return new Response(await r.text(),{status:r.status,headers:Object.fromEntries(r.headers)});
 }});
 type View={error?:string;messageId:string;claimId:string;completed:boolean;duplicate:boolean;ackMessageId:string;receiptCompleted:boolean;syncBatch?:{acknowledged:boolean};syncBatches?:{batchMessageId:string;items:unknown[]}[]};
 async function rpc(role:string,name:string,args:unknown,allowError=false):Promise<View>{
  const r=await frontend.fetch(new Request(resourceFor(role),{method:'POST',headers:{authorization:'Bearer '+tokens[role],'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}})}));
  assert.equal(r.status,200);const body=await r.json() as RpcResponse<ToolCallResult<View>>;assert.equal(body.error,undefined);if(!allowError)assert.equal(body.result.isError,false,JSON.stringify(body.result.structuredContent));return body.result.structuredContent;
 }
 async function drain(){let count=0;while(publications.length){assert.ok(++count<60);const item=publications.shift()!;if(Object.hasOwn(item.payload,'cleanupMessageId'))continue;
  const metadata:QueueMetadata={topicName:TOPIC,region:'iad1',deliveryCount:1,messageId:'synthetic_queue_'+count,createdAt:new Date(),expiresAt:new Date(Date.now()+3600000)};
  await frontend.consume(item.payload,metadata);await frontend.consume(item.payload,metadata); // native at-least-once callback
 }}
 try {
  const transfer=source.store.freeze(source.store.status().revision!,'test:cloudflare');
  assert.equal((await admin(mf,{operation:'import',transfer})).status,200);assert.equal((await admin(mf,{operation:'activate',handoff:transfer.handoff,revision:transfer.revision})).status,200);
  const unauth=await frontend.fetch(new Request(resourceFor('jarvis'),{method:'POST',headers:{'content-type':'application/json'},body:'poison'}));assert.equal(unauth.status,401);
  const badBearer=await frontend.fetch(new Request(resourceFor('jarvis'),{method:'POST',headers:{authorization:'Bearer invalid','content-type':'application/json'},body:'{}'}));assert.equal(badBearer.status,401);
  const health=await rpc('jarvis','bridge_health',{}) as unknown as {readiness:{deliveryEnabled:boolean}};assert.equal(health.readiness.deliveryEnabled,true,JSON.stringify(health.readiness));
  const secs=Math.floor(Date.now()/1000);const signature=await new SignJWT({iss:'Upstash',sub:environment.BRIDGE_QSTASH_DESTINATION_URL,iat:secs,nbf:-1,exp:secs+300,jti:'synthetic_tick',body:createHash('sha256').update(QSTASH_TICK_BODY).digest('base64url')})
   .setProtectedHeader({alg:'HS256'}).sign(new TextEncoder().encode(environment.QSTASH_CURRENT_SIGNING_KEY));
  const tick=()=>frontend.fetch(new Request(environment.BRIDGE_QSTASH_DESTINATION_URL,{method:'POST',headers:{'upstash-signature':signature},body:QSTASH_TICK_BODY}));
  const firstTick=await tick();assert.equal(firstTick.status,200,JSON.stringify({tick:await firstTick.json(),effectErrors,unexpected,publications:publications.length}));await drain();assert.equal(notifications.length,1);
  const batch=notifications[0]!.messageId;assert.ok(batch);assert.notEqual(batch,syncId);
  assert.equal((await tick()).status,200);await drain();assert.equal(notifications.length,1,'tick/queue replay no duplicate webhook');
  const read=await rpc('friday','bridge_read',{messageId:batch});assert.ok(read.syncBatches?.length);
  const held=await rpc('friday','bridge_receipt_claim',{messageId:batch});
  // One complete commits; its HTTP response is deliberately discarded. Replay uses the same claim.
  const complete={messageId:batch,claimId:held.claimId,hostedEventId:null,hostedTurnId:null};await rpc('friday','bridge_receipt_complete',complete);
  const replay=await rpc('friday','bridge_receipt_complete',complete);assert.equal(replay.duplicate,true);assert.ok(replay.ackMessageId);
  await drain();assert.equal(notifications.length,2);
  const ack=await rpc('jarvis','bridge_receipt_claim',{messageId:replay.ackMessageId});
  const end=await rpc('jarvis','bridge_receipt_complete',{messageId:replay.ackMessageId,claimId:ack.claimId,hostedEventId:null,hostedTurnId:null});assert.equal(end.ackMessageId,null);await drain();assert.equal(notifications.length,2);
  const wakeId=randomUUID();const draft={protocol:MESSAGE_PROTOCOL,id:wakeId,from:'jarvis',to:'friday',kind:'message',class:'wake',route:'inbox',threadId,
   text:'Synthetic urgent workflow data',sentAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString()};
  await rpc('jarvis','bridge_message_send',draft);await rpc('jarvis','bridge_message_send',draft);await drain();assert.equal(notifications.length,3);assert.equal(notifications[2]!.messageId,wakeId);
  const claims=await Promise.all([rpc('friday','bridge_receipt_claim',{messageId:wakeId},true),rpc('friday','bridge_receipt_claim',{messageId:wakeId},true)]);
  assert.equal(claims.filter(c=>c.claimId).length,1,'one receipt holder');assert.equal(claims.find(c=>c.error)?.error,'receipt_busy');
  const done=await rpc('friday','bridge_receipt_complete',{messageId:wakeId,claimId:claims.find(c=>c.claimId)!.claimId,hostedEventId:null,hostedTurnId:null});await drain();assert.equal(notifications.length,4);assert.ok(done.ackMessageId);
  // The Vercel adapter retains Blob SDK execution; only bounded metadata/capabilities cross, never object bytes.
  const bytes=Buffer.from('synthetic local file');const hash=createHash('sha256').update(bytes).digest('hex');
  const begun=await rpc('jarvis','bridge_attachment_begin',{name:'fixture.txt',size:bytes.length,sha256:hash}) as unknown as BeginResult;
  fakeBlob.objects.set('att/'+begun.attachmentId,{body:bytes,etag:'fixture-etag'});
  await rpc('jarvis','bridge_attachment_finalize',{id:begun.attachmentId,etag:'fixture-etag'});
  const attachedId=randomUUID();await rpc('jarvis','bridge_message_send',{...draft,id:attachedId,attachmentIds:[begun.attachmentId]});
  const grant=await rpc('friday','bridge_attachment_download',{messageId:attachedId,attachmentId:begun.attachmentId,rangeStart:1,rangeEnd:bytes.length-1}) as unknown as DownloadResult;
  assert.equal(grant.size,bytes.length);assert.equal(grant.sha256,hash);assert.equal(grant.download.headers.range,'bytes=1-'+(bytes.length-1));
  assert.equal(fakeBlob.calls.some(c=>c.op==='del'),false);
  const command={operation:'create',taskId:randomUUID(),commandId:randomUUID(),sequence:1,assignee:'friday',description:'Synthetic local task data',deadline:Date.now()+86400000};
  const notice={messageId:randomUUID(),sentAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString()};
  await rpc('jarvis','bridge_task_command',{command,notice});await rpc('jarvis','bridge_task_command',{command,notice});
  const task=await rpc('jarvis','bridge_task_get',{taskId:command.taskId,commandId:command.commandId}) as unknown as TaskToolOutput;
  assert.equal(task.caller!.nextSequence,2);assert.equal(task.caller!.command!.status,'committed');
  assert.equal(unexpected,0,'all outbound traffic stays in synthetic adapter harness');
  const status=await(await admin(mf,{operation:'status'})).json() as {revision:number};assert.ok(status.revision>transfer.revision);
  await Promise.all(Array.from({length:10},()=>rpc('friday','bridge_status',{messageId:wakeId})));
  const after=await(await admin(mf,{operation:'status'})).json() as {revision:number};assert.equal(after.revision-status.revision,10,'concurrent DO reads preserve every revision');
 } finally {await mf.dispose();source.db.close();}
});

test('Cloudflare SQLite/reference parity: expired claims, truthful batch outcomes, ACKs and immutable replay',async()=>{
 const at=Date.UTC(2026,10,16,15,30), policy='c'.repeat(64);
 const who=(role:string):VerifiedPrincipal=>({role,scopes:Object.values(SCOPES[role]!),principalKey:(role==='jarvis'?'a':'b').repeat(64),[VERIFIED_AUTHORIZATION]:{policyId:policy,expiresAt:at+86400000}});
 async function story(store:Store){
  let now=at;const bridge=new Bridge({store,clock:()=>now,dailyEnabled:true,messagePolicyIds:{jarvis:policy,friday:policy},wakeSync:()=>['jarvis','friday']});
  const events=new NativeEvents({store,clock:()=>now,policyId:policy,enabled:true,protector:createProtector(storageKey),transport:async(_u,r)=>({status:200,body:JSON.stringify({challenge:JSON.parse(r.body).challenge})})});
  await events.subscribe(who('jarvis'),{name:EVENT_NAME,arguments:{recipient:'jarvis'},delivery:{mode:'webhook',url:'https://callback.example.test/events',secret:'whsec_'+randomBytes(32).toString('base64')},ttlMs:null});
  const id=randomUUID(),wake=randomUUID(),thread=randomUUID();
  const send=(messageId:string,kind:'wake'|'sync')=>bridge.sendMessage(who('jarvis'),{protocol:MESSAGE_PROTOCOL,id:messageId,from:'jarvis',to:'friday',kind:'status',class:kind,route:'inbox',threadId:thread,text:'Synthetic FYI',sentAt:new Date(now).toISOString(),expiresAt:new Date(now+(kind==='sync'?6:1)*3600000).toISOString()});
  const queued=await send(id,'sync');const immediate=await send(wake,'wake');assert.equal(queued.delivery,'batched');assert.equal(immediate.delivery,'immediate');
  const wc=await bridge.claim(who('friday'),{messageId:wake});now+=60001;
  await assert.rejects(bridge.complete(who('friday'),{messageId:wake,claimId:wc.claimId,hostedEventId:null,hostedTurnId:null}));
  const fresh=await bridge.claim(who('friday'),{messageId:wake});const done=await bridge.complete(who('friday'),{messageId:wake,claimId:fresh.claimId,hostedEventId:null,hostedTurnId:null});
  const replay=await bridge.complete(who('friday'),{messageId:wake,claimId:fresh.claimId,hostedEventId:null,hostedTurnId:null});assert.equal(replay.ackMessageId,done.ackMessageId);
  const ac=await bridge.claim(who('jarvis'),{messageId:done.ackMessageId});const ack=await bridge.complete(who('jarvis'),{messageId:done.ackMessageId,claimId:ac.claimId,hostedEventId:null,hostedTurnId:null});assert.equal(ack.ackMessageId,null);
  now=at+2*3600000;await bridge.flushSync();
  const state=await store.transaction(s=>s);
  return {messages:Object.keys(state.messages).length,jobs:Object.keys(state.jobs).length,receipts:Object.values(state.receipts).map(r=>r.state).sort(),ackTerminal:ack.ackMessageId,duplicate:replay.duplicate};
 }
 const local=sqlite();local.store.seedForTest(emptyState(),0,keyId);
 assert.deepEqual(await story(local.store),await story(new MemoryStore()));local.db.close();
});
test('Cloudflare state capacity and transfer: exact 4MiB, escaping, unknown sections, active-lease freeze refusal',async()=>{
 const a=sqlite(),b=sqlite();const s=emptyState();s.opaque={nested:['data',{'unicode':'✓'}]};s.padding='';
 s.padding='x'.repeat(MAX_STATE_BYTES-Buffer.byteLength(JSON.stringify(s)));a.store.seedForTest(s,0,keyId);
 assert.equal(Buffer.byteLength(JSON.stringify(s)),MAX_STATE_BYTES);
 const target=new SQLiteStore(b.store.storage,'test:target');const transfer=a.store.freeze(0,'test:target');target.importFrozen(transfer,keyId);target.activate(transfer.handoff,0);
 assert.deepEqual(await target.transaction(v=>v),s);
 await target.transaction(v=>{delete v.padding;v.receipts[randomUUID()]={state:'claimed',leaseUntil:Date.now()+60000};});
 assert.throws(()=>target.freeze(target.status().revision!,'test:postgres'),/migration_active_leases/);a.db.close();b.db.close();
});

// These are SQLite protocol failure-window tests, not PostgreSQL qualification.
test('Cloudflare handoff outage windows: no automatic source fallback, late writes fenced, restart and lost activation reconcile', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'bridge-cf-handoff-'));
  let source = sqlite(join(directory, 'source.sqlite'));
  let destination = sqlite(join(directory, 'destination.sqlite'));
  const target = () => new SQLiteStore(destination.store.storage, 'test:target');
  try {
    const state = emptyState(); state.schedulerTicks = { checkpoint: 7 };
    source.store.seedForTest(state, 70, keyId);
    let release!: () => void;
    const pending = new Promise<void>(resolve => { release = resolve; });
    const lateWrite = (async () => { await pending; return source.store.transaction(s => { s.schedulerTicks = { checkpoint: 999 }; }); })();
    const rejectedLateWrite = assert.rejects(lateWrite, /storage_writer_frozen/);
    const transfer = source.store.freeze(70, 'test:target');
    release(); await rejectedLateWrite;
    assert.throws(() => source.store.activate(transfer.handoff, 70), /migration_activation_conflict/);
    assert.throws(() => target().importFrozen({ ...transfer, checksum: '0'.repeat(64) }, keyId), /migration_checksum_mismatch/);
    assert.deepEqual(target().status(), { mode: 'dormant' });
    source.db.close(); source = sqlite(join(directory, 'source.sqlite'));
    assert.deepEqual(source.store.freeze(70, 'test:target'), transfer, 'lost freeze response survives source restart');
    await assert.rejects(source.store.transaction(s => s), /storage_writer_frozen/);
    target().importFrozen(transfer, keyId);
    destination.db.close(); destination = sqlite(join(directory, 'destination.sqlite'));
    await assert.rejects(target().transaction(s => s), /storage_writer_frozen/);
    assert.equal(target().status().mode, 'frozen');
    target().importFrozen(transfer, keyId); // Lost import response; no extra activation.
    target().activate(transfer.handoff, 70); // Simulate losing the returned status.
    destination.db.close(); destination = sqlite(join(directory, 'destination.sqlite'));
    assert.equal(target().status().mode, 'active'); assert.equal(target().status().revision, 71);
    assert.throws(() => target().activate(transfer.handoff, 70), /migration_activation_conflict/);
    assert.equal(target().status().revision, 71, 'activation retry cannot advance revision twice');
    await assert.rejects(source.store.transaction(s => s), /storage_writer_frozen/);
    await target().transaction(s => { s.schedulerTicks = { checkpoint: 8 }; });
    const reverse = target().freeze(72, 'test:postgres');
    source.store.importFrozen(reverse, keyId); source.store.activate(reverse.handoff, 72);
    assert.deepEqual(await source.store.transaction(s => s.schedulerTicks), { checkpoint: 8 });
    await assert.rejects(target().transaction(s => s), /storage_writer_frozen/);
    assert.throws(() => target().importFrozen(transfer, keyId), /migration_destination_not_frozen/);
  } finally { source.db.close(); destination.db.close(); }
});

test('Cloudflare handoff drain: live job lease blocks freeze and pending outbox evidence survives transfer', async () => {
  const source = sqlite(), destination = sqlite();
  const target = new SQLiteStore(destination.store.storage, 'test:target');
  try {
    const state = emptyState(), id = 'job_' + 'a'.repeat(64), messageId = randomUUID();
    state.jobs[id] = { id, messageId, recipient: 'friday', subscriptionId: null, eventId: randomUUID(), body: '{}',
      state: 'leased', attempts: 1, dueAt: Date.now() - 1000, leaseId: randomUUID(), leaseUntil: Date.now() + 60000,
      firstTransportOutcome: { at: Date.now() - 1000, workerAttempt: 1, status: 503, error: null, terminal: false }, transportAttempts: 1 };
    source.store.seedForTest(state, 0, keyId);
    assert.throws(() => source.store.freeze(0, 'test:target'), /migration_active_leases/);
    assert.equal(source.store.status().mode, 'active'); assert.equal(source.store.status().revision, 0);
    const expected = await source.store.transaction(s => {
      const job = s.jobs[id]!; job.state = 'pending'; job.leaseId = null; job.leaseUntil = null; return job;
    });
    const transfer = source.store.freeze(1, 'test:target'); target.importFrozen(transfer, keyId); target.activate(transfer.handoff, 1);
    assert.deepEqual(await target.transaction(s => s.jobs[id]), expected);
    await assert.rejects(source.store.transaction(s => s), /storage_writer_frozen/);
  } finally { source.db.close(); destination.db.close(); }
});
