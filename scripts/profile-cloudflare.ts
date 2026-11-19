// Local CPU proxy, not a Cloudflare billed-CPU measurement. No network or credentials.
import { DatabaseSync } from 'node:sqlite';
import { SQLiteStore } from '../cloudflare/sqlite-store.ts';
import gateway from '../cloudflare/gateway.ts';
import { emptyState } from '../src/store.ts';
import type { DurableObjectNamespace } from '@cloudflare/workers-types';

const results=[];
for(const size of [84540,1024*1024,4*1024*1024]){
 const db=new DatabaseSync(':memory:');const store=new SQLiteStore({sql:{exec(sql,...v){const s=db.prepare(sql);if(/^SELECT/i.test(sql))return{toArray:()=>s.all(...v)};s.run(...v);return{toArray:()=>[]};}},transactionSync(fn){db.exec('BEGIN');try{const r=fn();db.exec('COMMIT');return r;}catch(e){db.exec('ROLLBACK');throw e;}}},'profile:local');
 const state=emptyState();state.padding='';state.padding='x'.repeat(size-Buffer.byteLength(JSON.stringify(state)));store.seedForTest(state,0,'a'.repeat(64));
 const samples=[];for(let i=0;i<30;i++){const start=process.cpuUsage();await store.transaction(s=>Object.keys(s.messages).length);const cpu=process.cpuUsage(start);samples.push((cpu.user+cpu.system)/1000);}samples.sort((a,b)=>a-b);
 // Structural native Fetch boundary. It never reads/parses the incoming state-sized stream.
 const namespace={idFromName:()=>({}),get:()=>({fetch:async(r:Request)=>{void r.body?.cancel();return new Response('{}');}})} as unknown as DurableObjectNamespace;
 const thin=[];for(let i=0;i<100;i++){const request=new Request('https://local.example/invoke',{method:'POST',headers:{authorization:'Bearer '+'1'.repeat(64)},body:JSON.stringify(state)});const start=process.cpuUsage();await gateway.fetch(request,{BRIDGE:namespace,GATEWAY_KEY:'1'.repeat(64),MIGRATION_KEY:'2'.repeat(64)});const cpu=process.cpuUsage(start);thin.push((cpu.user+cpu.system)/1000);}thin.sort((a,b)=>a-b);
 results.push({stateBytes:size,storeCpuMs:{p50:samples[15],p95:samples[28]},thinGatewayCpuMs:{p50:thin[50],p95:thin[95]}});db.close();
}
console.log(JSON.stringify({measurement:'local_Node_CPU_proxy_not_Cloudflare_billed_CPU',results},null,2));
