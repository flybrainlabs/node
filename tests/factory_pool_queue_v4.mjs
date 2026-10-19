// Real PostgreSQL concurrency and restart boundaries, isolated acceptance only.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {FactoryPoolQueueV4,reserveTargetV4,poolReplenishmentV4} from '../tools/factory_pool_queue_v4.mjs';
const host=process.env.FLYBRAIN_POOL_TEST_SOCKET;
if(!host?.startsWith('/var/tmp/flybrainlabs-postgres-acceptance-'))throw new Error('An isolated acceptance PostgreSQL Unix socket is required');
const options={host,port:55439,user:'pool_acceptance',database:'postgres',max:16},scope='acceptance:'+randomUUID(),q=await new FactoryPoolQueueV4(new pg.Pool(options)).initialize(),checks=[];
try{
 const jobs=1000;
 await q.transaction(async c=>{for(let i=0;i<jobs;i++)await q.enqueue({id:scope+':'+i,kind:'input',scope,payload:{input:i}},c);});
 const ids=new Set();let completed=0;
 await Promise.all(Array.from({length:100},(_,i)=>(async()=>{for(;;){const j=await q.claim('input',scope+':miner:'+i,60,null,[scope]);if(!j)break;if(j.scope!==scope)throw new Error('Dedicated acceptance state required');assert(!ids.has(j.id));ids.add(j.id);await q.finish(j,{computed:true});completed++;}})()));
 assert.equal(completed,jobs);assert.equal(ids.size,jobs);checks.push('100 concurrent claimers completed 1000 durable input jobs without duplicate leases');
 const identical=await q.enqueue({id:scope+':0',kind:'input',scope,payload:{input:0}});assert.equal(identical.state,'done');
 await assert.rejects(q.enqueue({id:scope+':0',kind:'input',scope,payload:{input:1}}),/POOL_JOB_CONFLICT/);
 await assert.rejects(q.pool.query('UPDATE factory_pool_v4.jobs SET payload=$2 WHERE id=$1',[scope+':0',{input:'changed'}]),/Frozen job identity/);checks.push('Repeated requests retain the original payload and completion; conflicting work is rejected');
 const id=scope+':crash';await q.enqueue({id,kind:'replay',scope,payload:{submission:'fixture'}});const first=await q.claim('replay','terminated-process',60,null,[scope]);
 await q.pool.query("UPDATE factory_pool_v4.jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",[id]);
 const second=await q.claim('replay','replacement-process',60,null,[scope]);assert.equal(second.id,first.id);assert(BigInt(second.fence)>BigInt(first.fence));
 await assert.rejects(q.finish(first,{stale:true}),/POOL_LEASE_LOST/);await q.renew(second,60);await q.finish(second,{recovered:true});checks.push('Expired leases recover with a new fence; the stopped process cannot complete or renew its old lease');
 const tid=scope+':transport';await q.enqueue({id:tid,kind:'payment',scope,payload:{payer:'fixture'}});const lease=await q.claim('payment','sender',60,null,[scope]),packet={instructionHash:'a'.repeat(64),signature:'acceptance-'+randomUUID(),rawBase64:'AAEC',lastValidBlockHeight:100,feeLamports:5000};
 const stored=await q.signed(lease,tid,packet),same=await q.signed(lease,tid,{...packet,signature:'never-use-replacement',rawBase64:'BAUG'});assert.equal(same.signature,stored.signature);assert.equal(same.raw_base64,'AAEC');
 await assert.rejects(q.pool.query('UPDATE factory_pool_v4.transactions SET raw_base64=$2 WHERE id=$1',[tid,'replacement']),/Signed transaction changed/);
 await q.receipt(lease,tid,'unknown',{signature:stored.signature});await q.receipt(lease,tid,'finalized',{signature:stored.signature,slot:10});await assert.rejects(q.receipt(lease,tid,'unknown',{}),/POOL_RECEIPT_CONFLICT/);await q.finish(lease,{finalized:true});checks.push('Signed packets survive retries byte for byte, and finalized receipts cannot be downgraded');
 let cursor='0',events=[];for(;;){const page=await q.events(scope,cursor,73);if(!page.length)break;events.push(...page);cursor=page.at(-1).sequence;}assert.equal(events.length,1002);assert.equal(new Set(events.map(x=>x.sequence)).size,events.length);checks.push('Durable event cursor reconnects across bounded pages without missing or duplicating committed completions');
 const reopened=new FactoryPoolQueueV4(new pg.Pool(options));try{const {rows:[r]}=await reopened.pool.query('SELECT * FROM factory_pool_v4.transactions WHERE id=$1',[tid]);assert.equal(r.state,'finalized');assert.equal(r.raw_base64,packet.rawBase64);}finally{await reopened.close();}checks.push('A fresh database connection recovers the committed original transaction and receipt');
 assert.deepEqual(reserveTargetV4({peakTasksPerSecond:2,prepareP95Seconds:100,registrationP95Seconds:20}),{required:480,target:480,withinCapacity:true});assert.equal(reserveTargetV4({peakTasksPerSecond:100,prepareP95Seconds:100,registrationP95Seconds:20}).withinCapacity,false);assert.throws(()=>reserveTargetV4({peakTasksPerSecond:NaN,prepareP95Seconds:1,registrationP95Seconds:1}));checks.push('Reserve sizing uses measured consumption and preparation time; exceeding capacity is explicit');
 assert.deepEqual(poolReplenishmentV4({remaining:100,preparedTasks:0,openCatalogs:0,preparedCatalogs:0,target:8,groups:4}),{shortage:8,withinCapacity:true});assert.equal(poolReplenishmentV4({remaining:100,preparedTasks:8,openCatalogs:0,preparedCatalogs:2,target:8,groups:4}).shortage,0);checks.push('Closed claim windows trigger fresh catalog supply even while many frozen future tasks remain queued');
 console.log(JSON.stringify({passed:true,postgresql:true,concurrentClaimers:100,jobs,checks,publicChainWrites:0}));
}finally{await q.close();}
