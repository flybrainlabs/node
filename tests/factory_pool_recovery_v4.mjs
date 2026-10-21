// Actual PostgreSQL lifecycle and reconciliation with explicit chain/packet
// fixtures. The SBF suite independently covers real isolated token transfers.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {Keypair,PublicKey} from '@solana/web3.js';
import {FactoryPoolQueueV4} from '../tools/factory_pool_queue_v4.mjs';
import {FactoryPoolSupplyV4} from '../tools/factory_pool_supply_v4.mjs';
import {reconcilePoolBlockedV4,replayCapacityV4} from '../tools/factory_pool_maintenance_v4.mjs';
import {verifyPoolManifestV4,verifyPoolHistoryV4} from '../web/factory-pool-v4.mjs';
import {canonical,hash} from '../web/target-protocol-v2.mjs';
import {STATE} from '../web/task-factory-v4-codec.mjs';
const host=process.env.FLYBRAIN_POOL_TEST_SOCKET;if(!host?.startsWith('/var/tmp/flybrainlabs-postgres-acceptance-'))throw new Error('Isolated PostgreSQL required');
const database='pool_recovery_'+randomUUID().replaceAll('-',''),admin=new pg.Pool({host,port:55439,user:'pool_acceptance',database:'postgres',max:1});await admin.query('CREATE DATABASE '+database);await admin.end();
const q=await new FactoryPoolQueueV4(new pg.Pool({host,port:55439,user:'pool_acceptance',database,max:6})).initialize();
const key=()=>Keypair.generate().publicKey.toBase58(),authority=Keypair.generate(),payer=key(),poolId='9'.repeat(64),envelope={graphRoot:'1'.repeat(64)},base={factory:key(),factoryId:'0'.repeat(64),catalogRoot:'1'.repeat(64),budgetAtoms:'100',taskCount:1,deadline:'20000'};
const trust={schema:'flybrainlabs-factory-pool-trust-v4',poolId,authority:authority.publicKey.toBase58(),genesisHash:key(),programId:key(),mint:key(),policyHash:'2'.repeat(64),envelopeHash:await hash(canonical(envelope)),anchorFactory:base.factory,envelope};
Object.assign(base,{programId:trust.programId,genesisHash:trust.genesisHash,cluster:'devnet'});
const supply=new FactoryPoolSupplyV4({queue:q,baseDeployment:base,trust,authority,authorization:{rewardAtoms:'20000',evidenceHash:'e'.repeat(64)}});
const contexts=new Map(),statuses=new Map(),chainTime=Math.floor(Date.now()/1000),service={queue:q,contexts,config:{poolTrust:trust,replayP95Seconds:90},connection:{getSlot:async()=>1,getBlockTime:async()=>chainTime,getSignatureStatuses:async signatures=>({value:signatures.map(s=>statuses.get(s)||null)})}};
const checks=[];
try{
 await q.initialize();assert.equal((await q.pool.query("SELECT count(*)::int AS n FROM pg_trigger WHERE tgname IN ('immutable_job','immutable_transaction') AND NOT tgisinternal")).rows[0].n,2);
 // More than 128 retained database catalogs never become a giant active
 // manifest. These are lifecycle fixtures, not 132 claimed on-chain factories.
 const catalogs=[];for(let n=0;n<132;n++){const d={...base,factory:key(),factoryId:n.toString(16).padStart(64,'0')};catalogs.push(d);await q.pool.query("INSERT INTO factory_pool_v4.catalogs(id,pool_id,deployment,plan_hash,compiled,state,serving_state,registered_at) VALUES($1,$2,$3,$4,$5,'registered',$6,clock_timestamp())",[d.factory,poolId,d,'f'.repeat(64),{},n===131?'serving':n===0?'draining':'retired']);}
 const first=await supply.manifest({anchor:base,now:100,ttl:60});assert.equal(first.catalogs.length,2);assert(first.catalogs.some(c=>c.factory===catalogs[131].factory));let previous=await verifyPoolManifestV4(first,trust,{now:110});const second=await supply.manifest({anchor:base,now:170,ttl:60});previous=await verifyPoolManifestV4(second,trust,{now:180,previous});assert.equal(previous.revision,2);
 const old=await supply.history(catalogs[0].factory,{now:170,ttl:60});assert.equal((await verifyPoolHistoryV4(old,trust,{factory:catalogs[0].factory,now:180})).catalog.factory,catalogs[0].factory);await assert.rejects(verifyPoolHistoryV4(old,trust,{factory:catalogs[0].factory,now:231}));const renewed=await supply.history(catalogs[0].factory,{now:232,ttl:60});await verifyPoolHistoryV4(renewed,trust,{factory:catalogs[0].factory,now:240});assert.equal((await q.pool.query('SELECT count(*)::int AS n FROM factory_pool_v4.catalogs')).rows[0].n,132);checks.push('132 retained PostgreSQL catalog fixtures, bounded active manifests, monotonic renewal and independently renewed signed draining history');
 async function blocked(name,{votes=0,attempt=0,deadline=chainTime+300,packet=null}={}){
  const factory=key(),submission=key(),task=key(),s={task:new PublicKey(task).toBytes(),attempt:0,state:STATE.REVEALED,validVotes:votes,invalidVotes:0},t={attempt,state:STATE.ACTIVE,verifyDeadline:BigInt(deadline)};
  contexts.set(factory,{reader:{factory:async()=>({verifiers:[new PublicKey(payer).toBytes()]}),account:async address=>address.toBase58()===submission?s:t}});
  const id='replay:'+name;await q.enqueue({id,kind:'replay',scope:factory,payload:{factory,submission,payer}});const job=await q.claim('replay',name,120,id);if(packet){await q.signed(job,id+':vote',{instructionHash:'a'.repeat(64),signature:packet,rawBase64:Buffer.from('immutable-fixture-packet').toString('base64'),lastValidBlockHeight:1000,feeLamports:5000});}
  await q.retry(job,{blocked:true,code:'POOL_TRANSACTION_UNKNOWN'});await q.pool.query('INSERT INTO factory_pool_v4.job_costs(job_id,background_count,estimate_ms,deadline) VALUES($1,2,90000,$2)',[id,deadline]);return {id,s,t};
 }
 const voted=await blocked('voted',{votes:1,packet:'voted-signature'});statuses.set('voted-signature',{confirmationStatus:'finalized',slot:1,err:null});
 const expired=await blocked('expired',{deadline:chainTime-1}),superseded=await blocked('superseded',{attempt:1}),unknown=await blocked('unknown',{packet:'unknown-signature'}),failed=await blocked('failed',{packet:'failed-signature'});statuses.set('failed-signature',{confirmationStatus:'finalized',slot:1,err:{InstructionError:[0,'Custom']}});
 const before=await replayCapacityV4(service);assert.equal(before.pendingJobs,4);const preview=await reconcilePoolBlockedV4(service,{dryRun:true});assert(preview.readOnly);assert.equal((await q.pool.query("SELECT count(*)::int AS n FROM factory_pool_v4.jobs WHERE state='done'")).rows[0].n,0);
 await reconcilePoolBlockedV4(service);for(const item of [voted,expired,superseded])assert.equal((await q.pool.query('SELECT state FROM factory_pool_v4.jobs WHERE id=$1',[item.id])).rows[0].state,'done');for(const item of [unknown,failed]){const row=(await q.pool.query('SELECT state,quarantined FROM factory_pool_v4.jobs WHERE id=$1',[item.id])).rows[0];assert.equal(row.state,'blocked');assert(row.quarantined);}assert.equal((await replayCapacityV4(service)).pendingJobs,0);assert.equal((await q.pool.query('SELECT raw_base64 FROM factory_pool_v4.transactions WHERE signature=$1',['unknown-signature'])).rows[0].raw_base64,Buffer.from('immutable-fixture-packet').toString('base64'));checks.push('Voted, expired and superseded blocked jobs resolve; failed and unknown immutable packets remain quarantined; actual weighted capacity recovers without new signatures');
 const paymentScope=catalogs[0].factory;let paid=false;contexts.set(paymentScope,{reader:{task:async()=>({state:STATE.SOLVED,get paid(){return paid;}}),factory:async()=>({})}});await q.enqueue({id:'payment:old',kind:'payment',scope:paymentScope,payload:{index:0}});const payment=await q.claim('payment','old-payment',120,'payment:old');await q.retry(payment,{blocked:true,code:'POOL_TRANSACTION_UNKNOWN'});await reconcilePoolBlockedV4(service);assert.equal((await q.pool.query("SELECT state FROM factory_pool_v4.jobs WHERE id='payment:old'")).rows[0].state,'blocked');paid=true;await reconcilePoolBlockedV4(service);assert.equal((await q.pool.query("SELECT state FROM factory_pool_v4.jobs WHERE id='payment:old'")).rows[0].state,'done');checks.push('An unpaid draining historical right remains recoverable; only its observed original payment effect resolves the job (chain fixture, no token transfer claimed)');
 console.log(JSON.stringify({passed:true,checks,postgresql:true,historicalCatalogs:132,chainFixtures:true,packetFixtures:true,publicChainTransactions:0,newSignatures:0}));
}finally{await q.pool.end();}
