import assert from 'node:assert/strict';
import {FactoryPoolServiceV4} from '../tools/factory_pool_service_v4.mjs';
import {FactoryPoolCalibrationV4} from '../tools/factory_pool_calibration_v4.mjs';

const config={deployment:{cluster:'devnet'},replayConcurrency:1,maxTransactionsPerVerifier:1,serializeCalibrationWithReplay:true};
const service=new FactoryPoolServiceV4({config,signers:[{},{}]});
let release;
const order=[];
const replay=service.nativeWork(async()=>{order.push('replay-start');await new Promise(ok=>release=ok);order.push('replay-finish');});
await new Promise(setImmediate);
const calibration=service.nativeWork(async()=>{order.push('calibration-start');throw new Error('retained-calibration-fault');});
const rejected=assert.rejects(calibration,/retained-calibration-fault/);
const successor=service.nativeWork(async()=>order.push('successor'));
await new Promise(setImmediate);
assert.deepEqual(order,['replay-start']);
release();
await Promise.all([replay,rejected,successor]);
assert.deepEqual(order,['replay-start','replay-finish','calibration-start','successor']);
assert.throws(()=>new FactoryPoolServiceV4({config:{...config,replayConcurrency:2},signers:[{},{}]}),/POOL_SHARED_NATIVE_LANE/);
config.serializeCalibrationWithReplay=false;
let finish;
const held=service.nativeWork(async()=>new Promise(ok=>finish=ok));
let parallel=false;
await service.nativeWork(async()=>parallel=true);
assert.equal(parallel,true);
finish();await held;
service.stopped=true;config.serializeCalibrationWithReplay=true;
await assert.rejects(service.nativeWork(async()=>assert.fail('Stopped service admitted native work')),/POOL_STOPPED/);
const calibrationQueue={pool:{query:async()=>({rows:[{total:'3200'}]})},enqueue:async()=>assert.fail('Fully allocated rewards started another calibration')};
const budgeted=new FactoryPoolCalibrationV4({queue:calibrationQueue,supply:{trust:{poolId:'fixture'},authorization:{evidenceHash:'e'.repeat(64),rewardAtoms:'3200'}},policy:{groups:16,deadlineSeconds:86400,toolSha256:'f'.repeat(64),evidenceHash:'e'.repeat(64),rules:{rewardAtoms:'200'}}});
await budgeted.schedule(16);assert.equal(budgeted.supplyStatus.code,'POOL_REWARD_AUTHORIZATION_EXHAUSTED');
console.log(JSON.stringify({passed:true,checks:['Calibration and full replay share one native lane on a small host','A failed calibration releases capacity without losing the queued successor','Explicit parallel configuration remains available','Stopped services reject queued native work','Fully allocated rewards stop future calibration without affecting funded task replay'],chainWrites:0}));

// Full, paused or expired ACTIVE catalogs still consume the active safety
// ceiling. Expiring an existing slot does not allocate a new active factory.
{
 const {FactoryPoolKeeperV4}=await import('../tools/factory_pool_keeper_v4.mjs');const jobs=[];
 const keeper=new FactoryPoolKeeperV4({config:{openTaskPolicy:{minimum:1,target:2,maximum:4}},signers:[{publicKey:{toBase58:()=> 'fixture-payer'}}],queue:{enqueue:async job=>jobs.push(job)}});
 const catalog={deployment:{factory:'fixture-factory'}},scheduled={state:1,paused:false,activeIndex:0xffffffff,nextIndex:0,count:1,deadline:1000n};
 assert.equal(await keeper.schedule(catalog,scheduled,null,100,{demand:1,open:0,active:4}),false);assert.equal(jobs.length,0);
 const expired={state:1,index:0,attempt:0,queue:[],revealDeadline:50n,verifyDeadline:60n};
 assert(await keeper.schedule(catalog,{...scheduled,activeIndex:0,nextIndex:1},expired,100,{demand:1,open:0,active:4}));assert.equal(jobs[0].payload.operation,'expire');
}
console.log('Active factory ceiling includes nonclaimable work; safe expiry can reuse an existing slot.');
