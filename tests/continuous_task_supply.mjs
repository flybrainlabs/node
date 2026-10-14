// Isolated scheduler fault fixtures. No chain writes or production task issue.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,sign} from 'node:crypto';
import {TaskSupplyDispatcher,capacity,validateCatalog,scientificTask} from '../tools/continuous_task_supply.mjs';
import {id,unhex} from '../web/target-protocol-v2.mjs';
const pair=generateKeyPairSync('ed25519'),authorityId=pair.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex');
const signed=async(domain,v)=>({...v,signature:sign(null,unhex(await id(domain,v)),pair.privateKey).toString('hex')});
const network={networkId:'continuous-supply-fixture',authorityId,campaignId:'isolated-finite-plan'};
const items=[];for(let n=1;n<=8;n++){const base='web/data/target-mining-v2/product-group-'+n+'-20261011/';items.push({goal:JSON.parse(await readFile(base+'goal.json')),calibration:JSON.parse(await readFile(base+'calibration.json')),economicTaskId:n.toString(16).padStart(64,'0'),rewardAtoms:'100000000'});}
const catalog={schema:'flybrain-continuous-task-catalog-v1',...network,source:'existing calibration in isolated fixtures only',stage:'finite-fixture-stage',budgetAtoms:'800000000',items};
const valid=await validateCatalog(catalog,network);assert.equal(valid.length,8);assert.notEqual(valid[0].scientificTaskId,valid[1].scientificTaskId);
await assert.rejects(validateCatalog({...catalog,budgetAtoms:'900000000'},network),/SUPPLY_FINITE_BUDGET/);
await assert.rejects(validateCatalog({...catalog,items:[items[0],items[0]]},network),/SUPPLY_DUPLICATE_SCIENCE/);
await assert.rejects(validateCatalog({...catalog,items:[{...items[0],calibration:{...items[0].calibration,scientificDefinitionHash:'0'.repeat(64)}}]},network),/SUPPLY_CALIBRATION_OR_BUDGET/);
assert.equal(await scientificTask({...items[0].goal,description:'renamed'}),valid[0].scientificTaskId);
const dir=await mkdtemp(join(tmpdir(),'flybrain-supply-')),file=join(dir,'state.sqlite');let db=new DatabaseSync(file),clock=200000,published=0,reads=0,funds=0,available=false,loseResponse=true;
const source={snapshot:{...network,round:null,supply:{pendingGoals:0,remainingUnopenedGoals:0,planRevision:0,planHash:null}},readiness:{...network,verifiers:[{connected:true,modelReadyReported:true},{connected:true,modelReadyReported:true}],archiveSpace:{configuredCapBytes:8*1024**3,reservedBytes:0,freeFilesystemBytes:10*1024**3}},stats:{...network,verificationQueue:0}};
const receipts=new Map(),known=new Set();
const adapters={network,clock:()=>clock,existingTasks:async()=>known,readState:async()=>{reads++;return {snapshot:await signed('authority-snapshot',source.snapshot),readiness:await signed('authority-readiness',source.readiness),stats:await signed('network-stats',source.stats)};},checkFunding:async()=>{funds++;return available;},signRequest:async(plan,h)=>{const v={publicKey:authorityId,action:'publish-future-plan',requestId:'supply-'+h,roundId:'',payload:{plan}};return signed('authority-action',v);},recoverReceipt:async r=>receipts.get(r.requestId)||null,publish:async req=>{
 if(receipts.has(req.requestId))return receipts.get(req.requestId);published++;
 const plan=req.payload.plan,h=await id('target-plan-revision',plan);assert.equal(plan.previousPlanHash,source.snapshot.supply.planHash);
 source.snapshot.supply={pendingGoals:plan.append.length,remainingUnopenedGoals:plan.append.length-1,planRevision:plan.revision,planHash:h};
 for(const i of plan.append)known.add(await scientificTask(i.goal));
 const receipt=await signed('plan-receipt',{planHash:h,revision:plan.revision,appendedGoals:plan.append.length,onlyUnopenedGoals:true,publishedAt:clock});receipts.set(req.requestId,receipt);
 if(loseResponse)throw new Error('Simulated lost response after durable authority commit');return receipt;
}};
try{
 let dispatcher=new TaskSupplyDispatcher({db,...adapters});assert.equal((await dispatcher.tick()).reason,'waiting-approved-tasks');assert.equal(reads,0);assert.equal(funds,0);
 await dispatcher.importCatalog(catalog);await dispatcher.importCatalog(catalog);assert.equal(dispatcher.reserved,8);
 source.readiness.verifiers[0].connected=false;assert.equal((await dispatcher.tick()).reason,'verifier-unavailable');assert.equal(funds,0);source.readiness.verifiers[0].connected=true;
 source.stats.verificationQueue=2;assert.equal((await dispatcher.tick()).reason,'verification-backpressure');assert.equal(funds,0);source.stats.verificationQueue=0;
 source.readiness.archiveSpace.reservedBytes=8*1024**3;assert.equal((await dispatcher.tick()).reason,'archive-backpressure');source.readiness.archiveSpace.reservedBytes=0;
 assert.equal((await dispatcher.tick()).reason,'waiting-finalized-budget');assert.equal(published,0);
 available=true;await assert.rejects(dispatcher.tick(),/lost response/);assert.equal(published,1);assert.equal(dispatcher.reserved,3);assert.equal(source.snapshot.supply.pendingGoals,5);
 db.close();db=new DatabaseSync(file);dispatcher=new TaskSupplyDispatcher({db,...adapters});assert.equal((await dispatcher.tick()).reason,'published');assert.equal(published,1);assert.equal(dispatcher.reserved,3);
 assert.equal((await dispatcher.tick()).reason,'queue-sufficient');assert.equal(published,1);
 const event={networkId:network.networkId,authorityId,eventSequence:1,kind:'ROUND_FINALIZED',roundId:'0'.repeat(64),payload:{},createdAt:clock},e=await signed('protocol-event',event);assert.equal(await dispatcher.event(e),true);assert.equal(await dispatcher.event(e),false);await assert.rejects(dispatcher.event({...e,signature:'0'.repeat(128)}));await assert.rejects(dispatcher.event(await signed('protocol-event',{...event,eventSequence:3})),/SUPPLY_EVENT_GAP/);
 db.prepare('UPDATE supply_lease SET owner=?,expires=? WHERE id=1').run('different-process',clock+100);assert.equal((await dispatcher.tick()).reason,'dispatcher-leased');db.prepare("UPDATE supply_lease SET owner='',expires=0 WHERE id=1").run();
 source.snapshot.supply.pendingGoals=0;source.snapshot.supply.remainingUnopenedGoals=0;loseResponse=false;assert.equal((await dispatcher.tick()).reason,'published');assert.equal(published,2);assert.equal(dispatcher.reserved,0);const calls=reads;assert.equal((await dispatcher.tick()).reason,'waiting-approved-tasks');assert.equal(reads,calls);
 assert.equal(source.snapshot.supply.pendingGoals,3);assert.equal(db.prepare("SELECT COUNT(*) AS n FROM supply_items WHERE state='issued'").get().n,8);
 const bad=structuredClone(source);bad.snapshot.supply.remainingUnopenedGoals=0;bad.stats.verificationQueue=null;assert.equal(capacity(bad.snapshot,bad.readiness,bad.stats,{}).reason,'verification-backpressure');
 // An unrelated admin publication after an ambiguous POST is recovered from
 // the original signed receipt, without rebasing or creating another batch.
 const recovered=db.prepare('SELECT * FROM supply_batches ORDER BY rowid LIMIT 1').get();db.prepare("UPDATE supply_batches SET state='prepared' WHERE id=?").run(recovered.id);source.snapshot.supply.planHash='f'.repeat(64);assert.equal((await dispatcher.tick()).reason,'published');assert.equal(published,2);
 console.log(JSON.stringify({passed:true,checks:27,scope:'isolated finite scheduler and signed fault fixtures',productionMutations:0}));
}finally{db.close();await rm(dir,{recursive:true,force:true});}
