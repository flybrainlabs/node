// One bounded dispatcher consumes the existing authority outbox. It never
// invents scientific tasks, renews a grant, funds a stage or watches chain blocks.
import {DatabaseSync} from 'node:sqlite';
import {readFile,mkdir,chmod} from 'node:fs/promises';
import {dirname} from 'node:path';
import {id,canonical,validateGoal} from '../web/target-protocol-v2.mjs';
import {createHash,randomUUID} from 'node:crypto';
import {keyFile,request,verified,api} from './target_dev_identity.mjs';

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const fields=['graphRoot','modelRoot','parameterProfileHash','inputDomainHash','stimulusSetRoot','responseSetRoot','offTargetSetRoot','windows','evaluatorVersion','maxStimulusCost','steps','timeStepUs'];
export const scientificTask=goal=>id('science-task-v1',Object.fromEntries(fields.map(k=>[k,goal[k]])));
const failure=code=>Object.assign(new Error(code),{code});
export const defaults=Object.freeze({queueTarget:5,lowWater:2,maxVerificationQueue:2,minReadyVerifiers:2,minArchiveReserveBytes:268435456,minDiskReserveBytes:2147483648,recheckSeconds:60});

// A wakeup has no elapsed-time gate. Coalesce bursts while retaining one
// follow-up if new committed state arrives during an asynchronous check.
export function createSupplyWakeup(check,isStopped=()=>false){
  let running=null,requested=false;
  return ()=>{
    if(isStopped())return running||Promise.resolve();
    requested=true;
    if(!running)running=Promise.resolve().then(async()=>{
      try{while(requested&&!isStopped()){requested=false;await check();}}
      finally{running=null;}
    });
    return running;
  };
}

export function validatePolicy(policy){
  const p={...defaults,...policy};
  if(!Number.isInteger(p.queueTarget)||p.queueTarget<1||p.queueTarget>5||!Number.isInteger(p.lowWater)||p.lowWater<1||p.lowWater>=p.queueTarget||!Number.isInteger(p.maxVerificationQueue)||p.maxVerificationQueue<1||p.maxVerificationQueue>4||!Number.isInteger(p.minReadyVerifiers)||p.minReadyVerifiers!==2||p.recheckSeconds<30||p.recheckSeconds>300||!Number.isInteger(p.recheckSeconds)||![p.minArchiveReserveBytes,p.minDiskReserveBytes].every(n=>Number.isSafeInteger(n)&&n>=268435456))throw failure('SUPPLY_POLICY_BOUNDS');
  return p;
}

export async function validateCatalog(c,network){
  if(c.schema!=='flybrain-continuous-task-catalog-v1'||c.networkId!==network.networkId||c.authorityId!==network.authorityId||c.campaignId!==network.campaignId||typeof c.source!=='string'||!c.source||c.source.length>1024||!Array.isArray(c.items)||c.items.length<1||c.items.length>128||!/^([1-9][0-9]{0,19})$/.test(c.budgetAtoms)||!c.stage)throw failure('SUPPLY_CATALOG_IDENTITY');
  const goals=new Set(),science=new Set();let budget=0n;
  const items=[];
  for(const item of c.items){
    const g=item.goal,cal=item.calibration;await validateGoal(g);
    const definition={...g};delete definition.calibrationHash;
    if(g.neuronCount!==165122||g.graphRoot!=='6c42f6ff8e2198aca17a765acae0475b490abb0169d615e32b71c976f563deb4'||cal?.schema!=='flypow-target-calibration-v2'||cal.activationAllowed!==true||hash(canonical(cal))!==g.calibrationHash||cal.scientificDefinitionHash!==await id('calibration-science',definition)||!cal.levels?.some(l=>l.enabled&&l.challengeEffective&&l.sampleCount>=16&&l.heldOutCount>=8&&l.successes>0&&l.heldOutSuccesses>0)||!/^([1-9][0-9]{0,19})$/.test(item.rewardAtoms)||!/^[a-f0-9]{64}$/.test(item.economicTaskId))throw failure('SUPPLY_CALIBRATION_OR_BUDGET');
    const goalId=await id('goal-id',g),scientificTaskId=await scientificTask(g);
    if(goals.has(goalId)||science.has(scientificTaskId))throw failure('SUPPLY_DUPLICATE_SCIENCE');
    goals.add(goalId);science.add(scientificTaskId);budget+=BigInt(item.rewardAtoms);
    items.push({...item,goalId,scientificTaskId});
  }
  if(budget!==BigInt(c.budgetAtoms)||budget>0xffffffffffffffffn||new Set(c.items.map(i=>i.economicTaskId)).size!==c.items.length)throw failure('SUPPLY_FINITE_BUDGET');
  return items;
}

export function capacity(snapshot,readiness,stats,policy){
  const p=validatePolicy(policy),s=snapshot.supply;
  if(!s||!Number.isSafeInteger(s.pendingGoals)||s.pendingGoals<0||!Number.isSafeInteger(s.remainingUnopenedGoals))throw failure('SUPPLY_SNAPSHOT_INVALID');
  if(Math.max(0,s.remainingUnopenedGoals-(s.deferredGoals||0))>=p.lowWater)return {slots:0,reason:'queue-sufficient'};
  if(!Number.isSafeInteger(stats.verificationQueue)||stats.verificationQueue>=p.maxVerificationQueue)return {slots:0,reason:'verification-backpressure'};
  if(!Array.isArray(readiness.verifiers)||readiness.verifiers.filter(v=>v.connected&&v.modelReadyReported).length<p.minReadyVerifiers)return {slots:0,reason:'verifier-unavailable'};
  const a=readiness.archiveSpace;
  if(!a||![a.configuredCapBytes,a.reservedBytes,a.freeFilesystemBytes].every(Number.isSafeInteger))return {slots:0,reason:'archive-observation-unavailable'};
  // Reserve room for one full candidate per already announced goal as well as
  // the descriptors being added; existing upload reservations remain charged.
  const queuedBytes=s.pendingGoals*(snapshot.round?.goal?.maxCandidateBytes||268435456);
  const availableBytes=Math.min(a.configuredCapBytes-a.reservedBytes-p.minArchiveReserveBytes-queuedBytes,a.freeFilesystemBytes-p.minDiskReserveBytes-queuedBytes);
  if(availableBytes<=0)return {slots:0,reason:'archive-backpressure'};
  return {slots:Math.max(0,p.queueTarget-s.pendingGoals),availableBytes,reason:'ready'};
}

export class TaskSupplyDispatcher{
  constructor({db,network,policy={},signRequest,readState,publish,checkFunding,existingTasks,recoverReceipt=async()=>null,clock=()=>Math.floor(Date.now()/1000)}){
    Object.assign(this,{db,network,signRequest,readState,publish,checkFunding,existingTasks,recoverReceipt,clock});this.policy=validatePolicy(policy);this.owner=randomUUID();
    db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=10000;
      CREATE TABLE IF NOT EXISTS supply_catalogs(hash TEXT PRIMARY KEY,descriptor TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS supply_items(position INTEGER PRIMARY KEY AUTOINCREMENT,goal_id TEXT NOT NULL UNIQUE,science_id TEXT NOT NULL UNIQUE,catalog_hash TEXT NOT NULL,item TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'reserved',batch TEXT);
      CREATE TABLE IF NOT EXISTS supply_batches(id TEXT PRIMARY KEY,request TEXT NOT NULL,plan_hash TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'prepared',receipt TEXT);
      CREATE TABLE IF NOT EXISTS supply_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS supply_lease(id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,expires INTEGER NOT NULL);
      INSERT OR IGNORE INTO supply_lease VALUES(1,'',0);`);
  }
  transaction(fn){this.db.exec('BEGIN IMMEDIATE');try{const result=fn();this.db.exec('COMMIT');return result;}catch(e){this.db.exec('ROLLBACK');throw e;}}
  meta(key,value){if(value!==undefined)this.db.prepare('INSERT INTO supply_meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,String(value));return this.db.prepare('SELECT value FROM supply_meta WHERE key=?').get(key)?.value;}
  get reserved(){return this.db.prepare("SELECT COUNT(*) AS n FROM supply_items WHERE state='reserved'").get().n;}
  status(reason){this.meta('status',reason);this.meta('checkedAt',this.clock());return {reason,reservedGoals:this.reserved,lastPublishedAt:Number(this.meta('publishedAt')||0)};}
  async importCatalog(c){
    const items=await validateCatalog(c,this.network),catalogHash=await id('continuous-task-catalog',c);
    if(this.db.prepare('SELECT 1 FROM supply_catalogs WHERE hash=?').get(catalogHash))return;
    const known=await this.existingTasks();
    this.transaction(()=>{
      if(this.db.prepare('SELECT COUNT(*) AS n FROM supply_items').get().n+items.length>4096)throw failure('SUPPLY_RESERVE_LIMIT');
      this.db.prepare('INSERT INTO supply_catalogs VALUES(?,?)').run(catalogHash,JSON.stringify(c));
      for(const item of items){
        const old=this.db.prepare('SELECT * FROM supply_items WHERE goal_id=? OR science_id=?').get(item.goalId,item.scientificTaskId);
        if(old)throw failure('SUPPLY_CATALOG_OVERLAP');
        // Already registered/solved scientific work is historical, never supply.
        this.db.prepare('INSERT INTO supply_items(goal_id,science_id,catalog_hash,item,state) VALUES(?,?,?,?,?)').run(item.goalId,item.scientificTaskId,catalogHash,JSON.stringify(item),known.has(item.scientificTaskId)?'historical':'reserved');
      }
    });
  }
  async event(e){
    await verified(this.network.authorityId,'protocol-event',e);
    if(e.networkId!==this.network.networkId||e.authorityId!==this.network.authorityId||!Number.isSafeInteger(e.eventSequence)||e.eventSequence<1)throw failure('SUPPLY_EVENT_IDENTITY');
    const cursor=Number(this.meta('eventCursor')||0);
    if(e.eventSequence<=cursor)return false;
    if(e.eventSequence!==cursor+1)throw failure('SUPPLY_EVENT_GAP');
    this.meta('eventCursor',e.eventSequence);
    return ['ROUND_FINALIZED','ROUND_EXPIRED','FUTURE_PLAN_APPENDED'].includes(e.kind);
  }
  async tick(){
    if(this.busy)return this.status('dispatcher-busy');this.busy=true;
    const acquired=this.db.prepare('UPDATE supply_lease SET owner=?,expires=? WHERE id=1 AND (expires<=? OR owner=?)').run(this.owner,this.clock()+120,this.clock(),this.owner).changes;
    try{
      if(!acquired)return this.status('dispatcher-leased');
      const pending=this.db.prepare("SELECT * FROM supply_batches WHERE state='prepared' ORDER BY rowid LIMIT 1").get();
      if(!pending&&!this.reserved)return this.status('waiting-approved-tasks');
      if(pending){const recovered=await this.recoverReceipt(JSON.parse(pending.request));if(recovered){await this.issued(pending,recovered);return this.status('published');}}
      const {snapshot,readiness,stats}=await this.readState();
      for(const [domain,v]of [['authority-snapshot',snapshot],['authority-readiness',readiness],['network-stats',stats]]){
        await verified(this.network.authorityId,domain,v);
        if(v.networkId!==this.network.networkId||v.authorityId!==this.network.authorityId||v.campaignId!==this.network.campaignId)throw failure('SUPPLY_AUTHORITY_IDENTITY');
      }
      let batch=pending;
      if(batch){
        // An uncertain POST is replayed verbatim. A different admin revision
        // cannot be rebased silently into a second issue of these same tasks.
        const req=JSON.parse(batch.request);
        if(snapshot.supply.planHash!==batch.plan_hash&&snapshot.supply.planHash!==req.payload.plan.previousPlanHash) return this.status('publication-conflict');
      }else{
        const room=capacity(snapshot,readiness,stats,this.policy);if(!room.slots)return this.status(room.reason);
        const known=await this.existingTasks();let bytes=0;const picked=[];
        for(const row of this.db.prepare("SELECT * FROM supply_items WHERE state='reserved' ORDER BY position LIMIT 128").all()){
          if(known.has(row.science_id)){this.db.prepare("UPDATE supply_items SET state='historical' WHERE goal_id=?").run(row.goal_id);continue;}
          const item=JSON.parse(row.item);
          if(picked.length>=room.slots||bytes+item.goal.maxCandidateBytes>room.availableBytes)break;
          picked.push({row,item});bytes+=item.goal.maxCandidateBytes;
        }
        if(!picked.length)return this.status(this.reserved?'archive-backpressure':'waiting-approved-tasks');
        const catalogIds=[...new Set(picked.map(x=>x.row.catalog_hash))],catalogs=catalogIds.map(h=>JSON.parse(this.db.prepare('SELECT descriptor FROM supply_catalogs WHERE hash=?').get(h).descriptor));
        if(!await this.checkFunding(picked.map(x=>x.item),catalogs))return this.status('waiting-finalized-budget');
        const plan={schema:'flypow-target-plan-revision-v1',revision:snapshot.supply.planRevision+1,previousPlanHash:snapshot.supply.planHash||null,source:'bounded-continuous-supply-v1:'+catalogIds.join(','),append:picked.map(x=>({goal:x.item.goal,calibration:x.item.calibration}))};
        const planHash=await id('target-plan-revision',plan),req=await this.signRequest(plan,planHash);
        this.transaction(()=>{
          const held=this.db.prepare('SELECT owner,expires FROM supply_lease WHERE id=1').get();if(held.owner!==this.owner||held.expires<=this.clock())throw failure('SUPPLY_LEASE_LOST');
          this.db.prepare('INSERT INTO supply_batches(id,request,plan_hash) VALUES(?,?,?)').run(req.requestId,JSON.stringify(req),planHash);
          for(const {row}of picked)this.db.prepare("UPDATE supply_items SET state='prepared',batch=? WHERE goal_id=? AND state='reserved'").run(req.requestId,row.goal_id);
        });
        batch={id:req.requestId,request:JSON.stringify(req),plan_hash:planHash};
      }
      const req=JSON.parse(batch.request);
      // Recheck capacity and finalized funding before an uncommitted retry.
      // A receipt replay after successful publication never adds another goal.
      if(snapshot.supply.planHash!==batch.plan_hash){
        const room=capacity(snapshot,readiness,stats,this.policy),items=this.db.prepare('SELECT item,catalog_hash FROM supply_items WHERE batch=?').all(batch.id),catalogs=[...new Set(items.map(i=>i.catalog_hash))].map(h=>JSON.parse(this.db.prepare('SELECT descriptor FROM supply_catalogs WHERE hash=?').get(h).descriptor));
        if(room.slots<items.length||items.reduce((n,i)=>n+JSON.parse(i.item).goal.maxCandidateBytes,0)>room.availableBytes)return this.status(room.reason==='ready'?'archive-backpressure':room.reason);
        if(!await this.checkFunding(items.map(i=>JSON.parse(i.item)),catalogs))return this.status('waiting-finalized-budget');
      }
      const receipt=await this.publish(req);await this.issued(batch,receipt);
      return this.status('published');
    }finally{if(acquired)this.db.prepare("UPDATE supply_lease SET owner='',expires=0 WHERE id=1 AND owner=?").run(this.owner);this.busy=false;}
  }
  async issued(batch,receipt){
    const req=JSON.parse(batch.request);await verified(this.network.authorityId,'plan-receipt',receipt);
    if(receipt.planHash!==batch.plan_hash||receipt.appendedGoals!==req.payload.plan.append.length||receipt.revision!==req.payload.plan.revision||receipt.onlyUnopenedGoals!==true)throw failure('SUPPLY_RECEIPT_MISMATCH');
    this.transaction(()=>{this.db.prepare("UPDATE supply_batches SET state='issued',receipt=? WHERE id=?").run(JSON.stringify(receipt),batch.id);this.db.prepare("UPDATE supply_items SET state='issued' WHERE batch=?").run(batch.id);this.meta('publishedAt',this.clock());});
  }
}

// Share the wallet service's validated finalized reads and its existing model
// admission. Only nonempty, explicitly approved catalogs can reach chain().
export async function runTaskSupply(service,configPath,{signal}={}){
  const config=JSON.parse(await readFile(configPath,'utf8'));
  if(config.schema!=='flybrain-continuous-task-supply-config-v1'||config.enabled!==true||!/^http:\/\/127\.0\.0\.1:\d+$/.test(config.authorityBase)||config.authorityId!==service.config.authorityId||config.networkId===undefined||config.campaignId===undefined)throw failure('SUPPLY_CONFIGURATION');
  const authority=JSON.parse(await readFile(config.authorityConfigPath,'utf8'));
  if(authority.networkId!==config.networkId||authority.campaignId!==config.campaignId)throw failure('SUPPLY_CONFIGURATION_IDENTITY');
  await mkdir(dirname(config.stateDatabase),{recursive:true,mode:0o700});const db=new DatabaseSync(config.stateDatabase);await chmod(config.stateDatabase,0o600);
  const network={networkId:config.networkId,authorityId:config.authorityId,campaignId:config.campaignId};let admin,lastCatalogHash=null;
  const existingTasks=async()=>new Set(await Promise.all(service.db.prepare('SELECT spec_json FROM goal_specs').all().map(r=>scientificTask(JSON.parse(r.spec_json)))));
  const dispatcher=new TaskSupplyDispatcher({db,network,policy:config.policy,existingTasks,
    signRequest:async(plan,h)=>{await readFile(config.adminKeyPath);admin??=await keyFile(config.adminKeyPath);if(!authority.adminKeys.includes(admin.publicKey))throw failure('SUPPLY_ADMIN_IDENTITY');return request(admin,'publish-future-plan','',{plan},'supply-'+h);},
    readState:async()=>{const [snapshot,readiness,stats]=await Promise.all(['rounds/current','readiness','network-stats'].map(async(p)=> (await api(config.authorityBase,p)).json()));return {snapshot,readiness,stats};},
    publish:async req=>(await api(config.authorityBase,'admin/future-plan',req)).json(),
    recoverReceipt:async req=>{const row=service.db.prepare('SELECT request_hash,response_json FROM request_receipts WHERE miner_id=? AND request_id=?').get(req.publicKey,req.requestId);if(!row)return null;const {signature,...unsigned}=req;if(row.request_hash!==await id('request',unsigned))throw failure('SUPPLY_REQUEST_CONFLICT');return JSON.parse(row.response_json);},
    checkFunding:async(items,catalogs)=>{
      if(catalogs.some(c=>c.stage!==service.config.stage||c.budgetAtoms!==service.config.budgetAtoms))return false;
      if(items.some(i=>!service.config.units.some(u=>u.goalId===i.goalId&&u.economicTaskId===i.economicTaskId&&u.rewardAtoms===i.rewardAtoms)))return false;
      if(items.some(i=>!service.db.prepare('SELECT 1 FROM mining_v3_funded_goals WHERE goal_id=? AND enabled=1 AND stage=? AND reward_atoms=?').get(i.goalId,service.config.stage,i.rewardAtoms)))return false;
      const state=service.chainSnapshot&&service.clock()-service.chainSnapshot.asOf<15&&service.chainSnapshot.units?service.chainSnapshot:await service.chain();
      if(state.stage.closed||state.stage.deadline<=BigInt(service.clock()+authority.searchSeconds+authority.revealSeconds+authority.verificationSeconds))return false;
      return items.every(i=>state.units?.some(u=>u.goalId===i.goalId&&!u.paid&&!u.accepted&&!u.released));
    }});
  const load=async()=>{
    let bytes;try{bytes=await readFile(config.catalogPath);}catch(e){if(e.code==='ENOENT')return;throw e;}
    if(bytes.length>16*1024*1024)throw failure('SUPPLY_CATALOG_SIZE');const digest=hash(bytes);if(digest===lastCatalogHash)return;
    const approved=JSON.parse(bytes);if(!authority.adminKeys.includes(approved.adminKey))throw failure('SUPPLY_CATALOG_ADMIN');
    await verified(approved.adminKey,'continuous-task-catalog',approved.catalog);const {signature,...catalog}=approved.catalog;
    await dispatcher.importCatalog(catalog);lastCatalogHash=digest;
  };
  let timer,stopped=false;
  const evaluate=createSupplyWakeup(async()=>{try{await load();const result=await dispatcher.tick();console.log(JSON.stringify({kind:'continuous-task-supply',...result}));}catch(e){dispatcher.status('recovery-required');console.error(JSON.stringify({kind:'continuous-task-supply-retry',code:e.code||'INFRASTRUCTURE_RETRY',errorClass:e.name}));}},()=>stopped||signal?.aborted);
  // Existing committed events provide the wakeup; fallback is shared once per
  // minute. No model preparation or Solana call runs while the reserve is empty.
  const loop=async()=>{await evaluate();if(!stopped)timer=setTimeout(loop,dispatcher.policy.recheckSeconds*1000+Math.random()*5000);};
  const streamAbort=new AbortController();
  const stream=async()=>{
    while(!stopped){try{
      for(let page=0;page<4;page++){
        const events=await (await api(config.authorityBase,'events?after='+Number(dispatcher.meta('eventCursor')||0))).json();let wake=false;
        try{for(const e of events.events)if(await dispatcher.event(e))wake=true;}
        finally{if(wake)await evaluate();}
        if(events.events.length<128)break;if(page===3)throw failure('SUPPLY_RECONCILE_CONTINUES');
      }
      const response=await fetch(config.authorityBase+'/api/target-mining/v2/events/stream?after='+Number(dispatcher.meta('eventCursor')||0),{signal:streamAbort.signal});if(!response.ok)throw failure('SUPPLY_STREAM_UNAVAILABLE');
      let buffer='';const decoder=new TextDecoder();
      for await(const chunk of response.body){buffer+=decoder.decode(chunk,{stream:true}).replace(/\r\n/g,'\n');if(buffer.length>262144)throw failure('SUPPLY_STREAM_BOUND');let end,wake=false;
        try{while((end=buffer.indexOf('\n\n'))>=0){const block=buffer.slice(0,end);buffer=buffer.slice(end+2);const data=block.split('\n').filter(l=>l.startsWith('data:')).map(l=>l.slice(5).trimStart()).join('\n');if(!data)continue;
          if(await dispatcher.event(JSON.parse(data)))wake=true;
        }}finally{if(wake)await evaluate();}
      }
    }catch(e){if(stopped)break;dispatcher.meta('streamState','reconnecting');}
    if(!stopped)await new Promise(resolve=>{const t=setTimeout(resolve,30000+Math.random()*10000);streamAbort.signal.addEventListener('abort',()=>{clearTimeout(t);resolve();},{once:true});});}
  };
  const close=()=>{stopped=true;clearTimeout(timer);streamAbort.abort();};signal?.addEventListener('abort',close,{once:true});
  try{await Promise.all([loop(),stream()]);}finally{close();await evaluate();db.close();}
}
