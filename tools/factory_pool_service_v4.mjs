#!/usr/bin/env node
// Opt-in parallel V4 service. Existing accounts and SQLite archives are retained;
// PostgreSQL owns work leases, replay decisions and financial transport receipts.
import {readFile,mkdir,realpath,statfs} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomUUID} from 'node:crypto';
import {Connection,Keypair,PublicKey} from '@solana/web3.js';
import {createAssociatedTokenAccountIdempotentInstruction,getAssociatedTokenAddressSync} from '@solana/spl-token';
import {FactoryPoolQueueV4,reserveTargetV4,poolReplenishmentV4} from './factory_pool_queue_v4.mjs';
import {FactoryPoolTransportV4} from './factory_pool_transport_v4.mjs';
import {FactoryPoolSupplyV4} from './factory_pool_supply_v4.mjs';
import {FactoryPoolCalibrationV4} from './factory_pool_calibration_v4.mjs';
import {FactoryGatewayV4,serveFactoryGatewayV4} from './factory_gateway_v4.mjs';
import {verifyFactorySubmission,LocalFactoryContentStore,voteInstructions} from './factory_verifier_v4.mjs';
import {readerForDeployment,factoryTaskRecoveryV4} from '../web/task-factory-client-v4.mjs';
import {verifyPoolCatalogV4} from '../web/factory-pool-v4.mjs';
import {decodeSubmission,decodeTask,STATE,NONE,hex,fromHex,voteMessage} from '../web/task-factory-v4-codec.mjs';
import {canonical,hash} from '../web/target-protocol-v2.mjs';
import {candidateId,validateInput} from '../web/target-protocol-v2.mjs';
import {makeRound} from '../web/task-factory-v4-science.mjs';
import {instruction,meta,TOKEN_PROGRAM_ID} from './task_factory_v4_client.mjs';
import {factoryRpcTransportV4} from './factory_rpc_transport_v4.mjs';
import {getModelReadiness} from './candidate_verifier_v2.mjs';
const fail=code=>Object.assign(new Error(code),{code});
const signerFile=async file=>{const bytes=await readFile(file);return bytes.length===32?Keypair.fromSeed(bytes):Keypair.fromSecretKey(Uint8Array.from(JSON.parse(bytes.toString())));};
export class FactoryPoolServiceV4 {
  constructor({config,queue,connection,signers,supply=null,calibration=null,verify=verifyFactorySubmission,gatewayFactory=null}){
    Object.assign(this,{config,queue,connection,signers,supply,calibration,verify,gatewayFactory});this.contexts=new Map();this.owner=randomUUID();this.stopped=false;this.scan=0;this.eventClients=new Set();this.eventCursor='0';
    if(config.deployment.cluster!=='devnet'||!Number.isInteger(config.replayConcurrency)||config.replayConcurrency<1||config.replayConcurrency>8||signers.length!==2||!Number.isInteger(config.maxTransactionsPerVerifier)||config.maxTransactionsPerVerifier<1||config.maxTransactionsPerVerifier>4096)throw fail('POOL_RUNTIME_BOUNDS');
    if(config.serializeCalibrationWithReplay&&config.replayConcurrency!==1)throw fail('POOL_SHARED_NATIVE_LANE');
  }
  async nativeWork(operation){
    if(!this.config.serializeCalibrationWithReplay)return operation();
    const previous=this.nativeWorkTail||Promise.resolve();let release;
    this.nativeWorkTail=new Promise(resolve=>release=resolve);
    await previous;
    try{if(this.stopped)throw fail('POOL_STOPPED');return await operation();}finally{release();}
  }
  async context(deployment){
    if(this.contexts.has(deployment.factory))return this.contexts.get(deployment.factory);
    const {reader,factory}=await verifyPoolCatalogV4(deployment,this.config.poolTrust,this.connection);
    for(const signer of this.signers)if(!factory.verifiers.some(v=>new PublicKey(v).equals(signer.publicKey)))throw fail('POOL_VERIFIER_IDENTITY');
    const gateway=await (this.gatewayFactory?this.gatewayFactory(deployment,reader):new FactoryGatewayV4({...this.config,deployment},{reader,onContent:()=>this.wake()}).initialize());
    const c={deployment,reader,gateway,paymentCursor:0};this.contexts.set(deployment.factory,c);return c;
  }
  async initialize(){
    this.root=await this.context(this.config.deployment);
    await mkdir(this.config.outputDir,{recursive:true,mode:0o700});
    if(this.verify===verifyFactorySubmission){const ready=await getModelReadiness(this.config.binary,this.config.modelDir),e=this.config.poolTrust.envelope;if(!ready.nativeBinaryReady||ready.graphRoot!==e.graphRoot||!ready.parameterProfileHashes.includes(e.parameterProfileHash)||!ready.evaluatorVersions.includes(e.evaluatorVersion))throw fail('POOL_COMPLETE_MODEL_NOT_READY');this.nativeReady=true;}
    return this;
  }
  async gateway(factory){return factory?this.contexts.get(factory)?.gateway:null;}
  async input(req,body){
    const c=this.contexts.get(body.factory);if(!c||!/^[-a-f0-9]{36}$/.test(body.sessionId||'')||!['claim','renew','release'].includes(body.action))throw fail('POOL_INPUT_SCOPE');
    const session=await c.gateway.authenticate(req);c.gateway.rate('inputs:'+session.wallet,120);const owner=session.wallet+':'+body.sessionId;
    if(body.action!=='claim'){
      if(!/^input:[a-f0-9]{64}:[a-f0-9]{64}$/.test(body.id||'')||!/^\d{1,19}$/.test(String(body.fence)))throw fail('POOL_INPUT_SCOPE');
      const job=(await this.queue.pool.query('SELECT * FROM factory_pool_v4.jobs WHERE id=$1',[body.id])).rows[0];if(!job||job.scope!==body.factory||job.lease_owner!==owner||job.fence!==String(body.fence))throw fail('POOL_INPUT_SCOPE');
      if(body.action==='renew')await this.queue.renew(job,120);else await this.queue.retry(job,{delaySeconds:5,code:'INPUT_RELEASED'});return {ok:true};
    }
    const backlog=(await this.queue.pool.query("SELECT count(*)::int AS n FROM factory_pool_v4.jobs WHERE kind='replay' AND state IN ('ready','leased','blocked') AND scope=ANY($1::text[])",[[...this.contexts.keys()]])).rows[0].n;
    if(backlog>=(this.config.maxPendingReplays||8))return {busy:true,reason:'verification-capacity'};
    if(!c.inputRound||Date.now()-c.inputRoundAt>5000){
      if(!c.inputSync)c.inputSync=(async()=>{const f=await c.reader.factory();if(f.activeIndex===NONE||f.paused)throw fail('POOL_INPUT_CLOSED');const t=await c.reader.task(f.activeIndex),spec=JSON.parse(new TextDecoder().decode(await new LocalFactoryContentStore(this.config.contentDir).get(hex(t.descriptor.content),1024*1024)));c.inputRound=await makeRound({program:c.deployment.programId,genesis:c.deployment.genesisHash,factoryAddress:c.deployment.factory,taskAddress:c.reader.a.task(c.deployment.factory,t.index).toBase58(),factory:f,task:t,spec});const slot=await this.connection.getSlot('finalized');c.inputChainTime=await this.connection.getBlockTime(slot);c.inputRoundAt=Date.now();})().finally(()=>c.inputSync=null);await c.inputSync;
    }
    const round=c.inputRound;if(round.roundId!==body.roundId||c.inputChainTime===null||c.inputChainTime+(Date.now()-c.inputRoundAt)/1000>=round.pre.claimDeadline)throw fail('POOL_INPUT_CLOSED');validateInput(round.goal,body.input);
    const candidate=await candidateId(round.roundId,body.input),id='input:'+round.roundId+':'+candidate,payload={factory:body.factory,roundId:round.roundId,candidateId:candidate,input:body.input};
    const old=await this.queue.enqueue({id,kind:'input',scope:body.factory,payload});let lease;
    if(old.state==='leased'&&old.lease_owner===owner&&new Date(old.lease_until).getTime()>Date.now()){await this.queue.renew(old,120);lease=old;}else lease=await this.queue.claim('input',owner,120,id);
    return lease?{lease:{id,sessionId:body.sessionId,fence:lease.fence}}:{busy:true};
  }
  async manifest(){const {rows:[row]}=await this.queue.pool.query('SELECT body FROM factory_pool_v4.manifests WHERE pool_id=$1 ORDER BY revision DESC LIMIT 1',[this.config.poolTrust.poolId]);if(!row||row.body.expiresAt<=Date.now()/1000)throw fail('POOL_MANIFEST_NOT_READY');return row.body;}
  async openEvents(req,res,url){
    if(this.eventClients.size>=1000)throw fail('POOL_EVENT_CAPACITY');
    const cursor=req.headers['last-event-id']||url.searchParams.get('after')||'0';if(!/^\d{1,19}$/.test(cursor))throw fail('POOL_EVENT_CURSOR');
    const rows=await this.queue.events(this.config.poolTrust.poolId,cursor,100);res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-store','X-Accel-Buffering':'no'});
    for(const row of rows)res.write(`id: ${row.sequence}\nevent: pool-change\ndata: {}\n\n`);
    res.write('retry: '+String(3000+Math.floor(Math.random()*5000))+'\n: verify the signed manifest and finalized accounts\n\n');this.eventClients.add(res);
    const timer=setTimeout(()=>res.end(),480000+Math.floor(Math.random()*240000));res.once('close',()=>{clearTimeout(timer);this.eventClients.delete(res);});
  }
  async notify(){
    const rows=await this.queue.events(this.config.poolTrust.poolId,this.eventCursor,500);
    for(const row of rows){for(const res of this.eventClients)if(!res.write(`id: ${row.sequence}\nevent: pool-change\ndata: {}\n\n`))res.destroy();this.eventCursor=row.sequence;}
    if(Date.now()-(this.heartbeatAt||0)>15000){this.heartbeatAt=Date.now();for(const res of this.eventClients)if(!res.write(': heartbeat\n\n'))res.destroy();}
  }
  async discover(){
    const rows=(await this.queue.pool.query("SELECT deployment FROM factory_pool_v4.catalogs WHERE pool_id=$1 AND state='registered' ORDER BY registered_at,id",[this.config.poolTrust.poolId])).rows;
    for(const {deployment}of rows)await this.context(deployment);
    const slot=await this.connection.getSlot('finalized'),now=await this.connection.getBlockTime(slot);
    const observations=this.config.capacityObservations,runway=observations?(observations.prepareP95Seconds+observations.registrationP95Seconds)*(observations.safetyFactor||2):0;
    let remaining=0,openCatalogs=0;for(const c of this.contexts.values()){
      const f=await c.reader.factory();
      remaining+=Math.max(0,f.count-f.nextIndex)+(f.activeIndex!==NONE?1:0);
      if(f.state===STATE.RUNNING&&!f.paused&&f.activeIndex===NONE&&f.nextIndex<f.count)openCatalogs++;
      if(f.activeIndex!==NONE&&!f.paused){
        const t=await c.reader.task(f.activeIndex);
        if(f.state===STATE.RUNNING&&Number.isSafeInteger(now)&&now+runway<Number(t.claimDeadline))openCatalogs++;
        const recovery=factoryTaskRecoveryV4(f,t,now);
        if(recovery?.kind==='finalize')await this.queue.enqueue({id:'finalize:'+c.reader.a.task(c.deployment.factory,t.index).toBase58()+':'+t.attempt,kind:'payment',scope:c.deployment.factory,payload:{operation:'finalize',factory:c.deployment.factory,index:t.index,attempt:t.attempt,submission:recovery.submission,payer:this.signers[0].publicKey.toBase58()},priority:20});
        for(const e of t.queue)if(e.state===STATE.REVEALED){
          const address=new PublicKey(e.submission).toBase58(),s=await c.reader.submission(address,c.reader.a.task(c.deployment.factory,t.index));
          for(const signer of this.signers){const index=f.verifiers.findIndex(v=>new PublicKey(v).equals(signer.publicKey));if((s.validVotes|s.invalidVotes)&1<<index)continue;const payer=signer.publicKey.toBase58();await this.queue.enqueue({id:'replay:'+address+':'+payer,kind:'replay',scope:c.deployment.factory,payload:{factory:c.deployment.factory,submission:address,payer},priority:10});}
        }
      }
      // Bounded historical scan; each payment retains its own immutable job.
      for(let n=0;n<Math.min(4,f.nextIndex);n++){
        const index=c.paymentCursor++%f.nextIndex;if(index===f.activeIndex)continue;const t=await c.reader.task(index);if(t.state!==STATE.SOLVED||t.paid)continue;
        await this.queue.enqueue({id:'payment:'+c.deployment.factory+':'+index,kind:'payment',scope:c.deployment.factory,payload:{factory:c.deployment.factory,index,payer:this.signers[0].publicKey.toBase58()}});
      }
    }
    const prepared=(await this.queue.pool.query("SELECT COALESCE(sum((deployment->>'taskCount')::int),0)::int AS n,count(*)::int AS catalogs FROM factory_pool_v4.catalogs WHERE pool_id=$1 AND state='reserved'",[this.config.poolTrust.poolId])).rows[0];
    if(this.calibration&&observations){const target=reserveTargetV4(observations),room=poolReplenishmentV4({remaining,preparedTasks:prepared.n,openCatalogs,preparedCatalogs:prepared.catalogs,target:target.target,minimumOpenCatalogs:this.config.minimumOpenCatalogs||2,groups:this.calibration.policy.groups,maximum:observations.maximum||4096});this.reserveStatus={...target,...room,withinCapacity:target.withinCapacity&&room.withinCapacity,remaining,preparedTasks:prepared.n,openCatalogs};if(target.withinCapacity&&room.withinCapacity&&room.shortage)await this.calibration.schedule(room.shortage);}
    if(this.supply){
      let needs=true;try{needs=(await this.manifest()).expiresAt<Date.now()/1000+300;}catch{}
      if(needs||rows.length!==this.publishedCatalogCount){await this.supply.manifest({anchor:this.config.deployment});this.publishedCatalogCount=rows.length;}
    }
    const {rows:[counts]}=await this.queue.pool.query("SELECT count(*) FILTER (WHERE kind='replay' AND state IN ('ready','leased'))::int AS pending,count(*) FILTER (WHERE state='blocked' AND NOT(kind='calibrate' AND result->>'code'='POOL_REWARD_AUTHORIZATION_EXHAUSTED'))::int AS blocked,count(*) FILTER (WHERE state='blocked' AND kind='calibrate' AND result->>'code'='POOL_REWARD_AUTHORIZATION_EXHAUSTED')::int AS rewardCapacityPaused FROM factory_pool_v4.jobs WHERE scope=ANY($1::text[])",[[...this.contexts.keys(),this.config.poolTrust.poolId]]);
    this.root.gateway.verifierStatus={status:counts.blocked?'reconciliation-required':counts.pending?'replay-queue-active':'waiting-for-revealed-submission',at:new Date().toISOString(),serialReplay:this.config.replayConcurrency===1,maxReplayProcesses:this.config.replayConcurrency,nativeModelChecked:!!this.nativeReady,trustedKeys:2,independentOperators:1,pending:counts.pending,blocked:counts.blocked,catalogs:this.contexts.size,remainingTasks:remaining,openCatalogs,reserve:this.reserveStatus||null,supply:this.calibration?.supplyStatus||(counts.rewardCapacityPaused?{code:'POOL_REWARD_AUTHORIZATION_EXHAUSTED'}:null)};
    await this.notify();
  }
  async replay(job){return this.nativeWork(()=>this.replayInternal(job));}
  async replayInternal(job){
    const c=this.contexts.get(job.payload.factory),signer=this.signers.find(s=>s.publicKey.toBase58()===job.payload.payer);if(!c||!signer)throw fail('POOL_REPLAY_SCOPE');
    const address=new PublicKey(job.payload.submission),reader=c.reader;
    const state=async()=>{const s=await reader.account(address,decodeSubmission),t=await reader.account(new PublicKey(s.task),decodeTask),f=await reader.factory(),index=f.verifiers.findIndex(v=>new PublicKey(v).equals(signer.publicKey));if(index<0||!reader.a.task(reader.expected.factoryAddress,t.index).equals(new PublicKey(s.task))||!new PublicKey(t.factory).equals(reader.expected.factoryAddress))throw fail('POOL_REPLAY_SCOPE');return {s,t,f,index};};
    let {s,t,f,index}=await state();if((s.validVotes|s.invalidVotes)&1<<index)return {alreadyVoted:true,...await this.transport(signer).reconcile(job,'vote')};
    if(s.state!==STATE.REVEALED||t.state!==STATE.ACTIVE||t.attempt!==s.attempt||f.activeIndex!==t.index)return {noLongerEligible:true};
    let {rows:[saved]}=await this.queue.pool.query('SELECT * FROM factory_pool_v4.replays WHERE job_id=$1',[job.id]);
    if(!saved){
      const started=performance.now(),verified=await this.verify({reader,address,contentStore:new LocalFactoryContentStore(this.config.contentDir),modelDir:this.config.modelDir,outputDir:join(this.config.outputDir,c.deployment.factory,signer.publicKey.toBase58(),'lease-'+job.fence),binary:this.config.binary});
      const report=verified.report,reportHash=await hash(canonical(report));
      await this.queue.transaction(async db=>{await this.queue.guard(job,db,{lock:true});await db.query('INSERT INTO factory_pool_v4.replays(job_id,report_hash,report,wall_ms) VALUES($1,$2,$3,$4) ON CONFLICT(job_id) DO NOTHING',[job.id,reportHash,report,Math.ceil(performance.now()-started)]);});
      saved=(await this.queue.pool.query('SELECT * FROM factory_pool_v4.replays WHERE job_id=$1',[job.id])).rows[0];
    }
    ({s,t,f,index}=await state());if((s.validVotes|s.invalidVotes)&1<<index)return {alreadyVoted:true,...await this.transport(signer).reconcile(job,'vote')};
    const report=saved.report;
    if(await hash(canonical(report))!==saved.report_hash||report.submission!==address.toBase58()||report.task!==new PublicKey(s.task).toBase58()||report.attempt!==s.attempt||report.completeTrials!==t.descriptor.seeds.length||report.measurements?.length!==report.completeTrials||report.fullReplay!==true||s.state!==STATE.REVEALED||t.state!==STATE.ACTIVE||t.attempt!==s.attempt||f.activeIndex!==t.index)return {noLongerEligible:true};
    const reportHash=fromHex(saved.report_hash),verified={factory:f,task:t,submission:s,report,reportHash,message:voteMessage(reader.program,f,t,address,s,report.valid,reportHash,report.completeTrials)},transport=this.transport(signer);
    return transport.run(job,'vote',voteInstructions(reader,address,verified,signer),async()=>{const latest=await reader.submission(address,s.task);return !!((latest.validVotes|latest.invalidVotes)&1<<index);});
  }
  transport(signer){return new FactoryPoolTransportV4({queue:this.queue,connection:this.connection,payer:signer,maxTransactions:this.config.maxTransactionsPerVerifier,maxFeeLamports:1000000,beforeSend:()=>{if(this.stopped)throw fail('POOL_STOPPED');}});}
  async payment(job){
    const c=this.contexts.get(job.payload.factory);if(!c||job.payload.payer!==this.signers[0].publicKey.toBase58())throw fail('POOL_PAYMENT_SCOPE');
    const reader=c.reader,t=await reader.task(job.payload.index),f=await reader.factory();
    if(job.payload.operation==='finalize'){
      if(t.state!==STATE.ACTIVE||t.attempt!==job.payload.attempt)return {alreadyResolved:true,...await this.transport(this.signers[0]).reconcile(job,'finalize')};
      const address=new PublicKey(job.payload.submission),s=await reader.submission(address,reader.a.task(c.deployment.factory,t.index));
      if(s.state!==STATE.VALID||s.attempt!==t.attempt)throw fail('POOL_FINALIZE_QUORUM');
      const keys=[meta(c.deployment.factory,true),meta(reader.a.task(c.deployment.factory,t.index),true),meta(address)];if(f.nextIndex<f.count)keys.push(meta(reader.a.task(c.deployment.factory,f.nextIndex),true));
      return this.transport(this.signers[0]).run(job,'finalize',[instruction(reader.program,keys,7)],async()=>[STATE.SOLVED,STATE.FAILED].includes((await reader.task(t.index)).state));
    }
    if(t.paid)return {alreadyPaid:true,...await this.transport(this.signers[0]).reconcile(job,'payment')};if(t.state!==STATE.SOLVED)throw fail('POOL_PAYMENT_NOT_EARNED');
    const payer=this.signers[0],beneficiary=new PublicKey(t.beneficiary),mint=new PublicKey(f.mint),ata=getAssociatedTokenAddressSync(mint,beneficiary),factory=reader.expected.factoryAddress;
    return this.transport(payer).run(job,'payment',[createAssociatedTokenAccountIdempotentInstruction(payer.publicKey,ata,beneficiary,mint),instruction(reader.program,[meta(reader.a.global),meta(factory,true),meta(reader.a.task(factory,t.index),true),meta(new PublicKey(t.winner)),meta(reader.a.pool(0),true),meta(ata,true),meta(TOKEN_PROGRAM_ID)],9)],async()=>(await reader.task(t.index)).paid);
  }
  async work(kind,handler){
    if(['catalog','calibrate'].includes(kind)){
      const {rows:[backlog]}=await this.queue.pool.query("SELECT count(*)::int AS n FROM factory_pool_v4.jobs WHERE kind='replay' AND state IN ('ready','leased','blocked') AND scope=ANY($1::text[])",[[...this.contexts.keys()]]);
      const maximum=this.config.maxPendingReplays||8,disk=await statfs(this.config.contentDir);
      if(backlog.n>=maximum||Number(disk.bavail)*Number(disk.bsize)<this.config.diskReserveBytes){this.admissionStatus='POOL_REPLAY_OR_ARCHIVE_BACKPRESSURE';return false;}
    }
    const scopes=kind==='calibrate'?[this.config.poolTrust.poolId]:kind==='catalog'?(await this.queue.pool.query('SELECT id FROM factory_pool_v4.catalogs WHERE pool_id=$1',[this.config.poolTrust.poolId])).rows.map(r=>r.id):[...this.contexts.keys()];
    const job=await this.queue.claim(kind,this.owner+':'+randomUUID(),120,null,scopes);if(!job)return false;let lost=false;
    const renewal=setInterval(()=>this.queue.renew(job,120).catch(()=>lost=true),30000);
    try{const result=await handler(job);if(!lost)await this.queue.finish(job,result);}
    catch(error){if(!lost)try{await this.queue.retry(job,{delaySeconds:error.code==='POOL_CONFIRMATION_PENDING'?2:30,blocked:['POOL_TRANSACTION_UNKNOWN','POOL_TRANSACTION_FAILED','POOL_FINITE_AUTHORIZATION','POOL_SIGNER_ALLOWANCE','POOL_CALIBRATION_INELIGIBLE','POOL_CALIBRATION_SCOPE','POOL_CALIBRATION_TEMPLATE_EXHAUSTED','POOL_REWARD_AUTHORIZATION_EXHAUSTED','POOL_COMPLETE_HISTORY_REQUIRED','POOL_SCIENCE_ALREADY_REGISTERED','POOL_CATALOG_DEADLINE','POOL_DUPLICATE_SCIENCE'].includes(error.code),code:typeof error.code==='string'&&/^[A-Z0-9_]{1,80}$/.test(error.code)?error.code:'POOL_RETRY_REQUIRED'});}catch{}}
    finally{clearInterval(renewal);}return true;
  }
  wake(){this.again=true;}
  async run({signal}={}){
    const lanes=Array.from({length:this.config.replayConcurrency},()=>this.loop('replay',j=>this.replay(j),signal));
    lanes.push(this.loop('payment',j=>this.payment(j),signal));
    if(this.supply)lanes.push(this.loop('catalog',j=>this.supply.register(j,{contentStore:new LocalFactoryContentStore(this.config.contentDir)}),signal));
    if(this.calibration)lanes.push(this.loop('calibrate',j=>this.nativeWork(()=>this.calibration.run(j)),signal));
    while(!this.stopped&&!signal?.aborted){try{await this.discover();this.lastDiscoveryError=null;}catch{this.lastDiscoveryError='POOL_DISCOVERY_RETRY';}await new Promise(ok=>setTimeout(ok,5000));}
    this.stopped=true;await Promise.all(lanes);
  }
  async loop(kind,handler,signal){while(!this.stopped&&!signal?.aborted){try{if(!await this.work(kind,handler))await new Promise(ok=>setTimeout(ok,1000));}catch{this.lastWorkerError='POOL_DATABASE_RETRY';await new Promise(ok=>setTimeout(ok,5000));}}}
  async stop(){this.stopped=true;for(const res of this.eventClients)res.end();}
}

async function main(){
  const path=process.argv[2];if(!path)throw fail('POOL_PRIVATE_CONFIG_REQUIRED');const config=JSON.parse(await readFile(path,'utf8'));
  if(config.enabled!==true)throw fail('POOL_ACTIVATION_NOT_AUTHORIZED');
  const queue=await(await FactoryPoolQueueV4.connect((await readFile(config.databaseUrlFile,'utf8')).trim())).initialize(),shared=factoryRpcTransportV4(config.rpcUpstream),connection=new Connection(config.rpcUpstream,{commitment:'finalized',disableRetryOnRateLimit:true,fetch:(url,options)=>shared(url,{...options,factoryFresh:true})}),signers=await Promise.all(config.verifierKeyFiles.map(signerFile));
  let supply=null;if(config.supplyAuthorization){const authority=await signerFile(config.authorityKeyFile),transport=new FactoryPoolTransportV4({queue,connection,payer:authority,maxTransactions:config.maxCatalogTransactions,maxFeeLamports:config.maxCatalogFeeLamports});supply=new FactoryPoolSupplyV4({queue,baseDeployment:config.deployment,trust:config.poolTrust,authority,transport,authorization:config.supplyAuthorization});}
  const calibration=supply&&config.calibrationPolicy?new FactoryPoolCalibrationV4({queue,supply,policy:config.calibrationPolicy}):null;
  const service=await new FactoryPoolServiceV4({config,queue,connection,signers,supply,calibration}).initialize();
  if(supply){supply.transport.beforeSend=()=>{if(service.stopped)throw fail('POOL_STOPPED');};for(const planPath of config.approvedPlans||[]){const plan=JSON.parse(await readFile(planPath,'utf8'));await supply.importPlan(plan,async path=>JSON.parse(await readFile(new URL(path,pathToFileURL(planPath)),'utf8')));}}
  await service.discover();
  const server=serveFactoryGatewayV4(service.root.gateway,{port:config.port||8792,pool:service});const abort=new AbortController();for(const s of ['SIGTERM','SIGINT'])process.once(s,()=>{abort.abort();server.close();service.stop();});
  try{await service.run({signal:abort.signal});}finally{for(const c of service.contexts.values())c.gateway.close();await queue.close();}
}
const mainPath=process.argv[1]&&await realpath(process.argv[1]).catch(()=>null);
if(mainPath&&import.meta.url===pathToFileURL(mainPath).href)main().catch(error=>{console.error(JSON.stringify({status:'factory-pool-v4-stopped',code:error.code||'POOL_STARTUP_FAILED',privateConfigurationLogged:false}));process.exitCode=1;});
