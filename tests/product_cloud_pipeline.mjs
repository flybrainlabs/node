// Controlled-input deployment acceptance. Every candidate is computed anew
// for the frozen public round, uploaded, and replayed by the running node.
// This is not a measurement of normal browser search or independent operators.
import assert from 'node:assert/strict';
import { readFile,writeFile,mkdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { resolve,join } from 'node:path';
import { keyFile,request,verified,api,canonical } from '../tools/target_dev_identity.mjs';
import * as p from '../web/target-protocol-v2.mjs';
const output=resolve(process.argv[2]||'data/prepared/mining-product-20261011/cloud-pipeline');
const count=Number(process.argv[3]||2),deployment=JSON.parse(await readFile('web/data/mining-deployment-v1.json'));
assert(Number.isInteger(count)&&count>0&&count<=16);
assert.equal(deployment.environment,'development');assert.equal(deployment.capabilities.payment,false);assert.equal(deployment.capabilities.rewards,false);
const base=deployment.apiBase,authorityId=deployment.authorityId,root=process.cwd();
await mkdir(output,{recursive:true});
const key=await keyFile(join('/workspace/.flypow-tools/product-cloud-private','miner.key'));
const file=join(output,'report.json');let report;
try{report=JSON.parse(await readFile(file));}catch(e){if(e.code!=='ENOENT')throw e;report={schema:'flybrain-product-cloud-pipeline-v1',controlledInput:true,normalBrowserSearch:false,independentOperators:false,officialDownloads:0,modelCacheReused:true,rounds:[],checks:[]};}
if(report.failure){(report.previousFailures||=[]).push(report.failure);report.resumptions=(report.resumptions||0)+1;}report.passed=false;delete report.failure;
const save=()=>writeFile(file,JSON.stringify(report,null,2)+'\n');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const transient=e=>['TimeoutError','AbortError'].includes(e.name)||e instanceof TypeError&&/fetch failed|network/i.test(e.message)||e.code==='BACKPRESSURE'||e.status===503;
const retry=async fn=>{for(let attempt=0;;attempt++){try{return await fn();}catch(e){if(!transient(e)||attempt>=2)throw e;report.networkRetries=(report.networkRetries||0)+1;await save();console.log(JSON.stringify({retryingNetwork:true,attempt:attempt+1,reason:e.name||e.code}));await pause(2000*(attempt+1));}}};
const get=(path,domain)=>retry(async()=>verified(authorityId,domain,await(await api(base,path)).json()));
const post=async(path,action,rid,payload,domain,name)=>{const req=await request(key,action,rid,payload,name);return retry(async()=>verified(authorityId,domain,await(await api(base,path,req)).json()));};
const put=(u,index,chunk,req)=>retry(async()=>{const response=await fetch(base+'/api/target-mining/v2/artifacts/uploads/'+u.uploadId+'/chunks/'+index,{method:'PUT',headers:{'Content-Type':'application/octet-stream','X-Flypow-Action':JSON.stringify(req)},body:chunk,signal:AbortSignal.timeout(60000)});if(!response.ok){const body=await response.json().catch(()=>({code:'HTTP',message:String(response.status)}));const e=new Error(body.message);e.status=response.status;e.code=body.code;throw e;}return verified(authorityId,'chunk-receipt',await response.json());});
const native=args=>new Promise((ok,bad)=>{const child=spawn(join(root,'target/release/target_trial'),args,{stdio:['ignore','pipe','pipe']});let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);child.on('error',bad);child.on('close',code=>code?bad(new Error(err)):ok(JSON.parse(out)));});
try{
 report.before||=await get('network-stats','network-stats');await save();
 // A process can stop after adjudication but before saving its local winner.
 // Reconcile those exact persisted receipts before taking a new target.
 for(const record of report.rounds.filter(r=>r.receipt&&!r.winner)){
  const round=await get('rounds/'+record.roundId,'round-state');if(!round.winner)continue;
  assert.equal(round.winner.claimId,record.receipt.claimId,'Do not borrow another miner outcome');
  const claim=await get('claims/'+record.receipt.claimId,'claim-state');assert.equal(claim.status,'VALID');assert(claim.validVotes>=claim.quorum);record.claim=claim;record.winner=round.winner;report.lastStatistics=await get('network-stats','network-stats');await save();
 }
 while(report.rounds.filter(r=>r.winner).length<count){
  const snap=await get('rounds/current','authority-snapshot'),r=snap.round;
  assert(r,'No unconsumed calibrated target supply; never repeat solved goals');
  await p.validateRound(r,{networkId:deployment.networkId,authorityId});
  let record=report.rounds.find(x=>x.roundId===r.roundId);
  if(!record){record={roundId:r.roundId,goalId:r.pre.goalId,roundSequence:r.pre.roundSequence,difficultyMicros:r.pre.difficultyMicros,backgrounds:r.pre.requiredBackgrounds,attempts:[]};report.rounds.push(record);}
  const dir=join(output,r.roundId);await mkdir(dir,{recursive:true});await writeFile(join(dir,'goal.json'),canonical(r.goal));
  const supply=JSON.parse(await readFile('web/data/target-mining-v2/product-supply-20261011.json'));
  const member=supply.goals.find(g=>g.goalId===r.pre.goalId);assert(member,'Only the new, independently calibrated supply is accepted');
  const cal=JSON.parse(await readFile(member.path.replace('/assets/','web/').replace('goal.json','calibration.json')));
  const choices=cal.samples.filter(s=>s.trials.length>=r.pre.requiredBackgrounds&&s.trials.slice(0,r.pre.requiredBackgrounds).every(t=>t.metrics.passed)).map(s=>s.input);
  let m,trialDir;
  for(let i=0;i<choices.length;i++){
   const input=choices[i];trialDir=join(dir,'input-'+i);await mkdir(trialDir,{recursive:true});await writeFile(join(trialDir,'input.json'),canonical(input));const trials=[],attempt={input,measurements:[]};record.attempts.push(attempt);
   for(let j=0;j<r.pre.requiredBackgrounds;j++){
    const path=join(trialDir,'trial-'+j+'.bin'),meta=path+'.json';let a,computedNow=false;
    try{a=JSON.parse(await readFile(meta));assert.equal(a.seedHex,r.seeds[j]);assert.equal(await p.hash(await readFile(path)),a.resultRoot);}catch(e){if(e.code!=='ENOENT')throw e;computedNow=true;a=await native([join(root,'data/prepared/registry-male-cns-v1.0/graph-v1.bin'),join(root,'data/prepared/registry-male-cns-v1.0/model-v0.bin'),join(dir,'goal.json'),join(trialDir,'input.json'),r.seeds[j],path]);await writeFile(meta,canonical(a));}
    attempt.measurements.push(a);await save();console.log(JSON.stringify({computed:computedNow,cacheReused:!computedNow,round:r.pre.roundSequence,input:i,background:j+1,passed:a.metrics.passed}));
    if(!a.metrics.passed)break;
    trials.push({trialId:await p.trialId(r.roundId,r.goal,input,j,r.seeds[j]),repeatIndex:j,seedHex:r.seeds[j],resultRoot:a.resultRoot,bytes:a.bytes,metrics:a.metrics});
   }
   if(trials.length===r.pre.requiredBackgrounds){m={schema:'flypow-candidate-manifest-v2',roundId:r.roundId,goalId:r.pre.goalId,candidateId:await p.candidateId(r.roundId,input),input,trials,goalResultRoot:await p.goalResultRoot(trials)};break;}
  }
  assert(m,'Controlled inputs failed the actual frozen backgrounds; no fake result or renamed solution');await p.validateManifest(m,r);record.manifest=m;
  record.salt||=p.hex(crypto.getRandomValues(new Uint8Array(32)));await save();
  record.receipt=await post('claims','claim',r.roundId,{commitment:await p.commitment(r,key.publicKey,m,record.salt)},'claim-receipt','product-claim-'+m.candidateId);await save();
  for(let j=0;j<m.trials.length;j++){
   const t=m.trials[j],u=await post('artifacts/uploads','upload-create',r.roundId,{claimId:record.receipt.claimId,trialIndex:j,bytes:t.bytes,sha256:t.resultRoot},'upload-receipt','product-upload-'+record.receipt.claimId+'-'+j);
   let state=await post('artifacts/uploads/'+u.uploadId+'/status','upload-status',r.roundId,{uploadId:u.uploadId},'upload-state');const bytes=await readFile(join(trialDir,'trial-'+j+'.bin'));
   for(let index=0;state.status!=='SEALED'&&index<u.chunks;index++){
    if(state.receivedChunks.includes(index))continue;const chunk=bytes.subarray(index*u.chunkBytes,(index+1)*u.chunkBytes),req=await request(key,'upload-chunk',r.roundId,{uploadId:u.uploadId,index,bytes:chunk.length,sha256:await p.hash(chunk)},'product-chunk-'+u.uploadId+'-'+index);
    await put(u,index,chunk,req);
    if(!report.uploadResume&&index===0&&u.chunks>1){
     // Drop all local upload cursor information, then resume from durable
     // server truth. The accepted chunk must neither disappear nor duplicate.
     state=await post('artifacts/uploads/'+u.uploadId+'/status','upload-status',r.roundId,{uploadId:u.uploadId},'upload-state');assert(state.receivedChunks.includes(0));
     await put(u,0,chunk,req);report.uploadResume={uploadId:u.uploadId,retainedFirstChunk:true,idempotentRetry:true};await save();
    }
   }
   if(state.status!=='SEALED')await post('artifacts/uploads/'+u.uploadId+'/seal','upload-seal',r.roundId,{uploadId:u.uploadId},'seal-receipt','product-seal-'+u.uploadId);
  }
  await post('claims/'+record.receipt.claimId+'/reveal','reveal',r.roundId,{claimId:record.receipt.claimId,manifest:m,salt:record.salt},'reveal-receipt','product-reveal-'+record.receipt.claimId);record.revealed=true;await save();
  const end=Date.now()+45*60*1000;let note=0;
  while(Date.now()<end){
   const round=await get('rounds/'+r.roundId,'round-state'),claim=await get('claims/'+record.receipt.claimId,'claim-state');record.claim=claim;
   if(round.winner){assert.equal(round.winner.claimId,record.receipt.claimId,'Controlled client must actually win, not borrow another miner outcome');assert(claim.validVotes>=claim.quorum);assert.equal(claim.status,'VALID');record.winner=round.winner;break;}
   assert(!['INVALID','TIMED_OUT'].includes(claim.status),JSON.stringify(claim));
   if(Date.now()-note>30000){console.log(JSON.stringify({waitingReplay:true,round:r.pre.roundSequence,validVotes:claim.validVotes,queue:claim.verificationQueue}));await save();note=Date.now();}await pause(2000);
  }
  assert(record.winner,'Full cloud replay/adjudication deadline exceeded');report.lastStatistics=await get('network-stats','network-stats');await save();console.log(JSON.stringify({won:true,round:r.pre.roundSequence,total:report.rounds.filter(r=>r.winner).length,controller:report.lastStatistics.difficultyController}));
 }
 report.history=await get('rounds/history?limit=100','round-history');for(const r of report.rounds.filter(r=>r.winner))assert(report.history.rounds.some(h=>h.roundId===r.roundId&&h.winner.claimId===r.winner.claimId));
 report.after=await get('network-stats','network-stats');report.passed=true;report.checks=['New full-model computations bound to each frozen round and new calibrated goal','Private node performs complete replay and real quorum adjudication','Interrupted cursor recovery and duplicate chunk idempotency against actual cloud state','Cross-round progression and persistent signed history'];await save();
}catch(e){report.failure={message:e.message,at:new Date().toISOString()};await save();throw e;}
