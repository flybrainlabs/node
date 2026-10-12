#!/usr/bin/env node
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { stat } from 'node:fs/promises';
// Every assigned vote follows complete native replay of each required A/B.
import { readFile,writeFile,mkdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { resolve,join } from 'node:path';
import { keyFile,request,verified,api,canonical } from './target_dev_identity.mjs';
import { id,hash,validateRound,validateManifest } from '../web/target-protocol-v2.mjs';
export class ReplayError extends Error{constructor(status,message){super(message);this.status=status;this.code=status;this.fullReplay=false;}}
export async function nativeReply(binary,args){
  return new Promise((resolve,reject)=>{const child=spawn(binary,args,{stdio:['ignore','pipe','pipe']});let out='',err='';
    child.stdout.on('data',b=>{out+=b;if(out.length>1024*1024){child.kill('SIGTERM');reject(new ReplayError('LOCAL_MODEL_ERROR','Native reply exceeds the structured limit'));}});
    child.stderr.on('data',b=>err=(err+b).slice(-65536));child.on('error',e=>reject(new ReplayError('RETRYABLE_INFRA_ERROR',e.message)));
    child.on('close',(code,signal)=>{let reply;try{reply=JSON.parse(out);}catch{return reject(new ReplayError('RETRYABLE_INFRA_ERROR',signal?'Native process interrupted':'Native process did not return a structured outcome'));}
      if(code!==0){const status=['LOCAL_MODEL_ERROR','RETRYABLE_INFRA_ERROR'].includes(reply.replayStatus)?reply.replayStatus:'RETRYABLE_INFRA_ERROR';return reject(new ReplayError(status,reply.reason||'Native replay execution failed'));}resolve(reply);});
  });
}
export async function nativeCapabilities(binary){const result=await nativeReply(binary,['--capabilities']);if(result.schema!=='flybrain-native-replay-capabilities-v1'||result.structuredReplayVersion!==1||!Array.isArray(result.parameterProfileHashes)||!Array.isArray(result.evaluatorVersions))throw new ReplayError('LOCAL_MODEL_ERROR','Native structured replay capabilities are unavailable');return result;}
export async function getModelReadiness(binary,modelDir){const caps=await nativeCapabilities(binary);const digest=async path=>{const h=createHash('sha256');for await(const b of createReadStream(path))h.update(b);return h.digest('hex');};return {graphRoot:await digest(join(modelDir,'graph-v1.bin')),modelDataRoot:await digest(join(modelDir,'model-v0.bin')),nativeBinaryReady:(await stat(binary)).isFile(),parameterProfileHashes:caps.parameterProfileHashes,evaluatorVersions:caps.evaluatorVersions};}
export async function verifyJob({base,authorityId,key,job,modelDir,outputDir,binary,log=()=>{}}){
  const r=job.round,m=job.manifest;await validateRound(r,{authorityId});await validateManifest(m,r);
  const dir=join(outputDir,job.jobId+'-'+job.fencingToken);await mkdir(dir,{recursive:true,mode:0o700});await writeFile(join(dir,'goal.json'),canonical(r.goal));await writeFile(join(dir,'input.json'),canonical(m.input));
  let heartbeatError=null;
  const timer=setInterval(async()=>{try{const action=await request(key,'verifier-heartbeat',r.roundId,{jobId:job.jobId,fencingToken:job.fencingToken});await verified(authorityId,'verification-heartbeat',await(await api(base,'verifier-jobs/heartbeat',action)).json());}catch(e){heartbeatError=e;}},30000);
  const measurements=[];let valid=true,reason=null;
  try{
    for(let j=0;j<m.trials.length;j++){
      if(heartbeatError)throw heartbeatError;
      const a=job.artifacts.find(a=>a.trialIndex===j);if(!a)throw new Error('Missing private trial');const req=await request(key,'verifier-artifact',r.roundId,{uploadId:a.uploadId,jobId:job.jobId,fencingToken:job.fencingToken});
      const file=join(dir,'trial-'+j+'.bin'),bytes=new Uint8Array(await(await api(base,'verifier-artifacts/'+a.uploadId,req)).arrayBuffer());if(bytes.length!==m.trials[j].bytes||await hash(bytes)!==m.trials[j].resultRoot)throw new Error('Artifact root/length disagreement');await writeFile(file,bytes,{mode:0o600});
      const measured=await nativeReply(binary,[join(modelDir,'graph-v1.bin'),join(modelDir,'model-v0.bin'),join(dir,'goal.json'),join(dir,'input.json'),r.seeds[j],file,'--verify']);
      if(!['VALID','INVALID_RESULT'].includes(measured.replayStatus)||measured.fullReplay!==true||measured.steps!==r.goal.steps)throw new ReplayError('LOCAL_MODEL_ERROR','Native outcome does not prove a complete frozen trial');
      if(measured.replayStatus!=='VALID'||!measured.replayVerified||!measured.metrics.passed||measured.resultRoot!==m.trials[j].resultRoot||Buffer.compare(Buffer.from(canonical(measured.metrics)),Buffer.from(canonical(m.trials[j].metrics)))!==0){valid=false;reason='Complete native result/predicate/metrics mismatch';}
      measurements.push(measured);log({kind:'trial-replayed',claimId:job.claimId,background:j+1,status:measured.replayStatus,bytes:measured.bytes,milliseconds:measured.elapsedMs});
    }
  }catch(e){const fault=e instanceof ReplayError?e:new ReplayError('RETRYABLE_INFRA_ERROR',e.message);fault.completeTrials=measurements.length;await writeFile(join(dir,'replay-report.json'),canonical({schema:'flybrain-candidate-replay-fault-v3',claimId:job.claimId,verifierId:key.publicKey,status:fault.status,fullReplay:false,completeTrials:measurements.length,measurements,reason:fault.message}));throw fault;}
  finally{clearInterval(timer);}
  if(heartbeatError)throw heartbeatError;
  if(measurements.length!==r.pre.requiredBackgrounds)throw new ReplayError('LOCAL_MODEL_ERROR','Not every required background was replayed');
  const payload={jobId:job.jobId,fencingToken:job.fencingToken,networkId:r.pre.networkId,claimId:job.claimId,roundId:r.roundId,goalId:r.pre.goalId,candidateId:m.candidateId,goalResultRoot:m.goalResultRoot,manifestHash:await id('candidate-manifest',m),evaluatorVersion:r.goal.evaluatorVersion,difficultyPolicyHash:r.pre.difficultyPolicyHash,verificationPolicyHash:await id('verification-policy',r.pre.verificationPolicy),completeTrials:measurements.length,fullReplay:true,valid};
  const vote=await request(key,'verifier-vote',r.roundId,payload,'vote-'+job.jobId+'-'+job.fencingToken),receipt=await verified(authorityId,'vote-receipt',await(await api(base,'verifier-votes',vote)).json());
  await writeFile(join(dir,'replay-report.json'),canonical({schema:'flypow-candidate-replay-v2',claimId:job.claimId,verifierId:key.publicKey,fullReplay:true,valid,reason,measurements,receipt}));return {jobId:job.jobId,valid,measurements,receipt};
}
async function main(){const [configPath,...keyPaths]=process.argv.slice(2);if(!configPath||!keyPaths.length)throw new Error('usage: candidate_verifier_v2.mjs RUNTIME.json VERIFIER.key [...]');const cfg=JSON.parse(await readFile(configPath,'utf8')),keys=await Promise.all(keyPaths.map(keyFile));const modelReadiness=await getModelReadiness(cfg.binary,cfg.modelDir);console.log('Local development replay worker; local keys are functional tests, not independent operators.');
  for(;;){let work=false;for(const key of keys){let job=null;try{const req=await request(key,'verifier-lease','',{modelReadiness}),reply=await verified(cfg.authorityId,'verification-lease',await(await api(cfg.apiBase,'verifier-jobs/lease',req)).json());job=reply.job;if(job){work=true;await verifyJob({...cfg,key,job,base:cfg.apiBase,log:x=>console.log(JSON.stringify(x))});}}catch(e){if(job&&e instanceof ReplayError){try{const fault=await request(key,'verifier-fault',job.roundId,{jobId:job.jobId,fencingToken:job.fencingToken,kind:e.status,fullReplay:false,completeTrials:e.completeTrials||0},'fault-'+job.jobId+'-'+job.fencingToken);await verified(cfg.authorityId,'verification-fault-receipt',await(await api(cfg.apiBase,'verifier-jobs/fault',fault)).json());}catch(f){console.error(JSON.stringify({kind:'fault-report-retry',code:f.code||'RETRYABLE_INFRA_ERROR'}));}}console.error(JSON.stringify({kind:'verifier-retry',code:e.code||'RETRYABLE_INFRA_ERROR',message:e.message}));}}if(!work)await new Promise(r=>setTimeout(r,1500));}
}
if(process.argv[1]===new URL(import.meta.url).pathname)main().catch(e=>{console.error(e.message);process.exitCode=1;});
