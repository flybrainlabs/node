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
      const measured=await new Promise((resolve,reject)=>{const child=spawn(binary,[join(modelDir,'graph-v1.bin'),join(modelDir,'model-v0.bin'),join(dir,'goal.json'),join(dir,'input.json'),r.seeds[j],file,'--verify'],{stdio:['ignore','pipe','pipe']});let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);child.on('error',reject);child.on('close',code=>code?reject(Object.assign(new Error(err.trim()||'Native replay failed'),{scientificFailure:true})):resolve(JSON.parse(out)));});
      if(!measured.replayVerified||!measured.metrics.passed||measured.resultRoot!==m.trials[j].resultRoot||Buffer.compare(Buffer.from(canonical(measured.metrics)),Buffer.from(canonical(m.trials[j].metrics)))!==0)throw Object.assign(new Error('Full native predicate/metrics mismatch'),{scientificFailure:true});measurements.push(measured);log({kind:'trial-replayed',claimId:job.claimId,background:j+1,bytes:measured.bytes,milliseconds:measured.elapsedMs});
    }
  }catch(e){if(!e.scientificFailure)throw e;valid=false;reason=e.message;}
  finally{clearInterval(timer);}
  if(heartbeatError)throw heartbeatError;
  const payload={jobId:job.jobId,fencingToken:job.fencingToken,networkId:r.pre.networkId,claimId:job.claimId,roundId:r.roundId,goalId:r.pre.goalId,candidateId:m.candidateId,goalResultRoot:m.goalResultRoot,manifestHash:await id('candidate-manifest',m),evaluatorVersion:r.goal.evaluatorVersion,difficultyPolicyHash:r.pre.difficultyPolicyHash,verificationPolicyHash:await id('verification-policy',r.pre.verificationPolicy),completeTrials:r.pre.requiredBackgrounds,fullReplay:true,valid};
  const vote=await request(key,'verifier-vote',r.roundId,payload,'vote-'+job.jobId+'-'+job.fencingToken),receipt=await verified(authorityId,'vote-receipt',await(await api(base,'verifier-votes',vote)).json());
  await writeFile(join(dir,'replay-report.json'),canonical({schema:'flypow-candidate-replay-v2',claimId:job.claimId,verifierId:key.publicKey,fullReplay:true,valid,reason,measurements,receipt}));return {jobId:job.jobId,valid,measurements,receipt};
}
async function main(){const [configPath,...keyPaths]=process.argv.slice(2);if(!configPath||!keyPaths.length)throw new Error('usage: candidate_verifier_v2.mjs RUNTIME.json VERIFIER.key [...]');const cfg=JSON.parse(await readFile(configPath,'utf8')),keys=await Promise.all(keyPaths.map(keyFile));const digestFile=async path=>{const h=createHash('sha256');for await(const b of createReadStream(path))h.update(b);return h.digest('hex');};const modelReadiness={graphRoot:await digestFile(join(cfg.modelDir,'graph-v1.bin')),modelDataRoot:await digestFile(join(cfg.modelDir,'model-v0.bin')),nativeBinaryReady:(await stat(cfg.binary)).isFile()};console.log('Local development replay worker; local keys are functional tests, not independent operators.');
  for(;;){let work=false;for(const key of keys)try{const req=await request(key,'verifier-lease','',{modelReadiness}),reply=await verified(cfg.authorityId,'verification-lease',await(await api(cfg.apiBase,'verifier-jobs/lease',req)).json());if(reply.job){work=true;await verifyJob({...cfg,key,job:reply.job,base:cfg.apiBase,log:x=>console.log(JSON.stringify(x))});}}catch(e){console.error(JSON.stringify({kind:'verifier-retry',code:e.code||'INFRASTRUCTURE',message:e.message}));}if(!work)await new Promise(r=>setTimeout(r,1500));}
}
if(process.argv[1]===new URL(import.meta.url).pathname)main().catch(e=>{console.error(e.message);process.exitCode=1;});
