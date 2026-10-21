#!/usr/bin/env node
// Verification only: no goal generation, difficulty selection or round entropy.
import {readFile,writeFile,mkdir,stat,open,link,unlink} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {Keypair,PublicKey,Transaction,sendAndConfirmTransaction,Ed25519Program} from '@solana/web3.js';
import {readerForDeployment} from '../web/task-factory-client-v4.mjs';
import {makeRound,validateFactoryManifest} from '../web/task-factory-v4-science.mjs';
import {canonical,hash} from '../web/target-protocol-v2.mjs';
import {hex,fromHex,voteMessage,STATE} from '../web/task-factory-v4-codec.mjs';
import {instruction,meta,instructionSysvar} from './task_factory_v4_client.mjs';
import {nativeReply,ReplayError,getModelReadiness} from './candidate_verifier_v2.mjs';
export class LocalFactoryContentStore {
  constructor(directory){this.directory=resolve(directory);}
  async put(root,bytes){
    if(!/^[a-f0-9]{64}$/.test(root)||bytes.length>1024*1024||await hash(bytes)!==root)throw new Error('Invalid calibrated content');
    await mkdir(this.directory,{recursive:true,mode:0o700});const temporary=join(this.directory,root+'.'+randomUUID()+'.partial');
    try{const file=await open(temporary,'wx',0o600);try{await file.writeFile(bytes);await file.sync();}finally{await file.close();}try{await link(temporary,join(this.directory,root+'.bin'));}catch(error){if(error.code!=='EEXIST')throw error;}}finally{await unlink(temporary).catch(()=>{});}
    await this.get(root,1024*1024);return root;
  }
  async get(root,max=128*1024*1024){
    if(! /^[a-f0-9]{64}$/.test(root))throw new Error('Invalid content identity');
    let file;for(const ext of ['.bin','.json']){const candidate=join(this.directory,root+ext);try{await stat(candidate);file=candidate;break;}catch(e){if(e.code!=='ENOENT')throw e;}}
    if(!file)throw new ReplayError('RETRYABLE_INFRA_ERROR','Content not currently available');
    if((await stat(file)).size>max)throw new ReplayError('RETRYABLE_INFRA_ERROR','Content exceeds frozen limit');
    const bytes=new Uint8Array(await readFile(file));if(await hash(bytes)!==root)throw new ReplayError('RETRYABLE_INFRA_ERROR','Content hash mismatch');return bytes;
  }
}
export async function verifyFactorySubmission({reader,address,contentStore,modelDir,outputDir,binary,replay=nativeReply,readiness=getModelReadiness}){
  const f=await reader.factory(),s=await reader.account(new PublicKey(address),(await import('../web/task-factory-v4-codec.mjs')).decodeSubmission),t=await reader.account(new PublicKey(s.task),(await import('../web/task-factory-v4-codec.mjs')).decodeTask);
  if(!reader.a.task(reader.expected.factoryAddress,t.index).equals(new PublicKey(s.task))||!reader.a.submission(s.task,s.attempt,s.miner,s.commitment).equals(new PublicKey(address))||!new PublicKey(t.factory).equals(reader.expected.factoryAddress)||s.attempt!==t.attempt||t.state!==STATE.ACTIVE||f.activeIndex!==t.index||s.state!==STATE.REVEALED)throw new ReplayError('RETRYABLE_INFRA_ERROR','Submission is not eligible on chain');
  const specification=JSON.parse(new TextDecoder().decode(await contentStore.get(hex(t.descriptor.content),1024*1024))),round=await makeRound({program:reader.program.toBase58(),genesis:reader.expected.genesis,factoryAddress:reader.expected.factoryAddress.toBase58(),taskAddress:new PublicKey(s.task).toBase58(),factory:f,task:t,spec:specification});
  const manifestBytes=await contentStore.get(hex(s.evidence.manifest),1024*1024),manifest=JSON.parse(new TextDecoder().decode(manifestBytes));
  await validateFactoryManifest(manifest,round);
  if(await hash(manifestBytes)!==hex(s.evidence.manifest)||manifest.candidateId!==hex(s.evidence.candidate)||manifest.goalResultRoot!==hex(s.evidence.result))throw new ReplayError('RETRYABLE_INFRA_ERROR','Committed manifest evidence mismatch');
  const archiveBytes=await contentStore.get(hex(s.evidence.archive),1024*1024),expectedArchive=canonical({schema:'flybrainlabs-candidate-archive-v4',trials:manifest.trials.map(t=>({root:t.resultRoot,bytes:t.bytes}))});
  if(await hash(archiveBytes)!==hex(s.evidence.archive)||hex(archiveBytes)!==hex(expectedArchive))throw new ReplayError('RETRYABLE_INFRA_ERROR','Committed archive index mismatch');
  const ready=await readiness(binary,modelDir);
  if(ready.graphRoot!==round.goal.graphRoot||ready.modelDataRoot!==round.goal.modelDataRoot||!ready.parameterProfileHashes.includes(round.goal.parameterProfileHash)||!ready.evaluatorVersions.includes(round.goal.evaluatorVersion)||!ready.nativeBinaryReady)throw new ReplayError('LOCAL_MODEL_ERROR','Frozen complete-model replay is not ready');
  const dir=join(outputDir,new PublicKey(address).toBase58());await mkdir(dir,{recursive:true,mode:0o700});
  await writeFile(join(dir,'goal.json'),canonical(round.goal));await writeFile(join(dir,'input.json'),canonical(manifest.input));
  const measurements=[];let valid=true;
  for(let j=0;j<manifest.trials.length;j++){
    const trial=manifest.trials[j],bytes=await contentStore.get(trial.resultRoot,round.goal.maxTrialBytes);
    if(bytes.length!==trial.bytes||await hash(bytes)!==trial.resultRoot)throw new ReplayError('RETRYABLE_INFRA_ERROR','Complete trial bytes unavailable');
    const file=join(dir,'trial-'+j+'-'+randomUUID()+'.tmp');await writeFile(file,bytes,{mode:0o600});
    let measurement;try{measurement=await replay(binary,[join(modelDir,'graph-v1.bin'),join(modelDir,'model-v0.bin'),join(dir,'goal.json'),join(dir,'input.json'),round.seeds[j],file,'--verify']);}finally{await unlink(file).catch(error=>{if(error.code!=='ENOENT')throw error;});}
    if(!['VALID','INVALID_RESULT'].includes(measurement.replayStatus)||measurement.fullReplay!==true||measurement.steps!==round.goal.steps)throw new ReplayError('LOCAL_MODEL_ERROR','Complete frozen replay not established');
    if(measurement.replayStatus!=='VALID'||!measurement.replayVerified||measurement.resultRoot!==trial.resultRoot||measurement.bytes!==trial.bytes||!measurement.metrics?.passed||hex(canonical(measurement.metrics))!==hex(canonical(trial.metrics)))valid=false;
    measurements.push(measurement);
  }
  if(measurements.length!==t.descriptor.seeds.length)throw new ReplayError('LOCAL_MODEL_ERROR','Missing required background');
  // Recheck after expensive computation: never attest a stale attempt.
  const latest=await reader.submission(address,s.task),current=await reader.task(t.index);
  if(current.attempt!==t.attempt||current.state!==STATE.ACTIVE||latest.state!==STATE.REVEALED)throw new ReplayError('RETRYABLE_INFRA_ERROR','Chain task changed during replay');
  const report={schema:'flybrainlabs-complete-replay-v4',submission:new PublicKey(address).toBase58(),task:new PublicKey(s.task).toBase58(),attempt:t.attempt,fullReplay:true,completeTrials:measurements.length,valid,measurements},reportBytes=canonical(report),reportHash=fromHex(await hash(reportBytes));
  await writeFile(join(dir,'replay-report.json'),reportBytes);
  return {factory:f,task:t,submission:s,report,reportHash,message:voteMessage(reader.program,f,t,new PublicKey(address),s,valid,reportHash,measurements.length)};
}
export function voteInstructions(reader,address,verified,verifier){
  if(!verified.factory.verifiers.some(k=>new PublicKey(k).equals(verifier.publicKey)))throw new Error('Verifier is not admitted');
  const keys=[meta(reader.expected.factoryAddress,true),meta(new PublicKey(verified.submission.task),true),meta(new PublicKey(address),true),instructionSysvar()];
  if(verified.factory.nextIndex<verified.factory.count)keys.push(meta(reader.a.task(reader.expected.factoryAddress,verified.factory.nextIndex),true));
  return [Ed25519Program.createInstructionWithPrivateKey({privateKey:verifier.secretKey,message:verified.message}),instruction(reader.program,keys,6,{valid:verified.report.valid,report:verified.reportHash,completeTrials:verified.report.completeTrials,ed25519Index:0})];
}
export async function watchFactoryVerifier({reader,verifier,verifyAndVote,maxVoteTransactions,onError=()=>{},onBudget=()=>{}}){
  if(!Number.isSafeInteger(maxVoteTransactions)||maxVoteTransactions<1)throw new Error('A finite verifier transaction allowance is required');
  let stopped=false,running=false,again=false,transactions=0,taskListener,taskAddress;
  const retries=new Map();
  const wake=()=>{again=true;if(!running&&!stopped)void drain();};
  async function drain(){
    if(running||stopped)return;running=true;
    try{do{again=false;const f=await reader.factory(),index=f.verifiers.findIndex(k=>new PublicKey(k).equals(verifier.publicKey));
      if(index<0)throw new Error('Verifier is not admitted by this frozen factory');
      const address=f.activeIndex===0xffffffff?null:reader.a.task(reader.expected.factoryAddress,f.activeIndex);
      if(address?.toBase58()!==taskAddress){if(taskListener!==undefined)await reader.connection.removeAccountChangeListener(taskListener);taskListener=undefined;taskAddress=address?.toBase58();if(address)taskListener=reader.connection.onAccountChange(address,wake,'finalized');}
      if(!address)continue;const t=await reader.task(f.activeIndex);
      for(const entry of t.queue){
        if(stopped)break;if(transactions>=maxVoteTransactions){stopped=true;onBudget({transactions});break;}
        const submission=new PublicKey(entry.submission),key=submission.toBase58();if((retries.get(key)||0)>Date.now())continue;
        const s=await reader.submission(submission,address);
        if(s.attempt!==t.attempt||s.state!==STATE.REVEALED||(s.validVotes|s.invalidVotes)&(1<<index))continue;
        try{await verifyAndVote(submission);transactions++;retries.delete(key);again=true;}
        catch(error){retries.set(key,Date.now()+60000);onError(error);}
      }
    }while(again&&!stopped);}catch(error){onError(error);}finally{running=false;}
  }
  const factoryListener=reader.connection.onAccountChange(reader.expected.factoryAddress,wake,'finalized'),timer=setInterval(wake,60000);wake();
  return {get transactions(){return transactions;},async stop(){stopped=true;clearInterval(timer);await reader.connection.removeAccountChangeListener(factoryListener);if(taskListener!==undefined)await reader.connection.removeAccountChangeListener(taskListener);}};
}
async function main(){
  const [path,address]=process.argv.slice(2);if(!path||!address)throw new Error('Usage: factory_verifier_v4.mjs PRIVATE_RUNTIME.json SUBMISSION_ADDRESS');
  const cfg=JSON.parse(await readFile(path,'utf8')),reader=readerForDeployment(cfg.deployment);
  const replay=address=>verifyFactorySubmission({reader,address,contentStore:new LocalFactoryContentStore(cfg.contentDir),modelDir:cfg.modelDir,outputDir:cfg.outputDir,binary:cfg.binary});
  if(cfg.submitVotes!==true){if(address==='--watch')throw new Error('Watch mode requires explicit finite vote authorization');const verified=await replay(address);console.log(JSON.stringify({verified:true,valid:verified.report.valid,completeTrials:verified.report.completeTrials,transactionSubmitted:false}));return;}
  const verifier=Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(cfg.verifierKeyFile,'utf8'))));
  const verifyAndVote=async address=>{const verified=await replay(address),tx=new Transaction().add(...voteInstructions(reader,address,verified,verifier)),signature=await sendAndConfirmTransaction(reader.connection,tx,[verifier],{commitment:'finalized'});console.log(JSON.stringify({signature,valid:verified.report.valid,completeTrials:verified.report.completeTrials}));};
  if(address==='--watch'){
    const watcher=await watchFactoryVerifier({reader,verifier,verifyAndVote,maxVoteTransactions:cfg.maxVoteTransactions,onBudget:status=>{console.log(JSON.stringify({status:'finite-verifier-allowance-exhausted',...status}));watcher.stop().catch(()=>{});},onError:e=>console.error(JSON.stringify({status:e.status||'RETRYABLE_INFRA_ERROR',message:e.message,voteCreated:false}))});
    for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>watcher.stop().catch(()=>{}));
  }else await verifyAndVote(new PublicKey(address));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(e=>{console.error(JSON.stringify({status:e.status||'RETRYABLE_INFRA_ERROR',message:e.message,voteCreated:false}));process.exitCode=1;});
