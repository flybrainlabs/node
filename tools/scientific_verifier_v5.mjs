import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {PublicKey,Ed25519Program} from '@solana/web3.js';
import {canonical} from '../web/target-protocol-v2.mjs';
import {hex,fromHex,contentRoot,inputIdentity,computationIdentity,backgroundSeeds,voteMessage,STATES} from '../web/scientific-round-v5.mjs';
import {instruction,meta,instructionSysvar} from '../web/scientific-client-v5.mjs';
export async function verifyScientificClaim({reader,roundAddress,claimAddress,contentStore,worker,outputDir}){
  const started=performance.now(),r=await reader.round(roundAddress),c=await reader.claim(claimAddress,roundAddress),content=await reader.content(r,contentStore);
  if(c.state!==STATES.REVEALED||r.closed||!r.challenge.some(x=>x))throw new Error('Scientific claim is no longer eligible');
  const bytes=await contentStore.get(hex(c.manifest),1024*1024),manifest=JSON.parse(new TextDecoder().decode(bytes));
  const seeds=backgroundSeeds(r,c.role,c.assignment),computation=hex(computationIdentity(r,c.role,c.assignment,inputIdentity(manifest.input)));
  if(hex(contentRoot(manifest))!==hex(c.manifest)||manifest.schema!=='flybrain-scientific-manifest-v5'||manifest.round!==new PublicKey(roundAddress).toBase58()
    ||hex(inputIdentity(manifest.input))!==hex(c.input)||computation!==hex(c.computation)||manifest.computation!==computation
    ||manifest.analysis!==hex(r.specification.analysis)||manifest.role!==c.role||manifest.assignment!==c.assignment
    ||manifest.trials?.length!==seeds.length||hex(contentRoot(manifest.trials))!==hex(c.result))throw new Error('Committed scientific manifest mismatch');
  const dir=join(outputDir,new PublicKey(claimAddress).toBase58());await mkdir(dir,{recursive:true,mode:0o700});
  const measurements=[];let total=0,complete=true,passed=true;
  for(let j=0;j<seeds.length;j++){
    const trial=manifest.trials[j];
    if(trial.seedHex!==seeds[j]||trial.index!==j||!Number.isSafeInteger(trial.bytes)||trial.bytes<480||trial.bytes>content.goal.maxTrialBytes||!/^[a-f0-9]{64}$/.test(trial.resultRoot))throw new Error('Scientific trial order or limit');
    total+=trial.bytes;if(total>content.goal.maxCandidateBytes)throw new Error('Scientific aggregate limit');
    const archive=await contentStore.get(trial.resultRoot,trial.bytes);
    if(archive.length!==trial.bytes)throw new Error('Scientific evidence unavailable');
    const responsePath=join(dir,'trial-'+j+'.bin');await writeFile(responsePath,archive,{mode:0o600});
    const m=await worker.run({goal:content.goal,input:manifest.input,seedHex:seeds[j],responsePath,verify:true});
    if(m.verificationMethod!=='exact-events-v1'||m.steps!==content.goal.steps||m.offTargetCoverage!=='all-outside-response-set')throw new Error('Scientific model checker is not ready');
    if(!m.completeModelVerified||m.resultRoot!==trial.resultRoot||m.bytes!==trial.bytes||hex(contentRoot(m.metrics))!==hex(contentRoot(trial.metrics)))complete=false;
    passed=passed&&m.scientificPassed;
    const {pureComputeMs,elapsedMs,...observation}=m;
    measurements.push({...observation,pureComputeMicros:Math.round(pureComputeMs*1000),elapsedMicros:Math.round(elapsedMs*1000)});
  }
  const latest=await reader.claim(claimAddress,roundAddress);
  if(latest.state!==STATES.REVEALED||hex(latest.manifest)!==hex(c.manifest))throw new Error('Scientific claim changed during verification');
  const report={schema:'flybrain-scientific-verification-v5',round:new PublicKey(roundAddress).toBase58(),claim:new PublicKey(claimAddress).toBase58(),manifest:hex(c.manifest),
    computation,analysis:hex(r.specification.analysis),verificationMethod:'exact-events-v1',complete,passed:complete&&passed,
    completeTrials:measurements.length,measurements,elapsedMs:Math.ceil(performance.now()-started),independentOperators:false};
  const reportHash=contentRoot(report);await contentStore.put(hex(reportHash),canonical(report));
  return {round:r,claim:c,report,reportHash};
}
export function scientificVoteInstructions(reader,claimAddress,verified,signer){
  const {round:r,claim:c,report,reportHash}=verified;
  if(!r.verifiers.some(k=>new PublicKey(k).equals(signer.publicKey)))throw new Error('Scientific verifier is not admitted');
  const message=voteMessage(reader.program,r,new PublicKey(claimAddress),c,report.complete,report.passed,reportHash);
  return [Ed25519Program.createInstructionWithPrivateKey({privateKey:signer.secretKey,message}),instruction(reader.program,[meta(new PublicKey(c.round)),meta(claimAddress,true),instructionSysvar()],4,{complete:report.complete,passed:report.passed,report:reportHash,ed25519Index:0})];
}
