// Read actual signed HTTPS state after two real browser candidates were revealed.
// Does not submit claims, replay on the client, reset a round or create keys.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {dirname} from 'node:path';
import {api,verified} from '../tools/target_dev_identity.mjs';
import {validateRound} from '../web/target-protocol-v2.mjs';
const args=process.argv.slice(2),arg=k=>args[args.indexOf(k)+1];
const network=JSON.parse(await readFile(arg('--network-file'))),
 a=JSON.parse(await readFile(arg('--browser-a'))),b=JSON.parse(await readFile(arg('--browser-b'))),
 output=arg('--report');
assert(network.enabled&&network.developmentOnly&&!network.payment&&!network.rewards&&!network.requiredWallet);
assert(a.claim?.claimId&&b.claim?.claimId&&a.candidate.sciencePassed&&b.candidate.sciencePassed);
assert.equal(a.roundId,b.roundId);assert.notEqual(a.minerId,b.minerId);
assert.notEqual(a.claim.claimId,b.claim.claimId);
const read=async(domain,path)=>verified(network.authorityId,domain,await(await api(network.apiBase,path)).json());
const report={schema:'flypow-public-target-competition-v1',readOnly:true,developmentOnly:true,
 independentBrowserIdentities:true,independentVerifierOperators:false,controlledKnownInputs:true,
 roundId:a.roundId,goalId:a.goalId,checks:[],officialModelDownloads:0};
await mkdir(dirname(output),{recursive:true});
const save=()=>writeFile(output,JSON.stringify(report,null,2)+'\n');
const check=async s=>{report.checks.push(s);await save();console.log(JSON.stringify({passed:report.checks.length,check:s}));};
const before=await Promise.all([a,b].map(x=>read('claim-state','claims/'+x.claim.claimId)));
assert(before[0].receipt.claimSequence<before[1].receipt.claimSequence);
assert.equal(before[0].receipt.roundId,before[1].receipt.roundId);
report.receipts=before.map(x=>x.receipt);
await check('Two distinct retained HTTPS browser identities compute, commit, upload and reveal the same frozen scientific target');
const started=Date.now();let last='';
for(;;){
 const states=await Promise.all([a,b].map(x=>read('claim-state','claims/'+x.claim.claimId)));
 const round=await read('round-state','rounds/'+a.roundId);
 const status=states.map(x=>x.status+':'+x.verificationVotes).join(',');
 if(status!==last){last=status;console.log(JSON.stringify({verification:status,elapsedSeconds:Math.round((Date.now()-started)/1000)}));}
 report.claims=states;report.round=round;await save();
 if(states.every(x=>x.status==='VALID')&&round.winner){
  assert.equal(round.winner.claimId,a.claim.claimId);assert.equal(round.winner.minerId,a.minerId);
  assert(states.every(x=>x.verificationVotes>=2));
  await check('Actual cloud verifier quorum accepts both complete browser candidates and only the earlier eligible commitment wins');break;
 }
 assert(!states.some(x=>['INVALID','EXPIRED','VERIFICATION_EXPIRED'].includes(x.status)),states);
 if(Date.now()-started>50*60*1000)throw new Error('Remote full replay did not finish before the acceptance timeout');
 await new Promise(r=>setTimeout(r,10000));
}
const page=await(await api(network.apiBase,'events?after=0')).json();
for(const e of page.events)await verified(network.authorityId,'protocol-event',e);
assert.equal(page.events.filter(e=>e.kind==='ROUND_FINALIZED'&&e.roundId===a.roundId).length,1);
report.finalizedEvents=page.events.filter(e=>e.kind==='ROUND_FINALIZED'&&e.roundId===a.roundId);
const next=await read('authority-snapshot','rounds/current');
await validateRound(next.round,{networkId:network.networkId,authorityId:network.authorityId});
assert.notEqual(next.round.roundId,a.roundId);assert.notEqual(next.round.pre.goalId,a.goalId);
report.nextRound=next.round;report.controller=next.capabilities.controller;
assert.equal(next.capabilities.minComparableSuccessfulRounds,16);
await check('A single signed finalization persists and the campaign advances to a different calibrated goal without recycling the solved target');
report.passed=report.checks.length;await save();
