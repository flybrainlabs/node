// Synthetic process faults only; complete-model acceptance runs separately.
import assert from 'node:assert/strict';
import {mkdtemp,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {nativeReply,ReplayError} from '../tools/candidate_verifier_v2.mjs';
import {validateIssuedMint} from '../tools/settlement_bridge_v2.mjs';
import {CAP} from '../tools/economy_v2_client.mjs';
const dir=await mkdtemp('data/prepared/replay-fault-v3-');
for(const status of ['LOCAL_MODEL_ERROR','RETRYABLE_INFRA_ERROR','UNKNOWN']){const file=join(dir,status+'.mjs');await writeFile(file,`console.log(JSON.stringify({replayStatus:"${status}",fullReplay:false,reason:"injected process failure"}));process.exitCode=1;`);await assert.rejects(nativeReply(process.execPath,[file]),e=>e instanceof ReplayError&&e.status!=='INVALID_RESULT'&&e.fullReplay===false);}
await assert.rejects(nativeReply(join(dir,'missing-binary'),[]),e=>e.status==='RETRYABLE_INFRA_ERROR'&&e.fullReplay===false);
const legacy=join(dir,'unstructured.mjs');await writeFile(legacy,'console.error("native process failed");process.exitCode=1;');await assert.rejects(nativeReply(process.execPath,[legacy]),e=>e.status==='RETRYABLE_INFRA_ERROR');
const mint={supply:CAP-17n,decimals:8,mintAuthority:null,freezeAuthority:null};assert.equal(validateIssuedMint({issued:true},mint).burnedAtoms,'17');
for(const bad of [{...mint,supply:CAP+1n},{...mint,mintAuthority:'unexpected'},{...mint,freezeAuthority:'unexpected'},{...mint,decimals:9}])assert.throws(()=>validateIssuedMint({issued:true},bad));assert.throws(()=>validateIssuedMint({issued:false},mint));
console.log(JSON.stringify({processFaultCases:5,legalBurnSupply:true,invalidIssuanceStatesRejected:5,scientificAcceptanceClaimed:false}));
