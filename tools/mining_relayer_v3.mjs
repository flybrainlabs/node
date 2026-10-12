// Durable V3 transport and winner settlement. Scientific terminal state never
// stops financial reconciliation. Actual finalized token deltas gate "paid".
import {Keypair,PublicKey,Transaction} from '@solana/web3.js';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {addresses,meta,instruction,signatureInstruction,signedInstruction,system,instructionSysvar,settlementKeys,decodeUnit,decodeStaging,decodeFinancialIntent,decodeResult,encodeResult,intentMessage,winnerMessage,settlerPolicy,hash,text,hex,Writer,jsonValue} from './mining_v3_client.mjs';
import {decodeGlobal} from './economy_v2_client.mjs';
import {id,unhex,canonical,validateRound,validateManifest} from '../web/target-protocol-v2.mjs';
import {api,verified} from './target_dev_identity.mjs';
import {verifyScientific} from './wallet_mining_v3.mjs';
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const decodeKey=s=>s?.type==='Buffer'&&Array.isArray(s.data)&&s.data.length===32?Uint8Array.from(s.data):/^[a-f0-9]{64}$/.test(s)?unhex(s):new PublicKey(s).toBytes();
export function restoreIntent(value){const i={};for(const[k,v]of Object.entries(value))i[k]=['grantGeneration','rewardAtoms','maxResultRent'].includes(k)?BigInt(v):decodeKey(v);return i;}
export async function signerFile(path){const b=await readFile(path);return b.length===32?Keypair.fromSeed(b):Keypair.fromSecretKey(Uint8Array.from(JSON.parse(b.toString())));}
const signKey=k=>k.publicKey.toBytes();
export class MiningTransport {
  constructor(service){this.s=service;}
  async step(row,name,instructions,completed){
    const key=row.claim_id+':'+name,s=this.s;s.transportSteps||=new Map();
    if(s.transportSteps.has(key))return s.transportSteps.get(key);
    const operation=this.leasedStep(key,row,name,instructions,completed);s.transportSteps.set(key,operation);
    try{return await operation;}finally{s.transportSteps.delete(key);}
  }
  async leasedStep(key,row,name,instructions,completed){
    const s=this.s,owner=randomBytes(16).toString('hex'),acquired=s.db.prepare('INSERT INTO mining_v3_transport_leases VALUES(?,?,?) ON CONFLICT(operation_scope) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE mining_v3_transport_leases.expires_at<?').run(key,owner,s.clock()+120,s.clock());
    if(!acquired.changes)return {done:false};
    const fence=()=>{const lease=s.db.prepare('SELECT owner,expires_at FROM mining_v3_transport_leases WHERE operation_scope=?').get(key);if(lease?.owner!==owner||lease.expires_at<=s.clock())throw Object.assign(new Error('TRANSPORT_LEASE_LOST'),{code:'TRANSPORT_LEASE_LOST'});};
    try{return await this.runStep(row,name,instructions,completed,fence);}finally{s.db.prepare('DELETE FROM mining_v3_transport_leases WHERE operation_scope=? AND owner=?').run(key,owner);}
  }
  async runStep(row,name,instructions,completed,fence){
    const {s}=this,db=s.db,c=s.connection;
    if(await completed())return {done:true};
    let record=db.prepare('SELECT * FROM mining_v3_transactions WHERE claim_id=? AND step=? ORDER BY rowid DESC LIMIT 1').get(row.claim_id,name);
    if(record){
      const statuses=await c.getSignatureStatuses([record.signature],{searchTransactionHistory:true}),status=statuses.value[0];
      if(await completed()){db.prepare("UPDATE mining_v3_transactions SET state='finalized',observed_slot=?,updated_at=? WHERE operation_key=?").run(String(status?.slot||await c.getSlot('finalized')),s.clock(),record.operation_key);return {done:true,signature:record.signature};}
      const failed=status?.confirmationStatus==='finalized'&&status.err;
      if(failed)db.prepare("UPDATE mining_v3_transactions SET state='failed-finalized',error_code='CHAIN_REJECTED',updated_at=? WHERE operation_key=?").run(s.clock(),record.operation_key);
      if(!failed&&await c.getBlockHeight('finalized')<=record.last_valid_height){
        fence();await this.broadcast(record);return {done:false,signature:record.signature};
      }
      // Expired, missing history remains unknown. A replacement is allowed
      // only after the permanent/staging predicate was freshly read above;
      // immutable instruction scope and on-chain idempotence protect retries.
      if(!failed)db.prepare("UPDATE mining_v3_transactions SET state='expired-unknown',updated_at=? WHERE operation_key=?").run(s.clock(),record.operation_key);
    }
    const attempt=db.prepare('SELECT COUNT(*) AS n FROM mining_v3_transactions WHERE claim_id=? AND step=?').get(row.claim_id,name).n;
    if(attempt>=3)throw Object.assign(new Error('RETRY_BUDGET'),{code:'RETRY_BUDGET'});
    const fees=db.prepare('SELECT COUNT(*) AS n FROM mining_v3_transactions').get().n;
    if(fees>=Number(s.config.maxTransactions||96))throw Object.assign(new Error('PROJECT_FEE_BUDGET'),{code:'PROJECT_FEE_BUDGET'});
    const latest=await c.getLatestBlockhash('finalized'),tx=new Transaction({feePayer:s.relayer.publicKey,recentBlockhash:latest.blockhash}).add(...instructions);tx.sign(s.relayer);const bytes=tx.serialize();if(bytes.length>1232)throw new Error('PACKET_LIMIT');
    const fee=await c.getFeeForMessage(tx.compileMessage(),'finalized');if(fee.value===null||fee.value>20_000)throw new Error('PROJECT_FEE_LIMIT');
    const signature=encodeBase58(tx.signature),operationKey=row.claim_id+':'+name+':'+attempt;
    fence();db.prepare('INSERT INTO mining_v3_transactions(operation_key,claim_id,step,signed_bytes,signature,blockhash,last_valid_height,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,\'prepared\',?,?)').run(operationKey,row.claim_id,name,bytes.toString('base64'),signature,latest.blockhash,latest.lastValidBlockHeight,s.clock(),s.clock());
    record=db.prepare('SELECT * FROM mining_v3_transactions WHERE operation_key=?').get(operationKey);await this.broadcast(record);return {done:await completed(),signature};
  }
  async broadcast(record){
    const s=this.s;if(record.attempts>=5)return;
    s.db.prepare('UPDATE mining_v3_transactions SET attempts=attempts+1,updated_at=? WHERE operation_key=?').run(s.clock(),record.operation_key);
    try{const sent=await s.connection.sendRawTransaction(Buffer.from(record.signed_bytes,'base64'),{maxRetries:0,skipPreflight:false});if(sent!==record.signature)throw new Error('TRANSPORT_SIGNATURE_MISMATCH');s.db.prepare("UPDATE mining_v3_transactions SET state='sent',updated_at=? WHERE operation_key=?").run(s.clock(),record.operation_key);}
    catch(e){const known=e.name==='SendTransactionError'&&Array.isArray(e.logs)&&e.logs.some(line=>/failed:|Error:/.test(line));s.db.prepare("UPDATE mining_v3_transactions SET state=?,error_code=?,updated_at=? WHERE operation_key=?").run(known?'preflight-rejected':'send-unknown',known?'PREFLIGHT_REJECTED':'RPC_SEND_UNKNOWN',s.clock(),record.operation_key);}
  }
}
export function encodeBase58(bytes){const chars='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';let n=BigInt('0x'+Buffer.from(bytes).toString('hex')),out='';while(n){out=chars[Number(n%58n)]+out;n/=58n;}for(const b of bytes){if(b)break;out='1'+out;}return out;}
async function account(s,address,decoder){const a=await s.connection.getAccountInfo(new PublicKey(address),'finalized');if(!a)return null;if(!a.owner.equals(s.program))throw new Error('ACCOUNT_OWNER');return decoder(a.data);}
async function fileDigest(path){const h=createHash('sha256');for await(const b of createReadStream(path))h.update(b);return h.digest('hex');}
export async function prepareSummary(s,row,roundState,claimState){
  const r=roundState.round,m=JSON.parse(row.manifest_json),i=restoreIntent(JSON.parse(row.intent_json));await validateRound(r,{authorityId:s.config.authorityId});await validateManifest(m,r);
  if(roundState.status!=='FINALIZED'||roundState.winner?.claimId!==row.claim_id||claimState.status!=='VALID'||claimState.validVotes<2)throw new Error('FINAL_WINNER_REQUIRED');
  const votes=s.db.prepare('SELECT v.vote_json,j.job_id,j.fencing_token FROM verification_votes v JOIN verification_jobs j ON j.claim_id=v.claim_id AND j.verifier_id=v.verifier_id WHERE v.claim_id=? AND v.valid=1 ORDER BY v.verifier_id').all(row.claim_id),accepted=[];
  for(const v of votes){
    const vote=JSON.parse(v.vote_json);await verifyScientific(vote,'verifier-vote');const p=vote.payload;if(!s.config.scientificVerifierKeys.includes(vote.publicKey)||p.claimId!==row.claim_id||p.candidateId!==m.candidateId||p.roundId!==r.roundId||p.goalResultRoot!==m.goalResultRoot||p.manifestHash!==await id('candidate-manifest',m)||p.fullReplay!==true||p.completeTrials!==r.pre.requiredBackgrounds||p.valid!==true)throw new Error('REPLAY_VOTE_BINDING');
    const replay=JSON.parse(await readFile(join(s.config.replayDirectory,v.job_id+'-'+v.fencing_token,'replay-report.json'),'utf8'));
    if(replay.verifierId!==vote.publicKey||replay.claimId!==row.claim_id||!replay.fullReplay||!replay.valid||replay.measurements.length!==m.trials.length)throw new Error('FULL_REPLAY_REPORT');
    for(let j=0;j<m.trials.length;j++){const x=replay.measurements[j];if(x.replayStatus!=='VALID'||!x.fullReplay||!x.replayVerified||x.steps!==r.goal.steps||x.seedHex!==r.seeds[j]||x.resultRoot!==m.trials[j].resultRoot||Buffer.compare(Buffer.from(canonical(x.metrics)),Buffer.from(canonical(m.trials[j].metrics)))!==0)throw new Error('FULL_REPLAY_MEASUREMENT');}
    accepted.push({vote,replay});
  }
  if(new Set(accepted.map(x=>x.vote.publicKey)).size<2)throw new Error('REPLAY_QUORUM');
  const archives=s.db.prepare("SELECT upload_id,trial_index,sha256,bytes FROM candidate_artifacts WHERE claim_id=? AND status='SEALED' ORDER BY trial_index").all(row.claim_id);
  if(archives.length!==m.trials.length)throw new Error('ARCHIVE_REQUIRED');
  for(let j=0;j<archives.length;j++){const a=archives[j];if(a.trial_index!==j||a.sha256!==m.trials[j].resultRoot||a.bytes!==m.trials[j].bytes||await fileDigest(join(s.config.authorityData,'private/artifacts',a.upload_id,'response.bin'))!==a.sha256)throw new Error('ARCHIVE_COMMITMENT');}
  const g=decodeGlobal((await s.connection.getAccountInfo(s.a.global,'finalized')).data),plan=s.config.units.find(u=>u.economicTaskId===hex(i.economicTask)),archiveRoot=unhex(await id('wallet-mining-archive-v3',{manifestHash:hex(i.manifest),trials:archives.map(a=>({trialIndex:a.trial_index,sha256:a.sha256,bytes:a.bytes}))})),contribution=unhex(await id('contribution-v1',{schema:'flybrain-contribution-v1',actor:row.scientific_identity,kind:'discovery',scienceId:m.goalResultRoot,taskId:plan.scientificTaskId,budgetPlan:s.config.policyHash,authorization:row.intent_hash}));
  const roots=[i.genesis,i.program,i.policy,new PublicKey(s.config.stage).toBytes(),i.economicTask,i.unit,i.round,i.candidate,unhex(row.claim_id),contribution,unhex(r.goal.modelRoot),unhex(r.goal.graphRoot),unhex(r.goal.parameterProfileHash),i.goalResult,i.manifest,archiveRoot,i.miner,i.beneficiary,i.grant,i.session,new PublicKey(row.unit_address).toBytes(),new PublicKey(row.original_grant).toBytes(),settlerPolicy(s.program,g),unhex(await id('wallet-replay-evidence-v3',accepted.map(a=>({vote:a.vote,measurements:a.replay.measurements})))),unhex(await id('wallet-final-winner-v3',{roundId:r.roundId,winner:roundState.winner,status:roundState.status,receipt:claimState.receipt}))];
  const ms=m.trials.map(t=>t.metrics),sum=(arr)=>arr.reduce((a,b)=>a+BigInt(b),0n),min=arr=>arr.map(BigInt).reduce((a,b)=>a<b?a:b),max=arr=>arr.map(BigInt).reduce((a,b)=>a>b?a:b),representative=accepted[0].replay.measurements;
  const metrics=[sum(ms.map(v=>v.baselineSpikes)),BigInt(ms[0].stimulusCost),min(ms.map(v=>v.windows[0].targetNet)),max(ms.map(v=>v.windows[0].offTargetAbs)),min(ms.map(v=>v.windows[0].positiveCells)),min(ms.map(v=>v.windows[1].targetNet)),max(ms.map(v=>v.windows[1].offTargetAbs)),min(ms.map(v=>v.windows[1].positiveCells)),sum(representative.map(v=>v.neuronUpdates)),sum(representative.map(v=>v.synapticAdditions)),sum(m.trials.map(t=>t.bytes)),BigInt(accepted.length),BigInt(ms.length),0n,0n,0n];
  const blob=encodeResult({roots,originalGeneration:i.grantGeneration,roundSequence:BigInt(r.pre.roundSequence),claimSequence:BigInt(claimState.receipt.claimSequence),rewardAtoms:i.rewardAtoms,rentLamports:0n,acceptedAt:0n,settledSlot:0n,settledAt:0n,requiredTrials:r.pre.requiredBackgrounds,completeTrials:m.trials.length,steps:r.goal.steps,neurons:r.goal.neuronCount,metricsVersion:1,metrics});
  await mkdir(s.config.resultArchiveDirectory,{recursive:true,mode:0o700});await writeFile(join(s.config.resultArchiveDirectory,row.claim_id+'-prepared.bin'),blob,{mode:0o600});return blob;
}
export async function finalizedPayment(s,row,signature){
  await s.chain();const u=await account(s,row.unit_address,decodeUnit);if(!u?.paid)return null;
  if(new PublicKey(u.beneficiary).toBase58()!==row.wallet||u.amount.toString()!==row.reward_atoms||u.intent!==undefined&&new PublicKey(u.intent).toBase58()!==row.intent_address)throw new Error('PAID_UNIT_SCOPE');
  const tx=signature&&await s.connection.getTransaction(signature,{commitment:'finalized',maxSupportedTransactionVersion:0});if(!tx||tx.meta?.err||BigInt(tx.slot)!==u.paidSlot)return null;
  const keys=tx.transaction.message.getAccountKeys?tx.transaction.message.getAccountKeys({accountKeysFromLookups:tx.meta.loadedAddresses}).keySegments().flat():tx.transaction.message.accountKeys;
  const index=keys.findIndex(k=>k.equals(s.a.ata(s.config.mint,row.wallet))),before=tx.meta.preTokenBalances.find(b=>b.accountIndex===index),after=tx.meta.postTokenBalances.find(b=>b.accountIndex===index);
  if(!after||after.mint!==s.config.mint||after.owner!==row.wallet||BigInt(after.uiTokenAmount.amount)-BigInt(before?.uiTokenAmount.amount||'0')!==u.amount)throw new Error('FINALIZED_TOKEN_PAYMENT');
  const result=await s.connection.getAccountInfo(new PublicKey(row.result_address),'finalized');let bytes;
  if(result){if(!result.owner.equals(s.program)||result.data.length!==1024||hex(hash(result.data))!==hex(u.resultHash))throw new Error('RESULT_SCOPE');bytes=result.data;await writeFile(join(s.config.resultArchiveDirectory,row.claim_id+'-settled.bin'),bytes,{mode:0o600});}
  else if(u.closed){bytes=await readFile(join(s.config.resultArchiveDirectory,row.claim_id+'-settled.bin'));if(hex(hash(bytes))!==hex(u.resultHash))throw new Error('CLOSED_RESULT_ARCHIVE');}
  else return null;
  const r=decodeResult(bytes);if(new PublicKey(r.bindings.beneficiary).toBase58()!==row.wallet||r.rewardAtoms!==u.amount||hex(r.bindings.claim)!==row.claim_id||r.rentLamports!==u.actualRent)throw new Error('RESULT_PAYMENT_BINDING');
  return {signature,slot:String(tx.slot),commitment:'finalized',resultPda:row.result_address,resultSize:1024,resultHash:hex(u.resultHash),resultClosed:u.closed,resultClosedAt:u.closed?u.closedAt.toString():null,unit:row.unit_address,mint:s.config.mint,beneficiary:row.wallet,ata:s.a.ata(s.config.mint,row.wallet).toBase58(),rewardAtoms:u.amount.toString(),rentLamports:u.actualRent.toString(),networkFeeLamports:String(tx.meta.fee),tokenDeltaAtoms:(BigInt(after.uiTokenAmount.amount)-BigInt(before?.uiTokenAmount.amount||'0')).toString(),asOf:s.clock()};
}
export async function registerCandidateIntent(s,row){
  const a=s.a,i=restoreIntent(JSON.parse(row.intent_json)),keys=[meta(a.global),meta(a.config),meta(row.unit_address),meta(row.original_grant),meta(row.intent_address,true),meta(s.relayer.publicKey,true,true),system(),instructionSysvar()];
  return new MiningTransport(s).step(row,'register-intent',[signatureInstruction(i.session,intentMessage(i),Buffer.from(row.session_signature,'base64')),instruction(s.program,keys,9,{intent:i,ed25519Index:0})],async()=>{const x=await account(s,row.intent_address,decodeFinancialIntent);if(!x)return false;if(hex(x.hash)!==row.intent_hash)throw new Error('INTENT_CONFLICT');return true;});
}
export async function reconcileCandidate(s,row,settlers){
  const update=(state,reason=null)=>s.db.prepare('UPDATE mining_v3_candidates SET state=?,reason=?,updated_at=? WHERE claim_id=?').run(state,reason,s.clock(),row.claim_id),t=new MiningTransport(s),i=restoreIntent(JSON.parse(row.intent_json)),a=s.a;
  let u=await account(s,row.unit_address,decodeUnit);
  const priors=s.db.prepare("SELECT signature FROM mining_v3_transactions WHERE claim_id=? AND step LIKE 'settle:%' ORDER BY rowid DESC").all(row.claim_id);
  if(u?.paid&&new PublicKey(u.intent).toBase58()===row.intent_address){for(const prior of priors){const fact=await finalizedPayment(s,row,prior.signature);if(fact){s.db.prepare("UPDATE mining_v3_candidates SET state='paid-finalized',reason=NULL,settlement_signature=?,rent_lamports=?,finalized_json=?,updated_at=? WHERE claim_id=?").run(fact.signature,fact.rentLamports,JSON.stringify(fact),s.clock(),row.claim_id);return;}}if(row.finalized_json){s.db.prepare("UPDATE mining_v3_candidates SET reason='FINALIZED_HISTORY_UNAVAILABLE' WHERE claim_id=?").run(row.claim_id);return;}update('finality-unknown');return;}
  const registered=await registerCandidateIntent(s,row);if(!registered.done){update('registering-intent');return;}
  let roundState,claimState;try{[roundState,claimState]=await Promise.all([verified(s.config.authorityId,'round-state',await(await api(s.config.apiBase,'rounds/'+row.round_id)).json()),verified(s.config.authorityId,'claim-state',await(await api(s.config.apiBase,'claims/'+row.claim_id)).json())]);}catch(e){if(e.status===404){update('accepted-awaiting-science');return;}throw e;}
  if(claimState.status==='INVALID'||claimState.status==='TIMED_OUT'){update(claimState.status==='INVALID'?'science-invalid':'submission-timeout');return;}
  if(roundState.winner&&roundState.winner.claimId!==row.claim_id){update(claimState.status==='VALID'?'valid-not-selected':'not-selected');return;}
  if(roundState.status==='EXPIRED_NO_VALID_RESULT'){update('round-expired');return;}
  if(!roundState.winner){update(claimState.status==='VALID'?'verified-awaiting-arbitration':'verifying');return;}
  update('winner');let blob=row.prepared_bytes?Buffer.from(row.prepared_bytes,'base64'):await prepareSummary(s,row,roundState,claimState);
  if(!row.prepared_bytes)s.db.prepare('UPDATE mining_v3_candidates SET prepared_bytes=? WHERE claim_id=?').run(Buffer.from(blob).toString('base64'),row.claim_id);
  const preparedHash=hash(blob),createKeys=[meta(a.global),meta(a.config),meta(row.unit_address),meta(row.intent_address),meta(row.staging_address,true),meta(s.relayer.publicKey,true,true),system()];
  const created=await t.step(row,'create-staging',[instruction(s.program,createKeys,10,{expectedHash:preparedHash})],async()=>{const x=await account(s,row.staging_address,decodeStaging);if(!x)return false;if(hex(x.expectedHash)!==hex(preparedHash))throw new Error('STAGING_CONFLICT');return true;});if(!created.done){update('settling');return;}
  for(let offset=0;offset<1024;offset+=384){const end=Math.min(offset+384,1024),chunk=blob.subarray(offset,end),done=await t.step(row,'chunk-'+offset,[instruction(s.program,[meta(a.global),meta(a.config),meta(row.staging_address,true),meta(s.relayer.publicKey,false,true)],11,{offset,bytes:chunk})],async()=>{const x=await account(s,row.staging_address,decodeStaging);return x.written>=end&&Buffer.compare(Buffer.from(x.bytes.subarray(offset,end)),chunk)===0;});if(!done.done){update('settling');return;}}
  const sealed=await t.step(row,'seal',[instruction(s.program,[meta(a.global),meta(a.config),meta(row.unit_address),meta(row.intent_address),meta(row.staging_address,true),meta(s.relayer.publicKey,false,true)],12)],async()=>(await account(s,row.staging_address,decodeStaging)).sealed);if(!sealed.done)return;
  const g=decodeGlobal((await s.connection.getAccountInfo(a.global,'finalized')).data),message=winnerMessage(s.program,g,new PublicKey(row.unit_address),intentMessage(i),preparedHash);
  for(const signer of settlers.slice(0,2)){const index=g.settlers.findIndex(k=>hex(k)===hex(signKey(signer)));if(index<0)throw new Error('SETTLER_IDENTITY');const done=await t.step(row,'winner-vote-'+index,signedInstruction(s.program,[meta(a.global),meta(a.config),meta(s.config.stage,true),meta(row.unit_address,true),meta(row.intent_address),meta(row.staging_address,true),instructionSysvar()],13,{},message,signer),async()=>!!((await account(s,row.staging_address,decodeStaging)).votes&(1<<index)));if(!done.done)return;}
  u=await account(s,row.unit_address,decodeUnit);const funding=new PublicKey(u.fundingGrant).toBase58();
  try{const {g:grant}=await s.readGrant(funding,row.wallet,{usable:true});if(grant.generation!==u.fundingGeneration)throw new Error('GENERATION_REBIND_REQUIRED');const quote=BigInt(await s.connection.getMinimumBalanceForRentExemption(1024)),prepaid=BigInt((await s.connection.getAccountInfo(a.result(new PublicKey(row.unit_address))))?.lamports||0),actualRent=quote>prepaid?quote-prepaid:0n;if(actualRent>grant.maxResultRent||actualRent>grant.available||grant.spent+actualRent>grant.maxSpend)throw new Error('GRANT_LIMIT');}
  catch(e){const reason=e.code||e.message;if(['GRANT_UNAVAILABLE','GRANT_IDENTITY','GRANT_REVOKED','GRANT_EXPIRED','GRANT_LIMIT','GENERATION_REBIND_REQUIRED'].includes(reason)){update('funding-required',reason);return;}throw e;}
  const keys=settlementKeys(a,{stage:s.config.stage,unit:row.unit_address,intent:row.intent_address,staging:row.staging_address,grant:funding,mint:s.config.mint,miner:row.wallet,relayer:s.relayer.publicKey});
  const paid=await t.step(row,'settle:'+funding+':'+u.fundingGeneration,[instruction(s.program,keys,15)],async()=>(await account(s,row.unit_address,decodeUnit)).paid);if(paid.signature)s.db.prepare('UPDATE mining_v3_candidates SET settlement_signature=? WHERE claim_id=?').run(paid.signature,row.claim_id);update('settling');
}
export async function runRelayer(s,{once=false}={}){
  const settlers=await Promise.all(s.config.settlerKeypairs.map(signerFile)),owner=randomBytes(16).toString('hex');
  for(;;){
    const rows=s.db.prepare("SELECT * FROM mining_v3_candidates WHERE (state NOT IN ('paid-finalized','science-invalid','valid-not-selected','not-selected','submission-timeout','round-expired') OR (state='paid-finalized' AND updated_at<?)) ORDER BY CASE WHEN state='paid-finalized' THEN 1 ELSE 0 END,created_at,claim_id LIMIT 8").all(s.clock()-120);
    for(const row of rows){const lock=s.db.prepare('UPDATE mining_v3_candidates SET lease_owner=?,lease_until=? WHERE claim_id=? AND (lease_until<? OR lease_owner=?)').run(owner,s.clock()+120,row.claim_id,s.clock(),owner);if(!lock.changes)continue;
      try{await reconcileCandidate(s,row,settlers);}catch(e){console.error(JSON.stringify({kind:'wallet-settlement-retry',code:e.code||'NODE_OR_RPC_RETRY',errorClass:e.name,detail:['ReferenceError','TypeError'].includes(e.name)?e.message:undefined}));s.db.prepare("UPDATE mining_v3_candidates SET reason=?,updated_at=? WHERE claim_id=?").run(['RETRY_BUDGET','PROJECT_FEE_BUDGET','CHAIN_REJECTED'].includes(e.code)?e.code:'NODE_OR_RPC_RETRY',s.clock(),row.claim_id);}
      finally{s.db.prepare('UPDATE mining_v3_candidates SET lease_until=0 WHERE claim_id=? AND lease_owner=?').run(row.claim_id,owner);}
    }
    if(once)return;await pause(2500);
  }
}
