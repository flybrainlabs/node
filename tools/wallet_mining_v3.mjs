// Wallet Standard login and finite mining admission. Private signing material
// stays in the configured local signer; this server never accepts arbitrary CPI.
import {createServer} from 'node:http';
import {createHash,randomBytes,createPublicKey,verify as verifySignature} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {readFile,mkdir,chmod} from 'node:fs/promises';
import {dirname,resolve} from 'node:path';
import {Connection,Keypair,PublicKey,Transaction,SystemProgram} from '@solana/web3.js';
import {getAccount,getMint} from '@solana/spl-token';
import {addresses,meta,instruction,system,decodeGrant,decodeGeneration,decodeUnit,decodeMiningStage,decodeConfig,intentMessage,encodeIntent,jsonValue,hex} from './mining_v3_client.mjs';
import {inspect} from './settlement_bridge_v2.mjs';
import {id,unhex,commitment,claimId,validateManifest,validateRound,canonical} from '../web/target-protocol-v2.mjs';
import {verified,api} from './target_dev_identity.mjs';
import {WalletRpcProxy,walletRpcConfiguration} from './wallet_rpc_v3.mjs';
const digest=b=>createHash('sha256').update(b).digest('hex'),seconds=()=>Math.floor(Date.now()/1000);
const atom=(s,{zero=false}={})=>{if(typeof s!=='string'||! /^(0|[1-9][0-9]{0,19})$/.test(s))throw fail('INVALID_AMOUNT');const n=BigInt(s);if(n>0xffffffffffffffffn||(!zero&&n===0n))throw fail('INVALID_AMOUNT');return n;};
const fail=(code,status=400)=>Object.assign(new Error(code),{code,status});
const signatureKey=bytes=>createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(bytes)]),format:'der',type:'spki'});
export function verifyDetached(publicKey,message,signature){const raw=Buffer.from(signature,'base64');return raw.length===64&&raw.toString('base64')===signature&&verifySignature(null,message,signatureKey(new PublicKey(publicKey).toBytes()),raw);}
export async function verifyScientific(r,action){if(r.action!==action||! /^[a-f0-9]{64}$/.test(r.publicKey)||! /^[a-f0-9]{128}$/.test(r.signature)||! /^[A-Za-z0-9_-]{8,128}$/.test(r.requestId))throw fail('BAD_SCIENTIFIC_SIGNATURE');const {signature,...unsigned}=r;if(!verifySignature(null,unhex(await id('authority-action',unsigned)),signatureKey(unhex(r.publicKey)),Buffer.from(signature,'hex')))throw fail('BAD_SCIENTIFIC_SIGNATURE');}
export function signInMessage(input){
  return `${input.domain} wants you to sign in with your Solana account:\n${input.address}\n\n${input.statement}\n\nURI: ${input.uri}\nVersion: ${input.version}\nChain ID: ${input.chainId}\nNonce: ${input.nonce}\nIssued At: ${input.issuedAt}\nExpiration Time: ${input.expirationTime}\nRequest ID: ${input.requestId}\nResources:\n${input.resources.map(s=>'- '+s).join('\n')}`;
}
export class WalletMiningService {
  constructor(config,db,relayer,{connection=null,clock=seconds}={}){
    if(config.schema!=='flybrainlabs-wallet-mining-config-v3'||!['devnet','localnet'].includes(config.cluster)||!config.origins?.length||config.origins.some(o=>new URL(o).origin!==o)||!Array.isArray(config.units)||config.units.length<1||config.units.length>128||config.units.some(u=>! /^[a-f0-9]{64}$/.test(u.goalId)||! /^[a-f0-9]{64}$/.test(u.economicTaskId)||atom(u.rewardAtoms)===0n)||new Set(config.units.map(u=>u.economicTaskId)).size!==config.units.length||new Set(config.units.map(u=>u.goalId)).size!==config.units.length)throw fail('INVALID_CONFIGURATION');
    const rpc=walletRpcConfiguration(config);
    Object.assign(this,{config,db,relayer,clock});this.connection=connection||new Connection(rpc.upstream,{commitment:'finalized',disableRetryOnRateLimit:true,fetch:(url,options)=>fetch(url,{...options,signal:AbortSignal.timeout(15_000),redirect:'error'})});this.rpcProxy=new WalletRpcProxy(this);this.program=new PublicKey(config.programId);this.a=addresses(this.program);this.active=false;this.chainSnapshot=null;this.requests=new Map();
    if(relayer&&relayer.publicKey.toBase58()!==config.relayer)throw fail('WRONG_RELAYER');
    db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=10000; PRAGMA foreign_keys=ON;');
  }
  async initialize(){this.db.exec(await readFile(new URL('../config/wallet-mining-v3.sql',import.meta.url),'utf8'));if(!this.db.prepare('PRAGMA table_info(mining_v3_candidates)').all().some(c=>c.name==='intent_registered'))this.db.exec('ALTER TABLE mining_v3_candidates ADD COLUMN intent_registered INTEGER NOT NULL DEFAULT 0');return this;}
  async freezeAdmission(){
    await this.chain();this.db.exec('BEGIN IMMEDIATE');try{for(const u of this.config.units){const unit=this.a.unit(unhex(u.economicTaskId)).toBase58(),old=this.db.prepare('SELECT * FROM mining_v3_funded_goals WHERE goal_id=?').get(u.goalId);
      if(old&&(old.economic_task!==u.economicTaskId||old.program!==this.config.programId||old.policy!==this.config.policyHash||old.stage!==this.config.stage||old.unit_address!==unit||old.reward_atoms!==u.rewardAtoms))throw fail('FROZEN_ADMISSION_CONFLICT');
      this.db.prepare('INSERT INTO mining_v3_funded_goals VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(goal_id) DO UPDATE SET enabled=excluded.enabled').run(u.goalId,u.economicTaskId,this.config.programId,this.config.policyHash,this.config.stage,unit,u.rewardAtoms,Number(this.config.enabled));}this.db.exec('COMMIT');}catch(e){this.db.exec('ROLLBACK');throw e;}
  }
  audit(kind,wallet,claim,value){this.db.prepare('INSERT INTO mining_v3_audit(kind,wallet,claim_id,public_json,created_at) VALUES(?,?,?,?,?)').run(kind,wallet,claim,JSON.stringify(value),this.clock());}
  checkOrigin(origin){if(!this.config.origins.includes(origin))throw fail('ORIGIN_REJECTED',403);return origin;}
  async chain(){
    const snapshot=await inspect(this.connection,this.program,{genesisHash:this.config.genesisHash,mint:this.config.mint,policyHash:this.config.policyHash}),cfgInfo=await this.connection.getAccountInfo(this.a.config,'finalized');
    if(!cfgInfo?.owner.equals(this.program))throw fail('MINING_NOT_CONFIGURED',503);
    const c=decodeConfig(cfgInfo.data);if(new PublicKey(c.relayer).toBase58()!==this.config.relayer||new PublicKey(c.closeAuthority).toBase58()!==this.config.project||new PublicKey(c.rentRecipient).toBase58()!==this.config.project)throw fail('ROLE_MISMATCH',503);
    if(snapshot.settlers.map(k=>new PublicKey(Buffer.from(k,'hex')).toBase58()).join(',')!==this.config.settlers?.join(',')||new PublicKey(Buffer.from(snapshot.authority,'hex')).toBase58()!==this.config.project)throw fail('SETTLER_POLICY_MISMATCH',503);
    const stageAddress=new PublicKey(this.config.stage),stageInfo=await this.connection.getAccountInfo(stageAddress,'finalized');if(!stageInfo?.owner.equals(this.program))throw fail('STAGE_UNAVAILABLE',503);
    const stage=decodeMiningStage(stageInfo.data),budget=this.config.units.reduce((n,u)=>n+BigInt(u.rewardAtoms),0n);
    if(hex(stage.policy)!==this.config.policyHash||!this.a.miningStage(stage.id).equals(stageAddress)||stage.budget!==budget||stage.deadline.toString()!==this.config.deadline)throw fail('STAGE_POLICY_MISMATCH',503);
    let paid=0n,accepted=0n,pending=0n;const units=[];
    for(const plan of this.config.units){const address=this.a.unit(unhex(plan.economicTaskId)),info=await this.connection.getAccountInfo(address,'finalized');if(!info?.owner.equals(this.program))throw fail('UNIT_BUDGET_UNAVAILABLE',503);const u=decodeUnit(info.data);
      if(hex(u.economicTask)!==plan.economicTaskId||new PublicKey(u.stage).toBase58()!==this.config.stage||u.amount!==BigInt(plan.rewardAtoms)||u.released)throw fail('UNIT_BUDGET_MISMATCH',503);
      if(u.paid)paid+=u.amount;else if(u.accepted)accepted+=u.amount;else pending+=u.amount;
      units.push({goalId:plan.goalId,paid:u.paid,accepted:u.accepted,released:u.released});
    }
    if(stage.paid!==paid||stage.acceptedUnpaid!==accepted||stage.pendingAtoms!==pending||stage.remaining+paid+accepted+pending!==budget||BigInt(snapshot.vaults[0].balanceAtoms)<BigInt(snapshot.vaults[0].unallocatedAtoms)+stage.remaining+accepted+pending)throw fail('VAULT_LIABILITY_MISMATCH',503);
    this.chainSnapshot={snapshot,config:c,stage,units,asOf:this.clock()};return this.chainSnapshot;
  }
  challenge(origin,body){
    this.checkOrigin(origin);const wallet=new PublicKey(body.address).toBase58();if(wallet!==body.address||!PublicKey.isOnCurve(new PublicKey(wallet).toBytes()))throw fail('INVALID_WALLET');
    this.db.prepare('DELETE FROM mining_v3_challenges WHERE created_at<?').run(this.clock()-172800);
    this.db.prepare('DELETE FROM mining_v3_sessions WHERE expires_at<?').run(this.clock()-86400);
    if(this.db.prepare('SELECT COUNT(*) AS n FROM mining_v3_challenges WHERE created_at>?').get(this.clock()-300).n>=512)throw fail('LOGIN_RATE_LIMIT',429);
    if(this.db.prepare('SELECT COUNT(*) AS n FROM mining_v3_challenges WHERE wallet=? AND created_at>?').get(wallet,this.clock()-300).n>=8)throw fail('LOGIN_RATE_LIMIT',429);
    const nonce=randomBytes(20).toString('hex'),created=this.clock(),expires=created+300,input={domain:new URL(origin).host,address:wallet,statement:'Sign in to flybrainlabs on Solana '+(this.config.cluster==='devnet'?'Devnet':'localnet')+'. This does not authorize transfers.',uri:origin+'/',version:'1',chainId:'solana:'+this.config.cluster,nonce,issuedAt:new Date(created*1000).toISOString(),expirationTime:new Date(expires*1000).toISOString(),requestId:nonce,resources:['urn:solana:genesis:'+this.config.genesisHash,'urn:flybrainlabs:program:'+this.config.programId]};
    const message=signInMessage(input);this.db.prepare('INSERT INTO mining_v3_challenges VALUES(?,?,?,?,?,?,?,NULL)').run(nonce,wallet,origin,message,JSON.stringify(input),created,expires);return {input,message,expiresAt:expires,genesisHash:this.config.genesisHash};
  }
  login(origin,body){
    this.checkOrigin(origin);if(typeof body.nonce!=='string'||typeof body.signature!=='string'||typeof body.signedMessage!=='string')throw fail('BAD_LOGIN');
    this.db.exec('BEGIN IMMEDIATE');try{
      const q=this.db.prepare('SELECT * FROM mining_v3_challenges WHERE nonce=?').get(body.nonce);
      if(!q||q.used_at!==null||q.expires_at<this.clock()||q.origin!==origin||q.wallet!==body.address||q.message!==body.signedMessage||!verifyDetached(q.wallet,Buffer.from(q.message),body.signature))throw fail('BAD_LOGIN_SIGNATURE',401);
      const token=randomBytes(32).toString('hex'),csrf=randomBytes(32).toString('hex'),expires=this.clock()+28_800;
      this.db.prepare('UPDATE mining_v3_challenges SET used_at=? WHERE nonce=? AND used_at IS NULL').run(this.clock(),q.nonce);
      this.db.prepare('INSERT INTO mining_v3_sessions VALUES(?,?,?,?,?,0)').run(digest(token),digest(csrf),q.wallet,origin,expires);this.db.exec('COMMIT');return {token,csrfToken:csrf,wallet:q.wallet,expiresAt:expires,connected:true,loggedIn:true,grantAuthorized:false};
    }catch(e){this.db.exec('ROLLBACK');throw e;}
  }
  authenticate(origin,headers,mutation=false){
    this.checkOrigin(origin);const match=/^Bearer ([a-f0-9]{64})$/.exec(headers.authorization||''),session=match&&this.db.prepare('SELECT * FROM mining_v3_sessions WHERE token_hash=?').get(digest(match[1]));
    if(!session||session.revoked||session.expires_at<this.clock()||session.origin!==origin||(mutation&&digest(headers['x-mining-csrf']||'')!==session.csrf_hash))throw fail('SESSION_REQUIRED',401);return session;
  }
  logout(session){this.db.prepare('UPDATE mining_v3_sessions SET revoked=1 WHERE token_hash=?').run(session.token_hash);return {loggedIn:false,chainGrantRevoked:false};}
  async readGrant(address,wallet,{usable=false}={}){
    const observed=await this.connection.getAccountInfoAndContext(new PublicKey(address),{commitment:'finalized'});if(!observed.value?.owner.equals(this.program))throw fail('GRANT_UNAVAILABLE',409);
    const g=decodeGrant(observed.value.data);if(new PublicKey(g.miner).toBase58()!==wallet||hex(g.policy)!==this.config.policyHash||!this.a.grant(wallet,g.id).equals(new PublicKey(address))||BigInt(observed.value.lamports)<g.managementRent+g.available)throw fail('GRANT_IDENTITY',409);
    if(usable&&(g.revoked||g.expiresAt<BigInt(this.clock())||g.successes>=g.maxResults||g.spent>=g.maxSpend||g.available===0n))throw fail(g.revoked?'GRANT_REVOKED':g.expiresAt<BigInt(this.clock())?'GRANT_EXPIRED':'GRANT_LIMIT',409);
    return {g,slot:observed.context.slot,address};
  }
  async balances(session){
    const {stage}=await this.chain();const sol=await this.connection.getBalance(new PublicKey(session.wallet),'finalized');let token=0n;try{token=(await getAccount(this.connection,this.a.ata(this.config.mint,session.wallet),'finalized')).amount;}catch(e){if(!['TokenAccountNotFoundError','TokenInvalidAccountOwnerError'].includes(e.name))throw e;}
    const grants=(await this.connection.getProgramAccounts(this.program,{commitment:'finalized',filters:[{dataSize:512},{memcmp:{offset:8+32,bytes:session.wallet}}]})).filter(r=>r.account.data.subarray(0,8).toString()==='FBMGV003').map(r=>{const g=decodeGrant(r.account.data);if(hex(g.policy)!==this.config.policyHash||!this.a.grant(session.wallet,g.id).equals(r.pubkey)||BigInt(r.account.lamports)<g.managementRent+g.available)throw fail('GRANT_IDENTITY',409);return {address:r.pubkey.toBase58(),...jsonValue(g),miner:new PublicKey(g.miner).toBase58(),beneficiary:new PublicKey(g.beneficiary).toBase58(),session:new PublicKey(g.session).toBase58()};});
    return {wallet:session.wallet,solLamports:String(sol),tokenAtoms:token.toString(),mint:this.config.mint,symbol:'FBW',cluster:this.config.cluster,grants,funding:{state:stage.pendingAtoms===0n&&stage.acceptedUnpaid===0n?'complete':'funded',pendingAtoms:stage.pendingAtoms.toString(),acceptedUnpaidAtoms:stage.acceptedUnpaid.toString(),paidAtoms:stage.paid.toString()},pendingRewardAtoms:this.db.prepare("SELECT reward_atoms FROM mining_v3_candidates WHERE wallet=? AND state IN ('winner','settling','funding-required','finality-unknown')").all(session.wallet).reduce((s,r)=>s+BigInt(r.reward_atoms),0n).toString(),asOf:this.clock(),commitment:'finalized'};
  }
  async prepareGrant(session,body){
    if(!this.config.enabled||!this.relayer)throw fail('MINING_DISABLED',503);const {config:c,stage}=await this.chain(),miner=new PublicKey(session.wallet),id=randomBytes(32),generationInfo=await this.connection.getAccountInfo(this.a.generation(miner),'finalized'),generation=generationInfo?decodeGeneration(generationInfo.data).generation+1n:1n;
    if(['create','renew'].includes(body.action||'create')&&stage.pendingAtoms===0n&&stage.acceptedUnpaid===0n)throw fail('MINING_PLAN_COMPLETE',409);
    if(this.db.prepare('SELECT COUNT(*) AS n FROM mining_v3_grant_requests WHERE wallet=? AND created_at>?').get(session.wallet,this.clock()-3600).n>=12)throw fail('GRANT_REQUEST_LIMIT',429);
    if(this.db.prepare('SELECT COUNT(*) AS n FROM mining_v3_grant_requests WHERE created_at>?').get(this.clock()-3600).n>=64)throw fail('GRANT_REQUEST_LIMIT',429);
    const action=body.action||'create',keysBase=[meta(this.a.global),meta(this.a.config)],feePayer=miner;let ix,grant;
    if(action==='create'||action==='renew'){
      const sessionKey=new PublicKey(body.session),deposit=atom(body.deposit,{zero:action==='renew'}),maxSpend=atom(body.maxSpend),maxResultRent=atom(body.maxResultRent),maxResults=atom(body.maxResults),expiresAt=BigInt(body.expiresAt),now=BigInt(this.clock());
      if(!PublicKey.isOnCurve(sessionKey.toBytes())||deposit>c.maxDeposit||maxResults>64n||maxResultRent>maxSpend||expiresAt<=now||expiresAt-now>c.maxGrantLifetime)throw fail('FINITE_GRANT_LIMIT');
      let grantId=id;if(action==='renew'){const old=await this.readGrant(body.grant,session.wallet);grantId=old.g.id;if(maxSpend<old.g.spent||maxResults<old.g.successes||maxSpend>old.g.deposited+deposit-old.g.withdrawn)throw fail('FINITE_GRANT_LIMIT');}
      else if(deposit===0n||maxSpend>deposit)throw fail('FINITE_GRANT_LIMIT');
      grant=this.a.grant(miner,grantId);const keys=[...keysBase,meta(this.a.generation(miner),true),meta(grant,true),meta(miner,true,true),meta(this.relayer.publicKey,true,true),system()];ix=instruction(this.program,keys,action==='create'?4:5,{id:grantId,generation,session:sessionKey,deposit,maxSpend,maxResultRent,maxResults,expiresAt});
    }else{
      const current=await this.readGrant(body.grant,session.wallet);grant=new PublicKey(body.grant);
      if(action==='revoke')ix=instruction(this.program,[meta(this.a.global),meta(grant,true),meta(miner,false,true)],6);
      else if(action==='withdraw'){const amount=atom(body.amount);if(amount>current.g.available)throw fail('WITHDRAWAL_LIMIT');ix=instruction(this.program,[meta(this.a.global),meta(grant,true),meta(miner,true,true)],7,{amount});}
      else if(action==='close')ix=instruction(this.program,[...keysBase,meta(grant,true),meta(miner,true,true),meta(this.config.project,true)],8);
      else if(action==='rebind'){
        const row=this.db.prepare('SELECT * FROM mining_v3_candidates WHERE claim_id=? AND wallet=?').get(body.claimId,session.wallet);if(!row)throw fail('ORIGINAL_CLAIM_REQUIRED');const u=decodeUnit((await this.connection.getAccountInfo(new PublicKey(row.unit_address),'finalized')).data);if(!u.accepted||u.paid||new PublicKey(u.beneficiary).toBase58()!==session.wallet)throw fail('ORIGINAL_CLAIM_REQUIRED');
        ix=instruction(this.program,[...keysBase,meta(row.unit_address,true),meta(row.intent_address),meta(grant),meta(miner,false,true)],14,{generation:current.g.generation});
      }else throw fail('UNSUPPORTED_GRANT_ACTION');
    }
    const latest=await this.connection.getLatestBlockhash('finalized'),tx=new Transaction({feePayer,recentBlockhash:latest.blockhash}).add(ix);if(ix.keys.some(k=>k.isSigner&&k.pubkey.equals(this.relayer.publicKey)))tx.partialSign(this.relayer);
    const transaction=tx.serialize({requireAllSignatures:false,verifySignatures:false});if(transaction.length>1232)throw fail('PACKET_LIMIT');
    const requestId=randomBytes(16).toString('hex'),fee=await this.connection.getFeeForMessage(tx.compileMessage(),'finalized'),rent=await this.connection.getMinimumBalanceForRentExemption(1024,'finalized');
    this.db.prepare('INSERT INTO mining_v3_grant_requests VALUES(?,?,?,?,?,NULL,?,?)').run(requestId,session.wallet,action,grant.toBase58(),digest(tx.serializeMessage()),latest.lastValidBlockHeight,this.clock());
    return {requestId,action,grant:grant.toBase58(),generation:generation.toString(),transaction:transaction.toString('base64'),lastValidBlockHeight:latest.lastValidBlockHeight,feePayer:session.wallet,networkFeeLamports:fee.value===null?null:String(fee.value),resultRentQuoteLamports:String(rent),auxiliaryRentPayer:this.config.relayer,resultRentRecipient:this.config.project,unusedPrincipalRecipient:session.wallet,cluster:this.config.cluster,genesisHash:this.config.genesisHash};
  }
  async confirmGrant(session,body){
    const r=this.db.prepare('SELECT * FROM mining_v3_grant_requests WHERE id=? AND wallet=?').get(body.requestId,session.wallet);if(!r||typeof body.signature!=='string')throw fail('UNKNOWN_GRANT_REQUEST');
    const tx=await this.connection.getTransaction(body.signature,{commitment:'finalized',maxSupportedTransactionVersion:0});if(!tx)throw fail('CHAIN_STATUS_UNKNOWN',409);if(tx.meta?.err)throw fail('GRANT_TRANSACTION_FAILED',409);
    if(digest(tx.transaction.message.serialize())!==r.message_hash)throw fail('TRANSACTION_SCOPE_MISMATCH');this.db.prepare('UPDATE mining_v3_grant_requests SET signature=? WHERE id=?').run(body.signature,r.id);
    this.audit('GRANT_'+r.action.toUpperCase(),session.wallet,null,{grant:r.grant_address,signature:body.signature,slot:String(tx.slot),feeLamports:String(tx.meta.fee)});return {grant:r.grant_address,signature:body.signature,commitment:'finalized',slot:String(tx.slot)};
  }
  async participation(session,body){
    if(!this.config.enabled)throw fail('MINING_DISABLED',503);await verifyScientific(body.request,'wallet-participation-v3');const r=body.request,p=r.payload;
    if(p.wallet!==session.wallet)throw fail('WALLET_SCOPE');await this.readGrant(p.grant,session.wallet,{usable:true});
    const round=await verified(this.config.authorityId,'round-state',await(await api(this.config.apiBase,'rounds/'+r.roundId)).json());if(!this.config.units.some(u=>u.goalId===round.round.pre.goalId)||round.status!=='OPEN')throw fail('ROUND_NOT_FUNDED',409);
    this.db.prepare('INSERT OR IGNORE INTO mining_v3_participation VALUES(?,?,?,?,?)').run(session.wallet,r.roundId,r.publicKey,p.grant,this.clock());return {roundId:r.roundId,participated:true,serverTime:this.clock()};
  }
  async attempt(session,body){
    await verifyScientific(body.request,'wallet-attempt-v3');const r=body.request,p=r.payload;
    if(p.wallet!==session.wallet||! /^[a-f0-9]{64}$/.test(p.candidateId)||!['computing','local-invalid','local-complete','interrupted'].includes(p.state))throw fail('ATTEMPT_SCOPE');
    const old=this.db.prepare('SELECT * FROM mining_v3_attempts WHERE wallet=? AND round_id=? AND candidate_id=?').get(session.wallet,r.roundId,p.candidateId);
    if(!old){await this.participation(session,{request:body.participation});if(body.participation.roundId!==r.roundId||body.participation.publicKey!==r.publicKey||body.participation.payload.grant!==p.grant)throw fail('ATTEMPT_SCOPE');}
    else if(old.scientific_identity!==r.publicKey||old.original_grant!==p.grant)throw fail('ATTEMPT_SCOPE');
    this.db.prepare('INSERT INTO mining_v3_attempts VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(wallet,round_id,candidate_id) DO UPDATE SET state=excluded.state,updated_at=excluded.updated_at').run(session.wallet,r.roundId,p.candidateId,r.publicKey,p.grant,p.state,this.clock(),this.clock());return {candidateId:p.candidateId,state:p.state,localReportOnly:true};
  }
  async acceptCandidate(session,body){
    if(!this.config.enabled)throw fail('MINING_DISABLED',503);await verifyScientific(body.commitRequest,'claim');const req=body.commitRequest,m=body.manifest;
    const round=await verified(this.config.authorityId,'round-state',await(await api(this.config.apiBase,'rounds/'+req.roundId)).json());const r=round.round;await validateRound(r,{authorityId:this.config.authorityId});
    await validateManifest(m,r);const plan=this.config.units.find(u=>u.goalId===r.pre.goalId);if(!plan)throw fail('ROUND_NOT_FUNDED',409);
    const commit=await commitment(r,req.publicKey,m,body.salt);if(req.payload.commitment!==commit||m.roundId!==req.roundId)throw fail('CANDIDATE_BINDING');
    const cid=await claimId(req.roundId,req.publicKey,commit),u=this.a.unit(unhex(plan.economicTaskId));
    const old=this.db.prepare('SELECT * FROM mining_v3_candidates WHERE claim_id=?').get(cid);if(old){if(old.wallet!==session.wallet||old.intent_hash!==body.intentHash)throw fail('FROZEN_WALLET_CONFLICT',409);return this.registerBeforeAcceptance(old);}
    const {stage}=await this.chain();if(round.status!=='OPEN'||this.clock()>=r.pre.claimDeadline||stage.closed||stage.deadline<BigInt(this.clock()))throw fail('NEW_CLAIMS_CLOSED',409);
    const unitInfo=await this.connection.getAccountInfo(u,'finalized');if(!unitInfo?.owner.equals(this.program))throw fail('NO_UNIT_BUDGET');const frozen=decodeUnit(unitInfo.data);if(frozen.released||frozen.accepted||frozen.paid||frozen.amount!==BigInt(plan.rewardAtoms)||new PublicKey(frozen.stage).toBase58()!==this.config.stage)throw fail('NO_UNIT_BUDGET');
    if(this.db.prepare('SELECT COUNT(*) AS n FROM mining_v3_candidates WHERE unit_address=?').get(u.toBase58()).n>=16)throw fail('CANDIDATE_QUEUE_LIMIT',429);
    const {g}=await this.readGrant(body.grant,session.wallet,{usable:true}),i={genesis:new PublicKey(this.config.genesisHash),program:this.program,policy:unhex(this.config.policyHash),unitAccount:u,economicTask:unhex(plan.economicTaskId),unit:new Uint8Array(32),round:unhex(req.roundId),candidate:unhex(m.candidateId),commitment:unhex(commit),goalResult:unhex(m.goalResultRoot),manifest:unhex(await id('candidate-manifest',m)),scientificIdentity:unhex(req.publicKey),miner:new PublicKey(session.wallet),beneficiary:new PublicKey(session.wallet),grant:g.id,grantGeneration:g.generation,session:g.session,rewardAtoms:frozen.amount,maxResultRent:g.maxResultRent},message=intentMessage(i),intentHash=hex(message),intentAddress=this.a.intent(u,session.wallet,unhex(commit)),staging=this.a.staging(u,intentAddress);
    if(intentHash!==body.intentHash||!verifyDetached(g.session,message,body.sessionSignature))throw fail('FINITE_INTENT_SIGNATURE');
    this.db.exec('BEGIN IMMEDIATE');try{
    const racing=this.db.prepare('SELECT * FROM mining_v3_candidates WHERE claim_id=?').get(cid);if(racing){if(racing.wallet!==session.wallet||racing.intent_hash!==body.intentHash)throw fail('FROZEN_WALLET_CONFLICT',409);this.db.exec('COMMIT');return this.registerBeforeAcceptance(racing);}
    if(this.db.prepare('SELECT COUNT(*) AS n FROM mining_v3_candidates WHERE unit_address=?').get(u.toBase58()).n>=16)throw fail('CANDIDATE_QUEUE_LIMIT',429);
    if(this.db.prepare('SELECT claim_id FROM mining_v3_candidates WHERE wallet=? AND round_id=? AND candidate_id=?').get(session.wallet,req.roundId,m.candidateId))throw fail('SAME_WALLET_CANDIDATE_ALREADY_ACCEPTED',409);
    this.db.prepare('INSERT INTO mining_v3_candidates(claim_id,wallet,round_id,candidate_id,scientific_identity,unit_address,intent_address,staging_address,original_grant,intent_hash,intent_json,session_signature,manifest_json,state,result_address,reward_atoms,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(cid,session.wallet,req.roundId,m.candidateId,req.publicKey,u.toBase58(),intentAddress.toBase58(),staging.toBase58(),body.grant,intentHash,JSON.stringify(jsonValue(i)),body.sessionSignature,JSON.stringify(m),'accepted-awaiting-science',this.a.result(u).toBase58(),plan.rewardAtoms,this.clock(),this.clock());
    this.db.prepare('INSERT OR IGNORE INTO mining_v3_participation VALUES(?,?,?,?,?)').run(session.wallet,req.roundId,req.publicKey,body.grant,this.clock());this.audit('CANDIDATE_INTENT_PERSISTED',session.wallet,cid,{roundId:req.roundId,unit:u.toBase58(),intentHash});this.db.exec('COMMIT');
    }catch(e){this.db.exec('ROLLBACK');throw e;}
    return this.registerBeforeAcceptance(this.db.prepare('SELECT * FROM mining_v3_candidates WHERE claim_id=?').get(cid));
  }
  async registerBeforeAcceptance(row){
    const {registerCandidateIntent}=await import('./mining_relayer_v3.mjs');
    if(this.requests.has(row.claim_id))return this.requests.get(row.claim_id);
    const operation=(async()=>{for(let attempt=0;attempt<4;attempt++){if((await registerCandidateIntent(this,row)).done){this.db.prepare('UPDATE mining_v3_candidates SET intent_registered=1 WHERE claim_id=?').run(row.claim_id);this.audit('CANDIDATE_INTENT_ACCEPTED',row.wallet,row.claim_id,{intent:row.intent_address});return this.publicRecord(row);}await new Promise(done=>setTimeout(done,1800));}throw fail('INTENT_REGISTRATION_PENDING',409);})();this.requests.set(row.claim_id,operation);
    try{return await operation;}finally{this.requests.delete(row.claim_id);}
  }
  publicRecord(r){
    const v={claimId:r.claim_id,wallet:r.wallet,roundId:r.round_id,candidateId:r.candidate_id,unit:r.unit_address,intent:r.intent_address,originalGrant:r.original_grant,state:r.state,reason:r.reason,resultPda:r.result_address,rewardAtoms:r.reward_atoms,rentLamports:r.rent_lamports,signature:r.settlement_signature,finalized:r.finalized_json?JSON.parse(r.finalized_json):null,startedAt:r.created_at,asOf:r.updated_at};
    try{const claim=this.db.prepare('SELECT status,claim_sequence FROM candidate_claims WHERE claim_id=?').get(r.claim_id),round=this.db.prepare('SELECT sequence,status FROM target_rounds WHERE round_id=?').get(r.round_id);v.scientificStatus=claim?.status||'NOT_SUBMITTED';v.claimSequence=claim?.claim_sequence||null;v.roundSequence=round?.sequence||null;v.roundStatus=round?.status||null;v.validVotes=this.db.prepare('SELECT COUNT(*) AS n FROM verification_votes WHERE claim_id=? AND valid=1').get(r.claim_id).n;v.invalidVotes=this.db.prepare('SELECT COUNT(*) AS n FROM verification_votes WHERE claim_id=? AND valid=0').get(r.claim_id).n;v.quorum=2;}catch{v.scientificStatus='NODE_RECONNECTING';}return v;
  }
  history(session,{before='',limit=20}={}){
    limit=Math.max(1,Math.min(50,Number(limit)||20));let time=0,key='';if(before){const m=/^([0-9]{1,12}):([a-f0-9]{64})$/.exec(before);if(!m)throw fail('INVALID_HISTORY_CURSOR');time=Number(m[1]);key=m[2];}
    const page=this.db.prepare('SELECT round_id,MAX(started_at) AS started_at FROM mining_v3_participation WHERE wallet=? GROUP BY round_id HAVING (?=0 OR MAX(started_at)<? OR (MAX(started_at)=? AND round_id>?)) ORDER BY started_at DESC,round_id LIMIT ?').all(session.wallet,time,time,time,key,limit+1),selected=page.slice(0,limit);
    const rounds=selected.map(p=>{const candidates=this.db.prepare('SELECT * FROM mining_v3_candidates WHERE wallet=? AND round_id=? ORDER BY created_at,claim_id').all(session.wallet,p.round_id).map(r=>this.publicRecord(r));let round=null,winner=null;try{round=this.db.prepare('SELECT sequence,status FROM target_rounds WHERE round_id=?').get(p.round_id);winner=this.db.prepare('SELECT claim_id FROM round_winners WHERE round_id=?').get(p.round_id);}catch{}return {roundId:p.round_id,roundSequence:round?.sequence||null,status:round?.status||'NODE_RECONNECTING',winnerClaim:winner?.claim_id||null,startedAt:p.started_at,attemptedCandidates:this.db.prepare('SELECT COUNT(*) AS n FROM mining_v3_attempts WHERE wallet=? AND round_id=?').get(session.wallet,p.round_id).n,completedCandidates:this.db.prepare("SELECT COUNT(*) AS n FROM mining_v3_attempts WHERE wallet=? AND round_id=? AND state IN ('local-complete','local-invalid')").get(session.wallet,p.round_id).n,submittedCandidates:candidates.length,candidates,state:!candidates.length?(round&&['FINALIZED','EXPIRED_NO_VALID_RESULT'].includes(round.status)?'no-qualified-candidate':'searching'):null};});
    return {wallet:session.wallet,rounds,items:rounds.flatMap(r=>r.candidates),participation:rounds.map(r=>({roundId:r.roundId,startedAt:r.startedAt})),nextBefore:page.length>limit?selected.at(-1).started_at+':'+selected.at(-1).round_id:null,asOf:this.clock(),historySource:'persistent wallet-scoped participation and accepted candidates; local-only artifacts remain on original device'};
  }
}
export function serve(service,{host='127.0.0.1',port=8789}={}){
  const server=createServer(async(req,res)=>{
    const origin=req.headers.origin;try{
      service.checkOrigin(origin);res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json');
      if(req.method==='OPTIONS'){if(!['GET','POST'].includes(req.headers['access-control-request-method'])||(req.headers['access-control-request-headers']||'').toLowerCase().split(',').some(h=>h.trim()&&!['content-type','authorization','x-mining-csrf'].includes(h.trim())))throw fail('CORS_REJECTED',403);res.setHeader('Access-Control-Allow-Methods','GET, POST');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization, X-Mining-CSRF');res.writeHead(204);res.end();return;}
      const url=new URL(req.url,'http://localhost'),path=url.pathname.replace('/api/mining/v3/',''),mutation=req.method==='POST';let body={};if(mutation){const chunks=[];let size=0;for await(const b of req){size+=b.length;if(size>1_048_576)throw fail('BODY_LIMIT',413);chunks.push(b);}body=JSON.parse(Buffer.concat(chunks).toString());}let result;
      if(path==='challenge'&&mutation)result=service.challenge(origin,body);
      else if(path==='login'&&mutation)result=service.login(origin,body);
      else if(path==='configuration'&&!mutation)result=Object.fromEntries(['schema','enabled','cluster','rpc','genesisHash','programId','mint','policyHash','stage','deadline','budgetAtoms','units','project','relayer','settlers','authorityId','apiBase','retentionSeconds','testOnly','defaultGrant','asOf'].map(k=>[k,k==='asOf'?service.clock():service.config[k]]));
      else if(/^evidence\/[a-f0-9]{64}$/.test(path)&&!mutation){const row=service.db.prepare('SELECT * FROM mining_v3_candidates WHERE claim_id=?').get(path.slice(9));if(!row)throw fail('NOT_FOUND',404);result=service.publicRecord(row);}
      else {const session=service.authenticate(origin,req.headers,mutation);
        if(path==='rpc'&&mutation)result=await service.rpcProxy.request(body,session);
        else if(path==='logout'&&mutation)result=service.logout(session);
        else if(path==='balances'&&!mutation)result=await service.balances(session);
        else if(path==='grant/prepare'&&mutation)result=await service.prepareGrant(session,body);
        else if(path==='grant/confirm'&&mutation)result=await service.confirmGrant(session,body);
        else if(path==='participation'&&mutation)result=await service.participation(session,body);
        else if(path==='attempts'&&mutation)result=await service.attempt(session,body);
        else if(path==='candidates'&&mutation)result=await service.acceptCandidate(session,body);
        else if(path==='history'&&!mutation)result=service.history(session,Object.fromEntries(url.searchParams));
        else if(/^candidate\/[a-f0-9]{64}$/.test(path)&&!mutation){const row=service.db.prepare('SELECT * FROM mining_v3_candidates WHERE claim_id=? AND wallet=?').get(path.slice(10),session.wallet);if(!row)throw fail('NOT_FOUND',404);result=service.publicRecord(row);}
        else throw fail('NOT_FOUND',404);
      }res.end(JSON.stringify(result));
    }catch(e){res.writeHead(e.status||503);res.end(JSON.stringify({code:e.code||'RETRYABLE_INFRA_ERROR',message:e.code||'Node/RPC unavailable; financial state remains unconfirmed'}));}
  });server.headersTimeout=15_000;server.requestTimeout=30_000;server.listen(port,host);return server;
}
async function main(){
  const file=process.argv[2];if(!file)throw new Error('Usage: wallet_mining_v3.mjs PRIVATE_RUNTIME.json');const config=JSON.parse(await readFile(file,'utf8'));await mkdir(dirname(config.database),{recursive:true,mode:0o700});const db=new DatabaseSync(config.database);await chmod(config.database,0o600);
  const relayer=Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(config.relayerKeypair,'utf8')))),service=await new WalletMiningService(config,db,relayer).initialize();await service.freezeAdmission();
  serve(service,{port:config.port||8789});const {runRelayer}=await import('./mining_relayer_v3.mjs');runRelayer(service).catch(()=>{console.error('Mining relayer paused; retained durable outbox');process.exitCode=1;});
  const supplyPath=config.continuousSupplyConfig;
  if(supplyPath){const {runTaskSupply}=await import('./continuous_task_supply.mjs');runTaskSupply(service,supplyPath).catch(()=>{console.error('Task supply paused; retained catalog and signed publication requests');});}
  console.log('Wallet mining V3 listening on loopback; '+config.cluster+' only');
}
if(process.argv[1]===new URL(import.meta.url).pathname)main().catch(e=>{console.error(e.code||'Wallet mining runtime failed; check private configuration');process.exitCode=1;});
