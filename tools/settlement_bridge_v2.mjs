// Chain inspector and recoverable payment transport. Callers keep intents in a
// private durable directory; no formal asset or transaction is created here.
import {Connection,PublicKey,Transaction} from '@solana/web3.js';
import {getMint,getAccount,TOKEN_PROGRAM_ID} from '@solana/spl-token';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {addresses,decodeGlobal,decodeSlot,CAP,POOLS} from './economy_v2_client.mjs';
import {Reader,hex} from '../web/campaign-codec.mjs';
export async function inspect(connection,program,expected={}){
 const pid=new PublicKey(program),a=addresses(pid),genesis=await connection.getGenesisHash(),globalObservation=await connection.getAccountInfoAndContext(a.global,{commitment:'finalized'}),globalInfo=globalObservation.value;
 if(!globalInfo||!globalInfo.owner.equals(pid))throw new Error('Wrong global account owner');const g=decodeGlobal(globalInfo.data);
 if(hex(g.network)!==hex(new PublicKey(genesis).toBytes())||(expected.genesisHash&&expected.genesisHash!==genesis))throw new Error('Wrong chain identity');
 if(expected.policyHash&&hex(g.policy)!==expected.policyHash)throw new Error('Wrong frozen policy');
 const mint=new PublicKey(g.mint);if(expected.mint&&expected.mint!==mint.toBase58())throw new Error('Wrong asset');
 const m=await getMint(connection,mint,'finalized',TOKEN_PROGRAM_ID);validateIssuedMint(g,m);
 const pi=await connection.getAccountInfo(pid,'finalized');if(!pi?.executable)throw new Error('Program is not executable');
 const vaultObservation=await connection.getMultipleAccountsInfoAndContext([a.pool(0),a.pool(1),a.pool(2)],{commitment:'finalized'});const {unpackAccount}=await import('@solana/spl-token');
 const vaults=[];for(let i=0;i<3;i++){if(!vaultObservation.value[i])throw new Error('Vault unavailable');const v=unpackAccount(a.pool(i),vaultObservation.value[i],TOKEN_PROGRAM_ID);if(!v.owner.equals(a.global)||!v.mint.equals(mint)||g.available[i]>POOLS[i]||v.delegate||v.closeAuthority)throw new Error('Vault or allocation identity');vaults.push({address:a.pool(i).toBase58(),balanceAtoms:v.amount.toString(),unallocatedAtoms:g.available[i].toString()});}
 if(vaults.reduce((sum,v)=>sum+BigInt(v.balanceAtoms),0n)>m.supply)throw new Error('Vault balances exceed current asset supply');
 return {schema:'flybrain-chain-inspection-v2',programId:pid.toBase58(),genesisHash:genesis,mint:mint.toBase58(),global:a.global.toBase58(),policyHash:hex(g.policy),authority:hex(g.authority),settlers:g.settlers.map(hex),capAtoms:CAP.toString(),currentSupplyAtoms:m.supply.toString(),burnedAtoms:(CAP-m.supply).toString(),issuanceProof:'program-owned global issued flag; original Issue/Adopt enforces CAP and authority revocation',vaults,finality:'finalized',upgradeTrust:'inspect-loader-upgrade-authority-before-formal-activation',chainObservation:{global:{contextSlot:String(globalObservation.context.slot),commitment:'finalized',method:'getAccountInfoAndContext'},vaults:{contextSlot:String(vaultObservation.context.slot),commitment:'finalized',method:'getMultipleAccountsInfoAndContext'},snapshot:'distinct actual contexts; minContextSlot is only a lower bound'},formalAssetApproved:false};
}
export function validateIssuedMint(global,mint){if(!global.issued||typeof mint.supply!=='bigint'||mint.supply<0n||mint.supply>CAP||mint.decimals!==8||mint.mintAuthority!==null||mint.freezeAuthority!==null)throw new Error('Issuance or authority state incomplete');return {issuedCapAtoms:CAP.toString(),currentSupplyAtoms:mint.supply.toString(),burnedAtoms:(CAP-mint.supply).toString()};}
export async function paymentOutcome(connection,program,intent){
 const pid=new PublicKey(program);
 for(const key of ['genesisHash','programId','mint','policyHash','beneficiaryHex','slot','paymentId'])if(typeof intent[key]!=='string'||!intent[key])throw new Error('Frozen payment identity required: '+key);
 if(intent.programId!==pid.toBase58())throw new Error('Frozen program mismatch');
 const inspection=await inspect(connection,pid,{genesisHash:intent.genesisHash,mint:intent.mint,policyHash:intent.policyHash});
 const a=addresses(pid),slot=new PublicKey(intent.slot);
 const slotInfo=await connection.getAccountInfo(slot,'finalized');if(!slotInfo)return {state:'inflight-unknown',safeToUnlock:false,reason:'slot-unavailable'};
 if(!slotInfo.owner.equals(pid))throw new Error('Frozen slot owner mismatch');const frozen=decodeSlot(slotInfo.data);
 if(!a.slot(frozen.economicTask,frozen.kind,frozen.unit).equals(slot)||hex(frozen.beneficiary)!==intent.beneficiaryHex||!frozen.accepted||frozen.released)throw new Error('Frozen slot/recipient mismatch');
 const payment=a.payment(slot,Uint8Array.from(Buffer.from(intent.paymentId,'hex')));
 const read=async minContextSlot=>{const result=await connection.getAccountInfoAndContext(payment,{commitment:'finalized',...(minContextSlot==null?{}:{minContextSlot})});return result;};
 const verify=info=>{if(!info.owner.equals(pid))throw new Error('Wrong consumption owner');const r=new Reader(info.data);if(Buffer.from(r.bytes(8)).toString()!=='FLYPV002')throw new Error('Wrong payment discriminator');if(hex(r.key())!==hex(slot.toBytes())||hex(r.key())!==intent.paymentId||r.u64().toString()!==intent.amountAtoms||hex(r.key())!==intent.beneficiaryHex||info.data.slice(r.p).some(x=>x!==0))throw new Error('Payment identity mismatch');};
 const observed=await read();if(observed.value){verify(observed.value);return {state:'paid',consumptionVerified:true,contextSlot:String(observed.context.slot),commitment:'finalized',consumptionPda:payment.toBase58()};}
 const statuses=await connection.getSignatureStatuses([intent.signature],{searchTransactionHistory:true}),s=statuses.value[0];
 if(s?.confirmationStatus==='finalized'&&!s.err)throw new Error('Finalized transaction lacks expected consumption: operator reconciliation required');
 const height=await connection.getBlockHeight('finalized');
 if(height>intent.lastValidBlockHeight){
  // A null status (including pruned history) never proves non-execution. A
  // proven finalized failure still requires a fresh post-expiry receipt check.
  if(!s||s.confirmationStatus!=='finalized'||!s.err)return {state:'inflight-unknown',safeToUnlock:false,reason:'history-unavailable-or-not-finalized'};
  const tip=await connection.getSlot('finalized'),rechecked=await read(Math.max(tip,s.slot||0));
  if(rechecked.value){verify(rechecked.value);return {state:'paid',consumptionVerified:true,contextSlot:String(rechecked.context.slot),commitment:'finalized',consumptionPda:payment.toBase58()};}
  if(rechecked.context.slot<tip)return {state:'inflight-unknown',safeToUnlock:false};
  return {state:'failed-proven-unexecuted',transactionExpired:true,consumptionAbsent:true,finalizedExpiredRecheck:true,reliableHistory:true,contextSlot:String(rechecked.context.slot),commitment:'finalized'};
 }
 return {state:'inflight-unknown',safeToUnlock:false};
}
export function validateIntentTransaction(program,intent){
 const tx=Transaction.from(Buffer.from(intent.signedTransaction,'base64')),pid=new PublicKey(program),slot=new PublicKey(intent.slot),consumption=addresses(pid).payment(slot,Uint8Array.from(Buffer.from(intent.paymentId,'hex')));
 const match=tx.instructions.filter(ix=>ix.programId.equals(pid)&&ix.data[0]===5).some(ix=>{try{const r=new Reader(ix.data.subarray(1));return ix.keys[2].pubkey.equals(slot)&&ix.keys[5].pubkey.equals(consumption)&&hex(r.key())===intent.paymentId&&r.u64().toString()===intent.amountAtoms;}catch{return false;}});
 if(!match||!tx.verifySignatures())throw new Error('Frozen payment does not match signed transaction');
 const signature=tx.signature;if(!signature||bs58Encode(signature)!==intent.signature)throw new Error('Frozen transaction signature mismatch');
}
function bs58Encode(bytes){const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';let n=BigInt('0x'+Buffer.from(bytes).toString('hex')),s='';while(n>0n){s=alphabet[Number(n%58n)]+s;n/=58n;}for(const b of bytes){if(b)break;s='1'+s;}return s;}
export async function transport(connection,program,intentFile){
 const intent=JSON.parse(await readFile(intentFile,'utf8'));if(!intent.signedTransaction||!intent.signature||!intent.paymentId)throw new Error('Durable signed intent is required before broadcast');
 const persist=async outcome=>{const temp=intentFile+'.observed-'+process.pid;await writeFile(temp,JSON.stringify({...intent,lastObservation:outcome,observedAt:Math.floor(Date.now()/1000)},null,2)+'\n',{mode:0o600});await rename(temp,intentFile);return outcome;};
 validateIntentTransaction(program,intent);
 const outcome=await paymentOutcome(connection,program,intent);if(outcome.state!=='inflight-unknown')return persist(outcome);
 try{const returned=await connection.sendRawTransaction(Buffer.from(intent.signedTransaction,'base64'),{skipPreflight:false,maxRetries:0});if(returned!==intent.signature)throw new Error('Transaction identity mismatch');}catch(e){if(e.message==='Transaction identity mismatch')throw e;return persist({state:'inflight-unknown',safeToUnlock:false});}
 // A submitted transaction never reports paid before the on-chain marker.
 return persist(await paymentOutcome(connection,program,intent));
}
if(process.argv[1]?.endsWith('settlement_bridge_v2.mjs')){const args=process.argv.slice(2),value=n=>args[args.indexOf('--'+n)+1];if(!args.includes('--rpc')||!args.includes('--program'))throw new Error('usage: --rpc URL --program PUBKEY [--expected CONFIG] [--output REPORT]');const report=await inspect(new Connection(value('rpc'),'finalized'),value('program'),args.includes('--expected')?JSON.parse(await readFile(value('expected'),'utf8')):{});if(args.includes('--output'))await writeFile(value('output'),JSON.stringify(report,null,2)+'\n',{mode:0o600});console.log(JSON.stringify({inspected:true,finality:report.finality,formalAssetApproved:false}));}
