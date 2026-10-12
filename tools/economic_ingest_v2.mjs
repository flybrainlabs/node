// Durable threshold-signed financial observation transport. Facts originate in
// reviewed on-chain inspection; this CLI never invents a transaction or funds.
import {readFile,mkdir,writeFile,rename,readdir,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {sign as nodeSign} from 'node:crypto';
import {keyFile,request} from './target_dev_identity.mjs';
import {Connection} from '@solana/web3.js';
import {inspect} from './settlement_bridge_v2.mjs';
import {decodeInstructions} from './explorer_chain_indexer.mjs';
import {id,unhex} from '../web/target-protocol-v2.mjs';
const args=process.argv.slice(2),value=n=>args[args.indexOf('--'+n)+1];
if(!args.includes('--api')||!args.includes('--outbox'))throw new Error('usage: --api URL --outbox PRIVATE_DIR [--fact REVIEWED_FACT.json --admin-key PATH --witness-keys PATH,PATH --inspection REVIEWED_CHAIN.json]');
const api=new URL(value('api'));if(api.protocol!=='https:'&&!['localhost','127.0.0.1'].includes(api.hostname))throw new Error('HTTPS or loopback required');
const dir=value('outbox');await mkdir(dir,{recursive:true,mode:0o700});
async function existingKey(path){if((await stat(path)).size!==32)throw new Error('Existing raw32 signing key required');return keyFile(path);}
async function durable(path,v){const temp=path+'.tmp-'+process.pid;await writeFile(temp,JSON.stringify(v)+'\n',{flag:'wx',mode:0o600});await rename(temp,path);}
async function observe(fact){
 if(!args.includes('--rpc'))throw new Error('Fresh RPC observation is required; original event retained');
 const connection=new Connection(value('rpc'),'finalized'),inspection=await inspect(connection,fact.programId,{genesisHash:fact.genesisHash,mint:fact.mint,policyHash:fact.policyHash});
 const location=fact.sourceLocator;if(!location||location.signature!==fact.transaction||location.genesisHash!==fact.genesisHash||!Array.isArray(location.instructionPath))throw new Error('Stable source location required');
 const transaction=await connection.getTransaction(fact.transaction,{commitment:'finalized',maxSupportedTransactionVersion:0});
 if(!transaction)throw new Error('HISTORY_UNAVAILABLE: cannot refresh by inventing an observation');
 const decoded=decodeInstructions(transaction,{programId:fact.programId}),position=decoded.instructions.find(i=>JSON.stringify(i.instructionPath)===JSON.stringify(location.instructionPath));
 const expected={'global-issued':'Issue','stage-opened':'OpenStage','slot-reserved':'ReserveTask','right-confirmed':'Accept','payment-submitted':'Claim','payment-finalized':'Claim','slot-released':'ReleaseUnaccepted','stage-cancelled':'CloseStage'}[fact.kind];
 if(transaction.meta?.err||!position||position.instruction!==expected)throw new Error('Finalized chain instruction does not match immutable fact');
 if(position.slotPda&&fact.data?.slotId!==position.slotPda)throw new Error('Frozen slot/source mismatch');
 if(position.amountAtoms&&fact.data?.amountAtoms&&position.amountAtoms!==fact.data.amountAtoms)throw new Error('Frozen payment/source amount mismatch');
 const context=await connection.getSlot('finalized');return {observedAt:Math.floor(Date.now()/1000),commitment:'finalized',contextSlot:String(context),transactionSlot:String(transaction.slot),method:'getTransaction finalized; getSlot actual current context; these are distinct views',transactionSha256:await id('economic-rpc-transaction-v1',{signature:fact.transaction,slot:String(transaction.slot),instructions:decoded.instructions}),chainInspection:inspection.chainObservation};
}
async function envelopeFor(fact){
 const paths=value('witness-keys').split(',');if(paths.length<2)throw new Error('Two admitted observers required');const keys=await Promise.all(paths.map(existingKey));if(new Set(keys.map(k=>k.publicKey)).size!==keys.length)throw new Error('Distinct observers required');
 const observation=await observe(fact),digest=unhex(await id('economic-chain-observation-v2',{fact,observation})),witnesses=keys.map(k=>({publicKey:k.publicKey,signature:nodeSign(null,digest,k.key).toString('hex')}));
 return request(await existingKey(value('admin-key')),'economic-operation','',{fact,observation,witnesses},'economic-event-'+fact.eventId+'-'+observation.observedAt);
}
if(args.includes('--fact')){
 const fact=JSON.parse(await readFile(value('fact'),'utf8'));if(!/^[a-f0-9]{64}$/.test(fact.eventId))throw new Error('Event identity');
 const envelope=await envelopeFor(fact),file=join(dir,fact.eventId+'.json');
 try{const prior=JSON.parse(await readFile(file,'utf8'));if(JSON.stringify(prior.envelope.payload.fact)!==JSON.stringify(fact))throw new Error('Immutable fact already exists');await durable(file,{...prior,envelope,state:prior.state==='committed'?'committed':'pending',observations:[...(prior.observations||[]),envelope.payload]});}catch(e){if(e.code!=='ENOENT')throw e;await durable(file,{envelope,state:'pending',observations:[envelope.payload]});}
}
const pending=[];for(const name of await readdir(dir)){if(!/^[a-f0-9]{64}\.json$/.test(name))continue;const path=join(dir,name),v=JSON.parse(await readFile(path,'utf8'));if(['pending','quarantined'].includes(v.state))pending.push({path,v});}
const rank={'global-issued':0,'stage-opened':1,'slot-reserved':2,'right-confirmed':3,'payment-submitted':4,'payment-finalized':5,'payment-proven-unexecuted':5,'slot-released':3,'stage-cancelled':6};
pending.sort((a,b)=>{const x=a.v.envelope.payload.fact,y=b.v.envelope.payload.fact,sx=BigInt(x.sourceLocator?.slot||0),sy=BigInt(y.sourceLocator?.slot||0);return sx<sy?-1:sx>sy?1:(rank[x.kind]??99)-(rank[y.kind]??99);});
let committed=0,quarantined=0;for(const {path,v}of pending){
 try{
 if(args.includes('--refresh')){const envelope=await envelopeFor(v.envelope.payload.fact);v.envelope=envelope;v.observations=[...(v.observations||[]),envelope.payload];await durable(path,v);}
 const response=await fetch(api.origin+'/api/economy/ingest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(v.envelope),signal:AbortSignal.timeout(60000)});const result=await response.json();
 if(!response.ok)throw new Error(result.code||result.error||'Economic ingestion rejected; durable envelope retained');
 await durable(path,{...v,state:'committed',receipt:result});committed++;
 }catch(e){await durable(path,{...v,state:'quarantined',errorCode:e.message.split(':')[0],retryable:true});quarantined++;}
}
console.log(JSON.stringify({committed,quarantined,pending:pending.length-committed,formalTransactionCreated:false}));
