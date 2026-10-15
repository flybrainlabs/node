#!/usr/bin/env node
// One serial native replay lane, frozen trusted verifier keys and finite,
// persistent transaction allowances. No task content is generated here.
import {readFile,writeFile,mkdir,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {Connection,Keypair,PublicKey} from '@solana/web3.js';
import {getAssociatedTokenAddressSync,createAssociatedTokenAccountIdempotentInstruction} from '@solana/spl-token';
import {readerForDeployment} from '../web/task-factory-client-v4.mjs';
import {STATE,hex,fromHex,voteMessage} from '../web/task-factory-v4-codec.mjs';
import {canonical,hash} from '../web/target-protocol-v2.mjs';
import {FactoryGatewayV4,serveFactoryGatewayV4} from './factory_gateway_v4.mjs';
import {verifyFactorySubmission,LocalFactoryContentStore,voteInstructions} from './factory_verifier_v4.mjs';
import {instruction,meta,TOKEN_PROGRAM_ID} from './task_factory_v4_client.mjs';
import {DevnetJournal} from './devnet_journal.mjs';

const signerFile=async file=>{const bytes=await readFile(file);return bytes.length===32?Keypair.fromSeed(bytes):Keypair.fromSecretKey(Uint8Array.from(JSON.parse(bytes.toString())));};
export function verifierRpcFetchV4(endpoint,transport=globalThis.fetch){
  let genesis=null,pending=null;
  return async(url,options)=>{
    if(String(url)!==endpoint)return transport(url,options);
    const request=JSON.parse(options.body);
    if(request.method!=='getGenesisHash')return transport(url,options);
    const response=value=>new Response(JSON.stringify({...value,id:request.id}),{headers:{'Content-Type':'application/json'}});
    if(genesis&&genesis.until>Date.now())return response(genesis.value);
    if(!pending)pending=(async()=>{const result=await transport(url,options);if(!result.ok)throw new Error('Verifier chain identity temporarily unavailable');const value=await result.json();if(value.error||value.result!=='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG')throw new Error('Wrong verifier chain identity');genesis={value,until:Date.now()+60000};return value;})().finally(()=>pending=null);
    return response(await pending);
  };
}
export async function runFactoryVerifierV4(config,{reader,gateway,verify=verifyFactorySubmission,onStatus=()=>{}}){
  if(config.submitVotes!==true||!Number.isSafeInteger(config.maxTransactionsPerVerifier)||config.maxTransactionsPerVerifier<1||config.maxTransactionsPerVerifier>96)throw new Error('Finite verifier authorization required');
  const signers=await Promise.all(config.verifierKeyFiles.map(signerFile));if(signers.length!==2)throw new Error('Two actual admitted trusted keys are required');
  const initial=await reader.factory();for(const signer of signers)if(!initial.verifiers.some(k=>new PublicKey(k).equals(signer.publicKey)))throw new Error('Existing verifier identity differs from the frozen factory');
  const journals=[];await mkdir(config.journalDir,{recursive:true,mode:0o700});
  for(const signer of signers){const j=new DevnetJournal(join(config.journalDir,signer.publicKey.toBase58()+'.json'),signer,{maxTransactions:config.maxTransactionsPerVerifier,maxFees:1000000});j.connection=reader.connection;await j.initialize({factory:config.deployment.factory,catalogRoot:config.deployment.catalogRoot,scope:'V4 trusted replay and fixed-entitlement payment only'});journals.push(j);}
  let stopped=false,running=false,again=false,paymentAt=0;const retries=new Map(),paidTasks=new Set();
  const status=value=>{gateway.verifierStatus={...value,at:new Date().toISOString(),serialReplay:true,trustedKeys:2,independentOperators:1};onStatus(gateway.verifierStatus);};
  async function decision(address,signer){
    const dir=join(config.outputDir,signer.publicKey.toBase58()),file=join(dir,address.toBase58(),'decision.json');
    let report;try{report=JSON.parse(await readFile(file,'utf8'));}catch(error){if(error.code!=='ENOENT')throw error;status({status:'replaying',submission:address.toBase58()});const verified=await verify({reader,address,contentStore:new LocalFactoryContentStore(config.contentDir),modelDir:config.modelDir,outputDir:dir,binary:config.binary});report=verified.report;await writeFile(file,canonical(report),{mode:0o600,flag:'wx'});}
    const s=await reader.account(address,(await import('../web/task-factory-v4-codec.mjs')).decodeSubmission),t=await reader.account(new PublicKey(s.task),(await import('../web/task-factory-v4-codec.mjs')).decodeTask),f=await reader.factory();
    if(!reader.a.task(reader.expected.factoryAddress,t.index).equals(new PublicKey(s.task))||!new PublicKey(t.factory).equals(reader.expected.factoryAddress)||report.submission!==address.toBase58()||report.task!==new PublicKey(s.task).toBase58()||report.attempt!==s.attempt||report.completeTrials!==t.descriptor.seeds.length||report.measurements?.length!==report.completeTrials||report.fullReplay!==true||s.state!==STATE.REVEALED||t.state!==STATE.ACTIVE||t.attempt!==s.attempt||f.activeIndex!==t.index)throw new Error('Replay decision is no longer eligible');
    const reportHash=fromHex(await hash(canonical(report)));return {factory:f,task:t,submission:s,report,reportHash,message:voteMessage(reader.program,f,t,address,s,report.valid,reportHash,report.completeTrials)};
  }
  async function payments(f){
    if(Date.now()-paymentAt<10000)return;paymentAt=Date.now();const payer=signers[0];
    for(let index=0;index<f.nextIndex;index++){
      if(index===f.activeIndex||paidTasks.has(index))continue;
      const t=await reader.task(index);if(t.paid){paidTasks.add(index);continue;}if(t.state!==STATE.SOLVED)continue;
      const beneficiary=new PublicKey(t.beneficiary),mint=new PublicKey(f.mint),ata=getAssociatedTokenAddressSync(mint,beneficiary),task=reader.a.task(reader.expected.factoryAddress,index);
      const instructions=[createAssociatedTokenAccountIdempotentInstruction(payer.publicKey,ata,beneficiary,mint),instruction(reader.program,[meta(reader.a.global),meta(reader.expected.factoryAddress,true),meta(task,true),meta(new PublicKey(t.winner)),meta(reader.a.pool(0),true),meta(ata,true),meta(TOKEN_PROGRAM_ID)],9)];
      await journals[0].run('pay-task-'+index,instructions,[],async()=>(await reader.task(index)).paid);paidTasks.add(index);status({status:'paid',taskIndex:index});
    }
  }
  async function drain(){
    if(running||stopped)return;running=true;
    try{do{again=false;const f=await reader.factory();await payments(f);if(f.activeIndex===0xffffffff){status({status:f.paused?'paused':'waiting-for-contract-task'});continue;}const t=await reader.task(f.activeIndex);
      for(const entry of t.queue){
        if(stopped)break;
        const address=new PublicKey(entry.submission),id=address.toBase58();if((retries.get(id)||0)>Date.now())continue;
        for(let n=0;n<signers.length;n++){
          if(stopped)break;
          const latestFactory=await reader.factory();if(latestFactory.activeIndex!==t.index)break;
          const s=await reader.submission(address,reader.a.task(reader.expected.factoryAddress,t.index)),index=latestFactory.verifiers.findIndex(k=>new PublicKey(k).equals(signers[n].publicKey));
          if(s.state!==STATE.REVEALED||(s.validVotes|s.invalidVotes)&(1<<index))continue;
          try{const verified=await decision(address,signers[n]);if(stopped)break;const ixs=voteInstructions(reader,address,verified,signers[n]);await journals[n].run('vote-'+id,ixs,[],async()=>{const value=await reader.submission(address,verified.submission.task);return !!((value.validVotes|value.invalidVotes)&(1<<index));});retries.delete(id);status({status:'verdict-finalized',submission:id,valid:verified.report.valid,completeTrials:verified.report.completeTrials});again=true;}
          catch(error){retries.set(id,Date.now()+60000);status({status:'retryable-replay-or-chain-error',submission:id,errorClass:error.name||'Error',voteNotAssumed:true});break;}
        }
      }
      if(!again)status({status:'waiting-for-revealed-submission'});
    }while(again&&!stopped);}catch(error){status({status:'retryable-chain-error',errorClass:error.name||'Error'});}finally{running=false;}
  }
  const wake=()=>{again=true;if(!running&&!stopped)void drain();},timer=setInterval(wake,5000);wake();
  return {wake,async stop(){stopped=true;clearInterval(timer);while(running)await new Promise(ok=>setTimeout(ok,100));}};
}
async function main(){
  const file=process.argv[2];if(!file)throw new Error('Usage: factory_service_v4.mjs PRIVATE_RUNTIME.json');const config=JSON.parse(await readFile(file,'utf8'));
  const connection=new Connection(config.rpcUpstream,{commitment:'finalized',disableRetryOnRateLimit:true,fetch:verifierRpcFetchV4(config.rpcUpstream)}),reader=readerForDeployment(config.deployment,connection);
  await mkdir(config.outputDir,{recursive:true,mode:0o700});await mkdir(config.partialDir,{recursive:true,mode:0o700});let watcher;
  const gateway=await new FactoryGatewayV4(config,{reader,onContent:()=>watcher?.wake()}).initialize(),server=serveFactoryGatewayV4(gateway,{port:config.port||8792});await new Promise((ok,no)=>{server.once('listening',ok);server.once('error',no);});watcher=await runFactoryVerifierV4(config,{reader,gateway});
  console.log(JSON.stringify({status:'factory-v4-service-ready',taskAuthority:'contract',serialReplay:true,trustedVerifierKeys:2,independentOperators:1,mainnet:false}));
  for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{server.close();watcher.stop().then(()=>{gateway.close();process.exit(0);});});
}
const mainPath=process.argv[1]&&await realpath(process.argv[1]).catch(()=>null);
if(mainPath&&import.meta.url===pathToFileURL(mainPath).href)main().catch(error=>{console.error(JSON.stringify({status:'factory-v4-service-stopped',errorClass:error.name||'Error',privateConfigurationLogged:false}));process.exitCode=1;});
