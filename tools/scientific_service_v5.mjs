// V5 uses separate scopes in the durable lease/transaction journal. It never
// creates a new reward allocation; only configured, already funded rounds run.
import {mkdir,open,link,unlink,readFile,stat} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomUUID,createPublicKey,verify as verifySignature} from 'node:crypto';
import {createServer} from 'node:http';
import {PublicKey,Connection,Keypair} from '@solana/web3.js';
import {getAssociatedTokenAddressSync,createAssociatedTokenAccountIdempotentInstruction,TOKEN_PROGRAM_ID} from '@solana/spl-token';
import {ScientificReaderV5,instruction,meta,slotHashes} from '../web/scientific-client-v5.mjs';
import {hex,fromHex,contentRoot,STATES} from '../web/scientific-round-v5.mjs';
import {canonical,hash} from '../web/target-protocol-v2.mjs';
import {FactoryPoolQueueV4} from './factory_pool_queue_v4.mjs';
import {FactoryPoolTransportV4} from './factory_pool_transport_v4.mjs';
import {ExactTrialWorker} from './exact_trial_worker.mjs';
import {verifyScientificClaim,scientificVoteInstructions} from './scientific_verifier_v5.mjs';

export class ScientificContentStore {
  constructor(directory,maxBytes=128*1024*1024){this.directory=resolve(directory);this.maxBytes=maxBytes;}
  path(root){if(!/^[a-f0-9]{64}$/.test(root))throw new Error('Scientific content root');return join(this.directory,root+'.bin');}
  async get(root,max=this.maxBytes){const path=this.path(root),size=(await stat(path)).size;if(size>Math.min(max,this.maxBytes))throw new Error('Scientific content bound');const bytes=new Uint8Array(await readFile(path));if(await hash(bytes)!==root)throw new Error('Scientific content hash');return bytes;}
  async put(root,bytes){if(bytes.length>this.maxBytes||await hash(bytes)!==root)throw new Error('Scientific artifact identity or bound');await mkdir(this.directory,{recursive:true,mode:0o700});const temporary=this.path(root)+'.'+randomUUID()+'.partial';try{const f=await open(temporary,'wx',0o600);try{await f.writeFile(bytes);await f.sync();}finally{await f.close();}try{await link(temporary,this.path(root));}catch(e){if(e.code!=='EEXIST')throw e;}}finally{await unlink(temporary).catch(()=>{});}await this.get(root,bytes.length);return root;}
}
export function uploadMessage({genesis,program,round,claim,root,bytes}){return canonical({schema:'flybrain-scientific-upload-v5',genesis,program,round,claim,root,bytes});}
export class ScientificServiceV5 {
  constructor({config,connection,queue,signers,worker,contentStore,verify=verifyScientificClaim}){
    if(!['devnet','localnet'].includes(config.deployment.cluster)||!Array.isArray(config.rounds)||!config.rounds.length||config.rounds.length>64||signers.length!==2||signers[0].publicKey.equals(signers[1].publicKey)||!Number.isInteger(config.maxTransactionsPerSigner)||!Number.isSafeInteger(config.maxFeeLamportsPerSigner))throw new Error('Scientific service bounds');
    Object.assign(this,{config,connection,queue,signers,worker,contentStore,verify});this.reader=new ScientificReaderV5(connection,config.deployment);this.owner=randomUUID();this.stopped=false;this.rounds=new Set(config.rounds);this.summary=[];
    // Constructing a transport validates the explicit finite fee allowances.
    for(const signer of signers)this.transport(signer);
  }
  scope(address){return 'science-v5:'+address;}
  transport(signer){return new FactoryPoolTransportV4({queue:this.queue,connection:this.connection,payer:signer,maxTransactions:this.config.maxTransactionsPerSigner,maxFeeLamports:this.config.maxFeeLamportsPerSigner,beforeSend:()=>{if(this.stopped)throw new Error('Scientific service stopped');}});}
  async initialize(){await this.queue.pool.query(`CREATE SCHEMA IF NOT EXISTS scientific_v5;
    CREATE TABLE IF NOT EXISTS scientific_v5.uploads (claim text NOT NULL, root text NOT NULL, bytes bigint NOT NULL CHECK(bytes>0), PRIMARY KEY(claim,root));
    CREATE TABLE IF NOT EXISTS scientific_v5.verifications (claim text PRIMARY KEY, manifest text NOT NULL, report_hash text NOT NULL, report jsonb NOT NULL);`);
    for(const address of this.rounds){const r=await this.reader.round(address);await this.reader.content(r,this.contentStore);for(const signer of this.signers)if(!r.verifiers.some(k=>new PublicKey(k).equals(signer.publicKey)))throw new Error('Scientific signer is not admitted');}
    return this;
  }
  async enqueue(address,operation,claim=null,signer=this.signers[0]){return this.queue.enqueue({id:['science-v5',address,operation,claim||'-',signer.publicKey.toBase58()].join(':'),kind:operation==='vote'?'replay':'payment',scope:this.scope(address),payload:{round:address,operation,claim,payer:signer.publicKey.toBase58()}});}
  async discover(){
    const now=BigInt(await this.connection.getSlot('confirmed'));const summary=[];
    for(const address of this.rounds){const r=await this.reader.round(address),spec=r.specification;
      const state=r.closed?'closed':now<spec.commitStart?'scheduled':now<spec.commitEnd?'commit':!r.challenge.some(x=>x)?'awaiting-challenge':now<=spec.revealEnd?'challenge-and-reveal':now<=spec.verifyEnd?'verification':'resolving';
      summary.push({address,state,commitEnd:String(spec.commitEnd),revealEnd:String(spec.revealEnd),verifyEnd:String(spec.verifyEnd),rewardAtoms:String(spec.rewardAtoms),remaining:String(r.remaining),acceptedUnpaid:String(r.acceptedUnpaid),paid:String(r.paid),places:r.winners.map(hex),challenge:hex(r.challenge),sourceSlot:String(r.sourceSlot)});
      if(!r.closed&&!r.challenge.some(x=>x)&&now>spec.challengeSlot&&now<=spec.challengeSlot+128n)await this.enqueue(address,'challenge');
      for(let role=0;role<3;role++){
        const addressBytes=r.queues[role][r.cursors[role]];
        if(!addressBytes)continue;
        const claimAddress=new PublicKey(addressBytes).toBase58(),c=await this.reader.claim(claimAddress,address);
        if(c.state===STATES.REVEALED&&now<=spec.verifyEnd){for(const signer of this.signers){const i=r.verifiers.findIndex(v=>new PublicKey(v).equals(signer.publicKey));if(!((c.completeVotes|c.invalidVotes)&(1<<i)))await this.enqueue(address,'vote',claimAddress,signer);}}
        const bits=n=>n.toString(2).replaceAll('0','').length;
        const quorum=bits(c.invalidVotes)>=2||bits(c.positiveVotes)>=2||bits(c.completeVotes&~c.positiveVotes)>=2;
        if(quorum||now>spec.verifyEnd||c.state===STATES.COMMITTED&&now>spec.revealEnd)await this.enqueue(address,'resolve',claimAddress);
      }
      for(const winner of r.winners.filter(k=>k.some(x=>x))){const a=new PublicKey(winner).toBase58(),c=await this.reader.claim(a,address);if(c.state===STATES.ACCEPTED)await this.enqueue(address,'pay',a);}
      if(!r.closed&&r.cursors.every((n,i)=>n===r.queues[i].length)&&(now>spec.verifyEnd||r.winners.every(k=>k.some(x=>x))))await this.enqueue(address,'close');
    }
    this.summary=summary;return summary;
  }
  async operation(job){
    const {round:address,operation,claim:claimAddress,payer}=job.payload;
    if(!this.rounds.has(address))throw new Error('Scientific round is not approved');
    const signer=this.signers.find(s=>s.publicKey.toBase58()===payer);if(!signer)throw new Error('Scientific payer');
    let r=await this.reader.round(address),c=claimAddress?await this.reader.claim(claimAddress,address):null;
    const transport=this.transport(signer),program=this.reader.program;
    if(operation==='vote'){
      const index=r.verifiers.findIndex(k=>new PublicKey(k).equals(signer.publicKey));
      if((c.completeVotes|c.invalidVotes)&(1<<index))return transport.reconcile(job,'vote');
      if(c.state!==STATES.REVEALED||r.closed)return {stale:true};
      // Share the one exact computation between keys of this same operator.
      // This is not advertised as operator independence.
      let saved=(await this.queue.pool.query('SELECT report,manifest,report_hash FROM scientific_v5.verifications WHERE claim=$1',[claimAddress])).rows[0];
      if(!saved){const result=await this.verify({reader:this.reader,roundAddress:address,claimAddress,contentStore:this.contentStore,worker:this.worker,outputDir:this.config.outputDir});
        await this.queue.transaction(async db=>{await this.queue.guard(job,db,{lock:true});await db.query('INSERT INTO scientific_v5.verifications(claim,manifest,report_hash,report) VALUES($1,$2,$3,$4) ON CONFLICT(claim) DO NOTHING',[claimAddress,hex(c.manifest),hex(result.reportHash),result.report]);});saved=(await this.queue.pool.query('SELECT report,manifest,report_hash FROM scientific_v5.verifications WHERE claim=$1',[claimAddress])).rows[0];}
      const report=saved.report;c=await this.reader.claim(claimAddress,address);r=await this.reader.round(address);
      if(saved.manifest!==hex(c.manifest)||hex(contentRoot(report))!==saved.report_hash||report.manifest!==hex(c.manifest)||report.computation!==hex(c.computation)||report.claim!==claimAddress||report.round!==address||report.verificationMethod!=='exact-events-v1'||report.completeTrials!==r.specification.backgrounds)throw new Error('Scientific cached verdict binding');
      return transport.run(job,'vote',scientificVoteInstructions(this.reader,claimAddress,{round:r,claim:c,report,reportHash:contentRoot(report)},signer),async()=>{const latest=await this.reader.claim(claimAddress,address);return !!((latest.completeVotes|latest.invalidVotes)&(1<<index));});
    }
    if(operation==='challenge')return transport.run(job,'challenge',[instruction(program,[meta(address,true),slotHashes()],2)],async()=>(await this.reader.round(address)).challenge.some(x=>x));
    if(operation==='resolve')return transport.run(job,'resolve',[instruction(program,[meta(address,true),meta(claimAddress,true),meta(this.reader.a.computation(c.computation),true),meta(signer.publicKey,true,true),meta('11111111111111111111111111111111')],5)],async()=>[2,3,4,5].includes((await this.reader.claim(claimAddress,address)).state));
    if(operation==='pay'){
      const destination=getAssociatedTokenAddressSync(new PublicKey(r.mint),new PublicKey(c.beneficiary));
      return transport.run(job,'pay',[createAssociatedTokenAccountIdempotentInstruction(signer.publicKey,destination,new PublicKey(c.beneficiary),new PublicKey(r.mint)),instruction(program,[meta(this.reader.a.global),meta(address,true),meta(claimAddress,true),meta(this.reader.a.pool(0),true),meta(destination,true),meta(TOKEN_PROGRAM_ID)],6)],async()=>(await this.reader.claim(claimAddress,address)).state===STATES.PAID);
    }
    if(operation==='close')return transport.run(job,'close',[instruction(program,[meta(this.reader.a.global,true),meta(address,true)],7)],async()=>(await this.reader.round(address)).closed);
    throw new Error('Scientific operation');
  }
  async tick(){
    if(this.busy||this.stopped)return;this.busy=true;
    try{await this.discover();const scopes=[...this.rounds].map(a=>this.scope(a));
      for(const kind of ['payment','replay']){const job=await this.queue.claim(kind,this.owner,600,null,scopes);if(!job)continue;
        try{await this.queue.finish(job,await this.operation(job));}catch(e){await this.queue.retry(job,{delaySeconds:3,blocked:['POOL_TRANSACTION_UNKNOWN','POOL_SIGNER_ALLOWANCE','POOL_TRANSACTION_FAILED'].includes(e.code),code:e.code||'SCIENCE_RETRY'});}}
    }finally{this.busy=false;}
  }
  async upload(req,root,bytes){
    const round=req.headers['x-scientific-round'],claim=req.headers['x-scientific-claim'],signature=req.headers['x-scientific-signature'];
    if(!this.rounds.has(round)||!/^[a-f0-9]{128}$/.test(signature||''))throw new Error('Scientific upload authorization');
    const r=await this.reader.round(round),c=await this.reader.claim(claim,round),content=await this.reader.content(r,this.contentStore),slot=BigInt(await this.connection.getSlot('confirmed'));
    if(r.closed||!r.challenge.some(x=>x)||slot>r.specification.revealEnd||![STATES.COMMITTED,STATES.REVEALED].includes(c.state)||bytes.length>content.goal.maxTrialBytes)throw new Error('Scientific upload window or bound');
    const message=uploadMessage({genesis:this.config.deployment.genesisHash,program:this.config.deployment.programId,round,claim,root,bytes:bytes.length});
    const key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(c.miner)]),format:'der',type:'spki'});
    if(!verifySignature(null,message,key,Buffer.from(signature,'hex'))||await hash(bytes)!==root)throw new Error('Scientific upload signature/hash');
    await this.queue.transaction(async db=>{await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['science-upload:'+claim]);
      const {rows:[used]}=await db.query('SELECT COALESCE(sum(bytes),0)::text AS n FROM scientific_v5.uploads WHERE claim=$1',[claim]);
      const old=(await db.query('SELECT bytes FROM scientific_v5.uploads WHERE claim=$1 AND root=$2',[claim,root])).rows[0];
      if(!old&&BigInt(used.n)+BigInt(bytes.length)>BigInt(content.goal.maxCandidateBytes)+1048576n)throw new Error('Scientific claim storage quota');
      await db.query('INSERT INTO scientific_v5.uploads(claim,root,bytes) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[claim,root,bytes.length]);});
    await this.contentStore.put(root,bytes);
  }
  serve({host='127.0.0.1',port=8795}={}){
    let uploading=0;const server=createServer(async(req,res)=>{
      try{
        const origin=req.headers.origin,allowed=this.config.allowedOrigins||['https://flybrain.work'];
        if(origin&&!allowed.includes(origin))throw new Error('Origin');
        if(origin){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');}
        if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Methods':'GET, PUT, OPTIONS','Access-Control-Allow-Headers':'Content-Type, X-Scientific-Round, X-Scientific-Claim, X-Scientific-Signature','Access-Control-Max-Age':'600'});res.end();return;}
        const url=new URL(req.url,'http://localhost');
        if(req.method==='GET'&&url.pathname==='/api/science/v5/status'){res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({schema:'flybrain-scientific-status-v5',status:this.lastError?'attention-required':'ready',code:this.lastError||null,rounds:this.summary,verificationMethod:'exact-events-v1',independentOperators:1,biologicalValidation:false}));return;}
        const root=/^\/api\/science\/v5\/content\/([a-f0-9]{64})\.bin$/.exec(url.pathname)?.[1];if(!root)throw new Error('Route');
        if(req.method==='GET'){const bytes=await this.contentStore.get(root);res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':bytes.length,'Cache-Control':'public, max-age=31536000, immutable'});res.end(bytes);return;}
        const size=Number(req.headers['content-length']);if(req.method!=='PUT'||uploading>=2||!Number.isSafeInteger(size)||size<1||size>this.contentStore.maxBytes)throw new Error('Request limit');
        uploading++;try{const chunks=[];let length=0;for await(const chunk of req){length+=chunk.length;if(length>size)throw new Error('Upload size');chunks.push(chunk);}if(length!==size)throw new Error('Upload truncated');await this.upload(req,root,Buffer.concat(chunks));res.writeHead(201);res.end('{}');}finally{uploading--;}
      }catch{if(!res.headersSent)res.writeHead(400,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end('{"error":"scientific request unavailable"}');}
    });server.requestTimeout=120000;server.listen(port,host);this.server=server;return server;
  }
  stop(){this.stopped=true;this.server?.close();this.worker.close();}
}

// Explicit maintenance entry. Configuration and key files stay private.
export async function runScientificService(config){
  const queue=await FactoryPoolQueueV4.connect(config.databaseUrl);let worker,service,timer;
  try{
    await queue.initialize();const connection=new Connection(config.rpcUrl,'finalized');
    const signers=await Promise.all(config.verifierKeyFiles.map(async path=>Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(path,'utf8'))))));
    worker=new ExactTrialWorker({binary:config.binary,graph:join(config.modelDir,'graph-v1.bin'),model:join(config.modelDir,'model-v0.bin')});
    service=await new ScientificServiceV5({config,connection,queue,signers,worker,contentStore:new ScientificContentStore(config.contentDir)}).initialize();service.serve({port:config.port||8795});
    await service.tick();timer=setInterval(()=>service.tick().then(()=>service.lastError=null).catch(error=>service.lastError=error.code||'SCIENCE_SERVICE_UNAVAILABLE'),1500);
    const stop=async()=>{clearInterval(timer);service.stop();const deadline=Date.now()+20000;while(service.busy&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,25));await queue.close();};return {service,stop};
  }catch(error){clearInterval(timer);service?.stop();worker?.close();await queue.close();throw error;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  if(process.argv.length!==4||process.argv[2]!=='--config')throw new Error('Usage: scientific_service_v5.mjs --config PRIVATE_CONFIG');
  try{const config=JSON.parse(await readFile(process.argv[3],'utf8')),running=await runScientificService(config);let stopping=false;const stop=async()=>{if(stopping)return;stopping=true;await running.stop();};process.once('SIGINT',stop);process.once('SIGTERM',stop);}catch(error){process.stderr.write('Scientific service unavailable: '+(error.code||'CONFIGURATION_OR_RUNTIME')+'\n');process.exitCode=1;}
}
