#!/usr/bin/env node
// Finite content/RPC transport. Scientific tasks and rewards come only from the
// frozen chain catalog; this service has no catalog-creation instruction.
import {createServer} from 'node:http';
import {createReadStream} from 'node:fs';
import {readFile,writeFile,mkdir,stat,open,rename,unlink,statfs} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {PublicKey,Transaction} from '@solana/web3.js';
import {TOKEN_PROGRAM_ID,ASSOCIATED_TOKEN_PROGRAM_ID,getAssociatedTokenAddressSync} from '@solana/spl-token';
import {canonical,hash,goalResultRoot} from '../web/target-protocol-v2.mjs';
import {readerForDeployment} from '../web/task-factory-client-v4.mjs';
import {makeRound,validateFactoryManifest} from '../web/task-factory-v4-science.mjs';
import {commitment,fromHex,hex,STATE} from '../web/task-factory-v4-codec.mjs';
import {LocalFactoryContentStore} from './factory_verifier_v4.mjs';

const fail=(code,status=400)=>Object.assign(new Error(code),{code,status});
const digest=b=>createHash('sha256').update(b).digest('hex');
const validRoot=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const key=s=>new PublicKey(s).toBase58();
const delay=ms=>new Promise(ok=>setTimeout(ok,ms));
export class FactoryGatewayV4 {
  constructor(config,{reader,authenticate,fetch:fetchImpl=globalThis.fetch,onContent=()=>{}}={}){
    this.config=config;this.fetch=fetchImpl;this.reader=reader||readerForDeployment(config.deployment);this.authenticateOverride=authenticate;this.onContent=onContent;this.content=new LocalFactoryContentStore(config.contentDir);this.locks=new Map();this.rates=new Map();this.cache=new Map();this.activeRpc=0;
    if(config.deployment.cluster!=='devnet'||config.maxStorageBytes>2*1024**3||config.maxStorageBytes<1||!Array.isArray(config.origins)||config.origins.some(x=>!/^https:\/\//.test(x)))throw new Error('Explicit finite Devnet gateway configuration required');
    this.db=new DatabaseSync(config.database);this.db.exec(`PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS uploads(submission TEXT PRIMARY KEY,wallet TEXT NOT NULL,scope TEXT NOT NULL,objects TEXT NOT NULL,total INTEGER NOT NULL,created INTEGER NOT NULL);`);
  }
  async initialize(){await mkdir(this.config.contentDir,{recursive:true,mode:0o700});await mkdir(this.config.partialDir,{recursive:true,mode:0o700});await this.reader.factory();return this;}
  async authenticate(req){
    const origin=req.headers.origin;if(!this.config.origins.includes(origin))throw fail('ORIGIN_REJECTED',403);
    if(this.authenticateOverride)return this.authenticateOverride(req);
    const response=await this.fetch('http://127.0.0.1:8789/api/mining/v3/session/check',{method:'POST',headers:{Origin:origin,Authorization:req.headers.authorization||'','X-Mining-CSRF':req.headers['x-mining-csrf']||'','Content-Type':'application/json'},body:'{}',signal:AbortSignal.timeout(10000)});
    if(!response.ok)throw fail('SESSION_REQUIRED',401);const s=await response.json();
    if(s.authenticated!==true||s.programId!==this.config.deployment.programId||s.genesisHash!==this.config.deployment.genesisHash||s.expiresAt<Date.now()/1000)throw fail('SESSION_REQUIRED',401);key(s.wallet);return s;
  }
  rate(id,limit){const now=Math.floor(Date.now()/60000);let r=this.rates.get(id);if(!r||r.minute!==now){r={minute:now,count:0};if(this.rates.size>1024)for(const [k,v]of this.rates)if(v.minute!==now)this.rates.delete(k);if(this.rates.size>1024&&!this.rates.has(id))throw fail('GATEWAY_BUSY',503);this.rates.set(id,r);}if(++r.count>limit)throw fail('RATE_LIMITED',429);}
  async authorize(req,body){
    const session=await this.authenticate(req);this.rate('upload:'+session.wallet,32);
    const address=key(body.submission),f=await this.reader.factory(),s=await this.reader.account(new PublicKey(address),(await import('../web/task-factory-v4-codec.mjs')).decodeSubmission),t=await this.reader.account(new PublicKey(s.task),(await import('../web/task-factory-v4-codec.mjs')).decodeTask);
    if(new PublicKey(s.miner).toBase58()!==session.wallet||!new PublicKey(t.factory).equals(this.reader.expected.factoryAddress)||!this.reader.a.task(this.reader.expected.factoryAddress,t.index).equals(new PublicKey(s.task))||!this.reader.a.submission(s.task,s.attempt,s.miner,s.commitment).equals(new PublicKey(address))||t.attempt!==s.attempt||![STATE.COMMITTED,STATE.REVEALED,STATE.VALID].includes(s.state))throw fail('SUBMISSION_SCOPE',403);
    const spec=JSON.parse(new TextDecoder().decode(await this.content.get(hex(t.descriptor.content),1024*1024))),round=await makeRound({program:this.config.deployment.programId,genesis:this.config.deployment.genesisHash,factoryAddress:this.config.deployment.factory,taskAddress:new PublicKey(s.task).toBase58(),factory:f,task:t,spec});
    await validateFactoryManifest(body.manifest,round);
    const expectedArchive={schema:'flybrainlabs-candidate-archive-v4',trials:body.manifest.trials.map(x=>({root:x.resultRoot,bytes:x.bytes}))};
    if(hex(canonical(body.archive))!==hex(canonical(expectedArchive)))throw fail('ARCHIVE_SCOPE');
    const manifest=canonical(body.manifest),archive=canonical(body.archive),evidence={candidate:fromHex(body.manifest.candidateId),result:fromHex(await goalResultRoot(body.manifest.trials)),manifest:fromHex(await hash(manifest)),archive:fromHex(await hash(archive))};
    if(hex(commitment(this.reader.program,f,s.task,s.attempt,s.miner,s.beneficiary,evidence,fromHex(body.salt)))!==hex(s.commitment))throw fail('COMMITMENT_SCOPE',403);
    const objects=[...body.manifest.trials.map(x=>({hash:x.resultRoot,bytes:x.bytes})),{hash:hex(evidence.manifest),bytes:manifest.length},{hash:hex(evidence.archive),bytes:archive.length}];
    if(objects.some(x=>!validRoot(x.hash)||!Number.isSafeInteger(x.bytes)||x.bytes<1||x.bytes>Math.max(round.goal.maxTrialBytes,1024*1024))||new Set(objects.map(x=>x.hash)).size!==objects.length)throw fail('ARTIFACT_BOUNDS');
    const total=objects.reduce((n,x)=>n+x.bytes,0);if(total>round.goal.maxCandidateBytes+2*1024*1024)throw fail('ARTIFACT_BOUNDS');
    const scope=await hash(canonical({submission:address,objects})),old=this.db.prepare('SELECT * FROM uploads WHERE submission=?').get(address);
    if(old){if(old.wallet!==session.wallet||old.scope!==scope)throw fail('FROZEN_UPLOAD_CONFLICT',409);return {submission:address,objects,authorized:true};}
    const reserved=this.db.prepare('SELECT COALESCE(SUM(total),0) AS n FROM uploads').get().n;
    if(reserved+total>this.config.maxStorageBytes)throw fail('CONTENT_CAPACITY',503);
    const disk=await statfs(this.config.contentDir);if(Number(disk.bavail)*Number(disk.bsize)<this.config.diskReserveBytes+total)throw fail('DISK_RESERVE',503);
    // Recheck under the same synchronous SQLite writer before reserving bytes.
    this.db.exec('BEGIN IMMEDIATE');try{const used=this.db.prepare('SELECT COALESCE(SUM(total),0) AS n FROM uploads').get().n;if(used+total>this.config.maxStorageBytes)throw fail('CONTENT_CAPACITY',503);this.db.prepare('INSERT INTO uploads VALUES(?,?,?,?,?,?)').run(address,session.wallet,scope,JSON.stringify(objects),total,Math.floor(Date.now()/1000));this.db.exec('COMMIT');}catch(e){this.db.exec('ROLLBACK');throw e;}
    return {submission:address,objects,authorized:true};
  }
  async upload(req,url,root,bytes){
    const session=await this.authenticate(req);this.rate('chunks:'+session.wallet,300);
    const submission=key(url.searchParams.get('submission')),offset=Number(url.searchParams.get('offset')),total=Number(url.searchParams.get('total')),row=this.db.prepare('SELECT * FROM uploads WHERE submission=? AND wallet=?').get(submission,session.wallet),object=row&&JSON.parse(row.objects).find(x=>x.hash===root);
    if(!object||total!==object.bytes||!Number.isSafeInteger(offset)||offset<0||offset+bytes.length>total||!bytes.length||bytes.length>1024*1024)throw fail('UPLOAD_SCOPE',403);
    const previous=this.locks.get(root)||Promise.resolve(),operation=previous.catch(()=>{}).then(async()=>{
      const target=join(this.config.contentDir,root+'.bin');
      try{const existing=await stat(target);if(existing.size!==total)throw fail('CONTENT_CONFLICT',409);return {received:total,complete:true};}catch(e){if(e.code!=='ENOENT')throw e;}
      const dir=join(this.config.partialDir,submission);await mkdir(dir,{recursive:true,mode:0o700});const part=join(dir,root+'.part');let size=0,exists=false;try{size=(await stat(part)).size;exists=true;}catch(e){if(e.code!=='ENOENT')throw e;}
      const finish=async()=>{const h=createHash('sha256');for await(const chunk of createReadStream(part))h.update(chunk);if(h.digest('hex')!==root){await unlink(part);throw fail('CONTENT_HASH');}await rename(part,target);this.onContent();return {received:total,complete:true};};
      if(offset>size)throw fail('UPLOAD_CURSOR',409);
      let tail=bytes;
      if(offset<size){const overlap=Math.min(bytes.length,size-offset),file=await open(part,'r');try{const expected=Buffer.alloc(overlap);await file.read(expected,0,expected.length,offset);if(!expected.equals(bytes.subarray(0,overlap)))throw fail('UPLOAD_CONFLICT',409);}finally{await file.close();}tail=bytes.subarray(overlap);if(!tail.length)return size===total?finish():{received:size,complete:false};}
      const file=await open(part,exists?'r+':'wx',0o600);try{let done=0;while(done<tail.length){const result=await file.write(tail,done,tail.length-done,size+done);if(!result.bytesWritten)throw fail('CONTENT_WRITE',503);done+=result.bytesWritten;}await file.sync();}finally{await file.close();}
      size+=tail.length;if(size===total)return finish();
      return {received:size,complete:size===total};
    });this.locks.set(root,operation);try{return await operation;}finally{if(this.locks.get(root)===operation)this.locks.delete(root);}
  }
  reviewRpc(body,session){
    if(body?.jsonrpc!=='2.0'||!(typeof body.id==='string'&&body.id.length<=80||Number.isSafeInteger(body.id))||!Array.isArray(body.params)||body.params.length>2||Object.keys(body).some(k=>!['id','jsonrpc','method','params'].includes(k)))throw fail('RPC_REQUEST_REJECTED');
    const p=body.params,final=o=>o&&o.commitment==='finalized';
    switch(body.method){
      case 'getGenesisHash':if(p.length)throw fail('RPC_PARAMETERS');break;
      case 'getAccountInfo':if(p.length!==2||!final(p[1])||p[1].encoding!=='base64')throw fail('RPC_PARAMETERS');key(p[0]);break;
      case 'getSlot':case 'getBlockHeight':case 'getLatestBlockhash':if(p.length!==1||!final(p[0]))throw fail('RPC_PARAMETERS');break;
      case 'getBlockTime':if(p.length!==1||!Number.isSafeInteger(p[0])||p[0]<0)throw fail('RPC_PARAMETERS');break;
      case 'getMinimumBalanceForRentExemption':if(![768,165].includes(p[0])||p.length!==2||!final(p[1]))throw fail('RPC_PARAMETERS');break;
      case 'getBalance':if(p.length!==2||!final(p[1]))throw fail('RPC_PARAMETERS');key(p[0]);break;
      case 'getFeeForMessage':if(p.length!==2||typeof p[0]!=='string'||p[0].length>1644||!final(p[1]))throw fail('RPC_PARAMETERS');break;
      case 'getSignatureStatuses':if(p.length!==2||!Array.isArray(p[0])||p[0].length>4||p[0].some(s=>typeof s!=='string'||!/^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(s))||p[1]?.searchTransactionHistory!==true)throw fail('RPC_PARAMETERS');break;
      case 'sendTransaction':{
        if(!session||p.length!==2||typeof p[0]!=='string'||p[0].length>1644||p[1]?.encoding!=='base64'||p[1].skipPreflight===true||p[1].maxRetries!==0||p[1].preflightCommitment!=='finalized')throw fail('RPC_TRANSACTION_REJECTED');
        const bytes=Buffer.from(p[0],'base64');if(bytes.length>1232||bytes.toString('base64')!==p[0])throw fail('RPC_TRANSACTION_REJECTED');const tx=Transaction.from(bytes);
        if(!tx.verifySignatures()||tx.feePayer.toBase58()!==session.wallet||tx.instructions.length<1||tx.instructions.length>2)throw fail('RPC_TRANSACTION_REJECTED');
        const last=tx.instructions.at(-1),data=last.data;
        if(last.programId.toBase58()!==this.config.deployment.programId||data.length<6||data[0]!==11||data.readUInt32LE(1)!==data.length-5||![3,4,5,7,8,9].includes(data[5])||!last.keys.some(k=>k.pubkey.toBase58()===this.config.deployment.factory))throw fail('RPC_TRANSACTION_SCOPE');
        if(tx.instructions.length===2){const ata=tx.instructions[0];if(data[5]!==9||!ata.programId.equals(ASSOCIATED_TOKEN_PROGRAM_ID)||ata.data.length!==1||ata.data[0]!==1||ata.keys.length!==6||ata.keys[0].pubkey.toBase58()!==session.wallet||ata.keys[3].pubkey.toBase58()!==this.config.deployment.mint||!ata.keys[1].pubkey.equals(getAssociatedTokenAddressSync(ata.keys[3].pubkey,ata.keys[2].pubkey))||!ata.keys[5].pubkey.equals(TOKEN_PROGRAM_ID))throw fail('RPC_TRANSACTION_SCOPE');}
        break;
      }
      default:throw fail('RPC_METHOD_REJECTED');
    }
    return body;
  }
  async rpc(req,body){
    this.rate('rpc:global',600);this.rate('rpc:'+req.socket.remoteAddress,240);if(this.activeRpc>=6)throw fail('RPC_BUSY',503);
    const session=body.method==='sendTransaction'?await this.authenticate(req):null,request=this.reviewRpc(body,session),cacheable=['getGenesisHash','getAccountInfo','getSlot','getBlockHeight','getBlockTime','getLatestBlockhash','getMinimumBalanceForRentExemption','getBalance'].includes(body.method),cacheKey=body.method+':'+JSON.stringify(body.params),cached=this.cache.get(cacheKey);
    if(cacheable&&cached&&cached.until>Date.now())return {...cached.value,id:body.id};
    this.activeRpc++;
    try{
      const response=await this.fetch(this.config.rpcUpstream,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request),signal:AbortSignal.timeout(15000)});if(!response.ok)throw fail(response.status===429?'RPC_RATE_LIMITED':'RPC_UNAVAILABLE',response.status===429?429:503);
      const text=await response.text();if(text.length>100000)throw fail('RPC_RESPONSE_LIMIT',503);const value=JSON.parse(text);if(value.jsonrpc!=='2.0'||value.id!==body.id)throw fail('RPC_INVALID_RESPONSE',503);
      if(body.method==='getGenesisHash'&&value.result!==this.config.deployment.genesisHash)throw fail('WRONG_CHAIN',503);
      if(cacheable&&!value.error){if(this.cache.size>=64)this.cache.delete(this.cache.keys().next().value);this.cache.set(cacheKey,{value,until:Date.now()+(body.method==='getGenesisHash'?600000:body.method==='getMinimumBalanceForRentExemption'?60000:1500)});}
      return value;
    }finally{this.activeRpc--;}
  }
  close(){this.db.close();}
}
async function bodyBytes(req,max){const chunks=[];let size=0;for await(const b of req){size+=b.length;if(size>max)throw fail('BODY_LIMIT',413);chunks.push(b);}return Buffer.concat(chunks);}
export function serveFactoryGatewayV4(service,{port=8792,host='127.0.0.1'}={}){
  let active=0;const server=createServer(async(req,res)=>{
    if(active>=12){res.writeHead(503,{'Content-Type':'application/json'});return res.end('{"code":"GATEWAY_BUSY"}');}active++;let released=false;const release=()=>{if(!released){released=true;active--;}};res.once('close',release);res.once('finish',release);
    try{
      const origin=req.headers.origin;if(origin&&!service.config.origins.includes(origin))throw fail('ORIGIN_REJECTED',403);
      if(origin)res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Cache-Control','no-store');
      if(req.method==='OPTIONS'){res.setHeader('Access-Control-Allow-Methods','GET, POST, OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization, X-Mining-CSRF, Solana-Client');res.writeHead(204);return res.end();}
      const url=new URL(req.url,'http://localhost'),path=url.pathname.replace(/^\/api\/task-factory\/v4\//,''),content=/^content\/([a-f0-9]{64})\.bin$/.exec(path);let value;
      if(req.method==='GET'&&content){const file=join(service.config.contentDir,content[1]+'.bin');let info;try{info=await stat(file);}catch{throw fail('CONTENT_NOT_FOUND',404);}res.setHeader('Content-Type','application/octet-stream');res.setHeader('Content-Length',info.size);res.setHeader('Cache-Control','public, max-age=31536000, immutable');createReadStream(file).on('error',()=>res.destroy()).pipe(res);return;}
      if(req.method==='GET'&&path==='configuration')value=service.config.deployment;
      else if(req.method==='GET'&&path==='health')value={schema:'flybrainlabs-factory-health-v4',transportReady:true,taskAuthority:'contract',catalogCreation:false,verifier:service.verifierStatus||{status:'not-started'}};
      else if(req.method==='POST'&&path==='rpc')value=await service.rpc(req,JSON.parse((await bodyBytes(req,8192)).toString()));
      else if(req.method==='POST'&&path==='uploads')value=await service.authorize(req,JSON.parse((await bodyBytes(req,1024*1024)).toString()));
      else if(req.method==='POST'&&content)value=await service.upload(req,url,content[1],await bodyBytes(req,1024*1024));
      else throw fail('NOT_FOUND',404);
      res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));
    }catch(error){if(!res.headersSent){res.setHeader('Content-Type','application/json');res.writeHead(error.status||503);res.end(JSON.stringify({code:error.code||'RETRYABLE_INFRA_ERROR'}));}else res.destroy();}
  });server.headersTimeout=15000;server.requestTimeout=40000;server.listen(port,host);return server;
}
