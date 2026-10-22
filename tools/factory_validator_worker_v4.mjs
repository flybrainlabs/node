#!/usr/bin/env node
import {createServer} from 'node:http';
import {createReadStream} from 'node:fs';
import {readFile,writeFile,mkdir,stat,unlink} from 'node:fs/promises';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {ed25519} from '@noble/curves/ed25519';
import {Connection} from '@solana/web3.js';
import {readerForDeployment} from '../web/task-factory-client-v4.mjs';
import {verifyPoolCatalogV4} from '../web/factory-pool-v4.mjs';
import {canonical,hash,validateGoal,validateInput} from '../web/target-protocol-v2.mjs';
import {verifyFactorySubmission} from './factory_verifier_v4.mjs';
import {getModelReadiness,nativeReply} from './candidate_verifier_v2.mjs';

const fail=code=>Object.assign(new Error(code),{code});
const hex=bytes=>Buffer.from(bytes).toString('hex');
function authenticated(req,token){const actual=Buffer.from(req.headers.authorization||''),expected=Buffer.from('Bearer '+token);return actual.length===expected.length&&timingSafeEqual(actual,expected);}
async function jsonBody(req,max=1024*1024){let length=0;const parts=[];for await(const part of req){length+=part.length;if(length>max)throw fail('VALIDATOR_REQUEST_BOUND');parts.push(part);}return JSON.parse(Buffer.concat(parts).toString('utf8'));}
function json(res,status,body){res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(body));}
export async function startValidatorRelayV4(config){
  const token=(await readFile(config.tokenFile,'utf8')).trim();
  const allowed=new Set(['getGenesisHash','getAccountInfo','getMultipleAccounts','getSlot','getBlockTime']);
  const server=createServer(async(req,res)=>{try{
    if(!authenticated(req,token))return json(res,401,{code:'VALIDATOR_AUTH_REQUIRED'});
    const url=new URL(req.url,'http://127.0.0.1');
    if(req.method==='GET'&&/^\/content\/[a-f0-9]{64}$/.test(url.pathname)){
      const root=url.pathname.slice(9);let path;
      for(const ext of ['.bin','.json']){const candidate=join(config.contentDir,root+ext);try{const info=await stat(candidate);if(!info.isFile()||info.size>268435456)throw fail('VALIDATOR_CONTENT_BOUND');path=candidate;break;}catch(error){if(error.code!=='ENOENT')throw error;}}
      if(!path)return json(res,404,{code:'VALIDATOR_CONTENT_UNAVAILABLE'});
      res.writeHead(200,{'content-type':'application/octet-stream','content-length':(await stat(path)).size,'cache-control':'no-store'});const stream=createReadStream(path);stream.on('error',()=>res.destroy());req.on('close',()=>{if(res.destroyed)stream.destroy();});stream.pipe(res);return;
    }
    if(req.method==='POST'&&url.pathname==='/rpc'){
      const packet=await jsonBody(req);if(Array.isArray(packet)||!allowed.has(packet.method)||packet.jsonrpc!=='2.0')return json(res,403,{code:'VALIDATOR_READ_ONLY_RPC'});
      const upstream=await fetch(config.rpcUpstream,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(packet),signal:AbortSignal.timeout(30000)});
      const body=await upstream.text();if(body.length>8*1024*1024)throw fail('VALIDATOR_RPC_BOUND');res.writeHead(upstream.status,{'content-type':'application/json','cache-control':'no-store'});res.end(body);return;
    }
    json(res,404,{code:'VALIDATOR_ROUTE'});
  }catch{if(!res.headersSent)json(res,503,{code:'VALIDATOR_RELAY_RETRY'});else res.destroy();}});
  server.requestTimeout=60000;await new Promise(resolve=>server.listen(config.port||8796,'127.0.0.1',resolve));return server;
}
export async function startValidatorWorkerV4(config){
  const token=(await readFile(config.tokenFile,'utf8')).trim(),secret=await readFile(config.identityFile);
  if(secret.length!==32)throw fail('VALIDATOR_IDENTITY_FORMAT');
  const publicKey=hex(ed25519.getPublicKey(secret)),readiness=await getModelReadiness(config.binary,config.modelDir),envelope=config.trust.envelope;
  if(readiness.graphRoot!==envelope.graphRoot||!readiness.nativeBinaryReady||!readiness.parameterProfileHashes.includes(envelope.parameterProfileHash)||!readiness.evaluatorVersions.includes(envelope.evaluatorVersion))throw fail('VALIDATOR_MODEL_IDENTITY');
  let busy=false,completed=0,lastCompletion=null;
  await mkdir(config.outputDir,{recursive:true,mode:0o700});
  const sign=(request,report)=>{const body={schema:'flybrain-validator-attestation-v1',validatorId:config.id,publicKey,nonce:request.nonce,operation:request.operation,factory:request.deployment?.factory||null,submission:request.submission,completedAt:Date.now(),report,reportHash:null};return hash(canonical(report)).then(reportHash=>{body.reportHash=reportHash;return {...body,signature:hex(ed25519.sign(canonical(body),secret))};});};
  const contentStore={async get(root,max){if(!/^[a-f0-9]{64}$/.test(root))throw fail('VALIDATOR_CONTENT_ID');const response=await fetch(config.relayUrl+'/content/'+root,{headers:{authorization:'Bearer '+token},signal:AbortSignal.timeout(120000)});if(!response.ok||Number(response.headers.get('content-length'))>max)throw fail('VALIDATOR_CONTENT_UNAVAILABLE');const bytes=new Uint8Array(await response.arrayBuffer());if(bytes.length>max||await hash(bytes)!==root)throw fail('VALIDATOR_CONTENT_HASH');return bytes;}};
  const rpcFetch=(url,options)=>fetch(url,{...options,headers:{...options?.headers,authorization:'Bearer '+token},signal:AbortSignal.timeout(45000)});
  const server=createServer(async(req,res)=>{try{
    if(!authenticated(req,token))return json(res,401,{code:'VALIDATOR_AUTH_REQUIRED'});
    if(req.method==='GET'&&req.url==='/health')return json(res,200,{schema:'flybrain-validator-health-v1',validatorId:config.id,publicKey,ready:true,busy,completed,lastCompletion,model:readiness});
    if(req.method!=='POST'||!['/replay','/self-check'].includes(req.url))return json(res,404,{code:'VALIDATOR_ROUTE'});
    if(busy)return json(res,409,{code:'VALIDATOR_BUSY'});
    const request=await jsonBody(req);if(!/^[a-f0-9]{48}$/.test(request.nonce||'')||'/'+request.operation!==req.url)throw fail('VALIDATOR_REQUEST_SCOPE');
    busy=true;let report;
    try{
      if(request.operation==='replay'){
        const deployment=request.deployment;if(deployment?.programId!==config.trust.programId||deployment.genesisHash!==config.trust.genesisHash||deployment.policyHash!==config.trust.policyHash)throw fail('VALIDATOR_CHAIN_SCOPE');
        const connection=new Connection(config.relayUrl+'/rpc',{commitment:'finalized',fetch:rpcFetch,disableRetryOnRateLimit:true});
        await verifyPoolCatalogV4(deployment,config.trust,connection);
        const reader=readerForDeployment(deployment,connection),verified=await verifyFactorySubmission({reader,address:request.submission,contentStore,modelDir:config.modelDir,binary:config.binary,outputDir:join(config.outputDir,request.nonce),readiness:async()=>readiness});report=verified.report;
      }else{
        await validateGoal(request.goal);validateInput(request.goal,request.input);
        if(request.goal.graphRoot!==readiness.graphRoot||request.goal.modelDataRoot!==readiness.modelDataRoot||!Array.isArray(request.seeds)||request.seeds.length!==2||request.seeds.some(s=>!/^[a-f0-9]{16}$/.test(s)))throw fail('VALIDATOR_SELF_CHECK_SCOPE');
        const dir=join(config.outputDir,'self-check-'+request.nonce);await mkdir(dir,{recursive:true,mode:0o700});
        await writeFile(join(dir,'goal.json'),canonical(request.goal));await writeFile(join(dir,'input.json'),canonical(request.input));const measurements=[];
        for(const seed of request.seeds){const output=join(dir,seed+'.bin'),args=[join(config.modelDir,'graph-v1.bin'),join(config.modelDir,'model-v0.bin'),join(dir,'goal.json'),join(dir,'input.json'),seed,output];const generated=await nativeReply(config.binary,args),verified=await nativeReply(config.binary,[...args,'--verify']);if(generated.resultRoot!==verified.resultRoot||verified.fullReplay!==true||verified.replayVerified!==true||verified.replayStatus!=='VALID')throw fail('VALIDATOR_SELF_CHECK_REPLAY');measurements.push(verified);await unlink(output);}
        report={schema:'flybrain-validator-self-check-v1',submission:'self-check',task:'complete-model-integrity',attempt:0,fullReplay:true,completeTrials:2,valid:true,measurements};
      }
      const attestation=await sign(request,report);await writeFile(join(config.outputDir,request.nonce+'.attestation.json'),canonical(attestation),{mode:0o600});completed++;lastCompletion=Date.now();json(res,200,attestation);
    }finally{busy=false;}
  }catch(error){if(!res.headersSent)json(res,503,{code:/^[A-Z0-9_]{1,80}$/.test(error.code||'')?error.code:'VALIDATOR_REPLAY_RETRY'});else res.destroy();}});
  server.requestTimeout=60000;server.timeout=0;await new Promise(resolve=>server.listen(config.port||8795,'127.0.0.1',resolve));return server;
}
export async function runValidatorWorkerV4(){
  const [mode,path]=process.argv.slice(2);
  if(mode==='--initialize-key'){await writeFile(path,randomBytes(32),{flag:'wx',mode:0o600});const secret=await readFile(path);console.log(JSON.stringify({publicKey:hex(ed25519.getPublicKey(secret))}));return;}
  if(!['--worker','--relay'].includes(mode)||!path)throw fail('VALIDATOR_PRIVATE_CONFIG_REQUIRED');
  const config=JSON.parse(await readFile(path,'utf8')),server=await (mode==='--worker'?startValidatorWorkerV4(config):startValidatorRelayV4(config));
  console.log(JSON.stringify({status:'ready',role:mode.slice(2),validatorId:config.id||null}));
  for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>server.close());
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)runValidatorWorkerV4().catch(()=>{console.error(JSON.stringify({code:'VALIDATOR_STARTUP_FAILED'}));process.exitCode=1;});
