// Complete scientific replay is distributed independently of frozen settlement keys.
import {readFile} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {ed25519} from '@noble/curves/ed25519';
import {Connection,PublicKey} from '@solana/web3.js';
import {ValidatorBondReaderV1} from '../web/validator-bond-v1.mjs';
import {canonical,hash} from '../web/target-protocol-v2.mjs';

const fail=code=>Object.assign(new Error(code),{code});
const hex=bytes=>Buffer.from(bytes).toString('hex');
export const replayConsensusV4=report=>({submission:report.submission,task:report.task,attempt:report.attempt,fullReplay:report.fullReplay,completeTrials:report.completeTrials,valid:report.valid,measurements:report.measurements.map(m=>({replayStatus:m.replayStatus,replayVerified:m.replayVerified,fullReplay:m.fullReplay,steps:m.steps,resultRoot:m.resultRoot,bytes:m.bytes,metrics:m.metrics}))});
export async function validateReplayAttestationV4(attestation,member,request){
  const {signature,...body}=attestation||{};
  if(body.schema!=='flybrain-validator-attestation-v1'||body.validatorId!==member.id||body.publicKey!==member.publicKey||body.nonce!==request.nonce||body.operation!==request.operation||body.factory!==(request.deployment?.factory||null)||body.submission!==request.submission||!Number.isSafeInteger(body.completedAt)||Math.abs(Date.now()-body.completedAt)>15*60*1000||!/^[a-f0-9]{128}$/.test(signature||'')||!ed25519.verify(Buffer.from(signature,'hex'),canonical(body),Buffer.from(member.publicKey,'hex')))throw fail('FLEET_ATTESTATION_INVALID');
  if(await hash(canonical(body.report))!==body.reportHash)throw fail('FLEET_REPORT_HASH');
  if(request.operation==='replay'&&(body.report.submission!==request.submission||body.report.fullReplay!==true||body.report.completeTrials<1||body.report.measurements?.length!==body.report.completeTrials))throw fail('FLEET_REPORT_SCOPE');
  return body.report;
}
export class FactoryValidatorFleetV4 {
  constructor(config,token){
    if(config.schema!=='flybrain-validator-fleet-v1'||!Array.isArray(config.members)||config.members.length<1||config.members.length>64||!Number.isInteger(config.minimumAttestations)||config.minimumAttestations<1||config.minimumAttestations>config.members.length)throw fail('FLEET_CONFIGURATION');
    const ids=new Set(),keys=new Set();
    for(const member of config.members){const url=new URL(member.url);if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||url.username||url.password||!/^[a-z0-9-]{1,64}$/.test(member.id)||!/^[a-f0-9]{64}$/.test(member.publicKey)||ids.has(member.id)||keys.has(member.publicKey))throw fail('FLEET_MEMBER_IDENTITY');ids.add(member.id);keys.add(member.publicKey);}
    if(config.requestTimeoutMs!==undefined&&(!Number.isSafeInteger(config.requestTimeoutMs)||config.requestTimeoutMs<1||config.requestTimeoutMs>600000))throw fail('FLEET_CONFIGURATION');
    Object.assign(this,{config,token,cache:new Map(),lastProbe:null});
    if(config.staking){
      const connection=new Connection(config.stakingRpcUrl||'http://127.0.0.1:8796/rpc',{commitment:'finalized',disableRetryOnRateLimit:true,fetch:(url,options)=>fetch(url,{...options,headers:{...options?.headers,authorization:'Bearer '+token},signal:AbortSignal.timeout(15000)})});
      this.bonds=new ValidatorBondReaderV1(connection,config.staking);
    }
  }
  static async load(path){const config=JSON.parse(await readFile(path,'utf8'));if(!config.staking)throw fail('FLEET_BOND_CONFIGURATION_REQUIRED');return new this(config,(await readFile(config.tokenFile,'utf8')).trim());}
  async memberBond(member){return this.bonds?this.bonds.check(new PublicKey(Buffer.from(member.publicKey,'hex'))):null;}
  async request(member,path,body,timeout=600000,signal){const limit=AbortSignal.timeout(timeout),response=await fetch(new URL(path,member.url),{method:body?'POST':'GET',headers:{authorization:'Bearer '+this.token,...(body?{'content-type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,signal:signal?AbortSignal.any([signal,limit]):limit});if(!response.ok)throw fail('FLEET_WORKER_UNAVAILABLE');const text=await response.text();if(text.length>2*1024*1024)throw fail('FLEET_RESPONSE_BOUND');return JSON.parse(text);}
  async probe(){
    const results=await Promise.allSettled(this.config.members.map(async member=>{const bond=await this.memberBond(member),health=await this.request(member,'/health',null,15000);if(health.validatorId!==member.id||health.publicKey!==member.publicKey||health.ready!==true||(bond&&health.staking?.bond!==bond.bond))throw fail('FLEET_WORKER_NOT_READY');return {id:member.id,ready:true,busy:health.busy,completed:health.completed,...(bond?{staking:bond}:{})};}));
    this.lastProbe={at:Date.now(),ready:results.filter(r=>r.status==='fulfilled').length,members:results.map((r,i)=>r.status==='fulfilled'?r.value:{id:this.config.members[i].id,ready:false})};return this.summary();
  }
  summary(){return {schema:'flybrain-validator-fleet-status-v1',configured:this.config.members.length,minimumAttestations:this.config.minimumAttestations,ready:this.lastProbe?.ready||0,at:this.lastProbe?.at||null,members:this.lastProbe?.members||[]};}
  async initialize(){await this.probe();if(this.lastProbe.ready<this.config.minimumAttestations)throw fail('FLEET_QUORUM_UNAVAILABLE');return this;}
  async verify({reader,address,deployment,deadlineAt}){
    const submission=String(address),key=reader.expected.factoryAddress.toBase58()+':'+submission;
    if(deadlineAt!==undefined&&!Number.isSafeInteger(deadlineAt))throw fail('FLEET_REPLAY_DEADLINE');
    if(this.cache.has(key))return this.cache.get(key);
    if(deadlineAt!==undefined&&deadlineAt<=Date.now())throw fail('FLEET_REPLAY_DEADLINE');
    const operation=this.replayAll({operation:'replay',submission,deployment},{deadlineAt});
    this.cache.set(key,operation);
    try{const result=await operation;setTimeout(()=>this.cache.delete(key),120000).unref();return result;}catch(error){this.cache.delete(key);throw error;}
  }
  async replayAll(input,{deadlineAt}={}){
    if(deadlineAt!==undefined&&!Number.isSafeInteger(deadlineAt))throw fail('FLEET_REPLAY_DEADLINE');
    const expires=Math.min(Date.now()+(this.config.requestTimeoutMs||600000),deadlineAt??Infinity);
    if(expires<=Date.now())throw fail('FLEET_REPLAY_DEADLINE');
    const request={...input,nonce:hex(randomBytes(24))};
    const controller=new AbortController(),groups=new Map();
    const agreed=await new Promise((resolve,reject)=>{
      let pending=this.config.members.length,settled=false;
      const finish=(error,group)=>{
        if(settled)return;settled=true;clearTimeout(timer);
        // Cancel transport waits. A remote native replay may finish and retain
        // its signed evidence; cancellation never asserts scientific invalidity.
        controller.abort();
        if(error)reject(error);else resolve([...group]);
      };
      const timer=setTimeout(()=>finish(fail('FLEET_REPLAY_DEADLINE')),Math.max(1,expires-Date.now()));
      const advance=()=>{
        if(settled)return;
        if(Date.now()>=expires)return finish(fail('FLEET_REPLAY_DEADLINE'));
        const order=group=>Math.min(...group.map(value=>this.config.members.indexOf(value.member)));
        const ordered=[...groups.values()].sort((a,b)=>b.length-a.length||order(a)-order(b)),first=ordered[0]||[];
        // Preserve the largest-agreement rule even for a configured minority:
        // early completion is safe only when no unfinished group can overtake it.
        if(first.length>=this.config.minimumAttestations&&(!pending||first.length>(ordered[1]?.length||0)+pending))return finish(null,first);
        if(first.length+pending<this.config.minimumAttestations)return finish(fail('FLEET_REPLAY_QUORUM'));
      };
      for(const member of this.config.members){
        void (async()=>{
          try{
            const bond=await this.memberBond(member);
            if(settled||Date.now()>=expires)return;
            const attestation=await this.request(member,'/'+request.operation,request,Math.max(1,expires-Date.now()),controller.signal);
            const report=await validateReplayAttestationV4(attestation,member,request);
            if(bond&&(!attestation.bond||attestation.bond.bond!==bond.bond||attestation.bond.validator!==bond.validator||attestation.bond.generation!==bond.generation||attestation.bond.state!=='active'||BigInt(attestation.bond.amountAtoms)<BigInt(bond.amountAtoms)))throw fail('FLEET_BOND_ATTESTATION_SCOPE');
            const key=await hash(canonical(replayConsensusV4(report)));
            if(!settled){const group=groups.get(key)||[];group.push({member,report,attestation});groups.set(key,group);}
          }catch{
            // Missing, busy, forged and divergent workers cannot create a vote.
            // Every request has a rejection handler, including late completions.
          }finally{pending--;advance();}
        })();
      }
    });
    if(Date.now()>=expires)throw fail('FLEET_REPLAY_DEADLINE');
    agreed.sort((a,b)=>this.config.members.indexOf(a.member)-this.config.members.indexOf(b.member));
    const report={...agreed[0].report,distributedVerification:{schema:'flybrain-distributed-replay-v1',minimumAttestations:this.config.minimumAttestations,consensusHash:await hash(canonical(replayConsensusV4(agreed[0].report))),attestations:agreed.map(v=>v.attestation)}};
    if(Date.now()>=expires)throw fail('FLEET_REPLAY_DEADLINE');
    return {report};
  }
}
