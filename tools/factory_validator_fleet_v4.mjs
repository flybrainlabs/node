// Complete scientific replay is distributed independently of frozen settlement keys.
import {readFile} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {ed25519} from '@noble/curves/ed25519';
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
    Object.assign(this,{config,token,cache:new Map(),lastProbe:null});
  }
  static async load(path){const config=JSON.parse(await readFile(path,'utf8'));return new this(config,(await readFile(config.tokenFile,'utf8')).trim());}
  async request(member,path,body,timeout=600000){const response=await fetch(new URL(path,member.url),{method:body?'POST':'GET',headers:{authorization:'Bearer '+this.token,...(body?{'content-type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(timeout)});if(!response.ok)throw fail('FLEET_WORKER_UNAVAILABLE');const text=await response.text();if(text.length>2*1024*1024)throw fail('FLEET_RESPONSE_BOUND');return JSON.parse(text);}
  async probe(){
    const results=await Promise.allSettled(this.config.members.map(async member=>{const health=await this.request(member,'/health',null,5000);if(health.validatorId!==member.id||health.publicKey!==member.publicKey||health.ready!==true)throw fail('FLEET_WORKER_NOT_READY');return {id:member.id,ready:true,busy:health.busy,completed:health.completed};}));
    this.lastProbe={at:Date.now(),ready:results.filter(r=>r.status==='fulfilled').length,members:results.map((r,i)=>r.status==='fulfilled'?r.value:{id:this.config.members[i].id,ready:false})};return this.summary();
  }
  summary(){return {schema:'flybrain-validator-fleet-status-v1',configured:this.config.members.length,minimumAttestations:this.config.minimumAttestations,ready:this.lastProbe?.ready||0,at:this.lastProbe?.at||null,members:this.lastProbe?.members||[]};}
  async initialize(){await this.probe();if(this.lastProbe.ready<this.config.minimumAttestations)throw fail('FLEET_QUORUM_UNAVAILABLE');return this;}
  async verify({reader,address,deployment}){
    const submission=String(address),key=reader.expected.factoryAddress.toBase58()+':'+submission;
    if(this.cache.has(key))return this.cache.get(key);
    const operation=this.replayAll({operation:'replay',submission,deployment});
    this.cache.set(key,operation);
    try{const result=await operation;setTimeout(()=>this.cache.delete(key),120000).unref();return result;}catch(error){this.cache.delete(key);throw error;}
  }
  async replayAll(input){
    const request={...input,nonce:hex(randomBytes(24))};
    const results=await Promise.allSettled(this.config.members.map(async member=>{const attestation=await this.request(member,'/'+request.operation,request);const report=await validateReplayAttestationV4(attestation,member,request);return {member,report,attestation};}));
    const groups=new Map();
    for(const result of results){if(result.status!=='fulfilled')continue;const value=result.value,key=await hash(canonical(replayConsensusV4(value.report)));const group=groups.get(key)||[];group.push(value);groups.set(key,group);}
    const agreed=[...groups.values()].sort((a,b)=>b.length-a.length)[0];
    if(!agreed||agreed.length<this.config.minimumAttestations)throw fail('FLEET_REPLAY_QUORUM');
    const report={...agreed[0].report,distributedVerification:{schema:'flybrain-distributed-replay-v1',minimumAttestations:this.config.minimumAttestations,consensusHash:await hash(canonical(replayConsensusV4(agreed[0].report))),attestations:agreed.map(v=>v.attestation)}};
    return {report};
  }
}
