import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {randomBytes} from 'node:crypto';
import {ed25519} from '@noble/curves/ed25519';
import {FactoryValidatorFleetV4,validateReplayAttestationV4} from '../tools/factory_validator_fleet_v4.mjs';
import {canonical,hash} from '../web/target-protocol-v2.mjs';

const token='private-test-token',members=[],servers=[],secrets=[];
const report={submission:'submission',task:'task',attempt:1,fullReplay:true,completeTrials:1,valid:true,measurements:[{replayStatus:'VALID',replayVerified:true,fullReplay:true,steps:256,resultRoot:'a'.repeat(64),bytes:480,metrics:{passed:true}}]};
let divergent=1,tampered=false,lastAttestation,lastRequest;
try{
  for(let i=0;i<4;i++){
    const secret=randomBytes(32),member={id:'validator-'+i,publicKey:Buffer.from(ed25519.getPublicKey(secret)).toString('hex')};secrets.push(secret);
    const server=createServer(async(req,res)=>{
      if(req.headers.authorization!=='Bearer '+token){res.writeHead(401);res.end();return;}
      if(req.url==='/health'){res.end(JSON.stringify({validatorId:member.id,publicKey:member.publicKey,ready:true,busy:false,completed:0}));return;}
      let text='';for await(const chunk of req)text+=chunk;const request=JSON.parse(text);
      const actual={...report,valid:i>=4-divergent?false:true},body={schema:'flybrain-validator-attestation-v1',validatorId:member.id,publicKey:member.publicKey,nonce:request.nonce,operation:request.operation,factory:request.deployment.factory,submission:request.submission,completedAt:Date.now(),report:actual,reportHash:await hash(canonical(actual))};
      const attestation={...body,signature:Buffer.from(ed25519.sign(canonical(body),secret)).toString('hex')};
      lastAttestation=attestation;lastRequest=request;
      if(tampered)attestation.report={...attestation.report,attempt:999};res.end(JSON.stringify(attestation));
    });await new Promise(ok=>server.listen(0,'127.0.0.1',ok));servers.push(server);members.push({...member,url:'http://127.0.0.1:'+server.address().port});
  }
  const config={schema:'flybrain-validator-fleet-v1',members,minimumAttestations:3},fleet=await new FactoryValidatorFleetV4(config,token).initialize();
  assert.equal(fleet.summary().ready,4);
  const input={operation:'replay',submission:'submission',deployment:{factory:'factory'}};
  assert.equal((await fleet.replayAll(input)).report.distributedVerification.attestations.length,3);
  const member=members.find(m=>m.id===lastAttestation.validatorId);
  await assert.rejects(validateReplayAttestationV4(lastAttestation,member,{...lastRequest,nonce:'0'.repeat(48)}),/FLEET_ATTESTATION_INVALID/);
  const altered={...lastAttestation,reportHash:'0'.repeat(64)};await assert.rejects(validateReplayAttestationV4(altered,member,lastRequest),/FLEET_ATTESTATION_INVALID/);
  divergent=2;await assert.rejects(fleet.replayAll(input),/FLEET_REPLAY_QUORUM/);
  divergent=0;tampered=true;await assert.rejects(fleet.replayAll(input),/FLEET_REPLAY_QUORUM/);
  assert.throws(()=>new FactoryValidatorFleetV4({...config,members:[members[0],members[0]],minimumAttestations:2},token),/FLEET_MEMBER_IDENTITY/);
  assert.throws(()=>new FactoryValidatorFleetV4({...config,members:[{...members[0],url:'http://example.com'}],minimumAttestations:1},token),/FLEET_MEMBER_IDENTITY/);
  console.log(JSON.stringify({passed:true,signedQuorum:true,divergenceRejected:true,tamperingRejected:true,nonceBound:true,duplicateIdentityRejected:true,loopbackRequired:true}));
}finally{await Promise.all(servers.map(server=>new Promise(ok=>server.close(ok))));}
