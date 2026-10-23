import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {randomBytes} from 'node:crypto';
import {ed25519} from '@noble/curves/ed25519';
import {Keypair} from '@solana/web3.js';
import {FactoryValidatorFleetV4} from '../tools/factory_validator_fleet_v4.mjs';
import {FactoryPoolServiceV4} from '../tools/factory_pool_service_v4.mjs';
import {canonical,hash} from '../web/target-protocol-v2.mjs';
import {STATE} from '../web/task-factory-v4-codec.mjs';

const deferred=()=>{let resolve;const promise=new Promise(ok=>resolve=ok);return {promise,resolve};};
const tick=()=>new Promise(setImmediate);
async function within(work,milliseconds=1500){
  let timer;
  try{return await Promise.race([work,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('TEST_WAIT_BOUND')),milliseconds);})]);}
  finally{clearTimeout(timer);}
}
const input={operation:'replay',submission:'candidate-a',deployment:{factory:'fixture-factory'}};
const results=[];

async function fixture(modes,{minimum=3,timeout=2000,barrier=false}={}){
  const token=randomBytes(24).toString('hex'),members=[],servers=[],closed=modes.map(()=>deferred()),allStarted=deferred();
  const busy=modes.map(()=>false);let requests=0;
  for(const [index,mode]of modes.entries()){
    const secret=randomBytes(32),member={id:'validator-'+index,publicKey:Buffer.from(ed25519.getPublicKey(secret)).toString('hex')};
    const server=createServer(async(req,res)=>{
      try{
        if(req.headers.authorization!=='Bearer '+token){res.writeHead(401).end();return;}
        if(req.url==='/health'){res.end(JSON.stringify({validatorId:member.id,publicKey:member.publicKey,ready:true,busy:busy[index],completed:0}));return;}
        let body='';for await(const part of req)body+=part;
        const request=JSON.parse(body);requests++;if(requests>=modes.length)allStarted.resolve();
        if(busy[index]){res.writeHead(409).end();return;}
        busy[index]=true;res.once('close',()=>closed[index].resolve());
        try{
          if(barrier)await allStarted.promise;
          if(mode.hold)await mode.hold.promise;
          if(mode.status){res.writeHead(mode.status).end();return;}
          const report={submission:request.submission,task:'fixture-task',attempt:1,fullReplay:true,completeTrials:1,valid:!mode.divergent,
            measurements:[{replayStatus:'VALID',replayVerified:true,fullReplay:true,steps:256,resultRoot:'a'.repeat(64),bytes:480,metrics:{passed:true}}]};
          const packet={schema:'flybrain-validator-attestation-v1',validatorId:member.id,publicKey:member.publicKey,nonce:request.nonce,
            operation:request.operation,factory:request.deployment.factory,submission:request.submission,completedAt:Date.now(),report,reportHash:await hash(canonical(report))};
          const attestation={...packet,signature:Buffer.from(ed25519.sign(canonical(packet),secret)).toString('hex')};
          if(mode.tamper)attestation.report={...report,attempt:999};
          if(!res.destroyed)res.end(JSON.stringify(attestation));
        }finally{busy[index]=false;}
      }catch{if(!res.destroyed)res.writeHead(503).end();}
    });
    await new Promise(ok=>server.listen(0,'127.0.0.1',ok));servers.push(server);
    members.push({...member,url:'http://127.0.0.1:'+server.address().port});
  }
  const config={schema:'flybrain-validator-fleet-v1',minimumAttestations:minimum,requestTimeoutMs:timeout,members};
  return {fleet:new FactoryValidatorFleetV4(config,token),config,token,closed,allStarted,
    get requests(){return requests;},
    release(){for(const mode of modes)mode.hold?.resolve();},
    async close(){this.release();await tick();await Promise.all(servers.map(s=>{s.closeAllConnections();return new Promise(ok=>s.close(ok));}));}
  };
}

{
  const last=deferred(),h=await fixture([{}, {}, {}, {hold:last}],{barrier:true});
  try{
    const first=h.fleet.replayAll(input);await within(h.allStarted.promise);
    const result=await within(first),snapshot=Buffer.from(canonical(result)).toString('hex');
    assert.equal(result.report.distributedVerification.attestations.length,3);
    await within(h.closed[3].promise);
    // The remote replay may still be busy after its HTTP wait was cancelled.
    // The other three workers must be sufficient for the following candidate.
    const second=await within(h.fleet.replayAll({...input,submission:'candidate-b'}));
    assert.equal(second.report.submission,'candidate-b');
    assert.equal(second.report.distributedVerification.attestations.length,3);
    last.resolve();await tick();await tick();
    assert.equal(Buffer.from(canonical(result)).toString('hex'),snapshot,'Late reports changed an already returned report');
    results.push('Three signed matches finish while a fourth native job is held; cancelled transport and a busy fourth do not block the next candidate or mutate evidence');
  }finally{await h.close();}
}
{
  const h=await fixture([{}, {}, {divergent:true}, {divergent:true}]);
  try{await assert.rejects(within(h.fleet.replayAll(input)),/FLEET_REPLAY_QUORUM/);results.push('Two conflicting pairs produce no accepted report');}
  finally{await h.close();}
}
{
  const h=await fixture([{}, {}, {tamper:true}, {tamper:true}]);
  try{await assert.rejects(within(h.fleet.replayAll(input)),/FLEET_REPLAY_QUORUM/);results.push('Forged evidence cannot complete a quorum');}
  finally{await h.close();}
}
{
  const a=deferred(),b=deferred(),h=await fixture([{status:503},{status:503},{hold:a},{hold:b}],{barrier:true});
  try{await assert.rejects(within(h.fleet.replayAll(input)),/FLEET_REPLAY_QUORUM/);results.push('An impossible quorum fails before waiting for unresponsive members');}
  finally{await h.close();}
}
{
  const a=deferred(),b=deferred(),h=await fixture([{}, {}, {hold:a}, {hold:b}],{timeout:150});
  try{
    await assert.rejects(within(h.fleet.replayAll(input)),/FLEET_REPLAY_DEADLINE/);
    await within(Promise.all([h.closed[2].promise,h.closed[3].promise]));
    results.push('A bounded collection deadline cancels remaining transport without fabricating a scientific rejection');
  }finally{await h.close();}
}
{
  const a=deferred(),b=deferred(),h=await fixture([{}, {}, {hold:a}, {hold:b}],{timeout:2000});
  try{
    const started=Date.now();
    await assert.rejects(within(h.fleet.replayAll(input,{deadlineAt:started+150})),/FLEET_REPLAY_DEADLINE/);
    assert(Date.now()-started<1200);
    results.push('The task deadline takes precedence over the longer configured worker timeout');
  }finally{await h.close();}
}
{
  const h=await fixture([{}, {}, {}, {}]);
  try{
    await assert.rejects(h.fleet.replayAll(input,{deadlineAt:Date.now()-1}),/FLEET_REPLAY_DEADLINE/);
    await assert.rejects(h.fleet.replayAll(input,{deadlineAt:NaN}),/FLEET_REPLAY_DEADLINE/);
    assert.equal(h.requests,0);
    assert.throws(()=>new FactoryValidatorFleetV4({...h.config,requestTimeoutMs:600001},h.token),/FLEET_CONFIGURATION/);
    results.push('Expired or invalid collection budgets dispatch no replay');
  }finally{await h.close();}
}
{
  const late=deferred(),h=await fixture([{}, {}, {hold:late,divergent:true}, {hold:late,divergent:true}, {hold:late,divergent:true}],{minimum:2});
  try{
    let returned=false;const work=h.fleet.replayAll(input).then(v=>{returned=true;return v;});
    await within(h.allStarted.promise);await tick();await tick();assert.equal(returned,false);
    late.resolve();const result=await within(work);
    assert.equal(result.report.valid,false);assert.equal(result.report.distributedVerification.attestations.length,3);
    results.push('A minority threshold cannot return an early group that a larger unfinished group can overtake');
  }finally{await h.close();}
}
{
  const late=deferred(),h=await fixture([{hold:late},{hold:late},{divergent:true},{divergent:true}],{minimum:2});
  try{
    const work=h.fleet.replayAll(input);await within(h.allStarted.promise);await tick();await tick();
    late.resolve();const result=await within(work);
    assert.equal(result.report.valid,true);
    results.push('A final equal-sized minority tie retains configured member order regardless of reply order');
  }finally{await h.close();}
}
{
  const h=await fixture([{}, {}, {}, {}]);
  try{
    const reader={expected:{factoryAddress:{toBase58:()=>input.deployment.factory}}};
    const result=await h.fleet.verify({reader,address:input.submission,deployment:input.deployment,deadlineAt:Date.now()+1500});
    const count=h.requests;
    const reused=await h.fleet.verify({reader,address:input.submission,deployment:input.deployment,deadlineAt:Date.now()-1});
    assert.equal(reused,result);assert.equal(h.requests,count);
    results.push('Existing accepted evidence is reused for the next settlement signer without starting another collection');
  }finally{await h.close();}
}
{
  const signer=Keypair.generate(),factory=Keypair.generate().publicKey,task=Keypair.generate().publicKey,address=Keypair.generate().publicKey;
  const chainNow=Math.floor(Date.now()/1000)-86400;
  const submission={task:task.toBytes(),attempt:1,state:STATE.REVEALED,validVotes:0,invalidVotes:0};
  const taskState={factory:factory.toBytes(),index:0,attempt:1,state:STATE.ACTIVE,verifyDeadline:chainNow+90};
  const reader={expected:{factoryAddress:factory},a:{task:()=>task},account:async p=>p.equals(address)?submission:taskState,
    factory:async()=>({verifiers:[signer.publicKey.toBytes()],activeIndex:0})};
  const connection={getSlot:async()=>1,getBlockTime:async()=>chainNow};let calls=0;
  const queue={pool:{query:async sql=>{assert.match(sql,/^SELECT/);return {rows:[]};}}};
  const service=new FactoryPoolServiceV4({config:{deployment:{cluster:'devnet'},replayConcurrency:1,maxTransactionsPerVerifier:1,
    confirmationMarginSeconds:60,contentDir:'/unused-content',outputDir:'/unused-output'},queue,connection,signers:[signer,{}],
    verify:async args=>{calls++;assert(args.deadlineAt>Date.now()+29000&&args.deadlineAt<=Date.now()+30000);throw new Error('STOP_BEFORE_WRITE');}});
  service.contexts.set(factory.toBase58(),{reader,deployment:{factory:factory.toBase58()}});
  await assert.rejects(service.replayInternal({id:'fixture',fence:'1',payload:{factory:factory.toBase58(),payer:signer.publicKey.toBase58(),submission:address.toBase58()}}),/STOP_BEFORE_WRITE/);
  assert.equal(calls,1);
  results.push('The coordinator derives collection time from finalized chain time and reserves the configured confirmation margin, despite local clock offset');
}
console.log(JSON.stringify({passed:true,cases:results.length,checks:results,scope:'Actual loopback HTTP with fixture scientific reports; no model computation, wallet persistence or chain I/O',chainWrites:0}));
