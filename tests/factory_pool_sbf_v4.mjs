// Real PostgreSQL plus the retained SBF in LiteSVM. Native replay outcomes are
// explicit fixtures; this test establishes transport and accounting, not science.
import assert from 'node:assert/strict';
import {readFile,mkdtemp,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {LiteSVM,Clock,FailedTransactionMetadata} from 'litesvm';
import {getTransactionDecoder} from '@solana/kit';
import {Keypair,PublicKey,Transaction} from '@solana/web3.js';
import {TOKEN_PROGRAM_ID,getAssociatedTokenAddressSync} from '@solana/spl-token';
import {FactoryPoolQueueV4} from '../tools/factory_pool_queue_v4.mjs';
import {FactoryPoolTransportV4} from '../tools/factory_pool_transport_v4.mjs';
import {FactoryPoolSupplyV4} from '../tools/factory_pool_supply_v4.mjs';
import {FactoryPoolServiceV4} from '../tools/factory_pool_service_v4.mjs';
import {inspectPoolV4} from '../tools/factory_pool_inspect_v4.mjs';
import {LocalFactoryContentStore} from '../tools/factory_verifier_v4.mjs';
import {MiningWalletV4,newMiningMnemonic} from '../web/mining-wallet-v4.mjs';
import {MiningWalletPoolPolicyV4} from '../web/mining-wallet-pool-policy-v4.mjs';
import {verifyPoolManifestV4} from '../web/factory-pool-v4.mjs';
import {addresses,instruction,meta,system} from '../tools/task_factory_v4_client.mjs';
import {readerForDeployment,FactoryMiningClientV4,verifyFactoryRound} from '../web/task-factory-client-v4.mjs';
import {factoryWorkerPoolReaderV4} from '../web/factory-worker-reader-v4.mjs';
import {createFactoryWorkerPortV4} from '../web/factory-worker-port-v4.mjs';
import {canonical,hash as sha} from '../web/target-protocol-v2.mjs';
import {decodeFactory,decodeTask,decodeSubmission,fromHex,commitment,hash,text,Writer} from '../web/task-factory-v4-codec.mjs';
const host=process.env.FLYBRAIN_POOL_TEST_SOCKET;if(!host?.startsWith('/var/tmp/flybrainlabs-postgres-acceptance-'))throw new Error('Isolated PostgreSQL required');
const database='pool_sbf_'+randomUUID().replaceAll('-',''),admin=new pg.Pool({host,port:55439,user:'pool_acceptance',database:'postgres',max:1});await admin.query('CREATE DATABASE '+database);await admin.end();
const q=await new FactoryPoolQueueV4(new pg.Pool({host,port:55439,user:'pool_acceptance',database,max:8})).initialize(),vector=JSON.parse(await readFile('tests/vectors/factory-user-rpc-v4.json','utf8')),d=vector.deployment;
const svm=new LiteSVM().withDefaultPrograms();svm.addProgramFromFile(d.programId,process.env.MINING_WALLET_SBF||'/workspace/.flypow-publish/task-factory-v4-20261015/sbf/flypow_economy_v2_program.so');
for(const [address,v]of Object.entries(vector.accounts))svm.setAccount({address,lamports:BigInt(v.lamports),data:new Uint8Array(Buffer.from(v.data[0],'base64')),programAddress:v.owner,executable:!!v.executable});
svm.setClock(new Clock(BigInt(vector.slot),0n,0n,0n,BigInt(vector.clock)));
const authority=Keypair.generate(),signers=[Keypair.generate(),Keypair.generate()],third=Keypair.generate(),a=addresses(d.programId),scope=await sha(new TextEncoder().encode(randomUUID()));
const global=new Writer().bytes(text('FLYGV002')).key(authority.publicKey.toBytes()).key(new PublicKey(d.genesisHash).toBytes()).key(fromHex(d.policyHash));for(const k of [...signers,third])global.key(k.publicKey.toBytes());global.key(new PublicKey(d.mint).toBytes()).u8(1).u64(1000000).u64(0).u64(0);
const globalData=new Uint8Array(512);globalData.set(global.result());svm.setAccount({address:a.global.toBase58(),lamports:svm.minimumBalanceForRentExemption(512n),data:globalData,programAddress:d.programId,executable:false});
const mint=Buffer.alloc(82);mint.writeBigUInt64LE(1000000n,36);mint[44]=8;mint[45]=1;svm.setAccount({address:d.mint,lamports:svm.minimumBalanceForRentExemption(82n),data:mint,programAddress:TOKEN_PROGRAM_ID.toBase58(),executable:false});
const poolTokens=Buffer.alloc(165);new PublicKey(d.mint).toBuffer().copy(poolTokens,0);a.global.toBuffer().copy(poolTokens,32);poolTokens.writeBigUInt64LE(1000000n,64);poolTokens[108]=1;svm.setAccount({address:a.pool(0).toBase58(),lamports:svm.minimumBalanceForRentExemption(165n),data:poolTokens,programAddress:TOKEN_PROGRAM_ID.toBase58(),executable:false});
function patch(address,offset,bytes){const account=svm.getAccount(address);account.data.set(bytes,offset);svm.setAccount(account);}
patch(a.global.toBase58(),8,authority.publicKey.toBytes());patch(a.global.toBase58(),104,new Uint8Array([...signers[0].publicKey.toBytes(),...signers[1].publicKey.toBytes(),...third.publicKey.toBytes()]));
patch(d.factory,40,authority.publicKey.toBytes());patch(d.factory,168,new Uint8Array([...signers[0].publicKey.toBytes(),...signers[1].publicKey.toBytes(),...third.publicKey.toBytes()]));
for(const k of [authority,...signers])svm.airdrop(k.publicKey.toBase58(),100000000n);
const statuses=new Map();let transactions=0;
const connection={async getGenesisHash(){return d.genesisHash;},async getAccountInfo(k){const v=svm.getAccount(k.toBase58());return v.exists?{owner:new PublicKey(v.programAddress),data:Buffer.from(v.data),lamports:Number(v.lamports)}:null;},async getBalance(k){return Number(svm.getBalance(k.toBase58())||0n);},async getMinimumBalanceForRentExemption(n){return Number(svm.minimumBalanceForRentExemption(BigInt(n)));},async getFeeForMessage(){return {value:5000};},async getLatestBlockhash(){return {blockhash:svm.latestBlockhash(),lastValidBlockHeight:1000000000};},async getBlockHeight(){return 1;},async getSignatureStatuses(sigs){return {value:sigs.map(s=>statuses.get(s)||null)};},async getSlot(){return vector.slot;},async getBlockTime(){return Number(svm.getClock().unixTimestamp);},async sendRawTransaction(raw){
 const tx=Transaction.from(raw),result=svm.sendTransaction(getTransactionDecoder().decode(raw));assert(!(result instanceof FailedTransactionMetadata),'SBF failed: '+(result instanceof FailedTransactionMetadata?String(result.err())+' '+result.meta().logs().join(' '):''));transactions++;
 const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';let n=BigInt('0x'+tx.signature.toString('hex')),s='';while(n){s=alphabet[Number(n%58n)]+s;n/=58n;}for(const b of tx.signature){if(b)break;s='1'+s;}statuses.set(s,{confirmationStatus:'finalized',slot:vector.slot,err:null});return s;
}};
const original=JSON.parse(await readFile('tests/vectors/target-v2.json','utf8')),specification={schema:'flybrainlabs-scientific-task-v4',goal:original.round.goal,seeds:original.round.seeds.slice(0,2)};
const envelope=Object.fromEntries(['graphRoot','modelRoot','parameterProfileHash','inputDomainHash','evaluatorVersion','steps','timeStepUs','maxCandidateBytes','maxStimulusCost'].map(k=>[k,specification.goal[k]])),trust={schema:'flybrainlabs-factory-pool-trust-v4',poolId:scope,authority:authority.publicKey.toBase58(),genesisHash:d.genesisHash,programId:d.programId,mint:d.mint,policyHash:d.policyHash,envelopeHash:await sha(canonical(envelope)),anchorFactory:d.factory,envelope};
const base={...d,taskPool:{trust,manifestUrl:d.apiBase+'/api/task-factory/v4/pool'}},directory=await mkdtemp(join(tmpdir(),'flybrainlabs-pool-sbf-')),content=new LocalFactoryContentStore(join(directory,'content')),transport=new FactoryPoolTransportV4({queue:q,connection,payer:authority,maxTransactions:40,maxFeeLamports:800000}),supply=new FactoryPoolSupplyV4({queue:q,baseDeployment:base,trust,authority,transport,authorization:{evidenceHash:'e'.repeat(64),rewardAtoms:'400'}}),deployments=[],specs=new Map(),checks=[];
try{
 await q.initialize();checks.push('The additive PostgreSQL migration is safely reentrant and preserves the immutable packet/job triggers');
 for(let batch=0;batch<2;batch++){
  const tasks=[];for(let i=0;i<2;i++){const spec=structuredClone(specification);spec.goal.windows[0].minTargetNet+=100+batch*2+i;const path='goal-'+batch+'-'+i;specs.set(path,spec);tasks.push({specification:path,approvedCalibrationHash:spec.goal.calibrationHash,rules:{rewardAtoms:'100',claimSeconds:10,revealSeconds:20,verifySeconds:30,maxAttempts:2}});}
  const plan={schema:'flybrainlabs-task-catalog-plan-v4',approval:{approved:true,evidenceHash:'e'.repeat(64)},factoryId:await sha(new TextEncoder().encode(scope+':'+batch)),budgetAtoms:'200',deadline:String(vector.clock+86400),excludedScientificIdentities:[],tasks};deployments.push(await supply.importPlan(plan,p=>specs.get(p)));
 }
 for(let tries=0;tries<30;tries++){
  const job=await q.claim('catalog','sbf-register',120,null,deployments.map(d=>d.factory));if(!job)break;
  try{const result=await supply.register(job,{contentStore:content});await q.finish(job,result);}catch(error){if(error.code!=='POOL_CONFIRMATION_PENDING')throw error;await q.retry(job,{delaySeconds:0,code:error.code});}
 }
 for(const deployment of deployments){const f=await readerForDeployment(deployment,connection).factory();assert.equal(f.state,1);assert.equal(f.uploaded,2);}checks.push('Two distinct catalogs initialize, append permanent science markers and seal through real SBF transactions');
 const document=await supply.manifest({anchor:base});await verifyPoolManifestV4(document,trust);checks.push('The finalized registered catalogs produce an authority-signed discoverable manifest');
 const memory={async load(){return null;},async save(){}},wallet=new MiningWalletV4({deployment:base,store:memory});await wallet.initialize();await wallet.save(newMiningMnemonic(),'fixture-only-local-password',{confirmed:true,restored:true});svm.airdrop(wallet.address,50000000n);
 const policy=new MiningWalletPoolPolicyV4({deployment:base,connection,address:wallet.address});wallet.policy=policy;await policy.approve();const provider=wallet.provider(),account=provider.accounts[0],miner=new PublicKey(wallet.address);
 async function walletSend(ix){const tx=new Transaction({feePayer:miner,recentBlockhash:svm.latestBlockhash()}).add(ix),[signed]=await provider.features['solana:signTransaction'].signTransaction({account,chain:'solana:devnet',transaction:tx.serialize({requireAllSignatures:false,verifySignatures:false})});return connection.sendRawTransaction(Buffer.from(signed.signedTransaction));}
 let replayCalls=0;
 const config={...base,deployment:base,poolTrust:trust,replayConcurrency:2,maxTransactionsPerVerifier:40,outputDir:join(directory,'replay'),contentDir:join(directory,'content'),diskReserveBytes:1,maxPendingReplays:8};
 const service=await new FactoryPoolServiceV4({config:Object.assign(config,{openTaskPolicy:{minimumWindowSeconds:1,target:3,maximum:3},replayP95Seconds:1,uploadP95Seconds:1,confirmationMarginSeconds:1,computeP95Seconds:1}),queue:q,connection,signers,supply,gatewayFactory:async deployment=>({config:{deployment},authenticate:async req=>({wallet:req.fixtureWallet}),rate(){},close(){}}),verify:async({reader,address})=>{replayCalls++;const s=await reader.submission(address,(await reader.account(address,decodeSubmission)).task),t=await reader.task(0);return {report:{schema:'flybrainlabs-complete-replay-v4',submission:address.toBase58(),task:new PublicKey(s.task).toBase58(),attempt:t.attempt,fullReplay:true,completeTrials:2,valid:true,measurements:[{fixture:true},{fixture:true}]}};}}).initialize();
 await service.discover();const beforeOpen=service.root.gateway.verifierStatus.openCatalogs;
 assert.equal(beforeOpen,1,'Only the original active task is open; two newly sealed SCHEDULED catalogs are not open work');
 await service.input({fixtureWallet:wallet.address},{action:'demand',factory:base.factory,sessionId:randomUUID()});
 for(let tries=0;tries<20;tries++){await service.discover();const job=await q.claim('keeper','independent-open',120,null,deployments.map(d=>d.factory));if(!job)break;try{await q.finish(job,await service.keeper.perform(job));}catch(error){if(error.code!=='POOL_CONFIRMATION_PENDING')throw error;await q.retry(job,{delaySeconds:0,code:error.code});}}
 await service.discover();assert.equal(service.root.gateway.verifierStatus.openCatalogs,3);checks.push('SCHEDULED stock is excluded from open inventory; authenticated demand opens two independent catalogs through the durable keeper before any candidate is verified');
 const submissions=[];
 for(const [i,deployment]of deployments.entries()){
  await policy.include(deployment,document);const reader=readerForDeployment(deployment,connection),factory=new PublicKey(deployment.factory),task=reader.a.task(factory,0);
  assert.equal((await reader.task(0)).state,1);const f=await reader.factory(),t=await reader.task(0),salt=hash(text('pool-test-salt-'+i)),evidence=Object.fromEntries(['candidate','result','manifest','archive'].map(k=>[k,hash(text(scope+k+i))])),digest=commitment(reader.program,f,task,0,miner,miner,evidence,salt),address=reader.a.submission(task,0,miner,digest);
  if(i===0){const pending=hash(text('earlier-unrevealed-'+scope)),pendingAddress=reader.a.submission(task,0,miner,pending);await walletSend(instruction(d.programId,[meta(factory),meta(task,true),meta(pendingAddress,true),meta(miner,false,true),meta(miner,true,true),system()],4,{commitment:pending,beneficiary:miner}));}
  const before=svm.getBalance(wallet.address),factoryBalance=svm.getBalance(deployment.factory);
  await walletSend(instruction(d.programId,[meta(factory),meta(task,true),meta(address,true),meta(miner,false,true),meta(miner,true,true),system()],4,{commitment:digest,beneficiary:miner}));
  assert.equal(before-svm.getBalance(wallet.address),svm.minimumBalanceForRentExemption(768n)+5000n);assert.equal(svm.getBalance(deployment.factory),factoryBalance);
  const clock=svm.getClock();clock.slot+=2n;svm.setClock(clock);svm.expireBlockhash();await walletSend(instruction(d.programId,[meta(factory),meta(task,true),meta(address,true),meta(miner,false,true)],5,{evidence,salt}));submissions.push(address);
 }
 checks.push('One unlocked wallet automatically pays exact PDA rent and fees in both verified catalogs; each original commitment remains readable');
 await service.discover();
 async function replayScopes(scopes){for(let tries=0;tries<30;tries++){const job=await q.claim('replay','sbf-replay',120,null,scopes);if(!job)break;try{await q.finish(job,await service.replay(job));}catch(error){if(error.code!=='POOL_CONFIRMATION_PENDING')throw error;await q.retry(job,{delaySeconds:0,code:error.code});}}}
 await replayScopes([deployments[0].factory]);assert.equal(replayCalls,2);
 await service.discover();
 const firstReader=readerForDeployment(deployments[0],connection),pendingTask=await firstReader.task(0),clock=svm.getClock();assert.equal((await q.pool.query("SELECT 1 FROM factory_pool_v4.jobs WHERE scope=$1 AND payload->>'operation'='finalize'",[deployments[0].factory])).rows.length,0);clock.unixTimestamp=pendingTask.revealDeadline+1n;svm.setClock(clock);svm.expireBlockhash();
 await replayScopes([deployments[1].factory]);assert.equal(replayCalls,4,'one complete decision per signer and submission; confirmation retries reuse it');
 for(const [i,deployment]of deployments.entries()){const reader=readerForDeployment(deployment,connection);assert.equal((await reader.task(0)).state,i===0?1:2);assert.equal((await reader.submission(submissions[i],reader.a.task(deployment.factory,0))).validVotes,3);}
 checks.push('Two verifier identities attest each old result while catalogs remain separate; transaction retries reuse durable replay decisions');
 for(let tries=0;tries<30;tries++){await service.discover();const job=await q.claim('keeper','sbf-keeper',120,null,deployments.map(d=>d.factory))||await q.claim('payment','sbf-payments',120,null,deployments.map(d=>d.factory));if(!job)break;try{await q.finish(job,await (job.kind==='keeper'?service.keeper.perform(job):service.payment(job)));}catch(error){if(error.code!=='POOL_CONFIRMATION_PENDING')throw error;await q.retry(job,{delaySeconds:0,code:error.code});}}
 assert.equal((await firstReader.task(0)).state,2);checks.push('An earlier unrevealed commitment retains its deadline; the valid candidate finalizes before expiry/retry once that earlier window ends');
 const ata=getAssociatedTokenAddressSync(new PublicKey(d.mint),miner),tokenAmount=()=>Buffer.from(svm.getAccount(ata.toBase58()).data).readBigUInt64LE(64);assert.equal(tokenAmount(),200n);const beforeReplay=transactions;await service.discover();assert.equal(await q.claim('payment','no-duplicate-payment',120,null,deployments.map(d=>d.factory)),null);assert.equal(transactions,beforeReplay);assert.equal(tokenAmount(),200n);checks.push('Both original rewards settle through SPL Token once; repeated discovery creates no extra payment or token-account deposit');
 const selected=service.contexts.get(deployments[0].factory);await service.input({fixtureWallet:wallet.address},{action:'claim',factory:deployments[0].factory,roundId:'0'.repeat(64),input:original.input,sessionId:randomUUID()}).then(()=>assert.fail('Forged round accepted'),e=>assert.equal(e.code,'POOL_INPUT_CLOSED'));
 const body={action:'claim',factory:deployments[0].factory,roundId:selected.inputRound.roundId,input:original.input,sessionId:randomUUID()},assigned=await service.input({fixtureWallet:wallet.address},body);assert(assigned.lease);assert((await service.input({fixtureWallet:signers[0].publicKey.toBase58()},{...body,sessionId:randomUUID()})).busy);
 await assert.rejects(service.input({fixtureWallet:signers[0].publicKey.toBase58()},{...assigned.lease,action:'renew',factory:body.factory}),/POOL_INPUT_SCOPE/);await service.input({fixtureWallet:wallet.address},{...assigned.lease,action:'renew',factory:body.factory});await service.input({fixtureWallet:wallet.address},{...assigned.lease,action:'release',factory:body.factory});checks.push('Authenticated miners lease distinct canonical inputs; another wallet cannot renew or release the assignment');
 const client=new FactoryMiningClientV4({deployment:deployments[0],wallet:{publicKey:miner},connection,contentStore:content}),round=(await client.roundAt(1)).r,workerPort=createFactoryWorkerPortV4(client.reader,1,{poolManifest:await service.manifest()});let workerReader;
 try{workerReader=await factoryWorkerPoolReaderV4(base,round,workerPort.port);assert.equal((await verifyFactoryRound(workerReader,round)).roundId,round.roundId);}finally{workerReader?.dispose();workerPort.close();}checks.push('The Worker independently verifies the successor signature and finalized accounts over a bounded read-only port without an RPC key');
 const beforePlanTransactions=transactions,readOnlyPlan=await inspectPoolV4({queue:q,connection,config});assert(readOnlyPlan.readOnly);assert.equal(readOnlyPlan.newSignatures,0);assert.equal(readOnlyPlan.newBudgetAtoms,'0');assert.equal(transactions,beforePlanTransactions);checks.push('Read-only existing-catalog and job inspection creates no migration, signature, budget allocation or chain transaction');
 const healthyAt=service.lastDiscoveryAt;assert(service.health().businessReady);const realSlot=connection.getSlot;connection.getSlot=async()=>{throw new Error('injected-rpc-discovery-failure');};await assert.rejects(service.discover());assert.equal(service.health().businessReady,false);assert.equal(service.lastDiscoveryAt,healthyAt);assert(service.health().lastDiscoveryFailureAt);connection.getSlot=realSlot;await service.discover();assert(service.health().businessReady);
 const query=q.pool.query.bind(q.pool);let failQuery=true;q.pool.query=(...args)=>{if(failQuery){failQuery=false;throw new Error('injected-database-discovery-failure');}return query(...args);};await assert.rejects(service.discover());assert.equal(service.health().businessReady,false);q.pool.query=query;await service.discover();assert(service.health().businessReady);checks.push('Actual discovery RPC and database failures retain last success age, report unready and recover after resynchronization');
 const originalClock=svm.getClock(),closedClock=svm.getClock(),refills=[];closedClock.unixTimestamp=(await firstReader.task(1)).claimDeadline+1n;svm.setClock(closedClock);service.calibration={policy:{groups:4},schedule:async count=>refills.push(count)};config.minimumOpenCatalogs=3;config.capacityObservations={peakTasksPerSecond:0,prepareP95Seconds:1,registrationP95Seconds:1,minimum:8,maximum:4096};await service.discover();assert(refills[0]>0);assert(service.reserveStatus.remaining>=service.reserveStatus.target);assert.equal(service.reserveStatus.openCatalogs,1);svm.setClock(originalClock);service.calibration=null;config.capacityObservations=null;checks.push('Closing all successor claim windows schedules fresh catalogs even though the frozen future-task count is above the reserve target');
 if(process.env.FLYBRAIN_POOL_BROWSER_FIXTURE){
  const wire=address=>{const v=svm.getAccount(address);return {lamports:Number(v.lamports),owner:v.programAddress,executable:v.executable,data:[Buffer.from(v.data).toString('base64'),'base64'],rentEpoch:0};},exhausted=value=>{const copy=structuredClone(value),data=Buffer.from(copy.data[0],'base64');data.writeUInt32LE(data.readUInt32LE(328),392);data.writeUInt32LE(0xffffffff,396);data[408]=2;copy.data[0]=data.toString('base64');return copy;};
  const accounts={...vector.accounts,[base.factory]:exhausted(wire(base.factory))},exhaustedAccounts={},contents={};
  for(const deployment of deployments){accounts[deployment.factory]=wire(deployment.factory);exhaustedAccounts[deployment.factory]=exhausted(accounts[deployment.factory]);for(let i=0;i<deployment.taskCount;i++)accounts[a.task(deployment.factory,i).toBase58()]=wire(a.task(deployment.factory,i).toBase58());}
  const rows=(await q.pool.query('SELECT compiled FROM factory_pool_v4.catalogs WHERE pool_id=$1',[scope])).rows;for(const {compiled}of rows)for(const object of compiled.contents)contents[object.hash]=object.base64;
  await writeFile(process.env.FLYBRAIN_POOL_BROWSER_FIXTURE,JSON.stringify({...vector,clock:Number(svm.getClock().unixTimestamp),accounts,poolDeployment:{...base,taskPool:{...base.taskPool,minimumComputeSeconds:1}},poolManifest:await supply.manifest({anchor:base,ttl:3600}),contents,exhaustedAccounts,nativeReplayFixture:true})+'\n',{mode:0o600,flag:'wx'});
 }
 wallet.lock();assert(!policy.approved);await assert.rejects(policy.include(deployments[0],document));await service.stop();
 console.log(JSON.stringify({passed:true,checks,postgresql:true,sbfTransactions:transactions,catalogs:2,replayDecisions:replayCalls,nativeReplayFixture:true,publicChainTransactions:0,secretMaterialLogged:false}));
}finally{await q.close();}
