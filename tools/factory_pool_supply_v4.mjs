// Import only a preapproved calibrated reserve. Registration reserves existing
// FBW; this service cannot mint, change task rules or recycle scientific work.
import {createHash} from 'node:crypto';
import {PublicKey,TransactionInstruction} from '@solana/web3.js';
import {canonical} from '../web/target-protocol-v2.mjs';
import {fromHex,hex,decodeFactory,STATE} from '../web/task-factory-v4-codec.mjs';
import {compileCatalog} from './compile_task_catalog_v4.mjs';
import {addresses,meta,system} from './task_factory_v4_client.mjs';
import {decodeGlobal} from './economy_v2_client.mjs';
import {poolManifestMessageV4,verifyPoolGoalV4} from '../web/factory-pool-v4.mjs';
import {ed25519} from '@noble/curves/ed25519';
import {scientificDescriptorHash} from '../web/task-factory-v4-science.mjs';
const digest=v=>createHash('sha256').update(canonical(v)).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
export class FactoryPoolSupplyV4 {
  constructor({queue,baseDeployment,trust,authority,transport,authorization}){
    Object.assign(this,{queue,baseDeployment,trust,authority,transport,authorization});this.a=addresses(baseDeployment.programId);
    if(baseDeployment.cluster!=='devnet'||!authority.publicKey.equals(new PublicKey(trust.authority))||!authorization||!/^[a-f0-9]{64}$/.test(authorization.evidenceHash)||!/^[1-9][0-9]{0,19}$/.test(authorization.rewardAtoms)||BigInt(authorization.rewardAtoms)>0xffffffffffffffffn)throw fail('POOL_FINITE_AUTHORIZATION');
  }
  async historical(identities){
    return this.queue.transaction(async c=>{for(const identity of identities){fromHex(identity);await c.query("INSERT INTO factory_pool_v4.science(identity,catalog_id,descriptor_hash,historical) VALUES($1,'historical','historical',true) ON CONFLICT(identity) DO NOTHING",[identity]);}});
  }
  async importPlan(plan,load){
    if(plan.approval?.evidenceHash!==this.authorization.evidenceHash)throw fail('POOL_PLAN_NOT_AUTHORIZED');
    const compiled=await compileCatalog(plan,async path=>{const spec=await load(path);verifyPoolGoalV4(spec.goal,this.trust);return spec;}),factory=this.a.factory(fromHex(plan.factoryId)).toBase58();
    const deployment={...this.baseDeployment,factory,factoryId:plan.factoryId,catalogRoot:compiled.root,budgetAtoms:compiled.budget,taskCount:compiled.descriptors.length,deadline:String(plan.deadline),poolFactory:factory};
    const stored={instructions:compiled.instructions.map(hex),descriptors:await Promise.all(compiled.descriptors.map(async d=>({identity:hex(d.scientificIdentity),hash:hex(await scientificDescriptorHash(d))}))),contents:compiled.contents.map(c=>({hash:c.hash,base64:Buffer.from(c.bytes).toString('base64')}))};
    const planHash=digest(plan);
    return this.queue.transaction(async c=>{
      await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['pool-budget:'+this.trust.poolId]);
      const {rows:[old]}=await c.query('SELECT * FROM factory_pool_v4.catalogs WHERE id=$1',[factory]);
      if(old){if(old.plan_hash!==planHash)throw fail('POOL_PLAN_CONFLICT');return old.deployment;}
      const {rows:[sum]}=await c.query("SELECT COALESCE(sum((deployment->>'budgetAtoms')::numeric),0)::text AS total FROM factory_pool_v4.catalogs WHERE pool_id=$1",[this.trust.poolId]);
      if(BigInt(sum.total)+BigInt(compiled.budget)>BigInt(this.authorization.rewardAtoms))throw fail('POOL_REWARD_AUTHORIZATION_EXHAUSTED');
      for(const d of stored.descriptors)await c.query('INSERT INTO factory_pool_v4.science(identity,catalog_id,descriptor_hash) VALUES($1,$2,$3)',[d.identity,factory,d.hash]);
      await c.query('INSERT INTO factory_pool_v4.catalogs(id,pool_id,deployment,plan_hash,compiled) VALUES($1,$2,$3,$4,$5)',[factory,this.trust.poolId,deployment,planHash,stored]);
      await this.queue.enqueue({id:'catalog:'+factory,kind:'catalog',scope:factory,payload:{factory,planHash,payer:this.authority.publicKey.toBase58()}},c);
      await this.queue.event(this.trust.poolId,'catalog-reserved',{factory,taskCount:deployment.taskCount},c);return deployment;
    });
  }
  async register(job,{contentStore}){
    const {rows:[catalog]}=await this.queue.pool.query('SELECT * FROM factory_pool_v4.catalogs WHERE id=$1',[job.payload.factory]);
    if(!catalog||catalog.pool_id!==this.trust.poolId||catalog.plan_hash!==job.payload.planHash)throw fail('POOL_CATALOG_JOB_SCOPE');
    const d=catalog.deployment,connection=this.transport.connection,program=new PublicKey(d.programId),factory=new PublicKey(d.factory),compiled=catalog.compiled;
    await this.queue.guard(job);
    if(await connection.getGenesisHash()!==d.genesisHash)throw fail('POOL_WRONG_GENESIS');
    const globalInfo=await connection.getAccountInfo(this.a.global,'finalized');if(!globalInfo?.owner.equals(program))throw fail('POOL_GLOBAL_SCOPE');
    const g=decodeGlobal(globalInfo.data);
    if(!new PublicKey(g.authority).equals(this.authority.publicKey)||!new PublicKey(g.network).equals(new PublicKey(d.genesisHash))||hex(g.policy)!==d.policyHash||!new PublicKey(g.mint).equals(new PublicKey(d.mint))||!g.issued)throw fail('POOL_GLOBAL_SCOPE');
    const read=async()=>{const info=await connection.getAccountInfo(factory,'finalized');if(!info)return null;if(!info.owner.equals(program))throw fail('POOL_FACTORY_OWNER');const f=decodeFactory(info.data);if(hex(f.id)!==d.factoryId||hex(f.catalogRoot)!==d.catalogRoot||String(f.budget)!==d.budgetAtoms||String(f.deadline)!==d.deadline||f.count!==d.taskCount||!new PublicKey(f.authority).equals(this.authority.publicKey)||hex(f.policy)!==d.policyHash)throw fail('POOL_FACTORY_SCOPE');return f;};
    let f=await read();
    for(const [index,descriptor]of compiled.descriptors.entries()){
      const marker=await connection.getAccountInfo(this.a.science(fromHex(descriptor.identity)),'finalized');
      if(marker&&(!marker.owner.equals(program)||marker.data.length<76||marker.data.subarray(0,8).toString()!=='FBTIV004'||marker.data.subarray(8,40).toString('hex')!==descriptor.identity||!new PublicKey(marker.data.subarray(40,72)).equals(factory)||marker.data.readUInt32LE(72)!==index))throw fail('POOL_SCIENCE_ALREADY_REGISTERED');
    }
    const slot=await connection.getSlot('finalized'),now=await connection.getBlockTime(slot);if(!Number.isSafeInteger(now)||now>=Number(d.deadline))throw fail('POOL_CATALOG_DEADLINE');
    if(!f){
      if(g.available[0]<BigInt(d.budgetAtoms))throw fail('POOL_FINALIZED_FUNDING_REQUIRED');
      await this.transport.run(job,'initialize',[new TransactionInstruction({programId:program,keys:[meta(this.a.global,true),meta(factory,true),meta(this.authority.publicKey,true,true),system()],data:Buffer.from(compiled.instructions[0],'hex')})],async()=>!!await read());f=await read();
    }
    for(let i=f.uploaded;i<d.taskCount;i++){
      const content=compiled.contents[i];await contentStore.put(content.hash,Buffer.from(content.base64,'base64'));
      const identity=fromHex(compiled.descriptors[i].identity),keys=[meta(factory,true),meta(this.a.task(factory,i),true),meta(this.a.science(identity),true),meta(this.authority.publicKey,true,true),system()];
      await this.transport.run(job,'append-'+i,[new TransactionInstruction({programId:program,keys,data:Buffer.from(compiled.instructions[i+1],'hex')})],async()=>(await read()).uploaded>i);
    }
    f=await read();
    if(f.state===STATE.DRAFT)await this.transport.run(job,'seal',[new TransactionInstruction({programId:program,keys:[meta(factory,true),meta(this.authority.publicKey,false,true)],data:Buffer.from(compiled.instructions.at(-1),'hex')})],async()=>(await read()).state!==STATE.DRAFT);
    f=await read();if(f.uploaded!==f.count||f.state===STATE.DRAFT)throw fail('POOL_CATALOG_NOT_SEALED');await this.transport.reconcileAll(job);
    await this.queue.transaction(async c=>{await this.queue.guard(job,c,{lock:true});await c.query("UPDATE factory_pool_v4.catalogs SET state='registered',registered_at=COALESCE(registered_at,clock_timestamp()) WHERE id=$1",[d.factory]);await this.queue.event(this.trust.poolId,'catalog-registered',{factory:d.factory},c);});return {factory:d.factory,catalogRoot:d.catalogRoot};
  }
  async manifest({anchor,now=Math.floor(Date.now()/1000),ttl=900}={}){
    if(!anchor||anchor.factory!==this.trust.anchorFactory||!Number.isInteger(ttl)||ttl<60||ttl>86400)throw fail('POOL_MANIFEST_ANCHOR');
    return this.queue.transaction(async c=>{
      await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['pool-manifest:'+this.trust.poolId]);
      const rows=(await c.query("SELECT deployment FROM factory_pool_v4.catalogs WHERE pool_id=$1 AND state='registered' ORDER BY registered_at,id",[this.trust.poolId])).rows;
      const catalogs=[anchor,...rows.map(r=>r.deployment)].map(d=>Object.fromEntries(['factory','factoryId','catalogRoot','budgetAtoms','taskCount','deadline'].map(k=>[k,d[k]])));
      if(catalogs.length>128)throw fail('POOL_MANIFEST_CAPACITY');
      const {rows:[last]}=await c.query('SELECT revision FROM factory_pool_v4.manifests WHERE pool_id=$1 ORDER BY revision DESC LIMIT 1',[this.trust.poolId]);
      const body={schema:'flybrainlabs-factory-pool-manifest-v4',...Object.fromEntries(['poolId','authority','genesisHash','programId','mint','policyHash','envelopeHash','anchorFactory'].map(k=>[k,this.trust[k]])),revision:Number(last?.revision||0)+1,issuedAt:now,expiresAt:now+ttl,catalogs};
      const document={...body,signature:Buffer.from(ed25519.sign(poolManifestMessageV4(body),this.authority.secretKey.subarray(0,32))).toString('hex')};
      await c.query('INSERT INTO factory_pool_v4.manifests(pool_id,revision,hash,body) VALUES($1,$2,$3,$4)',[this.trust.poolId,body.revision,digest(document),document]);await this.queue.event(this.trust.poolId,'manifest-published',{revision:body.revision},c);return document;
    });
  }
}
