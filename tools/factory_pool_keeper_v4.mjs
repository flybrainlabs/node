// Permissionless frozen-task operations use the existing bounded signer journal.
import {PublicKey} from '@solana/web3.js';
import {factoryTaskRecoveryV4} from '../web/task-factory-client-v4.mjs';
import {STATE,NONE} from '../web/task-factory-v4-codec.mjs';
import {instruction,meta} from './task_factory_v4_client.mjs';
const fail=code=>Object.assign(new Error(code),{code});
export function poolOpenPolicyV4(value={}) {
  const policy={minimum:1,target:2,maximum:4,idleTarget:0,minimumWindowSeconds:90,demandTtlSeconds:120,...value};
  if(!Object.values(policy).every(Number.isSafeInteger)||policy.minimum<1||policy.target<policy.minimum||policy.maximum<policy.target||policy.maximum>32||policy.idleTarget<0||policy.idleTarget>policy.maximum||policy.minimumWindowSeconds<1||policy.demandTtlSeconds<30||policy.demandTtlSeconds>600)throw fail('POOL_OPEN_POLICY');
  return policy;
}
export class FactoryPoolKeeperV4 {
  constructor(service){this.service=service;this.policy=poolOpenPolicyV4(service.config.openTaskPolicy);}
  async schedule(c,f,t,now,{demand,open,active=0}={}) {
    const recovery=factoryTaskRecoveryV4(f,t,now);if(!recovery)return false;
    if(['advance','expire'].includes(recovery.kind)&&open>=(demand?this.policy.target:this.policy.idleTarget))return false;
    if(recovery.kind==='advance'&&active>=this.policy.maximum)return false;
    if(recovery.kind==='expire'&&!demand)return false;
    const payer=this.service.signers[0].publicKey.toBase58(),id=`keeper:${recovery.kind}:${c.deployment.factory}:${recovery.index}:${recovery.attempt??0}`;
    await this.service.queue.enqueue({id,kind:'keeper',scope:c.deployment.factory,priority:recovery.kind==='finalize'?100:10,payload:{operation:recovery.kind,factory:c.deployment.factory,index:recovery.index,attempt:recovery.attempt??0,...(recovery.submission?{submission:recovery.submission}:{}),payer}});
    return ['advance','expire'].includes(recovery.kind);
  }
  async perform(job) {
    if(job.payload.operation==='finalize')return this.performLocked(job);
    const s=this.service,db=await s.queue.pool.connect(),key='pool-open:'+s.config.poolTrust.poolId;
    try{
      const {rows:[lock]}=await db.query('SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS locked',[key]);if(!lock.locked)throw fail('POOL_KEEPER_BUSY');
      return await this.performLocked(job);
    }finally{await db.query('SELECT pg_advisory_unlock(hashtextextended($1,0))',[key]).catch(()=>{});db.release();}
  }
  async performLocked(job) {
    const s=this.service,c=s.contexts.get(job.payload.factory);if(!c||job.payload.payer!==s.signers[0].publicKey.toBase58())throw fail('POOL_KEEPER_SCOPE');
    if(job.payload.operation==='finalize')return s.payment(job);
    if(!['advance','expire'].includes(job.payload.operation))throw fail('POOL_KEEPER_SCOPE');
    const reader=c.reader,index=job.payload.index,t=await reader.task(index),f=await reader.factory(),transport=s.transport(s.signers[0]);
    const resolved=async()=>{const latest=await reader.task(index),factory=await reader.factory();return job.payload.operation==='advance'?factory.nextIndex>index:latest.state!==STATE.ACTIVE||latest.attempt!==job.payload.attempt;};
    if(await resolved())return {alreadyResolved:true,...await transport.reconcile(job,job.payload.operation)};
    const slot=await s.connection.getSlot('finalized'),now=await s.connection.getBlockTime(slot),action=factoryTaskRecoveryV4(f,t,now);
    if(!action||action.kind!==job.payload.operation||action.index!==index||action.kind==='expire'&&action.attempt!==job.payload.attempt)return {superseded:true};
    if(action.kind==='advance'&&now+t.descriptor.verifySeconds>Number(f.deadline))return {deadlineClosed:true};
    // A durable original packet is reconciled with its original bytes. Only
    // a new operation needs a fresh global open-capacity reservation.
    const packet=(await s.queue.pool.query('SELECT id FROM factory_pool_v4.transactions WHERE job_id=$1 LIMIT 1',[job.id])).rows[0];
    if(!packet){
      const demand=(await s.queue.pool.query('SELECT count(*)::int AS n FROM factory_pool_v4.demand WHERE pool_id=$1 AND expires_at>clock_timestamp()',[s.config.poolTrust.poolId])).rows[0].n;
      const open=new Set(),active=new Set();for(const context of s.contexts.values()){const factory=await context.reader.factory();if(factory.state===STATE.RUNNING&&factory.activeIndex!==NONE){active.add(context.deployment.factory);const task=await context.reader.task(factory.activeIndex);if(!factory.paused&&task.state===STATE.ACTIVE&&task.queue.length<8&&now+this.policy.minimumWindowSeconds<Number(task.claimDeadline))open.add(context.deployment.factory);}}
      const pending=(await s.queue.pool.query("SELECT DISTINCT j.scope FROM factory_pool_v4.jobs j JOIN factory_pool_v4.transactions p ON p.job_id=j.id WHERE j.kind='keeper' AND j.state<>'done' AND j.payload->>'operation' IN ('advance','expire') AND p.state NOT IN ('failed','finalized')")).rows;for(const row of pending)if(s.contexts.has(row.scope)){open.add(row.scope);active.add(row.scope);}
      if(action.kind==='advance'&&active.size>=this.policy.maximum)throw fail('POOL_KEEPER_CAPACITY');
      if(open.size>=(demand?this.policy.target:this.policy.idleTarget))throw fail('POOL_KEEPER_CAPACITY');
    }
    const task=reader.a.task(c.deployment.factory,index),keys=[meta(c.deployment.factory,true),meta(task,true)];
    if(action.kind==='expire'&&f.nextIndex<f.count)keys.push(meta(reader.a.task(c.deployment.factory,f.nextIndex),true));
    return transport.run(job,action.kind,[instruction(reader.program,keys,action.kind==='advance'?3:8)],resolved);
  }
  async plan() {
    const s=this.service,slot=await s.connection.getSlot('finalized'),now=await s.connection.getBlockTime(slot),actions=[];
    for(const c of s.contexts.values()){const f=await c.reader.factory(),t=f.activeIndex===NONE?null:await c.reader.task(f.activeIndex),action=factoryTaskRecoveryV4(f,t,now);if(action)actions.push({factory:c.deployment.factory,...action});}
    return {readOnly:true,actions,policy:this.policy,newSignatures:0,newBudgetAtoms:'0'};
  }
}
