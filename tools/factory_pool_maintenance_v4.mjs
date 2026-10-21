// Read-only evidence drives reconciliation; unknown packets remain immutable.
import {PublicKey} from '@solana/web3.js';
import {STATE,decodeTask,decodeSubmission} from '../web/task-factory-v4-codec.mjs';
export async function replayCapacityV4(service) {
  const scopes=[...service.contexts.keys()],fallback=service.config.replayP95Seconds||90;
  const {rows:[cost]}=await service.queue.pool.query(`SELECT count(*)::int AS jobs,
    COALESCE(sum(COALESCE(c.estimate_ms,$2)),0)::text AS milliseconds
    FROM factory_pool_v4.jobs j LEFT JOIN factory_pool_v4.job_costs c ON c.job_id=j.id
    WHERE j.kind='replay' AND j.scope=ANY($1::text[]) AND j.state IN ('ready','leased','blocked')
      AND NOT j.quarantined AND (c.deadline IS NULL OR c.deadline>extract(epoch FROM clock_timestamp()))`,[scopes,Math.ceil(fallback*1000)]);
  const {rows:[leases]}=await service.queue.pool.query("SELECT count(*)::int AS n FROM factory_pool_v4.jobs WHERE kind='input' AND scope=ANY($1::text[]) AND state='leased' AND lease_until>clock_timestamp()",[scopes]);
  return {pendingJobs:cost.jobs,queuedSeconds:Number(cost.milliseconds)/1000,leasedInputs:leases.n,fallbackReplaySeconds:fallback,estimated:true};
}
export async function reconcilePoolBlockedV4(service,{dryRun=false}={}) {
  const {rows}=await service.queue.pool.query("SELECT * FROM factory_pool_v4.jobs WHERE state='blocked' AND scope=ANY($1::text[]) ORDER BY reconciled_at NULLS FIRST,created_at,id LIMIT 32",[[...service.contexts.keys(),service.config.poolTrust.poolId]]);
  const actions=[];
  for(const job of rows) {
    const c=service.contexts.get(job.scope);let resolved=false,retry=false,reason='original-evidence-required';
    if(job.kind==='replay'&&c) {
      const address=new PublicKey(job.payload.submission),s=await c.reader.account(address,decodeSubmission);
      // Fetch the actual immutable task, never assume the current active index.
      const original=await c.reader.account(new PublicKey(s.task),decodeTask);
      const f=await c.reader.factory(),index=f.verifiers.findIndex(key=>new PublicKey(key).toBase58()===job.payload.payer);
      resolved=index>=0&&!!((s.validVotes|s.invalidVotes)&1<<index)||original.attempt!==s.attempt||[STATE.SOLVED,STATE.FAILED].includes(original.state)||s.state===STATE.INVALID;
      if(!resolved&&s.state===STATE.REVEALED){const slot=await service.connection.getSlot('finalized'),now=await service.connection.getBlockTime(slot);resolved=Number.isSafeInteger(now)&&now>Number(original.verifyDeadline);}
      reason=resolved?'chain-resolved-or-ineligible':'active-unknown-transaction';
    } else if(['payment','keeper'].includes(job.kind)&&c){
      const t=await c.reader.task(job.payload.index),f=await c.reader.factory(),op=job.payload.operation;
      resolved=job.kind==='payment'?t.paid:op==='advance'?f.nextIndex>job.payload.index:op==='expire'?t.state!==STATE.ACTIVE||t.attempt!==job.payload.attempt:op==='finalize'?[STATE.SOLVED,STATE.FAILED].includes(t.state):false;reason=resolved?'original-business-effect-confirmed':'original-effect-not-confirmed';
    } else if(job.kind==='catalog'){
      const row=(await service.queue.pool.query('SELECT state FROM factory_pool_v4.catalogs WHERE id=$1 AND pool_id=$2',[job.scope,service.config.poolTrust.poolId])).rows[0];resolved=row?.state==='registered'||row?.state==='retired';reason=resolved?'catalog-already-registered':'catalog-evidence-required';
    } else if(job.kind==='calibrate'&&job.result?.code==='POOL_REWARD_AUTHORIZATION_EXHAUSTED'&&service.supply) {
      const {rows:[sum]}=await service.queue.pool.query("SELECT COALESCE(sum((deployment->>'budgetAtoms')::numeric-released_authorization_atoms),0)::text AS n FROM factory_pool_v4.catalogs WHERE pool_id=$1",[service.config.poolTrust.poolId]);
      const required=BigInt(job.payload.groups)*BigInt(service.calibration.policy.rules.rewardAtoms);
      retry=BigInt(service.supply.authorization.rewardAtoms)-BigInt(sum.n)>=required;
      reason=retry?'existing-authorization-restored':'reward-authorization-exhausted';
    }
    const packets=(await service.queue.pool.query('SELECT id,signature,state FROM factory_pool_v4.transactions WHERE job_id=$1 ORDER BY created_at,id',[job.id])).rows;
    if(packets.length){
      const statuses=(await service.connection.getSignatureStatuses(packets.map(packet=>packet.signature),{searchTransactionHistory:true})).value;
      let allConfirmed=true;
      for(let i=0;i<packets.length;i++){
        const status=statuses[i];if(status?.confirmationStatus!=='finalized'){allConfirmed=false;continue;}
        if(status.err){allConfirmed=false;reason='known-failed-packet';}
        if(!dryRun)await service.queue.pool.query("UPDATE factory_pool_v4.transactions SET state=$2,receipt=$3 WHERE id=$1 AND state<>'finalized'",[packets[i].id,status.err?'failed':'finalized',{signature:packets[i].signature,slot:status.slot,commitment:'finalized',err:status.err||null}]);
      }
      if(!resolved&&allConfirmed){retry=true;reason='original-packets-finalized';}
    }
    const action={id:job.id,kind:job.kind,action:resolved?'resolved':retry?'retry':'quarantine',reason};actions.push(action);
    if(!dryRun)await service.queue.transaction(async db=>{
      const changed=await db.query("UPDATE factory_pool_v4.jobs SET state=$4,quarantined=$5,reconciled_at=clock_timestamp(),ready_at=clock_timestamp() WHERE id=$1 AND state='blocked' AND fence=$2 AND payload_hash=$3 RETURNING id",[job.id,job.fence,job.payload_hash,resolved?'done':retry?'ready':'blocked',!resolved&&!retry]);
      if(changed.rowCount)await service.queue.event(job.scope,'job-reconciled',action,db);
    });
  }
  return {readOnly:dryRun,actions};
}
