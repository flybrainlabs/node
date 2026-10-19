// Server-time leases, fencing and durable signed bytes. Notifications are hints;
// all work and financial recovery are read from PostgreSQL after a restart.
import {readFile} from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import pg from 'pg';
import {canonical} from '../web/target-protocol-v2.mjs';
const hash=v=>createHash('sha256').update(canonical(v)).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
export class FactoryPoolQueueV4 {
  constructor(pool){this.pool=pool;}
  static async connect(connectionString){return new this(new pg.Pool({connectionString,max:12,connectionTimeoutMillis:10000,statement_timeout:15000,application_name:'flybrainlabs-factory-pool-v4'}));}
  async initialize(){const sql=await readFile(new URL('../config/factory-pool-v4.sql',import.meta.url),'utf8');await this.transaction(async c=>{await c.query("SELECT pg_advisory_xact_lock(hashtextextended('factory-pool-v4-schema',0))");await c.query(sql);});return this;}
  async transaction(fn){const c=await this.pool.connect();try{await c.query('BEGIN');const r=await fn(c);await c.query('COMMIT');return r;}catch(error){await c.query('ROLLBACK');throw error;}finally{c.release();}}
  async enqueue({id,kind,scope,payload,priority=0},connection=this.pool){
    const digest=hash(payload);
    await connection.query('INSERT INTO factory_pool_v4.jobs(id,kind,scope,payload,payload_hash,priority) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING',[id,kind,scope,payload,digest,priority]);
    const {rows:[row]}=await connection.query('SELECT * FROM factory_pool_v4.jobs WHERE id=$1',[id]);
    if(!row||row.payload_hash!==digest||row.kind!==kind||row.scope!==scope)throw fail('POOL_JOB_CONFLICT');return row;
  }
  async claim(kind,owner=randomUUID(),seconds=60,id=null,scopes=null){
    if(!Number.isInteger(seconds)||seconds<1||seconds>3600||typeof owner!=='string'||owner.length<1||owner.length>160)throw fail('POOL_LEASE_BOUNDS');
    const {rows}=await this.pool.query(`WITH picked AS (
      SELECT id FROM factory_pool_v4.jobs WHERE kind=$1 AND ($4::text IS NULL OR id=$4) AND ($5::text[] IS NULL OR scope=ANY($5)) AND ready_at<=clock_timestamp()
        AND (state='ready' OR state='leased' AND lease_until<=clock_timestamp())
      ORDER BY priority DESC,ready_at,created_at,id FOR UPDATE SKIP LOCKED LIMIT 1)
      UPDATE factory_pool_v4.jobs j SET state='leased',lease_owner=$2,
        lease_until=clock_timestamp()+$3*interval '1 second',fence=j.fence+1,attempts=j.attempts+1
      FROM picked WHERE j.id=picked.id RETURNING j.*`,[kind,owner,seconds,id,scopes]);return rows[0]||null;
  }
  async guard(job,connection=this.pool,{lock=false}={}){
    const {rows:[row]}=await connection.query(`SELECT id FROM factory_pool_v4.jobs WHERE id=$1 AND state='leased' AND lease_owner=$2 AND fence=$3 AND lease_until>clock_timestamp()${lock?' FOR UPDATE':''}`,[job.id,job.lease_owner,job.fence]);
    if(!row)throw fail('POOL_LEASE_LOST');
  }
  async renew(job,seconds=60){
    if(!Number.isInteger(seconds)||seconds<1||seconds>3600)throw fail('POOL_LEASE_BOUNDS');
    const {rowCount}=await this.pool.query(`UPDATE factory_pool_v4.jobs SET lease_until=clock_timestamp()+$4*interval '1 second' WHERE id=$1 AND state='leased' AND lease_owner=$2 AND fence=$3 AND lease_until>clock_timestamp()`,[job.id,job.lease_owner,job.fence,seconds]);if(rowCount!==1)throw fail('POOL_LEASE_LOST');
  }
  async finish(job,result){return this.transaction(async c=>{
    await this.guard(job,c,{lock:true});
    await c.query("UPDATE factory_pool_v4.jobs SET state='done',result=$2,lease_until=NULL WHERE id=$1",[job.id,result]);
    await this.event(job.scope,'job-completed',{id:job.id,kind:job.kind},c);
  });}
  async retry(job,{delaySeconds=5,blocked=false,code='retryable'}={}){
    if(!Number.isInteger(delaySeconds)||delaySeconds<0||delaySeconds>86400||!/^[A-Za-z0-9_-]{1,80}$/.test(code))throw fail('POOL_RETRY_BOUNDS');
    return this.transaction(async c=>{await this.guard(job,c,{lock:true});await c.query("UPDATE factory_pool_v4.jobs SET state=$2,lease_until=NULL,ready_at=clock_timestamp()+$3*interval '1 second',result=$4 WHERE id=$1",[job.id,blocked?'blocked':'ready',delaySeconds,{code}]);});
  }
  async event(scope,kind,value,c=this.pool){const {rows:[row]}=await c.query('INSERT INTO factory_pool_v4.events(scope,kind,value) VALUES($1,$2,$3) RETURNING sequence',[scope,kind,value]);await c.query("SELECT pg_notify('factory_pool_v4',$1)",[String(row.sequence)]);return row.sequence;}
  async signed(job,id,record){
    return this.transaction(async c=>{
      await this.guard(job,c,{lock:true});
      await c.query(`INSERT INTO factory_pool_v4.transactions(id,job_id,instruction_hash,signature,raw_base64,last_valid_height,fee_lamports) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO NOTHING`,[id,job.id,record.instructionHash,record.signature,record.rawBase64,String(record.lastValidBlockHeight),record.feeLamports]);
      const {rows:[row]}=await c.query('SELECT * FROM factory_pool_v4.transactions WHERE id=$1',[id]);
      if(row.job_id!==job.id||row.instruction_hash!==record.instructionHash)throw fail('POOL_TRANSACTION_SCOPE');return row;
    });
  }
  async receipt(job,id,state,receipt){
    if(!['finalized','failed','unknown'].includes(state))throw fail('POOL_RECEIPT_STATE');
    return this.transaction(async c=>{await this.guard(job,c,{lock:true});const {rows:[row]}=await c.query('SELECT * FROM factory_pool_v4.transactions WHERE id=$1 FOR UPDATE',[id]);if(!row||row.job_id!==job.id||row.state==='finalized'&&(state!=='finalized'||hash(row.receipt)!==hash(receipt)))throw fail('POOL_RECEIPT_CONFLICT');await c.query('UPDATE factory_pool_v4.transactions SET state=$2,receipt=$3 WHERE id=$1',[id,state,receipt]);});
  }
  async events(scope,after='0',limit=100){if(!/^\d{1,19}$/.test(String(after))||!Number.isInteger(limit)||limit<1||limit>500)throw fail('POOL_EVENT_CURSOR');return (await this.pool.query('SELECT sequence,kind,value FROM factory_pool_v4.events WHERE scope=$1 AND sequence>$2 ORDER BY sequence LIMIT $3',[scope,after,limit])).rows;}
  async close(){await this.pool.end();}
}

export function reserveTargetV4({peakTasksPerSecond,prepareP95Seconds,registrationP95Seconds,safetyFactor=2,minimum=8,maximum=4096}){
  if(![peakTasksPerSecond,prepareP95Seconds,registrationP95Seconds,safetyFactor].every(Number.isFinite)||peakTasksPerSecond<0||prepareP95Seconds<0||registrationP95Seconds<0||safetyFactor<1||!Number.isInteger(minimum)||!Number.isInteger(maximum)||minimum<1||maximum<minimum||maximum>4096)throw fail('POOL_CAPACITY_OBSERVATION');
  const required=Math.max(minimum,Math.ceil(peakTasksPerSecond*(prepareP95Seconds+registrationP95Seconds)*safetyFactor));
  return {required,withinCapacity:required<=maximum,target:Math.min(required,maximum)};
}
export function poolReplenishmentV4({remaining,preparedTasks,openCatalogs,preparedCatalogs,target,minimumOpenCatalogs=2,groups=16,maximum=4096}){
  if(![remaining,preparedTasks,openCatalogs,preparedCatalogs,target,minimumOpenCatalogs,groups,maximum].every(Number.isSafeInteger)||[remaining,preparedTasks,openCatalogs,preparedCatalogs].some(n=>n<0)||target<1||minimumOpenCatalogs<1||minimumOpenCatalogs>32||groups<1||groups>64||maximum<target)throw fail('POOL_CAPACITY_OBSERVATION');
  const shortage=Math.max(0,target-remaining-preparedTasks,(minimumOpenCatalogs-openCatalogs-preparedCatalogs)*groups);
  return {shortage,withinCapacity:remaining+preparedTasks+shortage<=maximum};
}
