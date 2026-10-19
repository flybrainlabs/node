// The operator authorizes a fixed generator/envelope and a finite reward total.
// Each generation freezes its entire historical inventory before evaluation.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {canonical} from '../web/target-protocol-v2.mjs';
import {scientificIdentity} from '../web/task-factory-v4-science.mjs';
import {verifyPoolGoalV4} from '../web/factory-pool-v4.mjs';
const execute=promisify(execFile),hash=bytes=>createHash('sha256').update(bytes).digest('hex'),fail=code=>Object.assign(new Error(code),{code});
async function frozen(path,value){const bytes=canonical(value);try{await writeFile(path,bytes,{flag:'wx',mode:0o600});}catch(error){if(error.code!=='EEXIST')throw error;if(!(await readFile(path)).equals(Buffer.from(bytes)))throw fail('POOL_CALIBRATION_FROZEN_INPUT');}}
export class FactoryPoolCalibrationV4 {
  constructor({queue,supply,policy}){
    Object.assign(this,{queue,supply,policy});
    if(!policy||!Number.isInteger(policy.groups)||policy.groups<1||policy.groups>64||!Number.isInteger(policy.deadlineSeconds)||policy.deadlineSeconds<86400||policy.deadlineSeconds>90*86400||!/^[a-f0-9]{64}$/.test(policy.toolSha256)||!/^[a-f0-9]{64}$/.test(policy.evidenceHash)||policy.evidenceHash!==supply.authorization.evidenceHash)throw fail('POOL_CALIBRATION_POLICY');
  }
  async inventory(){
    const original=JSON.parse(await readFile(this.policy.initialInventory,'utf8'));if(!Array.isArray(original.goals)||original.count!==original.goals.length||original.count<55)throw fail('POOL_COMPLETE_HISTORY_REQUIRED');
    const goals=new Map();for(const row of original.goals){const goal=row.goal||row;goals.set(await scientificIdentity(goal),goal);}
    const rows=(await this.queue.pool.query('SELECT compiled FROM factory_pool_v4.catalogs WHERE pool_id=$1',[this.supply.trust.poolId])).rows;
    for(const {compiled}of rows)for(const content of compiled.contents){const spec=JSON.parse(Buffer.from(content.base64,'base64'));goals.set(await scientificIdentity(spec.goal),spec.goal);}
    if(goals.size<55)throw fail('POOL_COMPLETE_HISTORY_REQUIRED');
    return {schema:'flybrainlabs-factory-science-inventory-v4',count:goals.size,goals:[...goals].sort(([a],[b])=>a.localeCompare(b)).map(([scientificIdentity,goal])=>({scientificIdentity,goal}))};
  }
  async schedule(shortage){
    if(!Number.isInteger(shortage)||shortage<=0)return;
    const allocated=(await this.queue.pool.query("SELECT COALESCE(sum((deployment->>'budgetAtoms')::numeric),0)::text AS total FROM factory_pool_v4.catalogs WHERE pool_id=$1",[this.supply.trust.poolId])).rows[0].total;
    const remaining=BigInt(this.supply.authorization.rewardAtoms)-BigInt(allocated),groups=Math.min(shortage,this.policy.groups,Number(remaining>0n?remaining/BigInt(this.policy.rules.rewardAtoms):0n));
    this.supplyStatus={code:groups?'POOL_CALIBRATION_READY':'POOL_REWARD_AUTHORIZATION_EXHAUSTED',allocatedRewardAtoms:allocated,remainingRewardAtoms:String(remaining>0n?remaining:0n)};
    if(!groups)return;
    const active=(await this.queue.pool.query("SELECT 1 FROM factory_pool_v4.jobs WHERE kind='calibrate' AND scope=$1 AND state<>'done' LIMIT 1",[this.supply.trust.poolId])).rows.length;if(active)return;
    const inventory=await this.inventory(),digest=hash(canonical(inventory)),id='calibrate:'+this.supply.trust.poolId+':'+digest;
    return this.queue.enqueue({id,kind:'calibrate',scope:this.supply.trust.poolId,payload:{inventory,inventoryHash:digest,groups,payer:this.supply.authority.publicKey.toBase58()}});
  }
  async run(job){
    if(job.scope!==this.supply.trust.poolId||hash(canonical(job.payload.inventory))!==job.payload.inventoryHash||hash(await readFile(this.policy.tool))!==this.policy.toolSha256)throw fail('POOL_CALIBRATION_SCOPE');
    const directory=join(resolve(this.policy.outputDirectory),hash(Buffer.from(job.id)));await mkdir(directory,{recursive:true,mode:0o700});
    const inventoryPath=join(directory,'inventory.json');await frozen(inventoryPath,job.payload.inventory);
    const output=join(directory,'generation');let summary;
    try{summary=JSON.parse(await readFile(join(output,'summary.json'),'utf8'));}catch(error){if(error.code!=='ENOENT')throw error;
      const args=[this.policy.tool,'--historical-inventory',inventoryPath,'--output',output,'--groups',String(job.payload.groups)];
      for(const [field,flag]of [['cacheDir','--cache'],['modelDir','--model'],['binary','--binary'],['goalFile','--goal']])if(this.policy[field])args.push(flag,this.policy[field]);
      if(this.policy.template)args.push('--template',this.policy.template);
      let run;try{run=await execute(this.policy.python,args,{timeout:86400000,maxBuffer:2*1024*1024});}catch(error){await frozen(join(directory,'failure-'+job.fence+'.json'),{stderrHash:hash(Buffer.from(error.stderr||'')),toolHash:this.policy.toolSha256});throw fail(String(error.stderr).includes('The anatomical selection envelope is exhausted')?'POOL_CALIBRATION_TEMPLATE_EXHAUSTED':'POOL_CALIBRATION_TOOL_FAILED');}
      await frozen(join(directory,'execution.json'),{stdoutHash:hash(Buffer.from(run.stdout)),stderrHash:hash(Buffer.from(run.stderr))});summary=JSON.parse(await readFile(join(output,'summary.json'),'utf8'));
    }
    if(summary.schema!=='flybrainlabs-factory-catalog-proposal-v4'||summary.historicalGoalsExcluded!==job.payload.inventory.count||summary.eligibleCount<1||summary.approval!==false||summary.publicBudgetAtoms!=='0')throw fail('POOL_CALIBRATION_INELIGIBLE');
    const tasks=[];
    for(const row of summary.eligibleTasks){
      if(!/^group-[1-9][0-9]*\/specification\.json$/.test(row.specification))throw fail('POOL_CALIBRATION_PATH');
      const spec=JSON.parse(await readFile(join(output,row.specification),'utf8')),report=JSON.parse(await readFile(join(output,row.specification.replace('specification.json','calibration.json')),'utf8'));
      verifyPoolGoalV4(spec.goal,this.supply.trust);
      if(report.enabled!==true||report.sampleCount<20||report.heldOutCount<8||report.successes<1||report.heldOutSuccesses<1||hash(canonical(report))!==spec.goal.calibrationHash||report.scientificIdentity!==await scientificIdentity(spec.goal))throw fail('POOL_CALIBRATION_EVIDENCE');
      tasks.push({specification:row.specification,approvedCalibrationHash:spec.goal.calibrationHash,rules:this.policy.rules});
    }
    let plan;const planPath=join(directory,'plan.json');
    try{plan=JSON.parse(await readFile(planPath,'utf8'));}catch(error){if(error.code!=='ENOENT')throw error;plan={schema:'flybrainlabs-task-catalog-plan-v4',approval:{approved:true,evidenceHash:this.policy.evidenceHash},factoryId:hash(Buffer.from('Flybrain/pool-generation/v4\0'+job.id)),budgetAtoms:String(BigInt(this.policy.rules.rewardAtoms)*BigInt(tasks.length)),deadline:String(Math.floor(Date.now()/1000)+this.policy.deadlineSeconds),excludedScientificIdentities:job.payload.inventory.goals.map(x=>x.scientificIdentity),tasks};await frozen(planPath,plan);}
    await this.queue.guard(job);const deployment=await this.supply.importPlan(plan,async path=>JSON.parse(await readFile(join(output,path),'utf8')));return {factory:deployment.factory,eligibleTasks:tasks.length,historicalGoalsExcluded:job.payload.inventory.count,inventoryHash:job.payload.inventoryHash};
  }
}
