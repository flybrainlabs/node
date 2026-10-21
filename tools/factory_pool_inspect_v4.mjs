#!/usr/bin/env node
// Read-only preflight: no schema migration, signers, gateway, task opening or
// authorization changes. Use the same private config as the service.
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {Connection} from '@solana/web3.js';
import {FactoryPoolQueueV4} from './factory_pool_queue_v4.mjs';
import {verifyPoolCatalogV4} from '../web/factory-pool-v4.mjs';
import {factoryTaskRecoveryV4} from '../web/task-factory-client-v4.mjs';
import {poolOpenPolicyV4} from './factory_pool_keeper_v4.mjs';
import {NONE} from '../web/task-factory-v4-codec.mjs';
export async function inspectPoolV4({queue,connection,config,limit=128}){
  if(!Number.isInteger(limit)||limit<1||limit>256)throw new Error('POOL_INSPECT_BOUND');
  const policy=poolOpenPolicyV4(config.openTaskPolicy),pool=config.poolTrust.poolId;
  const data=await queue.transaction(async db=>{
    await db.query('SET TRANSACTION READ ONLY');
    const catalogs=(await db.query('SELECT deployment,state,serving_state FROM factory_pool_v4.catalogs WHERE pool_id=$1 ORDER BY registered_at NULLS LAST,id LIMIT $2',[pool,limit])).rows;
    const total=(await db.query('SELECT count(*)::int AS n FROM factory_pool_v4.catalogs WHERE pool_id=$1',[pool])).rows[0].n;
    const jobs=(await db.query("SELECT j.kind,j.state,count(*)::int AS count FROM factory_pool_v4.jobs j WHERE j.scope=$1 OR EXISTS(SELECT 1 FROM factory_pool_v4.catalogs c WHERE c.pool_id=$1 AND c.id=j.scope) GROUP BY j.kind,j.state ORDER BY j.kind,j.state",[pool])).rows;
    return {catalogs,total,jobs};
  });
  const slot=await connection.getSlot('finalized'),now=await connection.getBlockTime(slot);if(!Number.isSafeInteger(now))throw new Error('POOL_CHAIN_TIME');
  const actions=[];for(const item of data.catalogs){if(item.serving_state==='retired')continue;if(item.state==='reserved'){actions.push({factory:item.deployment.factory,kind:'register-reserved',taskCount:item.deployment.taskCount,budgetAtoms:item.deployment.budgetAtoms});continue;}const deployment=item.deployment,{reader,factory}=await verifyPoolCatalogV4(deployment,config.poolTrust,connection),task=factory.activeIndex===NONE?null:await reader.task(factory.activeIndex),action=factoryTaskRecoveryV4(factory,task,now);if(action)actions.push({factory:deployment.factory,...action});}
  return {schema:'flybrainlabs-continuous-pool-plan-v4',readOnly:true,newSignatures:0,newBudgetAtoms:'0',observedAt:new Date().toISOString(),finalizedChainTime:now,policy,catalogs:data.total,inspectedCatalogs:data.catalogs.length,truncated:data.total>limit,jobs:data.jobs,actions};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  let queue;try{const file=process.argv[2];if(!file)throw new Error('POOL_PRIVATE_CONFIG_REQUIRED');const config=JSON.parse(await readFile(file,'utf8'));queue=await FactoryPoolQueueV4.connect((await readFile(config.databaseUrlFile,'utf8')).trim());const connection=new Connection(config.rpcUpstream,{commitment:'finalized',disableRetryOnRateLimit:true});console.log(JSON.stringify(await inspectPoolV4({queue,connection,config}),null,2));}
  catch(error){console.error(JSON.stringify({readOnly:true,code:/^[A-Z0-9_]{1,80}$/.test(error.code||error.message)?error.code||error.message:'POOL_INSPECTION_FAILED'}));process.exitCode=1;}finally{await queue?.pool.end();}
}
