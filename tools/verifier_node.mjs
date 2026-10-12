// Full replay + actual archive integrity precede signing. Three locally held keys are NOT independent operators.
import { readFile,writeFile,mkdir,copyFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { CampaignClient } from '../web/solana-client.mjs';
import { buildRecord,jsonBytes,digest } from '../web/response-record.mjs';
import { taskForIndex } from '../web/catalog-task.mjs';
import { encodeCampaign,Writer,hex,merkle } from '../web/campaign-codec.mjs';
import { loadKey,vote,connection } from './campaign_tools.mjs';
const run=promisify(execFile),args=process.argv.slice(2);
const [chainPath,graphPath,modelPath,catalogPath,submission,keyPath,archiveDir]=args;
if(!archiveDir)throw new Error('Usage: node tools/verifier_node.mjs CHAIN.json GRAPH MODEL CATALOG SUBMISSION PRIVATE_KEY ARCHIVE_DIR [--numpy] [--send]');
const client=new CampaignClient(JSON.parse(await readFile(chainPath)));await client.load();const s=await client.receipt(submission),catalog=JSON.parse(await readFile(catalogPath));
if(client.rules.readout_schema_id!==1||client.rules.simulation_config_id!==1||client.rules.verifier_policy_id!==1||client.rules.observe_start!==0||client.rules.roi_count!==1)throw new Error('This replay node only supports the documented v1 development model/readout');
const a=new Writer(),b=new Writer();encodeCampaign(a,catalog.campaign);encodeCampaign(b,client.rules.catalog);if(hex(a.result())!==hex(b.result()))throw new Error('Local catalog differs from immutable chain rules');
const key=await loadKey(keyPath),index=client.rules.verifiers.findIndex(k=>hex(k)===hex(key.publicKey.toBytes()));if(index<0)throw new Error('This key is not authorized');
const k=Number(s.task.globalTaskIndex);if(!Number.isSafeInteger(k))throw new Error('Pilot index bound');const task=await taskForIndex(catalog,k);
if(s.hashes.taskId!==task.taskId||s.task.bodyId!==BigInt(task.bodyId)||s.task.targetIndex!==task.targetIndex)throw new Error('Receipt task identity mismatch');
const responsePath=archiveDir+'/response.bin';
const command=args.includes('--numpy')?[process.env.FLYPOW_REFERENCE_PYTHON||'python3',['-B','tools/reference_sim.py',graphPath,modelPath,catalogPath,String(k),responsePath]]:['target/release/verify_response',[graphPath,modelPath,catalogPath,String(k),responsePath]];
const started=Date.now();const replay=await run(command[0],command[1],{maxBuffer:65536});
const response=new Uint8Array(await readFile(responsePath));
const graph=await readFile(graphPath),view=new DataView(graph.buffer,graph.byteOffset,graph.length),cfg={neuron_count:client.rules.catalog.model_neuron_count,steps:client.rules.catalog.simulation_steps,time_step_us:client.rules.catalog.time_step_us,registry_sha256:hex(client.rules.catalog.registry_root),model_root_sha256:hex(client.rules.catalog.model_root)};
const bodyIndex=body=>{let low=0,high=cfg.neuron_count;while(low<high){const mid=Math.floor((low+high)/2);if(view.getBigUint64(52+mid*8,true)<body)low=mid+1;else high=mid;}return low<cfg.neuron_count&&view.getBigUint64(52+low*8,true)===body?low:-1;};
const bundle=await buildRecord(response,cfg,task,bodyIndex);
const parsed=bundle.parsed;
if(s.header.topCount!==parsed.topCount || s.global.some((v,i)=>v!==parsed.global[i]) || s.roi.some((v,i)=>v!==parsed.roi[i]) || s.time.some((v,i)=>v!==parsed.time[i])
  || s.top.some((v,i)=>v.bodyId!==parsed.top[i].bodyId || v.deltaSpikes!==parsed.top[i].delta || v.firstDivergenceStep!==parsed.top[i].firstStep))throw new Error('Revealed scientific summary differs from the full independently replayed archive');
if(bundle.resultRoot!==s.hashes.resultRoot||bundle.previewRoot!==s.hashes.previewRoot||bundle.archiveRoot!==s.hashes.archiveManifestHash)throw new Error('Full replay / preview / file manifest differs from revealed chain commitment');
if(await digest(await readFile(archiveDir+'/preview.json'))!==bundle.previewRoot||await digest(await readFile(archiveDir+'/manifest.json'))!==bundle.archiveRoot)throw new Error('Actual archive files are missing or damaged');
const report={schema:'flypow-full-replay-verifier-v1',submission,task_id:task.taskId,implementation:args.includes('--numpy')?'independent-numpy':'rust-native',elapsed_ms:Date.now()-started,result_root:bundle.resultRoot,preview_root:bundle.previewRoot,archive_manifest_hash:bundle.archiveRoot,retention_seconds:String(client.rules.archive_retention_seconds),trust:'Operator promises retention; signature is not permanent storage or execution proof'};
if(args.includes('--send')){
  if(connection.rpcEndpoint!==client.config.rpc)throw new Error('Verifier transaction RPC must match configured genesis network (set FLYPOW_RPC explicitly)');
  // The voter only attests bytes that it has actually recomputed and holds at archiveDir.
  const ctx={program:client.program,a:client.a,r:client.rules},p={sub:new (await import('@solana/web3.js')).PublicKey(submission),t:task};report.transaction=await vote(ctx,p,key,index,true);
}
await writeFile(archiveDir+`/verifier-${index}-report.json`,JSON.stringify(report,null,2)+'\n');console.log(report);
