// Run on the node. Secret key files stay there and are never printed.
import {readFile,writeFile,access} from 'node:fs/promises';
import {constants} from 'node:fs';
import {dirname} from 'node:path';
import {keyFile,request,verified,api} from './target_dev_identity.mjs';
const [draftPath,keyPath,base,authorityId,receiptPath]=process.argv.slice(2);
if(!receiptPath||!/^http:\/\/127\.0\.0\.1:\d+$/.test(base)||!/^[a-f0-9]{64}$/.test(authorityId))throw new Error('Use the loopback node, pinned authority and explicit private key path');
await access(dirname(receiptPath),constants.W_OK);
try{await access(receiptPath);throw new Error('Receipt already exists; inspect the published plan before another revision');}catch(e){if(e.code!=='ENOENT')throw e;}
// Do not create a replacement identity if a deployment key is missing.
await readFile(keyPath);const key=await keyFile(keyPath);
const snapshot=await verified(authorityId,'authority-snapshot',await(await api(base,'rounds/current')).json());
const draft=JSON.parse(await readFile(draftPath));
const plan={...draft,revision:(snapshot.supply.planRevision||0)+1,previousPlanHash:snapshot.supply.planHash||null};
const req=await request(key,'publish-future-plan','',{plan});
const receipt=await verified(authorityId,'plan-receipt',await(await api(base,'admin/future-plan',req)).json());
await writeFile(receiptPath,JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify({revision:receipt.revision,appendedGoals:receipt.appendedGoals,planHash:receipt.planHash,onlyUnopenedGoals:receipt.onlyUnopenedGoals}));
