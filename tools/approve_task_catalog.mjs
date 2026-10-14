// Freeze an operator-reviewed finite task catalog; never create an admin key.
import {readFile,writeFile} from 'node:fs/promises';
import {sign} from 'node:crypto';
import {keyFile} from './target_dev_identity.mjs';
import {id,unhex} from '../web/target-protocol-v2.mjs';
import {validateCatalog} from './continuous_task_supply.mjs';
const [input,keyPath,authorityConfig,output]=process.argv.slice(2);
if(!output)throw new Error('Usage: approve_task_catalog.mjs REVIEWED_CATALOG.json EXISTING_ADMIN_KEY AUTHORITY_CONFIG.json PRIVATE_OUTPUT.json');
await readFile(keyPath);const key=await keyFile(keyPath),config=JSON.parse(await readFile(authorityConfig,'utf8')),catalog=JSON.parse(await readFile(input,'utf8'));
if(!config.adminKeys.includes(key.publicKey))throw new Error('Catalog signer is not the configured plan admin');
await validateCatalog(catalog,{networkId:config.networkId,campaignId:config.campaignId,authorityId:catalog.authorityId});
const signature=sign(null,unhex(await id('continuous-task-catalog',catalog)),key.key).toString('hex');
await writeFile(output,JSON.stringify({adminKey:key.publicKey,catalog:{...catalog,signature}},null,2)+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify({approvedTasks:catalog.items.length,budgetAtoms:catalog.budgetAtoms,stage:catalog.stage,chainTransactions:0}));
