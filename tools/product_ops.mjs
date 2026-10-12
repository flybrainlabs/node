// Authorized operator console. Keys stay local; no secret bytes are printed.
import {readFile,writeFile,stat} from 'node:fs/promises';
import {keyFile,request} from './target_dev_identity.mjs';
const args=process.argv.slice(2),get=n=>args[args.indexOf('--'+n)+1];
if(!args.includes('--api')||!args.includes('--key')||!args.includes('--payload'))throw new Error('usage: node product_ops.mjs --api URL --key PRIVATE_KEY_PATH --payload JSON_FILE [--output PRIVATE_FILE]');
const base=new URL(get('api'));if(base.protocol!=='https:'&&!['127.0.0.1','localhost'].includes(base.hostname))throw new Error('HTTPS or loopback required');
if((await stat(get('key'))).size!==32)throw new Error('Existing raw32 operator key required');
const key=await keyFile(get('key')),payload=JSON.parse(await readFile(get('payload'),'utf8'));const body=await request(key,'product-operation','',payload);
const r=await fetch(base.origin+'/api/operations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(180000)});const result=await r.json();if(!r.ok)throw new Error(result.error||'operation rejected');
if(args.includes('--output'))await writeFile(get('output'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
console.log(JSON.stringify(payload.operation==='list-requests'?{items:result.items.map(({id,status})=>({id,status})),privateDetailsSaved:args.includes('--output')}:result));
