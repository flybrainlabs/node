// Authenticated, bounded RESULT archive service. It never proxies official brain inputs or settles rewards.
import http from 'node:http';
import { randomBytes,createHash,createPublicKey,verify } from 'node:crypto';
import { readFile,writeFile,mkdir,readdir,stat,rename,unlink } from 'node:fs/promises';
import path from 'node:path';
import { PublicKey } from '@solana/web3.js';
import { CampaignClient } from '../web/solana-client.mjs';
import { Writer,text,hex,fromHex } from '../web/campaign-codec.mjs';
const [configPath,storage,portArg='8091']=process.argv.slice(2);if(!storage)throw new Error('Usage: node tools/archive_node.mjs CHAIN_CONFIG PRIVATE_RESULT_STORAGE [PORT]');
const config=JSON.parse(await readFile(configPath)),client=new CampaignClient(config);await client.load();
const root=path.resolve(storage);await mkdir(root,{recursive:true,mode:0o700});const CHUNK=4*1024*1024,MAX=128*1024*1024,QUOTA=20*1024*1024*1024,tickets=new Map(),nonces=new Map(),locks=new Set();
const origins=new Set((process.env.FLYPOW_ARCHIVE_ORIGINS||'https://flybrain.work,http://127.0.0.1:8083').split(','));
const sha=b=>createHash('sha256').update(b).digest('hex');
async function body(req,max){const parts=[];let n=0;for await(const b of req){n+=b.length;if(n>max)throw new Error('Request size limit');parts.push(b);}return Buffer.concat(parts);}
async function used(dir){let size=0;for(const e of await readdir(dir,{withFileTypes:true})){if(e.isSymbolicLink())throw new Error('Archive storage contains a symlink');const p=path.join(dir,e.name);size+=e.isDirectory()?await used(p):(await stat(p)).size;}return size;}
function authorizeMessage(sub,root,nonce,timestamp){return new Writer().bytes(text('FlyPoW/archive-authorize/v1\0')).key(client.program).key(client.campaign).key(new PublicKey(sub)).key(fromHex(root)).key(fromHex(nonce)).i64(timestamp).result();}
const server=http.createServer(async(req,res)=>{
  try{
    const origin=req.headers.origin;if(origin&&!origins.has(origin))throw new Error('Origin not allowed');if(origin){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Headers','Authorization,Content-Type');res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,OPTIONS');}
    if(req.method==='OPTIONS'){res.writeHead(204).end();return;}
    const url=new URL(req.url,'http://127.0.0.1');
    for(const [token,t]of tickets)if(t.expires<Date.now()&&!locks.has(t.root))tickets.delete(token);
    for(const [nonce,expires]of nonces)if(expires<Date.now())nonces.delete(nonce);
    if(req.method==='GET'&&url.pathname==='/v1/health'){
      res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
      res.end(JSON.stringify({schema:'flypow-archive-health-v1',campaign:client.campaign.toBase58(),program:client.program.toBase58(),accepting:tickets.size<32,active_uploads:tickets.size,max_uploads:32}));return;
    }
    if(req.method==='POST' && url.pathname==='/v1/uploads'){
      const input=JSON.parse((await body(req,65536)).toString()),raw=Buffer.from(input.manifest_json),archiveRoot=sha(raw),m=JSON.parse(raw.toString());
      if(m.schema!=='flypow-archive-manifest-v1'||m.files?.length!==2||m.files[0].name!=='response.bin'||m.files[1].name!=='preview.json')throw new Error('Unsupported archive manifest');
      let bytes=0;for(const f of m.files){if(!Number.isSafeInteger(f.bytes)||f.bytes<0||f.bytes>MAX||!/^[a-f0-9]{64}$/.test(f.sha256))throw new Error('Archive file bounds');bytes+=f.bytes;}
      if(bytes>MAX||m.files[0].bytes<480||m.files[1].bytes>4*1024*1024)throw new Error('Archive exceeds campaign service bounds');
      if(m.files[0].sha256!==m.result_root||m.files[1].sha256!==m.preview_root)throw new Error('File list does not bind result and preview roots');
      if(!/^[a-f0-9]{64}$/.test(input.nonce)||!Number.isSafeInteger(input.timestamp)||Math.abs(Math.floor(Date.now()/1000)-input.timestamp)>60||nonces.has(input.nonce))throw new Error('Authorization expired or reused');
      const receipt=await client.receipt(input.submission),miner=new PublicKey(input.miner);
      if(receipt.identity.miner!==hex(miner.toBytes())||receipt.identity.campaign!==hex(client.campaign.toBytes())||receipt.hashes.archiveManifestHash!==archiveRoot||receipt.hashes.taskId!==m.task_id||receipt.hashes.resultRoot!==m.result_root||receipt.hashes.previewRoot!==m.preview_root||![1,2].includes(receipt.header.status))throw new Error('Archive does not match revealed on-chain receipt');
      const pk=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(miner.toBytes())]),format:'der',type:'spki'});
      if(!verify(null,authorizeMessage(input.submission,archiveRoot,input.nonce,input.timestamp),pk,Buffer.from(input.signature,'base64')))throw new Error('Invalid miner authorization');
      // Reserve admission after bounded body parsing and authentication. A slow
      // unauthenticated request must not hold the shared quota/admission lock.
      if(locks.has('admission'))throw new Error('Upload admission in progress; retry');
      locks.add('admission');
      try {
      if(nonces.has(input.nonce))throw new Error('Authorization reused');
      const dir=path.join(root,archiveRoot);
      // A sealed archive is immutable; a retry only acknowledges its existing roots.
      let sealed=false;try{await stat(path.join(dir,'sealed.json'));sealed=true;}catch(e){if(e.code!=='ENOENT')throw e;}
      if(sealed){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({sealed:true,chunk_bytes:CHUNK,archive_root:archiveRoot}));return;}
      if([...tickets.values()].some(t=>t.root===archiveRoot))throw new Error('This archive already has an active upload');
      const reserved=[...tickets.values()].reduce((sum,t)=>sum+t.reserved,0);
      if(tickets.size>=32||await used(root)+reserved+bytes*2+65536>QUOTA)throw new Error('Archive quota or bounded upload queue exhausted');
      nonces.set(input.nonce,(input.timestamp+61)*1000);
      await mkdir(dir,{recursive:true,mode:0o700});await writeFile(path.join(dir,'manifest.json'),raw);
      const token=randomBytes(32).toString('hex');tickets.set(token,{dir,manifest:m,root:archiveRoot,reserved:bytes*2+65536,expires:Date.now()+3600000});res.setHeader('Content-Type','application/json');res.end(JSON.stringify({token,chunk_bytes:CHUNK,archive_root:archiveRoot}));return;
      } finally { locks.delete('admission'); }
    }
    const upload=/^\/v1\/uploads\/([a-f0-9]{64})\/(response\.bin|preview\.json|seal)$/.exec(url.pathname);
    if(upload){
      const token=upload[1],name=upload[2],t=tickets.get(token);if(!t||req.headers.authorization!==`Bearer ${token}`)throw new Error('Upload authorization unavailable');
      // Sealing and part writes share the root lock, including across upload tokens.
      const lk=t.root;if(locks.has(lk))throw new Error('Archive operation already in progress');locks.add(lk);
      try{
        if(name==='seal' && req.method==='POST'){
          await body(req,0);
          for(const f of t.manifest.files){
            const h=createHash('sha256');
            // Each temporary part is independently bounded; assembled files are streamed by chunks.
            const file=path.join(t.dir,f.name+'.assembling');const {open}=await import('node:fs/promises');const writer=await open(file,'w',0o600);
            try{for(let at=0;at<f.bytes;at+=CHUNK){const b=await readFile(path.join(t.dir,f.name+'.part-'+Math.floor(at/CHUNK)));if(b.length!==Math.min(CHUNK,f.bytes-at))throw new Error('Missing or corrupt archive part');h.update(b);await writer.write(b);}}finally{await writer.close();}
            if(h.digest('hex')!==f.sha256)throw new Error('Full result/preview SHA-256 mismatch');await rename(file,path.join(t.dir,f.name));
          }
          await writeFile(path.join(t.dir,'sealed.json'),JSON.stringify({archive_root:t.root,sealed_at:Math.floor(Date.now()/1000),retention_until:Math.floor(Date.now()/1000)+Number(client.rules.archive_retention_seconds)}));
          for(const f of t.manifest.files)for(let at=0;at<f.bytes;at+=CHUNK)await unlink(path.join(t.dir,f.name+'.part-'+Math.floor(at/CHUNK)));
          tickets.delete(token);res.setHeader('Content-Type','application/json');res.end(JSON.stringify({archive_root:t.root,sealed:true}));return;
        }
        if(req.method!=='PUT')throw new Error('Unsupported archive method');
        const f=t.manifest.files.find(f=>f.name===name),at=Number(url.searchParams.get('offset'));
        if(!f||!Number.isSafeInteger(at)||at<0||at>=f.bytes||at%CHUNK)throw new Error('Invalid archive block offset');
        const expected=Math.min(CHUNK,f.bytes-at),b=await body(req,expected);if(b.length!==expected)throw new Error('Incomplete archive block');
        await writeFile(path.join(t.dir,name+'.part-'+Math.floor(at/CHUNK)),b,{mode:0o600});res.writeHead(204).end();return;
      }finally{locks.delete(lk);}
    }
    const download=/^\/v1\/archive\/([a-f0-9]{64})\/(manifest\.json|response\.bin|preview\.json)$/.exec(url.pathname);
    if(req.method==='GET' && download){const dir=path.join(root,download[1]);await stat(path.join(dir,'sealed.json'));const {createReadStream}=await import('node:fs');const f=path.join(dir,download[2]),size=(await stat(f)).size;res.setHeader('Content-Type',download[2].endsWith('json')?'application/json':'application/octet-stream');res.setHeader('Content-Length',size);res.setHeader('Cache-Control','public,max-age=3600');createReadStream(f).pipe(res);return;}
    res.writeHead(404).end('Archive not available');
  }catch(error){if(!res.headersSent)res.writeHead(400,{'Content-Type':'application/json'});res.end(JSON.stringify({error:error.message}));}
});
server.requestTimeout=120000;server.headersTimeout=15000;server.listen(Number(portArg),'127.0.0.1',()=>console.log(`Result archive listening on loopback port ${portArg}; quota ${QUOTA}, max upload queue 32`));
