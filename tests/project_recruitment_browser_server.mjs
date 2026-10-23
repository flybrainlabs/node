// Test-only loopback server. Synthetic signers and fault controls never ship.
import {createServer} from 'node:http';
import {readFile,mkdtemp,rm,writeFile} from 'node:fs/promises';
import {join,resolve,extname} from 'node:path';
import {tmpdir} from 'node:os';
import {once} from 'node:events';
import {DatabaseSync} from 'node:sqlite';
import {Keypair} from '@solana/web3.js';
import {WalletMiningService} from '../tools/wallet_mining_v3.mjs';
import {SocialCommunityService} from '../tools/social_community.mjs';
import {serveSocial} from '../tools/social_server.mjs';

const root=resolve(process.argv[2]),fixtureFile=resolve(process.argv[3]),port=Number(process.argv[4]||8098),origin='http://127.0.0.1:'+port;
const directory=await mkdtemp(join(tmpdir(),'fbw-project-browser-')),db=new DatabaseSync(join(directory,'auth.db'));
const users=[Keypair.generate(),Keypair.generate()],admin=Keypair.generate(),keys=[...users,admin];
const config={...JSON.parse(await readFile('web/data/wallet-mining-v3.json','utf8')),origins:[origin],project:admin.publicKey.toBase58(),apiBase:origin,enabled:false};
const auth=await new WalletMiningService(config,db,null).initialize();
const community=await new SocialCommunityService(auth,JSON.parse(await readFile('config/community-allocation-v1.json','utf8'))).initialize();
const social=serveSocial(community,{port:0});await once(social,'listening');
let statsDown=false,dropSubmit=false,delayMeMs=0,financialRequests=0;
const readBody=async req=>{const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>32768)throw new Error('test body too large');chunks.push(chunk);}return Buffer.concat(chunks);};
const web=createServer(async(req,res)=>{
  try{
    const url=new URL(req.url,origin);res.setHeader('Cache-Control','no-store');
    if(url.pathname==='/__test/control'&&req.method==='POST'){
      const body=JSON.parse((await readBody(req)).toString());if('statsDown'in body)statsDown=!!body.statsDown;if('dropSubmit'in body)dropSubmit=!!body.dropSubmit;if('delayMeMs'in body)delayMeMs=Number(body.delayMeMs);
      res.setHeader('Content-Type','application/json');res.end('{}');return;
    }
    if(url.pathname==='/__test/state'){
      res.setHeader('Content-Type','application/json');res.end(JSON.stringify({applicationRecords:db.prepare('SELECT COUNT(*) n FROM project_applications').get().n,applications:db.prepare('SELECT id,project_id,status,revision FROM project_applications ORDER BY created_at,id').all(),financialRequests}));return;
    }
    if(url.pathname==='/assets/data/wallet-mining-v3.json'){
      res.setHeader('Content-Type','application/json');res.end(JSON.stringify(config));return;
    }
    if(url.pathname.startsWith('/api/community/')||url.pathname.startsWith('/api/social/')){
      if(statsDown&&url.pathname==='/api/community/projects/stats'){res.writeHead(503,{'Content-Type':'application/json'});res.end('{"code":"synthetic_stats_outage"}');return;}
      const body=await readBody(req),headers=Object.fromEntries(Object.entries(req.headers).filter(([name])=>!['host','connection','content-length'].includes(name)));headers.origin=req.headers.origin||origin;
      const response=await fetch('http://127.0.0.1:'+social.address().port+url.pathname+url.search,{method:req.method,headers,body:req.method==='POST'?body:undefined,redirect:'manual'});
      const payload=Buffer.from(await response.arrayBuffer());
      if(dropSubmit&&url.pathname==='/api/community/projects/applications/submit'&&response.ok){dropSubmit=false;res.writeHead(503,{'Content-Type':'application/json'});res.end('{"code":"synthetic_gateway_lost_receipt"}');return;}
      if(delayMeMs&&url.pathname==='/api/community/projects/me')await new Promise(done=>setTimeout(done,delayMeMs));
      res.writeHead(response.status,{'Content-Type':response.headers.get('content-type'),'Cache-Control':'no-store'});res.end(payload);return;
    }
    if(url.pathname.startsWith('/api/mining/v3/')){
      const action=url.pathname.slice('/api/mining/v3/'.length),mutation=req.method==='POST',body=mutation?JSON.parse((await readBody(req)).toString()):{};
      let value;
      if(action==='challenge')value=auth.challenge(req.headers.origin,body);
      else if(action==='login')value=auth.login(req.headers.origin,body);
      else{
        const session=auth.authenticate(req.headers.origin||origin,req.headers,mutation);
        if(action==='logout')value=auth.logout(session);
        else if(action==='balances')value={wallet:session.wallet,mint:config.mint,solLamports:'0',tokenAtoms:'0',pendingRewardAtoms:'0',grants:[],funding:{state:'completed'},commitment:'finalized',asOf:Math.floor(Date.now()/1000)};
        else if(action==='history')value={wallet:session.wallet,items:[],rounds:[]};
        else{financialRequests++;res.writeHead(403,{'Content-Type':'application/json'});res.end('{"code":"no_financial_operations_in_recruitment_test"}');return;}
      }
      res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));return;
    }
    if(url.pathname==='/results/'||url.pathname==='/results'){
      const legacyId=/^[a-f0-9]{64}$/.test(url.searchParams.get('id')||'');
      if(legacyId||['input','task','model','type','evidence','since','related'].some(key=>url.searchParams.has(key))){res.writeHead(302,{Location:(legacyId?'/results/detail/':'/results/publications/')+url.search});res.end();return;}
    }
    let pathname=url.pathname;
    if(/^\/results\/[a-f0-9]{64}\/?$/.test(pathname))pathname='/results/detail/';
    const relative=decodeURIComponent(pathname).replace(/^\//,'')+(pathname.endsWith('/')?'index.html':''),file=resolve(root,relative);
    if(!file.startsWith(root+'/'))throw new Error('Unsafe static path');
    let bytes;try{bytes=await readFile(file);}catch{res.writeHead(404,{'Content-Type':'text/html; charset=utf-8'});res.end(await readFile(join(root,'404.html')));return;}
    res.setHeader('Content-Type',({'.html':'text/html; charset=utf-8','.mjs':'text/javascript','.js':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.webp':'image/webp','.wasm':'application/wasm'}[extname(file)]||'application/octet-stream'));res.end(bytes);
  }catch(error){res.writeHead(error.status||503,{'Content-Type':'application/json'});res.end(JSON.stringify({code:error.code||'synthetic_test_error'}));}
});
web.listen(port,'127.0.0.1');await once(web,'listening');
await writeFile(fixtureFile,JSON.stringify({origin,keys:keys.map(key=>({address:key.publicKey.toBase58(),seed:Buffer.from(key.secretKey.subarray(0,32)).toString('hex'),publicKey:Buffer.from(key.publicKey.toBytes()).toString('hex')}))}),{mode:0o600});
console.log(JSON.stringify({origin,fixtureFile,syntheticOnly:true,productionDeployed:false}));
async function stop(){await new Promise(done=>web.close(done));await new Promise(done=>social.close(done));db.close();await rm(directory,{recursive:true,force:true});await rm(fixtureFile,{force:true});process.exit();}
process.on('SIGINT',stop);process.on('SIGTERM',stop);
