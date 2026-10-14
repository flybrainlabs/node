// Isolated integration harness: ephemeral signers, database and oEmbed fixtures.
// This file is never installed by the community deployment script.
import {createServer} from 'node:http';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {join,resolve,extname} from 'node:path';
import {tmpdir} from 'node:os';
import {DatabaseSync} from 'node:sqlite';
import {Keypair} from '@solana/web3.js';
import {WalletMiningService} from '../tools/wallet_mining_v3.mjs';
import {SocialCommunityService} from '../tools/social_community.mjs';
import {XPublicVerificationProvider} from '../tools/x_public_verification.mjs';
import {serveSocial} from '../tools/social_server.mjs';
import {GitHubProvider} from '../tools/github_provider.mjs';
import {createHash} from 'node:crypto';
const root=resolve(process.argv[2]),port=Number(process.argv[3]||8096),origin='http://127.0.0.1:'+port,directory=await mkdtemp(join(tmpdir(),'community-browser-')),db=new DatabaseSync(join(directory,'state.sqlite'));
const users=[Keypair.generate(),Keypair.generate()],admin=Keypair.generate(),keys=[...users,admin],config={...JSON.parse(await readFile('web/data/wallet-mining-v3.json')),origins:[origin],project:admin.publicKey.toBase58(),apiBase:origin,enabled:false},auth=await new WalletMiningService(config,db,null).initialize();
const provider=new XPublicVerificationProvider();provider.fetcher=async url=>{const post=provider.parsePostUrl(url.searchParams.get('url')),q=db.prepare('SELECT * FROM social_x_challenges WHERE submitted_post_id=? ORDER BY rowid DESC LIMIT 1').get(post.postId)||db.prepare('SELECT * FROM social_daily_x_challenges WHERE submitted_post_id=? ORDER BY rowid DESC LIMIT 1').get(post.postId);if(post.username==='fixture_two')throw new Error('Isolated provider outage');return new Response(JSON.stringify({type:'rich',version:'1.0',provider_name:'Twitter',author_url:'https://twitter.com/'+post.username,author_name:post.username,html:'<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Identity verification '+(post.username==='fixture_wrong'?'wrong-code':q.public_code)+'</p>— '+post.username+' <a href="https://twitter.com/'+post.username+'/status/'+post.postId+'">Date</a></blockquote>'}));};
const githubFixtures=process.argv.includes('--github-fixtures'),repos=JSON.parse(await readFile('config/github-community-tasks-v2.json')).repositories;
let githubRelationStatus=204,githubService;const githubTokens=new Map();
const githubConfig=githubFixtures?{clientId:'fixture-browser-client',clientSecret:'fixture-browser-secret',encryptionKey:'56'.repeat(32),callbackUrl:origin+'/api/auth/github/callback',engagementRewardsEnabled:true}:{};
const githubProvider=githubFixtures?new GitHubProvider({...githubConfig,fetcher:async(url,request)=>{
  if(url.pathname==='/login/oauth/access_token'){
    const form=new URLSearchParams(request.body),q=db.prepare("SELECT * FROM social_github_oauth_states WHERE status='exchanging' AND code_hash=?").get(createHash('sha256').update(form.get('code')).digest('hex'));
    if(!q||form.get('code_verifier')!==githubService.cipher.open(q.encrypted_verifier,'pkce:'+q.state_hash))return Response.json({error:'bad_verification_code'});
    const index=keys.findIndex(key=>key.publicKey.toBase58()===q.wallet),user={id:10001+index,login:'fixture-github-'+index,type:'User',avatar_url:''},token='fixture-browser-access-token-'+index;githubTokens.set(token,user);
    return Response.json({access_token:token,token_type:'bearer',scope:'read:user'});
  }
  const user=githubTokens.get(request.headers.Authorization?.replace('Bearer ',''));if(!user)return new Response(null,{status:401});
  if(url.pathname==='/user')return Response.json(user);
  if(url.pathname.startsWith('/repos/')){const repo=repos.find(repo=>url.pathname==='/repos/flybrainlabs/'+repo.name);return Response.json({id:Number(repo.id),private:false,visibility:'public',full_name:'flybrainlabs/'+repo.name,owner:{login:'flybrainlabs'}});}
  return new Response(null,{status:githubRelationStatus});
}}):null;
const service=await new SocialCommunityService(auth,JSON.parse(await readFile('config/community-allocation-v1.json')),{provider,githubConfig,githubProvider}).initialize(),social=serveSocial(service,{port:0});githubService=service.github;await new Promise(r=>social.once('listening',r));
const web=createServer(async(req,res)=>{try{
  const url=new URL(req.url,origin);res.setHeader('Cache-Control','no-store');
  if(url.pathname==='/assets/data/wallet-mining-v3.json'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify(config));return;}
  if(githubFixtures&&url.pathname==='/__fixture/github-status'){githubRelationStatus=Number(url.searchParams.get('status')||204);res.end('{}');return;}
  if(githubFixtures&&url.pathname==='/__fixture/github-engagement'){githubService.engagementEnabled=url.searchParams.get('enabled')==='true';res.end('{}');return;}
  if(url.pathname.startsWith('/api/social/')||url.pathname.startsWith('/api/community/')||url.pathname==='/api/auth/github/callback'){const chunks=[];for await(const c of req)chunks.push(c);const upstream=await fetch('http://127.0.0.1:'+social.address().port+url.pathname+url.search,{method:req.method,headers:{...Object.fromEntries(Object.entries(req.headers).filter(([k])=>!['host','connection','content-length'].includes(k))),origin:req.headers.origin||origin},body:req.method==='POST'?Buffer.concat(chunks):undefined,redirect:'manual'});const headers={'Content-Type':upstream.headers.get('content-type')};for(const name of ['set-cookie','location','retry-after'])if(upstream.headers.get(name))headers[name]=upstream.headers.get(name);res.writeHead(upstream.status,headers);res.end(Buffer.from(await upstream.arrayBuffer()));return;}
  if(url.pathname.startsWith('/api/mining/v3/')){const path=url.pathname.split('/api/mining/v3/')[1],mutation=req.method==='POST';let body={};if(mutation){const chunks=[];for await(const c of req)chunks.push(c);body=JSON.parse(Buffer.concat(chunks));}let value;if(path==='challenge')value=auth.challenge(req.headers.origin,body);else if(path==='login')value=auth.login(req.headers.origin,body);else {const s=auth.authenticate(req.headers.origin||origin,req.headers,mutation);if(path==='logout')value=auth.logout(s);else if(path==='balances')value={wallet:s.wallet,mint:config.mint,solLamports:'0',tokenAtoms:'0',pendingRewardAtoms:'0',grants:[],funding:{state:'completed'},commitment:'finalized',asOf:Math.floor(Date.now()/1000)};else if(path==='history')value={wallet:s.wallet,items:[],rounds:[]};else throw new Error('No financial mutation in community test');}res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));return;}
  const relative=decodeURIComponent(url.pathname).replace(/^\//,'')+(url.pathname.endsWith('/')?'index.html':''),path=resolve(root,relative);if(!path.startsWith(root+'/'))throw new Error('Unsafe path');res.setHeader('Content-Type',({'.html':'text/html','.mjs':'text/javascript','.js':'text/javascript','.css':'text/css','.json':'application/json','.webp':'image/webp','.png':'image/png'}[extname(path)]||'application/octet-stream'));res.end(await readFile(path));
}catch(e){res.writeHead(e.status||404,{'Content-Type':'application/json'});res.end(JSON.stringify({code:e.code||'fixture_not_found'}));}});web.listen(port,'127.0.0.1');await new Promise(r=>web.once('listening',r));
// The parent test consumes this pipe in memory; never include fixture signers in a report.
console.log(JSON.stringify({origin,keys:keys.map(k=>({address:k.publicKey.toBase58(),seed:Buffer.from(k.secretKey.subarray(0,32)).toString('hex'),publicKey:Buffer.from(k.publicKey.toBytes()).toString('hex')}))}));
async function stop(){await new Promise(r=>web.close(r));await new Promise(r=>social.close(r));db.close();await rm(directory,{recursive:true,force:true});process.exit();}process.on('SIGTERM',stop);process.on('SIGINT',stop);
