// @ts-check
// A separate community process reuses wallet sessions without starting a relayer.
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {WalletMiningService} from './wallet_mining_v3.mjs';
import {SocialCommunityService} from './social_community.mjs';

const fail=(code,status=400)=>Object.assign(new Error(code),{code,status});
const publicPaths=new Set(['/api/social/tasks','/api/social/leaderboard','/api/community/airdrop/allocation','/api/community/rules','/api/social/health']);
const adminActions={
  'tasks/update':'updateTask','points/adjust':'adjustPoints','users/review-status':'reviewStatus','x/review':'manualReview','x/reject':'rejectReview',
  'snapshots/supersede':'supersedeSnapshot','snapshots/create':'createSnapshot','snapshots/approve':'approveSnapshot',
  'rules/create':'createRules','rules/publish':'publishRules',
  'allocations/create':'createAllocation','allocations/approve':'approveAllocation','allocations/cancel':'cancelAllocation'
};
function csv(rows){const value=v=>'"'+String(v??'').replaceAll('"','""')+'"';return rows.length?Object.keys(rows[0]).map(value).join(',')+'\n'+rows.map(row=>Object.values(row).map(value).join(',')).join('\n')+'\n':'wallet,points,rank,eligibility\n';}
export function serveSocial(service,{host='127.0.0.1',port=8791}={}){
  const server=createServer(async(req,res)=>{
    try{
      const url=new URL(req.url,'http://localhost'),path=url.pathname,origin=req.headers.origin,mutation=req.method==='POST';
      res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json');res.setHeader('X-Content-Type-Options','nosniff');
      if(origin){service.auth.checkOrigin(origin);res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');}
      if(req.method==='OPTIONS'){
        service.auth.checkOrigin(origin);if(!['GET','POST'].includes(req.headers['access-control-request-method'])||(req.headers['access-control-request-headers']||'').toLowerCase().split(',').some(h=>h.trim()&&!['content-type','authorization','x-mining-csrf'].includes(h.trim())))throw fail('CORS_REJECTED',403);
        res.setHeader('Access-Control-Allow-Methods','GET, POST');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization, X-Mining-CSRF');res.writeHead(204);res.end();return;
      }
      if(!['GET','POST'].includes(req.method))throw fail('method_not_allowed',405);
      const publicView=!mutation&&(publicPaths.has(path)||/^\/api\/social\/contributions\/[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(path));
      let session=null;if(!publicView||req.headers.authorization)session=service.auth.authenticate(origin,req.headers,mutation);
      let body={};if(mutation){if(req.headers['content-type']?.split(';')[0]!=='application/json')throw fail('content_type_required',415);const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>32768)throw fail('body_limit',413);chunks.push(chunk);}try{body=JSON.parse(Buffer.concat(chunks).toString());}catch{throw fail('invalid_json');}if(!body||Array.isArray(body)||typeof body!=='object')throw fail('invalid_request');}
      let result;
      if(path==='/api/social/health'&&!mutation)result={project:'flybrainlabs',service:'community',schemaVersion:1,tokenExecutionEnabled:false};
      else if(path==='/api/social/tasks'&&!mutation)result=service.tasks(session);
      else if(path==='/api/social/profile'&&!mutation)result=service.profile(session);
      else if(path==='/api/social/profile/visibility'&&mutation)result=service.setVisibility(session,body);
      else if(path==='/api/social/x/challenge')result=mutation?service.createChallenge(session):service.challengeView(session);
      else if(path==='/api/social/x/verify'&&mutation)result=await service.verifyPost(session,body);
      else if(path==='/api/social/x/binding'&&!mutation)result={binding:service.profile(session).x};
      else if(path==='/api/social/x/unbind'&&mutation)result=service.unbind(session);
      else if(path==='/api/social/leaderboard'&&!mutation)result=service.leaderboard(Object.fromEntries(url.searchParams));
      else if(path==='/api/social/leaderboard/me'&&!mutation)result=service.profile(session);
      else if(path==='/api/social/points/history'&&!mutation)result=service.pointsHistory(session.wallet,Object.fromEntries(url.searchParams));
      else if(path.startsWith('/api/social/contributions/')&&!mutation)result=service.pointsHistory(path.split('/').at(-1),Object.fromEntries(url.searchParams),true);
      else if(path==='/api/community/airdrop/allocation'&&!mutation)result=service.budget();
      else if(path==='/api/community/rules'&&!mutation)result=service.publicRules();
      else if(path==='/api/social/admin'&&!mutation)result=service.adminOverview(session);
      else if(path==='/api/social/admin/users'&&!mutation)result=service.adminUser(session,url.searchParams.get('wallet'));
      else if(path.startsWith('/api/social/admin/')&&mutation){const action=adminActions[path.slice('/api/social/admin/'.length)];if(!action)throw fail('not_found',404);result=await service[action](session,body);}
      else if(/^\/api\/social\/admin\/(snapshots|allocations)\/[a-f0-9]{32}\/export$/.test(path)&&!mutation){
        service.admin(session);const [,kind,id]=path.match(/\/(snapshots|allocations)\/([a-f0-9]{32})\/export$/),content=kind==='snapshots'?service.snapshotContent(id):service.allocationContent(id);
        if(url.searchParams.get('format')==='csv'){res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition','attachment; filename="community-'+kind+'-'+id+'.csv"');res.end(csv(content.entries));return;}
        result={...content,exportedAt:service.clock(),tokenExecutionEnabled:false};
      }else throw fail('not_found',404);
      res.end(JSON.stringify(result));
    }catch(error){res.writeHead(error.status||503);res.end(JSON.stringify({code:error.status?error.code:'retryable_store_error',message:error.status?error.code:'Community storage is temporarily unavailable; no success is assumed.'}));}
  });server.headersTimeout=10000;server.requestTimeout=20000;server.listen(port,host);return server;
}
async function main(){
  const file=process.argv[2];if(!file)throw new Error('Private runtime configuration is required');
  const config=JSON.parse(await readFile(file,'utf8')),allocation=JSON.parse(await readFile(new URL('../config/community-allocation-v1.json',import.meta.url),'utf8'));
  const db=new DatabaseSync(config.database),auth=new WalletMiningService(config,db,null);
  const service=await new SocialCommunityService(auth,allocation,{adminWallets:config.communityAdminWallets||[config.project]}).initialize();
  const server=serveSocial(service,{port:8791});await new Promise((resolve,reject)=>{server.once('listening',()=>resolve(undefined));server.once('error',reject);});console.log('flybrainlabs community service listening on loopback; existing wallet sessions reused');
}
if(process.argv[1]===new URL(import.meta.url).pathname)main().catch(error=>{console.error('Community startup failed: '+(error.code||error.name||'unknown')+'; check private configuration and migration history');process.exitCode=1;});
