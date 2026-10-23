// @ts-check
// A separate community process reuses wallet sessions without starting a relayer.
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {WalletMiningService} from './wallet_mining_v3.mjs';
import {SocialCommunityService} from './social_community.mjs';
import {loadGitHubConfig,githubCookie,clearFlowCookie} from './social_github.mjs';

const fail=(code,status=400)=>Object.assign(new Error(code),{code,status});
const publicPaths=new Set(['/api/social/tasks','/api/social/leaderboard','/api/community/airdrop/allocation','/api/community/rules','/api/social/health','/api/community/projects/stats']);
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
      if(path==='/api/auth/github/callback'&&req.method==='GET'){
        // The OAuth redirect is authenticated by one-use state and a private cookie.
        // Finalization subsequently requires the original Bearer/CSRF wallet session.
        let status='failed',code='github_unavailable';
        try{const result=await service.github.callback(url.searchParams,githubCookie(req.headers));status=result.status;}
        catch(error){code=/^github_[a-z_]+$/.test(error.code||'')?error.code:'github_unavailable';}
        const destination=new URL('/social/',service.github.provider.callbackUrl);
        destination.searchParams.set('github',status);if(status==='failed')destination.searchParams.set('github_error',code);
        if(status!=='ready')res.setHeader('Set-Cookie',clearFlowCookie());
        res.setHeader('Referrer-Policy','no-referrer');res.writeHead(303,{Location:destination.href});res.end();return;
      }
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
      if(path.startsWith('/api/community/projects/')){
        const prefix='/api/community/projects/',route=path.slice(prefix.length),query=Object.fromEntries(url.searchParams);
        const application=route.match(/^applications\/([a-f0-9]{32})\/(update|withdraw|resubmit)$/);
        const review=route.match(/^admin\/applications\/([a-f0-9]{32})\/review$/);
        const detail=route.match(/^admin\/applications\/([a-f0-9]{32})$/);
        if(route==='stats'&&!mutation)result=service.projects.stats();
        else if(route==='me'&&!mutation)result=service.projects.me(session);
        else if(route==='interests'&&mutation)result=service.projects.interest(session,body);
        else if(route==='preferences'&&mutation)result=service.projects.preference(session,body);
        else if(route==='applications/submit'&&mutation)result=service.projects.submit(session,body);
        else if(application&&mutation)result=service.projects.change(session,application[1],application[2],body);
        else if(route==='admin/applications'&&!mutation)result=service.projects.adminList(session,query);
        else if(detail&&!mutation)result=service.projects.adminDetail(session,detail[1],query);
        else if(route==='admin/summary'&&!mutation)result=service.projects.adminSummary(session);
        else if(review&&mutation)result=service.projects.review(session,review[1],body);
        else if(route==='admin/export'&&!mutation){
          const content=service.projects.exportCsv(session,query);
          res.setHeader('Content-Type','text/csv; charset=utf-8');
          res.setHeader('Content-Disposition','attachment; filename="fbw-project-applications.csv"');
          res.end(content);return;
        }else throw fail('not_found',404);
        res.end(JSON.stringify(result));return;
      }
      if(path==='/api/social/health'&&!mutation)result={project:'flybrainlabs',service:'community',schemaVersion:3,githubConfigured:service.github.configured,githubStarVerificationEnabled:service.github.starVerificationEnabled,githubEngagementRewardsEnabled:service.github.engagementEnabled,tokenExecutionEnabled:false};
      else if(path==='/api/social/tasks'&&!mutation)result=service.tasks(session);
      else if(path==='/api/social/profile'&&!mutation)result=service.profile(session);
      else if(path==='/api/social/github/start'&&mutation){if(Object.keys(body).length)throw fail('invalid_request');const started=service.github.start(session);res.setHeader('Set-Cookie',started.cookie);result={authorizeUrl:started.authorizeUrl,expiresAt:started.expiresAt};}
      else if(path==='/api/social/github/complete'&&mutation){if(Object.keys(body).length)throw fail('invalid_request');result=service.github.complete(session,githubCookie(req.headers));res.setHeader('Set-Cookie',clearFlowCookie());}
      else if(path==='/api/social/github/binding'&&!mutation)result=service.github.view(session.wallet);
      else if(path==='/api/social/github/verify'&&mutation)result=await service.github.verify(session,body);
      else if(path==='/api/social/register'&&mutation)result=service.register(session,body);
      else if(path==='/api/social/invite')result=mutation?service.createInvite(session):service.inviteView(session);
      else if(path==='/api/social/check-in'&&mutation)result=service.checkIn(session);
      else if(path==='/api/social/daily-x/challenge')result=mutation?service.createDailyChallenge(session):service.dailyChallengeView(session);
      else if(path==='/api/social/daily-x/verify'&&mutation)result=await service.verifyDailyPost(session,body);
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
    }catch(error){if(error.retryAfter)res.setHeader('Retry-After',String(error.retryAfter));res.writeHead(error.status||503);res.end(JSON.stringify({code:error.status?error.code:'retryable_store_error',message:error.status?error.code:'Community storage is temporarily unavailable; no success is assumed.'}));}
  });server.headersTimeout=10000;server.requestTimeout=20000;server.listen(port,host);return server;
}
async function main(){
  const file=process.argv[2];if(!file)throw new Error('Private runtime configuration is required');
  const config=JSON.parse(await readFile(file,'utf8')),allocation=JSON.parse(await readFile(new URL('../config/community-allocation-v1.json',import.meta.url),'utf8'));
  const db=new DatabaseSync(config.database),auth=new WalletMiningService(config,db,null);
  const githubConfig=await loadGitHubConfig();
  const service=await new SocialCommunityService(auth,allocation,{adminWallets:config.communityAdminWallets||[config.project],githubConfig}).initialize();
  const server=serveSocial(service,{port:8791});await new Promise((resolve,reject)=>{server.once('listening',()=>resolve(undefined));server.once('error',reject);});console.log('flybrainlabs community service listening on loopback; existing wallet sessions reused');
}
if(process.argv[1]===new URL(import.meta.url).pathname)main().catch(error=>{console.error('Community startup failed: '+(error.code||error.name||'unknown')+'; check private configuration and migration history');process.exitCode=1;});
