// SQLite/SIWS integration with isolated GitHub provider fixtures, not live OAuth.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {Keypair} from '@solana/web3.js';
import {createHash,createPrivateKey,sign,randomUUID} from 'node:crypto';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {WalletMiningService} from '../tools/wallet_mining_v3.mjs';
import {SocialCommunityService} from '../tools/social_community.mjs';
import {GitHubProvider} from '../tools/github_provider.mjs';
import {GITHUB_COOKIE,githubCookie} from '../tools/social_github.mjs';
import {serveSocial} from '../tools/social_server.mjs';
const directory=await mkdtemp(join(tmpdir(),'flybrainlabs-github-')),file=join(directory,'state.sqlite'),origin='https://flybrain.work';
let now=1791950000,checks=0,server,db=new DatabaseSync(file);
const keys=Array.from({length:9},()=>Keypair.generate()),operatorKey=Keypair.generate();
const config={...JSON.parse(await readFile('web/data/wallet-mining-v3.json','utf8')),origins:[origin],project:operatorKey.publicKey.toBase58(),enabled:false};
let auth=await new WalletMiningService(config,db,null,{clock:()=>now}).initialize();
const login=key=>{
 const wallet=key.publicKey.toBase58(),q=auth.challenge(origin,{address:wallet}),privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),key.secretKey.subarray(0,32)]),format:'der',type:'pkcs8'});
 const out=auth.login(origin,{address:wallet,nonce:q.input.nonce,signedMessage:q.message,signature:sign(null,Buffer.from(q.message),privateKey).toString('base64')});
 return {...auth.authenticate(origin,{authorization:'Bearer '+out.token,'x-mining-csrf':out.csrfToken},true),headers:{Origin:origin,Authorization:'Bearer '+out.token,'X-Mining-CSRF':out.csrfToken,'Content-Type':'application/json'}};
};
const sessions=keys.map(login),operator=login(operatorKey),allocation=JSON.parse(await readFile('config/community-allocation-v1.json','utf8'));
const githubConfig={clientId:'fixture-client',clientSecret:'fixture-secret',encryptionKey:'34'.repeat(32),callbackUrl:origin+'/api/auth/github/callback',engagementRewardsEnabled:true};
const repositories=JSON.parse(await readFile('config/github-community-tasks-v2.json','utf8')).repositories;
const tokens=new Map(),codes=new Map();let fetches=0,relationStatus=204,repositoryOverride=null,userOverride=null,refreshes=0;
const provider=new GitHubProvider({...githubConfig,fetcher:async(url,request)=>{
 fetches++;assert(['https://api.github.com','https://github.com'].includes(url.origin));
 if(url.pathname==='/login/oauth/access_token'){
  const form=new URLSearchParams(request.body);assert.equal(form.get('client_secret'),'fixture-secret');
  if(form.get('grant_type')==='refresh_token'){refreshes++;const user=tokens.get(form.get('refresh_token'));if(!user)return new Response(null,{status:401});const access='fixture-refreshed-access-'+refreshes;tokens.set(access,user);return Response.json({access_token:access,token_type:'bearer',scope:'read:user',expires_in:3600,refresh_token:form.get('refresh_token')});}
  const entry=codes.get(form.get('code'));if(!entry)return Response.json({error:'bad_verification_code'});codes.delete(form.get('code'));
  assert.equal(createHash('sha256').update(form.get('code_verifier')).digest('base64url'),entry.challenge);
  const token='fixture-access-'+form.get('code'),refresh='fixture-refresh-'+form.get('code');tokens.set(token,entry.user);tokens.set(refresh,entry.user);
  return Response.json({access_token:token,token_type:'bearer',scope:'read:user',expires_in:120,refresh_token:refresh,refresh_token_expires_in:3600});
 }
 const token=request.headers.Authorization?.replace('Bearer ',''),user=tokens.get(token);if(!user)return new Response(null,{status:401});
 if(url.pathname==='/user')return Response.json(userOverride||{id:user.id,login:user.login,type:'User',avatar_url:'https://avatars.githubusercontent.com/u/'+user.id});
 if(url.pathname.startsWith('/repos/')){const repo=repositories.find(r=>url.pathname==='/repos/flybrainlabs/'+r.name);assert(repo);return Response.json(repositoryOverride||{id:Number(repo.id),private:false,visibility:'public',full_name:'flybrainlabs/'+repo.name,owner:{login:'flybrainlabs'}});}
 if(url.pathname.includes('/following/'))assert(url.pathname.endsWith('/following/flybrainlabs'));
 else assert(url.pathname.startsWith('/user/starred/flybrainlabs/'));
 return new Response(null,{status:relationStatus});
}});
let service=await new SocialCommunityService(auth,allocation,{githubConfig,githubProvider:provider}).initialize();
const check=(name,fn)=>{fn();checks++;},reject=async(fn,code)=>{await assert.rejects(fn,e=>e.code===code);checks++;};
let sequence=0;
function flow(session,user={id:1001,login:'fixture-one'}){
 const started=service.github.start(session),url=new URL(started.authorizeUrl),code='fixture-code-'+(++sequence);codes.set(code,{user,challenge:url.searchParams.get('code_challenge')});
 return {state:url.searchParams.get('state'),code,browser:started.cookie.split(';')[0].split('=')[1],cookie:started.cookie.split(';')[0],params:new URLSearchParams({state:url.searchParams.get('state'),code})};
}
async function connect(session,user){const q=flow(session,user);assert.equal((await service.github.callback(q.params,q.browser)).status,'ready');const result=service.github.complete(session,q.browser);return {q,result};}
try{
 check('retained GitHub migration and stable one-time tasks',()=>{assert.deepEqual(db.prepare('SELECT version FROM social_schema_migrations ORDER BY version').all().map(row=>row.version),[1,2,3,4]);assert.equal(db.prepare("SELECT COUNT(*) n FROM social_tasks WHERE category='github'").get().n,4);assert.equal(db.prepare("SELECT COUNT(*) n FROM social_tasks WHERE category='github' AND repeatable<>0").get().n,0);});
 const retired=['github_follow_flybrainlabs_v1',...['explorer','contracts','protocol','sdk','research','docs','examples'].map(name=>'github_star_'+name+'_v1')];
 for(const key of retired)db.prepare("INSERT INTO social_tasks SELECT ?,title,description,reward_points,category,verification_type,enabled,repeatable,revision,created_at,updated_at FROM social_tasks WHERE task_key='github_star_miner_v1'").run(key);
 check('legacy task definitions are retained while only selected tasks are listed',()=>{assert.equal(db.prepare("SELECT COUNT(*) n FROM social_tasks WHERE category='github'").get().n,12);assert.deepEqual(service.tasks().tasks.filter(t=>t.category==='github').map(t=>t.id).sort(),['github_connect_v1','github_star_infra_v1','github_star_miner_v1','github_star_node_v1']);assert.equal(service.github.view(sessions[0].wallet).starTotal,3);});
 const beforeRetired=fetches;for(const taskId of retired)await reject(()=>service.github.verify(sessions[0],{taskId}),'github_task_invalid');
 check('stale or forged retired-task requests never call GitHub',()=>assert.equal(fetches,beforeRetired));
 service.adjustPoints(operator,{wallet:sessions[0].wallet,pointsDelta:125,requestId:randomUUID(),reason:'Retain prior isolated community contribution points'});
 const prior=service.createSnapshot(operator,{requestId:randomUUID(),reason:'Freeze isolated historical community snapshot'}),frozen=JSON.stringify(service.snapshotContent(prior.snapshotId));
 const normal=await connect(sessions[0]);
 check('first binding awards fifty points atomically',()=>{assert.equal(normal.result.pointsAwarded,50);assert.equal(normal.result.profile.points,175);assert.equal(normal.result.profile.github.binding.userId,'1001');assert.equal(service.github.complete(sessions[0],normal.q.browser).pointsAwarded,0);});
 check('credentials and PKCE verifier never stored in plaintext',()=>{const row=db.prepare('SELECT * FROM social_github_credentials').get();assert(!row.encrypted_credentials.includes('fixture-access'));assert.equal(db.prepare('SELECT encrypted_result,encrypted_verifier FROM social_github_oauth_states WHERE status=\'completed\'').get().encrypted_result,null);});
 await reject(()=>service.github.callback(normal.q.params,normal.q.browser),'github_state_used');
 const reauth=await connect(sessions[0]);check('reauthorization does not add points',()=>assert.equal(reauth.result.pointsAwarded,0));
 const changed=flow(sessions[0],{id:1002,login:'fixture-other'});await service.github.callback(changed.params,changed.browser);check('wallet cannot replace permanent reward identity',()=>assert.throws(()=>service.github.complete(sessions[0],changed.browser),e=>e.code==='github_identity_conflict'));
 const duplicate=flow(sessions[1]);await service.github.callback(duplicate.params,duplicate.browser);check('GitHub identity cannot reward a different wallet',()=>assert.throws(()=>service.github.complete(sessions[1],duplicate.browser),e=>e.code==='github_identity_conflict'));
 const switched=flow(sessions[2],{id:1003,login:'fixture-three'});await service.github.callback(switched.params,switched.browser);check('browser wallet switch cannot finalize another wallet',()=>{assert.throws(()=>service.github.complete(sessions[3],switched.browser),e=>e.code==='github_wallet_mismatch');assert.equal(service.profile(sessions[2]).points,0);});
 db.exec("CREATE TRIGGER github_fixture_reject BEFORE INSERT ON community_points_ledger WHEN NEW.source_type='github_task' BEGIN SELECT RAISE(ABORT,'fixture atomic rollback');END");
 check('binding credentials receipts and points roll back together',()=>{assert.throws(()=>service.github.complete(sessions[2],switched.browser));assert.equal(db.prepare('SELECT 1 FROM social_github_bindings WHERE wallet=?').get(sessions[2].wallet),undefined);assert.equal(service.profile(sessions[2]).points,0);});
 db.exec('DROP TRIGGER github_fixture_reject');assert.equal(service.github.complete(sessions[2],switched.browser).pointsAwarded,50);checks++;
 const bad=flow(sessions[4],{id:1004,login:'fixture-four'});await reject(()=>service.github.callback(bad.params,'x'.repeat(43)),'github_browser_mismatch');
 await reject(()=>service.github.callback(new URLSearchParams({state:'z'.repeat(43),code:bad.code}),bad.browser),'github_browser_mismatch');
 const cancelled=flow(sessions[5],{id:1005,login:'fixture-five'});assert.equal((await service.github.callback(new URLSearchParams({state:cancelled.state,error:'access_denied'}),cancelled.browser)).status,'cancelled');checks++;
 const revoked=flow(sessions[6],{id:1006,login:'fixture-six'});auth.logout(sessions[6]);await reject(()=>service.github.callback(revoked.params,revoked.browser),'github_original_session_invalid');
 const expired=flow(sessions[7],{id:1007,login:'fixture-seven'});now+=601;await reject(()=>service.github.callback(expired.params,expired.browser),'github_state_expired');
 const beforeRefresh=refreshes;const follow=await service.github.verify(sessions[0],{taskId:'github_star_infra_v1'});
 check('expired credentials refresh and Star uses bound identity',()=>{assert.equal(follow.pointsAwarded,1);assert.equal(refreshes,beforeRefresh+1);assert.equal(follow.profile.points,176);});
 const beforeReplay=fetches;const replay=await service.github.verify(sessions[0],{taskId:'github_star_infra_v1'});check('completed task does not call provider or pay again',()=>{assert.equal(replay.pointsAwarded,0);assert.equal(fetches,beforeReplay);});
 const privateFailure=repositories[0];repositoryOverride={id:Number(privateFailure.id),private:true,visibility:'private',full_name:'flybrainlabs/'+privateFailure.name,owner:{login:'flybrainlabs'}};
 await reject(()=>service.github.verify(sessions[0],{taskId:'github_star_'+privateFailure.name+'_v1'}),'github_repository_unavailable');repositoryOverride=null;now+=11;
 const concurrent=await Promise.allSettled(Array.from({length:5},()=>service.github.verify(sessions[0],{taskId:'github_star_miner_v1'})));
 check('concurrent verification awards one point exactly once',()=>{assert.equal(concurrent.filter(r=>r.status==='fulfilled').length,1);assert.equal(service.profile(sessions[0]).points,177);});
 for(const repo of repositories.filter(r=>!['miner','infra'].includes(r.name))){
  assert(repo.id,'The selected public repository must be confirmed before this acceptance gate');
  const result=await service.github.verify(sessions[0],{taskId:'github_star_'+repo.name+'_v1'});assert.equal(result.pointsAwarded,1);checks++;
 }
 check('binding and three Star tasks total fifty-three in the unified ledger',()=>{const profile=service.profile(sessions[0]);assert.equal(profile.points,178);assert.equal(profile.github.pointsEarned,53);assert.equal(profile.github.starCompleted,3);assert.equal(profile.github.completedTaskIds.length,4);assert.equal(db.prepare('SELECT SUM(points_delta) total FROM community_points_ledger WHERE wallet=?').get(sessions[0].wallet).total,profile.points);assert.equal(service.leaderboard().items[0].points,178);});
 relationStatus=404;const noRepeat=await service.github.verify(sessions[0],{taskId:'github_star_miner_v1'});assert.equal(noRepeat.pointsAwarded,0);checks++;
 check('historical snapshot remains byte-identical',()=>assert.equal(JSON.stringify(service.snapshotContent(prior.snapshotId)),frozen));
 const current=service.createSnapshot(login(operatorKey),{requestId:randomUUID(),reason:'Include verified GitHub contributions in new snapshot'});check('new snapshot includes GitHub ledger contributions',()=>assert.equal(service.snapshotContent(current.snapshotId).entries[0].points,178));
 const extra=await connect(sessions[8],{id:1008,login:'fixture-eight'});assert.equal(extra.result.pointsAwarded,50);checks++;
 await reject(()=>service.github.verify(sessions[8],{taskId:'github_star_infra_v1'}),'github_not_starred');
 for(const [status,expected] of [[401,'github_reauthorization_required'],[403,'github_access_restricted'],[429,'github_rate_limited'],[503,'github_unavailable']]){
  now+=70;relationStatus=status;provider.blockedUntil=0;await reject(()=>service.github.verify(sessions[8],{taskId:'github_star_infra_v1'}),expected);assert.equal(service.profile(sessions[8]).points,50);
 }
 now+=70;relationStatus=204;provider.blockedUntil=0;userOverride={id:1008,login:'renamed-fixture',type:'User',avatar_url:'https://avatars.githubusercontent.com/u/1008'};
 const renamed=await service.github.verify(sessions[8],{taskId:'github_star_infra_v1'});check('username changes preserve stable GitHub identity',()=>{assert.equal(renamed.pointsAwarded,1);assert.equal(renamed.profile.github.binding.login,'renamed-fixture');});userOverride=null;
 const disabled=await new SocialCommunityService(auth,allocation,{githubConfig:{...githubConfig,engagementRewardsEnabled:false},githubProvider:provider}).initialize();
 relationStatus=404;await reject(()=>disabled.github.verify(sessions[2],{taskId:'github_star_miner_v1'}),'github_not_starred');
 check('read-only mode rejects absent Stars without saving a positive proof',()=>{assert.deepEqual(disabled.profile(sessions[2]).github.verifiedTaskIds,[]);assert.equal(disabled.profile(sessions[2]).points,50);});relationStatus=204;
 const readOnlyLedger=JSON.stringify(db.prepare('SELECT * FROM community_points_ledger ORDER BY rowid').all()),readOnlyReceipts=JSON.stringify(db.prepare('SELECT * FROM social_task_completions ORDER BY rowid').all());
 check('Star verification remains available independently of points',()=>{const task=disabled.tasks().tasks.find(t=>t.id==='github_star_miner_v1');assert.equal(task.available,true);assert.equal(task.rewardsAvailable,false);assert.equal(disabled.github.starVerificationEnabled,true);});
 const checked=await disabled.github.verify(sessions[8],{taskId:'github_star_miner_v1'});
 check('read-only Star proof is stored without awarding or consuming a reward',()=>{assert.equal(checked.state,'verified');assert.equal(checked.pointsAwarded,0);assert.equal(checked.profile.points,51);assert(checked.profile.github.verifiedTaskIds.includes('github_star_miner_v1'));assert.equal(checked.profile.github.starCompleted,2);assert(!checked.profile.github.completedTaskIds.includes('github_star_miner_v1'));});
 const readOnlyFetches=fetches,proofCount=db.prepare("SELECT COUNT(*) n FROM social_github_verification_audit WHERE result_code='star_verified'").get().n;
 await disabled.github.verify(sessions[8],{taskId:'github_star_miner_v1'});
 check('proof replay neither calls GitHub nor appends duplicate evidence',()=>{assert.equal(fetches,readOnlyFetches);assert.equal(db.prepare("SELECT COUNT(*) n FROM social_github_verification_audit WHERE result_code='star_verified'").get().n,proofCount);});
 db.prepare("UPDATE social_tasks SET category='community' WHERE task_key='github_star_node_v1'").run();
 const metadataCheck=await disabled.github.verify(sessions[8],{taskId:'github_star_node_v1'});
 check('editable category cannot bypass the reward authorization gate',()=>{assert.equal(metadataCheck.state,'verified');assert.equal(metadataCheck.pointsAwarded,0);assert.equal(metadataCheck.profile.points,51);});
 db.prepare("UPDATE social_tasks SET category='github' WHERE task_key='github_star_node_v1'").run();
 check('read-only checks leave ledger and reward receipts byte-identical',()=>{assert.equal(JSON.stringify(db.prepare('SELECT * FROM community_points_ledger ORDER BY rowid').all()),readOnlyLedger);assert.equal(JSON.stringify(db.prepare('SELECT * FROM social_task_completions ORDER BY rowid').all()),readOnlyReceipts);});
 const verificationPaused=await new SocialCommunityService(auth,allocation,{githubConfig:{...githubConfig,starVerificationEnabled:false,engagementRewardsEnabled:false},githubProvider:provider}).initialize();
 await reject(()=>verificationPaused.github.verify(sessions[8],{taskId:'github_star_miner_v1'}),'github_verification_paused');
 check('verification switch is independent and does not advertise points',()=>{const task=verificationPaused.tasks().tasks.find(t=>t.id==='github_star_miner_v1');assert.equal(task.available,false);assert.equal(task.rewardsAvailable,false);assert.equal(task.unavailableCode,'github_verification_paused');});
 const empty=await new SocialCommunityService(auth,allocation).initialize();check('missing private configuration retains existing Social service',()=>{assert.equal(empty.profile(sessions[0]).points,178);assert.equal(empty.github.configured,false);assert.equal(empty.tasks().tasks.find(t=>t.id==='github_connect_v1').available,false);});
 await reject(()=>service.github.verify(sessions[8],{taskId:'github_star_miner_v1',wallet:sessions[0].wallet}),'github_task_invalid');
 check('GitHub does not trigger X invitation rewards',()=>assert.equal(db.prepare('SELECT COUNT(*) n FROM community_referral_rewards').get().n,0));
 check('history and administration use existing totals',()=>{assert.equal(service.pointsHistory(sessions[0].wallet,{limit:'100'}).items.length,5);const summary=service.adminOverview(operator).github;assert.equal(summary.pointsAwarded,154);assert(summary.verificationResults.some(r=>r.result_code==='github_rate_limited'));assert(!summary.recentFailures.some(r=>r.result_code==='star_verified'));assert(!JSON.stringify(summary).includes('fixture-access'));});
 check('ledger, completions and identity are immutable',()=>{assert.throws(()=>db.prepare('DELETE FROM community_points_ledger').run());assert.throws(()=>db.prepare('DELETE FROM social_task_completions').run());assert.throws(()=>db.prepare("UPDATE social_github_bindings SET github_user_id='9999'").run());assert.throws(()=>db.prepare('DELETE FROM social_github_bindings').run());});
 const historical=login(Keypair.generate()),legacyTask=db.prepare("SELECT * FROM social_tasks WHERE task_key='github_star_explorer_v1'").get();
 service.transaction(()=>service.github.award(historical,legacyTask,'9001','isolated historical fixture','https://github.com/flybrainlabs/explorer','1415404602'));
 const historicalLedger=JSON.stringify(db.prepare('SELECT * FROM community_points_ledger WHERE wallet=?').all(historical.wallet));
 check('retired Star receipts retain points without increasing selected-task progress',()=>{const profile=service.profile(historical);assert.equal(profile.points,1);assert.equal(profile.github.pointsEarned,1);assert.equal(profile.github.starCompleted,0);assert.equal(profile.github.starTotal,3);assert(profile.github.completedTaskIds.includes('github_star_explorer_v1'));});
 server=serveSocial(service,{port:0});await new Promise(r=>server.once('listening',r));const base='http://127.0.0.1:'+server.address().port;
 const request=async(path,session=null,body=null,cookie=null)=>{const response=await fetch(base+path,{method:body===null?'GET':'POST',headers:{...(session?.headers||{Origin:origin}),...(cookie?{Cookie:cookie}:{})},body:body===null?undefined:JSON.stringify(body),redirect:'manual'});return {response,value:response.status===303?null:await response.json()};};
 const health=await request('/api/social/health');assert.equal(health.value.schemaVersion,3);checks++;
 const absent=await request('/api/social/github/binding');assert.equal(absent.response.status,401);checks++;
 const missingCsrf=await request('/api/social/github/start',{headers:{Origin:origin,Authorization:sessions[0].headers.Authorization}},{});assert.equal(missingCsrf.response.status,401);checks++;
 const api=await request('/api/social/github/start',sessions[0],{});check('start sets a secure session-specific cookie',()=>{assert.equal(api.response.status,200);assert.match(api.response.headers.get('set-cookie'),/HttpOnly; Secure; SameSite=Lax/);assert(!JSON.stringify(api.value).includes('fixture-secret'));});
 const apiUrl=new URL(api.value.authorizeUrl),apiCode='fixture-http-code-'+(++sequence),apiCookie=api.response.headers.get('set-cookie').split(';')[0];codes.set(apiCode,{user:{id:1001,login:'fixture-one'},challenge:apiUrl.searchParams.get('code_challenge')});
 const redirected=await fetch(base+'/api/auth/github/callback?'+new URLSearchParams({state:apiUrl.searchParams.get('state'),code:apiCode}),{headers:{Cookie:apiCookie},redirect:'manual'});assert.equal(redirected.status,303);assert.equal(redirected.headers.get('location'),origin+'/social/?github=ready');checks++;
 const finalized=await request('/api/social/github/complete',sessions[0],{},apiCookie);assert.equal(finalized.response.status,200);assert.equal(finalized.value.pointsAwarded,0);assert.equal(finalized.value.profile.points,178);checks++;
 const replayFlow=flow(sessions[0]);await reject(()=>service.github.callback(new URLSearchParams({state:replayFlow.state,code:apiCode}),replayFlow.browser),'github_code_used');
 const callback=await request('/api/auth/github/callback?state=invalid&code=invalid');check('callback fails to a fixed clean redirect',()=>{assert.equal(callback.response.status,303);assert(callback.response.headers.get('location').startsWith(origin+'/social/?github=failed'));assert(!callback.response.headers.get('location').includes('code=invalid'));});
 check('duplicate cookie names and absent cookie are rejected',()=>{assert.equal(githubCookie({cookie:GITHUB_COOKIE+'='+'a'.repeat(43)+'; '+GITHUB_COOKIE+'='+'b'.repeat(43)}),null);assert.equal(githubCookie({}),null);});
 await new Promise(r=>server.close(r));server=null;db.close();db=new DatabaseSync(file);auth=await new WalletMiningService(config,db,null,{clock:()=>now}).initialize();service=await new SocialCommunityService(auth,allocation,{githubConfig,githubProvider:provider}).initialize();
 check('restart preserves completed tasks credentials and points',()=>{assert.equal(service.profile(sessions[0]).points,178);assert.equal(service.profile(sessions[0]).github.starCompleted,3);assert(service.profile(sessions[8]).github.verifiedTaskIds.includes('github_star_miner_v1'));assert.equal(service.profile(sessions[8]).points,51);assert.equal(service.github.complete(sessions[0],normal.q.browser).pointsAwarded,0);assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check,'ok');});
 check('restart retains historical retired-task credit byte-for-byte',()=>{assert.equal(service.profile(historical).points,1);assert.equal(service.profile(historical).github.starCompleted,0);assert.equal(JSON.stringify(db.prepare('SELECT * FROM community_points_ledger WHERE wallet=?').all(historical.wallet)),historicalLedger);assert(!service.tasks(historical).tasks.some(t=>t.id==='github_star_explorer_v1'));});
 console.log(JSON.stringify({passed:true,checks,providerRequests:fetches,githubTasks:4,totalGitHubPoints:53,database:'isolated SQLite/WAL',wallet:'actual scripted SIWS Ed25519',realOAuth:false,engagementFixtureOnly:true,productionUsersCreated:0,chainTransactions:0}));
}finally{if(server)await new Promise(r=>server.close(r));db.close();await rm(directory,{recursive:true,force:true});}
