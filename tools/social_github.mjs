// @ts-check
// GitHub proof is finalized only with the original live wallet session and browser.
import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {GitHubCipher,GitHubProvider,githubError as fail} from './github_provider.mjs';

const hash=value=>createHash('sha256').update(value).digest('hex');
const uid=()=>randomBytes(32).toString('base64url');
const CONNECT='github_connect_v1',FOLLOW='github_follow_flybrainlabs_v1';
const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
export const GITHUB_COOKIE='__Host-fbw-github-flow';
export function githubCookie(headers){
  const values=String(headers.cookie||'').split(';').map(s=>s.trim()).filter(s=>s.startsWith(GITHUB_COOKIE+'='));
  if(values.length!==1)return null;
  const value=values[0].slice(GITHUB_COOKIE.length+1);return /^[A-Za-z0-9_-]{43}$/.test(value)?value:null;
}
export const flowCookie=value=>GITHUB_COOKIE+'='+value+'; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600';
export const clearFlowCookie=()=>GITHUB_COOKIE+'=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';

export async function loadGitHubConfig(file=process.env.GITHUB_OAUTH_CONFIG||'/etc/flypow/github-community.json'){
  try{
    const config=JSON.parse(await readFile(file,'utf8'));
    return {...config,engagementRewardsEnabled:process.env.GITHUB_ENGAGEMENT_REWARDS_ENABLED==='true'||config.engagementRewardsEnabled===true};
  }catch(error){if(error.code==='ENOENT')return {};throw fail('github_configuration_invalid',503);}
}

export class SocialGitHubService {
  constructor(community,config={},provider=null){
    this.community=community;this.db=community.db;this.clock=()=>community.clock();this.config=config;
    this.configured=!!(config.clientId&&config.clientSecret&&config.encryptionKey);
    this.bindingEnabled=this.configured&&config.bindingEnabled!==false;
    this.engagementEnabled=this.configured&&config.engagementRewardsEnabled===true;
    this.provider=provider||new GitHubProvider(config);this.cipher=this.configured?new GitHubCipher(config.encryptionKey):null;
    this.refreshes=new Map();this.manifest=null;
    if(this.configured){
      let url;try{url=new URL(this.provider.callbackUrl);}catch{throw fail('github_configuration_invalid',503);}
      if(!(url.protocol==='https:'||url.protocol==='http:'&&url.hostname==='127.0.0.1')||url.pathname!=='/api/auth/github/callback'||url.search||url.hash||url.username||url.password||!community.auth.config.origins.includes(url.origin))throw fail('github_configuration_invalid',503);
      this.origin=url.origin;
    }
  }
  async initialize(){
    this.manifest=JSON.parse(await readFile(new URL('../config/github-community-tasks-v1.json',import.meta.url),'utf8'));
    if(this.manifest.schema!=='flybrainlabs-github-community-tasks-v1'||this.manifest.owner!=='flybrainlabs'||this.manifest.repositories.length!==10||new Set(this.manifest.repositories.map(r=>r.name)).size!==10)throw fail('github_targets_invalid',503);
    this.community.transaction(()=>{
      this.db.prepare("UPDATE social_github_oauth_states SET status='failed',encrypted_verifier=NULL,encrypted_result=NULL,result_code='github_state_expired' WHERE expires_at<=? AND status IN('issued','authorized','exchanging')").run(this.clock());
      const seed=(key,title,description,points,verifier,enabled=1)=>this.db.prepare('INSERT INTO social_tasks VALUES(?,?,?,?,?,?,?,0,1,?,?) ON CONFLICT(task_key) DO NOTHING').run(key,title,description,points,'github',verifier,enabled,this.clock(),this.clock());
      seed(CONNECT,'Connect GitHub','Verify your GitHub identity once with your signed-in wallet.',50,'github_oauth');
      seed(FOLLOW,'Follow flybrainlabs','Follow the official account yourself, then verify the public relationship.',10,'github_follow');
      this.db.prepare('INSERT INTO social_github_task_targets VALUES(?,?,NULL,NULL,1,?) ON CONFLICT(task_key) DO NOTHING').run(FOLLOW,'flybrainlabs',this.clock());
      for(const repo of this.manifest.repositories){
        if(!/^[a-z][a-z0-9-]{1,39}$/.test(repo.name)||repo.id!==null&&!/^[1-9][0-9]{0,18}$/.test(repo.id))throw fail('github_targets_invalid',503);
        const key='github_star_'+repo.name+'_v1';seed(key,'Star '+repo.name,repo.description,1,'github_star',Number(!!repo.id));
        const target=this.db.prepare('SELECT * FROM social_github_task_targets WHERE task_key=?').get(key);
        if(target&&(target.owner!=='flybrainlabs'||target.repository!==repo.name||target.repository_id!==repo.id))throw fail('github_targets_conflict',503);
        this.db.prepare('INSERT INTO social_github_task_targets VALUES(?,?,?,?,?,?) ON CONFLICT(task_key) DO NOTHING').run(key,'flybrainlabs',repo.name,repo.id,Number(!!repo.id),this.clock());
      }
    });return this;
  }
  installed(key){return key===CONNECT||key===FOLLOW||!!this.manifest?.repositories.some(r=>key==='github_star_'+r.name+'_v1');}
  availability(task){
    if(task.category!=='github')return {available:true};
    const target=this.db.prepare('SELECT * FROM social_github_task_targets WHERE task_key=?').get(task.task_key);
    const code=!this.configured?'github_not_configured':task.task_key===CONNECT?(!this.bindingEnabled?'github_binding_paused':null):!this.engagementEnabled?'github_engagement_paused':!target?.verified_public?'github_repository_unavailable':null;
    return {available:!code,unavailableCode:code,targetUrl:target?'https://github.com/'+target.owner+(target.repository?'/'+target.repository:''):null,repository:target?.repository||null,repositoryId:target?.repository_id||null};
  }
  view(wallet){
    const binding=this.db.prepare('SELECT * FROM social_github_bindings WHERE wallet=?').get(wallet);
    const completions=this.db.prepare("SELECT task_key,points_awarded FROM social_task_completions WHERE wallet=? AND task_key LIKE 'github_%'").all(wallet);
    return {configured:this.configured,bindingEnabled:this.bindingEnabled,engagementRewardsEnabled:this.engagementEnabled,binding:binding?{userId:binding.github_user_id,login:binding.github_login,avatarUrl:binding.avatar_url,connectedAt:binding.connected_at,status:binding.binding_status,verificationMethod:binding.verification_method}:null,completedTaskIds:completions.map(r=>r.task_key),bindingPointsEarned:completions.find(r=>r.task_key===CONNECT)?.points_awarded||0,pointsEarned:completions.reduce((sum,r)=>sum+r.points_awarded,0),starCompleted:completions.filter(r=>r.task_key.startsWith('github_star_')).length,starTotal:10};
  }
  ensureSession(session){
    const live=this.db.prepare('SELECT * FROM mining_v3_sessions WHERE token_hash=?').get(session.token_hash);
    if(!live||live.revoked||live.wallet!==session.wallet||live.origin!==session.origin||live.expires_at<=this.clock())throw fail('github_original_session_invalid',401);
    return live;
  }
  requireConfigured(){if(!this.configured)throw fail('github_not_configured',503);}
  start(session){
    this.requireConfigured();if(!this.bindingEnabled)throw fail('github_binding_paused',409);
    this.ensureSession(session);if(session.origin!==this.origin)throw fail('github_origin_mismatch',403);
    const task=this.community.enabledTask(CONNECT),state=uid(),browser=uid(),verifier=uid(),stateHash=hash(state);
    this.community.transaction(()=>{
      if(this.db.prepare('SELECT COUNT(*) n FROM social_github_oauth_states WHERE wallet=? AND issued_at>?').get(session.wallet,this.clock()-600).n>=6)throw fail('github_rate_limited',429,600);
      this.db.prepare("UPDATE social_github_oauth_states SET status='cancelled',encrypted_verifier=NULL,encrypted_result=NULL,result_code='superseded' WHERE wallet=? AND session_identifier=? AND status IN('issued','authorized')").run(session.wallet,session.token_hash);
      this.db.prepare("INSERT INTO social_github_oauth_states(state_hash,wallet,session_identifier,origin,browser_hash,encrypted_verifier,issued_at,expires_at,status,task_revision,reward_points) VALUES(?,?,?,?,?,?,?,?,'issued',?,?)").run(stateHash,session.wallet,session.token_hash,session.origin,hash(browser),this.cipher.seal(verifier,'pkce:'+stateHash),this.clock(),this.clock()+600,task.revision,task.reward_points);
    });
    return {authorizeUrl:this.provider.authorize(state,createHash('sha256').update(verifier).digest('base64url')),expiresAt:this.clock()+600,cookie:flowCookie(browser)};
  }
  record(wallet,task,code,user=null,repository=null,evidence=null){
    this.db.prepare('INSERT INTO social_github_verification_audit(wallet,github_user_id,task_key,result_code,repository_id,evidence_hash,created_at) VALUES(?,?,?,?,?,?,?)').run(wallet,user,task,code,repository,evidence,this.clock());
  }
  async callback(params,browser){
    this.requireConfigured();
    const state=params.get('state');if(typeof state!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(state)||!browser)throw fail('github_state_invalid',400);
    const stateHash=hash(state),q=this.db.prepare('SELECT * FROM social_github_oauth_states WHERE state_hash=?').get(stateHash);
    if(!q||!equal(q.browser_hash,hash(browser)))throw fail('github_browser_mismatch',403);
    if(q.expires_at<=this.clock()||q.status!=='issued')throw fail(q.expires_at<=this.clock()?'github_state_expired':'github_state_used',409);
    this.ensureSession({wallet:q.wallet,token_hash:q.session_identifier,origin:q.origin});
    if(params.get('error')){
      this.community.transaction(()=>{this.db.prepare("UPDATE social_github_oauth_states SET status='cancelled',consumed_at=?,encrypted_verifier=NULL,result_code='github_cancelled' WHERE state_hash=? AND status='issued'").run(this.clock(),stateHash);this.record(q.wallet,CONNECT,'github_cancelled');});
      return {status:'cancelled'};
    }
    const code=params.get('code');if(typeof code!=='string'||code.length<4||code.length>512||!/^[A-Za-z0-9_-]+$/.test(code))throw fail('github_code_invalid',400);
    this.community.transaction(()=>{
      if(this.db.prepare('SELECT 1 FROM social_github_oauth_states WHERE code_hash=?').get(hash(code)))throw fail('github_code_used',409);
      if(this.db.prepare("UPDATE social_github_oauth_states SET status='exchanging',consumed_at=?,code_hash=? WHERE state_hash=? AND status='issued'").run(this.clock(),hash(code),stateHash).changes!==1)throw fail('github_state_used',409);
    });
    try{
      const credentials=await this.provider.exchange(code,this.cipher.open(q.encrypted_verifier,'pkce:'+stateHash)),identity=await this.provider.user(credentials.accessToken);
      this.ensureSession({wallet:q.wallet,token_hash:q.session_identifier,origin:q.origin});
      if(q.expires_at<=this.clock())throw fail('github_state_expired',409);
      this.community.transaction(()=>{
        this.db.prepare("UPDATE social_github_oauth_states SET status='authorized',encrypted_verifier=NULL,encrypted_result=? WHERE state_hash=? AND status='exchanging'").run(this.cipher.seal({credentials,identity},'oauth:'+stateHash),stateHash);
        this.record(q.wallet,CONNECT,'github_authorized',identity.id);
      });return {status:'ready'};
    }catch(error){
      this.community.transaction(()=>{this.db.prepare("UPDATE social_github_oauth_states SET status='failed',encrypted_verifier=NULL,encrypted_result=NULL,result_code=? WHERE state_hash=? AND status='exchanging'").run(error.code||'github_unavailable',stateHash);this.record(q.wallet,CONNECT,error.code||'github_unavailable');});throw error;
    }
  }
  saveCredentials(wallet,user,credentials,revision=1){
    const expires=credentials.expiresIn?this.clock()+credentials.expiresIn:null,refreshExpires=credentials.refreshExpiresIn?this.clock()+credentials.refreshExpiresIn:null;
    this.db.prepare('INSERT INTO social_github_credentials VALUES(?,?,?,?,?,?) ON CONFLICT(wallet) DO UPDATE SET encrypted_credentials=excluded.encrypted_credentials,expires_at=excluded.expires_at,refresh_expires_at=excluded.refresh_expires_at,revision=social_github_credentials.revision+1,updated_at=excluded.updated_at').run(wallet,this.cipher.seal(credentials,'token:'+wallet+':'+user),expires,refreshExpires,revision,this.clock());
  }
  award(session,task,user,evidence,url,repository=null){
    const prior=this.db.prepare('SELECT 1 FROM social_task_completions WHERE wallet=? AND task_key=?').get(session.wallet,task.task_key);
    if(prior)return 0;
    const id=randomBytes(16).toString('hex');
    this.db.prepare('INSERT INTO community_points_ledger(wallet,points_delta,source_type,source_id,task_key,idempotency_key,public_description,private_reason,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(session.wallet,task.reward_points,'github_task',id,task.task_key,'github:'+user+':'+task.task_key,task.title,'Read-only GitHub API verified a stable identity and fixed target','community-github-v3',this.clock());
    this.db.prepare('INSERT INTO social_task_completions VALUES(?,?,?,?,?,?,?,?,?)').run(id,task.task_key,session.wallet,evidence,url,'verified',task.reward_points,task.revision,this.clock());
    this.record(session.wallet,task.task_key,'completed',user,repository,hash(evidence));return task.reward_points;
  }
  complete(session,browser){
    this.requireConfigured();this.ensureSession(session);if(!browser)throw fail('github_browser_mismatch',403);
    try{return this.community.transaction(()=>{
      const q=this.db.prepare('SELECT * FROM social_github_oauth_states WHERE browser_hash=? ORDER BY issued_at DESC,rowid DESC LIMIT 1').get(hash(browser));
      if(!q||q.wallet!==session.wallet||q.session_identifier!==session.token_hash||q.origin!==session.origin)throw fail('github_wallet_mismatch',403);
      if(q.status==='completed')return {state:'completed',pointsAwarded:0,profile:this.community.profile(session)};
      if(q.status!=='authorized'||q.expires_at<=this.clock())throw fail(q.expires_at<=this.clock()?'github_state_expired':'github_state_invalid',409);
      const task=this.community.enabledTask(CONNECT);if(!this.bindingEnabled)throw fail('github_binding_paused',409);
      const {credentials,identity}=this.cipher.open(q.encrypted_result,'oauth:'+q.state_hash),prior=this.db.prepare('SELECT * FROM social_github_bindings WHERE wallet=? OR github_user_id=?').all(session.wallet,identity.id);
      if(prior.some(b=>b.wallet!==session.wallet||b.github_user_id!==identity.id))throw fail('github_identity_conflict',409);
      this.community.registerInside(session);
      this.db.prepare("INSERT INTO social_github_bindings VALUES(?,?,?,?,?,'github_oauth_pkce','active',?) ON CONFLICT(wallet) DO UPDATE SET github_login=excluded.github_login,avatar_url=excluded.avatar_url,binding_status='active',updated_at=excluded.updated_at").run(session.wallet,identity.id,identity.login,identity.avatarUrl,this.clock(),this.clock());
      this.saveCredentials(session.wallet,identity.id,credentials);
      const points=this.award(session,{...task,reward_points:q.reward_points,revision:q.task_revision},identity.id,'github:'+identity.id+':connect','https://github.com/'+identity.login);
      this.db.prepare("UPDATE social_github_oauth_states SET status='completed',encrypted_result=NULL,result_code='completed' WHERE state_hash=?").run(q.state_hash);
      return {state:'completed',pointsAwarded:points,profile:this.community.profile(session)};
    });}catch(error){
      // Preserve retriable authorized proofs; permanently conflicting identities
      // become terminal so repeated submissions cannot flood the audit table.
      const q=this.db.prepare('SELECT * FROM social_github_oauth_states WHERE browser_hash=? ORDER BY issued_at DESC,rowid DESC LIMIT 1').get(hash(browser));
      if(q&&q.wallet===session.wallet&&q.session_identifier===session.token_hash&&q.status==='authorized'&&q.result_code!==(error.code||'retryable_store_error')){
        this.community.transaction(()=>{
          const code=error.code||'retryable_store_error';this.record(session.wallet,CONNECT,code);
          if(code==='github_identity_conflict')this.db.prepare("UPDATE social_github_oauth_states SET status='failed',encrypted_result=NULL,result_code=? WHERE state_hash=?").run(code,q.state_hash);
          else this.db.prepare('UPDATE social_github_oauth_states SET result_code=? WHERE state_hash=?').run(code,q.state_hash);
        });
      }
      throw error;
    }
  }
  async token(binding){
    const row=this.db.prepare('SELECT * FROM social_github_credentials WHERE wallet=?').get(binding.wallet);
    if(!row)throw fail('github_reauthorization_required',401);
    const credentials=this.cipher.open(row.encrypted_credentials,'token:'+binding.wallet+':'+binding.github_user_id);
    if(!row.expires_at||row.expires_at>this.clock()+30)return credentials.accessToken;
    if(!credentials.refreshToken||row.refresh_expires_at&&row.refresh_expires_at<=this.clock())throw fail('github_reauthorization_required',401);
    if(!this.refreshes.has(binding.wallet)){
      const operation=(async()=>{
        const renewed=await this.provider.refresh(credentials.refreshToken),identity=await this.provider.user(renewed.accessToken);
        if(identity.id!==binding.github_user_id)throw fail('github_identity_conflict',409);
        if(!renewed.refreshToken)renewed.refreshToken=credentials.refreshToken;
        if(!renewed.refreshExpiresIn&&row.refresh_expires_at)renewed.refreshExpiresIn=Math.max(1,row.refresh_expires_at-this.clock());
        this.community.transaction(()=>this.saveCredentials(binding.wallet,binding.github_user_id,renewed));return renewed.accessToken;
      })();this.refreshes.set(binding.wallet,operation);operation.finally(()=>this.refreshes.delete(binding.wallet)).catch(()=>{});
    }
    return this.refreshes.get(binding.wallet);
  }
  async verify(session,body){
    if(Object.keys(body).length!==1||typeof body.taskId!=='string'||!this.installed(body.taskId)||body.taskId===CONNECT)throw fail('github_task_invalid',400);
    this.ensureSession(session);
    const task=this.db.prepare('SELECT * FROM social_tasks WHERE task_key=?').get(body.taskId);
    if(this.db.prepare('SELECT 1 FROM social_task_completions WHERE wallet=? AND task_key=?').get(session.wallet,task.task_key))return {state:'completed',pointsAwarded:0,profile:this.community.profile(session)};
    // The operational gate is independent of editable task metadata.
    this.requireConfigured();if(!this.engagementEnabled)throw fail('github_engagement_paused',409);
    const availability=this.availability(task);if(!availability.available)throw fail(availability.unavailableCode,409);
    if(!task.enabled)throw fail('task_paused',409);
    const binding=this.db.prepare('SELECT * FROM social_github_bindings WHERE wallet=?').get(session.wallet);
    if(!binding)throw fail('github_binding_required',409);
    const target=this.db.prepare('SELECT * FROM social_github_task_targets WHERE task_key=?').get(task.task_key);
    this.community.transaction(()=>{
      const lock=this.db.prepare('SELECT * FROM social_github_verification_locks WHERE wallet=? AND task_key=?').get(session.wallet,task.task_key);
      if(lock?.lease_until>this.clock())throw fail('github_verification_pending',409);
      if(lock?.retry_at>this.clock())throw fail(lock.result_code||'github_rate_limited',429,lock.retry_at-this.clock());
      this.db.prepare('INSERT INTO social_github_verification_locks VALUES(?,?,?,0,NULL) ON CONFLICT(wallet,task_key) DO UPDATE SET lease_until=excluded.lease_until,retry_at=0,result_code=NULL').run(session.wallet,task.task_key,this.clock()+60);
    });
    try{
      const token=await this.token(binding),identity=await this.provider.user(token);
      if(identity.id!==binding.github_user_id)throw fail('github_identity_conflict',409);
      if(target.repository)await this.provider.repository(target.owner,target.repository,target.repository_id,token);
      const relation=target.repository?await this.provider.starred(target.owner,target.repository,token):await this.provider.following(identity.login,token);
      this.ensureSession(session);
      if(!relation.found)throw fail(target.repository?'github_not_starred':'github_not_followed',409,10);
      return this.community.transaction(()=>{
        const current=this.community.enabledTask(task.task_key);if(current.revision!==task.revision||!this.availability(current).available)throw fail('task_paused',409);
        this.ensureSession(session);
        this.db.prepare("UPDATE social_github_bindings SET github_login=?,avatar_url=?,binding_status='active',updated_at=? WHERE wallet=? AND github_user_id=?").run(identity.login,identity.avatarUrl,this.clock(),session.wallet,identity.id);
        const points=this.award(session,task,identity.id,'github:'+identity.id+':'+(target.repository_id||'follow:flybrainlabs'),availability.targetUrl,target.repository_id);
        this.db.prepare('UPDATE social_github_verification_locks SET lease_until=0,retry_at=0,result_code=NULL WHERE wallet=? AND task_key=?').run(session.wallet,task.task_key);
        return {state:'completed',pointsAwarded:points,profile:this.community.profile(session)};
      });
    }catch(error){
      this.community.transaction(()=>{
        const code=error.code||'github_unavailable';
        this.record(session.wallet,task.task_key,code,binding.github_user_id,target.repository_id);
        if(code==='github_reauthorization_required')this.db.prepare("UPDATE social_github_bindings SET binding_status='reauthorization_required',updated_at=? WHERE wallet=?").run(this.clock(),session.wallet);
        this.db.prepare('UPDATE social_github_verification_locks SET lease_until=0,retry_at=?,result_code=? WHERE wallet=? AND task_key=?').run(this.clock()+Math.max(5,error.retryAfter||5),code,session.wallet,task.task_key);
      });throw error;
    }
  }
  adminOverview(){
    const totals=this.db.prepare("SELECT task_key,COUNT(*) completions,SUM(points_awarded) points FROM social_task_completions WHERE task_key LIKE 'github_%' GROUP BY task_key ORDER BY task_key").all();
    return {configured:this.configured,bindingEnabled:this.bindingEnabled,engagementRewardsEnabled:this.engagementEnabled,callbackUrl:this.configured?this.provider.callbackUrl:null,bindingCount:this.db.prepare('SELECT COUNT(*) n FROM social_github_bindings').get().n,pointsAwarded:totals.reduce((sum,r)=>sum+r.points,0),tasks:totals,verificationResults:this.db.prepare('SELECT result_code,COUNT(*) count FROM social_github_verification_audit GROUP BY result_code ORDER BY result_code').all(),recentFailures:this.db.prepare("SELECT wallet,github_user_id,task_key,result_code,repository_id,created_at FROM social_github_verification_audit WHERE result_code NOT IN('completed','github_authorized') ORDER BY sequence DESC LIMIT 50").all()};
  }
}
