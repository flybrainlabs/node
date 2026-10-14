// @ts-check
// Read-only GitHub operations. No follow, star or repository-write request exists.
import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';

export const githubError=(code,status=400,retryAfter=0)=>Object.assign(new Error(code),{code,status,retryAfter});
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
export class GitHubCipher {
  constructor(key){
    if(typeof key!=='string'||!/^[a-f0-9]{64}$/i.test(key))throw githubError('github_configuration_invalid',503);
    this.key=Buffer.from(key,'hex');
  }
  seal(value,context){
    const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.key,nonce);
    cipher.setAAD(Buffer.from(context));
    return [nonce,Buffer.concat([cipher.update(JSON.stringify(value),'utf8'),cipher.final()]),cipher.getAuthTag()].map(v=>v.toString('base64url')).join('.');
  }
  open(value,context){
    try{
      const [nonce,payload,tag]=value.split('.').map(v=>Buffer.from(v,'base64url'));
      const cipher=createDecipheriv('aes-256-gcm',this.key,nonce);cipher.setAAD(Buffer.from(context));cipher.setAuthTag(tag);
      return JSON.parse(Buffer.concat([cipher.update(payload),cipher.final()]).toString('utf8'));
    }catch{throw githubError('github_credentials_unavailable',503);}
  }
}

export class GitHubProvider {
  constructor({clientId='',clientSecret='',callbackUrl='https://flybrain.work/api/auth/github/callback',fetcher=globalThis.fetch,timeoutMs=8000}={}){
    this.clientId=clientId;this.clientSecret=clientSecret;this.callbackUrl=callbackUrl;this.fetcher=fetcher;this.timeoutMs=timeoutMs;
    this.active=0;this.blockedUntil=0;
  }
  authorize(state,challenge){
    const url=new URL('https://github.com/login/oauth/authorize');
    url.search=new URLSearchParams({client_id:this.clientId,redirect_uri:this.callbackUrl,scope:'read:user',state,code_challenge:challenge,code_challenge_method:'S256'}).toString();
    return url.href;
  }
  async request(path,{token=null,form=null,allow404=false}={}){
    const url=form?new URL('https://github.com/login/oauth/access_token'):new URL(path,'https://api.github.com');
    if(!form&&(url.origin!=='https://api.github.com'||!path.startsWith('/')||path.startsWith('//')))throw githubError('github_endpoint_rejected',400);
    if(this.active>=4)throw githubError('github_busy',429,5);
    if(Date.now()<this.blockedUntil)throw githubError('github_rate_limited',429,Math.ceil((this.blockedUntil-Date.now())/1000));
    this.active++;
    try{
      for(let attempt=0;attempt<2;attempt++){
        let response;
        try{
          response=await this.fetcher(url,{method:form?'POST':'GET',headers:{Accept:form?'application/json':'application/vnd.github+json','User-Agent':'flybrainlabs-community','X-GitHub-Api-Version':'2022-11-28',...(token?{Authorization:'Bearer '+token}:{}),...(form?{'Content-Type':'application/x-www-form-urlencoded'}:{})},body:form?new URLSearchParams(form).toString():undefined,signal:AbortSignal.timeout(this.timeoutMs),redirect:'error'});
        }catch{throw githubError('github_unavailable',503,5);}
        if(response.status===404&&allow404)return {found:false};
        if(response.status===429||response.status===403&&(response.headers.get('x-ratelimit-remaining')==='0'||response.headers.has('retry-after'))){
          const seconds=Math.max(5,Math.min(3600,Number(response.headers.get('retry-after'))||Number(response.headers.get('x-ratelimit-reset'))-Date.now()/1000||60));
          this.blockedUntil=Date.now()+seconds*1000;throw githubError('github_rate_limited',429,Math.ceil(seconds));
        }
        if(response.status===401)throw githubError('github_reauthorization_required',401);
        if(response.status===403)throw githubError('github_access_restricted',403);
        if(response.status>=500&&attempt===0){await delay(300);continue;}
        if(!response.ok)throw githubError('github_unavailable',503,5);
        if(response.status===204)return {found:true};
        const raw=await response.text();if(raw.length>65536)throw githubError('github_invalid_response',503);
        let value;try{value=JSON.parse(raw);}catch{throw githubError('github_invalid_response',503);}
        if(value.error)throw githubError(value.error==='bad_verification_code'?'github_code_rejected':'github_reauthorization_required',401);
        return value;
      }
      throw githubError('github_unavailable',503,5);
    }finally{this.active--;}
  }
  async exchange(code,verifier){return this.credentials(await this.request('',{form:{client_id:this.clientId,client_secret:this.clientSecret,redirect_uri:this.callbackUrl,code,code_verifier:verifier}}));}
  async refresh(refreshToken){return this.credentials(await this.request('',{form:{client_id:this.clientId,client_secret:this.clientSecret,grant_type:'refresh_token',refresh_token:refreshToken}}));}
  credentials(value){
    if(typeof value.access_token!=='string'||value.access_token.length<10||value.access_token.length>4096||value.token_type?.toLowerCase()!=='bearer')throw githubError('github_invalid_response',503);
    const scopes=String(value.scope||'').split(/[ ,]+/).filter(Boolean);
    if(scopes.some(scope=>scope!=='read:user'))throw githubError('github_scope_rejected',403);
    for(const key of ['expires_in','refresh_token_expires_in'])if(value[key]!==undefined&&(!Number.isSafeInteger(value[key])||value[key]<=0))throw githubError('github_invalid_response',503);
    if(value.refresh_token!==undefined&&(typeof value.refresh_token!=='string'||value.refresh_token.length>4096))throw githubError('github_invalid_response',503);
    return {accessToken:value.access_token,refreshToken:value.refresh_token||null,expiresIn:value.expires_in||null,refreshExpiresIn:value.refresh_token_expires_in||null};
  }
  async user(token){
    const value=await this.request('/user',{token});
    if(!Number.isSafeInteger(value.id)||value.id<1||value.type!=='User'||typeof value.login!=='string'||!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(value.login))throw githubError('github_invalid_identity',503);
    let avatar='';try{const url=new URL(value.avatar_url);if(url.origin==='https://avatars.githubusercontent.com'&&!url.username&&!url.password)avatar=url.href;}catch{}
    return {id:String(value.id),login:value.login,avatarUrl:avatar};
  }
  async following(login,token){const result=await this.request('/users/'+encodeURIComponent(login)+'/following/flybrainlabs',{token,allow404:true});if(typeof result.found!=='boolean')throw githubError('github_invalid_response',503);return result;}
  async repository(owner,name,id,token){
    const value=await this.request('/repos/'+owner+'/'+name,{token,allow404:true});
    if(value.found===false||String(value.id)!==id||value.private!==false||value.visibility!=='public'||value.full_name?.toLowerCase()!==(owner+'/'+name).toLowerCase()||value.owner?.login?.toLowerCase()!==owner)throw githubError('github_repository_unavailable',409);
    return value;
  }
  async starred(owner,name,token){const result=await this.request('/user/starred/'+owner+'/'+name,{token,allow404:true});if(typeof result.found!=='boolean')throw githubError('github_invalid_response',503);return result;}
}
