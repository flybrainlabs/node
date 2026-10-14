// Official endpoint/status contract fixtures; never uses production credentials.
import assert from 'node:assert/strict';
import {GitHubCipher,GitHubProvider} from '../tools/github_provider.mjs';
let checks=0,calls=0;
const check=(name,fn)=>{fn();checks++;};
const cipher=new GitHubCipher('12'.repeat(32)),sealed=cipher.seal({accessToken:'fixture-token'},'wallet-A');
check('authenticated encryption and identity-bound decryption',()=>{assert.equal(cipher.open(sealed,'wallet-A').accessToken,'fixture-token');assert.throws(()=>cipher.open(sealed,'wallet-B'));assert(!sealed.includes('fixture-token'));});
const provider=new GitHubProvider({clientId:'fixture-id',clientSecret:'fixture-secret',fetcher:async(url,request)=>{
  calls++;assert(['https://api.github.com','https://github.com'].includes(url.origin));assert.equal(request.redirect,'error');
  if(url.pathname==='/login/oauth/access_token'){assert.equal(request.method,'POST');assert.match(request.body,/code_verifier=fixture-verifier/);return Response.json({access_token:'fixture-valid-access-token',token_type:'bearer',scope:'read:user'});}
  assert.equal(request.method,'GET');return new Response(null,{status:204});
}});
const url=new URL(provider.authorize('fixture-state','fixture-challenge'));
check('S256 and minimum read scope',()=>{assert.equal(url.origin,'https://github.com');assert.equal(url.searchParams.get('code_challenge_method'),'S256');assert.equal(url.searchParams.get('scope'),'read:user');assert(!url.href.includes('fixture-secret'));});
await provider.exchange('fixture-code','fixture-verifier');checks++;
assert.equal((await provider.starred('flybrainlabs','miner','fixture-token')).found,true);checks++;
await assert.rejects(provider.request('https://evil.invalid/private'),e=>e.code==='github_endpoint_rejected');checks++;
for(const [status,headers,expected] of [[401,{},'github_reauthorization_required'],[403,{},'github_access_restricted'],[429,{},'github_rate_limited'],[403,{'x-ratelimit-remaining':'0'},'github_rate_limited'],[503,{},'github_unavailable']]){
  const p=new GitHubProvider({fetcher:async()=>new Response(null,{status,headers})});await assert.rejects(p.user('fixture-token'),e=>e.code===expected);checks++;
}
const missing=new GitHubProvider({fetcher:async()=>new Response(null,{status:404})});assert.equal((await missing.following('fixture-user','fixture-token')).found,false);checks++;
const unavailable=new GitHubProvider({fetcher:async()=>{throw new Error('fixture network timeout');}});await assert.rejects(unavailable.user('fixture-token'),e=>e.code==='github_unavailable');checks++;
for(const value of [{access_token:'fixture-token',token_type:'bearer',scope:'repo'},{access_token:'fixture-token',token_type:'bearer',scope:'user:follow'},{access_token:'fixture-token',token_type:'bearer',scope:'read:user',expires_in:-1}])check('unexpected permission or lifecycle rejected',()=>assert.throws(()=>provider.credentials(value)));
const identity=new GitHubProvider({fetcher:async()=>Response.json({id:123,login:'fixture-user',type:'User',avatar_url:'https://avatars.githubusercontent.com/u/123'})});assert.equal((await identity.user('fixture-token')).id,'123');checks++;
for(const value of [{id:123,login:'fixture',type:'Organization'},{id:'123',login:'fixture',type:'User'},{id:123,login:'../other',type:'User'}]){
  const p=new GitHubProvider({fetcher:async()=>Response.json(value)});await assert.rejects(p.user('fixture-token'),e=>e.code==='github_invalid_identity');checks++;
}
for(const value of [{id:1,private:true,visibility:'private',full_name:'flybrainlabs/miner',owner:{login:'flybrainlabs'}},{id:2,private:false,visibility:'public',full_name:'flybrainlabs/miner',owner:{login:'flybrainlabs'}},{id:1,private:false,visibility:'public',full_name:'someone/miner',owner:{login:'someone'}}]){
  const p=new GitHubProvider({fetcher:async()=>Response.json(value)});await assert.rejects(p.repository('flybrainlabs','miner','1','fixture-token'),e=>e.code==='github_repository_unavailable');checks++;
}
const busy=new GitHubProvider();busy.active=4;await assert.rejects(busy.user('fixture-token'),e=>e.code==='github_busy');checks++;
console.log(JSON.stringify({passed:true,checks,officialEndpointFixtures:true,requests:calls,realOAuth:false,productionUsersCreated:0}));
