// Actual Ed25519 challenge/session checks and HTTP origin/CSRF controls. This is
// scripted signing, not an extension or physical-device acceptance claim.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {Keypair} from '@solana/web3.js';
import {createPrivateKey,sign} from 'node:crypto';
import {WalletMiningService,serve} from '../tools/wallet_mining_v3.mjs';
const wallet=Keypair.generate(),other=Keypair.generate(),relayer=Keypair.generate(),origin='https://flybrain.work';let now=1_791_810_000,checks=0;
const config={schema:'flybrainlabs-wallet-mining-config-v3',cluster:'devnet',rpc:'https://api.devnet.solana.com',genesisHash:'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',programId:Keypair.generate().publicKey.toBase58(),mint:'HCdV49RkqtC7pPwzHCYg5KtkmU8opifjojLbAyZXKgQW',policyHash:'a'.repeat(64),origins:[origin],units:[{goalId:'b'.repeat(64),economicTaskId:'c'.repeat(64),rewardAtoms:'100000000'},{goalId:'d'.repeat(64),economicTaskId:'e'.repeat(64),rewardAtoms:'100000000'}],relayer:relayer.publicKey.toBase58(),enabled:false};
const service=await new WalletMiningService(config,new DatabaseSync(':memory:'),relayer,{clock:()=>now}).initialize();
const privateKey=k=>createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),k.secretKey.subarray(0,32)]),format:'der',type:'pkcs8'});
const loginBody=(q,k=wallet)=>({nonce:q.input.nonce,address:wallet.publicKey.toBase58(),signedMessage:q.message,signature:sign(null,Buffer.from(q.message),privateKey(k)).toString('base64')});
const q=service.challenge(origin,{address:wallet.publicKey.toBase58()});assert(q.message.includes(config.genesisHash)&&q.message.includes(origin+'/')&&q.message.includes('does not authorize transfers'));checks++;
for(const body of [{...loginBody(q),address:other.publicKey.toBase58()},{...loginBody(q),signedMessage:q.message.replace('flybrain.work','wrong.example')},loginBody(q,other)]){assert.throws(()=>service.login(origin,body));checks++;}
assert.throws(()=>service.login('https://wrong.example',loginBody(q)));checks++;
const session=service.login(origin,loginBody(q));assert.equal(session.grantAuthorized,false);assert.throws(()=>service.login(origin,loginBody(q)));checks++;
const headers={authorization:'Bearer '+session.token,'x-mining-csrf':session.csrfToken};assert.equal(service.authenticate(origin,headers,true).wallet,wallet.publicKey.toBase58());checks++;
assert.throws(()=>service.authenticate(origin,{authorization:headers.authorization},true));checks++;
assert.throws(()=>service.authenticate('https://wrong.example',headers,true));checks++;
assert.throws(()=>service.authenticate(origin,{authorization:'Bearer '+'0'.repeat(64)},false));checks++;
const expired=service.challenge(origin,{address:wallet.publicKey.toBase58()});now+=301;assert.throws(()=>service.login(origin,loginBody(expired)));checks++;
assert.equal(service.logout(service.authenticate(origin,headers)).chainGrantRevoked,false);assert.throws(()=>service.authenticate(origin,headers));checks++;
const server=serve(service,{port:0});await new Promise(done=>server.once('listening',done));const base='http://127.0.0.1:'+server.address().port+'/api/mining/v3/';
const wrong=await fetch(base+'challenge',{method:'POST',headers:{Origin:'https://wrong.example','Content-Type':'application/json'},body:JSON.stringify({address:wallet.publicKey.toBase58()})});assert.equal(wrong.status,403);checks++;
const preflight=await fetch(base+'history',{method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'Authorization, X-Mining-CSRF'}});assert.equal(preflight.status,204);checks++;
const publicConfig=await(await fetch(base+'configuration',{headers:{Origin:origin}})).json();assert(!Object.hasOwn(publicConfig,'database')&&!Object.hasOwn(publicConfig,'relayerKeypair'));checks++;
const fresh=service.challenge(origin,{address:wallet.publicKey.toBase58()}),active=service.login(origin,loginBody(fresh)),scopeHeaders={Origin:origin,Authorization:'Bearer '+active.token,'X-Mining-CSRF':active.csrfToken,'Content-Type':'application/json'};
const checked=await fetch(base+'session/check',{method:'POST',headers:scopeHeaders,body:'{}'});assert.equal(checked.status,200);const identity=await checked.json();assert.equal(identity.wallet,wallet.publicKey.toBase58());assert.equal(identity.authenticated,true);assert.equal(identity.programId,config.programId);assert(!identity.token&&!identity.csrfToken&&!identity.token_hash);checks++;
const noCsrf={...scopeHeaders};delete noCsrf['X-Mining-CSRF'];assert.equal((await fetch(base+'session/check',{method:'POST',headers:noCsrf,body:'{}'})).status,401);checks++;
server.close();console.log({checks,passed:true,signing:'scripted actual Ed25519',extensionConfirmation:false,physicalDevice:false});
