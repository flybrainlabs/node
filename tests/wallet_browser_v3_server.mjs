// Browser fixtures never broadcast to an actual RPC or authorize real funds.
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {Keypair,PublicKey,Transaction} from '@solana/web3.js';
import {randomBytes} from 'node:crypto';
import {addresses,meta,system,instruction} from '../tools/mining_v3_client.mjs';
const [minerA,minerB,project,relayer,program,mint,stage]=Array.from({length:7},()=>Keypair.generate()),a=addresses(program.publicKey),grants=new Map();let activeWallet=minerA.publicKey.toBase58();
const cfg={schema:'flybrainlabs-wallet-mining-config-v3',cluster:'devnet',rpc:'https://api.devnet.solana.com',genesisHash:'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',programId:program.publicKey.toBase58(),mint:mint.publicKey.toBase58(),stage:stage.publicKey.toBase58(),project:project.publicKey.toBase58(),relayer:relayer.publicKey.toBase58(),policyHash:'a'.repeat(64),enabled:true,testOnly:true,apiBase:''};
const server=createServer(async(req,res)=>{try{const path=new URL(req.url,'http://localhost').pathname;
 if(path==='/'){res.setHeader('Content-Type','text/html');res.end('<!doctype html><html><body><h1>Isolated wallet interface acceptance</h1></body></html>');return;}
 if(path==='/bundle.mjs'){res.setHeader('Content-Type','text/javascript');res.end(await readFile(new URL('../web/vendor/generated/wallet-session-v3.mjs',import.meta.url)));return;}
 if(path==='/public'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({cfg,wallets:[minerA,minerB].map((k,n)=>({name:'Fixture '+n,address:k.publicKey.toBase58(),publicKey:Array.from(k.publicKey.toBytes())}))}));return;}
 const chunks=[];for await(const b of req)chunks.push(b);const body=chunks.length?JSON.parse(Buffer.concat(chunks)):{};let value;
 if(path.endsWith('/challenge'))value={input:{nonce:'fixture-nonce'},message:'Isolated mock challenge'};
 else if(path.endsWith('/login')){activeWallet=body.address;value={wallet:activeWallet,token:'fixture-token',csrfToken:'fixture-csrf',expiresAt:Math.floor(Date.now()/1000)+1000};}
 else if(path.endsWith('/balances'))value={wallet:activeWallet,mint:cfg.mint,commitment:'finalized',solLamports:activeWallet===minerA.publicKey.toBase58()?'1000000':'2000000',tokenAtoms:'0',grants:grants.get(activeWallet)?[grants.get(activeWallet)]:[]};
 else if(path.endsWith('/history'))value={wallet:activeWallet,items:[],rounds:[],nextBefore:null};
 else if(path.endsWith('/grant/prepare')||path==='/unsafe'){
  const miner=new PublicKey(activeWallet),id=randomBytes(32),grant=a.grant(miner,id),values={id,generation:1n,session:new PublicKey(body.session),...Object.fromEntries(['deposit','maxSpend','maxResultRent','maxResults','expiresAt'].map(k=>[k,BigInt(body[k])]))},keys=[meta(a.global),meta(a.config),meta(a.generation(miner),true),meta(grant,true),meta(miner,true,true),meta(relayer.publicKey,true,true),system()];if(path==='/unsafe')keys[2]=meta(a.generation(project.publicKey),true);
  const tx=new Transaction({feePayer:miner,recentBlockhash:Keypair.generate().publicKey.toBase58()}).add(instruction(program.publicKey,keys,4,values));tx.partialSign(relayer);grants.set(activeWallet,{address:grant.toBase58(),generation:'1',session:body.session,available:body.deposit,spent:'0',successes:'0',maxResults:body.maxResults,maxSpend:body.maxSpend,maxResultRent:body.maxResultRent,expiresAt:body.expiresAt,revoked:false});
  value={requestId:'fixture-request',grant:grant.toBase58(),generation:'1',transaction:tx.serialize({requireAllSignatures:false}).toString('base64'),lastValidBlockHeight:1000,networkFeeLamports:'10000',auxiliaryRentPayer:cfg.relayer,resultRentRecipient:cfg.project,unusedPrincipalRecipient:activeWallet};
 }else if(path.endsWith('/grant/confirm'))value={grant:grants.get(activeWallet).address,commitment:'finalized'};else if(path.endsWith('/logout'))value={loggedIn:false,chainGrantRevoked:false};else throw new Error('Unknown fixture');
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));
 }catch{res.writeHead(400);res.end('{"code":"FIXTURE_REJECTED"}');}});
server.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({url:'http://127.0.0.1:'+server.address().port})));
