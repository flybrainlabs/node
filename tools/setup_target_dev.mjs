#!/usr/bin/env node
// Creates a finite local plan and public pinned preview configuration.
import { readFile,writeFile,mkdir } from 'node:fs/promises';
import { resolve,join } from 'node:path';
import { keyFile } from './target_dev_identity.mjs';
import { spawn } from 'node:child_process';
const [directory='/workspace/.flypow-tools/goal-v2-network',port='8084',authorityPort='8787',profile='brief']=process.argv.slice(2),root=resolve(new URL('..',import.meta.url).pathname),dir=resolve(directory);
if(!['brief','live-current-v3'].includes(profile))throw new Error('Unknown calibrated development plan');
await mkdir(dir,{recursive:true,mode:0o700});const privateDir=join(dir,'private');await mkdir(privateDir,{recursive:true,mode:0o700});const authority=await keyFile(join(privateDir,'authority-v2.key')),admin=await keyFile(join(privateDir,'admin.key'));
const verifiers=await Promise.all([0,1,2].map(i=>keyFile(join(privateDir,'verifier-'+i+'.key'))));
const config={schema:'flypow-target-authority-config-v2',networkId:'flypow-selective-local-v2',campaignId:'brief-selective-finite-plan-v2',goalPaths:[join(root,'web/data/target-mining-v2/brief/goal.json')],verifierKeys:verifiers.map(k=>k.publicKey),adminKeys:[admin.publicKey],allowedOrigins:['http://127.0.0.1:'+port,'http://localhost:'+port],tauSeconds:300,searchSeconds:1800,revealSeconds:600,verificationSeconds:1800,maxQueue:16,perIdentityClaims:2,maxPrivateBytes:4*1024*1024*1024};
if(profile==='live-current-v3')Object.assign(config,{networkId:'flypow-live-current-v3-local-20261011',campaignId:'downstream-two-goal-calibrated-plan-20261011',goalPaths:[1,2].map(j=>join(root,`web/data/target-mining-v2/live-group-${j}-20261011/goal.json`)),familyPaths:[join(root,'web/data/target-mining-v2/comparable-family-20261011.json')]});
await writeFile(join(dir,'authority-config.json'),JSON.stringify(config,null,2)+'\n');
const network={schema:'flypow-target-network-v2',enabled:true,developmentOnly:true,networkId:config.networkId,authorityId:authority.publicKey,apiBase:'',payment:false,rewards:false,requiredWallet:false};await writeFile(join(dir,'network-public.json'),JSON.stringify(network,null,2)+'\n');
const runtime={apiBase:'http://127.0.0.1:'+authorityPort,authorityId:authority.publicKey,modelDir:join(root,'data/prepared/registry-male-cns-v1.0'),outputDir:join(dir,'private/replays'),binary:join(root,'target/release/target_trial')};await writeFile(join(dir,'verifier-runtime.json'),JSON.stringify(runtime,null,2)+'\n');
console.log(JSON.stringify({directory:dir,authorityId:authority.publicKey,config:join(dir,'authority-config.json'),publicNetwork:join(dir,'network-public.json'),localKeysOnly:true,noPayment:true}));
