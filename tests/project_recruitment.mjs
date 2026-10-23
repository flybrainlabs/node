// Isolated HTTP acceptance: synthetic signers and a temporary persistent database.
import assert from 'node:assert/strict';
import {createPrivateKey, sign, randomUUID} from 'node:crypto';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import {DatabaseSync} from 'node:sqlite';
import {Keypair} from '@solana/web3.js';
import {WalletMiningService} from '../tools/wallet_mining_v3.mjs';
import {SocialCommunityService} from '../tools/social_community.mjs';
import {serveSocial} from '../tools/social_server.mjs';
import {RECRUITMENT_CONSENT} from '../tools/project_recruitment.mjs';

const directory=await mkdtemp(join(tmpdir(),'fbw-project-recruitment-'));
const origin='https://recruitment.example.invalid',admin=Keypair.generate(),users=[Keypair.generate(),Keypair.generate()];
const config={...JSON.parse(await readFile('web/data/wallet-mining-v3.json','utf8')),project:admin.publicKey.toBase58(),origins:[origin],enabled:false};
const allocation=JSON.parse(await readFile('config/community-allocation-v1.json','utf8'));
let db,auth,service,server,base;
const clock=()=>1900000000;
async function start(){
  db=new DatabaseSync(join(directory,'auth.db'));
  auth=await new WalletMiningService(config,db,null,{clock}).initialize();
  service=await new SocialCommunityService(auth,allocation).initialize();
  server=serveSocial(service,{port:0});await once(server,'listening');base='http://127.0.0.1:'+server.address().port;
}
async function stop(){await new Promise(resolve=>server.close(resolve));db.close();}
function login(key){
  const address=key.publicKey.toBase58(),challenge=auth.challenge(origin,{address});
  const privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),key.secretKey.subarray(0,32)]),format:'der',type:'pkcs8'});
  return auth.login(origin,{address,nonce:challenge.input.nonce,signedMessage:challenge.message,signature:sign(null,Buffer.from(challenge.message),privateKey).toString('base64')});
}
async function api(path,{session=null,body=null,csrf=true,expected=200,csv=false,requestOrigin=origin}={}){
  const headers={Origin:requestOrigin};
  if(session)headers.Authorization='Bearer '+session.token;
  if(body!==null){headers['Content-Type']='application/json';if(session&&csrf)headers['X-Mining-CSRF']=session.csrfToken;}
  const response=await fetch(base+'/api/community/projects/'+path,{method:body===null?'GET':'POST',headers,body:body===null?undefined:JSON.stringify(body)});
  assert.equal(response.status,expected,await response.clone().text());
  assert.match(response.headers.get('cache-control'),/no-store/);
  return csv?response.text():response.json();
}
const application=(patch={})=>({roles:['compute','reproduce'],contact:{type:'other',value:'synthetic-contact'},nickname:'Synthetic applicant',device:{threads:null,memoryGiB:null,operatingSystem:'unknown'},availability:{hoursPerDay:null,continuous:'unknown',client:'unknown'},skills:'Reproduction',intendedUse:'Research',notes:'Synthetic notes only',consent:true,consentVersion:RECRUITMENT_CONSENT,...patch});
const submit=(projectId,patch={})=>({requestId:randomUUID(),projectId,application:application(),...patch});
const change=(revision,patch={})=>({requestId:randomUUID(),revision,...patch});
function parseCsv(text){
  const rows=[];let row=[],value='',quoted=false;
  for(let i=0;i<text.replace(/^\uFEFF/,'').length;i++){
    const source=text.replace(/^\uFEFF/,''),c=source[i];
    if(c==='"'){if(quoted&&source[i+1]==='"'){value+='"';i++;}else quoted=!quoted;}
    else if(c===','&&!quoted){row.push(value);value='';}
    else if(c==='\n'&&!quoted){row.push(value.replace(/\r$/,''));rows.push(row);row=[];value='';}
    else value+=c;
  }
  return rows;
}
try{
  await start();const a=login(users[0]),b=login(users[1]),operator=login(admin);
  const initial=await api('stats');assert.equal(initial.projects.length,9);assert.equal(initial.totalUniqueApplicants,0);
  assert.ok(!JSON.stringify(initial).includes('contact'));
  await api('me',{expected:401});await api('applications/submit',{body:submit('FBW-P01'),expected:401});
  await api('applications/submit',{session:a,body:submit('FBW-P01'),csrf:false,expected:401});
  await api('me',{session:a,requestOrigin:'https://untrusted.example.invalid',expected:403});
  const body=submit('FBW-P01',{primaryPreference:true});
  const first=await api('applications/submit',{session:a,body});const id=first.application.id;
  assert.match(id,/^[a-f0-9]{32}$/);assert.equal(first.receivedAt,clock());
  const repeated=await Promise.all([api('applications/submit',{session:a,body}),api('applications/submit',{session:a,body})]);
  assert.ok(repeated.every(x=>x.application.id===id));
  await api('applications/submit',{session:a,body:{...body,application:application({notes:'Different payload'})},expected:409});
  await api('applications/submit',{session:a,body:submit('FBW-P01'),expected:409});
  const second=await api('applications/submit',{session:a,body:submit('FBW-P02',{primaryPreference:true})});
  const other=await api('applications/submit',{session:b,body:submit('FBW-P01')});
  let stats=await api('stats');assert.equal(stats.totalUniqueApplicants,2);assert.equal(stats.projects[0].applicationAccounts,2);assert.equal(stats.projects[1].applicationAccounts,1);
  assert.equal(stats.projects[0].primaryPreferenceAccounts,0);assert.equal(stats.projects[1].primaryPreferenceAccounts,1);
  await api('applications/'+id+'/update',{session:b,body:change(1,{application:application()}),expected:404});
  await api('applications/submit',{session:a,body:{...submit('FBW-P03'),wallet:users[1].publicKey.toBase58()},expected:400});
  await api('admin/applications',{session:a,expected:403});await api('admin/export',{session:a,expected:403});
  await api('admin/applications',{expected:401});
  const selected=await api('admin/applications/'+id+'/review',{session:operator,body:change(1,{status:'selected',internalNote:'Internal synthetic note',publicNote:'Selected for coordination'})});
  assert.equal(selected.application.status,'selected');
  const mine=await api('me',{session:a});assert.ok(!JSON.stringify(mine).includes('Internal synthetic note'));assert.equal(mine.applications.find(value=>value.id===id).publicNote,'Selected for coordination');
  await api('applications/'+id+'/update',{session:a,body:change(1,{application:application()}),expected:409});
  const updated=await api('applications/'+id+'/update',{session:a,body:change(2,{application:application({nickname:'=SUM(1,2)',notes:'Line one, "quoted"\n'+String.fromCodePoint(0x4e2d,0x6587)})})});
  assert.equal(updated.application.status,'submitted');assert.equal(updated.application.revision,3);
  const filtered=await api('admin/applications?projectId=FBW-P01&role=compute&status=submitted',{session:operator});assert.equal(filtered.total,2);
  const csv=await api('admin/export?projectId=FBW-P01&role=compute',{session:operator,csv:true});
  const csvRows=parseCsv(csv),columns=csvRows[0],exported=csvRows.slice(1).find(row=>row[columns.indexOf('id')]===id);
  assert.equal(exported[columns.indexOf('nickname')],"'=SUM(1,2)");assert.ok(exported[columns.indexOf('notes')].includes('\n'));assert.ok(csv.includes(String.fromCodePoint(0x4e2d,0x6587)));
  const withdrawn=await api('applications/'+id+'/withdraw',{session:a,body:change(3)});assert.equal(withdrawn.application.status,'withdrawn');
  const resubmitted=await api('applications/'+id+'/resubmit',{session:a,body:change(4,{application:application(),primaryPreference:true})});assert.equal(resubmitted.application.id,id);assert.equal(resubmitted.application.revision,5);
  const history=await api('admin/applications/'+id,{session:operator});assert.equal(history.events.length,5);assert.deepEqual(history.events.map(x=>x.action),['resubmit','withdraw','update','review','submit']);
  await api('admin/applications/'+other.application.id+'/review',{session:operator,body:change(1,{status:'rejected',internalNote:'Synthetic review'})});
  stats=await api('stats');assert.equal(stats.projects[0].applicationAccounts,1);assert.equal(stats.totalUniqueApplicants,1);
  await api('applications/'+other.application.id+'/resubmit',{session:b,body:change(2,{application:application()})});
  for(const bad of [submit('FBW-P99'),submit('FBW-P03',{application:application({roles:['unknown']})}),submit('FBW-P03',{application:application({device:{threads:-1}})}),submit('FBW-P03',{application:application({availability:{hoursPerDay:25}})}),submit('FBW-P03',{application:application({notes:'x'.repeat(2001)})}),submit('FBW-P03',{application:application({consent:false})}),submit('FBW-P03',{application:application({status:'selected'})})])await api('applications/submit',{session:a,body:bad,expected:400});
  service.projects.projects.get('FBW-P09').recruitmentStatus='closed';await api('applications/submit',{session:a,body:submit('FBW-P09'),expected:409});service.projects.projects.get('FBW-P09').recruitmentStatus='open';
  const interest={requestId:randomUUID(),projectId:'FBW-P01',interested:false};await api('interests',{session:a,body:interest});await api('interests',{session:a,body:interest});
  assert.equal((await api('stats')).projects[0].interestedAccounts,1);
  const rollback=submit('FBW-P04'),event=service.projects.event;service.projects.event=()=>{throw new Error('Synthetic transaction failure');};
  await api('applications/submit',{session:a,body:rollback,expected:503});service.projects.event=event;
  assert.equal(db.prepare("SELECT COUNT(*) n FROM project_applications WHERE project_id='FBW-P04'").get().n,0);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM project_interests WHERE project_id='FBW-P04'").get().n,0);
  await api('applications/submit',{session:a,body:rollback});
  const raceHeaders={Origin:origin,Authorization:'Bearer '+b.token,'X-Mining-CSRF':b.csrfToken,'Content-Type':'application/json'};
  const competing=await Promise.all([1,2].map(()=>fetch(base+'/api/community/projects/applications/submit',{method:'POST',headers:raceHeaders,body:JSON.stringify(submit('FBW-P05'))})));
  assert.deepEqual(competing.map(response=>response.status).sort(),[200,409]);await Promise.all(competing.map(response=>response.json()));
  const beforeRestart=(await api('me',{session:a})).applications;
  assert.equal(db.prepare('SELECT COUNT(*) n FROM community_points_ledger').get().n,0);
  await stop();await start();
  assert.deepEqual((await api('me',{session:a})).applications,beforeRestart);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM social_schema_migrations WHERE version=4').get().n,1);
  assert.equal((await api('admin/applications/'+id,{session:operator})).events.length,5);
  const summary=await api('admin/summary',{session:operator});assert.equal(summary.totalApplicationRecords,5);assert.equal(summary.totalUniqueApplicants,2);
  assert.equal((await api('me',{session:a})).primaryProjectId,'FBW-P01');assert.ok(second.application.id!==id);
  console.log('Project recruitment HTTP, real sign-in/CSRF, private ownership, idempotency, conflicts, lifecycle, CSV, rollback, migration restart and aggregate checks passed.');
}finally{if(server?.listening)await stop();await rm(directory,{recursive:true,force:true});}
