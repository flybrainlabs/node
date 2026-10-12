// Operator-only archive certification. No transaction or project close is sent.
import {readFile,writeFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {createPrivateKey,sign} from 'node:crypto';
import {PublicKey} from '@solana/web3.js';
import {WalletMiningService} from './wallet_mining_v3.mjs';
import {signerFile,finalizedPayment,prepareSummary} from './mining_relayer_v3.mjs';
import {decodeGlobal} from './economy_v2_client.mjs';
import {decodeUnit,closureMessage,hex} from './mining_v3_client.mjs';
import {verified,api} from './target_dev_identity.mjs';
const [runtimePath,claim,output]=process.argv.slice(2);if(!output||! /^[a-f0-9]{64}$/.test(claim))throw new Error('Usage: certify_result_archive_v3.mjs PRIVATE_RUNTIME CLAIM PUBLIC_CERTIFICATE');
try{
 const config=JSON.parse(await readFile(runtimePath,'utf8')),relayer=await signerFile(config.relayerKeypair),s=await new WalletMiningService(config,new DatabaseSync(config.database),relayer).initialize(),row=s.db.prepare('SELECT * FROM mining_v3_candidates WHERE claim_id=?').get(claim);if(!row||row.state!=='paid-finalized')throw new Error('Finalized original payment required');
 const fact=await finalizedPayment(s,row,row.settlement_signature);if(!fact)throw new Error('Finalized evidence unavailable');
 const [round,science]=await Promise.all([verified(config.authorityId,'round-state',await(await api(config.apiBase,'rounds/'+row.round_id)).json()),verified(config.authorityId,'claim-state',await(await api(config.apiBase,'claims/'+claim)).json())]);await prepareSummary(s,row,round,science);
 const unit=new PublicKey(row.unit_address),u=decodeUnit((await s.connection.getAccountInfo(unit,'finalized')).data),g=decodeGlobal((await s.connection.getAccountInfo(s.a.global,'finalized')).data),message=closureMessage(s.program,g,unit,u),certificates=[];
 for(const path of config.settlerKeypairs.slice(0,2)){const key=await signerFile(path),privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),key.secretKey.subarray(0,32)]),format:'der',type:'pkcs8'});certificates.push({publicKey:key.publicKey.toBase58(),signature:sign(null,message,privateKey).toString('hex')});}
 const value={schema:'flybrainlabs-finalized-result-archive-certificates-v3',genesisHash:config.genesisHash,programId:config.programId,unit:unit.toBase58(),claim,resultHash:hex(u.resultHash),paidSlot:u.paidSlot.toString(),message:hex(message),certificates,finalizedPayment:fact,completeArchivesRechecked:true,independentOperators:1};await writeFile(output,JSON.stringify(value,null,2)+'\n',{mode:0o600});console.log(JSON.stringify({certified:true,claim,unit:unit.toBase58(),certificates:certificates.length}));
}catch{console.error('Archive certification refused; finalized chain, winner and full archives must agree');process.exitCode=1;}
