// Explicit Devnet acceptance only. The private signer stays outside Chromium;
// stdio carries public signatures and signed bytes to the controlling test.
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {dirname} from 'node:path';
import {createInterface} from 'node:readline';
import {createPrivateKey,sign} from 'node:crypto';
import {Connection,Keypair,PublicKey,Transaction,SystemProgram} from '@solana/web3.js';
import {readerForDeployment} from '../web/task-factory-client-v4.mjs';

const [configPath,keyPath,journalPath,apply]=process.argv.slice(2);
if(apply!=='--apply')throw new Error('Explicit finite Devnet acceptance authorization required');
const config=JSON.parse(await readFile(configPath,'utf8'));
if(config.cluster!=='devnet'||config.genesisHash!=='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'||config.taskCount!==8||config.rewardAtoms!=='20000000000'||config.budgetAtoms!=='160000000000')throw new Error('Unexpected acceptance scope');
const miner=Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(keyPath,'utf8'))));
const connection=new Connection(config.rpcUrl,{commitment:'finalized',disableRetryOnRateLimit:true,fetch:(url,options)=>fetch(url,{...options,headers:{...options.headers,Origin:'https://flybrain.work'}})});
const reader=readerForDeployment(config,connection),factory=await reader.factory();
if(factory.count!==8||factory.budget!==160000000000n)throw new Error('Unexpected frozen factory');
const address=miner.publicKey.toBase58(),privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(miner.secretKey.slice(0,32))]),format:'der',type:'pkcs8'});
let journal;try{journal=JSON.parse(await readFile(journalPath,'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;journal={factory:config.factory,wallet:address,messages:[],transactions:[]};}
if(journal.factory!==config.factory||journal.wallet!==address)throw new Error('Acceptance journal identity changed');
const save=async()=>{await mkdir(dirname(journalPath),{recursive:true,mode:0o700});await writeFile(journalPath,JSON.stringify(journal),{mode:0o600});};
const respond=value=>process.stdout.write(JSON.stringify(value)+'\n');
respond({ready:true,address,publicKey:[...miner.publicKey.toBytes()],balanceLamports:await connection.getBalance(miner.publicKey,'finalized')});
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
  try{
    const request=JSON.parse(line),bytes=Buffer.from(request.bytes,'base64');let signed;
    if(request.kind==='message'){
      const message=bytes.toString('utf8');
      if(journal.messages.length>=4||!message.startsWith('flybrain.work wants you to sign in with your Solana account:\n'+address+'\n\nSign in to flybrainlabs on Solana Devnet. This does not authorize transfers.\n\nURI: https://flybrain.work/\nVersion: 1\nChain ID: solana:devnet\n')||!message.endsWith('- urn:solana:genesis:'+config.genesisHash+'\n- urn:flybrainlabs:program:'+config.programId))throw new Error('Sign-in scope rejected');
      const issued=message.match(/\nIssued At: (.+)\n/),expiry=message.match(/\nExpiration Time: (.+)\n/);
      if(!issued||!expiry||Math.abs(Date.now()-Date.parse(issued[1]))>300000||Date.parse(expiry[1])<Date.now()||Date.parse(expiry[1])-Date.parse(issued[1])!==300000)throw new Error('Sign-in freshness rejected');
      signed=sign(null,bytes,privateKey);journal.messages.push({at:new Date().toISOString(),signature:signed.toString('base64')});
    }else if(request.kind==='transaction'){
      const tx=Transaction.from(bytes),ix=tx.instructions[0],data=ix?.data;
      if(journal.transactions.length>=8||tx.instructions.length!==1||tx.feePayer.toBase58()!==address||tx.signatures.length!==1||!ix.programId.equals(reader.program)||data.length<6||data[0]!==11||data.readUInt32LE(1)!==data.length-5||![4,5].includes(data[5])||ix.keys[0].pubkey.toBase58()!==config.factory)throw new Error('Transaction scope rejected');
      const taskIndex=[0,1].find(i=>reader.a.task(config.factory,i).equals(ix.keys[1].pubkey));
      if(taskIndex===undefined)throw new Error('Only the first two acceptance tasks may be signed');
      const task=await reader.task(taskIndex);if(task.attempt!==0||task.state!==1)throw new Error('Acceptance task is not open');
      if(data[5]===4){
        if(data.length!==70||ix.keys.length!==6||!new PublicKey(data.subarray(38)).equals(miner.publicKey)||!ix.keys[3].pubkey.equals(miner.publicKey)||!ix.keys[4].pubkey.equals(miner.publicKey)||!ix.keys[5].pubkey.equals(SystemProgram.programId)||!reader.a.submission(ix.keys[1].pubkey,0,miner.publicKey,data.subarray(6,38)).equals(ix.keys[2].pubkey))throw new Error('Commitment accounts rejected');
      }else if(data.length!==166||ix.keys.length!==4||!ix.keys[3].pubkey.equals(miner.publicKey)||!journal.transactions.some(v=>v.tag===4&&v.submission===ix.keys[2].pubkey.toBase58()))throw new Error('Reveal accounts rejected');
      const fee=(await connection.getFeeForMessage(tx.compileMessage(),'finalized')).value;if(fee===null||fee>10000)throw new Error('Unexpected acceptance fee');
      tx.partialSign(miner);signed=tx.serialize();journal.transactions.push({taskIndex,tag:data[5],submission:ix.keys[2].pubkey.toBase58(),signedTransaction:signed.toString('base64'),feeLamports:fee});
    }else throw new Error('Unknown acceptance request');
    await save();respond({id:request.id,signed:signed.toString('base64')});
  }catch(error){respond({error:error.message});}
}
