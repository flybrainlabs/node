// Exactly one immutable signed packet per operation. An expired unknown packet
// is blocked for reconciliation, never silently replaced with another debit.
import {Transaction} from '@solana/web3.js';
import {createHash} from 'node:crypto';
const fail=code=>Object.assign(new Error(code),{code});
const hash=ixs=>createHash('sha256').update(JSON.stringify(ixs.map(ix=>({program:ix.programId.toBase58(),keys:ix.keys.map(k=>[k.pubkey.toBase58(),k.isWritable,k.isSigner]),data:ix.data.toString('hex')})))).digest('hex');
const base58=bytes=>{let n=BigInt('0x'+Buffer.from(bytes).toString('hex')),s='';const a='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';while(n){s=a[Number(n%58n)]+s;n/=58n;}for(const x of bytes){if(x)break;s='1'+s;}return s;};
export class FactoryPoolTransportV4 {
  constructor({queue,connection,payer,maxTransactions=96,maxFeeLamports=1000000,beforeSend=()=>{}}){Object.assign(this,{queue,connection,payer,maxTransactions,maxFeeLamports,beforeSend});if(!Number.isInteger(maxTransactions)||maxTransactions<1||maxTransactions>4096||!Number.isSafeInteger(maxFeeLamports)||maxFeeLamports<1||maxFeeLamports>10000000)throw fail('POOL_SIGNER_ALLOWANCE');}
  async run(job,name,instructions,completed){
    this.beforeSend();await this.queue.guard(job);const id=job.id+':'+name,scope=hash(instructions);
    let {rows:[record]}=await this.queue.pool.query('SELECT * FROM factory_pool_v4.transactions WHERE id=$1',[id]);
    if(record&&(record.job_id!==job.id||record.instruction_hash!==scope))throw fail('POOL_TRANSACTION_SCOPE');
    if(await completed())return {alreadyComplete:true,...await this.reconcile(job,name)};
    if(record?.state==='failed')throw fail('POOL_TRANSACTION_FAILED');
    if(record?.state==='finalized')throw fail('POOL_FINALIZED_EFFECT_MISSING');
    if(!record){
      // Serialize fee authorization per payer across unrelated replay jobs.
      record=await this.queue.transaction(async c=>{
        await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['pool-signer:'+this.payer.publicKey.toBase58()]);
        await this.queue.guard(job,c,{lock:true});
        const {rows:[counts]}=await c.query(`SELECT count(*)::int AS n,COALESCE(sum(fee_lamports),0)::text AS fees FROM factory_pool_v4.transactions WHERE signature IN
          (SELECT signature FROM factory_pool_v4.transactions t JOIN factory_pool_v4.jobs j ON j.id=t.job_id WHERE j.payload->>'payer'=$1)`,[this.payer.publicKey.toBase58()]);
        if(counts.n>=this.maxTransactions||BigInt(counts.fees)+20000n>BigInt(this.maxFeeLamports))throw fail('POOL_SIGNER_ALLOWANCE');
        const latest=await this.connection.getLatestBlockhash('finalized'),tx=new Transaction({feePayer:this.payer.publicKey,recentBlockhash:latest.blockhash}).add(...instructions);this.beforeSend();tx.sign(this.payer);
        const raw=tx.serialize(),fee=(await this.connection.getFeeForMessage(tx.compileMessage(),'finalized')).value;
        if(raw.length>1232||!Number.isSafeInteger(fee)||fee<0||fee>20000)throw fail('POOL_PACKET_OR_FEE');
        await this.queue.guard(job,c);
        const r={instructionHash:scope,signature:base58(tx.signature),rawBase64:raw.toString('base64'),lastValidBlockHeight:latest.lastValidBlockHeight,feeLamports:fee};
        await c.query('INSERT INTO factory_pool_v4.transactions(id,job_id,instruction_hash,signature,raw_base64,last_valid_height,fee_lamports) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO NOTHING',[id,job.id,scope,r.signature,r.rawBase64,String(r.lastValidBlockHeight),fee]);
        const {rows:[saved]}=await c.query('SELECT * FROM factory_pool_v4.transactions WHERE id=$1',[id]);if(saved.job_id!==job.id||saved.instruction_hash!==scope)throw fail('POOL_TRANSACTION_SCOPE');return saved;
      });
    }
    const status=(await this.connection.getSignatureStatuses([record.signature],{searchTransactionHistory:true})).value[0];
    if(status?.confirmationStatus==='finalized'){
      const receipt={signature:record.signature,slot:status.slot,commitment:'finalized',err:status.err||null};
      await this.queue.receipt(job,id,status.err?'failed':'finalized',receipt);if(status.err)throw fail('POOL_TRANSACTION_FAILED');return receipt;
    }
    if(await this.connection.getBlockHeight('finalized')>Number(record.last_valid_height)){
      if(await completed())return {alreadyComplete:true,signature:record.signature};
      await this.queue.receipt(job,id,'unknown',{signature:record.signature});throw fail('POOL_TRANSACTION_UNKNOWN');
    }
    this.beforeSend();await this.queue.guard(job);this.beforeSend();
    try{const signature=await this.connection.sendRawTransaction(Buffer.from(record.raw_base64,'base64'),{maxRetries:0,skipPreflight:false,preflightCommitment:'finalized'});if(signature!==record.signature)throw fail('POOL_SIGNATURE_MISMATCH');}
    catch(error){if(error.code==='POOL_SIGNATURE_MISMATCH')throw error;}
    // A worker releases its lease and revisits the same operation/packet.
    throw fail('POOL_CONFIRMATION_PENDING');
  }
  async reconcile(job,name){
    const id=job.id+':'+name,{rows:[record]}=await this.queue.pool.query('SELECT * FROM factory_pool_v4.transactions WHERE id=$1',[id]);if(!record)return {signature:null};
    if(record.job_id!==job.id)throw fail('POOL_TRANSACTION_SCOPE');const status=(await this.connection.getSignatureStatuses([record.signature],{searchTransactionHistory:true})).value[0];
    if(status?.confirmationStatus==='finalized'){const receipt={signature:record.signature,slot:status.slot,commitment:'finalized',err:status.err||null};await this.queue.receipt(job,id,status.err?'failed':'finalized',receipt);return receipt;}
    return {signature:record.signature,confirmation:'unknown'};
  }
  async reconcileAll(job){const {rows}=await this.queue.pool.query('SELECT id FROM factory_pool_v4.transactions WHERE job_id=$1',[job.id]);for(const r of rows)await this.reconcile(job,r.id.slice(job.id.length+1));}
}
