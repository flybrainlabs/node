// One bounded upstream lane is shared by the public gateway and verifier.
// Task progression has no minimum interval; this limits RPC resource pressure.
export function factoryRpcTransportV4(endpoint,{transport=globalThis.fetch,gapMs=400,maxQueued=16,timeoutMs=15000}={}){
  if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>120000)throw new RangeError('Finite RPC timeout required');
  const cache=new Map(),pending=new Map();let tail=Promise.resolve(),queued=0,nextAt=0,cooldown=0;
  const reply=(text,status=200)=>new Response(text,{status,headers:{'Content-Type':'application/json'}});
  return async(url,options={})=>{
    const {factoryFresh=false,...requestOptions}=options;
    if(String(url)!==endpoint)return transport(url,requestOptions);
    const request=JSON.parse(options.body),method=request.method,identity=method==='getGenesisHash',key=method+':'+JSON.stringify(request.params||[]);
    const ttl=identity?60000:method==='getMinimumBalanceForRentExemption'?60000:!factoryFresh&&['getAccountInfo','getBalance','getSlot','getBlockHeight','getBlockTime'].includes(method)?1000:0;
    const cached=cache.get(key),pack=value=>reply(JSON.stringify({...value,id:request.id}));
    if(ttl&&cached?.until>Date.now())return pack(cached.value);
    if(ttl&&pending.has(key))return pack(await pending.get(key));
    if(queued>=maxQueued||Date.now()<cooldown)return reply(JSON.stringify({code:'RPC_BUSY'}),503);
    queued++;
    const operation=tail.catch(()=>{}).then(async()=>{
      const wait=Math.max(0,nextAt-Date.now());if(wait)await new Promise(ok=>setTimeout(ok,wait));nextAt=Date.now()+gapMs;
      if(Date.now()<cooldown)return {status:503,text:JSON.stringify({code:'RPC_BUSY'})};
      if(method==='sendTransaction')cache.clear();
      const deadline=AbortSignal.timeout(timeoutMs),signal=requestOptions.signal?AbortSignal.any([requestOptions.signal,deadline]):deadline;
      const response=await transport(url,{...requestOptions,signal});
      if(response.status===429){const seconds=Number(response.headers.get('retry-after'));cooldown=Date.now()+Math.min(30000,Math.max(3000,Number.isFinite(seconds)?seconds*1000:3000));return {status:429,text:JSON.stringify({code:'RPC_RATE_LIMITED'})};}
      if(!response.ok)return {status:503,text:JSON.stringify({code:'RPC_UNAVAILABLE'})};
      const reader=response.body.getReader(),chunks=[];let length=0;
      for(;;){const {value,done}=await reader.read();if(done)break;length+=value.length;if(length>200000){await reader.cancel();return {status:503,text:JSON.stringify({code:'RPC_RESPONSE_LIMIT'})};}chunks.push(value);}
      const bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
      const value=JSON.parse(new TextDecoder().decode(bytes));
      if(value.jsonrpc!=='2.0'||value.id!==request.id)return {status:503,text:JSON.stringify({code:'RPC_INVALID_RESPONSE'})};
      if(identity&&value.result!=='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG')throw new Error('Wrong verifier chain identity');
      if(ttl&&!value.error&&value.result!==null){if(cache.size>=64)cache.delete(cache.keys().next().value);cache.set(key,{value,until:Date.now()+ttl});}
      if(method==='sendTransaction')cache.clear();return {status:200,value};
    }).catch(error=>{if(['TimeoutError','AbortError'].includes(error.name))return {status:503,text:JSON.stringify({code:'RPC_TIMEOUT'})};throw error;}).finally(()=>{queued--;});tail=operation;
    if(ttl){const valuePromise=operation.then(r=>{if(r.status!==200)throw Object.assign(new Error('RPC temporarily unavailable'),{status:r.status});return r.value;});pending.set(key,valuePromise);valuePromise.finally(()=>{if(pending.get(key)===valuePromise)pending.delete(key);}).catch(()=>{});}
    const result=await operation;return result.status===200?pack(result.value):reply(result.text,result.status);
  };
}
