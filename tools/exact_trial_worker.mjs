// One resident complete model, one active request, a finite waiting queue.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
export class ExactTrialWorker {
  constructor({binary,graph,model,maxQueued=12,timeoutMs=300000}){
    if(!Number.isInteger(maxQueued)||maxQueued<1||maxQueued>36||!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>900000)throw new Error('Native worker bounds');
    Object.assign(this,{binary,graph,model,maxQueued,timeoutMs});this.sequence=0;this.queue=[];this.active=null;this.closed=false;
  }
  start(){
    if(this.child)return;
    const child=spawn(this.binary,['--serve',this.graph,this.model],{stdio:['pipe','pipe','pipe']});this.child=child;
    child.stderr.on('data',()=>{}); // Runtime paths and diagnostics remain private.
    const lines=createInterface({input:child.stdout});
    lines.on('line',line=>{if(line.length>1024*1024)return this.fail(new Error('Native response limit'));let v;try{v=JSON.parse(line);}catch{return this.fail(new Error('Native response format'));}const item=this.active;if(!item||v.id!==item.id)return this.fail(new Error('Native response identity'));clearTimeout(item.timer);this.active=null;v.error?item.reject(new Error('Native execution failed: '+v.error)):item.resolve(v);this.pump();});
    child.on('error',()=>this.fail(new Error('Native worker unavailable')));
    child.on('exit',()=>this.fail(new Error('Native worker stopped')));
  }
  fail(error){const child=this.child;this.child=null;if(child){child.removeAllListeners('exit');child.kill();}if(this.active){clearTimeout(this.active.timer);this.active.reject(error);this.active=null;}for(const item of this.queue.splice(0))item.reject(error);}
  run(request){
    if(this.closed||this.queue.length+(this.active?1:0)>=this.maxQueued)return Promise.reject(new Error('Native verification capacity'));
    return new Promise((resolve,reject)=>{this.queue.push({request,id:'exact-'+(++this.sequence),resolve,reject});this.pump();});
  }
  pump(){if(this.closed||this.active||!this.queue.length)return;this.start();const item=this.queue.shift();this.active=item;item.timer=setTimeout(()=>this.fail(new Error('Native execution timeout')),this.timeoutMs);const bytes=JSON.stringify({...item.request,id:item.id});if(bytes.length>1024*1024){this.fail(new Error('Native request limit'));return;}this.child.stdin.write(bytes+'\n',error=>{if(error)this.fail(new Error('Native request transport'));});}
  close(){this.closed=true;this.fail(new Error('Native worker closed'));}
}
