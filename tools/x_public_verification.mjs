// @ts-check
// Read official public oEmbed evidence without executing or rendering its HTML.
import {createHash} from 'node:crypto';
import {parseFragment} from 'parse5';
const hosts=new Set(['x.com','twitter.com']);
const hash=s=>createHash('sha256').update(s).digest('hex');
const failure=(code,status=400)=>Object.assign(new Error(code),{code,status});
export class XPublicVerificationProvider {
  constructor({fetcher=globalThis.fetch,timeoutMs=8000,maxBytes=131072}={}){this.fetcher=fetcher;this.timeoutMs=timeoutMs;this.maxBytes=maxBytes;}
  parsePostUrl(value){
    if(typeof value!=='string'||value.length>512)throw failure('invalid_url');let url;try{url=new URL(value);}catch{throw failure('invalid_url');}
    const match=/^\/([A-Za-z0-9_]{1,15})\/status\/([1-9][0-9]{5,24})\/?$/.exec(url.pathname);
    if(url.protocol!=='https:'||!hosts.has(url.hostname)||url.port||url.username||url.password||!match)throw failure('invalid_url');
    return {username:match[1].toLowerCase(),postId:match[2],url:'https://x.com/'+match[1].toLowerCase()+'/status/'+match[2]};
  }
  normalizePostUrl(value){return this.parsePostUrl(value).url;}
  async fetchOEmbed(post){
    const endpoint=new URL('https://publish.x.com/oembed');endpoint.search=new URLSearchParams({url:post.url,omit_script:'true',hide_thread:'true'}).toString();
    let response;try{response=await this.fetcher(endpoint,{redirect:'error',headers:{Accept:'application/json'},signal:AbortSignal.timeout(this.timeoutMs)});}catch{throw failure('provider_unavailable',503);}
    if(!response.ok)throw failure(response.status===404?'post_unavailable':'provider_unavailable',response.status===404?422:503);
    if(Number(response.headers.get('content-length'))>this.maxBytes)throw failure('needs_review',422);
    const reader=response.body?.getReader();if(!reader)throw failure('needs_review',422);const chunks=[];let size=0;
    try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>this.maxBytes){await reader.cancel();throw failure('needs_review',422);}chunks.push(value);}}catch(error){if(error.code)throw error;throw failure('provider_unavailable',503);}
    try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw failure('needs_review',422);}
  }
  validateOEmbedResponse(value){if(!value||value.type!=='rich'||String(value.version)!=='1.0'||!['Twitter','X'].includes(value.provider_name)||typeof value.html!=='string'||Buffer.byteLength(value.html)>this.maxBytes)throw failure('needs_review',422);return value;}
  extractAuthor(value){
    let url;try{url=new URL(value.author_url);}catch{throw failure('author_unverifiable',422);}
    const match=/^\/([A-Za-z0-9_]{1,15})\/?$/.exec(url.pathname);
    if(url.protocol!=='https:'||!hosts.has(url.hostname)||url.port||url.username||url.password||url.search||url.hash||!match||typeof value.author_name!=='string'||value.author_name.length>200)throw failure('author_unverifiable',422);
    return {username:match[1],usernameNormalized:match[1].toLowerCase(),displayName:value.author_name,xUserId:null};
  }
  extractOriginalPostText(value,post,author){
    const fragment=parseFragment(value.html),quotes=[];let nodes=0;
    const visit=(node,depth=0)=>{if(++nodes>2000||depth>32)throw failure('needs_review',422);if(node.tagName==='blockquote')quotes.push(node);for(const child of node.childNodes||[])visit(child,depth+1);};visit(fragment);
    const quote=quotes[0],attr=(node,name)=>node?.attrs?.find(a=>a.name===name)?.value;
    if(quotes.length!==1||!attr(quote,'class')?.split(/\s+/).includes('twitter-tweet'))throw failure('needs_review',422);
    const paragraphs=quote.childNodes.filter(n=>n.tagName==='p');if(paragraphs.length!==1)throw failure('needs_review',422);
    const links=quote.childNodes.filter(n=>n.tagName==='a').map(n=>attr(n,'href')).filter(Boolean);
    const matching=links.map(url=>{try{return this.parsePostUrl(url);}catch{return null;}}).filter(p=>p?.postId===post.postId&&p.username===author.usernameNormalized);
    if(matching.length!==1)throw failure('author_unverifiable',422);
    const text=node=>{
      if(node.nodeName==='#text')return node.value;
      if(node.tagName==='a')return ''; // A nonce in a link is not original body proof.
      if(!['p','br','em','strong'].includes(node.tagName)||node.attrs?.some(a=>!['lang','dir'].includes(a.name)))throw failure('needs_review',422);
      if(node.tagName==='br')return '\n';return (node.childNodes||[]).map(text).join('');
    };
    return text(paragraphs[0]);
  }
  verifyChallenge(text,code){const escaped=code.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');return new RegExp('(?<![A-Za-z0-9_-])'+escaped+'(?![A-Za-z0-9_-])').test(text);}
  determineVerificationResult(value,post,code){
    this.validateOEmbedResponse(value);const author=this.extractAuthor(value),text=this.extractOriginalPostText(value,post,author);
    if(!this.verifyChallenge(text,code))throw failure('challenge_mismatch',422);
    return {...author,postId:post.postId,postUrl:'https://x.com/'+author.usernameNormalized+'/status/'+post.postId,verificationLevel:'challenge_verified',verificationMethod:'public_oembed',bodyHash:hash(text),evidenceHash:hash(JSON.stringify(value))};
  }
  async verify(url,code){const post=this.parsePostUrl(url),value=await this.fetchOEmbed(post);return this.determineVerificationResult(value,post,code);}
}
