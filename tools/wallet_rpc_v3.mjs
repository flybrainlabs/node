// Authenticated, bounded Solana transport. Provider credentials are runtime
// inputs; browser requests never select an upstream URL or signing identity.
import {createHash} from 'node:crypto';
import {PublicKey, Transaction} from '@solana/web3.js';

const DEVNET_GENESIS = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
const PUBLIC_RPC = 'https://api.devnet.solana.com';
const fail = (code, status = 400) => Object.assign(new Error(code), {code, status});
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

export function walletRpcConfiguration(config) {
  if (config.cluster === 'localnet') {
    if (!/^http:\/\/(127\.0\.0\.1|localhost):[0-9]+$/.test(config.rpc) || config.rpcUpstream) throw fail('WRONG_CHAIN');
    return {publicEndpoint: config.rpc, upstream: config.rpc};
  }
  if (config.cluster !== 'devnet' || config.genesisHash !== DEVNET_GENESIS) throw fail('WRONG_CHAIN');
  if (config.rpc === PUBLIC_RPC && !config.rpcUpstream) return {publicEndpoint: config.rpc, upstream: config.rpc};
  let gateway, upstream;
  try { gateway = new URL(config.apiBase); upstream = new URL(config.rpcUpstream); } catch { throw fail('INVALID_RPC_CONFIGURATION'); }
  if (gateway.protocol !== 'https:' || gateway.origin !== config.apiBase || gateway.username || gateway.password || gateway.search || gateway.hash ||
      config.rpc !== gateway.origin + '/api/mining/v3/rpc' || upstream.protocol !== 'https:' || upstream.username || upstream.password || upstream.hash) {
    throw fail('INVALID_RPC_CONFIGURATION');
  }
  return {publicEndpoint: config.rpc, upstream: config.rpcUpstream};
}

function publicKey(value) {
  try { if (typeof value !== 'string' || new PublicKey(value).toBase58() !== value) throw new Error(); }
  catch { throw fail('RPC_PARAMETERS_REJECTED'); }
}
function base58(bytes) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n, text = '';
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  while (n) { text = alphabet[Number(n % 58n)] + text; n /= 58n; }
  for (const b of bytes) { if (b) break; text = '1' + text; }
  return text;
}
function finalized(options = {}, extra = []) {
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      options.commitment !== 'finalized' || Object.keys(options).some(k => !['commitment', ...extra].includes(k))) throw fail('RPC_PARAMETERS_REJECTED');
}

export class WalletRpcProxy {
  constructor(service, {fetchImpl = globalThis.fetch, clock = () => Date.now()} = {}) {
    this.service = service;
    this.endpoint = walletRpcConfiguration(service.config).upstream;
    this.fetch = fetchImpl;
    this.clock = clock;
    this.active = 0;
    this.rates = new Map();
    this.chainUntil = 0;
    this.chainCheck = null;
    this.globalRate = {count: 0, until: 0};
  }
  admission(wallet) {
    const now = this.clock();
    if (this.globalRate.until <= now) this.globalRate = {count: 0, until: now + 60_000};
    for (const [key, state] of this.rates) if (state.until <= now) this.rates.delete(key);
    if (this.active >= 4 || !this.rates.has(wallet) && this.rates.size >= 512) throw fail('RPC_BUSY', 503);
    const rate = this.rates.get(wallet) || {count: 0, until: now + 60_000};
    if (rate.count >= 80 || this.globalRate.count >= 240) throw fail('RPC_RATE_LIMITED', 429);
    rate.count++;
    this.globalRate.count++;
    this.rates.set(wallet, rate);
  }
  async forward(request) {
    let response;
    try {
      response = await this.fetch(this.endpoint, {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(request), signal: AbortSignal.timeout(12_000), redirect: 'error'});
    } catch { throw fail('RPC_UNAVAILABLE', 503); }
    if (response.status === 429) throw fail('RPC_RATE_LIMITED', 429);
    if (!response.ok) throw fail('RPC_UNAVAILABLE', 503);
    const chunks = []; let length = 0, value;
    try {
      for await (const chunk of response.body) {
        length += chunk.length;
        if (length > 262_144) { throw new Error(); }
        chunks.push(Buffer.from(chunk));
      }
      value = JSON.parse(Buffer.concat(chunks).toString());
    } catch { throw fail('RPC_INVALID_RESPONSE', 503); }
    if (value?.jsonrpc !== '2.0' || value.id !== request.id || (!Object.hasOwn(value, 'result') && !Object.hasOwn(value, 'error'))) throw fail('RPC_INVALID_RESPONSE', 503);
    // Provider errors can echo a credential-bearing URL. Never forward their
    // message, data or headers to a browser or to an application log.
    if (Object.hasOwn(value, 'error')) throw fail('RPC_UPSTREAM_REJECTED', 503);
    return {jsonrpc: '2.0', id: request.id, result: value.result};
  }
  async chain() {
    if (this.clock() < this.chainUntil) return;
    if (!this.chainCheck) this.chainCheck = this.forward({jsonrpc: '2.0', id: 'chain', method: 'getGenesisHash', params: []}).then(value => {
      if (value.result !== this.service.config.genesisHash) throw fail('WRONG_CHAIN', 503);
      this.chainUntil = this.clock() + 30_000;
    }).finally(() => { this.chainCheck = null; });
    return this.chainCheck;
  }
  parameters(body, session) {
    if (!body || Array.isArray(body) || body.jsonrpc !== '2.0' ||
        !(typeof body.id === 'string' && body.id.length <= 80 || Number.isSafeInteger(body.id)) ||
        !Array.isArray(body.params) || body.params.length > 2 ||
        Object.keys(body).some(k => !['jsonrpc', 'id', 'method', 'params'].includes(k))) throw fail('RPC_REQUEST_REJECTED');
    const params = body.params;
    switch (body.method) {
      case 'getGenesisHash': if (params.length) throw fail('RPC_PARAMETERS_REJECTED'); break;
      case 'getMinimumBalanceForRentExemption':
        if (params.length !== 2 || params[0] !== 1024) throw fail('RPC_PARAMETERS_REJECTED');
        finalized(params[1]); break;
      case 'getAccountInfo':
        if (params.length !== 2) throw fail('RPC_PARAMETERS_REJECTED');
        publicKey(params[0]); finalized(params[1], ['encoding']);
        if (params[1].encoding !== 'base64') throw fail('RPC_PARAMETERS_REJECTED'); break;
      case 'getBlockHeight':
        if (params.length !== 1) throw fail('RPC_PARAMETERS_REJECTED');
        finalized(params[0]); break;
      case 'getSignatureStatuses':
        if (params.length !== 2 || !Array.isArray(params[0]) || !params[0].length || params[0].length > 4 ||
            params[0].some(s => typeof s !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(s)) ||
            !params[1] || params[1].searchTransactionHistory !== true || Object.keys(params[1]).length !== 1) throw fail('RPC_PARAMETERS_REJECTED'); break;
      case 'sendTransaction': return this.reviewedTransaction(body, session);
      default: throw fail('RPC_METHOD_REJECTED');
    }
    return body;
  }
  reviewedTransaction(body, session) {
    const [encoded, options] = body.params;
    if (body.params.length !== 2 || typeof encoded !== 'string' || encoded.length > 1644 ||
        !options || options.encoding !== 'base64' || options.maxRetries !== 0 || options.preflightCommitment !== 'finalized' ||
        options.skipPreflight && options.skipPreflight !== false || Object.keys(options).some(k => !['encoding', 'maxRetries', 'preflightCommitment', 'skipPreflight'].includes(k))) throw fail('RPC_TRANSACTION_REJECTED');
    let tx, bytes;
    try {
      bytes = Buffer.from(encoded, 'base64');
      if (bytes.length > 1232 || bytes.toString('base64') !== encoded) throw new Error();
      tx = Transaction.from(bytes);
      if (tx.feePayer.toBase58() !== session.wallet || tx.instructions.length !== 1 ||
          tx.instructions[0].programId.toBase58() !== this.service.config.programId || !tx.verifySignatures()) throw new Error();
    } catch { throw fail('RPC_TRANSACTION_REJECTED'); }
    const signature = base58(tx.signature);
    const row = this.service.db.prepare('SELECT id, signature FROM mining_v3_grant_requests WHERE wallet=? AND message_hash=?').get(session.wallet, digest(tx.serializeMessage()));
    if (!row || row.signature && row.signature !== signature) throw fail('RPC_TRANSACTION_SCOPE');
    // Record the original signature before a possibly ambiguous send outcome.
    this.service.db.prepare('UPDATE mining_v3_grant_requests SET signature=? WHERE id=?').run(signature, row.id);
    return {jsonrpc: '2.0', id: body.id, method: body.method, params: [encoded, {encoding: 'base64', maxRetries: 0, preflightCommitment: 'finalized', skipPreflight: false}]};
  }
  async request(body, session) {
    this.admission(session.wallet);
    this.active++;
    try {
      await this.chain();
      const request = this.parameters(body, session);
      const response = await this.forward(request);
      if (body.method === 'getGenesisHash' && response.result !== this.service.config.genesisHash) throw fail('WRONG_CHAIN', 503);
      if (body.method === 'sendTransaction' && response.result !== base58(Transaction.from(Buffer.from(request.params[0], 'base64')).signature)) throw fail('RPC_INVALID_RESPONSE', 503);
      return response;
    } finally { this.active--; }
  }
}
