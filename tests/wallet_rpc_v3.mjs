// Actual HTTP/session checks with an isolated provider fixture. No chain writes.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {Keypair, Transaction, SystemProgram} from '@solana/web3.js';
import {WalletRpcProxy, walletRpcConfiguration} from '../tools/wallet_rpc_v3.mjs';
import {WalletMiningService, serve} from '../tools/wallet_mining_v3.mjs';

const genesis = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG', origin = 'https://flybrain.work';
const privateEndpoint = 'https://provider.invalid/?api-key=fixture-private-key';
const miner = Keypair.generate(), program = Keypair.generate(), relayer = Keypair.generate();
const config = {schema: 'flybrainlabs-wallet-mining-config-v3', cluster: 'devnet', genesisHash: genesis,
  apiBase: 'https://node.example', rpc: 'https://node.example/api/mining/v3/rpc', rpcUpstream: privateEndpoint,
  origins: [origin], programId: program.publicKey.toBase58(), enabled: false, relayer: relayer.publicKey.toBase58(),
  units: [{goalId: 'a'.repeat(64), economicTaskId: 'b'.repeat(64), rewardAtoms: '1'}, {goalId: 'c'.repeat(64), economicTaskId: 'd'.repeat(64), rewardAtoms: '1'}]};
let checks = 0, now = 0, calls = [];
assert.equal(walletRpcConfiguration(config).upstream, privateEndpoint); checks++;
for (const patch of [{genesisHash: 'mainnet'}, {cluster: 'mainnet-beta'}, {rpc: privateEndpoint}, {rpcUpstream: 'http://provider.invalid'},
  {rpcUpstream: 'https://user:password@provider.invalid'}, {rpcUpstream: 'https://provider.invalid/#key'}, {rpcUpstream: undefined}]) {
  assert.throws(() => walletRpcConfiguration({...config, ...patch})); checks++;
}
const service = await new WalletMiningService(config, new DatabaseSync(':memory:'), relayer, {connection: {}, clock: () => 1791892000}).initialize();
const session = {wallet: miner.publicKey.toBase58()};
let mode = 'ok';
const rpc = new WalletRpcProxy(service, {clock: () => now, fetchImpl: async (url, options) => {
  assert.equal(url, privateEndpoint); assert(!options.headers.Authorization && !options.headers.Origin); assert.equal(options.redirect, 'error');
  const body = JSON.parse(options.body); calls.push(body);
  if (mode === 'limited') return new Response('', {status: 429});
  if (mode === 'unavailable') throw new Error(privateEndpoint);
  if (mode === 'error') return new Response(JSON.stringify({jsonrpc: '2.0', id: body.id, error: {code: -32000, message: privateEndpoint, data: privateEndpoint}}));
  if (mode === 'oversize') return new Response('x'.repeat(262145));
  return new Response(JSON.stringify({jsonrpc: '2.0', id: body.id, result: body.method === 'getGenesisHash' ? mode === 'wrong-chain' ? 'wrong' : genesis : body.method === 'getAccountInfo' ? {context: {slot: 1}, value: null} : 1234}));
}});
const request = (method, params = []) => ({jsonrpc: '2.0', id: 1, method, params});
assert.equal((await rpc.request(request('getMinimumBalanceForRentExemption', [1024, {commitment: 'finalized'}]), session)).result, 1234); checks++;
assert.equal((await rpc.request(request('getAccountInfo', [miner.publicKey.toBase58(), {commitment: 'finalized', encoding: 'base64'}]), session)).result.value, null); checks++;
for (const body of [[request('getGenesisHash')], request('getProgramAccounts'), request('requestAirdrop'), request('getMinimumBalanceForRentExemption', [1234, {commitment: 'finalized'}]),
  request('getAccountInfo', [miner.publicKey.toBase58(), {commitment: 'processed', encoding: 'base64'}]), request('getAccountInfo', ['not-a-key', {commitment: 'finalized', encoding: 'base64'}]),
  request('getAccountInfo', [miner.publicKey.toBase58(), {commitment: 'finalized', encoding: 'jsonParsed'}]), request('getBlockHeight', [{commitment: 'processed'}]),
  request('getSignatureStatuses', [['not-a-signature'], {searchTransactionHistory: true}]), {...request('getGenesisHash'), url: privateEndpoint}]) {
  const before = calls.length;
  await assert.rejects(rpc.request(body, session)); assert.equal(calls.length, before); checks++;
}
for (const [value, code] of [['limited', 'RPC_RATE_LIMITED'], ['unavailable', 'RPC_UNAVAILABLE'], ['error', 'RPC_UPSTREAM_REJECTED'], ['oversize', 'RPC_INVALID_RESPONSE']]) {
  mode = value;
  try {await rpc.request(request('getGenesisHash'), session); assert.fail();}
  catch (error) {assert.equal(error.code, code); assert(!error.message.includes(privateEndpoint)); checks++;}
}
mode = 'wrong-chain'; now += 30_001;
await assert.rejects(rpc.request(request('getBlockHeight', [{commitment: 'finalized'}]), session), {code: 'WRONG_CHAIN'}); checks++;
mode = 'ok'; await rpc.request(request('getGenesisHash'), session);
const signed = new Transaction({feePayer: miner.publicKey, recentBlockhash: Keypair.generate().publicKey.toBase58()}).add({programId: program.publicKey, keys: [], data: Buffer.from([1])});
signed.sign(miner);
const encoded = signed.serialize().toString('base64'), options = {encoding: 'base64', maxRetries: 0, preflightCommitment: 'finalized'};
assert.throws(() => rpc.parameters(request('sendTransaction', [encoded, options]), session), {code: 'RPC_TRANSACTION_SCOPE'}); checks++;
service.db.prepare('INSERT INTO mining_v3_grant_requests VALUES(?,?,?,?,?,NULL,?,?)').run('fixture', session.wallet, 'create', miner.publicKey.toBase58(), createHash('sha256').update(signed.serializeMessage()).digest('hex'), 10, 1791892000);
const prepared = rpc.parameters(request('sendTransaction', [encoded, options]), session);
assert.equal(prepared.params[1].skipPreflight, false); assert(service.db.prepare('SELECT signature FROM mining_v3_grant_requests WHERE id=?').get('fixture').signature); checks++;
for (const patch of [{skipPreflight: true}, {maxRetries: 10}, {preflightCommitment: 'processed'}, {encoding: 'jsonParsed'}]) {
  assert.throws(() => rpc.parameters(request('sendTransaction', [encoded, {...options, ...patch}]), session)); checks++;
}
assert.throws(() => rpc.parameters(request('sendTransaction', [encoded, options]), {wallet: relayer.publicKey.toBase58()})); checks++;
const unrelated = new Transaction({feePayer: miner.publicKey, recentBlockhash: signed.recentBlockhash}).add(SystemProgram.transfer({fromPubkey: miner.publicKey, toPubkey: relayer.publicKey, lamports: 1})); unrelated.sign(miner);
assert.throws(() => rpc.parameters(request('sendTransaction', [unrelated.serialize().toString('base64'), options]), session)); checks++;
for (let i = 0; i < 80; i++) rpc.admission('limit-wallet');
assert.throws(() => rpc.admission('limit-wallet'), {code: 'RPC_RATE_LIMITED'}); checks++;
rpc.active = 4; assert.throws(() => rpc.admission('other-wallet'), {code: 'RPC_BUSY'}); rpc.active = 0; checks++;

let forwarded = 0;
service.rpcProxy = {request: async () => {forwarded++; return {jsonrpc: '2.0', id: 1, result: genesis};}};
const token = 'a'.repeat(64), csrf = 'b'.repeat(64), hash = text => createHash('sha256').update(text).digest('hex');
service.db.prepare('INSERT INTO mining_v3_sessions VALUES(?,?,?,?,?,0)').run(hash(token), hash(csrf), session.wallet, origin, 1791892600);
const server = serve(service, {port: 0}); await new Promise(resolve => server.once('listening', resolve));
try {
  const url = 'http://127.0.0.1:' + server.address().port + '/api/mining/v3/';
  const post = headers => fetch(url + 'rpc', {method: 'POST', headers: {Origin: origin, 'Content-Type': 'application/json', ...headers}, body: JSON.stringify(request('getGenesisHash'))});
  assert.equal((await post({})).status, 401); checks++;
  assert.equal((await post({Authorization: 'Bearer ' + token})).status, 401); checks++;
  assert.equal((await post({Origin: 'https://wrong.example', Authorization: 'Bearer ' + token, 'X-Mining-CSRF': csrf})).status, 403); checks++;
  assert.equal(forwarded, 0); checks++;
  assert.equal((await (await post({Authorization: 'Bearer ' + token, 'X-Mining-CSRF': csrf})).json()).result, genesis); checks++;
  const publicConfig = await (await fetch(url + 'configuration', {headers: {Origin: origin}})).json();
  assert.equal(publicConfig.rpc, config.rpc); assert(!Object.hasOwn(publicConfig, 'rpcUpstream')); assert(!JSON.stringify(publicConfig).includes(privateEndpoint)); checks++;
} finally {await new Promise(resolve => server.close(resolve)); service.db.close();}
console.log(JSON.stringify({passed: true, checks, provider: 'fixture', broadcasts: 0, realWallet: false}));
