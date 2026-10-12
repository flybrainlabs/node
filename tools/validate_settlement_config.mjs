// Read-only configuration/inspection check. Never installs a config, issues an
// asset, reserves a stage or transmits a payment. An RPC inspection is separate.
import {readFile,writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {PublicKey} from '@solana/web3.js';
import {CAP,addresses} from './economy_v2_client.mjs';
const digest=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const pubkey=v=>{try{return typeof v==='string'&&new PublicKey(v).toBase58()===v;}catch{return false;}};
export function validate(config,inspection){
 if(config.schema!=='flybrain-economic-settlement-v2'||typeof config.enabled!=='boolean'||config.chain!=='solana'||config.decimals!==8||config.finality!=='finalized'||config.capAtoms!==CAP.toString())throw new Error('Wrong configuration schema, asset units, finality or cap');
 const missing=[];
 for(const key of ['networkId','authorityId','asset','programId','genesisHash','mint','policyHash'])if(!config[key])missing.push(key);
 if(!Array.isArray(config.vaults)||config.vaults.length!==3||config.vaults.some(v=>!v))missing.push('vaults');
 if(!Array.isArray(config.admittedObservers)||config.admittedObservers.length<2)missing.push('admittedObservers');
 if(config.upgradeReview?.reviewed!==true||!config.upgradeReview?.auditRef)missing.push('upgradeReview');
 if(!Number.isSafeInteger(config.inspectionReviewedAt)||config.inspectionReviewedAt<=0)missing.push('inspectionReviewedAt');
 if(missing.length){if(config.enabled)throw new Error('Activation has incomplete fields: '+missing.join(', '));return {schema:'flybrain-settlement-config-validation-v2',configurationValid:true,completeIdentity:false,enabled:false,requiredFields:missing,formalAssetApproved:false};}
 if(typeof config.networkId!=='string'||!config.networkId.length||!digest(config.authorityId)||!digest(config.policyHash)||!['programId','genesisHash','mint'].every(k=>pubkey(config[k])))throw new Error('Invalid chain or authority identity');
 if(config.asset!==`solana:${config.genesisHash}:${config.mint}:8`)throw new Error('Asset must bind genesis, mint and decimals');
 if(new Set(config.admittedObservers).size!==config.admittedObservers.length||!config.admittedObservers.every(digest))throw new Error('Distinct observer identities required');
 const a=addresses(config.programId);if(config.vaults.some((v,i)=>v!==a.pool(i).toBase58()))throw new Error('Wrong program-derived vaults');
 if(!inspection||inspection.schema!=='flybrain-chain-inspection-v2'||inspection.finality!=='finalized'||inspection.capAtoms!==CAP.toString())throw new Error('Actual finalized chain inspection required');
 for(const key of ['programId','genesisHash','mint','policyHash'])if(config[key]!==inspection[key])throw new Error('Inspected identity mismatch: '+key);
 if(!Array.isArray(inspection.vaults)||inspection.vaults.length!==3||config.vaults.some((v,i)=>inspection.vaults[i].address!==v))throw new Error('Inspected vault mismatch');
 if(!Array.isArray(inspection.settlers)||config.admittedObservers.some(k=>!inspection.settlers.includes(k)))throw new Error('Observers must match chain admission');
 return {schema:'flybrain-settlement-config-validation-v2',configurationValid:true,completeIdentity:true,enabled:config.enabled,requiredFields:[],formalAssetApproved:false,requires:['fresh RPC inspection','authority network/id and admitted-key cross-check','independent security and operator review','explicit issuance/funds authorization','reserved and published finite allocation stage']};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const args=process.argv.slice(2),value=k=>args[args.indexOf('--'+k)+1];if(!args.includes('--config'))throw new Error('usage: --config JSON [--inspection ACTUAL_CHAIN_REPORT] [--output REPORT]');
 const config=JSON.parse(await readFile(value('config'),'utf8')),inspection=args.includes('--inspection')?JSON.parse(await readFile(value('inspection'),'utf8')):undefined;
 const report=validate(config,inspection);if(args.includes('--output'))await writeFile(value('output'),JSON.stringify(report,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(report));
}
