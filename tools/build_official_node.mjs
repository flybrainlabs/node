// Uses the exact bundled Worker builder against local official files for reproducibility.
import { openAsBlob } from 'node:fs';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { buildOfficial } from '../web/official-builder.mjs';
const [annotation,weights,transmitter,output]=process.argv.slice(2);
if(!output)throw new Error('Usage: node tools/build_official_node.mjs ANNOTATIONS WEIGHTS TRANSMITTERS NEW_OUTPUT');
await mkdir(output);const manifest=JSON.parse(await readFile('web/data/official-inputs.json')),config=JSON.parse(await readFile('web/data/research-config.json'));
const files={annotation:await openAsBlob(annotation),weights:await openAsBlob(weights),transmitter:await openAsBlob(transmitter)};let last=0,peak=0;
const report=await buildOfficial(files,manifest,config,async(name,bytes)=>writeFile(output+'/'+name,bytes,{flag:'wx'}),(label,n,total)=>{peak=Math.max(peak,process.memoryUsage().rss);if(Date.now()-last>15000){console.log(label,n+'/'+total);last=Date.now();}});
report.node_peak_rss_bytes=peak;await writeFile(output+'/build-report.json',JSON.stringify(report,null,2)+'\n',{flag:'wx'});console.log(report);
