#!/usr/bin/env python3
"""Actual HTTPS publication, download checksum and explicit native reproduction.
No private key or candidate endpoint access is granted by this test.
"""
import argparse,json,hashlib,subprocess,time
from pathlib import Path
from urllib.request import Request,build_opener,ProxyHandler
from urllib.error import HTTPError

urlopen=build_opener(ProxyHandler({})).open

def main(a):
 out=Path(a.output);out.mkdir(parents=True,exist_ok=True);report=dict(schema='flybrain-public-product-api-acceptance-v2',api=a.api,checks=[],files=[],formalFunds=False,externalObservation=False)
 def fetch(path,headers=None):
  with urlopen(Request(a.api+path,headers=headers or {}),timeout=180) as r:return json.load(r)
 def check(text):report['checks'].append(text);(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(text,flush=True)
 manifest=fetch('/api/product/manifest');assert manifest['economicPolicy']['capAtoms']=='31183324300000000';assert manifest['economicPolicy']['asset']['mint'] is None;assert manifest['deployment']['operators']==1
 check('HTTPS product manifest separates global design supply, scientific records and unavailable formal assets')
 results=fetch('/api/results?limit=1');assert results['items'];rid=results['items'][0]['id'];detail=fetch('/api/results/'+rid);task=fetch('/api/tasks/'+detail['taskId']);assert task['results']['items']
 assert detail['trials'][0]['pairedTargetCounts']==[[0,55],[0,125]];assert detail['trust']['protocolRoundWinner'] is False and detail['trust']['externalObservation'] is False
 assert fetch('/api/results?input='+detail['input']['stimulatedBodyId'])['items'];assert not fetch('/api/results?input=999999999')['items'];assert not fetch('/api/results?before='+str(results['nextCursor']))['items']
 for s in ['privateKey','accessToken','salt','contact','privatePath']:assert s not in json.dumps(detail)
 check('Real task/result/filter/cursor and event-derived A/B values match; public result cannot claim round win or biological validation')
 files=out/'downloaded';files.mkdir(exist_ok=True)
 for f in detail['files']:
  dest=files/f['name'];h=hashlib.sha256();count=0
  with urlopen(a.api+f['url'],timeout=180) as r, dest.open('wb') as target:
   assert r.headers['X-Content-Sha256']==f['sha256'] and int(r.headers['Content-Length'])==f['bytes'] and 'filename="'+f['name']+'"' in r.headers['Content-Disposition']
   assert r.headers['Content-Type']==f['mime']
   while chunk:=r.read(65536):h.update(chunk);count+=len(chunk);target.write(chunk)
  assert count==f['bytes'] and h.hexdigest()==f['sha256'];report['files'].append(dict(name=f['name'],sha256=h.hexdigest(),bytes=count));print('Checksum verified: '+f['name'],flush=True)
 check('All twelve actual HTTPS reproduction files match filenames, MIME metadata, sizes and SHA-256; streaming transfer')
 f=detail['files'][0]
 with urlopen(Request(a.api+f['url'],headers={'Range':'bytes=0-31'}),timeout=60) as r:assert r.status==206 and len(r.read())==32
 for suffix,status in [('?expires=1&signature=invalid',410),('?expires='+str(int(time.time())+60)+'&signature=invalid',403)]:
  try:urlopen(a.api+'/api/results/'+rid+'/files/'+f['name']+suffix,timeout=60);raise AssertionError('Unauthorized download accepted')
  except HTTPError as e:assert e.code==status
 check('Public Range works; expired and forged links are rejected over actual HTTPS')
 run=subprocess.run(['python3',str((files/'reproduce.py').resolve())],cwd=files,check=True,capture_output=True,text=True,timeout=600)
 native=[]
 for line in run.stdout.splitlines():
  if line.startswith('{'):native.append(json.loads(line))
 assert len(native)==2 and all(r['replayVerified'] for r in native)
 report['nativeReproduction']=native;report['resultId']=rid;check('Downloaded executable and frozen files reproduce two full model backgrounds byte for byte; no official data download')
 (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--api',default='https://43.161.219.89.sslip.io');p.add_argument('--output',required=True);main(p.parse_args())
