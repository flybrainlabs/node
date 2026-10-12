#!/usr/bin/env python3
"""Loopback V2 preview with a same-origin API; preserves existing browser origin/cache."""
import argparse,http.client,json,re
from functools import partial
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('release',type=Path);p.add_argument('network_config',type=Path);p.add_argument('--deployment',type=Path,help='Explicit versioned same-origin development deployment only');p.add_argument('--forward-origin',choices=['https://flybrain.work','https://www.flybrain.work'],help='Authorized-origin development gateway through an explicit loopback tunnel');p.add_argument('--port',type=int,default=8084);p.add_argument('--authority',default='http://127.0.0.1:8787');a=p.parse_args();root=a.release.resolve();target=urlsplit(a.authority)
    if target.hostname not in ['127.0.0.1','localhost']:raise ValueError('Development API proxy must be loopback')
    if a.forward_origin and not a.deployment:raise ValueError('Explicit versioned development deployment required for an origin gateway')
    if a.deployment:
        deployment=json.loads(a.deployment.read_text())
        if deployment.get('schema')!='flybrain-mining-deployment-v1' or deployment.get('version')!=1 or deployment.get('environment')!='development' or deployment.get('apiBase')!='' or deployment.get('capabilities',{}).get('payment') or deployment.get('capabilities',{}).get('rewards'):raise ValueError('Explicit development deployment with funding disabled required')
    security={n:v for n,v in re.findall(r'Header\s+always\s+set\s+([\w-]+)\s+"([^"]*)"',(root/'.htaccess').read_text())}
    class Handler(SimpleHTTPRequestHandler):
        extensions_map={**SimpleHTTPRequestHandler.extensions_map,'.wasm':'application/wasm','.mjs':'text/javascript'}
        def log_message(self,*args):pass
        def end_headers(self):
            for n,v in security.items():self.send_header(n,v)
            self.send_header('Cache-Control','no-store' if '.json' in self.path or self.path.endswith('/') else 'no-cache');super().end_headers()
        def do_GET(self):
            if a.deployment and self.path.split('?')[0]=='/assets/data/mining-deployment-v1.json':
                blob=a.deployment.read_bytes();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(blob)));self.end_headers();self.wfile.write(blob)
            elif self.path.split('?')[0]=='/assets/data/target-network-v2.json':
                blob=a.network_config.read_bytes();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(blob)));self.end_headers();self.wfile.write(blob)
            elif self.path.startswith('/api/'):self.proxy()
            else:super().do_GET()
        def do_POST(self):self.proxy()
        def do_PUT(self):self.proxy()
        def proxy(self):
            if not self.path.startswith('/api/'):self.send_error(404);return
            length=int(self.headers.get('Content-Length','0'))
            if length<0 or length>4*1024*1024+65536:self.send_error(413);return
            conn=http.client.HTTPConnection(target.hostname,target.port,timeout=60);headers={n:v for n,v in self.headers.items() if n.lower() not in ['host','connection','cookie','authorization']};headers['Host']=f'{target.hostname}:{target.port}'
            if a.forward_origin:headers['Origin']=a.forward_origin
            try:
                conn.request(self.command,self.path,body=self.rfile.read(length) if length else None,headers=headers);res=conn.getresponse();self.send_response(res.status)
                for n,v in res.getheaders():
                    if n.lower() not in ['connection','transfer-encoding','cache-control']:self.send_header(n,v)
                self.end_headers()
                if res.getheader('Content-Type','').startswith('text/event-stream'):
                    while True:
                        chunk=res.readline()
                        if not chunk:break
                        self.wfile.write(chunk);self.wfile.flush()
                else:self.wfile.write(res.read())
            except (BrokenPipeError,ConnectionResetError):pass
            except (OSError,TimeoutError):
                if not self.wfile.closed:
                    try:self.send_error(503,'Development authority unavailable')
                    except OSError:pass
            finally:conn.close()
    server=ThreadingHTTPServer(('127.0.0.1',a.port),partial(Handler,directory=str(root)));server.daemon_threads=True
    print(f'V2 development preview http://127.0.0.1:{a.port}/mining/; retained origin, no production deployment',flush=True)
    try:server.serve_forever()
    finally:server.server_close()
if __name__=='__main__':main()
