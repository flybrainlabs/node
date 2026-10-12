#!/usr/bin/env python3
"""Loopback static release server applying the exported Apache security policy."""
from __future__ import annotations
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('release',type=Path);p.add_argument('--port',type=int,default=8080);a=p.parse_args()
    root=a.release.resolve();text=(root/'.htaccess').read_text()
    security={name:value for name,value in re.findall(r'Header\s+always\s+set\s+([\w-]+)\s+"([^"]*)"',text)}
    class Handler(SimpleHTTPRequestHandler):
        extensions_map={**SimpleHTTPRequestHandler.extensions_map,'.wasm':'application/wasm','.mjs':'text/javascript'}
        def end_headers(self):
            for name,value in security.items():self.send_header(name,value)
            self.send_header('Cache-Control','no-store' if self.path.endswith(('.json','.html','/')) else 'no-cache')
            super().end_headers()
    server=ThreadingHTTPServer(('127.0.0.1',a.port),partial(Handler,directory=str(root)))
    print(f'Checked static research release on http://127.0.0.1:{a.port}',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
if __name__=='__main__':main()
