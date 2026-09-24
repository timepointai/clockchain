#!/usr/bin/env python3
"""Serve exactly one private proposal as a read-only local graph. No DB access."""
import argparse
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

import model_policy as policy


def render(proposal, result):
    e = lambda value: html.escape(str(value), quote=True)
    entries, edges = proposal['entries'], proposal['edges']
    index = {(n['title'],n['year']): i for i,n in enumerate(entries)}
    width = max(800, len(entries)*340)
    svg = ['<svg role="img" aria-label="Local candidate causal graph" viewBox="0 0 '+str(width)+' 220"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8" fill="#8ae3c4"/></marker></defs>']
    for j,edge in enumerate(edges):
        a,b = [index[(edge[k]['title'],edge[k]['year'])] for k in ('from','to')]
        x1,x2 = 30+a*340+290,30+b*340
        svg.append(f'<a href="#edge-{j}"><path d="M{x1},100 L{x2-8},100" stroke="#8ae3c4" stroke-width="3" marker-end="url(#arrow)"/><title>{e(edge["rationale"])}</title></a>')
    for i,node in enumerate(entries):
        x = 30+i*340
        # foreignObject keeps the complete, unmodified title readable and clickable.
        svg.append(f'<a href="#node-{i}"><rect x="{x}" y="35" width="290" height="130" rx="12" fill="#24354b" stroke="#85acd9"/><foreignObject x="{x+12}" y="45" width="266" height="112"><div xmlns="http://www.w3.org/1999/xhtml" class="label">{e(node["title"])}<small>{e(node["year"])}</small></div></foreignObject></a>')
    svg.append('</svg>')
    sections = []
    def evidence(items):
        return ''.join('<blockquote>'+e(s['excerpt'])+'</blockquote><p>'+e(s.get('publisher',''))+' · '+e(s['url'])+'</p>' for s in items)
    for i,node in enumerate(entries):
        sections.append(f'<article id="node-{i}"><h2>{e(node["title"])}</h2><p>{e(node["summary"])}</p>'+evidence(node['prov_measured'].get('source_evidence',[]))+'<details><summary>All recorded fields</summary><pre>'+e(json.dumps(node,indent=2,ensure_ascii=False))+'</pre></details></article>')
    for i,edge in enumerate(edges):
        sections.append(f'<article id="edge-{i}"><h2>Link {i+1}: {e(edge["relation"])}</h2><p>{e(edge["rationale"])}</p>'+evidence(edge.get('evidence',[]))+'<details><summary>All recorded fields</summary><pre>'+e(json.dumps(edge,indent=2,ensure_ascii=False))+'</pre></details></article>')
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Clockchain · local test</title><style>body{background:#101720;color:#e5edf5;font:16px/1.55 system-ui;margin:36px auto;max-width:1200px;padding:20px}a{color:#8ae3c4}.label{font:15px/1.3 system-ui;color:#e5edf5}small{display:block;color:#8ae3c4;margin-top:8px}svg{width:100%;min-width:800px}nav{overflow:auto}article{background:#192434;border:1px solid #344960;border-radius:12px;padding:24px;margin:20px 0;scroll-margin:20px}article:target{border:2px solid #8ae3c4}blockquote{border-left:3px solid #8ae3c4;margin-left:0;padding-left:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}</style><h1>One local Clockchain test</h1><p>Unpublished draft · '+str(len(entries))+' nodes · '+str(len(edges))+' causal links · human publication review pending</p><p>Click a node or link to inspect its source evidence and complete recorded fields.</p><nav>'+''.join(svg)+'</nav><details><summary>Attempt and validation receipt</summary><pre>'+e(json.dumps(result,indent=2))+'</pre></details>'+''.join(sections)+'</html>').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt',type=Path,required=True)
    parser.add_argument('--port',type=int,default=8766)
    args = parser.parse_args()
    attempt = policy.private(args.attempt)
    proposal = policy.read(attempt/'proposal.json'); result = policy.read(attempt/'result.json')
    if result.get('status') != 'proposal' or result.get('admission') != 'pass': raise ValueError('validated proposal required')
    if policy.digest((attempt/'proposal.json').read_bytes()) != result['proposal_sha256']: raise ValueError('proposal changed after validation')
    page = render(proposal,result)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ('/','/index.html'):
                self.send_error(404); return
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(page)))
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers(); self.wfile.write(page)
        def log_message(self,*args): pass
    server = ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print('Local unpublished test: http://127.0.0.1:'+str(server.server_port),flush=True)
    server.serve_forever()


if __name__ == '__main__': main()
