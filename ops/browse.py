#!/usr/bin/env python3
"""One read-only browser: python3 ops/browse.py --config /private/browser.json [--open]."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import shlex
import signal
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

import browser_local
import model_policy as policy

MAX_BYTES = 8 * 1024 * 1024
PNG = b'\x89PNG\r\n\x1a\n'


def esc(value):
    return html.escape(str(value), quote=True)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def coordinate(value):
    if re.fullmatch(r'0x[0-9a-fA-F]{64}|-?(0|[1-9][0-9]{0,77})', value or ''):
        return value
    raise ValueError('Invalid Clockchain coordinate.')


def entity_id(value):
    if not re.fullmatch(r'-?(0|[1-9][0-9]{0,18})', value or '') or not -(2**63) <= int(value) < 2**63:
        raise ValueError('Entity ID must be an exact decimal i64.')
    return value


def now_coordinate():
    return str(int((datetime.now(timezone.utc) - datetime(2000, 1, 1, 12, tzinfo=timezone.utc)).total_seconds()))


def config_read(path):
    config = policy.read(policy.private(path))
    if config.get('schema') != 'cc.browser.v1' or not 1024 <= config.get('port', 8766) <= 65535:
        raise ValueError('Invalid browser configuration.')
    sources = config.get('sources', [])
    if not sources or len(sources) > 32:
        raise ValueError('Configure between 1 and 32 sources.')
    seen = set()
    for source in sources:
        sid = source.get('id', '')
        if not re.fullmatch('[a-z][a-z0-9-]{0,63}', sid) or sid in seen:
            raise ValueError('Source IDs must be unique lowercase slugs.')
        seen.add(sid)
        if source.get('kind') == 'local':
            source['attempt'] = str(policy.private(source['attempt']))
        elif source.get('kind') == 'node':
            url = urllib.parse.urlsplit(source['url'])
            if (url.scheme not in ('http', 'https') or not url.hostname or url.username
                    or url.password or url.path not in ('', '/') or url.query or url.fragment
                    or (url.scheme == 'http' and url.hostname not in ('127.0.0.1', 'localhost', '::1'))):
                raise ValueError('Node URL must be an HTTPS origin or loopback HTTP origin.')
            source['url'] = source['url'].rstrip('/')
            source['read_key_file'] = str(policy.private(source['read_key_file']))
            if source.get('read_key_field') not in (None, 'CC_NODE_READ_KEY'):
                raise ValueError('Only the scoped read key may be loaded from an env file.')
        else:
            raise ValueError('Source kind must be local or node.')
    if config.get('default_source', sources[0]['id']) not in seen:
        raise ValueError('Unknown default source.')
    return config


def read_key(source):
    path = Path(source['read_key_file'])
    if path.stat().st_mode & 0o077 or path.stat().st_size > 65536:
        raise ValueError('Read credential file must be small and owner-only.')
    raw = path.read_text().strip()
    if source.get('read_key_field'):
        values = []
        for line in raw.splitlines():
            match = re.fullmatch(r'(?:export\s+)?CC_NODE_READ_KEY=(.*)', line.strip())
            if match:
                values = shlex.split(match[1], comments=True)
                break
        raw = values[0] if len(values) == 1 else ''
    if not raw or any(c.isspace() for c in raw):
        raise ValueError('A scoped read credential is required.')
    return raw


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Node redirects are refused.')


class Node:
    def __init__(self, source):
        self.source = source
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(self, path, params=None, binary=False):
        url = self.source['url'] + path
        if params:
            url += '?' + urllib.parse.urlencode(params)
        request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + read_key(self.source)})
        with self.opener.open(request, timeout=15) as response:
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError('Node response exceeds the browser limit.')
        return raw if binary else json.loads(raw)

    def media(self, eid, at):
        media = self.get('/v2/media', {'entity_id': entity_id(eid), 'as_of': coordinate(at)})
        if not isinstance(media, dict) or not isinstance(media.get('readings'), list):
            raise ValueError('Invalid media response')
        for reading in media['readings']:
            images, absences = reading.get('images'), reading.get('absence_decisions')
            if not isinstance(images,list) or not isinstance(absences,list):
                raise ValueError('Invalid media records')
            expected = {(False,False):'no_generation_recorded', (True,False):'generated',
                        (False,True):'deliberately_unillustrated', (True,True):'conflicting_media_records'}[(bool(images),bool(absences))]
            if reading.get('state') != expected:
                raise ValueError('Media state does not match records')
        return media


def media_images(media):
    for reading in media.get('readings', []):
        for image in reading.get('images', []):
            yield reading, image


def local_data(source):
    proposal, receipt, assets = browser_local.load_attempt(Path(source['attempt']))
    entries = [dict(id=str(i), title=e['title'], year=e.get('year'), body=e,
                    summary=e.get('summary', '')) for i, e in enumerate(proposal['entries'])]
    index = {(e['title'], e.get('year')): str(i) for i, e in enumerate(proposal['entries'])}
    edges = [dict(src=index[(e['from']['title'], e['from']['year'])],
                  dst=index[(e['to']['title'], e['to']['year'])], relation=e['relation'], raw=e)
             for e in proposal['edges']]
    return dict(entries=entries, edges=edges, proposal=proposal, receipt=receipt, assets=assets)


def node_data(source, at, selected=''):
    node = Node(source)
    moments = node.get('/v1/moments', {'as_of': coordinate(at), 'limit': 50})
    ids = list(dict.fromkeys(str(m['subject']) for m in moments['moments'] if str(m['subject']) != '0'))
    if selected:
        entity_id(selected)
        if selected not in ids:
            ids.insert(0, selected)
    def fetch(eid):
        return node.get('/v1/entities/' + entity_id(eid), {'as_of': at})
    with ThreadPoolExecutor(max_workers=6) as pool:
        records = list(pool.map(fetch, ids))
    entries, edges, seen = [], [], set()
    for record in records:
        eid = str(record['entity']['entity_id'])
        payload = (record.get('tt', {}).get('envelope') or {}).get('payload') or {}
        entries.append(dict(id=eid, title=record['entity']['canonical_name'], year=payload.get('occurs_at'), body=record))
        for edge in record.get('edges', []):
            key = (str(edge['src_entity']), str(edge['dst_entity']), edge['relation'], edge['evidence_class'])
            if key not in seen:
                seen.add(key)
                edges.append(dict(src=key[0], dst=key[1], relation=key[2], raw=edge))
    selected = selected or (ids[0] if ids else '')
    media, media_error = None, None
    if selected:
        try:
            media = node.media(selected, at)
        except Exception:
            media_error = 'Media could not be read at this coordinate. No absence is inferred.'
    return dict(entries=entries, edges=edges, receipt=moments, selected=selected, media=media, media_error=media_error)


def link(source, at='', entity=''):
    params = {'source': source['id']}
    if at:
        params['as_of'] = at
    if entity:
        params['entity'] = entity
    return '/?' + urllib.parse.urlencode(params)


def details(title, data):
    return '<details><summary>' + esc(title) + '</summary><pre>' + esc(json.dumps(data, indent=2, ensure_ascii=False)) + '</pre></details>'


def graph(source, data, at):
    nodes = data['entries']
    if not nodes:
        return ''
    positions = {n['id']: 24 + i * 300 for i, n in enumerate(nodes)}
    width = max(650, len(nodes)*300 + 24)
    result = [f'<div class="graph"><svg role="img" aria-label="Recorded directed relationships" viewBox="0 0 {width} 240" style="min-width:{width}px"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8" fill="#41b5a5"/></marker></defs>']
    for edge in data['edges']:
        if edge['src'] not in positions or edge['dst'] not in positions:
            continue
        a, b = positions[edge['src']]+120, positions[edge['dst']]+120
        result.append(f'<path d="M{a},68 C{a},8 {b},8 {b},68" fill="none" stroke="#41b5a5" stroke-width="2" marker-end="url(#arrow)"/><text x="{(a+b)/2}" y="24" text-anchor="middle">{esc(edge["relation"])}</text>')
    for n in nodes:
        x = positions[n['id']]
        href = '#entry-' + n['id'] if source['kind'] == 'local' else link(source, at, n['id'])
        result.append(f'<a href="{esc(href)}"><rect x="{x}" y="70" width="250" height="140" rx="12"/><foreignObject x="{x+14}" y="80" width="222" height="118"><div xmlns="http://www.w3.org/1999/xhtml" class="graph-label">{esc(n["title"])}<small>{esc(n.get("year") or "Date in record")}</small></div></foreignObject></a>')
    return ''.join(result) + '</svg></div>'


STYLE = '''*{box-sizing:border-box}body{margin:0;background:#111820;color:#e6edf4;font:16px/1.55 system-ui}header,main{max-width:1280px;margin:auto;padding:26px}header{border-bottom:1px solid #304354}a{color:#78d8c8}h1{margin:0;font-size:32px}h2{line-height:1.3}p{overflow-wrap:anywhere}.muted,small{color:#a5b6c7}small{display:block}nav{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}nav a,button{border:1px solid #4e697f;border-radius:8px;padding:9px 14px;background:#203244;color:#e6edf4;text-decoration:none}nav a.active{border-color:#78d8c8;color:#78d8c8}form{display:flex;align-items:end;gap:12px;flex-wrap:wrap}label{display:grid;gap:5px;font-size:14px}input{padding:9px;border:1px solid #4e697f;border-radius:6px;background:#111820;color:#e6edf4;min-width:220px}article,.notice{padding:24px;background:#192632;border:1px solid #304354;border-radius:12px;margin:20px 0;scroll-margin:20px}article:target{border-color:#78d8c8}.badge{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#f2ce87}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;background:#111820;padding:16px;border-radius:8px}details{margin:15px 0}summary{cursor:pointer;color:#b9d2e4}figure{margin:20px 0}figure img{display:block;width:100%;max-width:620px;border-radius:9px}figcaption{max-width:850px;margin-top:10px;color:#b9c9d6}.graph{overflow:auto;background:#16222e;border-radius:12px}.graph svg{width:100%;height:240px}.graph rect{fill:#23384c;stroke:#597c9a}.graph text{fill:#78d8c8;font:13px system-ui}.graph-label{font:15px/1.35 system-ui;color:#e6edf4}.empty{text-align:center;padding:50px}.error{border-color:#c99573}@media(max-width:650px){header,main{padding:16px}h1{font-size:27px}article{padding:18px}}'''


def image_card(url, manifest, status, record):
    disclosure = manifest.get('reconstruction_disclosure') or 'Synthetic illustration. See the original manifest for its recorded scope.'
    return (f'<figure><img loading="lazy" src="{esc(url)}" alt="Generated illustration associated with this exact reading"><figcaption>{esc(disclosure)}</figcaption><p>{esc(status)} · Historical verification: {esc(manifest.get("historical_verification", "not_assessed"))}</p><a href="{esc(url)}">Open original PNG</a>'+details('Image provenance and binding', record)+'</figure>')


def render(config, source, data=None, at='', selected='', error=None):
    nav = ''.join(f'<a class="{"active" if s["id"]==source["id"] else ""}" href="{esc(link(s))}">{esc(s["label"])}</a>' for s in config['sources'])
    page = [f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Clockchain browser · {esc(source["label"])}</title><style>{STYLE}</style><header><h1>Clockchain browser</h1><p class="muted">Entries, recorded connections, source evidence and images</p><nav>{nav}</nav></header><main><span class="badge">{esc(source["label"])} · {"Unpublished draft" if source["kind"]=="local" else "Node records · read only"}</span>']
    if source['kind'] == 'node':
        page.append(f'<form method="get"><input type="hidden" name="source" value="{esc(source["id"])}"><label>As of · Clockchain ticks<input name="as_of" value="{esc(at)}" required></label><label>Entity ID · optional<input name="entity" value="{esc(selected)}" placeholder="Exact decimal ID"></label><button>View records</button></form><p class="muted">Up to 50 latest moments at this coordinate. Enter an entity ID to view another record; this is not a complete corpus listing.</p>')
    else:
        page.append(f'<p>Human publication review pending · <a href="{esc(link(source))}">Refresh from disk</a></p>')
    if error:
        page.append('<div class="notice error">'+esc(error)+'</div>')
    if data:
        page.append(f'<p>{len(data["entries"])} entries · {len(data["edges"])} recorded relationships</p>')
        page.append(graph(source, data, at))
        if not data['entries']:
            page.append('<div class="notice empty"><h2>No historical entries in this view</h2><p>The node returned no historical subjects among the moments in this coordinate window.</p></div>')
        for entry in data['entries']:
            eid = entry['id']
            page.append(f'<article id="entry-{esc(eid)}"><h2>{esc(entry["title"])}</h2>')
            if 'summary' in entry:
                page.append('<p>'+esc(entry['summary'])+'</p>')
            if source['kind'] == 'local':
                for i, item in enumerate(data['proposal'].get('images', [])):
                    if str(item['entry_index']) == eid:
                        url = '/image?' + urllib.parse.urlencode({'source':source['id'], 'index':i, 'sha':item['sha256']})
                        page.append(image_card(url, item['manifest'], 'Prepared image · '+item['manifest'].get('visual_review', 'pending'), item))
                page.append(details('Complete claim and source evidence', entry['body']))
            else:
                page.append(f'<small>Entity {esc(eid)}</small><p><a href="{esc(link(source, at, eid))}#entry-{esc(eid)}">Inspect images and media decisions</a></p>')
                readings = entry['body'].get('readings', {}).get('all', [])
                if not readings:
                    page.append('<p>Stored claim prose unavailable from this node response.</p>')
                for reading in readings:
                    page.append('<p>Claim body hash: '+esc(reading.get('body_hash', 'unavailable'))+'</p>')
                    if isinstance(reading.get('body'),str):
                        page.append('<details open><summary>Exact stored claim body from node</summary><pre>'+esc(reading['body'])+'</pre></details>')
                    else:
                        page.append('<p>Stored claim prose unavailable for this reading.</p>')
                if eid == data['selected']:
                    if data['media_error']:
                        page.append('<p class="error">'+esc(data['media_error'])+'</p>')
                    elif data['media'] is not None:
                        media = data['media']
                        if not media['readings']:
                            page.append('<p>No media readings at this coordinate.</p>')
                        for reading in media.get('readings', []):
                            page.append('<p>Media: '+esc(reading['state'])+' · '+esc(reading['source_binding'])+'</p>')
                            for image in reading.get('images', []):
                                m = image['manifest']
                                url = '/image?' + urllib.parse.urlencode({'source':source['id'], 'entity':eid, 'as_of':at, 'sha':m['image_sha256']})
                                page.append(image_card(url, m, 'Signed attachment · '+reading['source_binding'], image))
                        page.append(details('All media readings and absence decisions', media))
                page.append('<p class="muted">Showing the fields exposed by this node API. Hashes and classification do not replace a retained claim body or historical review.</p>')
                page.append(details('Complete entity API response', entry['body']))
            page.append('</article>')
        if data['edges']:
            page.append('<article><h2>Recorded connections</h2>')
            for edge in data['edges']:
                page.append('<h3>'+esc(edge['relation'])+'</h3><p>'+esc(edge['raw'].get('rationale', ''))+'</p>')
                page.append(details('Direction and recorded evidence', edge['raw']))
            page.append('</article>')
        page.append(details('Read receipt', data['receipt']))
    page.append('<p class="muted">This browser reads records only. Illustrations are distinct from historical source evidence. No generation, staging, approval, signing or publication controls are provided.</p></main></html>')
    return ''.join(page).encode()


def image_bytes(source, query):
    sha = query.get('sha', '')
    if not re.fullmatch('[0-9a-f]{64}', sha):
        raise ValueError('Invalid image digest.')
    if source['kind'] == 'local':
        data = local_data(source)
        index = int(query.get('index', '-1'))
        images = data['proposal'].get('images', [])
        if not 0 <= index < len(images) or images[index]['sha256'] != sha:
            raise ValueError('Image does not belong to the current candidate.')
        raw = data['assets'][f'/images/{index}.png']
    else:
        node = Node(source)
        media = node.media(query.get('entity', ''), query.get('as_of', ''))
        if not any(i['manifest'].get('image_sha256') == sha for _, i in media_images(media)):
            raise ValueError('Image is not recorded for this entity at this coordinate.')
        raw = node.get('/v1/images/' + sha, binary=True)
    if len(raw) > MAX_BYTES or not raw.startswith(PNG) or digest(raw) != sha:
        raise ValueError('Image integrity check failed.')
    return raw


def handler(config):
    sources = {s['id']:s for s in config['sources']}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get('Host') not in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}') or self.headers.get('Sec-Fetch-Site') == 'cross-site':
                self.send_error(403); return
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path not in ('/', '/image', '/health'):
                self.send_error(404); return
            if parsed.path == '/health':
                self.reply(b'{"service":"clockchain-browser","read_only":true}', 'application/json'); return
            try:
                lists = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, max_num_fields=8)
                if any(len(v) != 1 for v in lists.values()):
                    raise ValueError('Duplicate query parameters are refused.')
                q = {k:v[0] for k,v in lists.items()}
                source = sources[q.get('source', config.get('default_source', config['sources'][0]['id']))]
                if parsed.path == '/image':
                    self.reply(image_bytes(source, q), 'image/png'); return
                at, selected = q.get('as_of') or now_coordinate(), q.get('entity', '')
                data, error = None, None
                try:
                    data = local_data(source) if source['kind'] == 'local' else node_data(source, at, selected)
                except urllib.error.HTTPError as exc:
                    error = f'Node returned HTTP {exc.code}. Check this source’s read access and coordinate.'
                except Exception:
                    error = 'Source could not be loaded or verified. Check its configuration, receipt, credential and connection.'
                self.reply(render(config, source, data, at, selected, error), 'text/html; charset=utf-8', 502 if error else 200)
            except Exception:
                self.reply(b'Request refused or image unavailable; no data was changed.', 'text/plain; charset=utf-8', 400)

        def reply(self, raw, mime, status=200):
            self.send_response(status)
            for key,value in {'Content-Type':mime, 'Content-Length':str(len(raw)), 'Cache-Control':'private, no-store', 'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'Content-Security-Policy':"default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"}.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass
    return Handler


class Tunnel:
    """An explicitly configured read-access tunnel supervised with the browser."""
    def __init__(self, config):
        self.config, self.child, self.stopping = config, None, threading.Event()

    def run(self):
        cfg = self.config
        if not re.fullmatch('[a-z0-9-]+', cfg['app']) or not 1024 <= cfg['port'] <= 65535:
            raise ValueError('Invalid Fly tunnel configuration.')
        self.command = [cfg['executable'], 'proxy', f'{cfg["port"]}:80', cfg['app']+'.flycast', '-a', cfg['app'], '--bind-addr', '127.0.0.1']
        def supervise():
            while not self.stopping.is_set():
                try:
                    self.child = subprocess.Popen(self.command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.child.wait()
                except OSError:
                    pass
                self.stopping.wait(5)
        threading.Thread(target=supervise, daemon=True).start()

    def close(self):
        self.stopping.set()
        if self.child and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--open', action='store_true')
    args = parser.parse_args()
    config = config_read(args.config)
    server = ThreadingHTTPServer(('127.0.0.1', config.get('port', 8766)), handler(config))
    tunnel = Tunnel(config['fly_tunnel']) if config.get('fly_tunnel') else None
    def shutdown(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        if tunnel:
            tunnel.run()
        url = f'http://127.0.0.1:{server.server_port}/'
        print('Clockchain browser: '+url, flush=True)
        if args.open:
            webbrowser.open(url)
        server.serve_forever()
    finally:
        server.server_close()
        if tunnel:
            tunnel.close()


if __name__ == '__main__':
    main()
