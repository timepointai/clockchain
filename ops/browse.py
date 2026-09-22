#!/usr/bin/env python3
"""A very small window onto the live Clockchain ledger.

    python3 ops/browse.py                      # uses $DATABASE_URL
    python3 ops/browse.py <postgres-url> [port]

Every reload draws a fresh random sample. No dependencies: it shells out to
`psql`, which also means it reads exactly what any other client would see.

If CC_NODE_URL and CC_NODE_API_KEY are set it also asks the running node one
real feasibility question per page, because a verdict is the thing the ledger
exists to produce — the tables alone don't show it.
"""

import html
import json
import os
import subprocess
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

DB = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DATABASE_URL", "")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
NODE = os.environ.get("CC_NODE_URL")
NODE_KEY = os.environ.get("CC_NODE_API_KEY")
SEP = "\x1f"

# Prefer a client whose major matches the server; an older one refuses outright.
PSQL = next((p for p in ("/opt/homebrew/opt/postgresql@17/bin/psql",
                         "/usr/local/opt/postgresql@17/bin/psql", "psql")
             if os.path.exists(p) or p == "psql"), "psql")

if not DB:
    sys.exit("set DATABASE_URL or pass a postgres url")


def q(sql):
    p = subprocess.run([PSQL, DB, "-tA", "-F", SEP, "-c", sql],
                       capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise RuntimeError(p.stderr.strip()[:400])
    return [l.split(SEP) for l in p.stdout.split("\n") if l.strip()]


def one(sql, default="—"):
    r = q(sql)
    return r[0][0] if r else default


def verdict(a, b, claim):
    """Ask the running node. Returns None if it isn't configured or reachable."""
    if not (NODE and NODE_KEY):
        return None
    body = json.dumps({"subjects": [int(a), int(b)],
                       "as_of": "900000000000", "claim": int(claim)}).encode()
    req = urllib.request.Request(f"{NODE}/v1/feasibility", data=body,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {NODE_KEY}"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=30).read())
    except Exception as e:
        return {"result": "unreachable", "detail": str(e)[:200]}


def esc(x):
    return html.escape(str(x))


POSTURE = {"-1": "MINED_PAST", "0": "WITNESSED_PRESENT", "1": "STAKED_FUTURE"}
CLOSURE = {"0": "known-open", "1": "known-closed", "2": "no recorded cessation"}
START = {"0": "evidenced", "1": "record is silent"}
RELATION = {"0": "co-occurrence", "1": "influence", "2": "causation"}
ANCHOR = {"0": "pending (submitted to a calendar)", "1": "confirmed in a block"}


def page():
    kinds = dict((k, int(n)) for k, n in q(
        "select kind, count(*) from events group by kind"))
    total = sum(kinds.values())

    root = q("select height, tree_size, encode(root_id,'hex') from roots "
             "order by height desc limit 1")
    anchor = q("select status, coalesce(block_height::text,'—') from anchors "
               "order by anchored_at desc limit 1")

    ents = q("""select entity_id, canonical_name, resolution_key, start_state, closure_state
                from entities where entity_id <> 0 order by random() limit 3""")
    moms = q("""select m.subject, e.canonical_name, m.posture, encode(m.root_event_id,'hex')
                from moments m join entities e on e.entity_id = m.subject
                where m.subject <> 0 order by random() limit 3""")
    edges = q("""select a.canonical_name, b.canonical_name, g.relation, g.in_g
                 from edges g
                 join entities a on a.entity_id = g.src_entity
                 join entities b on b.entity_id = g.dst_entity
                 order by random() limit 3""")
    vocab = q("select label from vocabulary order by random() limit 6")

    # Two entities picked at random — NOT a pair already joined by an edge.
    # Sampling from `edges` would guarantee a one-hop walk and make every verdict
    # `Supported`, which demonstrates nothing: the question would already contain
    # its own answer.
    pair = q("""with p as (select entity_id, canonical_name from entities
                           where entity_id <> 0 order by random() limit 2),
                     v as (select claim_type, label from vocabulary order by random() limit 1)
                select (select entity_id from p offset 0 limit 1),
                       (select entity_id from p offset 1 limit 1),
                       (select canonical_name from p offset 0 limit 1),
                       (select canonical_name from p offset 1 limit 1),
                       (select claim_type from v), (select label from v)""")

    o = ["""<meta charset=utf-8><title>Clockchain</title><style>
body{font:15px/1.6 -apple-system,system-ui,sans-serif;max-width:820px;margin:40px auto;padding:0 20px;color:#1a1a1a}
h1{font-size:20px;margin:0 0 4px} h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;
color:#888;margin:32px 0 8px;font-weight:600}
.n{font-variant-numeric:tabular-nums} table{border-collapse:collapse;width:100%}
td{padding:5px 10px 5px 0;vertical-align:top;border-bottom:1px solid #eee}
.dim{color:#888} .mono{font-family:ui-monospace,Menlo,monospace;font-size:12px}
.v{display:inline-block;padding:2px 9px;border-radius:3px;font-weight:600;font-size:13px}
.Supported{background:#e6f4ea;color:#137333} .Unsupported{background:#f1f3f4;color:#5f6368}
.Contradicted{background:#fce8e6;color:#c5221f} .unreachable{background:#fef7e0;color:#b06000}
a{color:#1a73e8}</style>"""]

    o.append(f"<h1>Clockchain</h1><p class=dim>{total:,} events · reload for a new sample</p>")

    o.append("<h2>Ledger</h2><table>")
    for label, k in (("entities", 1), ("moments", 2), ("edges", 3), ("vocabulary", 5)):
        o.append(f"<tr><td>{label}</td><td class='n'>{kinds.get(str(k),0):,}</td></tr>")
    if root:
        h, ts, rid = root[0]
        o.append(f"<tr><td>latest root</td><td class=n>height {h} over {int(ts):,} leaves"
                 f"<br><span class='mono dim'>{esc(rid)}</span></td></tr>")
    if anchor:
        st, bh = anchor[0]
        o.append(f"<tr><td>bitcoin anchor</td><td>{esc(ANCHOR.get(st, st))}"
                 f"{'' if bh=='—' else ' · block '+esc(bh)}</td></tr>")
    o.append("</table>")

    o.append("<h2>Entities</h2><table>")
    for _, name, key, ss, cs in ents:
        o.append(f"<tr><td>{esc(name) or '<span class=dim>(unnamed)</span>'}"
                 f"<br><span class='mono dim'>{esc(key)}</span></td>"
                 f"<td class=dim>start {START.get(ss,ss)}<br>end {CLOSURE.get(cs,cs)}</td></tr>")
    o.append("</table>")

    o.append("<h2>Moments</h2><table>")
    for _, name, post, rid in moms:
        o.append(f"<tr><td>{esc(name)}</td><td class=dim>{POSTURE.get(post,post)}"
                 f"<br><span class=mono>{esc(rid[:24])}…</span></td></tr>")
    o.append("</table>")

    o.append("<h2>Edges</h2><table>")
    for a, b, rel, in_g in edges:
        o.append(f"<tr><td>{esc(a)}<br><span class=dim>{RELATION.get(rel,rel)}</span>"
                 f"<br>{esc(b)}</td><td class=dim>{'both endpoints resolved' if in_g=='t' else 'dangling'}</td></tr>")
    o.append("</table>")

    o.append("<h2>Vocabulary</h2><p class=dim>" +
             " · ".join(esc(v[0].replace('tax:', '')) for v in vocab) + "</p>")

    if pair:
        sa, sb, na, nb, code, label = pair[0]
        o.append("<h2>A question</h2>")
        o.append(f"<p>Does the record support <b>{esc(na)}</b> and <b>{esc(nb)}</b> "
                 f"being related as <b>{esc(label.replace('tax:',''))}</b>?</p>")
        v = verdict(sa, sb, code)
        if v is None:
            o.append("<p class=dim>Set CC_NODE_URL and CC_NODE_API_KEY to ask the node.</p>")
        else:
            r = v.get("result", "?")
            o.append(f"<p><span class='v {esc(r)}'>{esc(r)}</span></p>")
            for w in v.get("vanished", []):
                o.append(f"<p class=dim>{esc(w.get('factor','?'))}: "
                         f"{esc(w.get('reason','?'))}</p>")
            if v.get("consulted"):
                o.append(f"<p class=dim>rests on {len(v['consulted'])} event(s)</p>")
            if v.get("filter_version"):
                o.append(f"<p class='mono dim'>rule {esc(v['filter_version'][:24])}…</p>")
            if v.get("detail"):
                o.append(f"<p class=dim>{esc(v['detail'])}</p>")

    o.append("<h2></h2><p><a href='/'>↻ new sample</a></p>")
    return "".join(o)


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/favicon.ico":
            self.send_response(204); self.end_headers(); return
        try:
            body = page().encode()
            code = 200
        except Exception as e:
            body = f"<pre>{html.escape(str(e))}</pre>".encode()
            code = 500
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - base class name
        pass


if __name__ == "__main__":
    print(f"http://localhost:{PORT}")
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
