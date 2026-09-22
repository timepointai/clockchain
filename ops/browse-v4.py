#!/usr/bin/env python3
"""Existing loopback ledger viewer; reads CC_DATABASE_URL and CC_NODE_URL.

    CC_DATABASE_URL=postgres://... CC_NODE_URL=http://127.0.0.1:18080 \
      CC_NODE_READ_KEY=... python3 ops/browse-v4.py 8766

Use a read-only database role. The HTTP listener binds only to 127.0.0.1.
Queries run in one read-only transaction. No retired hosting discovery occurs.
"""

import csv
import io
import html
import json
import urllib.parse
import urllib.request
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import graphview as gv  # noqa: E402
import image_preview

PORT = 8766
NODE = os.environ.get("CC_NODE_URL", "http://127.0.0.1:18080").rstrip("/")


def node_key():
    return os.environ.get('CC_NODE_READ_KEY')


KEY = None

# One statement per panel, joined into a single psql invocation. Ordering is
# explicit everywhere: an unordered read of a ledger invites a reader to infer
# sequence from row order, which is not a fact about the data.
QUERIES = {
    "stats": (
        "select (select count(*) from entities), (select count(*) from moments), "
        "(select count(*) from edges), (select count(*) from vocabulary), "
        "(select count(*) from claim_bodies), "
        "(select count(*) from entities where start_state = 1)"
    ),
    "entities": (
        "select e.entity_id, e.canonical_name, e.start_state, "
        "  encode(e.birth_event,'hex'), e.resolution_key, "
        "  (select count(*) from edges x where x.src_entity = e.entity_id "
        "     or x.dst_entity = e.entity_id) "
        "from entities e order by e.canonical_name limit 400"
    ),
    "edges": (
        "select x.src_entity, x.dst_entity, s.canonical_name, d.canonical_name, "
        "  x.relation, x.evidence_class, coalesce(ev.evidence::text, '') "
        "from edges x "
        "join entities s on s.entity_id = x.src_entity "
        "join entities d on d.entity_id = x.dst_entity "
        "left join edge_evidence ev on ev.event_id = x.edge_id "
        "order by s.canonical_name limit 500"
    ),
    "vocab": (
        "select v.claim_type, v.label, v.start_state "
        "from vocabulary v order by v.label limit 300"
    ),
    "bodies": (
        "select m.subject, en.canonical_name, cb.body "
        "from moments m "
        "join entities en on en.entity_id = m.subject "
        "left join claim_bodies cb on cb.body_hash = m.body_hash "
        "order by en.canonical_name limit 400"
    ),
}

RELATION = {0: "co-occurrence", 1: "influence", 2: "causation",
            3: "participation", 4: "attestation", 5: "supersession"}
EVIDENCE = {0: "primary document", 1: "secondary source",
            2: "inference", 3: "assertion"}


def database_env():
    """Pass local connection fields through the environment, never process argv."""
    url = urllib.parse.urlsplit(os.environ.get('CC_DATABASE_URL', ''))
    if url.scheme not in ('postgres', 'postgresql') or url.hostname not in ('127.0.0.1', 'localhost', '::1'):
        raise ValueError('CC_DATABASE_URL must name a loopback PostgreSQL server')
    if not url.path.strip('/') or url.query or url.fragment:
        raise ValueError('Use a local database URI without query parameters')
    env = {key: value for key, value in os.environ.items() if not key.startswith('PG')}
    env.update(PGHOST=url.hostname, PGPORT=str(url.port or 5432),
               PGDATABASE=urllib.parse.unquote(url.path[1:]), PGCONNECT_TIMEOUT='10')
    for key, value in (('PGUSER', url.username), ('PGPASSWORD', url.password)):
        if value is not None:
            env[key] = urllib.parse.unquote(value)
    return env


def fetch():
    """Read every panel in one consistent, read-only local database transaction."""
    if not os.environ.get('CC_DATABASE_URL'):
        raise ValueError('CC_DATABASE_URL is required')
    script = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
    script += "\n".join(f"\\echo ===={name}\n{query};" for name, query in QUERIES.items())
    script += "\nCOMMIT;\n"
    env = database_env()
    result = subprocess.run(['psql', '-X', '-qAt', '--csv', '-v', 'ON_ERROR_STOP=1'],
                            input=script, env=env, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Read-only database query failed; check the local connection and schema')
    blocks, current = {}, None
    for row in csv.reader(io.StringIO(result.stdout)):
        if len(row) == 1 and row[0].startswith('===='):
            current = row[0][4:].strip()
            blocks[current] = []
        elif current and row:
            blocks[current].append(row)
    if set(blocks) != set(QUERIES):
        raise ValueError('Incomplete database response')
    return blocks


def esc(x):
    return html.escape(str(x) if x is not None else "")


def prov_line(body_json):
    """Render provenance at its tier. Never flatten; never infer from absence."""
    if not body_json:
        return '<span class="unk">bytes not kept — attributed in the hash, unreadable</span>'
    try:
        b = json.loads(body_json)
    except Exception:
        return '<span class="unk">body is not JSON</span>'
    m = b.get("prov_measured") or {}
    bits = []
    if m.get("text_model"):
        bits.append(f'<span class="m">measured</span> generated by '
                    f'<code>{esc(m["text_model"])}</code>')
    if b.get("prov_asserted"):
        bits.append('<span class="a">asserted</span> historical content is model-generated')
        bits.append(esc(b.get('summary', '')))
        bits.append('<details><summary>Claim, date precision and source evidence</summary><pre style="white-space:pre-wrap">'
                    + esc(json.dumps({'asserted': b['prov_asserted'], 'measured': m}, indent=2)) + '</pre></details>')
    if b.get("claim_type_alternatives"):
        bits.append('<span class="a">disputed</span> classifier also proposed '
                    + ", ".join(f"<code>{esc(x)}</code>"
                                for x in b["claim_type_alternatives"]))
    if b.get("date_is_known") is False:
        bits.append('<span class="u">approximate</span> a process or an '
                    'archaeological date — not a day')
    return " · ".join(bits) or '<span class="unk">no provenance recorded</span>'


CSS = """
*{box-sizing:border-box} body{font:14px/1.5 ui-monospace,Menlo,monospace;
margin:0;background:#0f1115;color:#d7dae0}
header{padding:18px 24px;border-bottom:1px solid #262a33;position:sticky;top:0;background:#0f1115}
h1{margin:0 0 6px;font-size:15px;letter-spacing:.08em;text-transform:uppercase;color:#8b93a1}
.stats{display:flex;gap:22px;flex-wrap:wrap;font-size:13px}
.stats b{color:#6ee7a8;font-weight:600}
nav{padding:10px 24px;border-bottom:1px solid #262a33}
nav a{color:#7aa2f7;text-decoration:none;margin-right:18px}
main{padding:20px 24px;max-width:1400px}
table{border-collapse:collapse;width:100%;margin-bottom:34px}
th{text-align:left;font-weight:600;color:#8b93a1;border-bottom:1px solid #262a33;
padding:7px 10px;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
td{padding:7px 10px;border-bottom:1px solid #191d24;vertical-align:top}
tr:hover td{background:#151922}
code{color:#c3a6ff;font-size:12px}
.m{color:#6ee7a8}.a{color:#f0c674}.u{color:#7aa2f7}.unk{color:#6b7280;font-style:italic}
.pill{border:1px solid #2c313c;border-radius:3px;padding:1px 7px;font-size:11px;color:#9aa3b2}
.no{color:#6b7280}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#8b93a1;
margin:30px 0 10px;border-left:2px solid #6ee7a8;padding-left:9px}
.note{color:#6b7280;font-size:12px;margin:-4px 0 14px;max-width:80ch}
.comp{border:1px solid #262a33;border-radius:5px;padding:12px;margin-bottom:16px;overflow-x:auto}
.comphead{color:#8b93a1;font-size:12px;margin-bottom:8px}
.walkbtn{color:#6ee7a8;text-decoration:none;border:1px solid #2c5c44;border-radius:3px;
padding:2px 9px;margin-left:10px;font-size:11px}
.walkbtn:hover{background:#16241d}
.verdict{border:1px solid #262a33;border-radius:5px;padding:14px;margin-bottom:24px}
.sup{color:#6ee7a8;font-size:19px;font-weight:600}
.uns{color:#f7768e;font-size:19px;font-weight:600}
.ev{color:#c3a6ff;font-size:11px}
"""


def page(walk=None):
    b = fetch()
    s = b["stats"][0] if b.get("stats") else ["?"] * 6
    ents, moms, edges, vocab, bodies, unknown = s
    o = [f"<!doctype html><meta charset=utf-8><title>Clockchain v4</title><style>{CSS}</style>",
         "<header><h1>Clockchain v4 &mdash; local ledger browser</h1><div class=stats>",
         f"<span>entities <b>{esc(ents)}</b></span>",
         f"<span>moments <b>{esc(moms)}</b></span>",
         f"<span>edges <b>{esc(edges)}</b></span>",
         f"<span>vocabulary <b>{esc(vocab)}</b></span>",
         f"<span>claim bodies <b>{esc(bodies)}</b></span>",
         f"<span>undated entities <b>{esc(unknown)}</b></span>",
         "</div></header>",
         "<nav><a href='#graph'>graph</a><a href='#entities'>entities</a>"
         "<a href='#edges'>edges</a>"
         "<a href='#claims'>claims &amp; provenance</a><a href='#vocab'>vocabulary</a>"
         "<a href='/'>reload</a></nav><main>"]

    nodes, edges_l = gv.build(b)
    comps, connected = gv.components(nodes, edges_l)
    isolated = len(nodes) - len(connected)

    o.append("<h2 id=graph>The causal graph</h2>")
    o.append(f"<p class=note>{len(comps)} connected components over <b>{len(connected)}</b> entities. "
             "Arrows show the stored direction; amber marks causation. Evidence classes are listed below. "
             "Year-based layout does not establish within-day order; a curved arrow may join same-year nodes.</p>")
    o.append(f"<p class=note>{isolated} entities have no edges (including any system entity).</p>")

    for i, group in enumerate(comps):
        svg, ordered = gv.svg_component(group, nodes, edges_l, i)
        a, z = ordered[0], ordered[-1]
        o.append("<div class=comp>")
        o.append(f"<div class=comphead>component {i+1} &mdash; {len(group)} entities "
                 f"<a class=walkbtn href='/walk?a={gv.esc(a)}&b={gv.esc(z)}'>"
                 f"run the walk &rarr;</a></div>")
        o.append(svg)
        o.append("</div>")

    # --- the live walk -----------------------------------------------------
    o.append("<h2 id=walk>Recorded graph walk</h2>")
    o.append("<p class=note>This runs the node's undirected recorded-graph feasibility query. "
             "The verdict names the events it consulted; it does not establish causal direction or historical truth. "
             "Inspect the directed edges and their source mechanisms separately.</p>")
    if walk:
        o.append(walk)
    else:
        o.append("<p class=note>Pick a component above and press "
                 "<i>run the walk</i>.</p>")

    o.append("<h2 id=entities>Entities</h2>")
    o.append("<p class=note>Identity is content-derived from the claim, never a path. "
             "A start of <span class=unk>unknown</span> is a typed unknown &mdash; the "
             "entity has no recorded beginning and vanishes from feasibility queries "
             "rather than being given a guessed one.</p>")
    o.append("<table><tr><th>name</th><th>start</th><th>edges</th><th>id</th>"
             "<th>birth event</th></tr>")
    for r in b.get("entities", []):
        eid, name, start_state, birth, _rk, deg = r[0], r[1], r[2], r[3], r[4], r[5]
        st = ('<span class="unk">unknown</span>' if start_state == "1"
              else '<span class="m">known</span>')
        d = f"<b>{esc(deg)}</b>" if deg != "0" else "<span class=no>0</span>"
        o.append(f"<tr><td><a href='/entity?id={esc(eid)}'>{esc(name)}</a></td>"
                 f"<td>{st}</td><td>{d}</td>"
                 f"<td><code>{esc(eid)}</code></td>"
                 f"<td><code>{esc(birth)[:16]}&hellip;</code></td></tr>")
    o.append("</table>")

    o.append("<h2 id=edges>Edges</h2>")
    o.append("<p class=note>Each edge lists its recorded evidence class and any attached mechanism evidence. "
             "A signature verifies attribution and integrity; it does not establish historical truth.</p>")
    o.append("<table><tr><th>from</th><th>relation</th><th>to</th><th>evidence</th></tr>")
    for r in b.get("edges", []):
        src, dst, rel, ev = r[2], r[3], r[4], r[5]
        o.append(f"<tr><td>{esc(src)}</td>"
                 f"<td><span class=pill>{esc(RELATION.get(int(rel), rel))}</span></td>"
                 f"<td>{esc(dst)}</td>"
                 f"<td><span class=pill>{esc(EVIDENCE.get(int(ev), ev))}</span>"
                 f"<details><summary>Mechanism and evidence</summary><pre style='white-space:pre-wrap'>{esc(r[6] if len(r) > 6 and r[6] else 'No evidence recorded')}</pre></details></td></tr>")
    if not b.get("edges"):
        o.append("<tr><td colspan=4 class=no>no edges</td></tr>")
    o.append("</table>")

    o.append("<h2 id=claims>Claims &amp; provenance</h2>")
    o.append("<p class=note>Model execution is measured; historical claims are asserted. "
             "Inspect the retained source passages and date precision on each record.</p>")
    o.append("<table><tr><th>subject</th><th>provenance</th></tr>")
    for r in b.get("bodies", []):
        _h, name, body = r[0], r[1], (r[2] if len(r) > 2 else None)
        o.append(f"<tr><td>{esc(name)}</td><td>{prov_line(body)}</td></tr>")
    o.append("</table>")

    o.append("<h2 id=vocab>Vocabulary</h2>")
    o.append("<p class=note>Bands are <b>measured, not invented</b>: a type's band opens at "
             "the earliest coordinate in the corpus carrying it &mdash; a claim the record "
             "supports. Closure is unknown everywhere, because nothing records a retirement "
             "and silence is not confirmation that a type is current.</p>")
    o.append("<table><tr><th>label</th><th>band start</th><th>code</th></tr>")
    for r in b.get("vocab", []):
        code, label, ss = r[0], r[1], r[2]
        st = ('<span class="unk">unknown</span>' if ss == "1"
              else '<span class="m">measured</span>')
        o.append(f"<tr><td><code>{esc(label)}</code></td><td>{st}</td>"
                 f"<td class=no>{esc(code)}</td></tr>")
    o.append("</table></main>")
    return "".join(o).encode()


def render_walk(a, b):
    """Run the acceptance test live and render it."""
    global KEY
    if KEY is None:
        KEY = node_key()
    if not KEY:
        return ('<div class=verdict><span class=uns>no credential</span>'
                '<p class=note>Set CC_NODE_READ_KEY. This is an error, '
                'not a verdict.</p></div>')
    import time
    as_of = int(time.time()) - 946_728_000
    # The claim must be admissible or the verdict is about the vocabulary, not
    # the graph. Any declared type works; this one is present in the corpus.
    try:
        vocabulary = fetch()['vocab']
        claim = vocabulary[0][0] if vocabulary else None
        if claim is None:
            raise ValueError('No vocabulary recorded')
        d = gv.feasibility(NODE, KEY, a, b, claim, as_of)
    except Exception as e:
        return (f'<div class=verdict><span class=uns>query failed</span>'
                f'<pre class=note>{html.escape(str(e))[:400]}</pre></div>')

    res = d.get("result", "?")
    cls = "sup" if res == "Supported" else "uns"
    o = [f'<div class=verdict><span class={cls}>{esc(res)}</span>']
    o.append('<p class=note>Recorded graph feasibility; factual verification is not assessed by this query.</p>')
    o.append(f'<p class=note>subjects <code>{esc(a)}</code> and <code>{esc(b)}</code>, '
             f'claim <code>{esc(claim)}</code>, pinned at '
             f'<code>{esc(as_of)}</code>.</p>')
    cons = d.get("consulted") or []
    if cons:
        o.append(f'<p><b>{len(cons)}</b> events consulted &mdash; this is the walk, '
                 f'enumerated:</p><ul>')
        for c in cons:
            o.append(f'<li class=ev>{esc(c)}</li>')
        o.append("</ul>")
    van = d.get("vanished")
    if van:
        o.append("<p>factors that vanished, and why:</p><ul>")
        for v in van:
            o.append(f'<li class=ev>{esc(json.dumps(v))}</li>')
        o.append("</ul>")
    else:
        o.append('<p class=note>Nothing vanished: every factor held.</p>')
    o.append("</div>")
    return "".join(o)


def render_entity(eid):
    """One entity's TT layer, read from the LIVE NODE.

    Deliberately NOT recomputed from the database here. The question this view
    answers is "what does the served surface actually say", and a browser that
    recomputed the content_hash locally would agree with itself no matter what
    production returned — the config-echo failure in tool form.
    """
    import time as _t
    key = node_key()
    if not key:
        return "<p class=no>no node key available</p>"
    as_of = int(_t.time()) - 946728000
    req = urllib.request.Request(f"{NODE}/v1/entities/{eid}?as_of={as_of}",
                                 headers={"Authorization": f"Bearer {key}"})
    try:
        d = json.load(urllib.request.urlopen(req, timeout=60))
    except Exception as e:
        return f"<p class=no>node returned {esc(type(e).__name__)}: {esc(str(e))}</p>"

    ent, tt = d.get("entity", {}), d.get("tt", {})
    o = [f"<h2 id=tt>TT layer &mdash; {esc(ent.get('canonical_name'))}</h2>",
         "<p class=note>Read live from <code>GET /v1/entities/{id}</code> on the "
         "running node, not recomputed here. A browser that recomputed these "
         "would agree with itself whatever production said.</p>"]
    if not tt.get("present"):
        o.append(f"<p class=no>no TT layer: {esc(tt.get('reason'))}</p>")
        return "".join(o)

    env = tt.get("envelope") or {}
    sh = tt.get("shadow") or {}
    rows = [
        ("claim_type", f"<code>{esc(tt.get('claim_type'))}</code>"),
        ("lens", f"<b>{esc(tt.get('lens'))}</b>"),
        ("alternatives", esc(json.dumps(tt.get("claim_type_alternatives")))),
        ("alternatives_cross_lens", esc(json.dumps(tt.get("alternatives_cross_lens")))),
        ("bundle (canonical citation)", f"<code>{esc(tt.get('bundle'))}</code>"),
        ("tt_release as stored", f"<code>{esc(tt.get('tt_release_as_stored'))}</code>"),
        ("tt_bundle_sha256", f"<code>{esc((tt.get('tt_bundle_sha256') or '')[:32])}&hellip;</code>"),
        ("content_hash", f"<code>{esc(env.get('content_hash'))}</code>"),
        ("canonical bytes", f"<code>{esc(env.get('canonical'))}</code>"),
        ("classification", f"<code>{esc(json.dumps(tt.get('classification')))}</code>"),
        ("classification source", esc(tt.get("classification_source"))),
    ]
    o.append("<table>")
    for k, v in rows:
        o.append(f"<tr><td style='white-space:nowrap'>{esc(k)}</td><td>{v}</td></tr>")
    o.append("</table>")

    state = sh.get("state")
    if sh.get("applicable") is False:
        o.append(f"<p class=note><b>shadow</b>: not applicable &mdash; "
                 f"{esc(sh.get('reason'))}</p>")
    else:
        colour = {"derived": "m", "unrecorded": "unk", "unlisted": "no"}.get(state, "")
        o.append(f"<p class=note><b>shadow</b>: <span class={colour}>{esc(state)}</span> "
                 f"&mdash; {esc(sh.get('meaning') or (str(sh.get('relation')) + ' -> ' + str(sh.get('event'))))}"
                 "</p>")
        o.append("<p class=note>Three states, kept apart on purpose: <span class=m>derived</span> "
                 "walks the bundle's bridge; <span class=unk>unrecorded</span> is the bundle "
                 "<em>asserting</em> this action leaves no public trace; <span class=no>unlisted</span> "
                 "is the bundle saying nothing at all. The last two are different facts.</p>")

    # --- edges, with the TT context the node derives for each -----------------
    edges = d.get("edges") or []
    o.append(f"<h2 id=edges>Edges &mdash; {esc(len(edges))}</h2>")
    if not edges:
        o.append("<p class=no>no edges. Roughly half the chain's entities have none; "
                 "the graph is a seed with connected regions, not a graph of history.</p>")
    else:
        o.append("<p class=note>The <b>relation</b> is Clockchain's own axis. "
                 "<b>TT labels nodes, not instance edges</b>, and defines no event-to-event "
                 "vocabulary &mdash; so what TT contributes here is <em>context about the "
                 "endpoints</em>: their types, whether the edge crosses lenses, the taxonomic "
                 "distance between the <em>kinds</em>, and whether the pair is a bundle bridge.</p>")
        o.append("<table><tr><th>dir</th><th>relation</th><th>endpoint types</th>"
                 "<th>lens</th><th>type_distance</th><th>bridge</th></tr>")
        for e in edges:
            t = e.get("tt") or {}
            td = t.get("type_distance") or {}
            br = t.get("bridge") or {}
            if t.get("state") != "derived":
                types = f"<span class=no>{esc(t.get('reason'))}</span>"
                lenscol = dist = brg = "<span class=no>untyped</span>"
            else:
                types = (f"<code>{esc(t.get('src_claim_type'))}</code> &rarr; "
                         f"<code>{esc(t.get('dst_claim_type'))}</code>")
                cross = t.get("lens_crossing")
                lenscol = (f"<span class={'unk' if cross else 'm'}>"
                           f"{esc(t.get('src_lens'))}&rarr;{esc(t.get('dst_lens'))}"
                           f"{' crosses' if cross else ''}</span>")
                if td.get("value") is not None:
                    dist = f"<b>{esc(td['value'])}</b>"
                else:
                    # NEVER a number and never 0 — the lenses are disjoint
                    # components of the bundle graph, so no path exists.
                    dist = f"<span class=unk>{esc(td.get('state','—'))}</span>"
                if br.get("bridge_related"):
                    brg = (f"<span class=m>{esc(br.get('relation'))}</span><br>"
                           f"<span class=note>{esc(br.get('direction'))}</span>")
                else:
                    brg = f"<span class=no>{esc(br.get('reason','—'))}</span>"
            o.append(f"<tr><td>{esc(e.get('direction'))}</td>"
                     f"<td><b>{esc(e.get('relation'))}</b></td>"
                     f"<td>{types}</td><td>{lenscol}</td><td>{dist}</td><td>{brg}</td></tr>")
        o.append("</table>")
        o.append("<p class=note><span class=unk>unreachable</span> is a real answer, not a "
                 "missing one: the two lenses are <b>disjoint components</b> of the bundle graph, "
                 "so no path exists between an A-lens and a B-lens type. It is never rendered as "
                 "a number and never as 0 &mdash; which is exactly why a cross-lens edge's only "
                 "meaningful taxonomic label is the bridge. "
                 "Distances carry TT's caveat: the 1.0/1.6 weights are design choices, not "
                 "values fitted to data.</p>")
    return "".join(o)


def render_images(eid):
    import time
    as_of = str(int(time.time()) - 946728000)
    query = urllib.parse.urlencode({'entity_id': eid, 'as_of': as_of})
    request = urllib.request.Request(NODE + '/v2/media?' + query,
        headers={'Authorization': 'Bearer ' + (node_key() or '')})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
    except Exception:
        return '<h2 id=images>Generated images</h2><p>Image catalog unavailable.</p>'
    if data.get('schema') != 'cc.media-readings.v2':
        return '<h2 id=images>Media decisions</h2><p>Typed media catalog unavailable.</p>'
    out = ['<h2 id=images>Media decisions by claim reading</h2>',
           '<p>Model interpretations and illustration decisions. Not historical evidence. Independently signed; outside historical ledger anchors.</p>',
           f'<p>Media visible as of {esc(data["as_of"])} ticks since J2000. Source bindings describe the current projection.</p>']
    if not data['readings']:
        out.append('<p>No readings visible for this query.</p>')
    labels = {'no_generation_recorded': 'No generation recorded',
              'deliberately_unillustrated': 'Deliberately unillustrated',
              'generated': 'Generated',
              'conflicting_media_records': 'Conflicting media records — inspect both decisions and images'}
    for reading in data['readings']:
        out.append(f'<section><h3>{esc(labels.get(reading["state"], reading["state"]))}</h3>'
                   f'<p>Source body: <code>{esc(reading["source_body_hash"])}</code> · {esc(reading["source_binding"])}</p>')
        for decision in reading['absence_decisions']:
            out.append(f'<p>Decision reason: {esc(decision["manifest"]["reason"])}</p>'
                       f'<details><summary>Signed absence decision</summary><pre>{esc(json.dumps(decision, indent=2))}</pre></details>')
        for entry in reading['images']:
            m = entry['manifest']
            digest = m['image_sha256']
            out.append(f'<article><h4>{esc(m["model"])}</h4><p>Training profile: {esc(m["permission_profile"])}</p>')
            out.append(f'<img style="max-width:100%;height:auto" src="/media-object?sha={esc(digest)}" alt="Synthetic interpretation of the recorded claim">')
            out.append(f'<details><summary>Full signed contribution</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">{esc(json.dumps(entry, indent=2))}</pre></details></article>')
        out.append('</section>')
    return ''.join(out)


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        route = urllib.parse.urlparse(self.path).path
        if route == '/media-object':
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            digest = query.get('sha', [''])[0]
            if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                self.send_error(400, 'Invalid image hash')
                return
            try:
                request = urllib.request.Request(NODE + '/v1/images/' + digest,
                    headers={'Authorization': 'Bearer ' + (node_key() or '')})
                with urllib.request.urlopen(request, timeout=30) as response:
                    raw = response.read(8 * 1024 * 1024 + 1)
                import hashlib
                if hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError('Image integrity failure')
            except Exception:
                self.send_error(503, 'Could not retrieve admitted image')
                return
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(raw)
            return
        if route in ('/image-preview', '/image-preview.png'):
            directory = os.environ.get('CC_IMAGE_PREVIEW_DIR')
            if not directory:
                self.send_error(404, 'No local image preview configured')
                return
            try:
                manifest, raw = image_preview.load(directory)
                body = raw if route.endswith('.png') else image_preview.page(manifest, raw)
            except (OSError, ValueError, KeyError):
                self.send_error(503, 'Local image preview failed its integrity check')
                return
            self.send_response(200)
            self.send_header('Content-Type', 'image/png' if route.endswith('.png') else 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            walk = None
            if self.path.startswith("/entity"):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                eid = q.get("id", [None])[0]
                if eid:
                    body = (f"<!doctype html><meta charset=utf-8><style>{CSS}</style>"
                            f"<main><p><a href='/'>&larr; back</a></p>"
                            f"{render_entity(eid)}{render_images(eid)}</main>").encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
            if self.path.startswith("/walk"):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                a, b = q.get("a", [None])[0], q.get("b", [None])[0]
                if a and b:
                    walk = render_walk(a, b)
            body = page(walk)
            code = 200
        except Exception as e:
            # Fail loud and legible. A browser that rendered an empty table on a
            # failed read would look like an empty ledger, which is the exact
            # absence-vs-error collapse the node itself refuses to make.
            body = (f"<!doctype html><meta charset=utf-8><style>{CSS}</style>"
                    f"<main><h2>could not read the ledger</h2>"
                    f"<pre style='color:#f7768e;white-space:pre-wrap'>{html.escape(str(e))}"
                    f"</pre><p class=note>This is an error, not an empty ledger. "
                    f"Check the configured local database and node connection.</p></main>").encode()
            code = 503
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # noqa: D102 - quiet
        pass


if __name__ == "__main__":
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    print(f"clockchain v4 browser  ->  http://localhost:{PORT}")
    print("reads the configured database; loopback access only")
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
