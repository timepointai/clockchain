"""Graph rendering and the live walk, for browse-v4.py.

Tables of nodes with a degree column do not show a graph. The point of v4 is
that the filter WALKS causally, so the browser has to draw the walk.

Two things here:

  components() — connected components from the edge set, laid out left-to-right
                 in time order and drawn as SVG boxes and arrows. Chains read
                 the way causation reads: earlier on the left, arrow to later.

  walk()       — the acceptance test as a button. Picks two connected entities,
                 runs the REAL feasibility query against the live node, and
                 renders the verdict with the events it consulted. This is the
                 most convincing panel because it is not a diagram OF the
                 mechanism, it IS the mechanism answering.
"""

import html
import json
import urllib.request

RELATION = {0: "co-occurrence", 1: "influence", 2: "causation",
            3: "participation", 4: "attestation", 5: "supersession"}
EVIDENCE = {0: "primary document", 1: "secondary source",
            2: "inference", 3: "assertion"}
# Asserted causation is coloured as ASSERTED, never as fact. A model said so.
REL_COLOR = {2: "#f0c674", 1: "#7aa2f7", 0: "#6b7280"}


def esc(x):
    return html.escape(str(x) if x is not None else "")


def build(blocks):
    """{id: {name, year, unknown_start}}, [(src, dst, rel, ev)]"""
    nodes, years = {}, {}
    for r in blocks.get("bodies", []):
        sid, name, body = r[0], r[1], (r[2] if len(r) > 2 else None)
        if body:
            try:
                years[sid] = json.loads(body).get("year")
            except Exception:
                pass
    for r in blocks.get("entities", []):
        eid, name, ss = r[0], r[1], r[2]
        nodes[eid] = {"name": name, "year": years.get(eid),
                      "unknown": ss == "1"}
    edges = [(r[0], r[1], int(r[4]), int(r[5])) for r in blocks.get("edges", [])]
    return nodes, edges


def components(nodes, edges):
    """Connected components, largest first. Isolated nodes are NOT components —
    they are the unconnected majority and get counted, not drawn."""
    adj = {}
    for s, d, _r, _e in edges:
        adj.setdefault(s, set()).add(d)
        adj.setdefault(d, set()).add(s)
    seen, comps = set(), []
    for n in adj:
        if n in seen:
            continue
        stack, group = [n], []
        seen.add(n)
        while stack:
            c = stack.pop()
            group.append(c)
            for nb in adj.get(c, ()):
                if nb not in seen:
                    seen.add(nb)
                    stack.append(nb)
        comps.append(group)
    comps.sort(key=len, reverse=True)
    return comps, seen


def svg_component(group, nodes, edges, idx):
    """One chain, left to right in time order."""
    members = set(group)
    ce = [e for e in edges if e[0] in members and e[1] in members]
    # Time order is the honest x-axis for a causal chain. A node with no year
    # sorts last rather than being placed at an invented coordinate.
    ordered = sorted(group, key=lambda n: (nodes[n]["year"] is None,
                                           nodes[n]["year"] or 0))
    pos = {n: i for i, n in enumerate(ordered)}
    BW, BH, GAP, TOP = 210, 54, 66, 40
    W = max(1, len(ordered)) * (BW + GAP) + 40
    H = TOP + BH + 90
    o = [f'<svg viewBox="0 0 {W} {H}" style="width:100%;height:auto;'
         f'max-width:{W}px" xmlns="http://www.w3.org/2000/svg">']
    o.append('<defs>')
    for rel, col in REL_COLOR.items():
        o.append(f'<marker id="a{idx}_{rel}" viewBox="0 0 10 10" refX="9" refY="5" '
                 f'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
                 f'<path d="M0,0 L10,5 L0,10 z" fill="{col}"/></marker>')
    o.append('</defs>')

    for s, d, rel, ev in ce:
        x1 = 20 + pos[s] * (BW + GAP) + BW
        x2 = 20 + pos[d] * (BW + GAP)
        y = TOP + BH / 2
        col = REL_COLOR.get(rel, "#6b7280")
        back = x2 < x1
        # An arrow that points backwards in time is drawn as an arc rather than
        # hidden: it means the model asserted a cause later than its effect, and
        # that is worth seeing, not smoothing away.
        if back:
            o.append(f'<path d="M{x1 - BW},{y + BH/2} C{x1 - BW},{y + 58} '
                     f'{x2 + BW},{y + 58} {x2 + BW},{y + BH/2}" fill="none" '
                     f'stroke="{col}" stroke-width="1.5" stroke-dasharray="4 3" '
                     f'marker-end="url(#a{idx}_{rel})"/>')
            tx, ty = (x1 - BW + x2 + BW) / 2, y + 62
        else:
            o.append(f'<line x1="{x1}" y1="{y}" x2="{x2 - 4}" y2="{y}" '
                     f'stroke="{col}" stroke-width="1.5" '
                     f'marker-end="url(#a{idx}_{rel})"/>')
            tx, ty = (x1 + x2) / 2, y - 8
        o.append(f'<text x="{tx}" y="{ty}" fill="{col}" font-size="10" '
                 f'text-anchor="middle" font-family="ui-monospace,monospace">'
                 f'{esc(RELATION.get(rel, rel))}</text>')

    for n in ordered:
        x = 20 + pos[n] * (BW + GAP)
        nd = nodes[n]
        yr = nd["year"]
        label = ("unknown" if nd["unknown"] or yr is None
                 else (f"{abs(int(yr))} BC" if int(yr) < 0 else str(yr)))
        stroke = "#3a4152" if not nd["unknown"] else "#4a3f2a"
        o.append(f'<rect x="{x}" y="{TOP}" width="{BW}" height="{BH}" rx="4" '
                 f'fill="#151922" stroke="{stroke}"/>')
        name = nd["name"]
        line = name if len(name) <= 27 else name[:26] + "…"
        o.append(f'<text x="{x + 10}" y="{TOP + 22}" fill="#d7dae0" font-size="11.5" '
                 f'font-family="ui-monospace,monospace">{esc(line)}</text>')
        o.append(f'<text x="{x + 10}" y="{TOP + 40}" fill="#6b7280" font-size="10.5" '
                 f'font-family="ui-monospace,monospace">{esc(label)}</text>')
        o.append(f'<text x="{x + BW - 10}" y="{TOP + 40}" fill="#6ee7a8" font-size="10" '
                 f'text-anchor="end" font-family="ui-monospace,monospace">'
                 f'walk</text>')
    o.append("</svg>")
    return "".join(o), ordered


def feasibility(node_url, key, a, b, claim, as_of):
    # Preserve the browser's legacy numeric spelling while permitting TT labels.
    if isinstance(claim, str) and claim.isdecimal():
        claim = int(claim)
    body = json.dumps({"subjects": [int(a), int(b)],
                       "as_of": str(as_of), "claim": claim}).encode()
    req = urllib.request.Request(f"{node_url}/v1/feasibility", data=body,
                                 headers={"Authorization": f"Bearer {key}",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)
