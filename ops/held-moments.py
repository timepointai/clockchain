#!/usr/bin/env python3
"""Reconcile moment EVENTS against moment ROWS, and name the gap.

    python3 ops/held-moments.py            # report; exit 1 if held > 0

M1b folds a supersession chain into one row, so `count(*) FROM moments` is
deliberately smaller than the number of moment events once corrections exist.
That gap is fine — and it is also exactly where a defect would hide, because
"fewer rows than events" is the signature of both a correct fold and a silent
drop. This decomposes it so the two cannot be confused:

    moment events
      = chains projected            (rows in `moments`)
      + links folded into a chain   (corrections; root != head)
      + rejected corrections        (lost a conflict; canonically later sibling)
      + HELD                        (ancestor referenced, never seen)
      + rows removed by hand        (ops/drop-inadmissible.sql)

**Held is the one that must never be silent.** A moment whose target has not
arrived is kept in `events` and projected nowhere; it is not dropped, and the
arrival of its target picks it up. Until then it is a signed claim this node
cannot show anyone, and nothing else on any surface reports it: `/health/deep`
publishes maintained counters and deliberately issues no COUNT(*) — v1's deep
check ran a full count per probe and became the thing it was watching — so this
question does not belong there. It belongs in a tool you run.

Read-only. Reports; never writes.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ccdb  # noqa: E402

MOMENT_KIND = 2

# One recursive walk, reused by every count below: for each moment event, climb
# `supersedes` and record where the climb stopped. The stop condition IS the
# classification, so the SQL and `chain_root()` in cc-ledger agree by having the
# same three cases rather than by two people remembering to keep them in step:
#
#   parent IS NULL                  -> well-rooted
#   parent present, not a moment    -> ill-formed lineage; its own root
#   parent absent from `events`     -> HELD
#
# ...plus a FOURTH case this walk needs and the Rust one does not: depth
# exhaustion. Found by telemetry's P1, which traced both walks case by case and
# agreed on every chain of depth <= 1023, then pinned the disagreement at the
# bound. `chain_root` spends one iteration per ascent, so a chain of length L
# needs L + 1 and it errors at exactly 1024 links; this CTE's `depth < 1024`
# guard still emits a depth-1024 row. Without the fourth bucket, that row is
# filed as 'rooted' (at 1024 links) or, worse, as 'ill_formed' with the WRONG
# root (at >= 1025, or a cycle) — because a truncated walk's parent is a present
# moment, which is indistinguishable from genuine ill-formed lineage unless the
# depth is checked FIRST.
#
# Unreachable on live data — 0 of 1176 events carry `supersedes` — and kept
# anyway, because "the two walks agree" is the claim this file's decomposition
# rests on, and it was not true at the boundary.
WALK = f"""
WITH RECURSIVE m AS (
    SELECT event_id, supersedes FROM events WHERE kind = {MOMENT_KIND}
), up(start_id, cur, parent, depth) AS (
    SELECT event_id, event_id, supersedes, 0 FROM m
  UNION ALL
    SELECT u.start_id, p.event_id, p.supersedes, u.depth + 1
      FROM up u JOIN m p ON p.event_id = u.parent
     WHERE u.depth < 1024
), term AS (
    SELECT DISTINCT ON (start_id) start_id, cur AS root, parent, depth
      FROM up ORDER BY start_id, depth DESC
), cls AS (
    SELECT t.*,
           -- Depth FIRST. A truncated walk's parent is a present moment, which
           -- is indistinguishable from ill-formed lineage once you have stopped
           -- looking at how you got there.
           CASE WHEN t.depth >= 1024
                     AND EXISTS (SELECT 1 FROM m p WHERE p.event_id = t.parent)
                     THEN 'exceeds_bound'
                WHEN t.parent IS NULL THEN 'rooted'
                WHEN EXISTS (SELECT 1 FROM events e WHERE e.event_id = t.parent)
                     THEN 'ill_formed'
                ELSE 'held' END AS state
      FROM term t
)
"""

QUERIES = {
    # The decomposition. Every moment event lands in exactly one bucket.
    "summary": WALK + """
        SELECT 'moment_events', count(*)::text FROM cls
        UNION ALL SELECT 'held', count(*)::text FROM cls WHERE state = 'held'
        UNION ALL SELECT 'projectable_chains',
                         count(DISTINCT root)::text FROM cls WHERE state <> 'held'
        UNION ALL SELECT 'ill_formed_lineage', count(*)::text FROM cls WHERE state = 'ill_formed'
        UNION ALL SELECT 'exceeds_bound', count(*)::text FROM cls WHERE state = 'exceeds_bound'
        UNION ALL SELECT 'rows_present', count(*)::text FROM moments
        UNION ALL SELECT 'rows_corrected', count(*)::text FROM moments
                         WHERE root_event_id <> head_event_id
        UNION ALL SELECT 'stats_moment_count', moment_count::text FROM ledger_stats
    """,
    # Held events, with what they are waiting for. Listed, not just counted: a
    # count tells you something is wrong and a list tells you what to go find.
    "held": WALK + """
        SELECT encode(c.start_id,'hex'), encode(c.parent,'hex'), c.depth::text
          FROM cls c WHERE c.state = 'held' ORDER BY c.start_id LIMIT 200
    """,
    # Chains that projected: the corrections, walkable root -> head.
    "chains": """
        SELECT encode(m.root_event_id,'hex'), encode(m.head_event_id,'hex'),
               m.subject::text, coalesce(e.canonical_name,'(entity absent)')
          FROM moments m LEFT JOIN entities e ON e.entity_id = m.subject
         WHERE m.root_event_id <> m.head_event_id
         ORDER BY m.record_coord DESC LIMIT 200
    """,
    # Rejected corrections: a moment that is not a root, and is not the child
    # its parent's chain actually followed. The docstring named this bucket from
    # the start and the summary never computed it — telemetry's P2. It was
    # reachable only by subtraction, which is not a report, and this is the
    # bucket that hides the most dangerous mistake a writer can make here:
    # superseding the ROOT of an already-corrected moment instead of its HEAD.
    # The loser is stored, signed, durable and invisible.
    "rejected": WALK + """
        SELECT encode(c.start_id,'hex'), encode(c.parent,'hex')
          FROM cls c
         WHERE c.state <> 'held' AND c.parent IS NOT NULL
           AND c.start_id <> (
                 SELECT e.event_id FROM events e
                  WHERE e.supersedes = c.parent AND e.kind = 2
                  ORDER BY e.event_time, e.event_id LIMIT 1)
         ORDER BY 1 LIMIT 200
    """,
    # Subjects carrying more than one LIVE moment. Detection only: TT ruled that
    # no automatic resolution is permitted, so this reports the pair and whether
    # the two bodies share a content_hash, and stops there. Same-hash means one
    # claim with two readings; different means two claims. Neither may be merged
    # by a tool. The defect this closes is that nobody was looking — the query is
    # one GROUP BY and nothing ran it.
    "multi": """
        select e.canonical_name, encode(m.body_hash,'hex'),
               cb.body::json->>'title', cb.body::json->>'year'
          from moments m
          join entities e on e.entity_id = m.subject
          left join claim_bodies cb on cb.body_hash = m.body_hash
         where m.subject <> 0
           and m.subject in (select subject from moments where subject <> 0
                              group by subject having count(*) > 1)
         order by e.canonical_name, m.record_coord
    """,
    # Projectable roots with no row. Not a fold artefact — something removed
    # them, which on this chain means ops/drop-inadmissible.sql.
    "missing": WALK + """
        SELECT encode(c.root,'hex')
          FROM (SELECT DISTINCT root FROM cls WHERE state <> 'held') c
         WHERE NOT EXISTS (SELECT 1 FROM moments m WHERE m.root_event_id = c.root)
         ORDER BY 1 LIMIT 200
    """,
}


def content_hash(title, year):
    """`content_hash` for a claim, matching `tt-core`'s RFC 8785 canonicalisation.

    The hashed payload is the frozen three-tuple {label, occurs_at, participants}
    and nothing else — summary, provenance and classification all sit outside it.
    Verified against timepoint-telemetry's independent implementation on Storming
    of the Bastille before being trusted here.
    """
    import hashlib
    payload = {"label": title, "occurs_at": str(year), "participants": []}
    return "sha256:" + hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False,
                   sort_keys=True).encode()).hexdigest()


def fetch():
    """Run every query in one round trip, split on the \\echo markers.

    Connection comes from `ccdb`, which takes it from CC_DATABASE_URL or a
    discovered railway link — never from a path hardcoded in this file. The
    three checks that used to carry one could only ever be run by their author.
    """
    script = "\n".join(f"\\echo ===={n}\n{q};" for n, q in QUERIES.items())
    out = ccdb.run(script)
    if "====" not in out:
        raise ccdb.Unreachable("no section markers in output — the query did not run")
    blocks, cur = {}, None
    for line in out.splitlines():
        if line.startswith("===="):
            cur = line[4:].strip()
            blocks[cur] = []
        elif cur is not None and line.strip():
            blocks[cur].append(line.split(ccdb.SEP))
    return blocks


def main():
    b = fetch()
    s = {k: v for k, v in (r for r in b["summary"])}
    n = lambda k: int(s.get(k, "0"))

    print("moment events vs moment rows")
    print(f"  moment events         {n('moment_events'):>6}")
    print(f"  projectable chains    {n('projectable_chains'):>6}   (expected rows)")
    print(f"  rows present          {n('rows_present'):>6}")
    print(f"  of which corrected    {n('rows_corrected'):>6}   (root != head)")
    print(f"  ill-formed lineage    {n('ill_formed_lineage'):>6}   (superseded a non-moment)")
    print(f"  rejected corrections  {len(b.get('rejected', [])):>6}   (lost to an earlier sibling)")
    print(f"  exceeds MAX_CHAIN     {n('exceeds_bound'):>6}   (walk truncated at 1024)")
    print(f"  HELD                  {n('held'):>6}   (ancestor never seen)")
    print(f"  ledger_stats          {n('stats_moment_count'):>6}")

    fail = False

    # The invariant /health/deep publishes against. It broke once — 351 served
    # over a table holding 321 — because ledger_stats has no decrement path and
    # a projection delete does not touch it.
    if n("stats_moment_count") != n("rows_present"):
        print(f"\nFAIL  ledger_stats.moment_count ({n('stats_moment_count')}) != "
              f"count(*) FROM moments ({n('rows_present')})")
        print("      /health/deep is publishing a number the table contradicts.")
        print("      Remedy: the counter resync at the end of ops/drop-inadmissible.sql.")
        fail = True

    missing = b.get("missing", [])
    if missing:
        print(f"\n{len(missing)} projectable root(s) with no row — removed by hand, not folded:")
        for r in missing[:20]:
            print(f"    {r[0]}")
        print("      Expected if ops/drop-inadmissible.sql has run and nothing has")
        print("      rebuilt since. Unexpected otherwise — check ops/check-admission.py.")

    if n("exceeds_bound"):
        fail = True
        print(f"\nFAIL  {n('exceeds_bound')} moment(s) exceed MAX_CHAIN=1024.")
        print("      The Rust projector REFUSES these at commit — an event this deep")
        print("      never entered `events`, so seeing any here means this walk and")
        print("      cc-ledger's disagree. Do not reconcile by adjusting this file.")

    rejected = b.get("rejected", [])
    if rejected:
        print(f"\n{len(rejected)} REJECTED correction(s) — signed, durable, invisible:")
        for r in rejected[:20]:
            print(f"    {r[0]}  lost to an earlier sibling of  {r[1]}")
        print("      Almost always the same mistake: a correction superseded the ROOT of")
        print("      an already-corrected moment instead of its HEAD. The canonically")
        print("      LATER sibling loses. Re-mint against the current head_event_id.")

    held = b.get("held", [])
    if held:
        fail = True
        print(f"\n{len(held)} HELD moment(s) — signed, durable, projected nowhere:")
        for r in held[:20]:
            print(f"    {r[0]}  waiting on  {r[1]}  (depth {r[2]})")
        print("      These are not lost. They project the moment their ancestor arrives.")
        print("      Non-zero here on a single-writer chain means a correction was minted")
        print("      against an event id that was never committed — check the minting run.")

    chains = b.get("chains", [])
    if chains:
        print(f"\n{len(chains)} corrected moment(s), root -> head:")
        for r in chains[:20]:
            print(f"    subject {r[2]:>6}  {r[3][:44]}")
            print(f"      {r[0][:16]}...  ->  {r[1][:16]}...")

    multi = b.get("multi", [])
    if multi:
        from collections import defaultdict
        g = defaultdict(list)
        for r in multi:
            if len(r) >= 4:
                g[r[0]].append((r[1], r[2], r[3]))
        print(f"\n{len(g)} subject(s) carrying more than one live moment:")
        for name, items in g.items():
            hs = [content_hash(t, y) for _, t, y in items]
            same = len(set(hs)) == 1
            verdict = ("one claim, two readings" if same
                       else "TWO DISTINCT CLAIMS on one subject")
            print(f"    {name[:50]}  ({len(items)} rows)  {verdict}")
            for (bh, t, y), h in zip(items, hs):
                print(f"      body {bh[:16]}  {h[:23]}…  title={t!r} year={y}")
            if not same:
                print("      ^ different content_hash on one entity — look at this.")
        print("      Reported, never resolved: TT permits keeping both or superseding")
        print("      one by a recorded decision, and bars collapsing by picking one.")

    if not fail:
        print("\nPASS  every moment event is accounted for")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
