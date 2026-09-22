#!/usr/bin/env python3
"""Do the pre-registered anchors still describe claims this corpus contains?

    python3 ops/check-anchors.py            # exit 1 if any anchor has moved

`the_pre_registered_hashes_reproduce` in `crates/cc-node/src/tt.rs` asserts that
`content_hash(title, year)` reproduces three digests timepoint-telemetry
registered before either side built. It computes them from **title and year
literals written in the test**, so it proves the hash function is stable. It
does **not** prove the corpus still carries those titles and those years.

The gap that opens: if a hand-correction ever changed an anchor's title or year,
that test keeps passing, and the pre-registration silently stops being about the
corpus it was registered against. The hash would still be correct — correct
about a claim that no longer exists. A true numerator over a denominator that
moved, in the one place both sides treat as an anchor.

Telemetry found it, and the census is what made it non-hypothetical: two of the
three anchors — End of Apartheid and Mani Is Executed for Heresy — are among the
five entities corrected by hand, and **four of nine hand-corrections left no
record at all**. The convention that would have flagged a title change is the
same one missing 44% of the time. Nothing is perturbed today; both corrections
were classification-tier and outside `content_hash` by construction. The test
simply would not have told us either way, which is the property that matters.

**Decomposition, so neither check pretends to be the other:**

  the Rust unit test  ->  the hash function is stable given (title, year)
  this check          ->  the corpus still contains those (title, year)
  together            ->  the pre-registered digest still describes a live claim

**The anchors are PARSED from `tt.rs`, never copied here.** A second list would
be a second copy with no owner, which is the defect this repository has bought
five times. If the test's tuples change, this reads the new ones; if the test is
deleted, this fails loudly rather than checking a list nobody maintains.

Read-only. Reports; never writes.
"""

import os
import pathlib
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ccdb  # noqa: E402

TT_RS = pathlib.Path(__file__).resolve().parent.parent / "crates/cc-node/src/tt.rs"

# Matches the (title, year, "sha256:...") tuples inside the test. Deliberately
# anchored on the digest literal so prose mentioning a title cannot be scooped
# up as an anchor.
TUPLE = re.compile(
    r'"((?:[^"\\]|\\.)+)"\s*,\s*(-?\d+)\s*,\s*"(sha256:[0-9a-f]{64})"',
    re.S,
)


def anchors():
    """The tuples inside the test, delimited by BRACE MATCHING, not a window.

    A fixed `src[start : start + 4000]` window sat here and failed in both
    directions at once — telemetry found both, measured rather than argued:

      * **Over-read.** The window ran 3266 characters past the function's
        closing brace. A neighbouring test containing a
        `(string, int, "sha256:…")` tuple would have been silently adopted as a
        fourth anchor, which is a plausible thing to write in a file about
        content hashes. The regex guard was aimed at prose, and prose was never
        the risk.
      * **Under-read.** At ~120 chars per tuple the window held about 27 more
        anchors before truncating. When it did, `found` would be non-empty, the
        empty-parse guard would not fire, and the check would validate a SUBSET
        and print PASS — a true numerator over an unstated denominator, inside
        the tool written to close a true-numerator-over-unstated-denominator
        gap. Sixth costume of the same defect.

    Brace matching is exact in both directions and has no constant to tune. The
    span is whatever the function is (693 chars today) rather than a number
    chosen to feel comfortably large.

    Telemetry also suggested a belt-and-braces cross-check: file-wide count of
    `sha256:` literals should equal the parsed count. **Measured before adopting
    it, and it would already fail** — the file has 4, because `content_hash`'s
    own doc comment contains the literal `"sha256:" + hex`. A secondary check
    that false-alarms on day one is worse than none.
    """
    src = TT_RS.read_text()
    start = src.find("fn the_pre_registered_hashes_reproduce")
    if start < 0:
        raise SystemExit(
            "FAIL  the_pre_registered_hashes_reproduce is gone from tt.rs. This check "
            "reads its anchors; it will not invent a list of its own."
        )
    open_brace = src.find("{", start)
    if open_brace < 0:
        raise SystemExit("FAIL  found the test but no opening brace — the scan has broken.")
    depth, end = 0, -1
    for i in range(open_brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        raise SystemExit(
            "FAIL  the test's braces do not balance — refusing to guess where it ends."
        )
    body = src[open_brace : end + 1]
    found = [(t, int(y), h) for t, y, h in TUPLE.findall(body)]
    if not found:
        raise SystemExit(
            "FAIL  found the test but parsed no (title, year, digest) tuples — the "
            "scan has broken, or the test's shape changed. Not reporting a pass."
        )
    return found


def rows(sql):
    """Connection from `ccdb`; this file no longer knows where the database is."""
    return ccdb.rows(sql)


def main():
    a = anchors()
    print(f"{len(a)} anchor(s) parsed from tt.rs:")
    for t, y, h in a:
        print(f"  {t}  ({y})  {h[:22]}…")

    titles = ",".join("'" + t.replace("'", "''") + "'" for t, _, _ in a)
    # Built as a LIST, then checked for duplicates, rather than collapsed into a
    # dict. The query joins `moments`, so an entity with more than one moment
    # yields more than one row, and a dict comprehension keyed on the title would
    # silently keep whichever came last — reporting on an arbitrary body with no
    # way to say it had. Two bodies for one anchor is itself something worth
    # hearing about, so it fails rather than picks. Telemetry's catch.
    fetched = [
        (r[0], r[1], r[2])
        for r in rows(f"""
            select e.canonical_name,
                   cb.body::json->>'title',
                   cb.body::json->>'year'
              from moments m
              join claim_bodies cb on cb.body_hash = m.body_hash
              join entities e on e.entity_id = m.subject
             where e.canonical_name in ({titles});
        """)
    ]
    dupes = {n for n in (f[0] for f in fetched)
             if [x[0] for x in fetched].count(n) > 1}
    if dupes:
        for n in sorted(dupes):
            print(f"\nFAIL  {n!r} returned multiple live bodies:")
            for f in fetched:
                if f[0] == n:
                    print(f"        title={f[1]!r} year={f[2]!r}")
        print("      An anchor with two live bodies cannot be checked against one")
        print("      pre-registered digest. Resolve the corpus before this check runs.")
        return 1
    live = {n: (t, y) for n, t, y in fetched}

    fail = False
    print("\nagainst the live corpus:")
    for title, year, digest in a:
        got = live.get(title)
        if got is None:
            print(f"  MOVED   {title!r} is pre-registered and is NOT in the corpus")
            print(f"          the digest {digest[:22]}… now describes no live claim")
            fail = True
            continue
        got_title, got_year = got
        if got_title != title or str(got_year) != str(year):
            print(f"  MOVED   {title!r} ({year}) -> stored as {got_title!r} ({got_year})")
            print(f"          a hashed field changed; {digest[:22]}… no longer describes it")
            fail = True
        else:
            print(f"  intact  {title!r} ({year})")

    if fail:
        print("\nFAIL  an anchor has moved. The Rust test will still pass — it computes")
        print("      from its own literals — so fix the corpus or re-register, and do")
        print("      not reconcile by editing the literal to match.")
        return 1
    print("\nPASS  every pre-registered anchor still describes a live claim")
    return 0


if __name__ == "__main__":
    sys.exit(main())
