#!/usr/bin/env python3
"""Check our TT classification validator against TT's shipped conformance corpus.

    python3 ops/tt-differential.py

`crates/cc-migrator/src/classification.rs` is a PORT of TT's §4 contract. This
runs every vector in `timepoint-telemetry/vectors/classification-verdicts.json`
through our binary and reports the two tiers the corpus defines:

  NORMATIVE  accepted / normalized / the multiset of rejection CODES.
             An implementation matching these in any language conforms.
             A failure here is a conformance failure.

  ADVISORY   rejection DETAIL strings, byte for byte. TT's own words for this
             tier: "the details render numbers as Python's repr() does — that is
             reference-implementation habit made visible, not design." Ports may
             opt in. We do, because the strict diff is what caught all seven of
             our divergences; but a failure here is a divergence, not a breach.

## Why this file no longer owns its own cases

It used to carry 39 hand-written cases and diff live against `tt_validate.py`.
That made it the private definition of a contract TT owns. Telemetry adopted the
cases upstream, so this is now **enforcement of TT's corpus** — the vectors are
the authority, and if this file and the corpus disagree, the corpus wins.

The two-tier split exists because making detail strings normative would export
Python's numeric formatting to every consumer in every language, permanently.

No credentials, no database, no network. No host layout, no Railway.
"""

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
CC = HERE.parent
VENDOR_VECTORS = CC / "vendor" / "tt" / "classification-verdicts.json"


def find_vectors():
    """TT's corpus, from the crate checkout or the vendored pin. Never a home path."""
    env = os.environ.get("TT_VECTORS")
    if env:
        return Path(env)
    sibling = CC.parent / "timepoint-telemetry" / "vectors" / "classification-verdicts.json"
    for p in (VENDOR_VECTORS, sibling):
        if p.is_file():
            return p
    return VENDOR_VECTORS


def find_migrator():
    env = os.environ.get("CC_MIGRATOR")
    if env:
        return Path(env)
    for p in (CC / "target" / "debug" / "cc-migrator",
              CC / "target" / "release" / "cc-migrator"):
        if p.is_file():
            return p
    return CC / "target" / "debug" / "cc-migrator"


VECTORS = find_vectors()
MIGRATOR = find_migrator()


def run(payload):
    p = subprocess.run([MIGRATOR, "classify", "-"], input=json.dumps(payload),
                       capture_output=True, text=True, timeout=60)
    lines = [x for x in p.stderr.strip().splitlines() if x.startswith("rejected:")]
    parsed = []
    for line in lines:
        # "rejected: <code>: <detail>"
        rest = line[len("rejected: "):]
        code, _, detail = rest.partition(": ")
        parsed.append({"code": code, "detail": detail})
    return p.returncode == 0, p.stdout.strip(), parsed


def main():
    if not os.path.exists(MIGRATOR):
        print(f"build first: cargo build -p cc-migrator  (missing {MIGRATOR})", file=sys.stderr)
        return 2
    if not os.path.exists(VECTORS):
        print(f"TT vectors not found at {VECTORS}", file=sys.stderr)
        return 2

    doc = json.load(open(VECTORS))
    try:
        corpus = os.path.relpath(VECTORS, CC)
    except ValueError:
        corpus = str(VECTORS)
    print(f"corpus   {corpus}")
    print(f"bundle   {doc['bundle']}")
    print(f"vectors  {len(doc['vectors'])}\n")

    norm_fail, adv_fail = 0, 0
    for v in doc["vectors"]:
        want = v["expect"]
        accepted, out, rejections = run(v["input"])
        problems, advisory = [], []

        if accepted != want["accepted"]:
            problems.append(f"verdict: corpus says {'accept' if want['accepted'] else 'reject'}, "
                            f"ours {'accept' if accepted else 'reject'}")
        elif accepted:
            got = json.loads(out) if out else None
            if got != want["normalized"]:
                problems.append(f"normalized differs\n      corpus {json.dumps(want['normalized'])}"
                                f"\n      ours   {json.dumps(got)}")
        else:
            want_codes = Counter(r["code"] for r in want["rejections"])
            got_codes = Counter(r["code"] for r in rejections)
            if want_codes != got_codes:
                problems.append(f"codes differ\n      corpus {sorted(want_codes.elements())}"
                                f"\n      ours   {sorted(got_codes.elements())}")
            else:
                want_d = sorted((r["code"], r["detail"]) for r in want["rejections"])
                got_d = sorted((r["code"], r["detail"]) for r in rejections)
                if want_d != got_d:
                    for (wc, wd), (_, gd) in zip(want_d, got_d):
                        if wd != gd:
                            advisory.append(f"{wc}\n      corpus {wd!r}\n      ours   {gd!r}")

        if problems:
            norm_fail += 1
            print(f"  NORMATIVE FAIL  {v['name']}")
            for p in problems:
                print(f"    {p}")
        elif advisory:
            adv_fail += 1
            print(f"  advisory differs  {v['name']}")
            for a in advisory:
                print(f"    {a}")
        else:
            print(f"  ok  {v['name']}")

    n = len(doc["vectors"])
    print()
    print(f"NORMATIVE  {n - norm_fail}/{n}   (conformance; a failure here is a breach)")
    print(f"ADVISORY   {n - norm_fail - adv_fail}/{n}   (detail strings byte-for-byte; opt-in)")
    if norm_fail:
        print("\nFAIL — does not conform to TT's classification vectors")
        return 1
    if adv_fail:
        print("\nPASS on the normative tier; advisory divergences above are not a breach.")
        return 0
    print("\nPASS — conforms on both tiers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
