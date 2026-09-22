#!/usr/bin/env python3
"""Verify the published (head_event_id, author_key, signature) triple.

    CC_GALLERY_KEY=... python3 ops/verify-triple.py        # exit 1 on any failure

**This is the check a consumer performs, run against what the API actually
sends** — not an assertion about a column, and not a re-derivation using this
repository's own code. It hex-decodes the three fields out of `/v1/recents` and
runs stock Ed25519 over them, the way a reader with a crypto library and no
knowledge of our canon would.

Why it exists as a script rather than a test: the defect it guards against
shipped once and was invisible to every test in the projector, because those
tests all checked the column against what the projector meant. M1b first
attributed a folded row's `author_key` to the chain ROOT, matching the schema's
"first-seen proposer" comment. `/v1/recents` joins `signature` from the event
`head_event_id` names, so every corrected moment would have carried a key that
did not sign the id beside it — and the API would have kept returning 200.

Why it lives on OUR credential: timepoint-telemetry asked for this in their
daily gate, and their key is scoped to /v1/entities + /v1/feasibility. It cannot
reach /v1/recents, which is gallery scope. Widening a credential is Sean's call
and nobody else's, so the answer is not to widen it — it is to run the check
here and let telemetry read the output. Printed, never typed.

The verification proves ONE thing: the holder of `author_key` signed that event
id. It does NOT prove the printed fields are the content behind that id — that
needs SHA-256 over the canon, which is not reachable from JSON. The API says so
in its own `verification` block and so does this.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE = os.environ.get("CC_BASE_URL", "http://127.0.0.1:18080")
# Clock Zero is 2000-01-01T00:00:00Z; a tick is a second.
CLOCK_ZERO = 946728000
KEY = os.environ.get("CC_GALLERY_KEY") or os.environ.get("CC_NODE_KEY")
LIMIT = int(os.environ.get("CC_VERIFY_LIMIT", "25"))


def fetch(path):
    req = urllib.request.Request(BASE + path,
                                 headers={"Authorization": f"Bearer {KEY}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def moment_total():
    """`(moment_count, None)`, or `(None, reason)` when it could not be read.

    Returns the REASON rather than a bare `None`, because the caller prints one.
    A bare `None` forced the caller to assert a cause it did not know, and "not
    readable with this key" was then printed for a 401, a moved JSON field, a
    DNS failure and a timeout alike — three of those four being false. An
    unstated denominator makes a reader ask; an incorrectly-explained one makes
    them stop asking, which is worse. Telemetry's catch.


    Deliberately optional and deliberately not a reason to widen anything: the
    gallery credential this script normally runs under cannot reach
    /health/deep, and the honest degradation is to name the denominator as
    unknown rather than to acquire a credential that would make the sentence
    shorter.
    """
    key = os.environ.get("CC_NODE_KEY")
    if not key:
        return None, "no credential that can read /health/deep was supplied"
    try:
        req = urllib.request.Request(BASE + "/health/deep",
                                     headers={"Authorization": f"Bearer {key}"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)["ledger"]["moment_count"], None
    except urllib.error.HTTPError as e:
        # 401 is the ONLY case that means "this key cannot read it". Everything
        # else is a different fact wearing the same absence.
        if e.code == 401:
            return None, "not readable with this key (401)"
        return None, f"/health/deep returned {e.code}"
    except Exception as e:
        return None, f"unreadable: {type(e).__name__}: {e}"


def main():
    if not KEY:
        print("set CC_GALLERY_KEY (or CC_NODE_KEY) — refusing to report a pass "
              "for a check that did not run", file=sys.stderr)
        return 1
    # `as_of` is REQUIRED and its absence is a 400, deliberately: a read with no
    # coordinate is a malformed request, never a read of the current time. The
    # first version of this script omitted it and got exactly that 400 — written
    # without reading the contract this repository publishes. It is recorded
    # here rather than quietly fixed, because the script refusing to report a
    # pass for a check that did not run is the only reason it was noticed at all.
    as_of = int(time.time()) - CLOCK_ZERO
    try:
        doc = fetch(f"/v1/recents?as_of={as_of}&limit={LIMIT}")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = " " + e.read().decode()[:200]
        except Exception:
            pass
        print(f"FAIL  /v1/recents returned {e.code} — the check did not run{detail}",
              file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError) as e:
        # A network failure used to come out as a traceback. A traceback is a
        # refusal that has not decided what it is refusing: the operator has to
        # read a stack to learn "the host did not answer", and a wrapper reading
        # only the exit code cannot tell it from a verification failure.
        print(f"FAIL  could not reach {BASE} — the check did not run: "
              f"{type(e).__name__}: {e}", file=sys.stderr)
        return 1

    entries = doc.get("entries", [])
    if not entries:
        print("FAIL  /v1/recents returned no entries; nothing was verified", file=sys.stderr)
        return 1

    ok = bad = 0
    corrected = 0
    for e in entries:
        root, head = e["root_event_id"], e["head_event_id"]
        if root != head:
            corrected += 1
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(e["author_key"])).verify(
                bytes.fromhex(e["signature"]), bytes.fromhex(head))
            ok += 1
        except (InvalidSignature, ValueError) as exc:
            bad += 1
            print(f"FAIL  {head[:16]}...  {type(exc).__name__}")
            print(f"      author_key {e['author_key'][:16]}...  "
                  f"root {root[:16]}...  {'CORRECTED' if root != head else 'uncorrected'}")

    # THE DENOMINATOR, stated before the number it qualifies.
    #
    # "verified 25/25 published triples" reads as a statement about the
    # published triples. It is a statement about ONE PAGE of them — RECENTS_MAX
    # caps this endpoint at 50 and the ledger holds several hundred moments.
    # timepoint-telemetry named the ceiling on their first direct run and asked
    # for it on the record before either of us quoted the figure, which is the
    # correct order: this week has produced several accurate-but-wrong
    # measurements and every one of them was a true numerator over an unstated
    # denominator.
    total, why = moment_total()
    # `if total` treats a moment_count of ZERO as absent — the same defect as
    # reading `grep -c` over a command that produced no output, reintroduced
    # inside the commit that fixed denominators. The one moment it would
    # misreport is an empty corpus, which is exactly when someone needs to know.
    scope = f"{len(entries)} of {total} moments" if total is not None else \
            f"{len(entries)} moments (ledger total unknown: {why})"
    print(f"verified {ok}/{len(entries)} triples with stock Ed25519 — {scope}")
    print("  THIS IS THE FRESHEST PAGE, NOT THE CORPUS. It does not verify the ledger.")
    print(f"  of which corrected moments (root != head): {corrected}")
    print(f"  corpus_digest {doc.get('corpus_digest', '?')}")
    print("  proves: the holder of author_key signed that event id")
    print("  does NOT prove: that the printed fields are the content behind it")
    print("  does NOT prove: anything about moments outside this page")

    if bad:
        print(f"\nFAIL  {bad} triple(s) did not verify.")
        print("      If the failures are exactly the corrected moments, `author_key`")
        print("      has drifted back to root attribution — see project_moment's")
        print("      attribution note and the_published_triple_verifies_for_a_corrected_moment.")
        return 1
    if corrected == 0:
        print("\nPASS  — but note NO corrected moment was in this sample, so the")
        print("      case this check exists for was not exercised. That is expected")
        print("      while the chain carries no supersession; it stops being expected")
        print("      the moment held-moments.py reports a non-zero corrected count.")
    else:
        print("\nPASS  including corrected moments")
    return 0


if __name__ == "__main__":
    sys.exit(main())
