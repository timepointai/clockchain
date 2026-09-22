#!/usr/bin/env python3
"""The Clockchain validator — integrity axis.

    python3 ops/validate.py                    # everything reachable
    CC_DATABASE_URL=postgres://… ops/validate.py

**Integrity only, deliberately.** Sean's three axes are integrity, quality and
usefulness; quality and usefulness are tabled until this one runs clean, because
a rubric written before the well-formedness checks work would be scoring a
corpus nobody had verified is well-formed.

This composes checks that already exist rather than reimplementing them, and it
runs each as a subprocess rather than importing it. That is the deliberate
choice: every check stays independently runnable and independently readable, so
a second party can run one without running all, and this file cannot become the
only way to ask a question. A runner that swallows its checks is a second copy
of them.

**It reports; it never resolves.** Nothing here writes to the chain. The one
check that could tempt a fix — subjects carrying two live moments — is
report-only by TT ruling, and the resolution it permits (supersede by recorded
decision) is a human act.

Exit code is the AND of its parts: 0 only if every check that ran passed, and a
check that could not run is a failure, never a pass. `verify-triple` needs a
gallery credential and is skipped-as-failure without one rather than quietly
omitted, because a validator that silently drops a check reports a clean corpus
it did not inspect.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ccdb  # noqa: E402

CHECKS = [
    ("media",
     "every image source body is still projected by some moment",
     ["check-media.py"], "CC_DATABASE_URL"),
    ("admission",
     "every stored claim still satisfies the strict gate",
     ["check-admission.py"], None),
    ("anchors",
     "the pre-registered digests still describe live claims",
     ["check-anchors.py"], None),
    ("moments",
     "moment events reconcile against moment rows; held, rejected, duplicated",
     ["held-moments.py"], None),
    ("triple",
     "the published (head_event_id, author_key, signature) verifies under stock Ed25519",
     ["verify-triple.py"], "CC_GALLERY_KEY"),
]


def main():
    if len(sys.argv) > 1:
        if len(sys.argv) == 3 and sys.argv[1] == "--fixture":
            return subprocess.run([sys.executable, os.path.join(HERE, "evidence_eval.py"), sys.argv[2]]).returncode
        print("usage: validate.py [--fixture evidence.json]", file=sys.stderr)
        return 2
    print("Clockchain validator — integrity")
    print(f"  reaching the chain by: {ccdb.describe()}")
    if ccdb.describe() == "UNREACHABLE":
        print("\nFAIL  no database. Set CC_DATABASE_URL to a connection string.")
        print("      Refusing to report on a corpus this cannot read.")
        return 1

    results = []
    for name, what, argv, needs in CHECKS:
        if needs and not os.environ.get(needs):
            results.append((name, "NOT RUN", f"{needs} is unset"))
            print(f"\n── {name}: NOT RUN ({needs} unset) — counted as a failure")
            continue
        print(f"\n── {name} · {what}")
        r = subprocess.run([sys.executable, os.path.join(HERE, *argv)],
                           capture_output=True, text=True)
        out = (r.stdout or "") + (r.stderr or "")
        for line in out.splitlines():
            print(f"   {line}")
        results.append((name, "PASS" if r.returncode == 0 else "FAIL", ""))

    print("\n" + "─" * 62)
    width = max(len(n) for n, _, _ in results)
    for name, verdict, note in results:
        print(f"  {name:<{width}}  {verdict}{('  — ' + note) if note else ''}")

    bad = [n for n, v, _ in results if v != "PASS"]
    if bad:
        # Named, not counted: a count tells you something is wrong and a list
        # tells you what to go and look at.
        print(f"\nFAIL  {', '.join(bad)}")
        return 1
    print(f"\nPASS  {len(results)} checks, all green")
    print("      Integrity only. Quality and usefulness are not measured here and")
    print("      a green result says nothing about either.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
