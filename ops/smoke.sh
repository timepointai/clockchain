#!/usr/bin/env bash
# Smoke checks for ops/. Catches the failure that actually happens: a script
# that has rotted or gained a syntax error and is only discovered mid-incident,
# when you least want to be debugging your own tooling.
#
# Deliberately does NOT touch a database or Railway — it must be runnable
# anywhere, including CI, with no credentials.
set -euo pipefail
cd "$(dirname "$0")"
fail=0
ok(){ printf "  ok    %s\n" "$1"; }
bad(){ printf "  FAIL  %s\n" "$1"; fail=1; }

for f in deploy-railway.sh deploy-fly.sh restore-verify.sh smoke.sh ci-local.sh; do
    [[ -f $f ]] || { bad "$f missing"; continue; }
    [[ -x $f ]] || { bad "$f not executable"; continue; }
    bash -n "$f" 2>/dev/null && ok "$f parses" || bad "$f has a syntax error"
done

for f in browse.py browse-v4.py graphview.py dup-report.py pg-proxy.py dedup.py tt-differential.py classify-run.py abstain-trace.py pilot-rule-coverage.py \
         held-moments.py verify-triple.py check-anchors.py ccdb.py validate.py check-admission.py; do
    [[ -f $f ]] || { bad "$f missing"; continue; }
    python3 -m py_compile "$f" 2>/dev/null && ok "$f compiles" || bad "$f has a syntax error"
done

# dedup.py carries its own regression suite — including the Ctesiphon/Egypt
# over-merge that destroyed a real event. Running it here means a rewrite of that
# rule cannot land without the case that proves it. Needs no credentials.
python3 dedup.py >/dev/null 2>&1 && ok "dedup regressions pass" \
    || bad "dedup.py regressions FAIL — an over-merge may be back"

# The mirror guard has fired twice and BOTH times it was catching its own parser,
# never the guarded thing drifting. A check whose only demonstrated behaviour is
# tripping over itself has not been shown to work — so this feeds it fixtures
# that ARE drifted (a field added to the gate, a field removed from it) and
# requires it to notice. Telemetry's catch. No credentials needed.
python3 check-admission.py --self-test >/dev/null 2>&1 \
    && ok "mirror guard catches real drift" \
    || bad "check-admission guard self-test FAILS — the guard may be blind"

[[ -f README.md ]] && ok "README.md present" || bad "README.md missing"

# --- rule: the fold and its proof ship together ---------------------------
# M1b made a moment row a function of a whole supersedes chain. Three of its
# four hard parts are invisible to a passing test that only commits roots — the
# M1 projector passes "a moment projects" perfectly — so the suite that
# discriminates them is named here. 13 of its 15 cases fail against the old
# projector; the 2 that do not are the deliberate no-op pins.
# The credential-scope matrix is the scope document; auth.rs's comments now
# point at it instead of describing scope themselves. If it disappears, two
# guards' doc comments become claims about a file that is not there.
[[ -f ../crates/cc-node/tests/credential_scope.rs ]] \
    && ok "the credential-scope matrix is present" \
    || bad "credential_scope.rs is gone — auth.rs points at a file that does not exist"
grep -q "credential_scope" ../crates/cc-node/src/auth.rs \
    && ok "auth.rs points at the matrix" \
    || bad "auth.rs no longer names where its scope is read"

# check-anchors.py PARSES the pre-registered tuples out of tt.rs rather than
# copying them. If the test it reads is renamed or deleted, the check must fail
# loudly rather than silently check nothing — assert the pairing both ways.
grep -q "the_pre_registered_hashes_reproduce" ../crates/cc-node/src/tt.rs \
    && ok "the pre-registration anchors are present in tt.rs" \
    || bad "the_pre_registered_hashes_reproduce is gone — check-anchors.py reads it"
grep -q "check-anchors" ../crates/cc-node/src/tt.rs \
    && ok "tt.rs names the check that covers its other half" \
    || bad "tt.rs no longer points at ops/check-anchors.py"

# --- rule: no check may hardcode the path to the database ------------------
# Three checks carried an author-specific home path as a working directory, which
# made them unrunnable by anyone else on any other machine — fatal for a tool
# whose purpose is letting a second party verify the first party's claims.
# Connection now comes from ccdb via CC_DATABASE_URL. This fails if an absolute
# home path comes back. tt-differential used to expanduser a one-laptop GitHub
# layout; that path is named here so it cannot return.
home_hits=$(grep -ln "/Users/[a-z]*/dev" -- *.py 2>/dev/null | grep -v "^ccdb.py$" || true)
if [[ -n "$home_hits" ]]; then
    echo "$home_hits" | sed 's/^/  FAIL  hardcoded home path: /'
    fail=1
else
    ok "no check hardcodes a home directory"
fi
if grep -q 'expanduser("~/dev/GitHub' tt-differential.py; then
    bad "tt-differential.py still expands a one-laptop GitHub path"
else
    ok "tt-differential.py has no host-layout path"
fi
if grep -q 'python3 ops/validate.py                                     # us, via railway' ccdb.py \
   || grep -q 'our path today' ccdb.py; then
    bad "ccdb.py still treats railway ssh as the default path"
else
    ok "ccdb.py does not default to railway ssh"
fi

# The validator composes the checks by NAME. If one is renamed or deleted the
# runner would skip it silently, which is the one failure a validator must not
# have — reporting a clean corpus it did not inspect.
for c in check-admission.py check-anchors.py held-moments.py verify-triple.py; do
    grep -q "\"$c\"" validate.py \
        && ok "validate.py composes $c" \
        || bad "validate.py no longer runs $c"
done

# --- two known signatures of a severed doc comment --------------------------
# NOT a guarantee, and the name says so. `readings_relation` was inserted at a
# line boundary inside `get_entity`'s doc comment: both halves stayed
# well-formed, it compiled, 239 tests passed, clippy was silent, and only
# `cargo doc` rendered it wrong.
#
# The first version of this check keyed on the orphan starting lowercase, and I
# "verified" it by re-severing the comment AT THE ORIGINAL PLACE — which
# reproduces the original orphan and proves only that the check catches the one
# input it was shaped around. timepoint-telemetry severed the same comment at a
# different point so the orphan began with a capital, ran this script, and it
# passed. Same defect, same file, same function, guard silent.
#
# Their generalisation, which is the durable part: **a guard written straight
# after a defect is FITTED to that defect**, because the specimen is the only
# example available, and narrowing it against false positives tightens the fit.
# The honest test is an input from the same class that you did not have in mind
# when you wrote it — which has to come from somewhere other than the incident.
#
# So: two signatures now, and `cargo doc` review remains the only complete check.
#   1. a block's FIRST line opens mid-sentence (catches a lowercase orphan)
#   2. a block's LAST line lacks terminal punctuation (catches the severed head,
#      whatever case the orphan begins with)
# Neither sees a break interior to a merged block.
# Invoked with `-c` and a single-quoted script, not a `<<PY` heredoc. The
# heredoc fed the script through STDIN inside an `if` condition, and
# timepoint-telemetry could not run smoke.sh at all — they had to awk this block
# out to test it. The hang was environmental and their access was never blocked,
# but a check whose shipped invocation must be RECONSTRUCTED before an outside
# party can run it is a check they run a transcription of. Same family as the
# three hardcoded home paths: the barrier was never the scope.
#
# EXIT 2 means the check could not run; EXIT 1 means it found something. The
# first version conflated them — a Python syntax error exited 1 and smoke
# reported a severed doc comment on a clean tree. A guard that cannot tell its
# own failure from its own finding will eventually report the wrong one.
rc=0
python3 -c '
import pathlib, re, sys
try:
    bad = []
    for f in pathlib.Path(sys.argv[1], "crates").rglob("*.rs"):
        block, start = [], 0
        for n, line in enumerate(f.read_text().splitlines() + [""], 1):
            t = line.strip()
            if t.startswith("///"):
                if not block:
                    start = n
                block.append(t[3:].strip())
                continue
            if block:
                first = next((b for b in block if b), "")
                w = first.split()[0] if first else ""
                if w and w[0].islower() and w.isalpha():
                    bad.append("%s:%d opens mid-sentence: %s" % (f, start, first[:52]))
                last = next((b for b in reversed(block) if b), "")
                ex = last.startswith(("*", "-", "|", ">")) or last.endswith("\\")
                if last and not ex and not re.search(u"[.!?:)\\]`\u2026]$", last):
                    bad.append("%s:%d ends unterminated: %s" % (f, n - 1, last[:52]))
                block = []
    print("\n".join(bad))
    sys.exit(1 if bad else 0)
except Exception as e:
    print("check error: %s: %s" % (type(e).__name__, e), file=sys.stderr)
    sys.exit(2)
' "$(pwd)/.." > /tmp/sevdoc.out 2>/tmp/sevdoc.err || rc=$?
# `|| rc=$?` because this file runs under `set -e`, which aborts on the first
# non-zero exit. The bare invocation killed smoke.sh at the python line, so
# every FAILURE path printed nothing at all and only the clean tree reported.
# The check was green and mute — the two states it most needs to distinguish
# were both invisible, and testing the happy path alone could not tell.
# Decided on EXIT CODE **and** output, because the code alone cannot separate
# them: an ImportError raised before the try block exits 1, which is also the
# code for "found something". The previous version reported a severed doc
# comment when the check itself was broken — a guard announcing the defect it
# exists to find, at the moment it stopped being able to find anything.
#
#   exit 0                    -> clean
#   exit != 0, stdout has text -> findings, and they are printed
#   exit != 0, stdout empty    -> the check could not run; NOT a clean result
if [[ ${rc:-0} -eq 0 ]]; then
    ok "doc comments clear of two known severance signatures"
elif [[ -s /tmp/sevdoc.out ]]; then
    sed 's/^/  FAIL  severed doc: /' /tmp/sevdoc.out
    bad "a doc comment looks severed — an item's rustdoc was split"
else
    sed 's/^/        /' /tmp/sevdoc.err | head -3
    bad "the severed-doc check COULD NOT RUN — not a clean result"
fi
rm -f /tmp/sevdoc.out /tmp/sevdoc.err

CC=../crates/cc-ledger
[[ -f $CC/tests/supersession.rs ]] && ok "the chain-fold suite is present" \
    || bad "cc-ledger/tests/supersession.rs is gone — M1b has no proof"
grep -q "held" $CC/src/lib.rs && ok "the projector still holds unrooted moments" \
    || bad "project_moment no longer mentions holding — arrival order may be back"
grep -q "root_event_id) DO UPDATE" $CC/src/lib.rs && ok "the fold still updates its head" \
    || bad "project_moment lost its upsert — corrections would fork a second row"

# The drop is only durable while something re-applies it: cc_ledger::rebuild()
# faithfully re-derives the projection from `events` and brings back every
# entity ops/drop-inadmissible.sql removed. Assert the pairing exists, so
# neither half can be deleted without the other becoming visibly incomplete.
[[ -f drop-inadmissible.sql ]] && ok "drop-inadmissible.sql present" \
    || bad "drop-inadmissible.sql missing — the rebuild remedy is gone"
grep -q "drop-inadmissible.sql" check-admission.py \
    && ok "check-admission names its remedy" \
    || bad "check-admission no longer points at the remedy"

# The two lessons that cost the most, asserted so a rewrite cannot quietly drop
# them: never verify by line count, and resolve a version-matched client.
grep -q "find_pg_bin" restore-verify.sh && ok "restore-verify resolves a matching client" \
    || bad "restore-verify lost its client-major gate"
grep -q "octet_length\|count(\*)" restore-verify.sh && ok "restore-verify counts rows" \
    || bad "restore-verify no longer counts rows"
grep -qi "wc -l" restore-verify.sh && bad "restore-verify verifies by LINE COUNT" \
    || ok "no line-count verification"

# --- rule: no credentials in argv -------------------------------------------
# A production password sat in `ps` output for hours because it was interpolated
# into a connection string on the command line. Prose did not stop that; this
# does. Flags the shapes that put a secret in argv: a psql/pg_dump URI carrying
# `user:password@`, or a -c/--command with an inline password assignment.
cred_hits=$(grep -nE \
  "(psql|pg_dump|pg_restore)[^|]*postgres(ql)?://[^ '\"]*:[^ '\"@]+@" \
  -- *.sh *.py 2>/dev/null | grep -vE "^smoke\.sh:|PGPASSWORD|<[A-Za-z]+>|\\$\{|:password@|:hunter2@|USER:PASS" || true)
if [[ -n "$cred_hits" ]]; then
    echo "$cred_hits" | sed 's/^/  FAIL  credential in argv: /'
    fail=1
else
    ok "no credentials interpolated into argv"
fi

# --- rule: this clone is shared with other agents ------------------------
# HEAD detached four times because a peer session reviewed commits by checking
# them out IN THIS TREE. A detached HEAD makes `git push origin main` a silent
# no-op that exits 0, which is how five commits came to be reported as pushed
# while sitting only here. Cheap to detect, expensive to miss.
# `|| echo unknown` sat here and made the guard print `ok "on a branch
# (unknown)"` whenever git itself failed — a sentence false every time it
# printed, from a check that passed. The guard written to enforce the
# guard-fires-wrong lesson contained it. Three outcomes, three answers.
# symbolic-ref, matching githooks/pre-commit. This check did NOT have the
# unborn-branch bug the hook had — it tests the exit code, so an unborn repo
# came out as "git failed", which is imprecise but fails closed. Two checks of
# the same state should still agree, and the one that reads stdout was the one
# that fabricated a cause.
if ! git -C .. rev-parse --git-dir >/dev/null 2>&1; then
    bad "not a git repository — this check did NOT run"
elif ! git -C .. symbolic-ref -q HEAD >/dev/null 2>&1; then
    bad "HEAD is DETACHED — commits here will not reach origin/main; run: git checkout main"
else
    ok "on a branch ($(git -C .. symbolic-ref --short HEAD)), not a detached HEAD"
fi
# ...and the hook that makes the check above redundant, which is the point:
# smoke runs when someone runs it, the hook runs on every commit.
if [[ "$(git -C .. config core.hooksPath 2>/dev/null)" == "githooks" ]]; then
    ok "pre-commit hook is enabled (core.hooksPath=githooks)"
else
    bad "core.hooksPath is not set — run: git config core.hooksPath githooks"
fi
[[ -x ../githooks/pre-commit ]] && ok "pre-commit hook is executable" \
    || bad "githooks/pre-commit missing or not executable"

rm -rf __pycache__
[[ $fail -eq 0 ]] && echo "smoke: PASS" || { echo "smoke: FAIL"; exit 1; }
