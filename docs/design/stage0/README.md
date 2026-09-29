# Stage 0 reference fold

Executable specification for [MULTI-SIGNER.md](../MULTI-SIGNER.md), not application
code. Python exhaustive enumeration plus Hypothesis was chosen so counterexample
traces also become a directly callable Rust differential oracle. No network,
database, signatures, generation or production data enters the model.

The pure fold is `model.fold(events)`. Its immutable result contains every event's
status/reason, frontier, active/canceled grants, effective Revokes and tombstones.
IDs and nonnegative integer key labels are symbols, not real keys. The exhaustive
run uses three signers; targeted depth checks use up to seven. The model does not validate
cryptography, canonical bytes, body prose, subject identity, edges, HTTP, receipts
or fold_version storage. Resolve represents a newly authored merged reading; body
selection is outside this authority/frontier model. This is not a proof of I4–I8
or of production correctness.

Ancestry is reflexive throughout. Revoke targets an exact grant, so an independent
surviving grant to the same key is a different capability. The root can only be
revoked by itself. A root relinquishment is an explicit control, not a body head;
root compromise remains total loss. Historical acts acknowledged by every
effective revoke are not prohibited merely because their writer is now revoked.
The safety claims exclude out-of-cut acts through revoked/canceled authority.

Use Python 3.13 (used for the recorded runs):

```sh
python3.13 -m venv /tmp/clockchain-stage0
/tmp/clockchain-stage0/bin/pip install -r docs/design/stage0/requirements.txt
HYPOTHESIS_STORAGE_DIRECTORY=/tmp/clockchain-stage0-hypothesis \
  /tmp/clockchain-stage0/bin/python docs/design/stage0/check.py \
  --max-events 5 --examples 300 --depth-examples 1000 --output /tmp/stage0-fast.json
/tmp/clockchain-stage0/bin/python docs/design/stage0/mutants.py \
  --output /tmp/stage0-mutants.json
```

The exhaustive domain is one genesis and three keys: five total events in CI,
seven in the full manual gate.
Every earlier parent is considered, including old parents after revocation;
Resolve considers every incomparable parent subset. It tries every available
grant reference, delegation target, revocation target and signer mutation.
Invalid extensions are checked but not extended: they cannot supply authority
or a valid parent. Duplicate structural corrections represent distinct body/
decision commitments, not duplicate delivery. Actual duplicate delivery is checked
separately.

Enumeration reduces only event-ID alpha-renaming and swapping non-root key names.
It retains all parent/issuer/target edges; it does not choose a winning event or
remove suppressed histories. The fold never uses the enumeration canonicalizer.
Pending/missing parents and malformed authority combinations also appear in the
partition and Hypothesis checks. The larger unbounded event space is not proved.

`check_invariants` checks parent/join authorization for every admitted transition
(including globally suppressed Resolve events), grant scope, absence of out-of-cut
frontier writers or effective revokers, and total audit classification for each
enumerated candidate. It also checks reflexive cutoff reasons and retention of
unsuppressed leaf events, so safe heads alone cannot conceal unauthorized admission
or lost siblings. Every candidate also checks reversed delivery and that an
operation through globally revoked/canceled authority cannot change the frontier,
active grants or effective revokes (root relinquishment is the explicit control
exception). `check_grief` tries every old-parent correction through a
tombstoned grant and checks unchanged frontier/tombstones. The fold is a function
of the input set, with no arrival state; I1 follows from that construction and the
issuer-stratification argument in the design. All named traces additionally run
every delivery permutation and every bipartition, with independent partition
folds before duplicate union. Hypothesis checks arbitrary DAGs, permutations and
partition/replay combinations through seven events.

The retained five-event counterexample `literal_monotone_tombstone_counterexample`
shows why unioning all branch-valid Revoke targets is wrong: it kills C through
revoked issuer K. The reference result preserves C and makes K's Revoke a visible,
non-effective branch. Effective tombstones may retract after a higher issuer's
revocation arrives; the candidate event set remains monotone.

## Checker checks and CI

The `stage0` job, **Stage 0 · model and mutants**, runs the commands above on every
PR/main push, with a five-minute job timeout. It uploads both JSON receipts even
on failure. Local measured time: 7.939 seconds for the fast/depth check and 2.361
seconds for mutations. [Fast receipt](fast-results.json): 1,287 distinct graphs,
8,839 candidate extensions, 17,678 signer mutations; ten named traces across
25,608 permutations and 768 bipartitions; 300 general Hypothesis examples.
These counts are different categories, not a count of independent proofs.

[mutants.py](mutants.py) replaces one rule in an isolated copy of `model.py`.
The checker and its scope/ancestry assertions remain unmutated. Breadth-first
search enumerates every smaller size in the three-key candidate grammar, without
symmetry reduction, before returning the first failing trace. Minimality is within
that grammar (valid reference prefixes plus the tested final extension), not a
claim about every possible malformed input. Each retained trace passes the normal
`check.py --case` subprocess and fails `check.py --case --mutant` with an assertion;
load errors/crashes do not count as kills. A survivor makes the suite fail.

| One-rule mutant | Killed | Minimum events, including genesis |
| --- | --- | ---: |
| Monotone tombstones | yes | 4 |
| Unscoped revocation | yes | 3 |
| Strict cut/cancellation ancestry | yes | 2 |
| Fork-point-only Resolve authority | yes | 4 |
| Revoked acts enter frontier | yes | 3 |
| Lowest event ID wins siblings | yes | 3 |

[Mutation receipt](mutant-results.json) contains each complete trace, assertion,
reference/mutant views and mutated-source hash. Some minima exercise root
relinquishment: the four-event monotone minimum does not replace the retained
five-event delegated-issuer counterexample. The Resolve mutant checks a previously
uncovered case: invalid authority can be admitted yet hidden from the frontier.
The new admission assertion catches it rather than weakening the mutant.

Depth coverage uses **targeted Hypothesis, not four-key exhaustive enumeration**.
With pinned seed `20260929`, `derandomize=True` and Hypothesis version pinned, all
1,000 examples executed; maximum depth actually reached was six, with seven keys
and eleven events including an appended attack. Of those examples, 182 acknowledged
an inner revoke and 818 made the issuer/descendant revokes concurrent. Depth phase:
4.344 seconds. Parent cutoffs, grant/key labels, old-parent corrections/counter-
revokes, delivery permutations and partition/duplicate replay vary. These are
bounded sampled traces, not exhaustive depth coverage. Any shrunk failure must be
retained as a named regression before this gate can pass.

Two hand-written depth-three traces additionally run every permutation and
bipartition: (1) concurrent G-revokes-A / A-revokes-K / K-revokes-C suppresses A's
revoke, so K survives and can resolve; (2) G acknowledges A's revoke of K before
revoking A, so both revokes remain effective, neither A nor K can resolve, and an
acknowledged C grant survives K's old-parent counter-revoke. Hypothesis also checks
the unacknowledged-delegation cutoff, where C is canceled instead.

## Full manual pre-release gate

Before release, run the full bound against the exact proposed model/checker,
plus the mutant suite, and retain their source-hashed receipts:

```sh
HYPOTHESIS_STORAGE_DIRECTORY=/tmp/clockchain-stage0-hypothesis \
  /tmp/clockchain-stage0/bin/python docs/design/stage0/check.py \
  --max-events 7 --examples 3000 --depth-examples 3000 --output /tmp/stage0-full.json
/tmp/clockchain-stage0/bin/python docs/design/stage0/mutants.py \
  --output /tmp/stage0-mutants.json
```

The [last full-bound receipt](results.json) belongs to
[revision f0c94df](https://github.com/timepointai/clockchain/tree/f0c94dfd98880943cda54b595681d4d1813fb4ac/docs/design/stage0),
before this checker revision: 204,522 distinct graphs modulo the stated symmetries,
2,307,805 candidate extensions, 1,799,288 invalid extensions, 4,615,610 signer
mutations, eight traces/15,528 permutations/512 bipartitions and 3,000 general
Hypothesis examples; 5,310.159 seconds. It contains no targeted depth run. Preserve
that receipt as dated evidence, not a pass for changed checker/model bytes.
This round ran the fast bound, depth checks and mutations; the revised full manual
gate has **not** been run. CI does not replace it or authorize release.

Stage (b) and stage (c) acceptance
requires differential agreement between Rust and this fold on generated DAGs,
including statuses, reasons, frontier, cancellations and effective tombstones.
The Rust harness must encode/sign symbolic DAGs with synthetic keys, map wire IDs
back to symbols, and vary import order/partitions and asserted timestamps.
Passing these model checks is not approval to begin those stages.
