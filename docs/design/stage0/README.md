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
Owner-selected `Revoke.cascade=true` retires the complete target grant subtree,
including acknowledged descendants and grants learned later. Past acts still use
the reflexive cutoff. A suppressed cascade has no effect; false preserves the
non-cascading departure behavior. The signed flag is explicit, not inferred.

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
grant reference, delegation target, revocation target, both cascade flags and
signer mutation. Symmetry keys include the flag; the two choices never coalesce.
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
revoked issuer K. With `cascade=false`, the reference result preserves C and makes K's Revoke a visible,
non-effective branch. Effective tombstones may retract after a higher issuer's
revocation arrives; the candidate event set remains monotone.

## Checker checks and CI

The `stage0` job, **Stage 0 · model and mutants**, runs the commands above on every
PR/main push, with a five-minute job timeout. It uploads both JSON receipts even
on failure. Local measured time: 18.427 seconds for the fast/depth check and
5.117 seconds for mutations. [Fast receipt](fast-results.json):
2,341 distinct graphs, 17,797 candidate extensions,
35,594 signer mutations; thirteen named traces across
26,568 permutations and 896 bipartitions;
300 general Hypothesis examples.
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
| Ignore signed cascade flag | yes | 3 |

[Mutation receipt](mutant-results.json) contains each complete trace, assertion,
reference/mutant views and mutated-source hash. Some minima exercise root
relinquishment: the four-event monotone minimum does not replace the retained
five-event delegated-issuer counterexample. The Resolve mutant checks a previously
uncovered case: invalid authority can be admitted yet hidden from the frontier.
The new admission assertion catches it rather than weakening the mutant.

Depth coverage uses **targeted Hypothesis, not four-key exhaustive enumeration**.
With pinned seed `20260929`, `derandomize=True` and Hypothesis version pinned, all
1,000 examples executed; maximum depth actually reached was six, with seven keys
and eleven events including an appended attack. Of those examples, 245 acknowledged
an inner revoke and 755 made the issuer/descendant revokes concurrent. Depth phase:
7.222 seconds; 258 cases used a cascading outer revoke. Parent cutoffs, grant/key labels, old-parent corrections/counter-
revokes, delivery permutations and partition/duplicate replay vary. These are
bounded sampled traces, not exhaustive depth coverage. Any shrunk failure must be
retained as a named regression before this gate can pass.

Two hand-written depth-three traces additionally run every permutation and
bipartition: (1) concurrent G-revokes-A / A-revokes-K / K-revokes-C suppresses A's
revoke, so K survives and can resolve; (2) G acknowledges A's revoke of K before
revoking A, so both revokes remain effective, neither A nor K can resolve, and an
acknowledged C grant survives K's old-parent counter-revoke. Hypothesis also checks
the unacknowledged-delegation cutoff, where C is canceled instead. Three additional
named traces pin compromise with visible attacker-issued grants (cascade true),
honest delegator departure (false), and a suppressed cascade with no descendant
effect. They run all delivery permutations and bipartitions too.

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

The [full-bound receipt](results.json), recorded 2026-09-30, passes on the final
cascade model/checker bytes: **489,782 distinct graphs** modulo the stated
symmetries, **6,421,108 candidate extensions**, 5,136,273 invalid extensions and
12,842,216 signer mutations. Thirteen named traces cover 26,568 permutations and
896 bipartitions. The run also passed 3,000 general Hypothesis examples and
3,000 targeted-depth examples, reaching depth six / seven keys / eleven events:
761 acknowledged, 2,239 concurrent, and 815 cascading cases. Total time:
**2,849.100 seconds**; targeted depth: 9.345 seconds.

The receipt pins model SHA-256
`9774ef0fa0fa8fe4248939f092d1419909a65d42ba0ae6aa6ee0adad85dd0551`
and checker SHA-256
`3701ee61bedeee933c15554daa92582ce880bc3574f7e7de1bcfd2f8bee70b8f`.
It replaces the older non-cascade receipt, which remains available in
[revision f0c94df](https://github.com/timepointai/clockchain/tree/f0c94dfd98880943cda54b595681d4d1813fb4ac/docs/design/stage0).
This bounded pass is not an unbounded proof. CI does not replace the full manual
gate or authorize release.

Stage (b) and stage (c) acceptance
requires differential agreement between Rust and this fold on generated DAGs,
including statuses, reasons, frontier, cancellations and effective tombstones.
The Rust harness must encode/sign symbolic DAGs with synthetic keys, map wire IDs
back to symbols, and vary import order/partitions and asserted timestamps.
Passing these model checks is not approval to begin those stages.
