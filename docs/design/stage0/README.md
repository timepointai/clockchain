# Stage 0 reference fold

Executable specification for [MULTI-SIGNER.md](../MULTI-SIGNER.md), not application
code. Python exhaustive enumeration plus Hypothesis was chosen so counterexample
traces also become a directly callable Rust differential oracle. No network,
database, signatures, generation or production data enters the model.

The pure fold is `model.fold(events)`. Its immutable result contains every event's
status/reason, frontier, active/canceled grants, effective Revokes and tombstones.
IDs are symbols; keys 0, 1 and 2 are abstract signers. The model does not validate
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

Reproduce with Python 3.13 (used for the recorded run):

```sh
python3.13 -m venv /tmp/clockchain-stage0
/tmp/clockchain-stage0/bin/pip install -r docs/design/stage0/requirements.txt
HYPOTHESIS_STORAGE_DIRECTORY=/tmp/clockchain-stage0-hypothesis \
  /tmp/clockchain-stage0/bin/python docs/design/stage0/check.py \
  --max-events 7 --examples 3000 --output /tmp/clockchain-stage0-results.json
```

The exhaustive domain is one genesis, three keys, and up to seven total events.
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

`check_invariants` checks parent authorization, grant scope, absence of out-of-cut
frontier writers or effective revokers, and total audit classification for each
enumerated candidate. Every candidate also checks reversed delivery and that an
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

The completed run passed: 204,522 distinct graphs (modulo the stated symmetries),
2,307,805 candidate extensions, 1,799,288 invalid extensions and 4,615,610 signer
mutations. The eight named traces passed 15,528 permutations and 512 bipartitions;
Hypothesis passed 3,000 examples. Runtime was 5,310.159 seconds on the review host.
The fold is 258 lines; the checker is 333 lines. Counts and source hashes are
recorded in `results.json`.

Stage (b) and stage (c) acceptance
requires differential agreement between Rust and this fold on generated DAGs,
including statuses, reasons, frontier, cancellations and effective tombstones.
The Rust harness must encode/sign symbolic DAGs with synthetic keys, map wire IDs
back to symbols, and vary import order/partitions and asserted timestamps.
Passing these model checks is not approval to begin those stages.
