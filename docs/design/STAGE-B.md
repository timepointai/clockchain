# Stage (b): authority and receipt separation

This records the merged Stage (b) boundary; subsequent projection work is in
[Stage (c)](STAGE-C.md).

Owner authorized this bounded PR on 2026-09-30 after the post-Stage (a) launch
audit. It implements the authority-chain boundary in
[MULTI-SIGNER.md](MULTI-SIGNER.md). The normal node remains on its legacy runtime;
the v1 review adapter and store refuse readiness. Resolve/frontier projection,
pinned edges/media/support, and the final governed fold identity remain stages
(c), (d), (e). This PR does not enable a production v1 runtime. Refs #6.

## Authority contract

`classify` checks branch-local admission in each parent's causal cone. Genesis
creates its root grant; Delegate records its exact issuer, grantee, subject and
issuance event. The grant must be active at the parent and held by the author.
A new delegate key must be absent from the parent's grant history, even when an
old grant is inactive. Concurrent independent grants remain separate capabilities.

Delegate's decision has old `None` and new `Grant { issuer, grantee }`. Revoke's
old value is `ActiveGrant(target)`; its new value includes that exact target and
signed cascade flag. Issuer/header grant mismatches, payload/decision mismatches,
empty rationale/evidence, altered subjects and authority assertion-time edits
reject. Correction after Delegate/Revoke uses the inherited body commitment.
No authority operation changes a selected body or its assertion time.

`analyze` returns branch admission separately from `Authority`: grant provenance,
active grants, canceled grants, effective revokes, tombstones and per-event
suppression reasons/controlling revoke IDs. Empty effect reason means eligible
under authority rules, not a head, frontier member or filter-support verdict.
HTTP admission outcomes carry the submitted candidate's authority effect; later
`Store::review_authority()` recomputes all effects from verified bytes.

Revoke can target only an active strict descendant of its signing grant, except
root self-relinquishment. Effective revokes are evaluated issuer-before-delegate,
with each stratum evaluated as a set. Root relinquishments are terminal controls
and cannot suppress one another. The candidate set grows monotonically;
effective tombstones can retract when a higher issuer suppresses a revoke.

For every covered grant, acts survive only in every effective revoke's reflexive
acknowledged past. Concurrent issuance cancels the derived grant and propagates
downward. Equality with the revoke parent preserves issuance. Cascade false keeps
acknowledged downstream grants; true tombstones the whole provenance subtree,
including acknowledged and later-learned descendants. Independent grants outside
that subtree survive. A suppressed cascade has no effects.

Effects distinguish `revoked_concurrent`, `canceled_grant`, `canceled_authority`,
`revoked_ancestor` and `root_relinquished`. Suppressed body dependencies cannot be
extended into eligibility by a good signer; they need re-authoring on a surviving
parent. An otherwise eligible authority control can retain its revocation effect
while its inherited body path is suppressed. Full body/frontier status projection
and surviving-common-grant Resolve joins remain (c), explicitly pending.

Dependency traversal is iterative without a semantic chain-depth cutoff. This is
a reference-oriented implementation that recomputes causal cones and effects;
large-history performance is not qualified for serving.

## Receipts and persistence

`NodeReceiptV1` / `SignedReceipt` use the separate `cc.receipt.v1` domain. The
canonical preimage is framed domain text, then instance[32], node key[32], event
ID[32], received_at (big-endian u64 Unix microseconds), encoding version (u16),
fold version (u16 number and 32-byte manifest), and initial admission result.
The result encodes state u16 (1 valid, 2 pending, 3 invalid), framed reason text,
and canonical missing-reference set. A 64-byte Ed25519 signature follows.
Canonical set/text/size checks reuse the v1 wire primitives; no event decoder
accepts a receipt. Receipt bytes do not alter event identity.

The fold reference must be supplied explicitly; there is no default, invented
production digest, or enabled Stage (b) fold identity. Tests use an explicitly
synthetic reference. Stage (e) must validate supported identities when enabling
runtime receipt issuance/verification. No automatic node receipt issuance or
production signing path is installed here.

`Store::retain_receipt` verifies canonical bytes, signature, instance and retained
event reference, then stores the observation in an independent append-only table.
It does not endorse the node key, asserted initial result or fold identity, nor
import an admission boolean from the observation. Repeated observations can differ;
exact duplicates are idempotent. A receipt claiming `valid` for an invalid candidate
cannot install authority. Malformed event attempts remain digest-keyed rejections.

The Stage (b) bootstrap adds only the observation table and changes its interim
schema hash. A Stage (a) store refuses reopening under this contract; there is no
silent schema upgrade. Replaying retained synthetic candidate bytes into a fresh
Stage (b) store reclassifies them under its rules. Applied v0 migration bytes,
legacy encodings and frozen private fixtures are untouched. This is not a
production migration, final fold identity or backup/restore qualification.

## Differential and integration acceptance

The original 1,728 G/C branch-admission cases remain. The new stdlib-only
`authority_oracle.py` calls the unchanged Stage 0 model and loads the unchanged
checker's pure grammar/named-trace functions without running its Hypothesis CLI.
It generates 3,352 G/C/D/R DAGs and 54,078 subsets/partitions: the small three-key
syntax through four events with signer mutations, applicable named traces, explicit
independent-grant/multiple-cut cases, and 150 seeded depth constructions reaching
six delegations. Resolve-containing traces are excluded explicitly until (c).

Rust signs those symbolic events with synthetic keys, maps event and grant IDs
back to symbols, and compares admission/reasons, active/canceled grants,
tombstones, effective revokes and suppression reasons. Three increasing, reversed
extreme and equal asserted-time patterns regenerate all signed IDs/references:
162,234 subset/time comparisons plus exact duplicate-union byte checks. This is bounded
authority agreement, not full `View`/frontier or production correctness.

Real PostgreSQL tests compare HTTP/import/restore outcomes and recomputed authority
through missing dependencies, suppressed cascade, replay and malformed inputs.
Separate tests cover concurrent arrival restoring a grant by retracting a lower
revoke, exact decision/scope checks, inherited Correction bodies, receipt
noninterference/immutability and old-stage store refusal. The normal runtime and
legacy known-gap tests remain explicitly legacy evidence.

Validation commands: pinned Rust 1.97.1 `make check`,
`cargo build -p cc-core -p cc-filter --target wasm32-unknown-unknown`, then
`python3 -m unittest discover -s ops -p 'test_*.py'`, with synthetic real PostgreSQL
and an operator test binary. Cargo invocations sharing a target run serially.
The Stage 0 fast/depth and seven-mutant checks remain required; their accepted
model/checker/full-bound receipt bytes are unchanged. Exact-head CI and actual
local outcomes are reported separately in the PR.

## Launch and next-stage boundary

[Refs #6](https://github.com/timepointai/clockchain/issues/6#issuecomment-5920400616)
was reopened with owner approval because its closure after #8 was not evidence of passing
launch gates. I2/I6 now receive authority-domain evidence; Resolve joins, complete
I1/I3 projections, I5 support and I8 versioned commitments remain outstanding.
The first PR review is the stopping point. No self-approval, merge or later-stage
implementation follows from this authorization.

The owner subsequently selected the full (a)–(e) sequence and authorized (c)
through first review. Later stages remain separately scoped.
The rejected single-key alternative requires rejecting Delegate/
Revoke before storage and a fold-version bump to enable them later, losing hot-key
recovery, delegation and rotation in the initial release. Neither sequence
recovers a compromised root. Completion still requires versioned runtime semantics,
exact-image operational evidence and a separately authorized historical-content/
human-publication session. Current live event counts remain unknown.

Refs #6. Only the owner may resolve the issue after (e) and operational evidence.
