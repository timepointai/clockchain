# Stage (e): fold_version rule identity and governed filter

The owner authorized this boundary on 2026-10-01, after Stage (d) PR #11 merged
(`2ce96d5cc1e7ee056867ed9792c575049e30f818`). Refs #6. Its final disposition
belongs to the owner after operational evidence. This PR stops at review.

The v1 path now has a governed rule identity, committed snapshots and versioned
reads. It is still non-serving: the normal node binary stays legacy, `/ready`
and `Store::readiness()` refuse with `stage_e_non_serving`, and nothing is wired
into normal boot. Runtime integration, fresh-store provisioning and operational
evidence remain separate, later authorizations.

## Rule identity

`fold_version = (1, SHA256(canonical_fold_manifest))`. The manifest
(`crates/cc-core/src/v1/fold-manifest-v1.txt`) names the encoding, the
authority, visibility, frontier and Resolve rules, the Stage (d) edge, support
and media interpretation, `as_of` and the projection-row schema. Every
owner-adopted default is a named manifest field (below). `supported_fold` accepts
only this exact pair; any change to the manifest changes the digest and is
refused until a new number and implementation exist.

The filter identity (`cc_filter::v1::FilterIdentity`) is boot configuration,
never a ledger event. Its canonical bytes commit to the fold version, encoding
version, constants version, the pinned TT taxonomy hash, the exact strictly
sorted nonempty Ed25519 curator key set, the trust policy
`cc.trust.curator-genesis-creator.v1` and the `max_hops` parameter. `filter_version`
is their SHA-256. Changing the curator set changes filter identity.

`corpus_digest` frames the sorted IDs of every retained candidate, including
pending and invalid ones. Malformed-input rejections and node receipts are not
events. The view commitment is
`SHA256(frame("cc.view.v1") || canon_version || fold_version || filter_version ||
corpus_digest || len || canonical_projection_rows)`. Rows are the
`cc.view-rows.json.v1` serialization of every event reading (status, reason,
frontier flag, selected revision, controlling revokes and full signed envelope
with its decision), revisions, subject readings, grants, active/tombstoned/
canceled grants, effective revokes, authority effects, and Stage (d) edge and
media readings. Receipts and body availability are excluded. Cache keys frame the
filter version, corpus digest and exact query bytes.

## Store, reads and refusal

`Store::bind(filter)` accepts only an identity `FilterIdentity::governed` would
construct for this build: its fold, encoding, constants, ontology and trust
policy, a valid strictly sorted nonempty curator set and a nonzero hop bound.
Anything else is refused before it is recorded. It records the identity in a new
append-only `cc_v1.rule_identity` row; the interim schema hash changes, so
Stage (b), (c) and (d) stores refuse silent reopening.

`semantic_readiness()` always reports `serving: false` and one of:
- `ready`;
- `rule_identity_unbound` (no identity bound on this handle);
- `rule_identity_unrecorded` (bound handle, but no stored row);
- `unsupported_fold_version`;
- `incompatible_rule_identity`.

Snapshots, exports and the review route refuse on anything but `ready`. The
reader-authorized `/health` diagnostic still answers 200 with the readiness
report; its corpus digest and commitment are null unless the state is `ready`.
A requested fold that is not the bound supported one returns
`unsupported_fold_version`; it is never answered under the current fold.

`Snapshot` carries the rule identity, corpus digest and commitment. Entity reads,
support verdicts (`Supported { path, excluded }` / `Unsupported { reasons }`)
and cache keys name them. The review router adds a reader-authorized `/health`
diagnostic and accepts `fold_version`/`fold_manifest` on `/v1/review` (409 on
mismatch).

`as_of` is applied after the authority and conflict fold. A resolved subject's
current revision is visible only if its asserted coordinate is at or before
`as_of`; otherwise the read is `after_as_of` (or `asserted_time_unknown`) and no
older body is selected. Hidden subjects lose their support neighbors, which
become explicit `as_of:` exclusions. Asserted time never changes authorization,
frontier, precedence or revocation.

Export manifests carry encoding, rule identity, corpus digest, commitment and
the retained envelopes. `restore_export` refuses an unknown encoding or fold, a
different filter identity, or a corpus/commitment that does not recompute
exactly, all before any admission. Old roots are verified only under their
named rule and never reinterpreted. Accepted envelopes then go through
`Store::admit`.

## Native and Wasm vectors

`crates/cc-core/tests/vectors/v1_rule_reference.py` independently computes the
manifest digest, ontology hash, filter canonical bytes and version, corpus
digests, a view commitment and a cache key into the new `v1-rule.txt`. The
Stage (a) vectors are unchanged.

The real canonical rows of a fixed synthetic projection (genesis, correction,
second subject, pinned edge, attestation) are pinned byte for byte in
`crates/cc-ledger/tests/vectors/v1-view-rows.json`. From those bytes the
reference independently recomputes the rows digest, corpus digest, testkit
filter version and view commitment into `v1-view.txt`.
`canonical_rows_and_view_commitment_are_pinned` fails on any serialization or
framing change. CI reruns the reference and requires both vector files to be
unchanged. `.gitattributes` keeps the manifest and vector bytes free of
line-ending normalization. `cc-wasm-vectors` recomputes all eight with the
shipped cc-core/cc-filter code natively (Cargo test) and as a wasm32 module run
by Node in a new CI step; both must report mask `0xff`.

## Named tests

| Name | File |
| --- | --- |
| i1_union_permutation_partition_convergence | crates/cc-ledger/tests/v1_projection_differential.rs |
| i2_parent_authority_and_surviving_join_grant and eight i2_* traces | crates/cc-ledger/tests/v1_projection_differential.rs |
| i3_total_auditable_classification | crates/cc-ledger/tests/v1_invariants.rs |
| i3_late_eligible_branch_reopens_resolved_frontier | crates/cc-ledger/tests/v1_invariants.rs |
| i4_subject_key_immutable_across_all_transitions | crates/cc-ledger/tests/v1_admission.rs |
| i5_pins_survive_correction_resolution_and_reaffirmation | crates/cc-ledger/tests/v1_edges.rs |
| i6_asserted_time_and_receipt_noninterference | crates/cc-ledger/tests/v1_projection_differential.rs |
| i7_http_import_admission_differential | crates/cc-node/tests/v1_ingress.rs |
| i8_versioned_commitments_and_unknown_refusal | crates/cc-node/tests/v1_rule_identity.rs |
| v1_canonical_author_bound_roundtrip, v1_no_legacy_ingress | crates/cc-core/tests/v1_encoding.rs |
| v1_curator_root_is_not_subject_authority, v1_decision_payload_matches_transition, v1_resource_exhaustion_is_not_invalid | crates/cc-ledger/tests/v1_invariants.rs |

The I2 traces and I1 partitions are model-checked by the new stdlib adapter
`docs/design/stage0/trace_oracle.py`, which imports the unchanged
`model.fold`/`projection_oracle.projection` for explicit symbolic traces. The
accepted model, checker, mutants and receipts are byte-unchanged.

## Evidence

- **I2:** ten traces compare Rust with the model on **1,128** subset/time-pattern
  views, then deliver **114** orders through the real `Store::admit` path: every
  order for traces of up to four events, otherwise listed, reversed and four
  seeded shuffles. Each order ends with a duplicate. Each arrival result must
  equal the classification of what was delivered, and the stored projection must
  equal the model.
- **I1:** seven traces (intersecting revokes, concurrent delegate descendants,
  retroactive revoke, competing resolutions, laundering, crisscross and partial
  join with a late sibling), each split two ways. Complementary halves go to
  separate stores in different orders, and each must match the model for its
  subset. Export/restore union, rebuild into a fresh store and duplicate replay
  must reproduce the independently computed root. The loop count itself is not
  claimed as evidence.
- **I6:** all **13** named model traces re-signed under three asserted-time
  patterns have distinct IDs and identical decisions. Receipts claiming other
  results and times, and body retention, leave the snapshot unchanged. A
  separate `as_of` test covers post-fold visibility and a backdated revoked
  writer.
- **I8:** eight single-field identity variants give distinct filter versions,
  commitments and cache keys over fixed events; corpus and rows are committed.
  `bind_refuses_ungoverned_filter_identity` covers nine ungoverned identities
  (empty, unsorted, duplicated or invalid curators; foreign trust policy, wrong
  encoding, constants, ontology; zero hop bound). Each is refused with nothing
  recorded.
  It also covers binding refusal, requested and stored unknown folds, a tampered
  stored identity, health diagnostics, HTTP 409, and export refusal for a
  version, manifest, root or other rule before admission, with exact restore.

Mutation spot checks are reported in the PR, each made locally and reverted.
This is bounded implementation evidence, not exhaustive production correctness.

## Owner questions (governed defaults pinned in the manifest)

The owner adopted the Stage (d) conservative readings as governed defaults.
Each remains open for change only through a new fold version.

1. Relations: `edge.relations`.
2. Support relations, undirected adjacency and hop bound: `support.relations`,
   `support.adjacency`, `support.hop_bound` (the value is filter `max_hops`;
   tests use 4).
3. Dispute author is the source subject's creator: `edge.dispute_author`.
4. No current body is stale, not contested: `edge.no_current_body`.
5. Curator trust keyed on edge author and Genesis creators: `support.trust`,
   filter `trust_policy`.
6. Media targets and event binding: `media.targets`, `media.event_binding`;
   no inference: `media.inference`.
7. Self-edges and older reaffirmation bases: `edge.self_edge`,
   `edge.reaffirm_basis`.
8. Same-subject support query: `support.same_subject`.
9. Note, revision-missing media stays pending with a revision reference:
   `media.revision_missing`.
10. Note, authority-only forks contest the subject: `subject.authority_only_fork`.
11. New, `as_of` hides a later current revision without falling back, and treats
    unknown asserted time as not visible: `as_of`, `as_of.unknown_time`.
12. New, projection rows use a JSON canonical schema: `projection.rows`. The
    rows bytes are now pinned by a conformance vector.
13. New, export/restore requires the same filter identity; there is no
    cross-rule migration (`restore_export`).
14. New, health is reader-authorized on the review router only; the normal
    binary's health stays legacy until runtime integration.
15. `as_of` considers only the current revision's asserted time. Edge and
    attestation asserted times are ignored for visibility (edge and media events
    carry none in v1): `as_of`.

## Owner notes (recorded, behavior unchanged)

- `Store::review`, `review_authority`, `review_projection` and raw `restore`
  remain public and unversioned for operator review. Runtime integration must
  remove them or route them through the versioned snapshot.
- A malformed or out-of-range `fold_version` query parameter gets axum's 400
  rejection, not the 409 `unsupported_fold_version`.
- `/health` recomputes the full fold on every request; it is a diagnostic, not
  a serving-scale endpoint.

Resource bounds remain unqualified for serving: the reaffirmation fixed point is
O(L^2) and projection is O(edges x candidates); snapshots recompute the full fold.

## Remaining boundary

Runtime integration (making v1 the serving path), fresh-store provisioning,
immutable-image operational evidence, the Stage 0 full manual gate on release
candidates and a separately authorized content/publication session remain.
Current live event counts remain unknown. [HOLD.md](../../HOLD.md) is unchanged.
