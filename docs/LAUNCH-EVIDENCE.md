# Launch evidence for issue #6

This is the public map from each gate of
[issue #6](https://github.com/timepointai/clockchain/issues/6) ("Pre-first-publish
gates") to the merged PRs that address it, the named tests that enforce it, and the
release checks the launch path runs. It holds no private values: no hostnames,
instance ids, keys, digests of private content, event ids or receipt contents.
The release evidence itself is retained privately by the owner.

This document records evidence. It does not close, resolve or dispose of any gate.

## How to read it

- **Line numbers.** Every `path:line` is the test's `fn` or `def` line on `main`
  at `8b196f3670045db5c05af328af6ce40ee19c756c`, the last merge before launch.
  Later merges may shift lines; the test names are stable. Each reference was
  checked by grepping that line for the name.
- **Kinds.** *PG* is an integration test against a real PostgreSQL database
  (`cc_testkit` ephemeral databases; CI and the local gate use PostgreSQL 18).
  *HTTP* drives a real router over a socket. *Binary* runs the built `cc-node`
  executable. *Pure* runs the in-memory fold. *Oracle* compares Rust against the
  Stage 0 Python reference model. *Unit* is a test with no database. *Census*
  checks that a list covers every route.
- **Assertions.** Every test listed asserts a specific outcome, such as a
  status, reason code, commitment or byte comparison; the one weaker test is
  marked under Gate 7. The Stage 0 checker additionally
  requires each of its seven one-rule mutants to be killed
  (`docs/design/stage0/mutants.py:22`).
- **PRs.** The stage PRs, merge commits and `main` CI runs are listed in the
  [v1.0 release notes](releases/v1.0.md#stages). In short: design and Stage 0
  #7, (a) #8, (b) #9, (c) #10, (d) #11, (e) #12, owner launch decisions #13,
  and (f) #16 (node), #14 (publisher) and #15 (release tooling).

## Legacy characterizations (not gate evidence)

Five legacy v0 tests still assert that the original gaps exist on the v0 path.
Each is marked `known_gap characterization` and "A fix under issue #6 may
intentionally change this expectation":

- `backdated_cross_author_sibling_wins_and_hides_the_other_in_all_720_orders`,
  `crates/cc-ledger/tests/rebinding.rs:208`;
- `subject_moving_correction_leaves_incident_edge_on_old_entity_in_all_720_orders`,
  `crates/cc-ledger/tests/rebinding.rs:292`;
- `original_writer_attestation_does_not_select_a_losing_correction`,
  `crates/cc-ledger/tests/rebinding.rs:373`;
- `http_same_body_correction_can_backdate_and_change_author_but_not_target_a_stale_head`,
  `crates/cc-node/tests/api.rs:2812`;
- `projection_only_divergence_can_change_verdict_without_protocol_or_corpus_identity_change`,
  `crates/cc-node/tests/api.rs:2877`.

They describe legacy node mode, which production no longer runs. v1 addresses the
gates with a new encoding, store and fold on a fresh database, not by changing v0
behavior. These tests remain as v0 regression records.

## Gate 1: cross-author backdating (priority)

**Decision** ([MULTI-SIGNER.md](design/MULTI-SIGNER.md), I2 and I6). Only a grant
valid in the event's parent cone can act. Asserted time and receipt time never
order authority, frontiers or revocation (fold manifest
`order.asserted_time=never_authority_frontier_precedence_or_revocation`).
**PRs:** #7, #8, #9, #10, #12.

| Test | Location | Kind | Asserts |
| --- | --- | --- | --- |
| `i2_parent_authority_and_surviving_join_grant` | `crates/cc-ledger/tests/v1_projection_differential.rs:414` | PG, oracle | An unauthorized author, wrong grant, branch-only delegate or revoked resolver is invalid with `parent_authority` |
| `i6_asserted_time_and_receipt_noninterference` | `crates/cc-ledger/tests/v1_projection_differential.rs:603` | Pure, PG | Re-signing with different asserted times changes ids but no decision; forged receipts and bodies leave the snapshot unchanged |
| `as_of_reads_follow_the_fold_and_never_reauthorize` | `crates/cc-ledger/tests/v1_invariants.rs:243` | PG | A backdated out-of-cut correction is `revoked_concurrent`, and `as_of` never changes the frontier |
| `receipts_are_separate_untrusted_observations_and_cannot_install_authority` | `crates/cc-ledger/tests/v1_authority.rs:117` | PG | A receipt cannot change authority, and event ingress refuses receipts |
| `stage_b_grants_revocations_suppression_acknowledgment_and_time_match_model` | `crates/cc-ledger/tests/v1_authority_differential.rs:149` | Oracle | Rust authority equals the reference model across DAGs and asserted-time variants |
| `v1_curator_root_is_not_subject_authority` | `crates/cc-ledger/tests/v1_invariants.rs:105` | Pure | A curator correcting another author's subject is `parent_authority` |

**Limit.** No v1 test replays the exact issue scenario as one named case (a
foreign signer with an earlier asserted time correcting the head). It is covered
by the unauthorized-author case of the I2 test and by I6.

## Gate 2: fold rebinding semantics (A vs B)

**Decision: B.** Visible conflict projection with immutable revision entities and
a stable signed `subject_key` (I1, I3, I4, I5). Pinned edges go stale and never
retarget. **PRs:** #7, #8, #10, #11.

| Test | Location | Kind | Asserts |
| --- | --- | --- | --- |
| `i4_subject_key_immutable_across_all_transitions` | `crates/cc-ledger/tests/v1_admission.rs:7` | Pure | Changing kind, namespace, value or subject reference is `subject_key_changed` or `wrong_subject` |
| `i4_revision_selection_is_immutable_and_does_not_omit_authority` | `crates/cc-ledger/tests/v1_projection.rs:43` | Pure | Identical bodies get distinct revision ids; selection is pinned |
| `i5_pins_survive_correction_resolution_and_reaffirmation` | `crates/cc-ledger/tests/v1_edges.rs:44` | Pure | Edges go stale, never retarget, across correction, resolve and reaffirm |
| `i3_total_auditable_classification` | `crates/cc-ledger/tests/v1_invariants.rs:28` | PG | Every retained candidate has exactly one status; rejects are retained |
| `i1_union_permutation_partition_convergence` | `crates/cc-ledger/tests/v1_projection_differential.rs:522` | PG | Partitions, export/restore union, rebuild and duplicate replay all give the full set's commitment |
| `i1_edge_store_delivery_order_convergence` | `crates/cc-ledger/tests/v1_edge_convergence.rs:238` | PG | Edge projection is independent of delivery order and duplicates |
| `i3_edge_subset_and_partition_invariants` | `crates/cc-ledger/tests/v1_edge_convergence.rs:174` | Pure | I3 holds over edges for every subset and partition |

## Gate 3: versioning

**Decision.** Canonical encoding 0 to 1 on an empty v1 store, with no history
migration. `fold_version = (1, SHA256(manifest))`. The filter identity commits
to the fold version, encoding, constants, TT taxonomy hash, curator set, trust
policy and `max_hops`. Unknown versions are refused (I8). **PRs:** #8, #12, #16.

| Test | Location | Kind | Asserts |
| --- | --- | --- | --- |
| `i8_versioned_commitments_and_unknown_refusal` | `crates/cc-node/tests/v1_rule_identity.rs:17` | PG, HTTP | Every identity component changes `filter_version` and the commitment; an unknown fold is 409; tampered or foreign-rule export roots are refused |
| `bind_refuses_ungoverned_filter_identity` | `crates/cc-ledger/tests/v1_invariants.rs:354` | PG | `bind` refuses changed or reordered curators and a foreign trust policy, encoding or constants |
| `earlier_stage_stores_refuse_silent_stage_e_reinterpretation` | `crates/cc-ledger/tests/v1_projection.rs:244` | PG | Stores from earlier stages are an identity error, never reinterpreted |
| `snapshot_fold_negotiation` | `crates/cc-node/tests/v1_serving.rs:381` | PG, HTTP | A foreign fold is 409; malformed fold parameters are refused |
| `export_restores_to_the_same_served_commitment` | `crates/cc-node/tests/v1_serving.rs:429` | PG | Export and restore preserve the served commitment |
| `identity_mismatch_fails_closed_in_provision_and_serve` | `crates/cc-node/tests/v1_provision.rs:157` | PG, binary | A mismatched identity fails both `provision-v1` and `serve` |
| `native_rule_vectors_match_independent_reference` | `crates/cc-wasm-vectors/tests/native.rs:2` | Unit | Rule identity matches the independent vectors; CI repeats this in wasm32 |

**Limit.** "Mixed-version" behavior has no test of that name. It is covered by
refusal: I8 refuses a foreign rule's root, and earlier-stage stores are refused.

## Gate 4: authority

**Decision** (I2). A ledger Genesis root grant, multi-key delegation and
issuer-scoped revocation on the causal subject DAG, and resolution by a surviving
common grant. A bearer credential is transport only; curators cannot override
subject authority. **PRs:** #7, #9, #10, #16.

| Test | Location | Kind | Asserts |
| --- | --- | --- | --- |
| `i2_revoke_concurrent_correction_no_revoked_winner` | `crates/cc-ledger/tests/v1_projection_differential.rs:447` | PG, oracle | A concurrent correction by a revoked key is `revoked_concurrent` in every order |
| `i2_revoke_concurrent_delegate_cancels_descendants` | `crates/cc-ledger/tests/v1_projection_differential.rs:463` | PG, oracle | A concurrent delegation and its descendants are canceled |
| `i2_prior_delegate_survives_later_revoke` | `crates/cc-ledger/tests/v1_projection_differential.rs:475` | PG, oracle | A causally prior delegation survives a later revoke |
| `i2_retroactive_revoke_from_old_parent_cannot_freeze` | `crates/cc-ledger/tests/v1_projection_differential.rs:482` | PG, oracle | Revocation is scoped to the issuer's own grants |
| `i2_cascade_compromise_visible_attacker_delegates` | `crates/cc-ledger/tests/v1_projection_differential.rs:496` | PG, oracle | A cascading revoke removes the compromised key's delegates |
| `i2_non_cascade_honest_delegator_departure` | `crates/cc-ledger/tests/v1_projection_differential.rs:503` | PG, oracle | A non-cascading revoke keeps the delegates |
| `i2_suppressed_cascade_has_no_descendant_effect` | `crates/cc-ledger/tests/v1_projection_differential.rs:510` | PG, oracle | A suppressed cascade has no effect |
| `concurrent_arrival_recomputes_effective_tombstones_and_replay` | `crates/cc-ledger/tests/v1_authority.rs:173` | PG | Effective revocations are recomputed as arrivals change |
| `freeze_and_counterclaim_have_independent_subject_authority` | `crates/cc-ledger/tests/v1_projection.rs:168` | Pure | A frozen subject has no current body; a counterclaim is a separate subject |
| `cascade_is_required_canonical_and_signed` | `crates/cc-core/tests/v1_encoding.rs:150` | Unit | The cascade flag is signed and canonical |
| `the_v1_credential_scope_matrix_holds_in_both_postures` | `crates/cc-node/tests/credential_scope.rs:534` | PG, HTTP | Each credential reaches exactly its scoped routes, live and frozen |
| `every_v1_route_appears_in_the_v1_matrix` | `crates/cc-node/tests/credential_scope.rs:610` | Census | No v1 route escapes the scope matrix |
| `every_route_is_scoped_and_refused_writes_store_nothing` | `crates/cc-node/tests/v1_serving.rs:229` | PG, HTTP | A refused write stores nothing |

**Limit.** The publisher has no Delegate or Revoke command yet, so production
signs with the root curator key. That is Stage (g) workstream G2.

## Gate 5: sibling conflict

**Decision** (I1, I3). All branches and competing resolutions stay visible. An
explicit signed Resolve joins declared frontiers, and a late eligible sibling
reopens the contest. **PRs:** #7, #10.

| Test | Location | Kind | Asserts |
| --- | --- | --- | --- |
| `i3_partial_competing_resolutions_and_late_eligible_reopening` | `crates/cc-ledger/tests/v1_projection.rs:12` | Pure | Competing resolves stay on the frontier; a late sibling makes the subject `contested`; a join resolves it |
| `i3_late_eligible_branch_reopens_resolved_frontier` | `crates/cc-ledger/tests/v1_invariants.rs:314` | Pure | A late eligible branch reopens; a revoked branch is visible but does not |
| `resolve_decisions_and_reachable_eligible_revision_are_checked` | `crates/cc-ledger/tests/v1_projection.rs:90` | Pure | Mutated Resolve decisions are refused |
| `suppressed_revision_cannot_be_selected_even_by_a_surviving_resolver` | `crates/cc-ledger/tests/v1_projection.rs:192` | Pure | A suppressed revision is `revision_ineligible` |
| `i1_union_permutation_partition_convergence` | `crates/cc-ledger/tests/v1_projection_differential.rs:522` | PG | Conflicting histories converge in every partition and order |

## Gate 6: recorded-decision semantics

**Decision.** A canonical `DecisionV1` binds the operation, exact old and new
values, parents, evidence, rationale, per-parent dispositions and the signer's
grant. An ordinary Attestation has no resolution or delegation power.
**PRs:** #7, #8, #9, #10, #11.

| Test | Location | Kind | Asserts |
| --- | --- | --- | --- |
| `v1_decision_payload_matches_transition` | `crates/cc-ledger/tests/v1_invariants.rs:151` | Pure | Changing a decision's old value, new value or kind on Correction, Delegate, Revoke, Resolve, EdgeAssert or EdgeReaffirm, or its rationale, evidence or parents on Correction, is `decision_mismatch` |
| `v1_canonical_author_bound_roundtrip` | `crates/cc-core/tests/v1_encoding.rs:101` | Unit | Author, grant, parents and decisions are signed identity |
| `exact_parent_grants_scope_decisions_and_inherited_body` | `crates/cc-ledger/tests/v1_authority.rs:10` | Pure | Decision mutations are invalid |
| `resolve_and_media_are_checked_while_stage_e_cannot_grant_readiness` | `crates/cc-ledger/tests/v1_admission.rs:165` | PG | An Attestation is valid but carries no authority |
| `v1_curator_root_is_not_subject_authority` | `crates/cc-ledger/tests/v1_invariants.rs:105` | Pure | Removing an Attestation leaves authority and subjects identical |

## Gate 7: unguarded import correction path

**Decision.** One `admit()` for HTTP, import, restore and publisher submission.
v0 and raw-supersedes ingress are excluded from v1. **PRs:** #8, #16, #14.

`Store::admit` is `crates/cc-ledger/src/v1.rs:480`. The v1 HTTP `submit`
handler calls `Store::admit` (`crates/cc-node/src/serve_v1.rs:376`), and the
publisher submits only over that route. Raw import and restore call `admit` for
each envelope and are compiled only with the `review` feature. The verified
restore path, `Store::restore_export` (`crates/cc-ledger/src/v1/rule.rs:314`),
is not feature-gated. It checks the fold, rule identity, instance, corpus digest
and commitment, then admits each envelope through `admit_all` and `admit`. It is
not exposed as a node HTTP route; v1 mode has no restore over HTTP.

| Test | Location | Kind | Asserts |
| --- | --- | --- | --- |
| `i7_http_import_admission_differential` | `crates/cc-node/tests/v1_ingress.rs:7` | PG, HTTP | Valid, pending and invalid inputs give the same outcome, authority and projection via HTTP, import and restore |
| `i7_edge_http_import_restore_admission_parity` | `crates/cc-node/tests/v1_edge_ingress.rs:11` | PG, HTTP | The same parity for edges and media |
| `admission_answers_201_valid_202_pending_and_422_invalid` | `crates/cc-node/tests/v1_serving.rs:635` | PG, HTTP | The serving router maps admission outcomes to 201, 202 and 422 |
| `serve_v1_mounts_only_the_v1_surface` | `crates/cc-node/tests/v1_provision.rs:278` | PG, binary | In v1 mode the v0 write and read routes are 404 |
| `migrate_refuses_in_v1_mode` | `crates/cc-node/tests/v1_provision.rs:247` | PG, binary | `cc-node migrate` exits 78 and applies nothing |
| `a_database_with_v0_tables_is_refused` | `crates/cc-node/tests/v1_provision.rs:228` | PG | Provisioning refuses a database holding v0 tables |
| `v1_fresh_store_refuses_even_empty_v0_projection` | `crates/cc-ledger/tests/v1_admission.rs:154` | PG | A v1 store refuses even an empty v0 schema |
| `i3_total_auditable_classification` | `crates/cc-ledger/tests/v1_invariants.rs:28` | PG | Legacy canon-version-0 bytes are invalid and retained as a rejection |
| `v1_strict_versions_sets_utf8_and_bounds` | `crates/cc-core/tests/v1_encoding.rs:119` | Unit | A changed canon version word is `unsupported_encoding`; a changed constants word is `unsupported_constants` |
| `v1_no_legacy_ingress` | `crates/cc-core/tests/v1_encoding.rs:189` | Unit | Weak: an all-zero buffer fails to decode, and the canon constants are 1 (v1) and 0 (legacy) |

**Limits.** The I7 differential drives the test-only review router; the serving
router's admission is covered separately by the 201/202/422 test, and both call
the same `Store::admit`. Despite its name, `v1_no_legacy_ingress` overwrites only
the length prefix of a zero buffer, not the version word, and checks no reason
code. The real version-word evidence is `i3_total_auditable_classification`
(a canon-version-0 envelope through `admit`) and
`v1_strict_versions_sets_utf8_and_bounds`. The route and database exclusions
are the provisioning and mount tests above.

## Byte-identical commitments

Fold version 1 is frozen. These tests pin its bytes, and CI regenerates the rule
vectors from an independent Python reference and requires no diff.

| Test | Location | Pins |
| --- | --- | --- |
| `canonical_rows_and_view_commitment_are_pinned` | `crates/cc-ledger/tests/v1_view_vectors.rs:10` | Projection rows, `filter_version`, corpus digest and view commitment |
| `v1_independent_wire_vectors` | `crates/cc-core/tests/v1_encoding.rs:197` | v1 signing preimages |
| `native_rule_vectors_match_independent_reference` | `crates/cc-wasm-vectors/tests/native.rs:2` | Rule identity vectors |
| `genesis_matches_the_independent_reference` | `crates/cc-publisher/tests/v1_vector.rs:43` | The publisher's Genesis envelope |
| `test_rule_vectors`, `test_view_vectors` | `ops/test_v1_identity.py:29`, `ops/test_v1_identity.py:44` | The release tooling's recomputed identity and empty view |
| `canon_vectors_are_pinned` | `crates/cc-core/tests/golden_canon.rs:119` | Legacy v0 canonical identities |

## Stage 0 reference model

`docs/design/stage0/check.py` enumerates every DAG within its bounds, replays
named traces (`named_cases`, `docs/design/stage0/check.py:216`) and runs
Hypothesis examples. `docs/design/stage0/mutants.py` requires each of its seven
one-rule mutants to fail. CI runs both on every commit. The model covers
authority, visibility and frontiers; by its own README it does not cover I4 to
I8. Rust agrees with its oracles in the differential tests above.

## Stage (f) runtime and publisher

| Test | Location | Asserts |
| --- | --- | --- |
| `provision_v1_is_idempotent_and_prints_the_identity` | `crates/cc-node/tests/v1_provision.rs:118` | `provision-v1` is idempotent |
| `serve_never_initializes_a_store` | `crates/cc-node/tests/v1_provision.rs:204` | `serve` never binds an identity |
| `v1_configuration_is_strict` | `crates/cc-node/tests/v1_provision.rs:351` | Malformed `CC_V1_*` configuration is refused |
| `frozen_posture_refuses_writes_and_keeps_serving_reads` | `crates/cc-node/tests/v1_serving.rs:278` | Frozen posture is 503 on writes only |
| `health_is_static_and_ready_tracks_the_store` | `crates/cc-node/tests/v1_serving.rs:492` | `/health` is fixed at boot; `/ready` is live |
| `submit_admits_reads_back_and_rerun_is_idempotent` | `crates/cc-publisher/tests/v1_online.rs:207` | Submit against the real v1 node, with byte read-back |
| `submit_refuses_instance_mismatch_before_any_write` | `crates/cc-publisher/tests/v1_online.rs:319` | Instance check precedes any write |
| `submit_refuses_curator_mismatch_before_any_write` | `crates/cc-publisher/tests/v1_online.rs:351` | Curator check precedes any write |
| `fold_mismatch_is_refused_by_submit_and_node_info` | `crates/cc-publisher/tests/v1_online.rs:391` | Fold check |
| `readback_detects_tampered_prose` | `crates/cc-publisher/tests/v1_online.rs:438` | Read-back compares bytes |
| `kind_outside_pinned_taxonomy_is_refused` | `crates/cc-publisher/tests/v1_offline.rs:669` | The kind must be in the pinned TT taxonomy |
| `keygen_creates_0600_once_and_never_overwrites` | `crates/cc-publisher/tests/v1_offline.rs:730` | Key file mode and no overwrite |

## Release checks

The launch path is `ops/deploy-fly.sh --v1-fresh`, documented in
[FIRST-ENTRY.md](FIRST-ENTRY.md) and
[CICD-FLY.md](CICD-FLY.md#v1-release-onto-a-fresh-database). It stops at the first
failure. In order, it:

1. requires a clean checkout equal to `origin/main` with a successful exact-SHA
   CI run;
2. requires valid `CC_V1_*` values, production `max_hops` 4, and a v1 `fly.toml`;
3. runs exact-image acceptance in local Docker, with its own PostgreSQL 18 and
   synthetic data: `migrate` refused, `provision-v1` twice, serve, a zero check,
   a synthetic Genesis through `cc-publisher v1`, a populated check, and a
   `pg_dump` restore that refuses a wrong instance or curator set and serves an
   equal commitment and byte-equal export;
4. refuses public IPs and uses a localhost-only proxy;
5. requires that no tick machine runs or is scheduled;
6. requires the target database to be empty or bound and empty, then backs it up
   and verifies the restore locally;
7. deploys the exact digest, with `cc-node provision-v1` as the release command;
8. checks `/health` against the expected identity recomputed from the checkout,
   `/ready` 200, and the deployed zero check;
9. takes a second verified backup.

The entry itself is a separate owner step: offline authoring, owner review,
`submit` (with its instance, fold and curator checks and byte read-back),
`verify`, a populated check and a verified post-entry backup.

Tests of this tooling:

| Test | Location | Asserts |
| --- | --- | --- |
| `test_checked_in_config_is_v1_only` | `ops/test_v1_release.py:65` | `fly.toml` releases with `cc-node provision-v1` |
| `test_v1_requirements_each_refused` | `ops/test_v1_release.py:80` | Each missing or invalid requirement is refused |
| `test_identity_and_config_refused_before_any_fly_call` | `ops/test_v1_release.py:302` | Refusals happen before any Fly call |
| `test_v1_fresh_is_production_only_and_exclusive` | `ops/test_v1_release.py:316` | `--v1-fresh` excludes the v0 modes |
| `test_v1_fresh_validates_then_runs_v1_acceptance` | `ops/test_v1_release.py:392` | Acceptance runs before promotion |
| `test_lifecycle_order_and_mismatched_identities_refused` | `ops/test_v1_acceptance.py:527` | Acceptance order and identity refusals |
| `test_provision_not_idempotent_fails` | `ops/test_v1_acceptance.py:611` | Acceptance fails if provisioning is not idempotent |
| `test_release_sequence_and_backup` | `ops/test_v1_e2e.py:119` | Provision twice, then restore, against real PostgreSQL and the built binaries |
| `test_refuses_other_fold_identity` | `ops/test_v1_backup.py:249` | Backup verification refuses another fold identity |
| `test_mismatched_node_refused` | `ops/test_v1_checks.py:308` | Production checks refuse a mismatched node |
| `test_production_default_never_writes` | `ops/test_v1_checks.py:269` | Production checks are read-only by default |

`ops/test_v1_e2e.py` skips unless `TEST_DATABASE_URL` and v1-capable debug
binaries are present, and skips its dump/restore half unless `pg_dump`,
`pg_restore` and `psql` are version 18. `ops/test_v1_backup.py` skips without
`TEST_DATABASE_URL` and, for its restore cases, without version 18 client
tools. A green CI run therefore does not by itself show that the restore halves
ran.

## What ran at launch

The owner's launch record in [HOLD.md](../HOLD.md) states that v1 was released
onto the fresh database and that the inaugural Engelbart 1968 Genesis was
admitted on 2026-10-02 as the only entry, with private ingress and posture `live`.
The release path above refuses to finish unless every one of its checks passes,
but the evidence that it ran (acceptance, backups, `/health`, receipts) is held
privately by the owner and is not reproduced here. This repository cannot show
that evidence; it shows what the path checks and that each check is tested.

Every stage merge commit has a passing `main` CI run, listed in the
[release notes](releases/v1.0.md#stages). That CI runs format, Clippy, the wasm32
build, rule-vector agreement, `cargo test --all` against PostgreSQL, the Python
operator tests, and the Stage 0 checker and mutants.

## Open items that touch the gates

- No v1 hot-key commands (Gate 4): G2 in [STAGE-G.md](design/STAGE-G.md).
- No signed node receipts at runtime; receipts are excluded from authority by
  design (Gate 1): G4.
- No external anchoring of commitments: a MULTI-SIGNER non-goal; sealing
  options are G4.

Disposition of #6 is the owner's decision.
