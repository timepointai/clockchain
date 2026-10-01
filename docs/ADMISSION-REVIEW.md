> Current v1 implementation: [Stage (d) review boundary](design/STAGE-D.md).
> The normal node remains legacy. The owner selected full stages (a)–(e);
> Refs #6, with final disposition reserved for the owner after (e) and operational evidence.

# Node admission and review contract

This describes source behavior, not a deployment receipt. Standing owner
constraints are in [HOLD.md](../HOLD.md).

The [multi-signer v1 design](design/MULTI-SIGNER.md) is accepted and merged in
PR #7. PR #8 delivered the non-serving [Stage (a)](design/STAGE-A.md) foundation;
[Stage (b)](design/STAGE-B.md) implements authority in the separate v1 store.
The normal node still runs the legacy behavior below. Issue #6 remains the open
launch-gate tracker; model evidence, intermediate software and green CI do not
pass its remaining runtime or publication gates.

## Owner decision — 2026-09-28: immutable HTTP body bindings

The repository records a **DECIDED** timepoint-telemetry ruling in
[`a_correction_may_move_its_subject_by_recorded_decision`](../crates/cc-ledger/tests/supersession.rs):
supersession is the ledger's correction mechanism; subject- and coordinate-moving
corrections are permitted with a recorded decision at mint time naming the old/new
subject or coordinate, evidence, and resolver. The doctrine is **bind the writer,
not the projector**. The fold follows the head in every column. That decision
artifact is currently a writer obligation, not a field the fold validates.

**Owner decision (Sean McDonald, 2026-09-28): keep the HTTP override.**
Bound entity bodies are immutable over HTTP; a body correction means a new
entity. This decision supersedes the prior correction policy **for HTTP ingress
only**. Rationale: strict admission can be relaxed later without invalidating
accepted events; loose admission cannot be tightened without orphaning history.
The owner supplied the independent policy decision and authorized merging #5
following green CI. No further policy approval is pending for this override.

The ledger fold and direct import remain unchanged. The owner decision does not
approve their unresolved correction behavior. The
[Pre-first-publish gates issue](https://github.com/timepointai/clockchain/issues/6)
tracks fold rebinding, versioning, authority, sibling conflict, recorded decisions,
cross-author backdating (priority), and corrections through unguarded import.
None blocks this merge; all block the first production entry. Characterization
and `known_gap` test annotations identify current behavior that a later governed
fix may intentionally change.

The correction-path gap below is consequently **partly introduced by this PR**:
pre-PR raw HTTP submission reached the permissive ledger correction fold. The
owner-publisher's missing erratum workflow predates this PR. These are separate
facts. The raw `Supersession` edge is not a substitute for the decided moment
supersession mechanism.

## Signed HTTP events

`POST /v1/events` verifies the canonical event signature, then checks subject
bindings and appends in the same transaction. It holds `SHARE ROW EXCLUSIVE`
locks on `moments`, `edges`, and `entities`, in that order, through commit. These
locks conflict with ordinary projection writes as well as concurrent HTTP calls.
A read credential remains unable to write; frozen posture still refuses writes.

For a new event:

- An existing entity ID cannot acquire a different resolution key or canonical
  name (`409 subject_identity_reused`). Window changes with the same identity
  fields are not subject substitutions.
- A moment requires a known entity. Once that entity has a moment, a different
  body commitment is rejected: `destination_subject_changed` if an edge targets
  it, `source_subject_changed` if it only sources edges, otherwise
  `subject_identity_reused`. These are `409` responses with no appended event.
- A superseding moment must refer to a known current head and preserve both
  subject ID and body hash. Unknown/non-current ancestry or a stored descendant
  awaiting this event returns `409 subject_binding_unavailable`; admission must
  not activate an unreviewed descendant with a different projected subject.
- A new edge requires both entities to exist and each to have exactly one
  distinct projected body hash. Missing or ambiguous endpoints return
  `409 edge_target_mismatch`. A birth cannot silently resolve legacy dangling
  moments/edges under a newly assigned identity.

The HTTP event schema carries an opaque moment body hash, not claim prose or
subject kind. Therefore this guard conservatively refuses **every different body
under an already-bound entity**, including a possible same-subject prose edit.
It does not classify prose, verify evidence, or manufacture a new identity. A new
claim body needs a separately reviewed entity and separately asserted edges.
The raw edge schema remains entity-based; no new body binding is invented inside
its existing signed bytes.

Exact signed events already in the ledger still return `201` / `unioned`, even
if they predate this admission policy. Canonical encodings, event IDs, migrations,
and the deterministic ledger replay/fold are unchanged. Ledger import/rebuild and
other direct database writers do not run this HTTP policy. This is an admission
boundary for fresh node requests, not a new consensus rule or a claim that every
possible writer is constrained by it.

Publisher candidate validation, attempt status/retry and owner dry-run are
separate application workflows; they are not HTTP node endpoints. They must not
be reported as having passed a live node check merely because a local CLI passed.

## Direct-import rebinding: measured fold behavior

The characterization tests in
[`crates/cc-ledger/tests/rebinding.rs`](../crates/cc-ledger/tests/rebinding.rs)
import two entity births, E's moment H1, an influence edge targeting E, and a
signed moment H2 via `cc_ledger::commit`, bypassing HTTP admission. Each case
checks **all 120 permutations** of those five events, plus rebuild and exact
re-import. The event set and entire projection digest converge in every tested
ordering, including edge-before-birth and correction-before-parent orderings.

| H2 form | Moment projection for E | Incident edge |
|---|---|---|
| No `supersedes` | Two independent rows: H1 and H2 | Still targets E, `status = 0` (proposed), `in_g = true` |
| `supersedes = H1.event_id` | One row: root H1, head H2, body H2 | Still targets E, `status = 0` (proposed), `in_g = true` |

All five signed events remain stored. **Neither case creates an explicit
rebinding-conflict state.** Deterministic convergence does not make the retained
edge historically valid for H2. Thus #5's HTTP refusal must not be described as
fold-level binding immutability or as protection against direct import.

### Broader characterization

The same test file adds:

- `backdated_cross_author_sibling_wins_and_hides_the_other_in_all_720_orders`:
  two different signers supersede H1. The backdated correction wins in all 720
  permutations of the six events. Its coordinate, body and author become the
  projected head; the original writer's sibling remains stored but unprojected.
  The incident edge remains proposed and in the graph. Rebuild and union agree.
- `subject_moving_correction_leaves_incident_edge_on_old_entity_in_all_720_orders`:
  H2 moves the moment from E to a third entity in all 720 permutations. E then has
  no projected moment, but the incident edge still targets E with `in_g = true`.
  No recorded-decision artifact is supplied; the fold does not enforce one.
- `original_writer_attestation_does_not_select_a_losing_correction`: a signed
  attestation by the original writer targeting the losing sibling is stored,
  but does not change which correction projects, including after rebuild.

The two earlier 120-order tests plus the two 720-order tests cover **1,680 import
orderings**. These establish behavior of the tested small event sets, not totality
for arbitrary input: the ledger's existing `MAX_CHAIN` refusal remains a bound
with documented arrival-order consequences.

The HTTP test
`http_same_body_correction_can_backdate_and_change_author_but_not_target_a_stale_head`
shows the complementary admission limit. A different signing key submitted with
the full bearer credential can supersede the current head with the same subject
and body but an earlier coordinate; it receives `201`, and the head's coordinate
and author change. A sibling targeting an already-stale head receives `409
subject_binding_unavailable`. Thus the node prevents that particular stale-head
sibling submission, but does **not** enforce subject-owner authority or the
recorded-decision obligation for coordinate movement. Bearer authorization is not
correction authority. This is a characterization, not approval of that behavior.

## Legacy gaps and the accepted replacement

The accepted v1 design chooses B: explicit conflict projection with immutable
revision entities. The sections below retain the legacy gaps that motivated it;
they do not reopen accepted design decisions. The legacy canonical-child rule
still hides siblings. The intermediate v1 stages have not yet implemented the
complete conflict projection or integrated it into normal node runtime.

### Protocol identity and replay compatibility

`protocol.rs` promises that different `filter_version` values identify governance
differences and different `corpus_digest` values identify different event sets.
Today the corpus digest commits to events; the filter version does not include
a ledger-fold implementation digest. `view_root` hashes projection contents
without a fold-version domain tag. A different build string helps identify an
artifact, but is not a governed rule identity.

The HTTP test
`projection_only_divergence_can_change_verdict_without_protocol_or_corpus_identity_change`
injects projection divergence in an isolated database. Merely marking an edge
challenged and out of `in_g` leaves the verdict Supported: neighbor queries ignore
both fields. Removing that projected edge changes the verdict to Unsupported
while the event IDs, `corpus_digest`, `filter_version`, and `/health` remain
identical; `view_root` changes. This is fault injection demonstrating the identity
gap, **not** an implementation of B or evidence of two released fold versions.

Before a conflict rule can exclude edges from the filter's graph, its governed
identity must cover the fold-to-graph interpretation. Either incorporate those
rules into `filter_version` (including any needed view/neighbor logic), or add an
explicit fold version to the protocol identity, verdicts, peer comparison and
cache keys. A standalone label or build SHA is insufficient. The decision must
also specify versioned projection commitments, old-event replay, old-root
verification, and mixed-version refusal/diagnostics without rewriting existing
identity or applied migrations. Same events under different decision-relevant
folds must be distinguishable before consumers compare verdicts. No versioning
choice or hash change is made in this PR.

### Decisions, conflicting siblings and signing authority

Any candidate design must cover siblings (including losing descendants), body
rebinding, subject moves and coordinate moves, with or without incident edges.
It must define who can authorize a correction, whether and how that authority
changes, and how backdated cross-author claims are held or contested. A signer
choosing an earlier `event_time` must not acquire authority merely by winning the
canonical-child comparison. Visibility must distinguish stored, projected,
contested and resolved readings rather than calling storage alone preservation
of the reviewable evidence.

A single recorded-decision mechanism could connect the earlier ruling to conflict
resolution, but it needs a signed, replay-visible binding to the exact correction,
old/new subjects and bodies/coordinates, evidence, resolver and decision rule.
It must specify competing decisions, revocation, authority changes and arrival
before/after the corrected event. The existing `AttestationBody` contains only a
target; its envelope identifies a signer and time. It has no owner role, approval
verdict, rationale or old/new bindings, and `project_attestation` only stores it
and updates counts. The attestation test confirms that it does not resolve a
sibling. Treating it as an owner approval would require new governed semantics,
not an inference from its signature. The accepted v1 design answers these
questions; complete resolution semantics and normal-runtime integration remain
implementation gates.

## Correction path under #5

The HTTP test
`erratum_cannot_replace_a_body_but_can_be_a_separate_supersession_assertion` in
[`crates/cc-node/tests/api.rs`](../crates/cc-node/tests/api.rs) establishes:

1. Changing E's body H1 to H2, even with valid `supersedes = H1.event_id`, returns
   `409 destination_subject_changed` when E has an incoming edge.
2. A separately created E2 with H2 is accepted. The existing raw signed
   `EdgeRelation::Supersession` from E2 to E is also accepted.
3. That edge is **only an assertion**: E still reads H1, E2 reads H2, both entities
   remain present, and the original influence edge still targets E. No reading
   is retired, no edge is transferred, and no erratum status is computed.

There is **no in-place claim-prose erratum path through this PR's HTTP guard**;
that restriction is introduced by #5 and is authorized by the 2026-09-28 owner
decision for HTTP ingress, superseding the earlier correction policy there. Separately, there is no owner-publisher erratum workflow. The publisher's `relation`
function still accepts only influence, causation, participation and co-occurrence;
it cannot express the raw Supersession relation through a candidate. Its moments
also use `supersedes: None`. Manually composing separate signed entities/edges is
a low-level assertion mechanism, not a completed correction workflow. Direct
ledger import can supersede H1, as the fold tests show, but it bypasses this
admission policy. The existing ruling permits writer-operated correction with a
recorded decision; direct import alone does not establish that the writer met
that obligation. No new correction path is built in this PR.

## Stored prose and media reads

`GET /v1/entities/{id}?as_of=...` returns each reading's exact retained `body`
string beside `body_hash`, with `body_status: retained`. If the attachment is not
retained, it returns null and `body_status: unavailable`. A nonexistent entity
remains `404 not_recorded`. Consumers must use node bytes or show unavailable,
never rebuild prose from a private attempt. A retained attachment is not by itself
historical verification; its commitment can be independently rehashed.

`GET /v2/media?entity_id=...&as_of=...` returns only bodies with admitted media
records. A claims-only entity has `readings: []`. Nonempty reading states are
`generated`, `deliberately_unillustrated`, and `conflicting_media_records`.
Deliberate absence requires a signed decision. Missing private PNGs, failed
fetches and withholding never create one. Stale/conflicting records stay visible.

## Verification scope

The real-Postgres HTTP tests in `crates/cc-node/tests/api.rs` create synthetic
local entities and signed events, never use the inaugural pair, and check:

- A valid influence edge cannot survive an admitted destination-body rewrite;
  rejection leaves the event count and projection digest unchanged.
- Identity reuse, supersession to another subject, missing edge bindings and
  held ancestry are refused. Competing first bodies cannot both be admitted.
- Exact replay and same-body continuation still work.
- A local claim's correctly hashed attachment is returned verbatim, missing
  prose is explicit, and claims-only media creates no signed absence.

These are local checks. A deployment must separately identify its source SHA and
immutable image digest and retain private endpoint/status receipts. An empty
production node can prove empty reads and missing-entity errors, not positive
stored-prose behavior. Exercise populated cases against the same immutable image
with isolated synthetic data; never populate production to make a check pass.

Python test-count differences are reconciled by name in
[TEST-ACCOUNTING.md](TEST-ACCOUNTING.md), with a reproducible discovery script.
