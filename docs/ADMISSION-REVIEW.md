# Node admission and review contract

This describes source behavior, not a deployment receipt. Standing owner
constraints are in [HOLD.md](../HOLD.md).

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

**Recommendation — B:** Keep the fold deterministic over valid signed event sets
and represent rebinding and its affected edges as explicit `conflict`, rather
than silently treating the surviving body as the edge's original subject. This
preserves contradictory evidence and leaves room to distinguish an erratum from
a subject replacement. Rejecting whichever binding arrives second would break
order independence; option A would need a precisely defined, order-independent
validity rule before it could replace the existing fold. B still needs a separate
reviewed design for conflict propagation and resolution. Neither A nor B is
implemented by this PR.

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

There is **no supported in-place claim-prose erratum path** through #5's HTTP
admission, nor an owner-publisher erratum workflow. The publisher's `relation`
function still accepts only influence, causation, participation and co-occurrence;
it cannot express the raw Supersession relation through a candidate. Its moments
also use `supersedes: None`. Manually composing separate signed entities/edges is
a low-level assertion mechanism, not a completed correction workflow. Direct
ledger import can supersede H1, as the fold tests show, but it bypasses this
admission policy and is not an approved erratum path. No correction path is built
in this PR.

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
