# Node admission and review contract

This describes source behavior, not a deployment receipt. Deployment and
publication are separate owner actions. No historical fixture is needed to test
this contract, and no fixture belongs in a production verification procedure.

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
