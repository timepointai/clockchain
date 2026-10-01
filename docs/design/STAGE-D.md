# Stage (d): pinned edges and revision-scoped media

The owner authorized this boundary on 2026-09-30, after merging Stage (c) PR #10
(`1b6b9afd9c1b11df7e0465ff93b3337978356da7`). The ship sequence is the full
(a)–(e). Refs #6. Its final disposition belongs to the owner after Stage (e) and
operational evidence. This PR stops at first review.

The Rust v1 module now admits and projects EdgeAssert, EdgeReaffirm and
Attestation candidates, and derives an enforced neighbor/support graph from the
projection. The normal node binary remains legacy. The review adapter is still
separate from normal boot; `/ready` and store readiness refuse with
`stage_d_non_serving`. This is not the governed Stage (e) fold identity, filter
verdict commitment, `as_of` query or publication route.

## Admission

Subject events are classified first and unchanged; edges and attestations only
read them, so they cannot affect subject authority, frontiers or revisions. An
edge or attestation is never a subject parent (`wrong_subject`). All three kinds
carry no subject, subject key, grant or asserted time (`non_subject_header`).

EdgeAssert has no parents. Its decision is `EdgeAssert`, nonempty rationale and
evidence, old `None` and new `Pins(pins)`. Its relation must be governed:
`causation`, `co_occurrence`, `disputes`, `influence` or `participation`. Each
endpoint pin `(subject, basis, revision, body)` must name a Genesis subject and
a valid event of that subject whose selection is exactly the pinned revision,
which binds exactly the pinned body hash. A missing subject or basis is
`pending / pin_missing`; a pending basis is `pin_pending`; an invalid basis is
`pin_invalid`; otherwise mismatches are `pin_subject`, `pin_revision` or
`pin_body`. Identical body bytes in another revision fail `pin_revision`.

A `disputes` edge is a counterclaim: its source is the disputing author's own
separate Genesis subject and its target is the exact disputed revision; anything
else is `dispute_counterclaim`. It cannot name the disputed subject as a parent
or use its grant, because edges have neither. It never supersedes the target or
supplies support.

EdgeReaffirm names the original edge, one or more prior edge events of that same
edge as sorted `parents[]`, one exact old-pin pair per parent and the new pins.
Only the original edge author can sign it (`edge_author`); endpoint subject IDs
must not change (`endpoint_changed`) and the relation is not in the payload.
Multiple parents must be incomparable (`comparable_parents`). The decision's old
value is `ParentPins(old)` and new is `Pins(new)`. New pins are checked exactly
like an assertion's. Missing parents or the edge are pending; an invalid one is
`ancestor`. No delegated edge-author rotation exists.

Attestation has no parents and a nonempty artifact kind. A revision target is
valid once that revision is known, otherwise `pending / revision_missing`. An
event target must be a retained subject or edge event: missing is pending,
invalid propagates `target_invalid`, and an attestation target is
`attestation_target`.

## Edge projection and enforced neighbors

Each valid EdgeAssert's identity is its event ID. Its valid assertion and
reaffirmations form an author-only chain; maximal events are the edge heads.
Several heads are `edge_conflict`: heads and non-common history are
`branch / edge_conflict`, older history is superseded. Every valid chain event
stays in `history` and in the all-event rows, so historical pinned readings
remain addressable.

With one head, each endpoint is compared with its subject reading. A contested
subject gives `subject_contested`; a subject with no current body gives
`no_current_body`. For a resolved head: basis not reflexively below the head is
`basis_not_ancestor`; a different selected revision is `revision_changed`; any
Correction or merging Resolve in `ancestors(head) - ancestors(basis)` is
`revision_created_since_basis`. Status precedence is invalid/pending (row
state), `edge_conflict`, `endpoint_contested`, `stale`, `current`. Reasons are
prefixed `source:`/`target:` and the pins at every head stay visible. Delegate
and Revoke steps do not stale an edge; selecting the old revision after a
correction does not restore it. Only reaffirmation advances the basis.

`support_graph(projection, curators)` takes an explicit curator key set. Only
current, non-dispute edges whose author and both endpoint creators are curators
enter `neighbors`. Every other edge, and every pending or invalid assertion or
reaffirmation, is listed in `excluded` with all its reasons. `query(from, to,
max_hops)` is two-valued: `Supported { path, excluded }` or
`Unsupported { reasons }`. A contested subject yields `subject_contested`; there
is no `Contradicted` variant, so conflicting readings and missing support cannot
become a falsity claim. Both answers name the excluded edges and disputes
touching either subject. The search stops once no unvisited subject remains, so
a large hop bound cannot spin.

## Revision-scoped media

A media reading binds an attestation to its exact target. A revision target and
an event that created a revision bind that revision and body hash; other event
targets bind the event only. Nothing follows a correction, so a new revision can
have zero media readings while prior images and signed absences stay on their
original revision. No media state is inferred from a missing image, stale edge
or new revision, and no binding is retargeted. Artifact bytes are not stored.

## Store boundary

Edges and media are recomputed from verified retained candidates; no derived
table is trusted. A contract marker in the interim bootstrap changes its schema
hash, so Stage (b) and (c) stores refuse silent reopening; tests provision fresh
stores. Applied v0 migrations, legacy encoding and the frozen v1 vectors are
unchanged; the reserved EdgeAssert, EdgeReaffirm and Attestation payloads are
used as encoded in Stage (a). No deployed store is touched.

## Evidence

`i5_pins_survive_correction_resolution_and_reaffirmation` covers both endpoints,
same bytes in a new revision, correction then selection of the old revision,
authority-only changes on both subjects, a contested endpoint, author-only and
endpoint-preserving reaffirmation, competing reaffirmations and their
multi-parent resolution. It checks actual neighbors, support queries and media
bindings, not only labels. Focused tests cover each remaining rule:
`basis_outside_current_head_history_is_stale` (a suppressed sibling basis that
selects the head's revision; deleting the `basis_not_ancestor` check locally
makes it fail), a cascading Revoke that keeps an edge current, a selecting
Resolve after an authority-only fork that restores `current`, the exact reason
codes `pin_pending`, `pin_invalid`, `wrong_edge`, `target_invalid`,
`target_pending`, `same_subject` and `wrong_subject` for a subject event with an
edge parent, termination with an unbounded hop limit, and exclusions that remain
visible in a supported answer. Another test covers exact pin, relation, dispute,
trust-root and media admission.

`i3_edge_subset_and_partition_invariants` reads **768** subsets (every subset of
six named seven-event cases) and **1,202** parts of 480 seeded two- or
three-way partitions of 60 generated DAGs of up to 17 events (forks, merges,
delegates, edges, disputes, reaffirmation forks and joins, non-author
reaffirmations, media) independently. Each check requires one row per
candidate, the signed pins at every edge head, current edges only on resolved
selected revisions, enforced neighbors, no pending or invalid edge in support,
and media bound exactly as in the full set. Generated full views reached every
edge status. The projection is a function of a set, so a union of parts is the
full set itself; no union equality is claimed as evidence.

`i1_edge_store_delivery_order_convergence` tests order through the real
PostgreSQL store, where each delivery is a separate `Store::admit` transaction
that rereads retained bytes. It runs **56** delivery orders (six per named case:
listed, reversed child-before-parent and four seeded shuffles; two for each of
ten generated DAGs), each on a fresh store and each ending with two duplicate
redeliveries: **682** admissions in total. Every arrival result must equal the
classification of the events delivered so far. The stored projection and
support graph must equal the full set's, and a reversed restore replay must
leave the classification unchanged.

`i7_edge_http_import_restore_admission_parity` sends sixteen inputs, including
child-before-parent edges, reaffirmations and media, a bad signature, wrong pin,
foreign reaffirmation and duplicates, through HTTP, import and restore on three
real PostgreSQL stores, comparing every outcome and full projection.

Exact local versus exact-head CI results accompany the PR. The accepted Stage 0
model, checker, receipts and HOLD bytes are unchanged; edges are outside the
model's abstraction. This is bounded implementation evidence, not exhaustive
production correctness.

## Open questions for owner

Each takes the most conservative reading; none changes a MULTI-SIGNER rule.

1. The governed v1 relation list above omits legacy `supersession` and
   `attestation`, which v1 represents by other means.
2. All current non-dispute relations give positive support; adjacency is
   undirected with an explicit hop bound until Stage (e) governs parameters.
3. A dispute's author must be its source subject's creator; this does not bar a
   target authority from disputing through its own new subject.
4. An endpoint with no current body is `stale / no_current_body`, not a contest.
5. Curator trust is an explicit parameter keyed on Genesis creators; Stage (e)
   pins the governed trust root and filter identity.
6. Attestations may target subject or edge events, not attestations. Event
   targets bind a revision only for its creating event.
7. Non-dispute self-edges are admitted, and a reaffirmation may pin an older
   basis (it is then stale); the design states neither rule.
8. A same-subject support query is `Unsupported / same_subject`.

## Owner notes (recorded, behavior unchanged)

- Attestation `revision_missing` lists the revision hash, not an event ID, in
  `missing`. It stays pending forever if the creating event is invalid, because
  that revision can never become known.
- An authority-only concurrent fork, such as two Delegates, makes the subject
  contested. Its edges are then `endpoint_contested` with no support, although
  the selected revision is unchanged; this follows the "unique resolved" wording.
  A selecting Resolve restores `current`.
- Resource bounds: reaffirmation classification is a fixed point that is
  O(L^2) in chain length L, and the projection is O(edges x candidates).
  Neither is qualified for serving-scale histories.

## Remaining boundary

Stage (e) (final governed manifest, trust root, versioned roots/verdicts/cache/
export/restore, `as_of`, refusal paths and native/Wasm checks), runtime
integration, fresh-store provisioning, immutable-image operational evidence and
a separately authorized content/publication session remain required. Current
live event counts remain unknown. [HOLD.md](../../HOLD.md) remains unchanged.
