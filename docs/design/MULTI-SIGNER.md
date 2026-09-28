# Multi-signer admission and projection v1

Design decision proposed for owner approval, 2026-09-28. **Design only: none of
this is implemented by this PR.** Implementation requires subsequent owner
approval. [HOLD.md](../../HOLD.md) remains the operating boundary.
This specifies every gate in [#6](https://github.com/timepointai/clockchain/issues/6).
Decided below means a concrete choice in this proposal, not a completed gate or
authorization for the first production entry.

## Attack result and replacement decisions

The starting sketch is unsafe if “authority at the fork point” alone can resolve
its descendants. With authorities A and B at P, A can revoke B while B writes a
correction from P. Both are authorized at P. Allowing B to select its own branch
would erase the revocation. A delegation by B on that branch could give C the
same escape. Neither receipt order nor a timestamp can distinguish the branches.

Decisions:

1. Resolve requires a **surviving common authority grant**, active at every named
   parent and still active after combining their revocation evidence. Authority
   at the common ancestor alone is insufficient. Revocations cannot be discarded
   by selecting a different body.
2. Revocation removes a key permanently for this subject. A delegation concurrent
   with revocation of its issuer is canceled at their join, including grants
   derived from that delegation. A delegation causally acknowledged before the
   revocation survives: revoking a delegator is not retroactive revocation of
   every previously independent delegate. Reusing a revoked key is prohibited;
   rotation uses a fresh key.
3. A resolution covers its explicitly signed causal frontier, not unseen events.
   A late sibling reopens `contested`. No finality or eventual delivery is assumed.
   A revoked key cannot unilaterally produce the sole head of a set containing its
   revocation. Before that revocation is delivered, a replica can have a different
   head; claiming otherwise would require coordination absent from this design.
4. If no common authority survives, the subject stays contested/frozen. Curators
   cannot bypass subject authority. A new subject and a disputes edge preserve an
   alternative assertion. Availability against a malicious full authority is not
   promised; unauthorized resolution is prohibited.
5. `parent_head` is a causal reference, **not an arrival-time CAS against the
   database's current head**. Stale known parents are admitted as branches;
   missing parents are pending. A current-head-only CAS would violate I1.
6. Body revisions get new immutable entity IDs under a stable subject aggregate.
   This preserves #5's entity/body immutability while making correction explicit.
   The HTTP-only bypass distinction ends: HTTP and import use the same admission.

These decisions choose **B: explicit conflict projection**, with immutable
revision entities. They do not choose A's rejection of every later body binding.
They replace the current timestamp/hash winner rule, rather than label its winner
as contested while continuing to feed it to the filter.

## Identity, trust and scope

A `SubjectGenesis` establishes a new aggregate. Its event ID is `subject_id`;
there is no caller-assigned reusable integer identity in v1. Its signed
`subject_key` is the fixed tuple `(kind, namespace, value)`: kind is a pinned
ontology identifier, namespace and value are explicit UTF-8 identifiers. For
example, a machine and a document about that machine have different kinds.
Every transition repeats the exact tuple. It cannot edit it through a body,
resolution, authority event or import. A different tuple requires a new genesis.

The tuple is inspectable identity, not a proof that prose describes that subject.
A writer lying about an unchanged tuple remains an evidence-review problem.
Different genesis events can assert the same tuple without sharing authority;
they are separate subjects, visible as possible duplicates, never auto-coalesced.
A random 32-byte genesis nonce distinguishes independent creations; it conveys
no priority. Human names and hash sort order are not authority.

`revision_id = SHA256(frame("cc.revision.v1") || subject_id || creating_event_id)`.
Genesis creates the first revision; Correction and a merging Resolution create
new revisions. Each revision binds exactly one body hash forever. A selecting
Resolution names an existing revision. A revision is an entity for body/media
binding; a subject aggregate is the explicitly mutable set of revision readings.
Read APIs return both IDs and never present the aggregate as a mutable old entity.
The creating event carries the body hash, so this formula has no self-reference.

Each subject starts with one full authority grant to its creator. Any number of
keys can become authorities by signed delegation. No sole-writer assumption,
shared signing key, or per-instance bearer credential establishes this authority.
All events name an instance ID to prevent cross-instance replay.

The nonempty instance curator key set is a boot-pinned trust root in the v1 filter
identity, **not a ledger event**. Any signer can create a subject and counterclaim;
a genesis creator outside this set is marked `untrusted_origin`, not rejected.
Only resolved subjects rooted in this set, including their authorized revisions,
can supply positive filter support. Other assertions and disputes remain visible
for review without automatically granting themselves support. An edge must also
meet that trust rule for its original author and the endpoint eligibility rules
below. Changing the curator set changes filter identity. Curators cannot rewrite
another subject, resolve its fork without a subject grant, or confer authority
by an ordinary Attestation. No key is inferred to be an independent human/source.
This explicitly replaces the current assumption that every filter-governance
change must itself be a node-0 ledger moment, for this v1 trust-root field only.

## Canonical encoding: version 0 to version 1

**Bump `CANON_VERSION` from 0 to 1.** The multi-signer design is v1, not a v0
reinterpretation. Production has zero entries per the owner; there is no history
migration or automatic re-signing. A future v1 installation uses an empty v1 event
store. A nonempty v0 store is refused, not silently converted. Existing private
fixtures and applied migration bytes remain unchanged; schema provisioning for
v1 is new work, not edits to applied migrations. Coordinate constants remain at
`CONSTANTS_VERSION = 0` because this decision does not change tick arithmetic.

All v1 signing preimages use SHA-256 and existing Ed25519 keys, with this fixed
field order:

```
frame("cc.event.v1"), u16(1), u16(constants_version), instance_id[32],
u16(kind_tag), author_key[32], subject_ref, subject_key,
signer_grant_ref, parents[], optional(asserted_time), typed_payload
```

Genesis uses an empty subject/grant reference and no parents. All other subject
transitions include the genesis event ID, their signer grant ID and parents.
Non-subject event kinds use their explicitly typed references below, not an
untyped `supersedes` escape hatch. Author is now identity-bearing for **every**
event, unlike v0 content-addressed events. `event_id = SHA256(preimage)`; the
signature signs that domain-separated preimage. A different author cannot union
into an existing author's operation. Exact valid duplicates remain idempotent.

Integers and lengths are big-endian; variable bytes use u32 length prefixes;
optionals use a 0/1 tag; IDs and keys have fixed lengths. Sets are sorted by raw
bytes and reject duplicates. Parents, evidence references and grant references
are sets; human rationale is not. UTF-8 is validated and compared byte-for-byte;
there is no implicit Unicode, case or whitespace normalization. Identity tuple
fields must be nonempty and at most 1,024 bytes each. Canonical envelopes are at
most 1 MiB, with at most 1,024 parents and 1,024 evidence references. Bodies live
outside the envelope under their commitments. These limits are versioned rules.
There is no consensus chain-depth cutoff or arrival-dependent work limit.

Unknown tags/versions, noncanonical sets, trailing bytes and bad signatures are
rejected before semantic storage. No decoder ignores the version words. Existing
body/media bytes keep their own content hashes; they do not acquire historical
validity from this version bump. All future media references bind revision ID
and body hash; absence remains a separate signed decision.

An independent `NodeReceiptV1` signs `(instance_id, node_key, event_id,
received_at, encoding_version, fold_version, initial_admission_result)` in the
`cc.receipt.v1` domain. `received_at` is node observation time, never writer claim
time, never proof of historical occurrence or global order. Receipts can differ
between nodes/retries. They are excluded from event identity, the semantic event
set digest and projection commitment. Their signatures authenticate observations;
they do not confer subject authority or influence fork selection.

## Event types and signed decisions

The following tags define the new identity-bearing schema. All references are
content IDs, never row IDs. Supporting source hashes name exact stored artifacts.

| Tag | Event | Payload and effect |
| --- | --- | --- |
| 1 | SubjectGenesis | Nonce, subject_key, initial body_hash, asserted_time/precision and evidence references. Creator obtains root grant `H("cc.root-grant.v1", event_id)`; creates first revision. |
| 2 | Correction | One parent; same subject_key; new body_hash and assertion coordinate/precision; mandatory decision below. Creates a new immutable revision. |
| 3 | Delegate | One parent; fresh grant event ID, grantee key and issuer_grant_ref. Full subject authority only in v1. Carries decision and evidence; copies parent's body selection. |
| 4 | Revoke | One parent; target key active at that parent, decision and evidence. Permanently revokes that key for this subject; copies body selection. Self/last-key revocation is allowed and explicitly freezes further writes. |
| 5 | Resolve | At least two incomparable parent heads in this subject; exact per-parent dispositions, selected revision or new merged body, mandatory decision. Joins causal history and revocations. |
| 6 | EdgeAssert | Author, relation, both endpoint pins, evidence and decision. Edge identity is this event ID. Includes `disputes` as a new governed relation, not an alias for influence. |
| 7 | EdgeReaffirm | Original edge ID, prior edge head(s), exact old pins and new pins, evidence and decision. Must be signed by original edge author; multiple parents explicitly resolve an edge fork. |
| 8 | Attestation | Exact event/revision target and typed supporting artifact reference. No correction, delegation, resolution or curator-approval power. |

A subject event inherits its stable subject_ref/key through the explicit fields;
Resolve cannot change either. Delegate/Revoke cannot smuggle a body or assertion
time edit. Existing unrestricted Moment supersession is **not** a v1 event kind.
Legacy event kinds cannot enter through import. Vocabulary and protocol constants
are boot-pinned, versioned inputs for this v1; generic runtime vocabulary mutation
is excluded, not an alternate authority route. Media authoring is revision-scoped
attachment work and cannot change the subject DAG or its authority.

Every Correction, Delegate, Revoke, Resolve and edge change has a canonical
`DecisionV1`: operation kind; rationale text (nonempty); nonempty set of evidence
artifact hashes; exact parent/revision references; and old/new typed values
appropriate to that operation. Resolver is the envelope author/grant. Old values
must equal the referenced state; new values must equal the payload. Resolve
lists every declared parent with `selected`, `merged`, or `not_selected`, and a
rationale for each. A body selection cannot omit the authority consequences of
any parent. This makes the recorded decision available to replay and review;
an opaque decision hash or free-form Attestation cannot stand in for it. Checks
establish integrity and completeness, not historical adequacy of the rationale.

## One admission function, including replay

`admit(rule_identity, candidate_set, envelope)` is the only path to the semantic
store. HTTP performs bearer/size/rate handling, then calls it. Import, gossip,
restore verification and publisher submission call the same function. Raw ledger
append becomes private to this module; there is no exposed bypass flag or legacy
version fallback. Rebuild recomputes from the retained candidates using these
same rules, never trusts a cached admission boolean from another node.

For supported, canonically framed, signature-valid events, admission retains the
candidate and returns `valid`, `pending(missing_refs)`, or `invalid(reason)`.
Invalid semantic candidates are audit evidence with no state-changing effect;
HTTP reports a typed rejection even though that audit record is retained. An
invalid reference propagates `invalid_ancestor`. Unknown dependencies stay
pending. A body commitment whose bytes are unavailable can be structurally valid;
its reading explicitly says prose unavailable and cannot pass evidence review.

Malformed bytes, unsupported versions and invalid signatures get a rejection
receipt keyed by input digest, outside the candidate event set. They are not
ledger events. A bad signature cannot poison a later valid envelope with the
same event ID. This is the exact scope of “every event” in I3; every ingress
attempt is additionally explained by its receipt. Valid-signature semantic
rejections are retained so they cannot disappear merely because a different
import order noticed the error earlier.

Arrival results can differ while parents are missing; final classification for
the same set cannot. A local current-head mismatch is never a rejection reason.
Operational exhaustion returns an unavailable/retryable result without partial
semantic installation; it does not declare an event invalid or choose a branch.
Admission and projection installation are atomic. Any sorting used to schedule
work or serialize rows has no branch selection significance.

## Fold and authority calculus

The fold is a pure function `F(rule_identity, E)` of a finite candidate set.
Dependencies are signed parent/grant/revision references. Missing references are
pending; wrong-subject references, malformed causal structure, dependency cycles
and invalid parents have typed, deterministic reasons. Error sets are sorted by
reason code/reference, not discovery order. DAG evaluation is topological;
multiple ready events are independent computations, not competing transactions.

Each valid subject event has a branch-local state:

```
(body_revision, grant_records, revoke_records, decision_history)
```

Genesis supplies the root grant. A normal transition is valid only if its named
grant belongs to its signer and is active at its parent. There is no timestamp
comparison. It adds its own operation to the causal history. Branch-local
validity is not a claim that the branch is the subject's sole public head.

### Grant survival at a join

Grant records identify their creation event, grantee and the exact issuer grant.
Root grants have no issuer. Revoke records identify target key and causal parent.
At a join, combine records from **all** parents, including bodies not selected.
Compute grants as follows:

1. A revoked key has no active grant. Tombstones never disappear or allow that
   same key to be delegated again within this subject.
2. A non-root grant D issued by key K is canceled if a valid revocation R of K
   exists in the joined history and D is **not an ancestor of R's parent**.
   Thus a delegation acknowledged before R survives issuance; an incomparable
   delegation loses its authority effect at the join. An event after R cannot
   obtain authority from K at its parent in the first place.
3. Cancellation of an issuance propagates through grants naming that canceled
   grant as issuer. This is distinct from ordinary revocation of a holder:
   revoking K does not cancel independent grants K issued before R's parent.
4. Apply these rules to a fixed point over the finite grant DAG. A grantee with
   an independent surviving grant can still act through that specific grant.
   Authority is not inferred from a matching public key on a canceled grant.

For Resolve with parent set P, the signer must name a grant in:

```
intersection(active_grant_ids(p) for p in P)
    intersect active_grant_ids(joined_history(P))
```

This establishes authority at **every** parent and surviving the join; a new
branch-only delegate cannot resolve the fork that would establish its authority.
No single “lowest common ancestor” is chosen by hash in crisscross DAGs. The
resulting authority state includes all surviving grants from the joined history,
not merely the intersection used to authorize the resolver. Independent concurrent
delegations can therefore survive a resolution by a common existing authority.
With no eligible grant, Resolve is invalid with `no_common_authority`.

The revocation rules use only causally valid revoke records. A non-author's forged
or unauthorized revocation has no effect. A grant canceled by a concurrent revoke
was locally valid on its branch; its historical events remain visible, with
`authority_effect_canceled` and the responsible revoke IDs. It does not turn those
events into disappearing bytes or give their descendants authority after the join.

### Frontiers and resolutions

The subject frontier is the set of maximal valid events under parent ancestry.
A normal transition has one parent; only Resolve can join incomparable parents.
One frontier event gives a resolved head (possibly frozen if no authority remains).
Two or more give `contested`: all heads, revisions, authority differences and
unselected branches are returned. The filter obtains **no positive support** from
any branch of that subject until a valid resolution covers the frontier.

A Resolve's declared parents must be pairwise incomparable and within the same
subject. It may select any revision reachable from those parents, including their
common prior reading, or author a new merged revision. Its decisions explain the
selection. It cannot erase events, revoke records or grants by omission from the
selected body. A partial join is valid but does not clear other frontier heads.
This allows bounded joins even when the frontier exceeds the parent-list limit.
A new sibling of an old ancestor always survives as an uncovered branch. Two
competing resolutions themselves fork; neither wins by signature, timestamp,
receipt order or event ID. A later eligible resolution must join them.

Every retained event gets one primary projection status: `head`, `superseded`,
`branch`, `pending`, or `invalid`. In a contest, maximal tips and divergent history
are `branch`; common history is `superseded`. After a full resolution, its tip is
`head` and covered history is `superseded`, with per-branch selection/disposition
and resolving event ID retained. An Attestation/edge assertion has its own visible
record/head; attachments cannot become a subject head. Missing and invalid
records are queryable with reasons. Nothing is stored-but-invisible by design.

### Revocation concurrency traces

Let P carry independent active grants a to A and b to B. They can be constructed
by an earlier, causally completed delegation; P is held fixed in these traces.

| Event set after P | Projection and permissible next action |
| --- | --- |
| R = A revokes B at P; C = B corrects at P | R and C are locally valid; frontier `{R,C}` is contested. Joined authority excludes B. A can resolve; B cannot. C's bytes and decision remain a branch. |
| D = B delegates C at P; R = A revokes B at P | D is locally valid, but its grant to C is canceled at join because D is not an ancestor of R's parent. Only surviving common authority such as A can resolve. |
| D as above; C then delegates X/corrects on D; concurrent R | All descendant branches remain visible. The canceled grant cannot authorize a resolution with R; its derived grants are canceled too. Extending the losing branch never covers R. |
| D is instead an ancestor of R's parent | C's prior delegation survives B's revocation; this is established authority, not a concurrent escape. C can act with its surviving grant at the resulting head. |
| B resolves other siblings before R arrives | That resolution can be a head in the smaller set. Adding the concurrent R makes the union contested; B's resolution cannot cover R and B cannot sign the join. |
| A revokes B and B revokes A, both at P | Both locally valid; both keys excluded at the join. No common authority survives. The contest remains visible and frozen. No curator override. |

All rows are evaluated from the union, never receipt sequence. A resolution by A
may knowingly select the content B proposed, with evidence and an explicit signed
decision. That is A's authorized adoption, not B winning a fork or recovering a
grant. “No revoked key can win” means no unilateral authoritative head covering
its revocation; it does not mean revoked authors' assertions become unreadable.
An adversarial authority can cause a freeze or withhold an event. Consensus here
guarantees set-relative safety, not liveness, identity independence or omniscience.
In particular, a revoked signer can keep revealing new events signed against an
old parent where its grant was valid, reopening contests. V1 deliberately accepts
this availability cost rather than inventing a receipt-order cutoff. Such events
cannot resolve a frontier containing their revocation; no bounded recovery or
finality claim is made.

### Why a revoked key cannot resolve the union

Take a valid revocation R of key K and a proposed sole head H. If R is not an
ancestor of H, some maximal descendant of R remains uncovered, so H is not the
sole frontier. If R is an ancestor, K is absent from authority after R. The first
join between R's history and a K-authored competing branch must check K against
the state on the side containing R and the joined tombstones; K fails. Ordinary descendants
cannot undo that tombstone. Thus K cannot unilaterally cover R and become the
sole head. A concurrent delegation from K also fails common-grant eligibility
and is canceled in the join; transitive delegation does not repair it. An
independent, pre-existing grant is a different authorization, not a resurrected
canceled grant. This argument assumes signature integrity and the same finite
event set; it makes no claim about undisclosed events or key collusion.

## Counterclaims, pinned edges and media

A non-author creates a new subject/revision and an `EdgeAssert(disputes)` naming
the exact disputed revision. It cannot name another subject as its parent or
impersonate its authority grant. A dispute is reviewable evidence, not an
instruction to supersede the target or proof that either claim is true.

An endpoint pin is `(subject_id, basis_head, revision_id, body_hash)`. The
`basis_head` is the exact subject state the author reviewed; it must select the
named revision. Pin **both** endpoints, not only the target: source correction must not silently transplant an assertion
either. The edge stores original author, relation and evidence. Endpoint hashes
must match the referenced immutable revisions; missing revisions are pending,
wrong hashes invalid. Merely possessing identical body bytes is not the same
revision identity.

For the current view an edge is `current` only when both pins match the unique
resolved selected revisions and no revision-creating event has entered either
head's causal history since its pinned basis. Compute that second condition from
`ancestors(current_head) - ancestors(basis_head)`, including the heads themselves;
any Correction or merging Resolve in that difference makes the pin stale. The
basis must be an ancestor of the current head, otherwise the pin is stale too.
A resolution selecting the old body does **not** silently restore an old edge.
Only reaffirmation can advance its basis past a correction. A changed selected
revision also yields `stale`, including identical bytes with a new revision ID.
Contested endpoints produce `endpoint_contested` with the old pins visible. Status precedence is
invalid/pending, then edge conflict, endpoint contest, stale, current. None of
pending, stale, contested or invalid edges enters the filter support graph.
Neighbor queries must enforce this, rather than merely display a label. A query
about a contested subject returns `Unsupported` with explicit `subject_contested`
reasons, never `Contradicted` merely because conflicting readings exist. Excluded
edge reasons remain visible in the proof/read surface; missing support is not a
claim that the historical assertion is false.
Authority-only transitions do not stale an edge if its selected revisions stay
unchanged. Historical pinned readings remain addressable.

Only the original edge author can reaffirm it, naming prior edge head and exact
old/new pins with a decision. Reaffirmation keeps the original endpoint subject
IDs and relation; changing those requires a new edge. It may update revision/body
and basis pins even when the selected body has returned to the original reading.
Reaffirmations form an author-only causal chain;
competing reaffirmations produce `edge_conflict` and no filter support. The
original author resolves them with the same explicit frontier/disposition rule
in an EdgeReaffirm containing multiple incomparable parents (the one-parent case
is ordinary reaffirmation). Its authority is the immutable edge author, not
endpoint ownership. A lost author key leaves the old edge stale/conflicted;
another author must assert a new edge. No delegated edge-author rotation in v1.
The canonical payload uses the sorted `parents[]` field for both cases, and signs
one old-pin pair for each parent in the multi-parent case.

No media decision follows from a missing PNG, stale edge or body revision. A new
revision can have zero media readings. Prior images and signed absence remain
bound to their original revision/body; neither silently follows a correction.

## Rule identity, commitments and reads

The implemented rules get `fold_version = (1, SHA256(canonical_fold_manifest))`.
The manifest includes this authority/visibility/edge interpretation and canonical
rule identifiers; the numeric version must increase for **any** semantic change.
It is not a hash of compiler output. Implementation conformance vectors pin the
manifest digest; this document does not invent a digest for unwritten code.

Filter identity commits to fold_version, encoding version, the exact sorted
curator key set, ontology/constants versions, trust policy and filter parameters.
The event corpus digest still describes the candidate event set, including
signature-valid invalid/pending records; it does not pretend to identify the
projection rule. Projection commitments use:

```
SHA256(frame("cc.view.v1") || canon_version || fold_version || filter_version
       || corpus_digest || canonical_projection_rows)
```

Rows include all statuses/reasons, frontier membership, revision pins, authority
and decision records. Display sorting by ID makes bytes stable, never chooses a
winner. Receipts and local body-availability/fetch errors are excluded from this
semantic root; body bytes have their own hashes and explicit availability reads.

Health, readiness, verdicts, entity/edge reads, export manifests and cache keys
name the full rule identity and corpus snapshot. A node refuses requested or
stored fold versions it cannot implement (`unsupported_fold_version`); it never
serves the current fold under an old tag. Boot with incompatible stored identity
fails semantic readiness. Liveness may expose the diagnostic. Peers cannot compare
verdicts across rule identities as though only gossip differs. Rebuild, restore
and verification require the named version. Old roots are verified only by their
specified verifier; they are not reinterpreted by v1.

`as_of` selects historical claim coordinates **after** authority/conflict folding
of the selected corpus snapshot. Backdating a claim cannot hide its revoke or
choose its authority. Evidence snapshots are named by corpus digest; v1 does not
invent a global “known by receipt time” order. Changing asserted times changes
claim IDs/content and possibly the temporal query result, but never authorization,
frontier selection, sibling precedence or revocation effectiveness.

## Required invariants and named tests

These are **future implementation acceptance tests**, not tests added or claimed
passing by this docs PR. Properties compare canonical projections and all reason
codes, not just a selected body. The implementation must test each distinct set
under every permutation for small cases and generated permutations/partitions for
larger DAGs, including duplicate delivery and child-before-parent delivery.

| Invariant | Required test and oracle |
| --- | --- |
| **I1** Same event set and rule identity, identical projection across orderings and import partitions. | `i1_union_permutation_partition_convergence`: enumerate revoke/correction, revoke/delegate/descendant, mutual revoke, competing resolution and crisscross cases; compare whole root/rows after union, rebuild and duplicate replay. Include partial resolution and late siblings. |
| **I2** No event changes a head without authority valid at its parent(s). | `i2_parent_authority_and_surviving_join_grant`: unauthorized author, wrong grant, parent-missing, branch-only delegate and revoked resolver cannot yield an authoritative head. `i2_revoke_concurrent_correction_no_revoked_winner` and `i2_revoke_concurrent_delegate_cancels_descendants` enumerate all delivery orders; `i2_prior_delegate_survives_later_revoke` pins the causal distinction; `i2_mutual_revoke_freezes_without_curator_bypass` pins safe deadlock. |
| **I3** Every retained event is head, superseded, branch, pending or invalid-with-reason. | `i3_total_auditable_classification`: projection IDs equal retained candidate IDs; statuses are exclusive and exhaustive, rejected branches retain decisions, incomplete parents wake deterministically, semantic rejects remain visible, malformed attempts get separate receipts. `i3_late_branch_reopens_resolved_frontier` prevents invisible siblings. |
| **I4** Subject-key change is never a correction. | `i4_subject_key_immutable_across_all_transitions`: mutate kind/namespace/value or subject_ref in Correction, Resolve and authority events; reject with `subject_key_changed`/`wrong_subject`. New genesis is separate authority; revision/body binding never changes. |
| **I5** Edges stay pinned; correction makes stale, never retargets. | `i5_pins_survive_correction_resolution_and_reaffirmation`: both endpoints, same bytes/new revision, correction followed by selection of the old revision (still stale), authority-only change, contested endpoint and competing reaffirmations; inspect actual filter neighbors and media bindings, not only UI status. |
| **I6** No ordering/authority depends on asserted time. | `i6_asserted_time_and_receipt_noninterference`: regenerate/re-sign isomorphic DAGs with reversed/extreme/equal claim times and different receipt metadata, updating IDs/references; compare authority/frontier decisions under the isomorphism. Roots need not match when signed content changes. Query-time filtering remains a separate test. |
| **I7** HTTP and import have identical semantic accept/reject. | `i7_http_import_admission_differential`: same rule identity, candidate prefix and envelope through both adapters; compare valid/pending/invalid result, reasons and stored projection, including unknown versions, signatures, stale parents, revoked keys, forks and replay. HTTP bearer failures stay outside this comparison; then compare unions across different partitions under I1. |
| **I8** Every commitment names fold_version; unknown version refuses. | `i8_versioned_commitments_and_unknown_refusal`: change fold/curator identity with fixed events; commitments/cache keys differ, health explains it, unknown request/store/export version refuses. Tampered manifest and old-root reinterpretation fail; native/Wasm vectors agree. |

Additional named checks: `v1_canonical_author_bound_roundtrip` (author, grant,
parents and decisions signed; canonical byte vectors); `v1_no_legacy_ingress`
(HTTP/import/restore reject v0 and raw supersedes); `v1_curator_root_is_not_subject_authority`;
`v1_decision_payload_matches_transition`; `v1_resource_exhaustion_is_not_invalid`.
A test that previously characterized a v0 gap is intentionally replaced or kept
under its explicit legacy version; it must not force preservation of that gap.

## Staged implementation plan and size estimates

Estimates are changed lines including meaningful tests and docs, excluding lock
files/generated vectors. They are review sizing estimates, not completed work.
All stages remain unreleased until I1–I8 pass together and the owner separately
opens the first-publication gate. No intermediate stage writes production or
permits a v0/v1 mixed graph.

| Stage | Deliverable and completion boundary | Estimated diff |
| --- | --- | --- |
| **(a) Encoding + single admit()** | v1 typed envelopes/DecisionV1, strict decoder and signer-bound IDs, canonical vectors, new empty-store schema provisioning, retained candidate/rejection interface, HTTP/import adapters to one semantic entry point. Remove public bypasses; restore uses admit. Stage remains non-serving until later semantics land. I4, I7 and encoding checks. | 1,200–1,800 lines across core/admission/schema/API tests. |
| **(b) Authority chain** | Genesis grants, provenance-bearing Delegate/Revoke, branch-local authorization, permanent key tombstones and deterministic concurrent-delegation cancellation. Receipt separation. Single-path and concurrency authority tests, I2/I6. | 900–1,400 lines. |
| **(c) Fork/resolution projection** | MV frontier, join eligibility, decision validation, all-event status/reason reads, safe freeze, late fork reopening, counterclaims. Replace timestamp/hash winner semantics; full I1/I3 property/permutation harness and node-prose reads. | 1,300–2,000 lines. |
| **(d) Pinned edges** | Both endpoint pins, disputes, author-only reaffirmation/forks, neighbor filtering, revision-scoped media behavior, I5. No inferred absence or auto-retarget. | 700–1,100 lines. |
| **(e) fold_version** | Final governed manifest, filter trust root, versioned roots/protocol/verdicts/cache/export/restore, refusal paths and native/Wasm checks; run I1–I8 end to end. Earlier stages reserve version fields; this stage pins and enables the complete rule identity. | 650–1,000 lines. |

Total estimate: 4,750–7,300 changed lines. Each implementation stage requires
`make check`, Wasm and applicable Python checks against synthetic real Postgres.
The design PR adds no implementation or tests; passing existing CI cannot prove
these proposed invariants. Completion of code still does not authorize production
content. #6 closes only with evidence that every implementation gate passes.

## Non-goals and enforced exclusions

- **External timestamp anchoring:** receipts are signed observations excluded from
  order/authority. No external-clock finality or historical-date proof is used.
- **Cross-instance authority federation:** instance ID is signed; mismatches are
  rejected. Curator sets are local versioned trust roots, not portable authority.
- **Administrative subject recovery:** no curator override or forced reset. With
  no surviving grant, the old subject freezes and a counterclaim uses a new one.
- **Automatic historical adjudication:** structural identity and signatures do
  not validate prose, evidence independence or historical accuracy. Pending
  bodies/evidence remain unknown; no source or image is manufactured.
- **Legacy correction/import compatibility:** v0 writers/imports and raw SQL
  application bypasses are excluded from the v1 runtime. Operator control of the
  database is outside cryptographic authorization; consistency verification must
  reject altered derived tables instead of treating them as valid event history.
- **Immediate irrevocable revocation across disconnected replicas:** excluded by
  the event-set contract. A missing event cannot affect a replica; newly learned
  branches reopen review instead of receiving a fabricated total order.

## Parking lot (nonblocking for v1)

1. Threshold/role-separated authority grants. V1 grants full authority to each
   key and safely freezes when no common resolver survives.
2. Delegated edge-author rotation. V1 fixes the original edge author; replacement
   assertions remain possible without rewriting an old edge.
3. Projection indexing/checkpoint performance. Full deterministic replay is the
   correctness oracle; optimization must preserve roots and all-event visibility.

None changes a v1 safety decision or blocks its implementation. External anchoring
and federation are explicit non-goals, not prerequisites hidden in this list.
