# Multi-signer admission and projection v1

Owner decision, 2026-09-30: merge this design only after the final full-bound
receipt and green CI. Stage 0 is an executable reference specification, not
production code. Stage (a) is authorized after that merge, on a separate branch
for review. Subsequent owner decision: the full **(a) → (b) → (c) → (d) → (e)**
sequence is selected. PR #9 is approved and Stage (c) is authorized through its
first PR review. Owner decision, 2026-09-30: PR #10 (Stage (c)) merged and Stage
(d) is authorized through its first PR review. Owner decision, 2026-10-01: PR #11
(Stage (d)) merged and Stage (e) is authorized through its PR review; runtime
integration and operational evidence still require separate authorization.
[HOLD.md](../../HOLD.md) remains the operating boundary.
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
2. Revocation is scoped to the exact grant: an authority can revoke only grants
   issued through its own grant, directly or transitively. The root grant can be
   revoked only by itself. A hot delegate cannot revoke its issuer or sibling.
   Root compromise is total loss; operate a cold root with hot delegates. An
   issuer can recover from compromise of its hot delegate without its consent.
3. Compute effective revocations before contention, in issuer-before-delegate
   strata. Out-of-cut acts under revoked authority remain visible as
   `branch / revoked_concurrent` but cannot contend or create tombstones.
   Concurrent delegations and their derivatives lose authority. Previously
   acknowledged delegations survive a non-cascading revoke; `cascade=true`
   retires the whole target grant subtree. Selecting a body cannot undo revocation.
4. Late **unrevoked** branches can reopen a contest. Revoked old-parent spam
   cannot. Authority can re-author suppressed content by Correction on a surviving
   parent. Root relinquishment is an explicit control, not a new body head.
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

Each subject starts with one root authority grant to its creator. Any number of
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
reinterpretation. Zero projected entries does not establish an empty event store.
The latest retained ledger-count receipt located for this review is dated
**2026-09-25T03:37:49.466380Z**: `/health/deep` reports `event_count = 0`, ledger
null, and no folded events. That build counts `SELECT count(*) FROM events`,
not entity projections. Thus EntityCreate, Moment (including node-0), Edge,
Attestation and VocabularyDeclare were each zero at that observation; this is
inferred from the total-zero receipt, not a separate GROUP BY query. **Current
production v0 counts are unknown; no new live read was performed.**

There is no history migration or automatic re-signing. If any v0 events exist,
including governance/node-0 events with no historical entries, deployment needs a
fresh v1 store and must refuse reuse of the nonempty v0 store. Verify the actual
event table, not the projection count, at that later owner-operated boundary.
The Engelbart fixture is v0 and cannot enter v1; preserve it as regression
evidence only. Any later inaugural pair must be re-authored and reviewed as v1.
Existing private fixture bytes and applied migration bytes remain unchanged.
Coordinate constants remain `CONSTANTS_VERSION = 0`; tick arithmetic is unchanged.

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
| 3 | Delegate | One parent; fresh grant event ID, grantee key and issuer_grant_ref. Body authority and scoped downstream delegation/revocation in v1. Carries decision and evidence; copies parent's body selection. |
| 4 | Revoke | One parent; exact target_grant active there, required signed `cascade: bool`, decision and evidence. Only the target's direct/transitive issuer grant can revoke it; the root alone may revoke itself. Copies body selection; no key-wide ban on independent grants outside the target subtree. |
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
**Globally, ancestor and descendant are reflexive:** `x ≤ y` means x is y or is
reachable through y's signed parents; strict ancestry is `x < y`. Grant-issuance
ancestry is likewise reflexive; revocation scope requires a *strict* issuer
ancestor, except root self-revocation. Missing dependencies remain pending;
malformed references/cycles and invalid parents have deterministic reasons.
Topological evaluation is dependency evaluation, never priority by event ID.

Branch-local validation checks the signer's exact grant at each parent, using
only that parent's causal cone. Resolve additionally requires the grant to
survive the joined cone. Delegate/Revoke live on that same DAG. All signed acts
remain available for audit even if a larger event set later suppresses their
authority effect. A signature from an unauthorized issuer cannot contribute a
revocation. Grant IDs, not a key-wide blacklist, define scope: a key using an
independent surviving grant is not acting through revoked authority. This is
necessary to prevent revoking a sibling/issuer through another grant to its key.
A hot-key recovery must cover all its grants; the root can revoke every grant
in its subject. A fresh key is required for delegation within the parent's cone;
concurrent grants to the same key remain distinct capabilities.

### Grant survival at a join

The literal rule “monotone tombstones from all branch-valid Revokes” is unsound,
even with issuer scope. Counterexample (five events, three keys):

```
G(A) → D(A grants K) → D2(K grants C)
                         ├─ R(A revokes K, parent=D2)
                         └─ Q(K revokes C, parent=D2), signed later
```

Here R has `cascade=false`. D2 is acknowledged by R; C must survive. Q is branch-valid and in K's issuance
scope. Blindly unioning Q's tombstone kills C through a revoked issuer. Suppressing
Q while retaining its tombstone has the same defect. The minimal replacement is
**issuer-stratified effective revocations**. The candidate set is monotone; the
effective tombstone set need not be. Learning R can remove Q's effect and restore
C. That is explicit recomputation, not a timestamp or arrival-order decision.

1. Keep the grant provenance tree: each Delegate names its issuer grant; its
   event ID is its grant ID. A Revoke must target an active grant strictly below
   its signing grant. Root self-revocation is the only equal-grant exception.
2. Evaluate branch-valid Revokes from root-issuer depth to leaf-issuer depth.
   At a depth, apply all eligible events as a set. A Revoke signed through a
   canceled grant, or outside any effective revocation cut of its signing grant,
   contributes **no** tombstone. Lower authorities cannot revoke upward, so no
   lower stratum can change an already evaluated higher stratum. Root
   self-revocations are terminal controls evaluated first; simultaneous root
   relinquishments do not cancel each other.
3. Owner decision, 2026-09-30: **B, signed cascading revocation**. Revoke encodes
   `cascade` as one required byte, 0 or 1 (other values/missing bytes reject).
   False covers only the target; true covers the target and every grant with that
   target in its reflexive issuance ancestry, including acknowledged descendants
   and descendants learned later. Coverage is computed from the retained grant
   provenance, not an arrival-time list supplied by the writer. No new grant ID
   can escape through a descendant of the retired grant. An independent grant
   outside that subtree is unaffected. A suppressed Revoke contributes no effects,
   including no descendant tombstones. Eligibility is still issuer-stratified.
   For **each covered grant g**, effective Revoke R preserves only acts `e ≤ parent(R)` under
   g. Any other act through g is `branch / revoked_concurrent`, excluded from
   contention and authority effects. With multiple effective revocations of g,
   preservation requires that inequality for **every** R: intersect their
   acknowledged pasts. No timestamp or hash chooses a preferred cutoff.
4. A grant D issued through g is canceled if `D ≰ parent(R)` for any effective
   R of g, or if its issuer grant's issuance is canceled. Propagate cancellation
   down the grant tree. **D = parent(R) survives issuance cancellation**;
   with `cascade=true` it is nevertheless tombstoned and inactive. With false,
   previously acknowledged independent delegates remain active. A canceled grant's
   events cannot contend, even if their signing key was never directly revoked.
5. Revoked/canceled grants are inactive. Visible descendants that depend on a
   suppressed body branch are `branch / revoked_ancestor`, also outside
   contention. They cannot launder it through Resolve. Re-author with a fresh
   Correction on a surviving parent, with the suppressed content cited as
   evidence. Effective authority controls retain their scoped tombstone effect
   even if their inherited body path is suppressed; they do not publish that body.

For Resolve, the signing grant must be active at every declared parent and after
combining their causal histories under these rules. A branch-only delegate cannot
resolve the fork that would establish its authority. Independent surviving grants
are retained in the result; no ancestor is selected by hash in a crisscross DAG.
A grant cannot be resurrected by selecting a body or by a new grant with its ID.
A fresh independent grant is a separate authorization, not a revived tombstone.

### Frontiers and resolutions

First validate causally, then derive effective revocations/cancellations, then
exclude suppressed acts and their dependent body branches from contention.
The frontier contains maximal remaining body transitions under `≤`. Effective
Revokes consume their strict causal past even when the control itself offers no
body head (notably root relinquishment). Root relinquishment is
`superseded / root_relinquished`; a prior independent delegate may continue by a
valid transition when `cascade=false`; true retires the whole grant tree.
The relinquishing root cannot present a new head in either case.

One frontier event gives a resolved head; two or more give `contested`. Suppressed
branches are still returned, with reasons and controlling revoke IDs, but never
count toward that number or withdraw support. No frontier means no current body
support; it is distinct from a contest. A current head may carry previously
acknowledged content from a now-revoked writer; the excluded class is that writer's
**out-of-cut acts**, not every historical signature by that key.

Resolve requires incomparable parents (`p ≰ q` and `q ≰ p`), per-parent decisions,
and either an eligible reachable revision or an explicitly authored merged
revision. It cannot drop revocation evidence. Partial joins leave other eligible
heads visible. Two valid resolutions themselves fork. Only late eligible branches
reopen review; suppressed old-parent spam does not. IDs sort display/commitment
bytes only. Every candidate projects as head, superseded, branch, pending or
invalid-with-reason, including suppressed Revokes whose authority effect is zero.

### Revocation concurrency traces

Let A be the root, K its hot delegate and C a delegate issued by K. Traces
use `cascade=false` unless explicitly marked true.

| Event set | Projection and permissible next action |
| --- | --- |
| A revokes K at P; K later signs Revoke(A) at P | K's revoke is invalid: upward scope, including the root, is forbidden. A's head survives; no retroactive freeze. |
| A revokes K at P; K later corrects/resolves/delegates at old P | Out-of-cut acts are visible `revoked_concurrent`; derived grants/branches are canceled. They neither contend nor drop support. |
| K delegated C before/equal A's revoke parent; K later revokes C at that old parent | C survives. K's later revoke is suppressed before its tombstone could take effect. This is the counterexample to the literal monotone union rule. |
| A sees an attacker Delegate(C) issued by compromised K and revokes K with `cascade=true` | Both K and C are inactive even though C was acknowledged; their out-of-cut acts cannot contend. |
| Honest K departs; A revokes K with `cascade=false` after acknowledging C | C remains active and can continue. True would retire C too; the signed choice distinguishes departure from subtree recovery. |
| Delegate(C) is the revoke's parent itself | Reflexivity preserves C's grant. C can continue independently. |
| Delegate(C) is incomparable with A's revoke parent | Its issuance and descendants are canceled, without creating contention. |
| Two issuer Revokes of K have different acknowledged pasts | Preserve K's acts only in the intersection. Excluded bodies and resolutions depending on them remain visible but cannot contend. |
| K tries to revoke a sibling or issuer grant | `invalid / revocation_scope`, even if K was active at the chosen parent. |
| Root revokes itself | Explicit relinquishment, no new root-authored body head. Previously established delegates may continue; no descendant can revive the root grant. |

A root can revoke its delegates or destroy recovery; root compromise is total
loss. Cold root plus hot delegates is the operating pattern, not an assumption
that any two keys are independent people. Curators have no subject reset power.

### Why a revoked key cannot resolve the union

Grant scope makes the revoke-dependency graph strictly downward, with the root
self-revocation exception handled first. Thus issuer-stratified evaluation has a
unique result from the event set. Within each stratum, union eligible Revokes;
intersect their reflexive acknowledged pasts; propagate cancellation downward.
Cascade coverage is an issuance-ancestry set; it cannot reach the signing
grant or an issuer above it (except explicit root relinquishment). Suppression
therefore retains the same acyclic issuer ordering. These are set operations, so
delivery order, asserted time and import partitions
cannot affect the result. Effective effects may retract on new evidence, but
replaying the same union yields the same effects.

Apart from explicit root relinquishment controls, an out-of-cut act through
revoked authority cannot enter the frontier, contribute a revoke, or create an
active delegation. Its dependent branches cannot restore
it. Such acts therefore cannot be a sole head, revoke a surviving grant, or make
a resolved subject contested. A malicious delegate cannot attack an ancestor's
recovery grant because its Revoke is out of scope. Legitimate unrevoked-author
forks still require resolution. A key with another independent surviving grant
may act through that grant; this does not revive its revoked authority. The
claim is set-relative: a replica missing the issuer's revocation cannot use it.

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
`ancestors(current_head) - ancestors(basis_head)`, using the reflexive definition above;
any Correction or merging Resolve in that difference makes the pin stale. The
basis must satisfy `basis_head ≤ current_head`, otherwise the pin is stale too.
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

These are production acceptance requirements. Stage 0 exercises the authority/
frontier subset as an abstract reference model; it does not prove the production
encoding, HTTP, edges or versioned storage. Properties compare canonical projections and all reason
codes, not just a selected body. The implementation must test each distinct set
under every permutation for small cases and generated permutations/partitions for
larger DAGs, including duplicate delivery and child-before-parent delivery.

| Invariant | Required test and oracle |
| --- | --- |
| **I1** Same event set and rule identity, identical projection across orderings and import partitions. | `i1_union_permutation_partition_convergence`: enumerate revoke/correction, revoke/delegate/descendant, retroactive out-of-scope revoke, competing resolution and crisscross cases; compare whole root/rows after union, rebuild and duplicate replay. Include partial resolution and late siblings. |
| **I2** No event changes a head without authority valid at its parent(s). | `i2_parent_authority_and_surviving_join_grant`: unauthorized author, wrong grant, parent-missing, branch-only delegate and revoked resolver cannot yield an authoritative head. `i2_revoke_concurrent_correction_no_revoked_winner` and `i2_revoke_concurrent_delegate_cancels_descendants` enumerate all delivery orders; `i2_prior_delegate_survives_later_revoke` pins the causal distinction; `i2_retroactive_revoke_from_old_parent_cannot_freeze` pins issuer scope; `i2_revoke_parent_equal_delegate_preserves_grant` pins reflexivity. `i2_cascade_compromise_visible_attacker_delegates`, `i2_non_cascade_honest_delegator_departure` and `i2_suppressed_cascade_has_no_descendant_effect` pin the signed choice; `ignore_cascade` must be killed. Suppressed Revokes have no tombstone effect; only eligible acts may contend. |
| **I3** Every retained event is head, superseded, branch, pending or invalid-with-reason. | `i3_total_auditable_classification`: projection IDs equal retained candidate IDs; statuses are exclusive and exhaustive, rejected branches retain decisions, incomplete parents wake deterministically, semantic rejects remain visible, malformed attempts get separate receipts. `i3_late_eligible_branch_reopens_resolved_frontier` preserves legitimate siblings; revoked-concurrent branches remain visible without reopening. |
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
No intermediate stage writes production or permits a v0/v1 mixed graph. The
owner selected the full (a)–(e) sequence; first-publication authorization remains
a separate decision.

**Stage 0** is the pure [Python reference fold](stage0/model.py) and
[exhaustive/Hypothesis checker](stage0/check.py). Python makes counterexample
traces and a later Rust differential oracle directly reusable without a second
specification language. The model covers grant scope, parent authority,
issuer-stratified tombstones, cancellation, visible suppression, frontier and
Resolve; it abstracts signatures, bodies, edges, encoding, HTTP and persistence.
The bounds, reproducible command and measured results are in
[stage0/README.md](stage0/README.md), including the seven-mutant checker check,
targeted depth coverage, fast CI bound and source-hashed full manual pre-release
gate. This is executable specification only.

| Stage | Deliverable and completion boundary | Estimated diff |
| --- | --- | --- |
| **(a) Encoding + single admit()** | v1 typed envelopes/DecisionV1, strict decoder and signer-bound IDs, canonical vectors, new empty-store schema provisioning, retained candidate/rejection interface, HTTP/import adapters to one semantic entry point. Remove public bypasses; restore uses admit. Stage remains non-serving until later semantics land. I4, I7 and encoding checks. | 1,200–1,800 lines across core/admission/schema/API tests. |
| **(b) Authority chain** | Genesis grants, provenance-bearing Delegate/Revoke, branch-local authorization, scoped, issuer-stratified tombstones and deterministic concurrent-delegation cancellation. Receipt separation. Single-path and concurrency authority tests, I2/I6. | 900–1,400 lines. |
| **(c) Fork/resolution projection** | MV frontier, join eligibility, decision validation, all-event status/reason reads, safe freeze, late fork reopening, counterclaims. Replace timestamp/hash winner semantics; full I1/I3 property/permutation harness and node-prose reads. | 1,300–2,000 lines. |
| **(d) Pinned edges** | Both endpoint pins, disputes, author-only reaffirmation/forks, neighbor filtering, revision-scoped media behavior, I5. No inferred absence or auto-retarget. | 700–1,100 lines. |
| **(e) fold_version** | Final governed manifest, filter trust root, versioned roots/protocol/verdicts/cache/export/restore, refusal paths and native/Wasm checks; run I1–I8 end to end. Earlier stages reserve version fields; this stage pins and enables the complete rule identity. | 650–1,000 lines. |

**Rejected ship-order alternative (retained design rationale):** `(a) → (c) → (d) → (e)`, with
Delegate and Revoke tags rejected by the shared admit() on every ingress before
candidate storage (rejection receipts only), permits a single-authority-key-per-
subject first publish. Enabling (b) cannot resurrect rejected candidates from the
ledger. `(b)` may follow only as a new
`fold_version`. Encoding v1 reserves those tags; enabling them changes semantics,
not merely configuration. I1 and I3–I8 still apply to the admitted event domain;
I2 reduces to the genesis key authorizing every correction and resolution.
Revocation/grant properties hold only vacuously because those operations reject,
not because multi-signer safety shipped. Lost: delegation, hot-key recovery,
rotation and cold-root/hot-delegate operation. The root must sign body changes;
its compromise is unrecoverable within that subject. The full sequence including
(b) retains all multi-signer obligations and is the selected sequence.

Total estimate: 4,750–7,300 changed lines. Each implementation stage requires
`make check`, Wasm and applicable Python checks against synthetic real Postgres.
Stage 0 is reference specification code only; existing production CI cannot
prove the proposed invariants. Stages (b)/(c) are accepted only when the Rust fold
agrees with the model on generated DAGs, including states/reasons and grant effects. Completion of code still does not authorize production
content. Refs #6. Only the owner may resolve that issue, after Stage (e) and
operational evidence for every launch gate.

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
  eligible branches reopen review instead of receiving a fabricated total order.
  Revoked-concurrent branches are excluded once the effective revoke is known.

## Parking lot (nonblocking for v1)

1. Threshold/role-separated authority grants. V1 grants body authority plus
   scoped downstream authority; the root remains the recovery trust boundary.
2. Delegated edge-author rotation. V1 fixes the original edge author; replacement
   assertions remain possible without rewriting an old edge.
3. Projection indexing/checkpoint performance. Full deterministic replay is the
   correctness oracle; optimization must preserve roots and all-event visibility.

None changes a v1 safety decision or blocks its implementation. External anchoring
and federation are explicit non-goals, not prerequisites hidden in this list.
