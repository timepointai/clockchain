# Stage (c): fork and resolution projection

This records the merged Stage (c) boundary; pinned edges and media are in
[Stage (d)](STAGE-D.md).

Owner authorized this boundary after approving Stage (b) PR #9. The ship sequence
is decided: full (a)–(e). Refs #6. Its final disposition belongs to the owner after
Stage (e) and operational evidence. This PR stops at first review.

The Rust v1 module now projects a retained candidate set into full event readings,
subject frontiers, immutable revisions and authority effects. The normal node
binary remains legacy. The review adapter is still separate from normal boot;
`/ready` and store readiness refuse with `stage_c_non_serving`. This is not a
production fold identity, filter verdict, temporal query or publication route.

## Admission and projection

Resolve requires at least two incomparable same-subject parents and the exact
signing grant active in every parent cone and their joined authority fold. It
cannot establish its own authority from a branch-only delegate. The accepted
issuer-stratified revocation and signed cascade rules are unchanged. Admission
stays distinct from projection: a causally valid Resolve may be globally suppressed
when a later revocation exposes a tainted parent path.

The projection excludes suppressed acts and root relinquishments from eligible
body heads. Eligible events and effective revokes consume their strict causal
pasts. Maximal remaining eligible events form each subject's frontier. One is
resolved; several are contested; none is `no_current_body`. `frozen` separately
reports that no active grant survives. Authority from one subject cannot edit or
unfreeze another: a counterclaim begins with an independent Genesis. Its eventual
`disputes` edge remains Stage (d).

Every retained candidate has exactly one `head`, `superseded`, `branch`, `pending`
or `invalid` row, preserving the model's full reason string. Contested eligible
histories remain `branch / contested`; common history is superseded. Suppressed
histories expose `revoked_concurrent`, `revoked_ancestor`, `canceled_grant` or
`canceled_authority` and controlling revoke IDs. Root relinquishment is
`superseded / root_relinquished`. Semantic rejects retain their signed envelopes,
including decisions. Missing parents stay pending and wake on replay. Malformed
attempts remain separate digest-keyed rejections.

Partial joins leave other eligible heads visible. Competing resolutions fork.
Late eligible branches reopen a resolved reading; suppressed branches do not.
IDs sort output only. Asserted times and node receipts do not determine authority,
frontiers or precedence. No assertion-time filter is applied to this operator
review snapshot; governed `as_of` runtime queries remain Stage (e).

## Decisions and immutable revisions

Genesis, Correction and merging Resolve create
`revision_id(subject, creating_event)`, permanently bound to their body hash and
asserted time. Identical body bytes created by distinct events have distinct
revision IDs. Delegate/Revoke inherit the parent's selection; selecting Resolve
inherits its named revision and assertion time rather than creating another one.
All valid revisions remain inspectable, including later suppressed revisions.

Resolve's decision has exact parent references, old `Heads(parents)` and new
`Body(hash)` for a merge or `Revision(id)` for selection. Every parent appears
exactly once in the canonical dispositions set, with a nonempty rationale.
A merge requires at least one `merged` disposition and no `selected` dispositions;
other parents may be `not_selected`. A selection requires at least one `selected`
parent whose cone contains that revision and no `merged` dispositions. Other
parents may be `not_selected`. The selected revision must be reachable in the
joined cone and its creating event authority-eligible there. Selecting an older
eligible revision is permitted; all joined authority effects still apply.
A selecting Resolve cannot introduce an asserted-time edit. These checks add
body/decision semantics outside the symbolic model's scope; no model rule is
changed to accommodate them.

## Operator review and optional prose

The separate review router takes explicit writer and reader credential digests.
Readers cannot submit candidates. `GET /v1/review` returns all rows with full
signed envelope fields, revision references, frontier membership, subjects and
authority data. It is an operator snapshot, without a fabricated Stage (e)
semantic commitment or support result.

`GET /v1/revisions/{hex_revision_id}/prose` resolves that immutable revision and
returns its body availability. Missing bytes are explicitly `unavailable` with
null prose. UTF-8 bytes are returned only after their SHA-256 commitment verifies;
non-UTF-8 bytes are explicitly `not_utf8`. Unknown revisions return 404 and
corrupt retained bytes refuse the read. Content-addressed body retention is
idempotent and append-only, separate from the semantic candidate set. Body
availability and observations cannot alter the fold. No prose or source is
reconstructed or generated, and no image or signed absence is inferred.

The Stage (c) bootstrap adds the optional body store and changes its interim
schema hash. Earlier stage stores refuse silent reopening; test replay provisions
a fresh store. Applied v0 migrations and legacy encoding bytes remain unchanged.
No deployed store is touched. Candidate/receipt/body review is not operational
backup/restore qualification or historical evidence approval.

## Evidence and remaining boundary

`projection_oracle.py` calls the unchanged `model.fold`, loading only the unchanged
checker's pure grammar and named traces. Unlike Stage (b), its expected rows
preserve every status and reason; it also returns frontier sets, all grant/effect
sets, and explicit per-Resolve admission outcomes. Rust generates and signs
isomorphic DAGs under increasing, reversed extreme and equal assertion times.
Coverage: **3,569 DAGs**, **65,414 subset masks** under three time patterns
(**196,242 full fold comparisons**), **232 symbolic Resolve events**, and all
**13 named traces / 26,568 full delivery permutations**. Named traces include
every Resolve-containing case previously omitted by (b).
Small grammar signer mutations, every named-trace bipartition, seeded depth and
mixed malformed DAGs cover pending/invalid admission as well as suppression.
Every named trace also runs every full delivery permutation. Duplicate unions
retain exact signed bytes; subset results compare full fold outputs.

Additional Rust tests cover body selection, exact decisions/dispositions, immutable
same-body revisions, authority-only inheritance, partial/competing joins, late
forks, independent counterclaims, freeze and old-stage refusal. Real PostgreSQL
HTTP/import/restore comparisons include Resolve; socket tests exercise all-event
reads, read/write authorization, unavailable/verified/corrupt prose and readiness.

Run pinned Rust `make check`, both cc-core/cc-filter Wasm builds, operator unittests,
and Stage 0 fast/depth/mutants using isolated synthetic PostgreSQL. Exact coverage
counts and actual local versus exact-head CI results accompany the PR. The
accepted model, checker and full-bound receipt bytes remain unchanged. This is
bounded implementation evidence, not exhaustive production correctness.

Stages (d) and (e), runtime integration, immutable-image operational verification
and fresh-store provisioning remain required. Launch then requires a separately
authorized content/publication session. Current live event counts remain unknown.
[HOLD.md](../../HOLD.md) remains unchanged.
