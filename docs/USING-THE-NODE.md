# API and data model

This page is the reference for the Clockchain v1 HTTP API and the data behind
it. Read [ARCHITECTURE.md](ARCHITECTURE.md) first for the picture. The machine
readable version of every route is [reference/openapi.json](reference/openapi.json);
CI fails if it and the routers disagree (`ops/test_openapi_routes.py`).

There are two ways to read:

- **The public gateway.** `https://clockchain.timepointai.com/public/v1`. No key,
  GET only, 60 requests a minute per address. This is what most readers use. The
  rules are in [PUBLIC-ACCESS.md](PUBLIC-ACCESS.md).
- **The node.** The production node has no public address. It is reached only by
  the gateway and by the owner, through a private tunnel
  ([CICD-FLY.md](CICD-FLY.md)). A node you run yourself ([LOCAL-DEV.md](LOCAL-DEV.md))
  serves the same routes without the `/public` prefix.

## Try it

```sh
G=https://clockchain.timepointai.com/public/v1
curl -fsS "$G/health"
curl -fsS "$G/snapshot"                     # the whole committed corpus
curl -fsS "$G/subjects/$SUBJECT_ID"         # one subject; id is 64 lowercase hex
```

Against a node you operate, the read routes need a Bearer read key. Supply it
through the environment and never paste it into source:

```sh
NODE=http://localhost:8080                  # your node's origin
curl -fsS -H "Authorization: Bearer $CC_NODE_READ_KEY" "$NODE/v1/snapshot"
```

## v1 mode

`cc-node` serves v1 only when `CC_NODE_LEDGER=v1`. Without that variable it runs
the legacy v0 node (see [the last section](#legacy-v0-node)). In v1 mode none of
the v0 routes exist. The design contract is [STAGE-F](design/STAGE-F.md).

## Routes

### Public gateway (`/public/v1`, no credential)

| Route | Answers |
|---|---|
| `GET /health` | Ledger identity and posture: `ledger`, `build`, `posture`, `fold_version`, `filter_version`, `curators`, `max_hops`, `semantic`. Not cached. |
| `GET /snapshot` | The full committed corpus and its projection. Optional `fold_version` and `fold_manifest` together; `409` if this build does not serve that fold. |
| `GET /subjects/{id}` | One subject. Optional `as_of`. |
| `GET /revisions/{revision}/prose` | The text of one revision, verified against its hash. |
| `GET /support?from=&to=` | Recorded support between two subjects. Optional `as_of`. |
| `GET /receipts/{event}` | Node receipts for one event. Never cached. |

The gateway returns the node's JSON minus the top-level `instance` field. It
refuses every method except GET, HEAD and OPTIONS (`405 read_only`), unknown
paths are `404 no_such_route`, and over-limit requests are `429 rate_limited`
with `Retry-After`. There is no seal and no export on the public side. Full
status mapping is in [PUBLIC-ACCESS.md](PUBLIC-ACCESS.md).

### Node (private)

| Route | Credential | Answers |
|---|---|---|
| `GET /health` | none | Identity fixed at boot (same fields as above, plus `instance`). Does no database access, so it does not track later changes. |
| `GET /ready` | none | The live check. `200 {serving:true, posture}`, or `503` with a `reason`. `busy` means another check is running. |
| `GET /robots.txt` | none | Deny all. |
| `GET /v1/snapshot` | read | As above. |
| `GET /v1/subjects/{id}` | read | As above. |
| `GET /v1/revisions/{revision}/prose` | read | As above. |
| `GET /v1/support?from=&to=` | read | As above. |
| `GET /v1/receipts/{event}` | read | Receipts, in receipt-digest order. `404 no_receipt` if none; `503 receipt_verification_failed` if a stored receipt fails its own check. |
| `GET /v1/seal` | read | One freshly signed seal. `503 no_seal_key` without a node key. |
| `POST /v1/candidates` | write | Submit one signed envelope (at most 1 MiB). `201` valid, `202` pending, `422` invalid. |
| `PUT /v1/bodies/{sha256}` | write | Retain a body by its SHA-256 (at most 1 MiB). `201` new, `200` already held, `422 body_hash_mismatch`. |
| `GET /v1/export` | write | The full export manifest, each envelope as one hex string. |

Credentials:

- No credential: only `/health`, `/ready` and `/robots.txt`.
- **Read key** (`CC_NODE_READ_KEY`): the read routes. The write key also works
  on them.
- **Write key** (`CC_NODE_API_KEY`, the full key): everything, including
  `/v1/export`.
- A missing or unknown credential is `401`. A read key on a write route is
  `403`. An unknown path with a valid read credential is `404 no_such_route`.
  The older gallery, beta and telemetry keys open no v1 route.

Rules that apply to every data route:

- IDs, digests and `as_of` are lowercase hex, exactly 64 characters.
- An unknown, misspelled or repeated query parameter is
  `400 {"error":"invalid_query"}`.
- A frozen node (`CC_NODE_POSTURE=frozen`) answers writes
  `503 {"error":"frozen"}` and still serves reads and export.
- At most `CC_V1_READ_CONCURRENCY` reads run at once. A read that finds the
  limit full gets `503 {"error":"busy"}` with `Retry-After: 1`; it does not wait.
- Errors are JSON `{"error": "<code>"}`. Codes seen in the router include
  `invalid_subject_id`, `invalid_revision_id`, `invalid_event_id`,
  `invalid_as_of`, `invalid_support_query`, `invalid_fold_request`,
  `invalid_body_hash`, `unsupported_fold_version`, `revision_unknown`,
  `body_verification_failed`, `store_unavailable`, `admission_unavailable`,
  `seal_unavailable`.

### What a read contains

Every projection read (snapshot, subject, prose, support) names three things:
`rule` (`fold_version`, `fold_manifest`, `filter_version`), `corpus_digest`, and
`commitment`. Receipts and seals do not, because they sit outside every
commitment.

**Snapshot.** `rows` (every retained event with its envelope, state, reason,
missing parents, whether it is a frontier event, its revision and controlling
revokes), `subjects`, `revisions`, `edges`, `media`, and `authority` (grants,
active, tombstones, effective revokes, canceled, effects).

**Subject.** `subject`, `as_of`, `state` (`resolved`, `contested` or
`no_current_body`), `frontier` (the head events), `revision` and `visibility`.
Visibility is one of `visible`, `after_as_of` (the claim's asserted time is
later than `as_of`), `asserted_time_unknown` (the claim has no asserted time
and `as_of` was given), or `subject_unknown`, which is a `404`. A revision is
returned only when visibility is `visible`. `as_of` hides claims by asserted
time. It does not change authority or which events are heads, and it does not
say what a reader could have known on that date.

**Prose.** `revision`, `availability` (`available`, `unavailable` if the body
was never uploaded, or `not_utf8`) and `prose`. Never reconstruct missing prose
from a local copy.

**Support.** `from`, `to`, `as_of` and `support`, which is either
`Supported {path, excluded}` or `Unsupported {reasons}`. It is support in the
recorded graph only: a path of current edges, within `max_hops`, whose edge
authors and subject creators are all in the curator set. It is not a claim that
the history is true.

**Receipt.** `receipt` (the signed bytes in hex, authoritative), `receipt_digest`,
`node_key`, `event`, `received_at` (Unix microseconds on the node's clock, not
historical time), `encoding_version`, `fold_version`, and
`initial_admission_result {state, reason, missing}`.

**Seal.** `seal` (`instance`, `node_key`, `fold_version`, `filter_version`,
`corpus_digest`, `commitment`, `counts {candidates}`, `build`, `sealed_at_us`),
`signature` and `node_key`. The node keeps no seal; two seals of the same state
differ only in clock and signature.

**Submit response.** `{event, input_digest, status {state, reason, missing}, authority}`.
`state` is `valid`, `pending` or `invalid`. Common reasons: `precision`,
`genesis`, `parents`, `subject_header`, `parent_missing` (pending),
`wrong_subject`, `ancestor`, `subject_key_changed`, `wrong_instance`,
`noncanonical`, `bad_signature`, `unsupported_encoding`.

## Data model

All v1 data lives in one Postgres schema, `cc_v1` (`crates/cc-ledger/src/v1.sql`).
It is created by `cc-node provision-v1`, not by the files in `migrations/`,
which are the v0 schema only.

| Table | Holds |
|---|---|
| `identity` | One row: the instance id, encoding version and schema hash. |
| `candidates` | Every signed envelope the node retained: `event_id` and the exact `envelope` bytes (up to 1 MiB). Valid, pending and invalid ones are all kept. |
| `rejections` | Digest and reason for input that could not become a candidate (undecodable or for another instance). |
| `bodies` | Body bytes by `body_hash`. Retained apart from events; a body can be missing while its event is present. |
| `receipts` | Signed node receipts, one per first admission of an event, when a node key is configured. |
| `rule_identity` | One row: the fold version, fold manifest and filter identity this store was bound to. Reopening under another identity fails readiness. |

Every table refuses update, delete and truncate through a trigger. There are no
derived tables: subjects, revisions, edges, media and authority are recomputed
from the retained envelopes on read (with an exact-match cache).

### An event

An event is a signed envelope. The wire form is canonical, so one meaning has
one byte string. Fields: `instance`, `author`, `subject` and `subject_key`
(kind, namespace, value), `grant`, `parents`, `asserted_time` (a coordinate and a
precision), and a payload by kind:

| Kind | Meaning |
|---|---|
| `Genesis` | Creates a subject with its first body. Needs no parent or grant. Carries a nonce. |
| `Correction` | A new body for a subject, with a recorded decision and rationale. |
| `Delegate` | Gives a key authority over one subject. |
| `Revoke` | Withdraws a grant, with or without its descendants. |
| `Resolve` | Joins two or more competing heads into one reading. |
| `EdgeAssert` | A typed relation between two pinned subject revisions. |
| `EdgeReaffirm` | Re-pins an existing edge after its endpoints change. |
| `Attestation` | Binds an artifact (such as an image) to an event or revision. |

Identifiers:

- **Event id** = SHA-256 of the canonical bytes before the trailing signature.
- **Body hash** = SHA-256 of the body bytes.
- **Subject id** = the event id of its Genesis.
- **Revision id** = a domain-separated hash of the subject and the event that
  created the revision.
- **Root grant** of a subject = a domain-separated hash of its Genesis id.
- **Corpus digest** = hash over the sorted ids of all retained candidates,
  including pending and invalid ones. Receipts and rejections are excluded.
- **Commitment** = hash over the encoding version, fold, `filter_version`, corpus
  digest and the canonical projection rows (`cc.view.v1`).
- **`filter_version`** = hash of the exact rule: fold, encoding, constants,
  pinned taxonomy, the sorted curator keys, trust policy and `max_hops`.

The wire encoding is in `crates/cc-core/src/v1.rs`; the rule text is
`crates/cc-core/src/v1/fold-manifest-v1.txt`. The rule is frozen as fold version
1; a change to admission or projection needs a new version.

## Signing and keys

Concepts only. The procedures are in [KEYS.md](KEYS.md) and
[PUBLISHER-V1.md](PUBLISHER-V1.md).

- **Authors sign; the node does not.** Events are signed offline with Ed25519.
  The node verifies them on admission.
- **Root and hot keys.** A subject's Genesis author holds its root grant and
  keeps that key offline. The root delegates to a hot key for routine
  corrections. A hot key can be revoked.
- **Curators.** The curator key set is part of the bound rule identity and
  cannot be changed on a running store. Support only counts subjects and edges
  authored by curators.
- **Node key.** Optional. An Ed25519 seed (`CC_V1_NODE_SEED`) lets the node sign
  receipts and seals. It is not an author key and cannot create events.
- **Node credentials.** The read and write keys are Bearer tokens for HTTP
  access. They are not signing keys.
- Keep every seed and key outside the repository, outside logs, and out of
  command lines.

## Reading and verifying an entry

1. Fetch the subject and its prose, or the whole snapshot.
2. Check the three names are consistent: the `rule`, `corpus_digest` and
   `commitment` should be the same across reads of one moment.
3. **Recompute.** Pass the snapshot to the verifier (the explorer's
   `#/verify` page, or `cc-wasm-verify`). It recomputes event ids from the
   envelopes, the corpus digest, the `filter_version` from the served identity,
   and the commitment. See [web/explorer/README.md](../web/explorer/README.md).
4. **Signatures.** The public API does not serve signatures. For a signature
   check, get the export from a node you are allowed to read it from, and check
   the last 64 bytes of each envelope against the rest with stock Ed25519.
   `cc-wasm-verify` does this when given an export.
5. **Receipts and seals.** To verify one, split off the trailing 64-byte
   signature, check it with Ed25519 over the rest, and compare the signer with a
   node key you pinned from a source other than the response. A receipt says
   the node saw the event. A seal says the node served that state at that time
   on its own clock. Neither says the event is true.
6. **Know the limit.** The verifier gets the rule, curator keys, digest and
   commitment from the same server as the corpus. Without a signed export from
   another source and a list of curator keys you obtained independently, a check
   shows internal consistency, not authorship.
7. **Truth is separate.** A passing check means the bytes are the ones signed and
   the answer follows the rule. Whether the history is right needs sources and
   judgment ([evaluation/design-boundaries.md](evaluation/design-boundaries.md)).

## Running a node (v1 settings)

| Variable | Meaning |
|---|---|
| `CC_NODE_LEDGER` | `v1`; any other value is refused. |
| `DATABASE_URL` | The fresh v1 database, never the legacy one. |
| `CC_NODE_API_KEY` | Write key. Required. |
| `CC_NODE_READ_KEY` | Read key. Optional; must differ from the write key. |
| `CC_NODE_POSTURE` | `live` or `frozen`. Required, no default. |
| `PORT` | Listen port. |
| `CC_V1_INSTANCE` | Instance id: 64 lowercase hex characters. |
| `CC_V1_CURATORS` | Ed25519 public keys, 64 lowercase hex each, comma-separated, strictly sorted. |
| `CC_V1_MAX_HOPS` | Hop bound for support. Default `4`. |
| `CC_V1_READ_CONCURRENCY` | Reads in flight before `503 busy`. Canonical decimal `1` to `64`, default `8`. |
| `CC_V1_NODE_SEED` | Optional 32-byte Ed25519 seed as 64 lowercase hex, to sign receipts and seals. Refused if malformed, if it has fewer than 8 distinct characters, or if its public key is a curator. Without it there are no receipts or seals and admission is unchanged. |

Treat the seed and keys as secrets: set them as platform secrets, never in
source or argv.

`cc-node provision-v1` creates the schema and binds the rule identity, or accepts
a database already bound to exactly that identity. It needs `CC_NODE_LEDGER`,
`DATABASE_URL` and the three `CC_V1_*` identity variables, and prints the
identity. `cc-node serve` reopens the store at boot and never provisions.
`cc-node migrate` refuses in v1 mode.

| Exit code | Meaning |
|---|---|
| 0 | Provisioned and ready. |
| 78 | Configuration error, or `migrate` in v1 mode. |
| 73 | The database holds non-v1 tables. |
| 65 | Stored instance or rule identity differs, is missing or partial, or the store is not provisioned and bound (`serve`). |
| 69 | Database unreachable or it refused the operation. |
| 70 | Any other refusal, such as a corrupt stored candidate. |

### Snapshot cache and read limit

A read reuses the last committed fold only when the rule identity, the corpus
digest and a digest of the retained candidate bytes all match. Every admission
invalidates the cache. Responses are byte-identical to an uncached fold. Export
never uses the cache. The database pool has ten connections, so the default read
limit of 8 stays below it. A read that waits more than five seconds for a
connection answers `503 store_unavailable`.

### Receipts and seals

With `CC_V1_NODE_SEED` set, the node signs a receipt (`cc.receipt.v1`) the first
time it retains each event, in the same transaction. If signing fails, nothing
is admitted and the submit answers `503 admission_unavailable`. A resubmission
gets no new receipt. Input that never becomes a candidate gets none. A retained
candidate classed `invalid` or `pending` gets one that records that result.
Receipts are observations: they never enter the candidate set, corpus digest,
commitment, snapshot or export, so a store restored from an export has none.

`GET /v1/seal` signs a seal (`cc.seal.v1`) over the current committed state. The
operator's hash-chained log of seals is `ops/seal_v1.py`
([OPERATIONS.md](OPERATIONS.md) section 8, [design/SEALING.md](design/SEALING.md)).

## Legacy v0 node

Without `CC_NODE_LEDGER=v1`, `cc-node` runs the v0 node over the schema in
`migrations/`. It is kept for the archive and regression tests; production does
not use it. Its routes, from `crates/cc-node/src/lib.rs`:

| Route | Credential |
|---|---|
| `GET /health` | none |
| `GET /health/deep`, `/v1/moments`, `/v1/edges/{id}/evidence`, `/v1/images`, `/v1/images/{sha}`, `/v2/media` | read |
| `GET /v1/recents` | gallery, read or write |
| `GET /v1/entities/{id}`, `POST /v1/feasibility` | beta, telemetry, read or write |
| `POST /v1/events`, `POST /v1/images`, `POST /v2/media/absence-decisions` | write |

v0 reads need an explicit `as_of` coordinate (whole ticks since Clock Zero, J2000.0
TCB at one tick per second, or `0x` plus 64 hex characters). A frozen v0 node
answers writes `403`, unlike v1's `503`. The v0 tables (`events`, `entities`,
`moments`, `edges`, `attestations`, `roots`, `anchors`, `exhibits`,
`commitment_log`, `vocabulary`, `claim_bodies`, `image_attachments`,
`media_absence_decisions`, `generation_*` and others) are described by the comments
in `migrations/`. The v0 feasibility answer (`Supported`, `Unsupported`,
`Contradicted`) is a statement about recorded graph evidence only. See
[ADMISSION-REVIEW.md](ADMISSION-REVIEW.md) and
[TYPED-MEDIA-ABSENCE.md](TYPED-MEDIA-ABSENCE.md) for v0 admission and media
rules. Details of the v0 routes were not re-verified against code beyond the
route table above.
