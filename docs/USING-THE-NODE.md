> Owner deployments are private. Open the Fly proxy described in [CICD-FLY.md](CICD-FLY.md) before using these examples.

# Using the node

The live base URL is `http://127.0.0.1:18080`. `/health` alone is
anonymous. Corpus reads require an issued Bearer credential and explicit `as_of`.

```sh
BASE=http://127.0.0.1:18080
AS_OF=842389200
# Supply CC_NODE_READ_KEY through the environment; never paste it into source.
curl -fsS "$BASE/health"
curl -fsS -H "Authorization: Bearer $CC_NODE_READ_KEY" "$BASE/health/deep"
curl -fsS -H "Authorization: Bearer $CC_NODE_READ_KEY" \
  "$BASE/v1/entities/3582419940486658630?as_of=$AS_OF"
```

## Access and coordinates

| Credential | Read surface |
|---|---|
| Read | All reads, including feasibility; cannot submit events |
| Gallery | `/v1/recents` only |
| Beta | Entity detail and feasibility |
| Telemetry | Entity detail, feasibility and recents |

The full API credential also permits writes when the node is live. Consumer tools
should use the narrower credential they need. Missing/invalid authentication is
`401`; a read key attempting a write is `403`. A valid scoped key cannot access
routes outside its scope. A valid full/read key gets `404` for an unknown route.

`as_of` accepts whole ticks since Clock Zero (J2000.0 TCB, one tick per SI second)
or `0x` followed by 64 hex characters. Negative coordinates are valid; zero is the
epoch, not the beginning of history. Entity ids should be strings in JavaScript
to avoid integer precision loss. This time slice is not a guarantee of what a
reader could have known at that date.

## Ask a feasibility question

```sh
curl -fsS "$BASE/v1/feasibility" \
  -H "Authorization: Bearer $CC_NODE_READ_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subjects":["3582419940486658630","2972449720562630121"],"as_of":"842389200","claim":"conflict-and-warfare"}'
```

Use an exact TT label for `claim`. Legacy numeric codes cannot distinguish an
unknown label from a valid type that the corpus has not recorded.

| `result` | Meaning under the governed first-failing-factor policy |
|---|---|
| `Supported` | Windows, type admissibility and bounded reachability all held |
| `Unsupported` | The first failing factor lacked evidence |
| `Contradicted` | The first failing factor had positive contrary evidence |

The rule checks both subject windows, admissibility, then reachability. An absence
earlier in that order can determine `Unsupported` even when a later factor is
contradicted. Always inspect the complete audit before interpreting the evidence.
This release exposes those factors without changing the governed verdict policy.

Every certificate carries:

- `evidence_scope: recorded_graph_feasibility` and `factual_verification: not_assessed`.
- `verdict_policy: first_zero_in_factor_order`.
- `filter_version`, `corpus_digest`, and the explicit `as_of` coordinate.
- `consulted`: sorted, deduplicated event ids used by certification.
- `audit.schema: cc.evidence-audit.v1`, `audit.absences`, and `audit.contradictions`.

`Supported` additionally carries `phi_support: true`. `Unsupported` carries
`vanished`; `Contradicted` carries `contradicted_by`. Missing evidence is not proof
of impossibility, and a feasible path is not proof of a particular historical claim.
A `503` is a read/evaluation failure, never a verdict. Missing `as_of`, an invalid
TT label, or a hop bound above the governed maximum is a `400`.

## Read records and verify signatures

`/v1/recents?as_of=…&limit=…` accepts up to 50 records per request. It may be dominated
by operational seals; a recent seal does not establish new historical coverage.
Entity responses expose their stored readings and a computed relation. Matching
entity identity does not by itself mean matching content hashes. Each item in
`readings.all` includes the exact stored `body` string and `body_status: retained`,
or `body: null` and `body_status: unavailable`, alongside `body_hash`. Readers must
not reconstruct missing prose from a local candidate. An unknown entity is still
`404 not_recorded`; it is not a retained reading with unavailable prose.

New `POST /v1/events` writes also pass the transactional
[subject admission guard](ADMISSION-REVIEW.md). A conflicting identity/body returns
a typed `409` without appending. Signature validity does not override this check.
Claims with no admitted media return `readings: []` from `/v2/media`; this does not
assert deliberate non-illustration.

`ops/verify-triple.py` checks served signatures with stock Ed25519. That verifies
the signature on an event id, not the JSON-to-canonical-content mapping or historical
truth. A page-level check is not a full-corpus audit.

## Settlement and evaluation

Authenticated `/health/deep` reports root, tree size, anchor status and block height.
Pending is not confirmed Bitcoin inclusion. A confirmed timestamp would establish
a commitment to bytes, not truth. The live check on 2026-09-07 reported Pending and
no committed founding exhibit; re-read rather than assuming either has changed.

Use the [evaluation guide](evaluation/README.md) to capture responses and validate
them offline. Quality and usefulness require external labels and matched consumer
runs; neither follows from an integrity PASS.

Operate and deploy through [the Fly guide](CICD-FLY.md). Railway URLs and deployment
commands belong to the retired host.

## Source date precision in controlled publication

Candidates may supply `prov_asserted.event_date` as a strict `YYYY-MM-DD`
and `prov_asserted.date_precision: "day"`. The Gregorian date must match
the claim year (CE 1–2100); captured source evidence must explicitly include
`date` support. Publication uses the start of that calendar day for entity
windows, moments and vocabulary, and the later endpoint for an edge. A cause
or influence dated after its effect is rejected, including within one year.

This is a day bucket under the existing calendar-to-coordinate convention,
not evidence of an exact instant or within-day order. Causal mechanisms need
separate source evidence. The title/year identity and TT envelope stay unchanged.
Candidates without a day retain their existing year mapping; applied events and
migration bytes are never rewritten. A source interval must not be represented
as an invented exact day.

## v1 mode

`CC_NODE_LEDGER=v1` makes `cc-node` serve a fresh v1 database instead of the
legacy ledger. Without that variable the node is the legacy node, unchanged.
In v1 mode none of the routes above are mounted. The contract is
[STAGE-F](design/STAGE-F.md).

| Variable | Meaning |
|---|---|
| `CC_NODE_LEDGER` | `v1`; any other value is refused |
| `DATABASE_URL` | The fresh v1 database, never the legacy one |
| `CC_V1_INSTANCE` | Instance ID, exactly 64 lowercase hex characters |
| `CC_V1_CURATORS` | Ed25519 public keys, 64 lowercase hex each, comma-separated with no spaces, strictly sorted |
| `CC_V1_MAX_HOPS` | Decimal hop bound; default `4` |
| `CC_V1_READ_CONCURRENCY` | Reads in flight before further reads get `503 busy`; canonical decimal `1` to `64`, default `8` |
| `CC_V1_NODE_SEED` | Optional. Exactly 64 lowercase hex characters, a 32-byte Ed25519 seed that signs node receipts. Refused if malformed, if it has fewer than 8 distinct characters, or if its public key is one of `CC_V1_CURATORS`. Absent: no receipts, and admission is unchanged |

`CC_NODE_API_KEY`, `CC_NODE_READ_KEY`, `CC_NODE_POSTURE` and `PORT` keep their
meaning. The gallery, beta and telemetry keys open no v1 route.

`serve` reads `CC_V1_READ_CONCURRENCY` and `CC_V1_NODE_SEED`; `provision-v1`
reads neither. A bad value stops `serve` with exit 78. The seed is a secret: set
it as a platform secret, never in source or argv. The boot log line names
`read_concurrency` and `node_key`, which is the public key or `off`. It never
prints the seed.

`cc-node provision-v1` creates the v1 schema and records the rule identity, or
accepts a database already provisioned with exactly this identity. It needs only
`CC_NODE_LEDGER`, `DATABASE_URL` and the identity variables `CC_V1_INSTANCE`,
`CC_V1_CURATORS` and `CC_V1_MAX_HOPS`, and prints
`{instance, fold_version:{version,manifest}, filter_version, semantic}`.
`cc-node serve` reopens that database read-only at boot and never provisions.
`cc-node migrate` refuses in v1 mode. Exit codes:

| Code | Meaning |
|---|---|
| 0 | Provisioned and `ready` |
| 78 | Configuration error, or `migrate` in v1 mode |
| 73 | The database holds non-v1 tables |
| 65 | Stored instance or rule identity differs, is missing or partial (no identity row or table), or the store is not provisioned and bound (`serve`) |
| 69 | Database unreachable, or it refused the operation (for example credentials or permissions) |
| 70 | Any other refusal, such as a corrupt stored candidate |

| Route | Scope | Answer |
|---|---|---|
| `GET /health` | public | Identity fixed at boot: `ledger`, `build`, `posture`, `instance`, `fold_version`, `filter_version`, `curators`, `max_hops`, and `semantic`, the readiness `serve` verified before listening. No database access, so it does not track later changes |
| `GET /ready` | public | The live check: 200 `{serving:true, posture}`, or 503 with `reason`; `busy` while another `/ready` check is running |
| `GET /robots.txt` | public | Deny all |
| `POST /v1/candidates` | write | Signed envelope bytes, at most 1 MiB; 201 valid, 202 pending, 422 invalid |
| `PUT /v1/bodies/{sha256}` | write | Body bytes, at most 1 MiB; 201 new, 200 existing, 422 hash mismatch |
| `GET /v1/export` | write | `ExportManifest` JSON with each envelope as one hex string |
| `GET /v1/snapshot` | read | Optional `fold_version` and `fold_manifest`; 409 if unsupported |
| `GET /v1/subjects/{id}` | read | Optional `as_of`; 404 for an unknown subject |
| `GET /v1/revisions/{id}/prose` | read | Verified body text when retained |
| `GET /v1/support?from=&to=` | read | Optional `as_of`; support verdict |
| `GET /v1/receipts/{event}` | read | Verified receipts for that event, in receipt-digest order: 200 `{event, receipts:[{receipt, receipt_digest, node_key, event, received_at, encoding_version, fold_version:{version,manifest}, initial_admission_result:{state, reason, missing}}]}`; 404 `no_receipt`; 400 `invalid_event_id`; 503 `receipt_verification_failed` if a stored receipt fails verification |
| `GET /v1/seal` | read | One freshly signed seal over the committed snapshot: 200 `{seal:{instance, node_key, fold_version:{version,manifest}, filter_version, corpus_digest, commitment, counts:{candidates}, build, sealed_at_us}, signature, node_key}`; 503 `no_seal_key` without `CC_V1_NODE_SEED`; 503 `seal_unavailable` if the node cannot sign, which happens only when its `build` string is empty, longer than 64 bytes or not printable ASCII; GET only (405 otherwise); no query parameters |

```sh
curl -fsS "$BASE/health"
curl -fsS -H "Authorization: Bearer $CC_NODE_READ_KEY" "$BASE/v1/subjects/$SUBJECT"
```

Missing or unknown credentials get `401`; the read key on a write route gets
`403`. A frozen node answers writes `503 {"error":"frozen"}` and still serves
reads and export. Every projection read (snapshot, subjects, prose, support)
names `rule`, `corpus_digest` and `commitment`; the receipts and seal routes
do not, because receipts and seals are outside every commitment.
IDs, digests and `as_of` (a 32-byte coordinate) are lowercase hex. Embedded
projection objects, the admission outcome and the export manifest keep their
canonical JSON, in which a hash is a list of 32 byte values. An unknown,
misspelled or repeated query parameter on any v1 data route is
`400 {"error":"invalid_query"}`.

### Snapshot cache, read limit, receipts and seals

None of this changes the rule identity, the fold or `/health`. The `/health`
document is unchanged and does not name the node key.

**Snapshot cache.** A read reuses the last committed snapshot when three things
match: the rule identity, the corpus digest, and a digest of the retained
candidate bytes. Any difference folds again from verified bytes. Every admission
invalidates the cache, whatever its outcome. Responses are byte-identical to an
uncached fold. Export never uses the cache. Checking the key still has
PostgreSQL hash every retained envelope on each read, so it grows with corpus
bytes; a hit skips the signature checks and the fold.

**Read limit.** At most `CC_V1_READ_CONCURRENCY` reads run at once. The limit
covers the read-scope routes: snapshot, subjects, prose, support, receipts,
seal and the unknown-path fallback. It applies after authentication, so a `401` never
takes a permit. `/health`, `/ready`, `/robots.txt` and the write-scope routes,
including `/v1/export`, are outside it. A read that finds the limit full gets
`503 {"error":"busy"}` with `Retry-After: 1` at once; it never waits for a
permit. The store pool has ten connections. Above about nine, admitted reads
can wait for a connection, and one that waits more than five seconds answers
`503 store_unavailable`. The default of 8 stays below the pool.

**Receipts.** With `CC_V1_NODE_SEED` set, the node signs a `NodeReceiptV1`
(domain `cc.receipt.v1`) for the first admission of each candidate: the call
that first retains that event id. The receipt is written in the same
transaction as the candidate. If signing fails, nothing is admitted and the
submit answers `503 admission_unavailable`. Otherwise:

- A resubmission of a retained event gets no new receipt.
- A rejected input that never becomes a candidate (undecodable, or the wrong
  instance) gets none. A retained candidate classified `invalid` or `pending`
  gets one that records that result.
- The submit response is unchanged: the `Outcome` JSON. Fetch the receipt from
  `GET /v1/receipts/{event}`.
- Receipts are observations, not events. They never enter the candidate set,
  corpus digest, view commitment, snapshot or export. A node with receipts on
  commits exactly what a node with them off commits.
- Receipts retained earlier stay readable if the seed is later removed.
- Export carries no receipts, so a store restored from an export has none. A
  database dump keeps them.

`receipt` is the signed bytes in hex and is authoritative. The other fields are
decoded conveniences. `received_at` is Unix microseconds observed by the node,
not historical time. To verify a receipt, decode `receipt`, split off the
trailing 64-byte signature, and check it with stock Ed25519 over the rest (the
preimage) against the node key. Pin the expected node key out of band: the node
does not publish it on `/health`, and the `node_key` inside a receipt only names
the key that signed it. A receipt attests that this node saw this event, not
that the event is true or that the corpus was in any given state.

**Seals.** With the same seed, `GET /v1/seal` signs a `NodeSealV1` (domain
`cc.seal.v1`, the receipt wire encoding, the same node key) over the committed
snapshot at that instant: the identity `/health` publishes, the
`corpus_digest` and `commitment` every projection read names, the number of
retained candidates, this `build` and `sealed_at_us`, the node clock in Unix
microseconds. The node keeps no seal and the response is not cached: two
seals of the same state differ only in clock and signature. `signature` is
64 bytes of hex, Ed25519 over the canonical bytes, which are the framed domain
followed by every `seal` field in the order listed, hashes as 32 raw bytes,
`version` as 2 bytes big-endian, `candidates` and `sealed_at_us` as 8, and
`build` as a 4-byte length and its ASCII. Pin the node key out of band;
`node_key` only names the key that signed. A seal attests that this node
served this state at this reading of its clock. It does not prove the state
is true, that no other store exists, or when anyone else saw it. Whoever
fetches seals keeps them; `ops/seal_v1.py` is the operator's hash-chained log
([OPERATIONS](OPERATIONS.md) section 8, [SEALING](design/SEALING.md)).
