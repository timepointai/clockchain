# Stage (f): v1 serving runtime and first-entry launch

Owner decision, 2026-10-01. The pinned STAGE-E defaults are accepted. Stage (f) is
authorized, and so is one owner-operated release onto a fresh v1 database. The
inaugural entry is the Engelbart 1968 "Mother of All Demos" subject, newly
authored as a v1 Genesis. See [HOLD.md](../../HOLD.md) for the exact scope.

Refs #6. Only the owner decides that issue.

## Goal

The normal `cc-node` binary serves v1 in an explicit v1 mode. The publisher can
sign and submit a v1 Genesis. The release tooling can:

- accept the exact image against v1;
- provision and bind a fresh v1 database;
- deploy;
- verify production.

All three pieces must be merged and verified **today**.

## Boundaries for agents

- Cloud sessions never deploy, never contact production, and never handle real
  keys or fixture content. Tests use synthetic keys and data only.
- Do not edit:
  - HOLD.md;
  - the Stage 0 model, checker or receipts;
  - applied migrations;
  - existing vectors;
  - the pinned fold manifest.
- New vectors may be added.
- Commit messages and PR text are description only. No trailers or attribution.
  Use "Refs #6", never closing keywords.
- Cloud sessions do not merge. The owner's supervisor merges each PR only after
  all of: exact-head CI, an independent local PostgreSQL 18 gate, and a review.

## Facts the design starts from

- `Store::provision` refuses a database holding any non-`cc_v1` relation. v1
  therefore needs its own fresh database; the v0 production database stays as an
  archive.
- `fly.toml` runs `release_command = "cc-node migrate"` (v0).
- The hourly `tick` machine runs `cc-anchor-tick`, which writes v0 events. v1
  launches without a tick.
- `cc-publisher` writes v0 events straight to the database. It has no v1 path.
- The normal router mounts only v0 routes. The v1 `review_router` is test-only
  and returns `/ready` 503 `stage_e_non_serving`.

## Shared contract

Every workstream codes against this contract. A change to it must be stated in
the PR body and mirrored by the other workstreams.

### Configuration (v1 mode)

| Variable | Meaning |
| --- | --- |
| `CC_NODE_LEDGER=v1` | Selects v1 mode. If absent, the legacy v0 behavior is unchanged. |
| `DATABASE_URL` | The fresh v1 database. |
| `CC_V1_INSTANCE` | Instance ID, 64 hex characters. |
| `CC_V1_CURATORS` | Comma-separated Ed25519 public keys, 64 hex each, strictly sorted. The identity must pass `FilterIdentity::governed`. |
| `CC_V1_MAX_HOPS` | Default `4`, the governed production value. |

`CC_NODE_API_KEY` (write), `CC_NODE_READ_KEY` (read), `CC_NODE_POSTURE`
(`live` or `frozen`) and `PORT` keep their current meaning.

### Node subcommands

- `cc-node provision-v1`:
  - idempotently runs `Store::provision` and then `bind` from the configuration
    above;
  - prints JSON `{instance, fold_version:{version,manifest}, filter_version, semantic}`;
  - exits 0 only when semantic readiness is `ready`;
  - exits non-zero on an identity mismatch, a `NotEmpty` database or a
    configuration error. This becomes the v1 release command.
- `cc-node migrate` refuses, with exit 78, when `CC_NODE_LEDGER=v1`. This keeps
  v0 tables out of the v1 database.
- `cc-node serve` in v1 mode verifies the stored identity at boot and fails
  closed on any mismatch. It never initializes a new rule identity implicitly;
  provisioning does that.

### HTTP in v1 mode

v0 routes are not mounted. Scopes reuse the existing keys. Every route goes into
`tests/credential_scope.rs`.

| Method and path | Scope | Contract |
| --- | --- | --- |
| `GET /health` | public | `{ledger:"v1", build, posture, instance, fold_version:{version,manifest}, filter_version, curators, max_hops, semantic}`. No fold recomputation. |
| `GET /ready` | public | 200 `{serving:true, posture}` when semantic readiness is `ready`; otherwise 503 with the reason. |
| `POST /v1/candidates` | write | Raw signed envelope, at most 1 MiB. Returns 201 valid, 202 pending, or 422 invalid, with the existing `Outcome` JSON. Frozen posture returns 503 `frozen`. |
| `PUT /v1/bodies/{sha256}` | write | Raw body bytes, at most 1 MiB, passed to `retain_body`. Returns 201 new, 200 existing, or 422 on hash mismatch. Frozen posture returns 503. |
| `GET /v1/snapshot` | read | Optional `fold_version` and `fold_manifest`; 409 `unsupported_fold_version`. Body: `{rule, corpus_digest, commitment, rows, subjects, revisions, edges, media, authority}`. |
| `GET /v1/subjects/{subject_id}` | read | Optional `as_of`. `EntityRead` plus `rule`, `corpus_digest` and `commitment`. |
| `GET /v1/revisions/{revision}/prose` | read | As in the review router today. |
| `GET /v1/support?from=&to=&as_of=` | read | Snapshot verdict JSON. |
| `GET /v1/export` | write | `ExportManifest` JSON, with envelopes as hex. Used for backup verification. |

`Store::review*` and raw `restore` are not reachable over HTTP in v1 mode
(STAGE-E N3). Node receipts are optional for launch. If they are implemented,
the node key comes from `CC_V1_NODE_SEED`; otherwise record them as a follow-up.

### Publisher CLI (`cc-publisher v1 …`; the v0 commands stay unchanged)

All commands except `node-info`, `submit` and `verify` work offline. Secrets come
from the environment or files, never from argv.

- `keygen --out FILE`: writes a random 32-byte seed as hex with mode 0600,
  refuses to overwrite, and prints the public key.
- `pubkey --key FILE`: prints the public key for a seed file.
- `node-info --node URL`: calls `/health` and checks that `fold_version`
  equals this build's `fold_v1()`.
- `genesis --key FILE --instance HEX --kind TT_KIND --namespace NS --value V --body FILE --asserted-time T [--evidence SHA256 …] --out DIR`:
  - validates the kind against the pinned TT taxonomy;
  - writes `envelope.bin`, `body.bin` and `preview.json` (event, subject,
    revision, author, body hash, subject key, asserted time, instance).
- `submit --node URL --dir DIR`:
  - the bearer token comes from `CC_NODE_API_KEY`;
  - checks that the instance, fold and curator membership match;
  - PUTs the body, POSTs the envelope, and requires 201;
  - then reads back the subject and prose, compares bytes, and writes
    `receipt.json`.
- `verify --node URL --subject ID`: read-only verification.

## Workstreams (parallel; one cloud session each)

| | Branch | Owns | Must deliver |
| --- | --- | --- | --- |
| **W1 node** | `feat/v1-serving-node` | `crates/cc-node`, the minimal glue in `crates/cc-ledger` | v1 mode config, subcommands, routes and readiness above; credential census; tests over real PostgreSQL. |
| **W2 publisher** | `feat/v1-publisher` | `crates/cc-publisher` | The v1 CLI above, with offline and online tests. |
| **W3 release** | `feat/v1-release-ops` | `ops/`, `Dockerfile`, `fly.toml`, `docs/CICD-FLY.md`, new `docs/FIRST-ENTRY.md` | v1 acceptance, deploy, checks, backup and restore; the owner runbook. |

W1 details:

- Fail closed on identity mismatch.
- Reject writes in frozen posture.
- No fold recomputation in `/health`.
- Port the applicable `cc-node` hardening from branch
  `salvage/live-brief-security-20261001` (`auth.rs`, `security.rs`,
  `credential_scope`).

W2 details:

- Offline tests cover:
  - deterministic preview for a fixed seed and nonce;
  - taxonomy rejection;
  - refusal to overwrite a key;
  - file mode 0600.
- Online tests:
  - before W1 merges, run against `review_router` for `/v1/candidates`, with a
    stub body route;
  - after W1 merges, rebase and run against the real v1 node.

W3 details:

- **Release mode.** `ops/deploy-fly.sh` / `release.py` get a `--v1-fresh` mode.
- **Acceptance** runs on an empty PostgreSQL 18 database:
  1. `provision-v1` with a synthetic curator;
  2. serve;
  3. a v1 zero check;
  4. a synthetic Genesis through `cc-publisher v1`;
  5. a populated check;
  6. `pg_dump -n cc_v1`, restore into an empty database, re-provision, and check
     for equal commitments.
- **Production steps:**
  1. back up the v1 database;
  2. deploy the exact digest;
  3. check `/health` against the expected instance, filter and curators, and
     check `/ready`;
  4. run the deployed v1 zero check.

  No synthetic write reaches production.
- **Tick.** v1 mode skips tick updates, and `verify_fly_machines` expects no
  running tick.
- **Porting.** Port the salvage hardening for `fly.toml`, `.dockerignore`,
  `SECURITY.md` and `robots.txt`.
- **Runbook.** Write `docs/FIRST-ENTRY.md`, covering:
  1. key ceremony with `cc-publisher v1 keygen` on the owner's Mac;
  2. instance ID;
  3. creating the v1 database on the Fly Postgres app, with placeholders only;
  4. Fly secrets;
  5. stopping the tick;
  6. build, then `deploy-fly.sh --v1-fresh`;
  7. authoring the 1968 Genesis (kind, namespace and value from the TT
     taxonomy; asserted time 1968-12-09; evidence hashes of the private source
     captures);
  8. owner review, then `submit`, `verify` and backup;
  9. post-launch evidence.

## Integration order

1. All three branches start from `main` at once and code against the contract.
2. W1 merges first.
3. W2 and W3 rebase onto `main` and complete their integration tests:
   - W2: its client against the real node;
   - W3: the full Docker acceptance with both binaries.
4. Then W2 merges, then W3.
5. Cargo.lock conflicts are resolved on rebase.

Each PR body keeps a short status section: what is done, what is blocked on
another workstream, and any contract deviation.

## Evidence rules

These carry over from the Stage (d)/(e) reviews:

- Every reported count comes from an assertion that can fail.
- Each key new rule gets a mutation spot check that removing it fails a test:
  - identity fail-closed;
  - frozen write refusal;
  - scope checks;
  - provision idempotence and mismatch;
  - publisher instance/fold/curator checks.
- Report actual local results, PostgreSQL version included, separately from
  exact-head CI.
- Use subagents for parallel subtasks and for an independent self-review
  against this contract before marking a PR ready.
