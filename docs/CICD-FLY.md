# Owner-operated private Fly deployment

CI checks public source and never deploys. Keep Fly and Clockchain credentials on
the owner's machine and in Fly secrets, not in GitHub Actions. No permanent Fly
acceptance app/database is needed. Public code does not expose production data.

## Access

The app has a private Flycast IPv6 address, no public IPv4/IPv6 ingress, and no
consumer credentials for gallery, beta or telemetry. The database remains private.
Only the owner holds the current full and read-only credentials. Other apps in the
same Fly organization still share private networking; application authentication
remains mandatory.

```sh
flyctl proxy 18080:80 timepoint-clockchain-prod.flycast -a timepoint-clockchain-prod
# Separate terminal; read credential supplied privately:
curl -fsS -H "Authorization: Bearer $CC_NODE_READ_KEY" http://127.0.0.1:18080/health/deep
```

Flycast uses private HTTP; do not force an HTTPS redirect to a public endpoint.
`fly.toml` describes this private service. Promotion explicitly disables public IP
allocation. Keep exactly one app writer. The v0 ledger used a stopped-between-runs
hourly tick; the v1 ledger runs none (see the v1 section below).

Check IP allocations on both app and database and inspect actual machine services,
not just this file. The checked-in request concurrency is soft 8 / hard 16; it
applies through Fly Proxy after an owner-run release and is not a per-client
rate limit. Read [security boundaries](../SECURITY.md) for crawler, cache and
egress limits. Retain live inspection evidence privately; a private ingress
address does not prove outbound traffic is restricted.

## Build, accept and release

Use a clean checkout of current main with a passing exact-SHA CI run. Install
`ops/requirements.txt`, run Docker locally, and authenticate `gh` and `flyctl` as
the owner. Build one Linux amd64 image and retain its manifest digest:

```sh
SHA=$(git rev-parse HEAD)
flyctl auth docker
docker buildx build --platform linux/amd64 --provenance=false \
  --build-arg CC_BUILD_REV="$SHA" \
  -t "registry.fly.io/timepoint-clockchain-prod:git-$SHA" --push .
```

Record the returned `sha256:` manifest digest, then run the release from the same
clean checkout. Supply `CC_NODE_API_KEY`, `CC_NODE_READ_KEY`, `CC_SMOKE_ENTITY`,
`CC_BACKUP_DB_APP`, `CC_BACKUP_DATABASE`, and `CC_BACKUP_USER` through the private
operator environment. No credential values belong in command arguments.

```sh
ops/deploy-fly.sh --app timepoint-clockchain-prod \
  --image registry.fly.io/timepoint-clockchain-prod@sha256:<manifest-digest> \
  --evidence /absolute/private/path/release-<sha>
```

The command requires exact-main CI, tests the immutable image in a temporary
Docker network with isolated PG18/media and synthetic content, and removes test
resources even on failure. Its PNG fixture is about 1.7 MiB. It rechecks main,
opens a localhost-only Fly proxy, pauses publication, captures production DB/media,
independently restores the backup, deploys the same digest, refreshes the tick
without starting it, and runs production checks using an existing real attachment.
No synthetic claim enters production and the genuine canary remains human-only.

Private release evidence must be outside the checkout and retained in the owner's
encrypted backup archive. Same-machine releases are serialized by a file lock.
Use one owner workstation for production releases; the lock is not distributed.

## Recovery after a failed promotion

Restore compatible app/tick digests with publication paused. The older migration
release command is skipped: applied newer additive migrations remain. This is not
safe for arbitrary destructive migrations. Failure details are retained in
`recovery.json`; do not infer recovery from a successful rollback command alone.
Database restore is separate disaster recovery. Preserve signing keys and media.
Projection replay is not established by an ordinary dump/restore result.

## Releasing onto a completely empty chain

Use `--zero-events` when production has no genesis, claims or media. It is mutually
exclusive with `--empty-corpus` (genesis-only). The zero-event release checks the
restored table counts, migration checksums and zero commitment, verifies the
append-only truncate guard, and leaves publication paused. It never initializes
the ledger to make a smoke check pass. `CC_SMOKE_ENTITY` is unnecessary in either
empty mode. Exact-image Docker acceptance still exercises zero, genesis-only and
synthetic populated states in its isolated database.

## v1 release onto a fresh database

`--v1-fresh` is the owner-authorized v1 launch. It is mutually exclusive with
`--zero-events` and `--empty-corpus`. The checked-in `fly.toml` is now a v1
config:

- `CC_NODE_LEDGER=v1`;
- `CC_V1_MAX_HOPS=4`;
- `release_command = "cc-node provision-v1"`;
- a `/health` check.

The v0 modes refuse it, and `--v1-fresh` refuses a v0 config. The step-by-step
owner procedure, including key ceremony, database creation, staged secrets, the
tick and the inaugural entry, is [FIRST-ENTRY.md](FIRST-ENTRY.md).

The operator environment adds `CC_V1_INSTANCE`, `CC_V1_CURATORS` and
`CC_V1_MAX_HOPS` (which must be 4) to the existing credentials and
`CC_BACKUP_*`, where `CC_BACKUP_DATABASE` names the v1 database.
`CC_SMOKE_ENTITY` is not used. The expected identity is recomputed from the
checkout and never taken from the node:

- `filter_version` comes from the curators and the hop bound;
- the empty view commitment is recomputed;
- the `cc_v1` schema hash comes from the checkout's `v1.sql`.

```sh
set -a; . <private operator env file>; set +a
ops/deploy-fly.sh --v1-fresh --app <app> \
  --image registry.fly.io/<app>@sha256:<manifest-digest> \
  --evidence /absolute/private/path/release-<sha>
```

1. **Exact-image acceptance** (`ops/v1_acceptance.py`) runs in a temporary
   Docker network with an isolated PostgreSQL 18 and synthetic data only:
   1. `cc-node migrate` must exit 78.
   2. `cc-node provision-v1` must succeed twice with identical output, using a
      synthetic curator from the image's own `cc-publisher v1 keygen`.
   3. The node serves, and `check_v1_zero` runs, including the candidate-route
      denial probes.
   4. A synthetic Genesis goes through `cc-publisher v1 genesis`, `submit` and
      `verify`.
   5. `check_v1_populated` runs.
   6. `pg_dump -n cc_v1` is restored into a fresh empty database. There,
      `provision-v1` must reproduce the identity and refuse a wrong instance
      and a wrong curator set. Every append-only trigger must refuse UPDATE,
      DELETE and TRUNCATE. The restored node must serve the same commitment
      and a byte-equal export.

   Containers, the network and the temporary key directory are removed on
   success or failure. Fresh and update acceptance retain every provisioning
   attempt's raw stdout, stderr and exit status under the private evidence
   directory's `provision-attempts/`, including failures and expected identity
   refusals. Node diagnostics go to stderr; successful `provision-v1` stdout
   contains only the identity JSON.
2. **Production**, after main is rechecked and public IPs are refused, has
   these steps:
   1. Machine census: one app, and no tick running or scheduled. Any scheduled
      machine is refused.
   2. A read-only inspection of the v1 database. It must hold no relation
      outside `cc_v1`, and must be uninitialized or hold exactly the expected
      instance, schema hash and rule identity with zero candidates, bodies,
      receipts and rejections.
   3. A backup, restored and verified in local PostgreSQL 18.
   4. `fly deploy` of the exact digest. The release command provisions and
      binds.
   5. The census again.
   6. `/health` checked against the expected instance, fold, `filter_version`,
      curators and `max_hops`, with `semantic` `ready`. `/ready` must return
      200.
   7. The read-only `check_v1_zero`.
   8. A second backup. Its restored copy is re-served by the same image, and
      its export must equal production's.

v1 mode never pauses or resumes v0 publication, because that would write to the
archived v0 database. It never updates or starts a tick, never submits an
entry, and never rolls back automatically. On failure, `FAILED` and
`recovery.json` record the previous image for an owner decision.

Production probes are read-only by construction. The only mutating-method
requests are anonymous and read-key `PUT /v1/bodies/<sha256("")>` carrying a
body that does not hash to that path. Even a node with broken authorization
could only refuse them. Candidate-route probes, which a broken node could record
as rejections, run only in acceptance.

Backups of a v1 database use `ops/backup_fly.py --v1`, or `ops/backup_restore.py
--v1` for a manually reachable source:

- The table census must list exactly the six `cc_v1` tables.
- All six statement-level append-only triggers must be proven on the restored
  copy, which also works with empty tables.
- Every candidate must hash to its event id, and every body to its key.
- The corpus digest is recomputed.
- The commitment is either recomputed (empty corpus) or read from the exact
  image re-serving the restored copy (`--image`, or `--node-bin` for the
  manual tool). Either way it must match production's `/v1/export` when one is
  given (`--export`).
