# Operations: v1 update releases, backups, monitoring

Owner-operated runbook for a bound, populated v1 node. The first release onto a
fresh database is [FIRST-ENTRY.md](FIRST-ENTRY.md); the Fly access model is
[CICD-FLY.md](CICD-FLY.md). Standing constraints are in [HOLD.md](../HOLD.md).

## 1. Scope and boundary

- Everything here runs from the owner's workstation, by the owner or by the
  owner's agent at the owner's explicit instruction. Never from CI or a cloud
  session; GitHub holds no production credential.
- `fold_version` 1 is frozen. An update ships a new image over the same store;
  it never changes the instance, curators, `max_hops` (4) or fold.
- No synthetic write reaches production. Synthetic keys, Genesis entries and
  submissions exist only in throwaway local Docker networks. Production
  HTTP from these tools is GET-only (`ReadOnlyNode` refuses any other method
  before a socket opens); database reads use a `default_transaction_read_only`
  session.
- Values, keys, evidence and backups stay outside this checkout. Commands below
  never put a credential in argv.

| Placeholder | Meaning |
| --- | --- |
| `<app>` | Fly app serving the node |
| `<db-app>`, `<v1-db>`, `<operator-user>` | Fly Postgres app, v1 database, Postgres user whose password the DB machine holds as `OPERATOR_PASSWORD` |
| `<digest>` | Image manifest digest, 64 hex after `sha256:` |
| `$HOME/clockchain-ops/` | Example private directory (encrypted, backed up, outside the checkout) |

## 2. Update release (`--v1-update`)

### Prerequisites

- A clean checkout equal to current `origin/main`, with a successful `ci.yml`
  run for that exact SHA. Python 3.11+ with `ops/requirements.txt`, Docker
  running, `flyctl` and `gh` authenticated as the owner.
- One linux/amd64 image built from that checkout and pushed, digest recorded:

```sh
SHA=$(git rev-parse HEAD)
flyctl auth docker
docker buildx build --platform linux/amd64 --provenance=false \
  --build-arg CC_BUILD_REV="$SHA" -t "registry.fly.io/<app>:git-$SHA" --push .
docker buildx imagetools inspect "registry.fly.io/<app>:git-$SHA"
```

- The operator environment file from FIRST-ENTRY section 4 (`NAME=value`
  lines, mode 0600): `CC_NODE_API_KEY`, `CC_NODE_READ_KEY` (distinct),
  `CC_BACKUP_DB_APP=<db-app>`, `CC_BACKUP_DATABASE=<v1-db>`,
  `CC_BACKUP_USER=<operator-user>`, `CC_V1_INSTANCE`, `CC_V1_CURATORS`,
  `CC_V1_MAX_HOPS=4`.
- The v1 `fly.toml` (`CC_NODE_LEDGER=v1`, `CC_V1_MAX_HOPS = "4"`,
  `release_command = "cc-node provision-v1"`, a `/health` check). Fly secrets
  include `DATABASE_URL`, `CC_V1_INSTANCE`, `CC_V1_CURATORS`, both node keys,
  and none of `CC_NODE_LEDGER`, `CC_NODE_POSTURE`, `CC_V1_MAX_HOPS`.

### Command

```sh
set -a; . "$HOME/clockchain-ops/release.env"; set +a
ops/deploy-fly.sh --v1-update --app <app> \
  --image registry.fly.io/<app>@sha256:<digest> \
  --evidence "$HOME/clockchain-ops/evidence/update-$SHA"
```

Mutually exclusive with `--v1-fresh` and the v0 modes. The evidence directory
must be new and outside the checkout; releases serialize on
`$HOME/.clockchain/release.lock`.

### What happens, in order (stops at the first failure)

1. **Local gates.** Image pinned to `registry.fly.io/<app>@sha256:…`; clean
   checkout equals `origin/main`; exact-SHA CI green; required variables set and
   keys distinct; `CC_V1_*` valid with `max_hops` 4; `fly.toml` passes
   `check_config` (which also refuses `CC_V1_NODE_SEED` in `[env]`).
2. **W3 acceptance** (`accept_v1`, evidence `acceptance/`): the new image in
   temporary Docker + PostgreSQL 18 with synthetic data: `migrate` refused,
   `provision-v1` idempotent, zero check, synthetic Genesis submit and verify,
   populated check, dump/restore with identity refusals and equal commitment
   and export.
3. **Update scenario** (`accept_v1_update`, evidence `acceptance-update/`).
   Read-only lookups first: the image production runs now (`flyctl machines
   list`) and the secret names (`check_secret_names`, which already fails here
   on a stale override or missing secret). Then, locally: the current image
   provisions a synthetic store and admits one synthetic Genesis; the new
   image's `provision-v1` must leave every row identical (fingerprint), must
   still refuse a wrong instance, and must serve the same identity, corpus
   digest, commitment and byte-identical export.
4. `origin/main` rechecked; public IPs refused; a localhost proxy opened on a
   random port (section 5).
5. **Identity gate** (`deploy_digest.py --v1-update`, evidence `production/`).
   Machine census: one started app, no tick running, no scheduled machine.
   Expected identity = stored rule identity (`inspect_v1`, state `bound`) =
   `/health` identity; `/ready` 200.
6. **Observations.** Corpus digest and view commitment (`/v1/snapshot`, read
   key), `/v1/export` bytes (full key, GET) and a `cc_v1` store fingerprint (row
   count and SHA-256 per table).
7. **Verified backup before.** `capture_v1` dumps on the DB machine, restores
   into local PostgreSQL 18, proves the append-only guards, and has the **new**
   image re-serve the restored copy; its commitment must equal the observed one.
8. **Deploy.** `flyctl deploy --ha=false --no-public-ips --image <digest>`;
   `cc-node provision-v1` runs as the release command and must be a no-op;
   app scaled to one machine. The only `flyctl` subcommands this mode may run
   are `machines list`, `secrets list`, `deploy` and `scale count 1`.
9. **Rollout wait.** Up to 12 attempts, 5 s apart, until the census shows the
   new digest and `/health` reports `build` = the checkout SHA's first 12
   characters. Only the rollout is retried.
10. **Read-only post checks**, each once: identity unchanged; `/ready` 200
    (only 503 `busy` is retried, 5 attempts); corpus digest, commitment and
    export bytes identical; store fingerprint identical; stored identity and
    counts identical.
11. **Verified backup after**: `bound`, same commitment and counts as the
    backup before. Then public IPs are rechecked and the proxy stopped.

Success prints `Owner release verified: <sha>` and `v1 store updated; identity,
commitments and export unchanged.`

### Optional `CC_V1_NODE_SEED` (G4 receipts)

Never required. It must never appear in `fly.toml` (`check_config` refuses it);
set it only as a Fly secret. The release records `node_seed: present|absent`
from secret names alone in `rollback.json` and `acceptance.json`, and the update
scenario runs the new image with a random synthetic seed when production has
one.

### Evidence

| Path | Contents |
| --- | --- |
| `acceptance/` | `provision.json`, `v1-zero.json`, `v1-populated.json`, `v1-restore.json`, `acceptance.json`, `cleanup.json`; on failure `FAILED` and container logs |
| `acceptance-update/` | `v1-update.json`, `cleanup.json`; on failure `FAILED` and logs |
| `proxy.log` | Release proxy output |
| `production/expected.json` | Expected identity summary (public values) |
| `production/rollback.json` | `previous_image`, `sha`, `secret_names`, `node_seed`, `automatic_rollback: false` |
| `production/before.json` | Identity, previous build, stored state, fingerprint, digests |
| `production/export-before.json` | Raw pre-deploy export bytes (0600) |
| `production/backup-before/`, `backup-after/` | `database.dump` and `manifest.json` |
| `production/acceptance.json` | `cc.v1-update.v1`: builds, identity, `unchanged`, `provision_v1`, `http_methods`, both backup summaries |
| `production/FAILED`, `recovery.json` | Written on failure: before or after the deploy, `deployed`, `previous_image`, `status: NOT RUN` |

`cleanup.json` must read `removed: true`; leftover synthetic resources fail the
release.

### Failure handling and rollback

There is **no automatic rollback**. `FAILED` says whether the failure came
before the deploy or after it started.

- **Before the deploy** (local gates, acceptance, identity gate, observations,
  backup before): production is unchanged. The only remote side effect is a
  temporary dump file on the DB machine, removed after transfer. Fix the cause
  and rerun with a fresh evidence directory.
- **After the deploy started** (this includes a failed `flyctl deploy` itself):
  check which digest the app runs (`flyctl machines list`). If `provision-v1`
  failed, Fly aborted the deploy and the old image still runs; FIRST-ENTRY
  section 9 lists its exit codes. If the new image runs and a post check
  failed, read the error type in `recovery.json` before acting.
- **The store needs no restore.** An update never writes, and the release
  proves it with the fingerprint. The one exception is a fingerprint, counts or
  commitment mismatch (`CommitmentChanged`): treat that as an incident and
  preserve the evidence. Any restore is a separate owner decision.
- **Preferred rollback: fix forward.** Revert on `main`, wait for green CI,
  build, and run `--v1-update` with the new digest. Every gate applies.
- **Redeploying `previous_image` through `--v1-update` does not work.**
  Acceptance and the rollout wait require `/health` `build` to equal the
  checkout's SHA, and an older image reports its own build. It is refused
  locally, before production. Checking out the older SHA fails the
  `origin/main` gate.
- **Emergency, outside the gates (owner decision).** Redeploy the recorded
  digest with the flags the release uses:
  `flyctl deploy --app <app> --config fly.toml --ha=false --no-public-ips --image <previous_image>`.
  The previous image's `provision-v1` checks the store it served before the
  update. Then verify read-only: `monitor_v1.py run` (section 4) and a verified
  backup against a fresh export, with the operator environment loaded and an
  interactive localhost proxy open:
  `CC_NODE_URL=http://127.0.0.1:<port> python3 ops/v1_checks.py export --out <file>`, then
  `python3 ops/backup_fly.py --v1 --image registry.fly.io/<app>@sha256:<previous digest> --export <file> --output <new dir>`.

## 3. Scheduled verified backups

`ops/schedule_backups.py` installs a launchd LaunchAgent (`local.clockchain.backup`)
that runs daily at **09:00 local** by default.

**Env file**: `NAME=value` lines, no quotes, no `export`. It must be a regular
file owned by you, `chmod 600`, outside the checkout. Required names:
`CC_FLY_APP`, `CC_BACKUP_DIR`, `CC_OPS_STATE_DIR`, `CC_BACKUP_DB_APP`,
`CC_BACKUP_DATABASE`, `CC_BACKUP_USER`, `CC_NODE_API_KEY` (the export is a
full-key read), `CC_V1_INSTANCE`, `CC_V1_CURATORS`, `CC_V1_MAX_HOPS=4`. Both
directories must be outside the checkout. They are created 0700, and an
existing one readable by others is refused.

```sh
chmod 600 "$HOME/clockchain-ops/jobs.env"
python3 ops/schedule_backups.py generate --env-file "$HOME/clockchain-ops/jobs.env"   # print the plist
python3 ops/schedule_backups.py install  --env-file "$HOME/clockchain-ops/jobs.env" [--time HH:MM]
python3 ops/schedule_backups.py run      --env-file "$HOME/clockchain-ops/jobs.env"   # one run now
python3 ops/schedule_backups.py remove                                                # unload and delete
```

- `install` writes `~/Library/LaunchAgents/local.clockchain.backup.plist`, then
  boots out any loaded copy and bootstraps the new one. Rerun it to change the
  time.
- The plist names only the interpreter, the script, the env file and a log
  file (`<CC_OPS_STATE_DIR>/local.clockchain.backup.log`). It also captures the
  install-time `PATH`, so `flyctl` and `docker` must be on it. Install with the
  Python that has `ops/requirements.txt`.
- The job runs this checkout's code and recomputes identity from it. Keep the
  checkout on the released `main`.

**Each run** reads the app machine's exact image digest, runs `flyctl auth
docker`, opens its own proxy (section 5), requires the `/health` identity and
`/ready` 200, and GETs `/v1/export`. It then runs `capture_v1` into
`CC_BACKUP_DIR/cc_v1-<UTC stamp>`: read-only source inspection, `pg_dump` 18 on
the DB machine, restore into local PostgreSQL 18, guard proofs, and a re-serve
by the deployed image whose export must match production's. It adds
`export.json` to the bundle and prunes. A failed bundle is renamed
`<name>.failed`.

**Retention**: the newest 30 verified bundles (`manifest.json` with
`restore_verified` and `production_export_matched` true) and the newest 5
`.failed` directories. Only directories matching the job's own name patterns
are deleted. A bundle left by a killed run (no manifest, no suffix) is neither
counted nor pruned; remove it by hand.

**Status**: `<CC_OPS_STATE_DIR>/backup-status.json` (0600, atomically replaced),
schema `cc.v1-backup-status.v1`. Success: `result: ok`, `started_at`,
`finished_at`, `backup`, `image`, `state`, `counts`, `corpus_digest`,
`commitment`, `commitment_basis`, `dump_sha256`, `restore_verified`, `kept`,
`removed`. Failure (including a concurrent run holding the job lock):
`result: failed` with a redacted `error`, plus a macOS notification
("Clockchain backup").

- Missed `StartCalendarInterval` runs during sleep coalesce into one run on
  wake. Nothing runs while the machine is powered off.
- Docker must be running (PG18 restore and image re-serve); otherwise the run
  fails and notifies.
- Env values never reach the plist, argv, stdout or the status file; error
  text has every env value of 4+ characters replaced with `[redacted]`.

## 4. Monitoring

`ops/monitor_v1.py` installs `local.clockchain.monitor`, which runs every 15
minutes (`StartInterval` 900). Its env file holds `CC_FLY_APP`,
`CC_OPS_STATE_DIR` and the three `CC_V1_*` values. It needs no node credential,
so prefer a separate file without keys.

```sh
python3 ops/monitor_v1.py generate --env-file "$HOME/clockchain-ops/monitor.env"
python3 ops/monitor_v1.py install  --env-file "$HOME/clockchain-ops/monitor.env"
python3 ops/monitor_v1.py run      --env-file "$HOME/clockchain-ops/monitor.env"
python3 ops/monitor_v1.py remove
```

Each run opens its own proxy, GETs `/health` and compares the served identity
(ledger, instance, fold, `filter_version`, curators, `max_hops`) with the one
recomputed from the checkout and env file. It then requires `/ready` 200. Only
503 `busy` is retried.

Success is quiet: `monitor-status.json` is rewritten with `result: ok`,
`checked_at`, `identity: match`, `filter_version`, `build`, `ready`. A failure
writes `result: alert` with `kind`, `checked_at` and a redacted `error`, sends
a macOS notification, and exits 1. If the previous check still holds the lock,
the run exits 0 silently.

| `kind` | Cause |
| --- | --- |
| `identity_drift` | `/health` identity differs, is malformed or is not JSON |
| `not_ready` | `/health` non-200, or `/ready` non-200 or not serving |
| `unreachable` | Proxy exited or never answered, or a network error |
| `configuration` | Env file or state directory unsafe or incomplete |
| `error` | Anything else |

The monitor sees only what the workstation sees while it is awake. It is not
an external uptime check.

## 5. Proxy handling

- Scheduled jobs use `fly_proxy.FlyProxy`:
  `flyctl proxy <random port>:80 <app>.flycast -a <app> --bind-addr 127.0.0.1`
  on a fresh loopback port, up to 30 s for `/health` 200, stopped through its
  own Popen handle (terminate, then kill after 10 s).
- An existing proxy, your interactive one included, is never reused or
  touched. Nothing signals by name or port (no `pkill` or `killall`).
- Each job keeps `fly-proxy-<job>.json` (pid and exact argv) and
  `fly-proxy-<job>.log` in `CC_OPS_STATE_DIR`. Since the job lock is held, a
  pidfile found at start was left by a crashed run of the same job. That pid is
  sent SIGTERM only if it is alive **and** its `ps` command line equals the
  recorded argv, random port included; otherwise it is left running and only
  the stale pidfile is removed.
- The release opens its own random-port loopback proxy and stops it in a
  `finally`; it uses no pidfile, and the release lock serializes it.

## 6. Restore drill

Scheduled runs already restore every bundle. A drill proves that a **retained**
bundle still restores, on its own, into an isolated local PostgreSQL 18. Never
restore into production as part of a drill.

Copy the bundle first, because `restore_verify_v1` rewrites `manifest.json` in
the directory it verifies. Use the image that served the backup (`image` in
`backup-status.json`, or `--image` of the release that took it):

```sh
set -a; . "$HOME/clockchain-ops/monitor.env"; set +a        # CC_V1_* only are needed
DRILL="$HOME/clockchain-ops/drills/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DRILL" && cp -Rp "<CC_BACKUP_DIR>/cc_v1-<stamp>" "$DRILL/bundle"
flyctl auth docker
PYTHONPATH=ops python3 - "$DRILL/bundle" "registry.fly.io/<app>@sha256:<digest>" <<'EOF'
import json, sys
from pathlib import Path
from backup_fly import restore_verify_v1
from v1_identity import Expected
bundle = Path(sys.argv[1])
report = restore_verify_v1(bundle, Expected.from_env(production=True), image=sys.argv[2],
                           export=json.loads((bundle / 'export.json').read_text()))
print(json.dumps({k: report[k] for k in ('state', 'counts', 'commitment', 'dump_sha256')}))
EOF
```

This restores `database.dump` into a throwaway `postgres:18` container. It runs
`inspect_v1`, proves the guards and recomputes contents. The exact image then
runs `provision-v1` as an identity check, re-serves the copy, and compares the
export. The container and network are removed afterwards.

Success: the drill's `manifest.json` has `schema: cc.backup-restore-v1.v1`,
`restore_verified: true`, `state: bound`, every `guards` entry `proven`,
`commitment_basis: exact_image_reserved_restored_copy`,
`production_export_matched: true`, and `dump_sha256` and `commitment` equal to
the original manifest and that run's `backup-status.json`.

Run the drill monthly, on a bundle at least a week old, and keep the drill
directory with the evidence.

Other tools: `ops/backup_fly.py --v1 --output <new dir> [--image …] [--export …]`
takes a **new** production backup, read-only, verified the same way.
`ops/backup_restore.py --v1 --output <new dir> [--node-bin <cc-node>] [--export …]`
dumps a **reachable** source (`CC_SOURCE_PG*`) into an already-created, empty,
isolated PG18 database (`CC_RESTORE_PG*`; servers and client tools must be 18);
it does not consume an existing bundle. `ops/restore-verify.sh` is the v0 drill
(`events`, `exhibits`, `roots`) and does not apply to `cc_v1`.

## 7. Fly-native alternative (documented, not built)

Backups and monitoring could instead run as a scheduled Fly Machine
(`fly machine run <job-image> --schedule daily`)
inside Fly's private network, reaching `<app>.flycast` and `<db-app>` without a
proxy. **This is not implemented**; adopting it is an owner decision.

Tradeoffs against the workstation launchd jobs:

- **Separate app required.** The release census (`verify_v1`) refuses any
  scheduled machine in the node's app, so a job machine there blocks releases.
- **Secrets move into Fly.** The full API key (for the export) and DB access
  become secrets of another app: a new private-network principal that can
  reach the node and database.
- **Verification is weaker unless rebuilt.** The workstation restores into
  local PG18 and re-serves with the exact image through Docker. A Fly Machine
  has no Docker daemon by default; it would need PG18 plus a `cc-node` binary
  (as `backup_restore.py --node-bin` does), or it degrades to dump-only.
- **New channels.** Bundles need durable off-machine storage with its own
  credentials and retention; alerts need outbound egress (email or webhook)
  instead of a local notification.
- **Timing.** `--schedule` takes `hourly`, `daily`, `weekly` or `monthly` and
  runs approximately, so a 15-minute monitor does not map onto it.
- **Gains.** Runs while the workstation sleeps or is off, independent of the
  owner's network.
- **Cost and surface.** Billed machine time, storage and egress, plus a new
  image to build, pin and update: a standing production component that does
  not exist today.
