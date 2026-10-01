# First v1 entry: owner runbook

Owner-operated. Run from the owner's workstation only, never from CI or a cloud
session. Scope comes from [HOLD.md](../HOLD.md): one release onto a fresh, empty
v1 database; production writes are limited to provisioning it, binding its rule
identity with the owner's curator key, and the single inaugural Genesis (the
Engelbart 1968 "Mother of All Demos" subject, no media, no absence decision).
The v0 database stays untouched as an archive.

Every `<PLACEHOLDER>` is a private value. Keep the values, keys, captures and
evidence outside this checkout. Commands below never put a credential in argv
or shell history: credentials are read from private files or from an operator
environment file loaded with `set -a; . <PRIVATE_DIR>/release.env; set +a`.

| Placeholder | Meaning |
| --- | --- |
| `<PRIVATE_DIR>` | Private, encrypted, backed-up directory outside the checkout |
| `<EVIDENCE_DIR>` | Private evidence directory outside the checkout |
| `<APP>` | The Fly app serving the node |
| `<PG_APP>` | The existing Fly Postgres app |
| `<V1_DB>`, `<V1_USER>` | New v1 database and its login role |
| `<OPERATOR_USER>` | Postgres user whose password the DB machine holds as `OPERATOR_PASSWORD` (the user the v0 backups use) |
| `<CAPTURES_DIR>` | Private source captures for the 1968 claim |
| `<BODY_FILE>` | Owner-authored UTF-8 prose body for the Genesis |
| `<NAMESPACE>`, `<VALUE>` | Subject key namespace and value (section 7) |
| `<DIGEST>` | Image manifest digest, `sha256:` + 64 hex |

**Run order: 1, 2, 3, 5, 4, 6, 7, 8.** Section 5 (tick) comes before section 4
(secrets): the v0 tick writes v0 events, and it must not exist when the v1
`DATABASE_URL` reaches any machine. Section 4 stages secrets anyway, so nothing
restarts until the deploy in section 6.

Run every command in **bash** (`bash` first; macOS defaults to zsh, which does
not split words or treat `#` as a comment the same way). Comments sit on their
own lines so a pasted line never passes them as arguments.

Prerequisites: a clean checkout of current `main` with a green exact-SHA CI run
(the same commit for every step), Docker, `flyctl` and `gh` authenticated as the
owner, `jq`, `openssl`, Python 3.11+ with `ops/requirements.txt`, and a Rust
toolchain for building `cc-publisher` locally:

```sh
git switch main && git pull --ff-only && test -z "$(git status --porcelain)"
SHA=$(git rev-parse HEAD)
cargo build --locked --release -p cc-publisher
PUB=target/release/cc-publisher
```

## 1. Key ceremony (owner's Mac)

The curator key is the root of authority: only the owner generates, holds and
uses it. Disconnect from the network for this section.

```sh
umask 077
mkdir -p <PRIVATE_DIR>
"$PUB" v1 keygen --out <PRIVATE_DIR>/curator.seed > <PRIVATE_DIR>/curator.pub
# Must print the same key:
"$PUB" v1 pubkey --key <PRIVATE_DIR>/curator.seed
cat <PRIVATE_DIR>/curator.pub
```

- `keygen` writes a random 32-byte seed as hex with mode 0600 and refuses to
  overwrite an existing file. It prints the public key.
- Keep `curator.pub` as exactly one line holding the 64-hex public key. If the
  CLI prints more than the key, reduce the file to the key alone. That key is
  `CC_V1_CURATORS`. With one curator there is no comma. With several, the keys
  are lowercase, comma-separated and strictly sorted.
- Store `curator.seed` privately. Make at least one offline backup, such as an
  encrypted removable volume kept apart from the workstation. To check the
  backup, run `"$PUB" v1 pubkey --key <BACKUP>/curator.seed` and confirm it
  prints the same public key.
- Never copy the seed into the checkout, a Fly secret, CI or a cloud session.
  The node never needs it.

Success: `pubkey` reproduces the key, and the offline backup reproduces it too.
Abort point: a lost or exposed seed before section 4 costs nothing. Generate a
new one. After the release, the curator set is part of the bound identity and
cannot be changed in place.

## 2. Instance id

```sh
umask 077
openssl rand -hex 32 > <PRIVATE_DIR>/instance.hex
# 65: 64 lowercase hex characters plus a newline.
wc -c < <PRIVATE_DIR>/instance.hex
```

Record the value privately with the key ceremony record. Every v1 event signs
this instance, so an envelope for another instance is rejected. It is not a
credential, but it is the store's identity and is recorded only privately.

## 3. Fresh v1 database on the existing Fly Postgres app

Store a new random password for the v1 role privately, then open a superuser
`psql` session:

```sh
umask 077
openssl rand -hex 32 > <PRIVATE_DIR>/v1-db-password
fly postgres connect -a <PG_APP>
```

In `psql`, use `\password` so the password is pasted at a prompt and never
written to a history file:

```sql
CREATE ROLE <V1_USER> LOGIN;
\password <V1_USER>
CREATE DATABASE <V1_DB> OWNER <V1_USER>;
REVOKE ALL ON DATABASE <V1_DB> FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE <V1_DB> TO <V1_USER>;
\c <V1_DB>
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
   AND c.relkind IN ('r','p','v','m','S','f');
```

The last query must return `0`.

- The role owns its database, so `provision-v1` can create the `cc_v1`
  schema, its tables, triggers and function.
- `provision-v1` refuses any database that holds a non-`cc_v1` relation.
- Do not run `cc-node migrate` against this database. In v1 mode it exits 78.

Write the v1 connection URL into `<PRIVATE_DIR>/v1-database-url` with an editor,
not with `echo`. Use the same host, port and options as the current v0
`DATABASE_URL`, and change only the user, password and database name. Fly
cannot show a secret's value again, so confirm the current v0 `DATABASE_URL` is
already recorded privately. A rollback to v0 needs it.

Success: the database exists, the census query returns 0, and the v0 database
is unchanged. Abort point: `DROP DATABASE <V1_DB>` and `DROP ROLE <V1_USER>`
undo this section. Nothing else depends on it yet.

## 4. Fly secrets (staged)

Do section 5 first. Then remove any stale secret named `CC_NODE_LEDGER`,
`CC_V1_MAX_HOPS` or `CC_NODE_POSTURE`, staged so nothing restarts. `fly.toml`
sets those, and a secret overrides `[env]`, so `/health` would report a
different identity or posture and the release checks would fail:

```sh
fly secrets list -a <APP>
# Record any of the three names the list shows, then unset only those.
# Plain `unset` would restart machines now.
fly secrets unset --stage CC_NODE_LEDGER CC_V1_MAX_HOPS CC_NODE_POSTURE -a <APP>
```

The release refuses to deploy while any of those three names is still a secret,
and while any of `DATABASE_URL`, `CC_V1_INSTANCE`, `CC_V1_CURATORS`,
`CC_NODE_API_KEY` or `CC_NODE_READ_KEY` is missing (it reads names only).

Stage the v1 secrets. Values go through stdin as `NAME=VALUE` lines built with
the shell's `printf` builtin, so they never appear in history or in a process
argument list:

```sh
# Confirm this flyctl supports staging:
fly secrets import --help | grep -- --stage
{
  printf 'DATABASE_URL=%s\n'   "$(cat <PRIVATE_DIR>/v1-database-url)"
  printf 'CC_V1_INSTANCE=%s\n' "$(cat <PRIVATE_DIR>/instance.hex)"
  printf 'CC_V1_CURATORS=%s\n' "$(cat <PRIVATE_DIR>/curator.pub)"
} | fly secrets import --stage -a <APP>
# Names and digests only:
fly secrets list -a <APP>
```

- `CC_NODE_API_KEY` (write) and `CC_NODE_READ_KEY` (read) keep their meaning.
  Rotate them now only if you want fresh v1 credentials.
- Do **not** create secrets named `CC_NODE_LEDGER`, `CC_V1_MAX_HOPS` or
  `CC_NODE_POSTURE` (until the posture decision in section 8).
- Never use plain `fly secrets set` or `fly secrets unset` here. Either deploys
  every staged secret at once and restarts the v0 app against the v1 database.

Create the operator environment file the release reads. Its `CC_V1_*` lines
come from the same private files the secrets were staged from, so the expected
identity cannot drift from what `provision-v1` will bind. Put the two node
credentials in `<PRIVATE_DIR>/node-keys.env` first, with an editor
(`CC_NODE_API_KEY=…` and `CC_NODE_READ_KEY=…` lines):

```sh
umask 077
{
  # awk 1 adds a final newline if the file lacks one.
  awk 1 <PRIVATE_DIR>/node-keys.env
  printf 'CC_BACKUP_DB_APP=%s\n'   '<PG_APP>'
  printf 'CC_BACKUP_DATABASE=%s\n' '<V1_DB>'
  printf 'CC_BACKUP_USER=%s\n'     '<OPERATOR_USER>'
  printf 'CC_V1_INSTANCE=%s\n'     "$(cat <PRIVATE_DIR>/instance.hex)"
  printf 'CC_V1_CURATORS=%s\n'     "$(cat <PRIVATE_DIR>/curator.pub)"
  printf 'CC_V1_MAX_HOPS=4\n'
} > <PRIVATE_DIR>/release.env
```

The release checks this identity against both the database and `/health`; the
node does not get to decide what is expected. The secrets cannot be read back
from Fly, so this shared source is the only pre-deploy guard: the release
command binds whatever identity the secrets carry, permanently, and a mismatch
shows up only in the post-deploy checks (section 9 has the recovery).

Success: `fly secrets list` shows the three names as staged or updated, and the
running v0 app has not restarted. Abort point: run
`fly secrets unset --stage DATABASE_URL CC_V1_INSTANCE CC_V1_CURATORS -a <APP>`,
then re-stage the v0 `DATABASE_URL`, and any stale secret recorded above, the
same way.

## 5. Stop the tick (before section 4)

v1 launches without a tick. A stopped machine that keeps a schedule starts again
on that schedule, so destroy it. Keep a private copy of its configuration first:

```sh
fly machines list -a <APP> --json \
  | jq -r '.[] | select(.config.metadata.fly_process_group == "tick") | .id'
fly machine status <TICK_ID> -a <APP> --display-config > <PRIVATE_DIR>/tick-machine.txt
fly machine destroy <TICK_ID> -a <APP> --force
fly machines list -a <APP> --json | python3 ops/verify_fly_machines.py --v1
```

`verify_fly_machines.py --v1` must print the app machine and no error. It
refuses any scheduled machine, and any running machine other than the app. The
release repeats this check before and after the deploy.

Success: the census passes. Abort point: the v0 service keeps running without
its tick. To restore it, recreate the machine from the saved configuration.

## 6. Build the image and release with `--v1-fresh`

Build one linux/amd64 image from the clean checkout, push it, and record its
manifest digest:

```sh
flyctl auth docker
docker buildx build --platform linux/amd64 --provenance=false \
  --build-arg CC_BUILD_REV="$SHA" \
  -t "registry.fly.io/<APP>:git-$SHA" --push .
# Note the manifest Digest:
docker buildx imagetools inspect "registry.fly.io/<APP>:git-$SHA"
```

Release from the same checkout, with the operator environment loaded and a new
private evidence directory:

```sh
set -a; . <PRIVATE_DIR>/release.env; set +a
ops/deploy-fly.sh --v1-fresh --app <APP> \
  --image registry.fly.io/<APP>@<DIGEST> \
  --evidence <EVIDENCE_DIR>/release-$SHA
```

The command does the following, in order. It stops at the first failure.

1. Requires a clean checkout equal to `origin/main` with a successful exact-SHA
   CI run.
2. Requires the `CC_V1_*` values to be valid, with production `max_hops` 4, and
   a v1 `fly.toml`.
3. Runs exact-image acceptance in local Docker with an isolated PostgreSQL 18
   and synthetic data only:
   1. `migrate` is refused.
   2. `provision-v1` succeeds twice with a synthetic `keygen` curator.
   3. The node serves.
   4. `check_v1_zero` passes.
   5. A synthetic Genesis goes through `genesis`, `submit` and `verify`.
   6. `check_v1_populated` passes.
   7. A `pg_dump -n cc_v1` restored into a fresh database passes
      `provision-v1`, refuses a wrong instance or curator set, and serves an
      equal commitment and a byte-equal export.
4. Rechecks `main`, refuses public IPs, and opens a localhost-only `fly proxy`.
5. Machine census: the app only, with no tick running or scheduled.
6. Inspects the v1 database read-only. It must be empty, or hold only the
   expected `cc_v1` instance and rule identity with no rows. Then it backs the
   database up and restores the backup in local PostgreSQL 18.
7. Runs `fly deploy` with the exact digest. The release command is
   `cc-node provision-v1`, which provisions and binds. No tick is updated or
   started, and v0 publication control is not touched.
8. Read-only checks:
   - census again, with the app on the new digest;
   - `/health` reports `ledger` `v1`, this build, the expected instance, fold,
     `filter_version` (recomputed from your curators and hop bound),
     `curators`, `max_hops` 4 and `semantic` `ready`;
   - `/ready` returns 200;
   - `check_v1_zero` passes. The empty snapshot's commitment equals the one
     recomputed locally, the export holds no envelopes, and the denial probes
     carry a body that cannot be stored even if authorization were broken.
9. Takes a second verified backup. The restored copy must be `bound`, every
   append-only trigger must refuse UPDATE, DELETE and TRUNCATE, and its
   commitment must equal production's export.

Success: the command ends with `Owner release verified: <sha>` and
`v1 store bound and empty.`, and the evidence directory holds:

- `acceptance/` with `acceptance.json`, `v1-zero.json`, `v1-populated.json`,
  `v1-restore.json` and `cleanup.json` (`removed: true`);
- `production/` with:
  - `expected.json`;
  - `rollback.json`;
  - `backup-before/manifest.json` (`uninitialized`);
  - `acceptance.json` (the check list, `tick`
    `none_running_or_scheduled`, `entry` `left_to_owner`);
  - `backup-after/manifest.json` (`bound`, with the recomputed empty
    commitment).

No event exists yet; production holds only the identity rows provisioning wrote.

## 7. Author the inaugural Genesis (offline)

Authoring is offline and owner-only. The claim is the 1968 claim from the
owner's private brief, newly authored as v1. The fixture files stay unchanged,
and nothing from the 1973 claim, the influence edge or the images enters this
entry.

**Kind.** The kind is a node id from the pinned TT taxonomy
(`vendor/tt/taxonomy-v2.1.json`). `genesis` refuses anything else. List the
non-deprecated ids with their definitions:

```sh
jq -r '.nodes[] | select(has("deprecated_in") | not) | [.id, .lens, .level, .definition] | @tsv' \
  vendor/tt/taxonomy-v2.1.json
```

Choose the most specific node whose definition covers what the claim asserts.
Prefer lens A ("Recorded Public Events") for a dated public event. For a 1968
public demonstration of computing, the closest lens-A species is
`invention-and-technology`: "Breakthroughs in technology and applied science:
inventions, patents, engineering firsts, and computing milestones". It has no
subspecies. Read the definitions yourself and record why you chose the kind.
`jq '.nodes[] | select(.id == "<KIND>")' vendor/tt/taxonomy-v2.1.json` shows one
node.

**Namespace and value.** These are not taxonomy terms, and the repo defines no
convention for them. Together with the kind they form the subject key.

- The bytes are used exactly as given; nothing normalizes case or Unicode
  form.
- Each field is 1 to 1024 bytes of UTF-8 with no control or invisible
  characters and no leading or trailing whitespace; `genesis` refuses
  anything else.
- Every later revision of the subject must carry the identical key, so the key
  cannot change after Genesis.
- Pick a namespace that names who mints the value, and a stable, lowercase,
  human-readable value that identifies the subject within it.
- Record both, and the reason, before signing.

**Asserted time.** Use `1968-12-09`. The CLI accepts `YYYY`, `YYYY-MM` or
`YYYY-MM-DD`; a full date gives day precision. Confirm `asserted_time` in
`preview.json` reads 1968-12-09 at day precision.

**Evidence.** Use the SHA-256 of each private source capture. The hashes commit
to the captures without publishing them:

```sh
shasum -a 256 <CAPTURES_DIR>/* | tee <PRIVATE_DIR>/evidence-sha256.txt
EVIDENCE=()
while read -r hash _; do EVIDENCE+=(--evidence "$hash"); done < <PRIVATE_DIR>/evidence-sha256.txt
```

**Sign.** The output directory must not exist yet. The seed is read from its
file and never passed as an argument:

```sh
"$PUB" v1 genesis --key <PRIVATE_DIR>/curator.seed \
  --instance "$(cat <PRIVATE_DIR>/instance.hex)" \
  --kind <KIND> --namespace <NAMESPACE> --value <VALUE> \
  --body <BODY_FILE> --asserted-time 1968-12-09 "${EVIDENCE[@]}" \
  --out <PRIVATE_DIR>/genesis-1968
```

This writes `envelope.bin`, `body.bin` and `preview.json`. Nothing is sent.

## 8. Owner review, submit, verify, backup, posture

**Review** `preview.json` before anything leaves the workstation:

```sh
jq . <PRIVATE_DIR>/genesis-1968/preview.json
cmp <BODY_FILE> <PRIVATE_DIR>/genesis-1968/body.bin
shasum -a 256 <PRIVATE_DIR>/genesis-1968/body.bin
```

Check each of the following:

- the instance equals `instance.hex`;
- the author equals `curator.pub`;
- the body hash equals the `shasum` output, and `cmp` printed nothing;
- the kind, namespace and value are exactly what section 7 recorded;
- the asserted time is 1968-12-09 at day precision;
- the evidence list equals `evidence-sha256.txt` (sorted);
- event and subject are the same id (a Genesis is its own subject).

If any check fails, delete the directory and re-author. Nothing has been sent.

**Submit** through a localhost-only proxy (second terminal):

```sh
flyctl proxy 18080:80 <APP>.flycast -a <APP> --bind-addr 127.0.0.1
```

Every envelope the node accepts for decoding is kept for good: an admitted or
refused (422) candidate stays in `cc_v1.candidates` and changes the commitment,
and undecodable or wrong-instance input leaves a `cc_v1.rejections` row. Both
tables are append-only. So submit exactly once: confirm the store is still
empty right before, never pass `--allow-untrusted`, and do not retry or re-sign
after any non-201 answer. Stop and decide as the owner instead.

```sh
set -a; . <PRIVATE_DIR>/release.env; set +a
export CC_NODE_URL=http://127.0.0.1:18080
"$PUB" v1 node-info --node "$CC_NODE_URL" \
  && python3 ops/v1_checks.py zero --sha "$SHA" \
       > <EVIDENCE_DIR>/release-$SHA/pre-entry-zero.json \
  && echo "store empty and identity confirmed: submit may run"
```

Run the submit only if that printed the confirmation line:

```sh
"$PUB" v1 submit --node "$CC_NODE_URL" --dir <PRIVATE_DIR>/genesis-1968
```

```sh
"$PUB" v1 verify --node "$CC_NODE_URL" --subject <SUBJECT> --dir <PRIVATE_DIR>/genesis-1968
python3 ops/v1_checks.py populated --sha "$SHA" --entry <PRIVATE_DIR>/genesis-1968 \
  > <EVIDENCE_DIR>/release-$SHA/entry-check.json
```

- `node-info` must report this build's `fold_version` (`fold_matches_build`
  true) and the expected instance and `filter_version`.
- `submit` checks the instance, the fold and that your key is a curator. It then
  uploads the body, posts the envelope and requires 201. It reads back the
  subject and prose, compares the bytes, and writes `receipt.json`.
- `<SUBJECT>` is the `subject` from `preview.json`.
- `v1_checks.py populated` is read-only. It checks:
  - exactly one valid Genesis row, which is the frontier;
  - a resolved subject;
  - prose identical to `body.bin`;
  - an export whose single envelope is byte-equal to `envelope.bin`;
  - a corpus digest recomputed locally from the event id.

**Post-entry backup** verifies the restored copy against production's export,
re-served by the exact deployed image:

```sh
python3 ops/v1_checks.py export --out <EVIDENCE_DIR>/release-$SHA/post-entry-export.json
python3 ops/backup_fly.py --v1 --image registry.fly.io/<APP>@<DIGEST> \
  --export <EVIDENCE_DIR>/release-$SHA/post-entry-export.json \
  --output <EVIDENCE_DIR>/release-$SHA/post-entry-backup
```

The backup must report `bound` with `candidates` 1, every guard `proven`, and a
commitment equal to the entry check's commitment.

**Posture.** Decide whether the node stays `live` or is frozen.

- `live` accepts further write-key submissions.
- `frozen` makes writes return 503 and leaves reads unchanged.

To freeze, run:

```sh
fly secrets set CC_NODE_POSTURE=frozen -a <APP>
python3 ops/v1_checks.py populated --posture frozen --sha "$SHA" --entry <PRIVATE_DIR>/genesis-1968
```

`fly secrets set` restarts the app with the secret, which overrides the `[env]`
`live`. To return to live, run `fly secrets unset CC_NODE_POSTURE -a <APP>`.

## 9. Rollback and abort points

There is no automatic rollback in `--v1-fresh`. After the entry, the curator
key, instance and rule identity are bound and cannot be changed in place.

| Step | Success looks like | If it fails or you stop here |
| --- | --- | --- |
| 1 Key | `pubkey` reproduces the key, and the offline backup does too | Generate again; nothing external exists |
| 2 Instance | 64 lowercase hex, recorded privately | Generate again |
| 3 Database | Census returns 0 | Drop the database and role |
| 5 Tick | `verify_fly_machines.py --v1` passes | Recreate the tick from the saved configuration to resume v0 |
| 4 Secrets | Staged; v0 app not restarted | Unset the staged secrets; re-stage the v0 `DATABASE_URL` |
| 6 Acceptance | `acceptance/acceptance.json` reads `pass`; cleanup `removed: true` | Nothing in production changed. Fix the cause and build a new image |
| 6 Pre-deploy inspection or backup | `backup-before` is `uninitialized` (or bound and empty) | Nothing deployed. Investigate any foreign relation, other instance or rows before retrying |
| 6 `fly deploy` / `provision-v1` | Release command exits 0 | Fly aborts the deploy and the old machine keeps its image. Read the release command's exit status: 78 configuration (a missing or malformed secret), 73 the database holds non-v1 tables, 65 the stored identity differs from the secrets, 69 database unreachable |
| 6 Post-deploy checks or backup | `production/acceptance.json` and `backup-after` are written | `FAILED` and `recovery.json` record the error and the previous image. Either fix forward with a new release, or return to v0: re-stage the v0 `DATABASE_URL` (and any stale secret recorded in section 4), then deploy the previous image (from `rollback.json`) with a v0 `fly.toml` from git history and `--skip-release-command`. The v1 database stays as it is (bound, no entry). If the bound identity is wrong (instance or curators), it cannot be rebound: use a new fresh database (section 3) as an owner decision |
| 7 Genesis | `preview.json` reviewed and correct | Delete the output directory and re-author. Nothing has been sent |
| 8 Submit | `zero` passes just before; 201 and `receipt.json`; `verify` and `populated` pass | Any decodable envelope the node received is permanent, including a 422: it stays a candidate and changes the commitment. Do not retry or re-sign; capture `/v1/export` and decide as the owner. A body uploaded without its envelope stays too but is outside the fold. A second Genesis would be a second subject |
| 8 Backup | `bound`, candidates 1, commitment equal | Retry the backup. The ledger is unaffected |

## 10. Evidence to retain privately

Keep these in the owner's encrypted archive, never in this repository:

- The key ceremony record: the public key, where the seed and its offline
  backup are kept, and the date. Never the seed bytes in the record itself.
- `instance.hex`, the subject-key decision (kind, namespace, value, and why),
  and `evidence-sha256.txt` with the captures it hashes.
- `<EVIDENCE_DIR>/release-<sha>/` in full: acceptance, `expected.json`,
  `rollback.json`, both backups with their manifests, `production/acceptance.json`,
  `entry-check.json`, the post-entry export and backup, and `proxy.log`.
- The `genesis-1968` directory: `envelope.bin`, `body.bin`, `preview.json`
  and `receipt.json`.
- The image digest, `SHA`, the CI run URL, and the saved tick configuration.
- The output of `fly secrets list` and `fly machines list` after the release,
  and the `/health` JSON. These hold names and ids only, no values.
