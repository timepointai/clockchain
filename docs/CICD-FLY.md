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
allocation. Keep exactly one app writer and a stopped-between-runs hourly tick.

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
