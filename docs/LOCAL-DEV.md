# Local development

## Do we need Docker for Postgres? Yes — and here's why

This system's core discipline is **no mocks**: every test runs against a real Postgres, because
the ledger's guarantees (append-only enforcement, the projector's byte-identical rebuild,
`bytea` coordinate ordering) are *Postgres behaviors*, not application logic a fake could stand
in for. So local dev needs a real Postgres, and it should be a supported version. Compose and CI currently use Postgres 17; the Fly production
database is Postgres 18. Test production-specific behavior against that major too. Docker is the least
friction way to get exactly that, isolated from whatever else is on your machine.

You are not *required* to use Docker — anything that puts a Postgres 17 at `DATABASE_URL` works
(a native install, a managed dev instance). Docker Compose is the supported default, and CI uses
a Postgres service container so the environments match.

## Prerequisites

- Rust — pinned in [`rust-toolchain.toml`](../rust-toolchain.toml); `rustup` installs the right
  version automatically.
- Docker (with Compose).
- `make`.

## The loop

```sh
cp .env.example .env      # first time only
make db-up                # start Postgres 17 in Docker (docker-compose.yml)
export CC_NODE_POSTURE=frozen
export CC_NODE_API_KEY="$(openssl rand -hex 32)"
make migrate              # apply migrations/ to the local DB
make run                  # run cc-node on :8080
# GET http://localhost:8080/health       -> {"status":"ok"}      (I/O-free liveness)
# GET http://localhost:8080/health/deep  -> {"status":"ok","db":"ok", ...}  (pings Postgres)

make test                 # the real-DB test rig (cc-testkit)
make check                # fmt + clippy(-D warnings) + Rust tests
make db-down              # stop and remove the local DB when you're done
```

## Connection settings (local defaults)

| Setting | Value |
|---|---|
| host / port | `localhost:5432` |
| database / user / password | `clockchain` / `clockchain` / `clockchain` (local only) |
| `DATABASE_URL` | `postgres://clockchain:clockchain@localhost:5432/clockchain` |
| `PORT` (cc-node) | `8080` |

Compose reads `.env` for its port. The Makefile supplies database defaults; export
`DATABASE_URL` (and `TEST_DATABASE_URL`) explicitly when overriding them. `cc-node`
does not load `.env` automatically. Nothing here is a
production secret — production secrets are managed through Fly (see
[`CICD-FLY.md`](CICD-FLY.md)).

## How the test rig uses the database (no mocks)

`cc-testkit` provisions an **ephemeral database per test run** against the local (or CI)
Postgres, applies the migrations, and hands the test a live pool. Tests exercise the real write
path, the real projector, and the real append-only guard. Property tests that must be real to
mean anything:

- `canon` determinism and cross-writer `H0` equality
- CRDT convergence — shuffle event arrival order, project, get an identical view
- filter monotonicity under accretion
- **rebuild determinism** — project from scratch == incremental projection, byte for byte

## Migrations

SQL migrations live in [`../migrations/`](../migrations/) and are embedded via
`sqlx::migrate!` so `cc-node` (and the test rig) apply them deterministically — no separate
tool required. `make migrate` applies them to your local `DATABASE_URL`. The first migration
creates the `events` log (append-only, enforced by `REVOKE` + a trigger) and its
materialized-view tables.

## A note on sqlx query checking

The skeleton uses runtime `sqlx::query(...)` so `cargo build` and the Docker image build need no
live database. As the schema stabilizes, the plan calls for moving to compile-time-checked
`sqlx::query!` with a committed `.sqlx` offline cache (`cargo sqlx prepare`); do that per
milestone, not before the tables settle.

## Full deployment gate

`ops/ci-local.sh` runs format, Clippy, Wasm compilation, Rust tests and the Python
evaluation tests. It removes test databases and their shared role: use an isolated
local test cluster, never production or a shared development database. Supply
`PGHOST`, `PGPORT`, `PGUSER`, and `TEST_DATABASE_URL` for that same cluster.
`make db-down` removes the Compose volume, including its local data.
