# Running locally

How to build, test and run Clockchain on your own machine. Every command here
is marked with whether it was run when this page was written (23 November
2026, macOS). "Not run" means it comes from the Makefile or CI config and has
not been exercised for this page.

## The short story

Clockchain keeps its guarantees in PostgreSQL: the log is append-only, the
projections rebuild byte for byte, and coordinates sort as `bytea`. A fake
database cannot stand in for that, so every test runs against a real Postgres.
There are no mocks. You need a Postgres, and Docker Compose is the supported way
to get one.

## Prerequisites

- **Rust.** The toolchain is pinned in [`rust-toolchain.toml`](../rust-toolchain.toml)
  (channel 1.97.1, with `rustfmt` and `clippy`). `rustup` installs it on first
  use. Make sure `rustup`'s `cargo` comes first on your `PATH`. On the test
  machine a Homebrew `cargo` 1.86 came first and ignored the pin; with
  `PATH=$HOME/.cargo/bin:$PATH` the pinned 1.97.1 was used. Check with
  `cargo --version`.
- **Wasm target** (for the verifier and the explorer): `rustup target add wasm32-unknown-unknown`.
- **Docker with Compose**, for Postgres, or any Postgres you control. Use one
  you can throw away: the tests create and drop their own databases.
- **Python 3** with the packages in [`ops/requirements.txt`](../ops/requirements.txt), for the operator tests.
- **Node 22 or newer**, for the explorer tests and the TypeScript client.
- `make`.

## Build

```sh
cargo build
```

Ran OK. A cold build took about 5 minutes 20 seconds. Later builds are incremental.

## Check formatting and lints

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

`fmt` ran OK (4 seconds). Clippy ran OK with no warnings (about 9 minutes on a busy machine, cold).

## Start the database

```sh
make db-up          # docker compose up -d db   (not run: Docker was not running)
```

This starts Postgres 17 from [`docker-compose.yml`](../docker-compose.yml) with
database, user and password all `clockchain`, on port 5432. To use another host
port, set `DB_PORT` for Compose. The Makefile defaults `DATABASE_URL` and
`TEST_DATABASE_URL` to `postgres://clockchain:clockchain@localhost:5432/clockchain`.
Override them on the command line if you use another Postgres.

You may use any Postgres you control instead. Production runs Postgres 18 and
CI uses 18, so test anything version-specific on 18.

`make db-down` stops the database and deletes its volume.

## Test

```sh
make test           # cargo test
make check          # fmt check, Clippy, cargo test
```

The test kit, `cc-testkit`, creates a throwaway database per test run, applies
the migrations, and hands the test a live connection. It reads `TEST_DATABASE_URL`
and falls back to `DATABASE_URL`. Give it a URL with a user and a password, as
the Compose default does. One test (`boot_failures_print_no_credentials`)
rewrites the password in that URL and fails if the URL has none.

When this page was written, `cargo test --all` was run against a throwaway
Postgres 18 cluster (not Docker): 364 tests passed and one failed, the test
above, because that cluster's URL had no password. Cargo stops at the first
failing test binary, so the crates after `cc-node` were not run in that pass;
add `--no-fail-fast` to run them all. The tests are slow: the ordering property
tests take minutes each, and the run took over an hour on a busy machine.
`make test` and `make check` themselves were not run.

`make check` is the quick Rust gate. It is not the whole CI gate. CI also
builds the Wasm crates, runs the explorer and client tests and runs the Python
tests. See [CONTRIBUTING.md](../CONTRIBUTING.md#tests-and-checks) for the full
list.

Python operator tests. Some of them need `psql` on your `PATH` and a test
database in `TEST_DATABASE_URL`:

```sh
python3 -m pip install -r ops/requirements.txt
python3 -m unittest discover -s ops -p 'test_*.py'
```

Run with Python 3.12 in a fresh virtual environment: 362 tests, 360 passed. The
two failures look environmental. One could not find `psql`, because Homebrew's
`postgresql@18` is not linked onto `PATH`. The other (`test_v1_e2e`) failed its
"wrong deployed revision" check, which compares the node's build revision with
the git commit; the checkout had uncommitted changes at the time. That cause is
likely but was not confirmed.

The Python client tests ran OK (68 tests):

```sh
python3 -m unittest discover -s clients/python/tests -t clients/python
```

Other test commands from CI (not run for this page):

```sh
cargo build -p cc-wasm-verify --target wasm32-unknown-unknown --release
node --test web/explorer/test/*.test.mjs
cd clients/typescript && npm ci && npm run typecheck && npm test
```

### The whole gate in one script

`ops/ci-local.sh` runs format, Clippy, the Wasm core build, the Rust tests and
the Python operator tests. Read this before you run it: it **drops every
database whose name starts with `cc_test_` and the role `cc_app` on the cluster
it connects to.** Run it only against an isolated local cluster. Supply
`PGHOST`, `PGPORT`, `PGUSER` and `TEST_DATABASE_URL` for that cluster. Not run.

## Run a node

The node needs a database, a posture and a write key. This starts it in legacy
mode, the simplest local setup. Not run (needs the database).

```sh
export DATABASE_URL=postgres://clockchain:clockchain@localhost:5432/clockchain
export CC_NODE_POSTURE=frozen                  # required: live or frozen
export CC_NODE_API_KEY="$(openssl rand -hex 32)"   # required: the write key
make migrate                                   # apply migrations/ (legacy mode only)
make run                                       # serves on PORT, default 8080
curl http://localhost:8080/health
```

`cc-node` does not read `.env`. Export the variables yourself. Nothing here is a
production secret.

To run in v1 mode, set `CC_NODE_LEDGER=v1`, `CC_V1_INSTANCE` (64 lowercase hex
characters) and `CC_V1_CURATORS` (comma-separated 64-character hex public keys).
In v1 mode `cc-node migrate` is refused; use `cc-node provision-v1` to bind a
fresh database. The variables are in [USING-THE-NODE.md](USING-THE-NODE.md#v1-mode).
Optional keys: `CC_NODE_READ_KEY` (read-only access), `CC_V1_MAX_HOPS` (default
4), `CC_V1_READ_CONCURRENCY` (default 8), `CC_MEDIA_DIR` (without it, media
routes report "not configured").

To front a local v1 node with the public gateway, run `cargo run -p cc-gateway`
with `CC_GATEWAY_NODE_URL` (an `http` or `https` origin, no path),
`CC_GATEWAY_READ_KEY` and a `PORT` different from the node's. Not run.

Do not run the owner tools in `ops/` that deploy or touch Fly. They need keys you
do not have and act on the private instance.

## Run the explorer

The explorer in [`web/explorer/`](../web/explorer/README.md) is static files and a
Wasm verifier. There is no npm step.

```sh
rustup target add wasm32-unknown-unknown
cargo fetch --locked
web/explorer/build.sh --fixture        # builds web/explorer/dist with a synthetic fixture
python3 -m http.server -d web/explorer/dist 8000
# open http://localhost:8000/?fixture=synthetic
```

Not run. `build.sh` builds offline, so run `cargo fetch --locked` first. It also
calls `sha256sum`, which macOS may lack. Any static server works if it sends
`application/wasm` for `.wasm` files.

`build.sh --api-base` accepts only a path starting with `/` or an `https://` URL.
It rejects `http://localhost`. To point the explorer at a local gateway, put a
reverse proxy in front that serves `/public/v1` from the same origin, or edit
`dist/index.html` by hand (the `cc-api-base` meta tag and the Content Security
Policy `connect-src`).

## Migrations

SQL migrations live in [`migrations/`](../migrations/) and are embedded with
`sqlx::migrate!`. `cc-node` and the test kit apply them; no separate tool is
needed. Never change a migration that has been applied.

## Common failures

- **`cargo` is older than 1.97.1 or ignores the pin.** Another `cargo` is first on
  your `PATH`. Put `$HOME/.cargo/bin` first.
- **Tests cannot connect.** The database is not up, or `TEST_DATABASE_URL` or
  `DATABASE_URL` points elsewhere. Check `docker compose ps`.
- **Port 5432 already in use.** Another Postgres is running. Stop it, or set `DB_PORT`
  and update `DATABASE_URL`.
- **`cc-node` exits at start.** `DATABASE_URL`, `CC_NODE_POSTURE` and `CC_NODE_API_KEY`
  are all required. Posture must be `live` or `frozen`. Keys must differ from each other.
- **`cc-node migrate` is refused.** That command is for legacy mode. In v1 mode use
  `cc-node provision-v1`.
- **Wasm build fails with "target not installed".** Run `rustup target add wasm32-unknown-unknown`.
- **`python3 -m venv` fails at `ensurepip`.** Seen with Homebrew Python 3.14. Use another
  Python, or install the requirements into a fresh environment some other way.
- **Docker image build.** The image uses `--locked`, so keep `Cargo.lock` in step with
  `Cargo.toml`.

## Known gaps in this page

- The Docker Compose database, `make test`, `make check`, running a node, the
  gateway, the Wasm builds and the explorer were not run. Docker was not running;
  the Rust and Python tests above ran against a throwaway Postgres 18 cluster instead.
- `.env.example` was not read, so its contents are not described here. Compose
  reads a `.env` file only for `DB_PORT`.
