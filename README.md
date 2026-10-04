# Clockchain

A signed, append-only temporal evidence ledger in Rust and PostgreSQL. It records
claims, source evidence, typed relationships and media provenance, with explicit
query coordinates and cryptographic verification. Signatures prove integrity and
authorship, not historical truth; feasibility is relative to recorded evidence.

This repository contains the core implementation and reusable operator tooling.
Production data, credentials, backups, approvals and private research are not part
of the public repository. Public source does not provide access to the owner's
private instance. No software license is granted beyond applicable repository-host
terms; existing upstream dependency licenses remain in force.

## Status

Clockchain v1 has been in production since 2026-10-02. The production node runs
`cc-node` in v1 mode (`CC_NODE_LEDGER=v1`) on a fresh v1 database, behind
private ingress only. It holds one entry: the inaugural Engelbart 1968 Genesis.
`fold_version` 1 and its governed defaults are frozen; a change to admission or
projection needs a new fold version. See the [v1.0 release notes](docs/releases/v1.0.md),
the [launch evidence](docs/LAUNCH-EVIDENCE.md) for the
[issue #6](https://github.com/timepointai/clockchain/issues/6) gates, and the
standing owner constraints in [HOLD.md](HOLD.md). Public access, further entries
and generation remain owner decisions.

The v1 surfaces are:

- the node in v1 mode: [using the node](docs/USING-THE-NODE.md#v1-mode);
- signing and submission: [publisher v1](docs/PUBLISHER-V1.md);
- the owner release runbook: [first entry](docs/FIRST-ENTRY.md) and
  [owner operations](docs/CICD-FLY.md#v1-release-onto-a-fresh-database);
- the rules: [multi-signer design](docs/design/MULTI-SIGNER.md) and stages
  [(a)](docs/design/STAGE-A.md) to [(f)](docs/design/STAGE-F.md).

### Legacy v0 paths

These remain in the code for the archive and for regression tests. They are not
part of the v1 service. Nothing here removes them.

- **Legacy node mode.** `cc-node` without `CC_NODE_LEDGER=v1`, its v0 routes
  (`/health/deep`, `/v1/entities/…`, `/v1/feasibility`, `/v1/events` and the
  rest) and `cc-node migrate`, which v1 mode refuses.
- **`cc-anchor-tick`.** The hourly v0 seal and anchor job. v1 runs no tick.
- **`cc-migrator`.** The v0 exhibit replay writer.
- **v0 publisher commands.** Every `cc-publisher` command outside `cc-publisher v1`
  (`validate`, `brief-stage`, `candidate-stage`, `approve-*`, `publish`, `pause`,
  `resume`, `status` and the rest). They write v0 events straight to a database.
- **The v0 database.** It is kept untouched as an archive. No v1 tool reads or
  writes it.

## Structure

- `crates/`: core, filter, ledger, anchor, node, authoring, publisher, migrator,
  testkit and Wasm vectors. `cc-migrator` and the `cc-anchor-tick` binary are
  legacy v0 paths (above).
- `migrations/`: immutable applied schema migrations.
- `vendor/tt/`: pinned ontology artifacts and conformance vectors; TT is upstream.
- `ops/`: validation, local acceptance, backup and owner-operated release tools.
- `docs/`: current API, media, evaluation and operating contracts.

## Develop and verify

Use the pinned Rust toolchain, Docker and PostgreSQL 18. `make db-up`, then
`make check`. CI runs format, Clippy, real-Postgres tests, Wasm compilation and
Python operator tests. Install operator Python dependencies with
`python3 -m pip install -r ops/requirements.txt`.

Corpus reads require a scoped Bearer credential. A missing body, missing
evidence, unknown date and deliberate media absence are distinct states. Do not
replace missing evidence with an assertion.

## Generation tooling (held, v0-era)

The checkout contains software and synthetic test fixtures, not a ledger.
Generation and model calls are held by [HOLD.md](HOLD.md). The tooling below
predates v1: it validates proposals with the v0 publisher and does not produce
v1 envelopes.

The [local permissive-model pilot](docs/LOCAL-GENERATION.md) generates at most
three source-backed proposals outside the repository. Model output supplies the
historical content; software supplies validation and measured provenance. The
[model operating workflow](docs/MODEL-OPERATIONS.md) provides daily discovery,
human model selection, bounded hosted evaluation and a configurable proposal-only
runtime. [Adaptive generation](docs/ADAPTIVE-GENERATION.md) describes the longer-term
batch and local-inference architecture. Deployment does not enable generation.

## Private operation

GitHub Actions tests code and never deploys. The owner explicitly releases a
clean, CI-passing main commit using an immutable image digest. Acceptance runs in
temporary local Docker containers with its own PG18, credentials and synthetic
data; it never uses production data. The same tested image is promoted. The
production app and its private Postgres run on Fly with no public ingress. The v1
release refuses any running or scheduled tick machine. Deploys, public exposure,
secrets, key ceremonies and new entries are owner actions run from the owner's
workstation.

See [owner operations](docs/CICD-FLY.md), [API](docs/USING-THE-NODE.md),
[media](docs/TYPED-MEDIA-ABSENCE.md), [evaluation](docs/evaluation/README.md) and
[contributing](CONTRIBUTING.md). No continuous generation or public service is implied.
