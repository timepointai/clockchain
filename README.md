# Clockchain

Clockchain is a signed, append-only ledger of historical claims, written in Rust
on PostgreSQL. This repo is the public core. The owner runs a private instance.

## What it does

A historical claim is only useful if you can see where it came from. Clockchain
records each claim with its source evidence, typed links to other claims, and
any media, such as an image. Every entry is signed, so you can check who wrote
it and that nobody changed it. Every read says which moment in time it asks
about, so the answer does not drift.

Signatures prove authorship and integrity. They do not prove a claim is true.
The goal is historical truth: the best-supported account of what happened,
revised as evidence improves. The ledger therefore keeps three things apart:
the cryptographic checks, the structural checks, and the historical confidence
in a claim. A missing body, missing evidence, an unknown date and a deliberate
absence of media are four different states. The ledger never fills a gap with
an assertion. See the [historical evidence standard](docs/evaluation/design-boundaries.md).

## Why it exists

Clockchain is the record layer of the Timepoint system: the place where
historical claims are kept with their evidence and a signature. It is a leaf
service. Other Timepoint services read from it; it calls none of them. Readers
use a public, read-only gateway or the typed clients in `clients/`. The shared
vocabulary comes from Timepoint Telemetry (TT), which is upstream and defines
the ontology and hash rules; the pinned copy is in `vendor/tt/`.

Some older Timepoint services were written for the retired Python Clockchain
API, which v1 does not serve. Timepoint Beta, the simulation engine, does not
call Clockchain at all. [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) records
each consumer and its migration path, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) shows where Clockchain sits.

## Status

Version 1 has run in production since 2026-10-02. The data is small: one
subject, the 1968 Engelbart demo, and two events. The node is private. A
read-only public gateway serves the corpus at
`https://clockchain.timepointai.com/public/v1`, and a static
[explorer](web/explorer/README.md) at `https://timepoint-clockchain-explorer.fly.dev`
reads it and verifies entries in your browser. Further entries and any content
generation are owner decisions, listed in [HOLD.md](HOLD.md). Release notes are
in [docs/releases/](docs/releases/v1.2.md).

Public source does not give access to the private instance or its data. No
software license is granted beyond the repository host's terms; upstream
dependency licenses still apply.

## Quick start

You need Docker and the Rust toolchain pinned in `rust-toolchain.toml`
(`rustup` installs it on first use).

```sh
make db-up        # Postgres in Docker
make check        # format, Clippy, then the Rust tests on a real database
```

Tests run against a real Postgres. There are no database mocks. To run a node
and read from it, follow [docs/LOCAL-DEV.md](docs/LOCAL-DEV.md).

## Map of the repo

- `crates/`: Rust workspace. `cc-core` (encoding, hashing, identity), `cc-filter`
  (the feasibility rule), `cc-ledger` (event log and projections), `cc-node` (the
  HTTP node), `cc-gateway` (public read-only gateway), `cc-publisher` (offline
  signing and submission), `cc-authoring`, `cc-testkit`, and two Wasm crates
  for the browser verifier. `cc-anchor` and `cc-migrator` are legacy v0.
- `migrations/`: SQL schema migrations. Never edit one that has been applied.
- `vendor/tt/`: pinned TT ontology and conformance vectors.
- `web/explorer/`: the static explorer and in-browser verifier.
- `clients/`: Python and TypeScript read clients, and recorded fixtures.
- `ops/`: Python tools for tests, backups and owner releases.
- `deploy/`: deploy templates for the gateway and explorer.
- `docs/`: documentation. [docs/README.md](docs/README.md) is the index.

Legacy v0 code (legacy node mode, `cc-anchor-tick`, `cc-migrator`, the v0
`cc-publisher` commands and the v0 database) stays for the archive and for
regression tests. It is not part of the v1 service.

## Map of the docs

- [START-HERE.md](START-HERE.md): the shortest route in.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the pieces fit together.
- [docs/TOPOLOGY.md](docs/TOPOLOGY.md): every surface of the stack.
- [docs/USING-THE-NODE.md](docs/USING-THE-NODE.md) and [docs/PUBLIC-ACCESS.md](docs/PUBLIC-ACCESS.md): the APIs.
- [docs/reference/openapi.json](docs/reference/openapi.json): every route.
- [docs/LOCAL-DEV.md](docs/LOCAL-DEV.md): running it locally.
- [docs/README.md](docs/README.md): all docs, sorted into start here, reference, operations and history.

## Working on it

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md). Report
security issues as described in [SECURITY.md](SECURITY.md). Deploys are manual
owner actions; CI never deploys.
