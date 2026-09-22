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

## Structure

- `crates/`: core, filter, ledger, anchor, node, authoring, publisher, migrator, testkit.
- `migrations/`: immutable applied schema migrations.
- `vendor/tt/`: pinned ontology artifacts and conformance vectors; TT is upstream.
- `ops/`: validation, local acceptance, backup and owner-operated release tools.
- `docs/`: current API, media, evaluation and operating contracts.

## Develop and verify

Use the pinned Rust toolchain, Docker and PostgreSQL 18. `make db-up`, then
`make check`. CI runs format, Clippy, real-Postgres tests, Wasm compilation and
Python operator tests. Install operator Python dependencies with
`python3 -m pip install -r ops/requirements.txt`.

Corpus reads require a scoped Bearer credential and explicit `as_of`. A missing
body, missing evidence, unknown date and deliberate media absence are distinct
states. Do not replace missing evidence with an assertion.

## Start a small corpus

The checkout contains software and synthetic test fixtures, not a legacy ledger.
Use the [local permissive-model pilot](docs/LOCAL-GENERATION.md) to generate at
most three source-backed proposals outside the repository. Model output supplies
the historical content; software supplies validation and measured provenance.

## Private operation

GitHub Actions tests code and never deploys. The owner explicitly releases a
clean, CI-passing main commit using an immutable image digest. Acceptance runs in
temporary local Docker containers with its own PG18, credentials and synthetic
1.7 MiB media; it never uses production data. The same tested image is promoted.
The production app, private Postgres and scheduled tick remain on Fly.

See [owner operations](docs/CICD-FLY.md), [API](docs/USING-THE-NODE.md),
[media](docs/TYPED-MEDIA-ABSENCE.md), [evaluation](docs/evaluation/README.md) and
[contributing](CONTRIBUTING.md). No continuous generation or public service is implied.
