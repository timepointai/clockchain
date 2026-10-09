# Clockchain

A signed, append-only temporal evidence ledger in Rust and PostgreSQL. It records
claims, source evidence, typed relationships and media provenance, with explicit
query coordinates and cryptographic verification. The project's goal is historical truth:
the best-supported account of what happened, refined as evidence improves.
Historical judgments weigh sources, corroboration, alternatives and uncertainty;
signatures make the authorship and integrity of those judgments verifiable, not
their truth.
Feasibility is relative to recorded evidence. See the
[historical evidence standard](docs/evaluation/design-boundaries.md).

This repository contains the core implementation and reusable operator tooling.
Production data, credentials, backups, approvals and private research are not part
of the public repository. Public source does not provide access to the owner's
private instance. No software license is granted beyond applicable repository-host
terms; existing upstream dependency licenses remain in force.

## Status

Clockchain v1 has been in production since 2026-10-02. The production node runs
`cc-node` in v1 mode (`CC_NODE_LEDGER=v1`) on a fresh v1 database, behind
private ingress only. It holds one subject and two events: the inaugural
Engelbart 1968 Genesis and the owner's Delegate of a per-subject hot signing key
(2026-10-05). The
Stage (g) post-launch program (update releases, scheduled verified backups,
monitoring, keys, node receipts, read-only gateway and explorer) is merged and
the production node runs its build; see [OPERATIONS.md](docs/OPERATIONS.md).
Since 2026-10-08 the read-only public gateway ([public access](docs/PUBLIC-ACCESS.md))
serves the corpus at `https://timepoint-clockchain-gateway.fly.dev/public/v1`
(IPv6 and, since 2026-10-09, shared IPv4); the node itself stays private.
`fold_version` 1 and its governed defaults are frozen; a change to admission or
projection needs a new fold version. See the [v1.0](docs/releases/v1.0.md),
[v1.1](docs/releases/v1.1.md) and [v1.2](docs/releases/v1.2.md) release notes, the
[launch evidence](docs/LAUNCH-EVIDENCE.md) for the
[issue #6](https://github.com/timepointai/clockchain/issues/6) gates (closed
2026-10-08), and the standing owner constraints in [HOLD.md](HOLD.md). Further
entries and generation remain owner decisions.

Report security issues as described in [SECURITY.md](SECURITY.md).

The v1 surfaces are:

- the node in v1 mode: [using the node](docs/USING-THE-NODE.md#v1-mode);
- public reads: the [read-only gateway](docs/PUBLIC-ACCESS.md) (`/public/v1`),
  plus a static [explorer and verifier](web/explorer/README.md) that reads the
  gateway when the owner builds and hosts it (not itself deployed);
- signing and submission: [publisher v1](docs/PUBLISHER-V1.md) and the
  [key runbook](docs/KEYS.md) (cold root, hot delegate);
- operations: routine [update releases, backups, monitoring and the seal
  log](docs/OPERATIONS.md); the completed one-time [first entry](docs/FIRST-ENTRY.md)
  runbook and [Fly deployment](docs/CICD-FLY.md);
- the rules: [multi-signer design](docs/design/MULTI-SIGNER.md), stages
  [(a)](docs/design/STAGE-A.md) to [(f)](docs/design/STAGE-F.md) and the
  [post-launch program (g)](docs/design/STAGE-G.md); sealing options in
  [SEALING.md](docs/design/SEALING.md).

### Legacy v0 paths

These remain in the code for the archive and for regression tests. They are not
part of the v1 service. Nothing here removes them.

- **Legacy node mode.** `cc-node` without `CC_NODE_LEDGER=v1`, its v0 routes
  (`/health/deep`, `/v1/entities/…`, `/v1/feasibility`, `/v1/events` and the
  rest) and `cc-node migrate`, which v1 mode refuses.
- **`cc-anchor-tick`.** The hourly v0 seal and anchor job. v1 runs no tick.
- **`cc-migrator`.** The v0 exhibit replay writer.
- **v0 publisher commands.** Every `cc-publisher` command outside
  `cc-publisher v1` (`validate`, `brief-stage`, `candidate-stage`, `approve-*`,
  `publish`, `pause`, `resume`, `status` and the rest). Apart from the offline
  `validate`, they act on the v0 database; `publish` writes v0 events.
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
production node and its private Postgres run on Fly with no public ingress; the
separate read-only gateway app is the only public surface, and it holds nothing
but a read key. The v1 release refuses any running or scheduled tick machine.
Deploys, public exposure, secrets, key ceremonies and new entries are owner
actions run from the owner's workstation under dated decisions in
[HOLD.md](HOLD.md).

See [owner operations](docs/CICD-FLY.md), [API](docs/USING-THE-NODE.md),
[media](docs/TYPED-MEDIA-ABSENCE.md), [evaluation](docs/evaluation/README.md) and
[contributing](CONTRIBUTING.md). No continuous generation is implied; the public
read service is the gateway described above, nothing more.
