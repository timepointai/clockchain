# Start here

Read [README](README.md), [contributing](CONTRIBUTING.md), and the document for the
interface you are changing. Current instructions are in [AGENTS.md](AGENTS.md);
standing owner constraints are in [HOLD.md](HOLD.md). Work starts from an owner's
explicit scope. Historical planning and production evidence remain private.

## Current state

Clockchain v1 has been in production since 2026-10-02, on private ingress, with
one subject and two events: the inaugural Engelbart 1968 Genesis and the owner's
2026-10-05 Delegate to a hot key. `fold_version` 1 is frozen. The
[v1.0 release notes](docs/releases/v1.0.md) list what shipped and the known
follow-ups. The [launch evidence](docs/LAUNCH-EVIDENCE.md) maps each
[issue #6](https://github.com/timepointai/clockchain/issues/6) gate to merged PRs
and named tests; disposing of #6 is the owner's decision. The post-launch program
is [Stage (g)](docs/design/STAGE-G.md).

For v1 work, read in this order:

1. [MULTI-SIGNER.md](docs/design/MULTI-SIGNER.md), then stages
   [(a)](docs/design/STAGE-A.md) to [(f)](docs/design/STAGE-F.md);
2. [using the node](docs/USING-THE-NODE.md#v1-mode) and
   [publisher v1](docs/PUBLISHER-V1.md);
3. the owner [first-entry runbook](docs/FIRST-ENTRY.md) and
   [owner operations](docs/CICD-FLY.md).

The legacy v0 paths (legacy node mode, `cc-anchor-tick`, `cc-migrator`, the v0
`cc-publisher` commands and the v0 database archive) stay in the code for the
archive and regression tests, but they are not part of the v1 service. The
[README](README.md#legacy-v0-paths) lists them.

## Continuity

For a fresh agent continuing an owner session, follow
[session continuity](docs/SESSION-HANDOFF.md). On the owner's workstation, the
current task and exact operator handoff are in `~/clockchain-private/HANDOFF.md`;
durable lessons are in `~/clockchain-private/MEMORY.md`. Read these before treating
an old plan, approval bundle or experimental result as current work. Cloud
sessions do not have these files; their scope comes from the owner's prompt and
the current stage contract.

The event log is the ledger; Postgres maintains projections. TT owns ontology and
hash semantics. Changes must preserve identity, exact body bytes, source provenance
and signed evidence. Content approval is separate from infrastructure permission.

GitHub CI never deploys. [Private owner operations](docs/CICD-FLY.md) describes
release checks and recovery. Production runs the v1 app and its private database,
with no tick; tests use disposable local containers. Corpus access is private and
authenticated.
