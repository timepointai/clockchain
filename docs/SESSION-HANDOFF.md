# Continuing an owner session

Read `AGENTS.md`, `HOLD.md`, `README.md`, and the relevant current contract first.
On the owner's workstation, continue with the owner's private `HANDOFF.md`, then
`MEMORY.md`, at the location supplied outside this checkout. These files contain
the current scope, dated observations, cleanup inventory, evidence locations and
exact operator handoff. They stay outside this public repository. If they are
unavailable, establish the current state with the owner; archived planning
documents are not a substitute.
A cloud session never has them: its scope is the owner's prompt plus the current
stage contract, and it never deploys, contacts production or handles real keys.

## Production state

Clockchain v1 has been in production since 2026-10-02: `cc-node` in v1 mode on a
fresh v1 database, private ingress only, one subject and two events (the
inaugural Engelbart 1968 Genesis and the owner's 2026-10-05 Delegate to a hot
key), and no tick.
Since 2026-10-09 the node runs the v1.2 build, released through the verified
update lane in [OPERATIONS.md](OPERATIONS.md); daily verified backups and a
15-minute identity monitor run from the owner's workstation, and the read-only
public gateway ([PUBLIC-ACCESS.md](PUBLIC-ACCESS.md)) serves the corpus at
`https://timepoint-clockchain-gateway.fly.dev/public/v1` while the node stays private.
`fold_version` 1 is frozen. The
[v1.0](releases/v1.0.md), [v1.1](releases/v1.1.md) and [v1.2](releases/v1.2.md) release notes and the
[launch evidence](LAUNCH-EVIDENCE.md) are the public record; the release evidence
itself is private. Recheck any dated observation against the running node, through
the owner's private proxy, before acting on it.

The v0 paths are legacy: legacy node mode, `cc-anchor-tick`, `cc-migrator`, the
v0 `cc-publisher` commands and the v0 database, which is kept untouched as an
archive. Their code and tests stay. Do not point a v0 tool at the v1 database, and
do not restore a v0 tick or v0 release mode onto the v1 app.

## Cleanup

Before local cleanup, identify each process and database from its saved service
record and current runtime identity. PIDs may be reused. A PostgreSQL data
directory may live under an old experiment directory; do not move or delete it
while the database is running. Preserve source captures and qualification evidence
needed by the selected model route before retiring a test. Do not reset its budget
or erase charge reservations as part of cleanup. Keep the software's regression
tests; a request to remove generated test content does not retire those checks.

## Before an owner release or entry

Recheck the deployed image digest and build, the bound rule identity (instance,
curators, `max_hops`, fold version) against `/health`, `/ready`, the posture, and
the latest verified backup. The v1 runbook is [FIRST-ENTRY.md](FIRST-ENTRY.md).
Distinguish the deployed executable revision from later documentation commits.
Any decodable envelope the node receives is permanent, including one answered
422: never retry or re-sign a submission to make a check pass.

For the legacy v0 path only, the zero-event release used `--zero-events`
verification; never create a genesis just to satisfy a genesis-only smoke check.

## Generation and content

Generation and model calls are held by `HOLD.md`. When the owner lifts that hold,
humans choose model changes. Daily discovery is a review inbox, not an activation
or publication mechanism. Source-bound inference produces a private candidate;
structural admission and model agreement do not establish historical truth.
Inspect all claims, date rationales and causal mechanisms against their sources.

Follow the owner's fresh scope. Infrastructure permission does not authorize
human-only staging, approval recording, signing or publication. Existing exact
approvals remain scoped to their artifacts and conditions; an archived canary is
not automatically the next kickoff. Prepare evidence and concrete commands for
the designated human operator without silently executing that boundary.

## Closeout

Update the private handoff and memory at closeout, preserving superseded records
as historical evidence. Record checks actually run, known limits, remaining work,
and which processes or artifacts remain. Do not copy credentials, production data
or private approval records into repository documentation or commits.
