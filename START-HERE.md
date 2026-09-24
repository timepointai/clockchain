# Start here

Read [README](README.md), [contributing](CONTRIBUTING.md), and the document for the
interface you are changing. Current instructions are in [AGENTS.md](AGENTS.md).
The public repository has no active product roadmap; work starts from an owner's
explicit scope. Historical planning and production evidence remain private.

For a fresh agent continuing an owner session, follow
[session continuity](docs/SESSION-HANDOFF.md). On the owner's workstation, the
current task and exact operator handoff are in `~/clockchain-private/HANDOFF.md`;
durable lessons are in `~/clockchain-private/MEMORY.md`. Read these before treating
an old plan, approval bundle or experimental result as current work.

The event log is the ledger; Postgres maintains projections. TT owns ontology and
hash semantics. Changes must preserve identity, exact body bytes, source provenance
and signed evidence. Content approval is separate from infrastructure permission.

GitHub CI never deploys. [Private owner operations](docs/CICD-FLY.md) describes
release checks and recovery. Production uses app + database + hourly tick; tests
use disposable local containers. Corpus access is private and authenticated.
