# Start here

Read [README](README.md), [contributing](CONTRIBUTING.md), and the document for the
interface you are changing. Current instructions are in [AGENTS.md](AGENTS.md).
The public repository has no active product roadmap; work starts from an owner's
explicit scope. Historical planning and production evidence remain private.

For a fresh agent continuing an owner session, follow
[session continuity](docs/SESSION-HANDOFF.md). Start with preparation of the first
live brief and source packet. Obtain the private handoff location from the owner;
read its `HANDOFF.md` and `MEMORY.md` before treating an old plan, approval bundle
or experimental result as current work. Exact operator paths stay private.

The event log is the ledger; Postgres maintains projections. TT owns ontology and
hash semantics. Changes must preserve identity, exact body bytes, source provenance
and signed evidence. Content approval is separate from infrastructure permission.

GitHub CI never deploys. [Private owner operations](docs/CICD-FLY.md) describes
release checks and recovery. Production uses app + database + hourly tick; tests
use disposable local containers. Corpus access is private and authenticated.
