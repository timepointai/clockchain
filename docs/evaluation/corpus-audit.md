# Corpus audit and source crawl

The auditor measures ledger integrity, graph consistency and evidence coverage
separately. A signed event, an acyclic graph, a reachable URL, and a successful
replay are not proof of historical truth or causation. Unreviewed claims stay
`not_assessed`. Nothing here stages, approves, signs or publishes corpus content.

## Remote counts without exporting corpus rows

Supply the database app, database and username through the owner environment.
The password stays in the database machine's existing environment.

```sh
python3 ops/corpus_audit.py aggregate \
  --fly-db "$CC_BACKUP_DB_APP" --database "$CC_BACKUP_DATABASE" \
  --user "$CC_BACKUP_USER" --output /absolute/private/audit-aggregate.json
```

This executes a repeatable-read, read-only transaction with a statement timeout.
It reports table counts, missing references/bodies, duplicate identity keys,
multiple readings, causal/influence cycles and chronology, and source coverage.
`contested_edges` in the existing health response means edges whose endpoints
resolve (the protection-ratio denominator), not a count of challenged claims.
Use edge status and evidence records to assess challenges and support.

## Full private audit

A full audit exports signed events, core projections, bodies, edge evidence and
commitment metadata. Obtain authorization for that private-data export when
required by the operator's environment. The column whitelist excludes credentials,
approvals, staged candidates, publication receipts and other operational records.
All output stays outside the checkout, mode 600; existing output is never replaced.

```sh
python3 ops/corpus_audit.py capture \
  --fly-db "$CC_BACKUP_DB_APP" --database "$CC_BACKUP_DATABASE" \
  --user "$CC_BACKUP_USER" --output /absolute/private/snapshot.json
python3 ops/corpus_audit.py audit /absolute/private/snapshot.json \
  --output /absolute/private/audit-run
```

The offline pass checks SHA-256 event preimages, Ed25519 signatures, body hashes,
references, counters, year/coordinate alignment, graph cycles and backwards edges,
edge-evidence hashes/signatures, commitment sequence and recorded Merkle roots.
It emits an individual claim/edge review queue. Multiple readings and reverse
chronology are review triggers, not instructions to delete or rewrite history.
Malformed snapshots fail rather than producing an incomplete PASS. Signatures
use stock cryptography; canonical/strict signature verification requires replay.

To compare the served API, open the localhost-only Fly proxy documented in
[CICD-FLY.md](../CICD-FLY.md), set `CC_NODE_READ_KEY`, and add:

```sh
--node http://127.0.0.1:18080 --as-of <explicit-whole-tick-coordinate>
```

Every captured entity is requested; identity, birth event and name are compared.
Failures and changed corpus digests are reported. Choose a coordinate covering
all captured births; older slices can legitimately lack entities. Requests and the
DB capture are not atomic, even if observed digests remain stable. HTTP is allowed
only for a literal loopback proxy; authenticated redirects are refused. This is
not a complete API projection equivalence check.

To retrieve the cited sources, add repeatable `--source-host exact.hostname`
options. Fetching is bounded by `--max-sources` (default 30), size and timeout.
Only HTTPS on allowed public hosts is fetched; DNS addresses are checked and
pinned, and each redirect is checked again. No API key accompanies source requests.
Raw captures retain time and SHA-256 outside the repo. HTTP success is retrieval
only, never an entailment verdict. Missing URLs do not prove no offline evidence
exists. No sources are invented to fill a gap.

## Canonical replay

Use a fresh local Postgres test cluster, not a Fly proxy. The replay tool requires
a literal loopback host and the `postgres` admin database, creates a uniquely
named ephemeral database, imports through the normal signed-event gate and then
removes that ephemeral database. It never rebuilds the source database.

```sh
TEST_DATABASE_URL=postgres://localuser@127.0.0.1:5432/postgres \
  cargo run -p cc-ledger --example audit_replay -- \
  /absolute/private/snapshot.json /absolute/private/replay.json
```

Replay checks canonical bytes against envelope columns, strict signatures, and
identity. It compares all fields of entities, moments, edges, vocabulary,
attestations, taxonomy tags and maintained counters with the capture, then checks
that a second local rebuild agrees. Drift produces exit 1 and per-table counts.
Bodies, evidence attachments, media, root/anchor history and operational state
are not reconstructed by event replay; their independent retention still matters.
Run the example's regression tests explicitly:

```sh
cargo test -p cc-ledger --example audit_replay
python3 -m unittest discover -s ops -p test_corpus_audit.py
```

## Ground-truth review

For each historical assertion, record the exact supporting source, passage or
locator, captured bytes/hash, date precision and a reviewer verdict. For each
causal edge, separately record evidence for the mechanism and direction; merely
showing that both endpoint events occurred is insufficient. Keep correlation,
influence, inferred causation and documented causation distinct. Review cycles as
possible feedback or modeling errors instead of assuming every cycle is false.

Use a preregistered representative sample for accuracy estimates. A convenient
spot check is illustrative and cannot estimate corpus-wide accuracy. Preserve
existing event identities and record corrections through the governed process;
an audit failure does not authorize destructive cleanup or a production reset.
