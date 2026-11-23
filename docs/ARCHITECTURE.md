# Architecture

This page explains how Clockchain works: what each part does, how one entry
travels from a signing key to a reader, and how a reader can check it. For the
list of every service and host, see [TOPOLOGY.md](TOPOLOGY.md). For the HTTP
routes and data model, see [USING-THE-NODE.md](USING-THE-NODE.md).

## The idea in one minute

Clockchain keeps a list of signed statements about history. A statement is a
claim, a correction, a link between two claims, or a piece of media. Nobody can
edit or delete a statement once the node has it. A later statement can say "this
replaces that one", but the old one stays.

Three things are kept apart on purpose:

- **Who said it.** Every statement is signed with an Ed25519 key. The signature
  proves authorship and that the bytes are unchanged.
- **What the ledger holds.** The node stores the signed bytes and works out, by a
  fixed rule, which statements are in force. Anyone running the same code over
  the same bytes gets the same answer.
- **Whether it is true.** The ledger never claims this. A signature or a hash
  says nothing about whether the history is right. See
  [evaluation/design-boundaries.md](evaluation/design-boundaries.md).

The current ledger is called v1. An older design (v0) is still in the code for
the archive and for tests. This page describes v1 unless it says otherwise.

## The crates

Everything is Rust under `crates/`. Postgres is the only datastore.

| Crate | What it does |
|---|---|
| `cc-core` | The rules for bytes. Defines the v1 envelope (`cc.event.v1`), the eight event kinds, how an event id is made, Ed25519 signing and checking, and the node receipt and seal formats. It does no I/O and reads no clock, so it gives the same answer natively and in WebAssembly. |
| `cc-ledger` | The v1 store in Postgres (`Store`). It is the only door for writing: `admit`, import and restore all go through it. It also folds the stored events into a read view (the projection) and computes digests. |
| `cc-filter` | The consensus rule for support: which subjects are linked by trusted edges within a hop bound. It builds the `filter_version` that names the exact rule in use. Used by the node and by the browser verifier. |
| `cc-node` | The server binary. In v1 mode it mounts 12 routes (read, write, health). It signs receipts and seals when given a node key. It also contains the legacy v0 server. |
| `cc-gateway` | A small public front for a private node. GET only, no keys from callers, per-address rate limit, cached reads. It calls the node with its own read key. |
| `cc-publisher` | The operator command line. `cc-publisher v1` makes keys, builds and signs Genesis, Delegate, Revoke, Correction, edge and attestation envelopes offline, then submits them to a node. The v0 commands act on the v0 database. |
| `cc-authoring` | Admission and classification checks for the v0 publishing path, plus helpers such as claim identity and the year-to-tick mapping (which `cc-publisher v1` uses for asserted times). The v1 node does not call it. |
| `cc-anchor` | v0 only. A Merkle tree over the v0 event log and Bitcoin timestamping through OpenTimestamps. v1 runs no anchor job. |
| `cc-migrator` | v0 only. Replays the founding exhibit into the v0 ledger. |
| `cc-wasm-verify` | The verifier. Rechecks a served snapshot using the same `cc-core` and `cc-filter` code the node runs. Built to WebAssembly for the explorer and usable natively. |
| `cc-wasm-vectors` | Recomputes the published rule test vectors in native code and in WebAssembly, so CI can show both agree. |
| `cc-testkit` | Test harness. Every test uses a real Postgres, never a mock. |

Outside `crates/`: `clients/` has typed Python and TypeScript clients for the
public API, `web/explorer` is a static browser explorer, `deploy/` holds
deployment templates, `migrations/` holds the v0 schema, and `ops/` holds
operator scripts.

## Life of one entry

```
 owner's offline machine                      private network                public
 ┌───────────────────────┐   candidates   ┌───────────────┐  read key  ┌─────────────┐
 │ cc-publisher v1       │ ─────────────▶ │ cc-node (v1)  │ ◀───────── │ cc-gateway  │ ◀── readers
 │ build + sign envelope │   bodies       │  admit, fold  │            │ GET only    │     agents, apps,
 └───────────────────────┘                │  receipts,    │            └─────────────┘     explorer
                                          │  seals        │                  │
                                          └──────┬────────┘                  ▼
                                                 ▼                    cc-wasm-verify
                                          Postgres (cc_v1)            (browser or native)
```

1. **Authoring.** The prose of a claim (the body) is plain bytes. Its SHA-256 is
   the body hash. `cc-publisher v1 genesis` builds an envelope that names the
   instance, the author key, a subject key, an optional asserted time and the
   body hash. Other kinds (`correction`, `delegate`, `revoke`, `resolve`, edges,
   attestations) are built the same way. The checks and file formats are in
   [PUBLISHER-V1.md](PUBLISHER-V1.md), [AUTHORING-V1.md](AUTHORING-V1.md) and
   [KEYS.md](KEYS.md).
2. **Signing.** The envelope is encoded in one canonical byte form. The
   author signs those bytes with Ed25519. The signed bytes are the entry. The
   event id is the SHA-256 of the bytes before the 64-byte signature. The node
   never holds the author's key; the root key stays offline with the owner.
3. **Submission.** The publisher sends the body to `PUT /v1/bodies/{sha256}` and
   the signed envelope to `POST /v1/candidates`. Both need the write key. Each is
   capped at 1 MiB.
4. **Admission.** `Store::admit` runs in one database transaction. It decodes
   the bytes strictly: the encoding must be canonical, the signature must verify
   and the instance must match this ledger. Input that fails this is not stored
   as an event; only a digest and a reason go into a rejections table. Anything
   that decodes is kept as a candidate, then the whole candidate set is
   classified. An event is `valid`, `pending` (a parent or other prerequisite is
   missing) or `invalid` (it breaks a rule). Invalid candidates are kept too,
   and they count in the corpus digest. If the node has a signing key, it writes
   a signed receipt in the same transaction.
5. **Storage.** Postgres holds the candidates, bodies, rejections, receipts and
   the bound rule identity in the `cc_v1` schema. Database triggers refuse any
   update, delete or truncate on these tables. See
   [the data model](USING-THE-NODE.md#data-model).
6. **Reading.** Reads do not trust stored derived tables. The node folds the
   stored, re-verified envelopes into a projection (event states, subject
   frontiers, revisions, authority, edges, media) and reuses a cached fold only
   when the rule identity, corpus digest and candidate bytes all match.
7. **Sealing.** `GET /v1/seal` returns a fresh signed statement of the current
   corpus digest and view commitment. The node keeps no seal. The operator keeps
   a hash-chained log of them (`ops/seal_v1.py`). This gives a time-ordered
   record the operator cannot quietly rewrite without breaking the chain. It is
   not a Bitcoin timestamp. v1 has no on-chain anchor; that was a v0 feature
   (`cc-anchor`). The options considered are in
   [design/SEALING.md](design/SEALING.md).
8. **Publishing.** The gateway republishes the node's read answers under
   `/public/v1`, minus the top-level `instance` field. Its answers are cached by
   corpus digest, so a cached answer can never outlive a change to the corpus.

## Authority in short

Each subject starts with a Genesis. The Genesis author holds that subject's
root grant. The root can delegate to a hot key for that one subject, and can
revoke grants below it. A grant covers corrections, resolutions, delegations
and revocations on that subject. It does not cover edges or attestations.
Support between subjects counts only when the subjects' Genesis authors and
the edge author are in the curator set, which is fixed when the store is bound
to its rule identity. The full rules are in [KEYS.md](KEYS.md) and
[design/STAGE-B.md](design/STAGE-B.md).

## How a reader verifies

There are three layers. Each says less than the one after it, and none says the
history is true.

1. **Signature.** Anyone can check one entry with stock Ed25519: the last 64
   bytes are the signature over the rest. Signed bytes are served by the
   private node's `/v1/export` (write key). The public gateway serves envelopes
   without signatures, so a public reader cannot check signatures without an
   export file.
2. **Recomputation.** `cc-wasm-verify` takes a served snapshot and recomputes
   the event ids, the corpus digest, the `filter_version`, and the view
   commitment from the served bytes. The explorer's "Verify in your browser"
   page runs it. It takes the rule, curator keys and digests from the same
   server as the corpus, so on its own it shows consistency, not authorship. It
   does not re-run the fold itself, so it does not recheck
   admission states or support verdicts; see
   [web/explorer/README.md](../web/explorer/README.md) for the exact list.
3. **Attestation.** A receipt says this node saw this event at a given time. A
   seal says this node served this state at a given time. Both are signed with
   the node key, which a reader must pin out of band. Neither says the event is
   true.

The typed clients in `clients/` read the public API and check the shape of each
answer, but they do not verify signatures or commitments.

## The `ops/` scripts

`ops/` runs on the owner's workstation, never in CI and never as a side effect of
a merge. In summary:

- **Release and update.** `release.py`, `deploy-fly.sh`, `deploy_digest.py`,
  `v1_update.py`, `v1_acceptance.py`: build the exact image, test it against a
  throwaway database, then promote by image digest. The owner starts each one.
- **Backup.** `backup_fly.py`, `v1_backup.py`, `schedule_backups.py`,
  `restore-verify.sh`: scheduled backups, each restored and checked
  independently before it counts.
- **Monitor.** `monitor_v1.py` checks `/health` and `/ready` every 15 minutes
  and compares the served identity with the one recomputed from the checkout.
- **Seal log.** `seal_v1.py` fetches a seal hourly and appends it to a
  hash-chained log.
- **Model workers and generation.** `generation_worker.py`, `local_generate.py`,
  `model_catalog.py`, `model_daily.py`, `model_runtime.py`, `model_evaluate.py`
  are about drafting proposals with language models under human control. They
  have no signing or approval power, and a model choice is always a human
  decision. Current standing limits are in [HOLD.md](../HOLD.md); see
  [MODEL-OPERATIONS.md](MODEL-OPERATIONS.md) and
  [ADAPTIVE-GENERATION.md](ADAPTIVE-GENERATION.md). The generation tables
  (`generation_*`) belong to the v0 schema.
- **Checks and evidence.** `v1_checks.py`, `deployed_checks.py`,
  `corpus_audit.py`, `evidence_eval.py`, `validate.py`, `tt-differential.py`.

See [ops/README.md](../ops/README.md) and [OPERATIONS.md](OPERATIONS.md).

## Where Clockchain sits among the Timepoint services

Clockchain is a leaf. At runtime the node makes no outbound calls in v1; the
gateway calls only the node; the publisher calls only the node. Other services
call Clockchain, never the other way round.

- Callers use the public read API (`/public/v1`) through the gateway, directly
  or through a typed client. They are the Timepoint MCP server, the API gateway,
  the web app, and the landing site's descriptors. Each only reads.
- The node itself stays on a private network. Only the gateway holds its read
  key.
- Timepoint Beta (the simulation engine) does not call Clockchain.
- Anything that wants a verified read uses `cc-wasm-verify` or the explorer.
- Consumers that were written for the retired Python Clockchain service
  (`/api/v1/*`) get a 401 or 404 from v1. [INTEGRATIONS.md](INTEGRATIONS.md)
  records each audit as of its pinned commits and what happens today.

[TOPOLOGY.md](TOPOLOGY.md) lists each service, its source and its caller.

## Where to read next

- Routes, fields and tables: [USING-THE-NODE.md](USING-THE-NODE.md), and the
  machine-readable [reference/openapi.json](reference/openapi.json).
- Public access rules: [PUBLIC-ACCESS.md](PUBLIC-ACCESS.md).
- Design history and frozen rules: [design/](design/) (stages A to G).
- Running it locally: [LOCAL-DEV.md](LOCAL-DEV.md).
