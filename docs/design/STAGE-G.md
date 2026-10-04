# Stage (g): post-launch program

Owner decision, 2026-10-03: build all twelve post-launch items in parallel.
Clockchain v1 has been live since 2026-10-02 with one entry: the inaugural
Engelbart 1968 Genesis. [HOLD.md](../../HOLD.md) gives the exact scope. Refs #6.

## Boundary

- **Build and merge.** Agents build. The owner's supervisor merges PRs in **this**
  repository after exact-head CI, an independent local PostgreSQL 18 gate and a
  review.
- **Owner actions.** Each of these stays a one-command step the owner runs from the
  owner's workstation:
  - deploying to production;
  - opening public ingress;
  - adding entries or media;
  - generating or holding keys;
  - setting production secrets;
  - merging in other repositories (consumer repos auto-deploy).
- **Agent limits.** No agent deploys, contacts production, calls a model, generates
  content, or handles real keys or the private fixture.
- **Fold version 1 is frozen.**
  - Do not change projection or admission semantics.
  - Do not change encoding, migrations, Stage 0 files, existing vectors, the fold
    manifest or `HOLD.md`.
  - Every existing commitment must stay byte-identical. The pinned vectors and the
    real-PostgreSQL tests guard this.
- **Commit and PR text.** Description only, with no trailers or attribution. Use
  "Refs #6", never closing keywords.
- **Data.** Synthetic test data only. The repository is public.

## Workstreams (one cloud session each)

| | Branch | Owns | Items |
| --- | --- | --- | --- |
| **G1 ops** | `feat/g1-ops-reliability` | `ops/`, `docs/OPERATIONS.md` | 1 + update releases |
| **G2 authority** | `feat/g2-publisher-authority` | `crates/cc-publisher/src/v1/authority*.rs`, tests, `docs/KEYS.md` | 2 |
| **G3 content** | `feat/g3-publisher-content` | `crates/cc-publisher/src/v1/{correction,edge,attest,entry}*.rs`, tests, `docs/AUTHORING-V1.md` | 8 (tooling), 9 |
| **G4 node** | `feat/g4-node-serving` | `crates/cc-node`, the serving glue in `crates/cc-ledger`, `docs/USING-THE-NODE.md`, `docs/design/SEALING.md` | 3, 4 |
| **G5 gateway** | `feat/g5-public-gateway` | new `crates/cc-gateway`, `deploy/public/`, `docs/PUBLIC-ACCESS.md` | 5 |
| **G6 explorer** | `feat/g6-explorer-verifier` | new `web/explorer/`, new `crates/cc-wasm-verify` | 7 |
| **G7 ecosystem** | `feat/g7-ecosystem` | new `clients/`, `docs/INTEGRATIONS.md`; draft PRs in consumer repos | 6 |
| **G8 docs** | `docs/g8-post-launch` | `README.md`, `START-HERE.md`, `docs/SESSION-HANDOFF.md`, new `docs/releases/`, new `docs/LAUNCH-EVIDENCE.md` | 10 (document), 11 (docs) |

Shared files: the workspace `Cargo.toml` members list, `Cargo.lock`, and
`.github/workflows/ci.yml` (additive steps only). Resolve conflicts in them on
rebase. A change outside your rows is a contract deviation; state it in your PR.

The supervisor handles item 12 (the cloud environment fix), item 10 (the #6
comment draft), item 11 (branch cleanup and `HOLD.md`), merges, and the final
owner deploy script.

## G1 · ops reliability

1. **`deploy-fly.sh --v1-update`** (with `release.py`), for a bound, populated store.
   It is mutually exclusive with `--v1-fresh`. In order:
   1. Verify that the expected identity (instance, curators, `max_hops`, fold) equals
      both the stored rule identity and `/health`.
   2. Take a backup and verify its restore locally on PostgreSQL 18.
   3. Deploy the exact digest. `provision-v1` stays the release command; it must
      be a no-op on a matching store.
   4. Post-deploy, read-only checks:
      - the identity is unchanged;
      - `/ready` returns 200;
      - the corpus digest and view commitment are byte-identical before and after
        the deploy (no writes happen);
      - the export is byte-equal.
   5. Take a verified backup after the deploy.

   The optional secret `CC_V1_NODE_SEED` (from G4) is handled when present.
2. **Scheduled verified backups** from the owner's workstation:
   - a launchd plist generator and runner;
   - daily at 09:00 local by default;
   - keep the last 30 in a private directory;
   - every run includes a local PostgreSQL 18 restore check;
   - on failure: a macOS notification plus a status JSON;
   - never print secrets; reuse or clean up `fly proxy` processes safely.
3. **Monitoring** (launchd, every 15 minutes): `/health` identity and `/ready`
   through a short-lived localhost proxy. Alert on failure or identity drift; stay
   quiet on success.
4. **`docs/OPERATIONS.md`** covers the update release, backups, monitoring, restore
   drills, and the Fly-native scheduled-machine alternative (documented, not built).

## G2 · authority (cold root, hot key)

Add `cc-publisher v1 delegate`, `v1 revoke` and `v1 grants`:
- `grants` is read-only and lists active grants from the node.
- They use the existing Stage (b) `Delegate` and `Revoke` payloads, signed offline.
  Submit reuses the `submit` path, with its instance, fold and curator checks.
- **Revoke:** an explicit cascade flag and issuer scope, exactly as the fold
  manifest defines them.
- **Tests:** against the real v1 node over real PostgreSQL. A delegated key can
  correct, and a revoked key cannot.
- **Mutation spot checks:** issuer scope, cascade, and refusal to sign with a key
  that has no grant.
- **`docs/KEYS.md` runbook:**
  - the hot-key ceremony (root signs a Delegate, root seed goes offline);
  - routine signing with the hot key;
  - rotation;
  - a compromise playbook (revoke with cascade);
  - what a lost root means.

## G3 · content commands and authoring

Add `cc-publisher v1 correction`, `v1 edge` (assert and reaffirm, with both
endpoint pins and the five governed relations), `v1 attest` (revision- or
event-scoped artifacts, as the v1 encoding already reserves), and
`v1 entry`.
- **`v1 entry`:** builds every envelope for one reviewed packet offline, from a
  manifest with sources, sha256 evidence, body, subject key and edges. It never
  submits on its own.
- **Port from the salvage branch:** only the safe, offline parts of its authoring
  and review flow (`salvage/live-brief-security-20261001`). No model calls, no
  generation, no image processing.
- **`docs/AUTHORING-V1.md`:** the packet format, review checklist and owner
  approval step.
- **Tests:** against the real v1 node.
  - An edge goes stale after a correction.
  - A dispute is never support.
  - An attest is bound to its revision.

## G4 · node serving and receipts

- **Snapshot cache.** Key it by (rule identity, corpus digest), invalidate it on
  admit, and keep the bytes identical to an uncached fold.
- **Read concurrency limit.** Use a semaphore; when full, answer 503 `busy`.
- **Signed `NodeReceiptV1` on admission**, only when `CC_V1_NODE_SEED` is set
  (64-hex seed). With it absent, receipts stay off and behavior is unchanged.
  - Add `GET /v1/receipts/{event}` with read scope and add it to the credential
    census.
  - Receipts never enter commitments.
- **`docs/design/SEALING.md`.** Options for sealing and anchoring v1 commitments
  (signed seal log, transparency log, external timestamping), each with tradeoffs.
  End it with an owner question; external anchoring is **not** implemented.
- **Tests:** cache equivalence across admits, busy behavior, receipts on and off,
  and unchanged pinned vectors.

## G5 · public read gateway

A new `cc-gateway` binary:
- It serves an unauthenticated, read-only `/public/v1` API by proxying the node's
  read routes with a server-side read key that never reaches clients.
- It strips `instance`, caches by corpus digest, limits each IP to 60 requests a
  minute by default, and allows GET-only CORS.
- It has no write routes and fails closed on any node error.

`deploy/public/` holds a separate Fly app template: public IPv6, a flycast route
to the private node, and the read key as a secret. It is **not deployed**. Public
exposure is an owner decision, documented in `docs/PUBLIC-ACCESS.md`, along with
abuse limits, cache invalidation and the threat model.

Contract (consumed by G6 and G7; JSON equals the node's read routes, minus
`instance`):

| Route | Notes |
| --- | --- |
| `GET /public/v1/health` | `{ledger, build, posture, fold_version{version,manifest}, filter_version, curators, max_hops, semantic}` |
| `GET /public/v1/snapshot` | optional fold params; 409 on mismatch |
| `GET /public/v1/subjects/{id}?as_of=` | |
| `GET /public/v1/revisions/{rev}/prose` | |
| `GET /public/v1/support?from=&to=&as_of=` | |
| `GET /public/v1/receipts/{event}` | only once G4 has merged; else 404 |

## G6 · explorer and in-browser verifier

`crates/cc-wasm-verify` must stay wasm-clean, with no sqlx or I/O. It verifies
each envelope's signature and canonical id, recomputes the corpus digest, recomputes
`filter_version` from the served identity, and checks that the view commitment is
consistent with the served canonical rows. It must state precisely what it does
**not** recompute: re-running the fold in the browser needs a wasm-clean
projection crate, which is a future owner decision.

`web/explorer/` is a static app that consumes the G5 contract:
- a subject view;
- a causal DAG view;
- a TT kind view;
- a verify-in-browser button.

Tests run against a synthetic fixture and a locally run gateway. A CI step builds
the verifier for wasm32.

## G7 · ecosystem integration

- **Audit.** Every consumer of the old node API (start with `timepoint-mcp`, the
  Flash `/api/v1/clockchain` proxy, `timepoint-api-gateway`, `timepoint-web-app`
  and the beta app). Record each one's routes, auth and failure behavior today in
  `docs/INTEGRATIONS.md`.
- **Clients.** Typed Python and TypeScript clients in `clients/` for the G5
  contract.
- **Draft PRs in consumer repos.** Each one is behind a feature flag that defaults
  to **off**, and none is ever merged. No consumer deploys change.

## G8 · docs and launch record

- Update `README.md`, `START-HERE.md` and `docs/SESSION-HANDOFF.md` to say v1 is in
  production. Mark the v0 paths legacy; that is documentation only, with no code
  removal.
- Add `docs/releases/v1.0.md`.
- Add a public-safe `docs/LAUNCH-EVIDENCE.md` mapping each #6 gate to the merged PRs,
  named tests and launch evidence, with no private values.
- Disposing of issue #6 remains the owner's call.

## Merge order

| When | Workstreams |
| --- | --- |
| Any time, once green | G8, G1, G4, G5 (independent files) |
| G2 before G3 | Both touch the publisher CLI dispatch; G3 rebases |
| After G5 | G6 and G7 run integration tests against the merged gateway |

## Evidence rules (unchanged)

- Every reported count comes from an assertion that can fail.
- Each key rule gets a mutation spot check: a test must fail when the rule is
  removed.
- Report actual local results separately from exact-head CI.
- Use subagents for parallel subtasks, and run an independent self-review against
  this contract before marking a PR ready.
