# Clockchain topology

One page that names every surface of the Clockchain v1 stack and where it is
defined. Checked against source and the live hosts on 2026-10-14.

- HTTP routes, parameters and response shapes: [reference/openapi.json](reference/openapi.json)
  (OpenAPI 3.1). `ops/test_openapi_routes.py` fails CI if the spec and the
  routers disagree.
- Contract prose: [PUBLIC-ACCESS.md](PUBLIC-ACCESS.md) (public gateway) and
  [USING-THE-NODE.md](USING-THE-NODE.md) (node).

```
 browsers / agents / apps
   │
   ├─ timepoint-clockchain-explorer.fly.dev ── static explorer + Wasm verifier ─┐
   ├─ timepoint-mcp-prod.fly.dev/mcp/ ── clockchain_v1_* tools ─────────────────┤
   ├─ api.timepointai.com/api/v1/clockchain/v1/* ── pass-through ───────────────┤
   ├─ timepoint-web-app-prod.fly.dev/clockchain ── v1 pages ────────────────────┤
   ├─ Python / TypeScript public clients ───────────────────────────────────────┤
   ▼                                                                            ▼
 clockchain.timepointai.com/public/v1   (= timepoint-clockchain-gateway.fly.dev)
 cc-gateway: GET only, no key from callers, 60 req/min per address, cached reads
   │  Bearer read key, private network
   ▼
 cc-node v1 (Fly app timepoint-clockchain-prod, private ingress)
   │  writes: cc-publisher v1 (operator, Bearer API key)
   ▼
 Postgres (Fly app timepoint-clockchain-prod-db)
```

## Services

| Service | Where | Source | Exposes |
|---|---|---|---|
| Node | `timepoint-clockchain-prod` (private) | `crates/cc-node` (`serve_v1.rs::router_with`) | 12 routes: health, ready, robots, 6 reads (snapshot, subjects, prose, support, receipts, seal), 3 writes (candidates, bodies, export). Auth: read key or API key; writes API key only. |
| Public gateway | `clockchain.timepointai.com`, `timepoint-clockchain-gateway.fly.dev` | `crates/cc-gateway` (`lib.rs::router`), template `deploy/public/` | 6 routes under `/public/v1`: health, snapshot, subjects, prose, support, receipts. No seal or export. |
| Explorer | `timepoint-clockchain-explorer.fly.dev` | `web/explorer`, `crates/cc-wasm-verify`, template `deploy/explorer/` | Views `#/` subjects, `#/subject/{id}`, `#/dag`, `#/edges`, `#/kind/{id}`, `#/verify`. Recomputes event ids, corpus digest, filter_version and commitment in the browser; signatures only with a supplied export. |
| Database | `timepoint-clockchain-prod-db` | `migrations/` (v0) and the v1 store in `cc-node` | Postgres, private. |

## Consumers (other repos)

| Consumer | Where | Calls | Notes |
|---|---|---|---|
| Python client `clockchain-public` 0.1.0 | `clients/python` | the 6 `/public/v1` routes | Vendored by timepoint-mcp, timepoint-api-gateway and timepoint-web-app. Does not verify. |
| TypeScript client `@clockchain/public-client` 0.1.0 | `clients/typescript` | the 6 `/public/v1` routes | Fixtures in `clients/fixtures/v1`, replayed through cc-gateway in CI. |
| MCP | timepoint-mcp `app/tools/clockchain_v1.py` | health, snapshot, subjects + prose, support | Tools `clockchain_v1_status`, `_list_subjects`, `_get_subject`, `_support`. Caller needs an MCP key with `read`; nothing is forwarded upstream. Flag `CLOCKCHAIN_V1_PUBLIC_ENABLED`. |
| API gateway | timepoint-api-gateway `gateway/routes/clockchain_v1.py` | the 6 routes, 1:1 under `/api/v1/clockchain/v1/*` | No auth or credits. Flag on in production. The legacy v0 `/api/v1/clockchain/*` router is still mounted behind it. |
| Web app | timepoint-web-app `app/clockchain_v1.py`, `app/routes/clockchain.py` | snapshot, subjects + prose | `GET /clockchain` and `/clockchain/{subject}`; legacy paths redirect. Its own MCP points callers to timepoint-mcp. |
| Landing | timepoint-landing `public/.well-known/ai-plugin.json`, `public/dev.html` | advertises `/public/v1` | The `/clockchain` gallery in `server.js` still reads the v0 node route `/v1/recents` with a gallery key; v1 serves no such route, so the gallery is empty. |

## Operator tools (not HTTP)

- `cc-publisher v1`: `keygen`, `pubkey`, `node-info`, `genesis`, `submit`, `grants`, `delegate`, `revoke`, `verify`, `context`, `correction`, `edge assert|reaffirm`, `attest`, `entry`, `review-packet`, `submit-packet`. See [PUBLISHER-V1.md](PUBLISHER-V1.md), [KEYS.md](KEYS.md).
- `cc-node` subcommands: `serve` (default), `provision-v1`; `migrate` is v0 only.
- `ops/`: release and update lane (`v1_update.py`, `deploy_digest.py`, `release.py`), backups (`v1_backup.py`, `schedule_backups.py`), monitor (`monitor_v1.py`, every 15 min on `/health` and `/ready`), seal log (`seal_v1.py`, hourly `GET /v1/seal`). See [OPERATIONS.md](OPERATIONS.md) and [ops/README.md](../ops/README.md).
- Libraries: `cc-core` (canon, hashing, identity), `cc-filter` (feasibility rule), `cc-ledger`, `cc-authoring`, `cc-anchor` (v0 anchoring), `cc-migrator` (v0), `cc-testkit`, `cc-wasm-vectors`.

## CI (`.github/workflows/ci.yml`)

`check` (fmt, clippy, Wasm builds and vectors, explorer, tests on real Postgres, client fixtures through cc-gateway, Python client, ops tests including the OpenAPI check), `clients-ts`, `stage0`.

## Docs index

Start: [README](../README.md), [START-HERE](../START-HERE.md), [HOLD](../HOLD.md).
Using: [PUBLIC-ACCESS](PUBLIC-ACCESS.md), [USING-THE-NODE](USING-THE-NODE.md), [INTEGRATIONS](INTEGRATIONS.md), [clients](../clients/README.md), [explorer](../web/explorer/README.md).
Writing: [PUBLISHER-V1](PUBLISHER-V1.md), [AUTHORING-V1](AUTHORING-V1.md), [FIRST-ENTRY](FIRST-ENTRY.md), [KEYS](KEYS.md), [ADMISSION-REVIEW](ADMISSION-REVIEW.md).
Operating: [OPERATIONS](OPERATIONS.md), [CICD-FLY](CICD-FLY.md), [LOCAL-DEV](LOCAL-DEV.md), [GREEN-DELIVERY](GREEN-DELIVERY.md), [SESSION-HANDOFF](SESSION-HANDOFF.md).
Generation and media: [ADAPTIVE-GENERATION](ADAPTIVE-GENERATION.md), [LOCAL-GENERATION](LOCAL-GENERATION.md), [MODEL-OPERATIONS](MODEL-OPERATIONS.md), [IMAGE-INTEGRITY](IMAGE-INTEGRITY.md), [TYPED-MEDIA-ABSENCE](TYPED-MEDIA-ABSENCE.md).
Design and evidence: [design/](design/), [evaluation/](evaluation/README.md), [releases/](releases/), [LAUNCH-EVIDENCE](LAUNCH-EVIDENCE.md), [TEST-ACCOUNTING](TEST-ACCOUNTING.md).
