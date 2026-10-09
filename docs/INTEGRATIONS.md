# Integrations

Stage (g) G7 ([STAGE-G.md](design/STAGE-G.md)). This page records every audited
consumer of the Clockchain node API, what each one does now that production
serves only the private v1 routes, and how each maps onto the G5 public read
contract (`/public/v1`). It also describes the typed clients in
[`clients/`](../clients/README.md) and the draft consumer pull requests.

No secret value, private hostname or production URL appears here, except the
public gateway origin the owner published on 2026-10-09
(`https://timepoint-clockchain-gateway.fly.dev`). Where a consumer has a production default URL,
this page says so without quoting it.

## Method

- Five consumer repositories, the ones STAGE-G.md names, were cloned read-only and
  audited at a pinned commit:

  | Repository | Commit audited |
  |---|---|
  | `timepointai/timepoint-mcp` | `02af9a1` |
  | `timepointai/timepoint-api-gateway` | `704ca41` |
  | `timepointai/timepoint-web-app` | `07849ff` |
  | `timepointai/timepoint-beta` | `adebd39` |
  | `timepointai/timepoint-flash` (public, archived) | `2e15597` |

- File and line references below are at those commits, checked with `git grep -n`.
- Beyond those five, a read-only GitHub code search for `CLOCKCHAIN` /
  `CLOCKCHAIN_URL` was run over the other repositories this session could reach.
  The hits are listed under [Found by code search](#found-by-code-search), not
  audited line by line. Repositories that were not searched are listed under
  [Unaudited repositories](#unaudited-repositories).
- "What happens today" comes from two sources. First, each consumer's own
  error handling. Second, what a real v1 node answers on the routes those
  consumers call: [`clients/fixtures/record.py`](../clients/fixtures/record.py)
  starts `cc-node` in v1 mode over a throwaway local database and probes those
  routes. The results are in
  [`clients/fixtures/legacy-probes.json`](../clients/fixtures/legacy-probes.json).
  Production itself was not contacted.

## What production serves

Production runs `cc-node` with `CC_NODE_LEDGER=v1` ([USING-THE-NODE.md](USING-THE-NODE.md),
"v1 mode"). The node itself has no public ingress; the G5 public gateway in
front of it is deployed ([PUBLIC-ACCESS.md](PUBLIC-ACCESS.md)). The node's
routes are:

- `GET /health` and `GET /ready`, both public.
- `GET /v1/snapshot`, `/v1/subjects/{id}`, `/v1/revisions/{id}/prose` and
  `/v1/support`, which need a Bearer read key.
- The write routes and `/v1/export`, which need the Bearer full key.

**None of the legacy routes is mounted.** Neither the Python service's
`/api/v1/*` routes nor the v0 node's `/v1/entities`, `/v1/feasibility`,
`/v1/recents` and `/mcp/` exist on it.

Every audited consumer calls `/api/v1/*` routes of the retired Clockchain
service. They authenticate with `X-Service-Key`; the only Bearer token any of
them sends is the API gateway's admin key, on its admin path (see
[timepoint-api-gateway](#timepoint-api-gateway)), and that key is not a v1
node credential. The probes record what a v1 node answers:

| Request | v1 node answer |
|---|---|
| Any legacy path with `X-Service-Key`, no credential, or an unknown Bearer | `401 {"error":"unauthorized"}` |
| Any legacy path with a valid Bearer read key | `404 {"error":"no_such_route"}` |
| `GET /health` | `200`, a v1 identity document (`ledger: "v1"`), not the legacy shape |

A consumer that could reach production would therefore get 401 on every call.
A consumer that cannot reach it (it is private) gets a connection or DNS
failure instead. Either way the failure handling recorded below is what users
see.

## Summary

| Consumer | Calls Clockchain? | Routes used | Auth sent | Behaviour today | v1 path | PR |
|---|---|---|---|---|---|---|
| timepoint-mcp | Yes, 13 call sites | `/api/v1/{search,moments,browse,graph/*,today,random,stats}`; writes via Flash `/api/v1/clockchain/{index,moments/*/visibility,ingest/tdf}` | `X-Service-Key` | Read tools report "not found" or raise tool errors; writes fail or report `indexed: false` | Flagged v1 read tools | [timepoint-mcp PR](#draft-pull-requests) |
| timepoint-api-gateway | Yes, about 30 routes and tools | `/api/v1/clockchain/*` passthrough to legacy `/api/v1/*`; entities; Conductor tools | `X-Service-Key`, admin Bearer, forwarded user headers | Upstream 401/404 passed through; 503/504 when unreachable | Flagged `/api/v1/clockchain/v1/*` read passthrough | [timepoint-api-gateway PR](#draft-pull-requests) |
| timepoint-web-app | Yes, about 20 call sites | `{gateway}/api/v1/clockchain/*` or `{CLOCKCHAIN_API_URL}/api/v1/*` | `X-Service-Key` | Explore shows "temporarily unavailable"; search shows "Search unavailable"; moment and entity pages 404 | Flagged v1 list and subject pages | [timepoint-web-app PR](#draft-pull-requests) |
| timepoint-beta | **No** | none | n/a | Unaffected | Nothing to migrate | None needed |
| timepoint-flash (archived) | Yes, `/api/v1/figures/*` only; **no `/api/v1/clockchain` proxy in this repository** | figures resolve, search, get, ground | `X-Service-Key` | Degrades silently to no entity data; reground tasks end `failed` | No v1 equivalent (see below) | None: archived, read-only |

## timepoint-mcp

### Configuration

Settings are pydantic `BaseSettings` (`app/config.py`):

| Setting | Line | Default |
|---|---|---|
| `FLASH_URL` | `:10` | A production URL (not recorded here) |
| `FLASH_OUTBOUND_KEY` | `:13` | Empty; secret |
| `FLASH_SERVICE_KEY` | `:14` | Empty; secret, legacy alias |
| `CLOCKCHAIN_URL` | `:17` | Empty |
| `CLOCKCHAIN_SERVICE_KEY` | `:18` | Empty; secret |

`app/server.py:211-216` always constructs `ClockchainClient`.

### Client

`app/clients/clockchain.py` builds three base URLs:

- `_proxy_base` (`:38`) is `{FLASH_URL}/api/v1/clockchain`.
- `_direct_base` (`:41`) is `{CLOCKCHAIN_URL}/api/v1`, or the proxy base when
  `CLOCKCHAIN_URL` is empty.
- Reads use `_read_base` (`:44`), which is the direct base.

Headers:

- Direct calls send `X-Service-Key: CLOCKCHAIN_SERVICE_KEY` (`:35`).
- Proxy calls send the Flash key (`:28`) and `X-User-ID`.
- No call sends `Authorization: Bearer`.

The client has one `httpx` timeout of 30 s and no retries.

### Routes

| Client method | Line | Request | MCP tool |
|---|---|---|---|
| `search` | `:91` | `GET {read}/search` | `search_moments` |
| `get_moment` | `:106` | `GET {read}/moments/{path}` | `get_moment` |
| `browse` | `:113` | `GET {read}/browse[/{path}]` | `browse_graph` |
| `neighbors` | `:122` | `GET {read}/graph/neighbors/{path}` | `get_connections` |
| `subgraph` | `:128` | `GET {read}/graph/subgraph/{path}` | `explore_graph` |
| `traverse` | `:143` | `GET {read}/graph/traverse/{path}` | `traverse_moments` |
| `path` | `:171` | `GET {read}/graph/path` | `find_path` |
| `today` | `:192` | `GET {read}/today` | `today_in_history` |
| `random` | `:197` | `GET {read}/random` | `random_moment` |
| `stats` | `:202` | `GET {read}/stats` | `graph_stats` |
| `index_moment` | `:207` | `POST {FLASH_URL}/api/v1/clockchain/index` | `generate_moment` |
| `update_visibility` | `:216` | `PATCH {FLASH_URL}/api/v1/clockchain/moments/{path}/visibility` | `publish_moment` |
| `ingest_tdf` | `:226` | `POST {FLASH_URL}/api/v1/clockchain/ingest/tdf` | `index_moment_from_tdf` |

### Failure behaviour today

`_get`, `_post` and `_patch` (`:70-89`) handle failures like this:

- A 404 becomes `{"error":"not_found"}`, whatever the body.
- Any other non-2xx raises `httpx.HTTPStatusError`.
- A connection error raises.

How each tool surfaces that:

- `search_moments`, `get_moment`, `browse_graph` and `get_connections` have no
  `try`/`except`, so a 401 or a connection error becomes an MCP tool error.
- `traverse_moments`, `find_path` and `explore_graph` catch the failure and
  return `{"error": ..., "suggestion": ...}`.
- `today_in_history`, `random_moment` and `graph_stats` pass the raw result
  through.
- `generate_moment` still spends the user's credits and returns
  `indexed: false` (`app/tools/clockchain_write.py:128-131, :175`).
- `/health` (`app/server.py:85`) reports `"clockchain": true` whenever
  `FLASH_URL` or `CLOCKCHAIN_URL` is set. It never probes the node, so it
  stays green.

### v1 mapping

| Today | v1 public |
|---|---|
| `graph_stats` | `GET /public/v1/health` (identity) plus counts from `/public/v1/snapshot` |
| `search_moments`, `browse_graph`, `today_in_history`, `random_moment` | No search route. List subjects from `/public/v1/snapshot` (`summarize_subjects` in the clients) and filter client-side |
| `get_moment` | `GET /public/v1/subjects/{id}` then `GET /public/v1/revisions/{rev}/prose`. v1 ids are 32-byte subject ids, not legacy paths, and no mapping table exists |
| `get_connections`, `traverse_moments`, `find_path`, `explore_graph` | `GET /public/v1/support?from=&to=`. This is a governed support verdict over pinned edges, not a graph walk. Edges are in `/public/v1/snapshot` |
| Write tools | None public. v1 writes are owner-signed envelopes submitted with `cc-publisher` ([PUBLISHER-V1.md](PUBLISHER-V1.md)) |

## timepoint-api-gateway

### Configuration

Settings are pydantic `BaseSettings` (`gateway/config.py`):

| Setting | Line | Notes |
|---|---|---|
| `CLOCKCHAIN_URL` | `:15` | Default is a production URL (not recorded here) |
| `CLOCKCHAIN_SERVICE_KEY` | `:34` | Secret |
| `CLOCKCHAIN_API_KEY` | `:35` | Legacy alias, resolved at `:178-181` |
| `CLOCKCHAIN_ADMIN_KEY` | `:109` | Secret |
| `CLOCKCHAIN_METERING_ENABLED` | `:130` | Default `False` |

The pooled backend is registered at `gateway/main.py:103`.

### `/api/v1/clockchain/*` passthrough

`gateway/routes/clockchain.py:16` mounts it. Outbound headers come from
`_headers` (`:38`):

- `X-Service-Key` is set (`:41`).
- `Authorization: Bearer <CLOCKCHAIN_ADMIN_KEY>` is added only for a matching
  `X-Admin-Key` (`:51`).
- `X-User-Id` and `X-User-Email` carry the caller's identity (`:52-67`).

Routes forwarded:

- Reads: `/browse[/{path}]`, `/moments/{path}`, `/today`, `/random`,
  `/search`, `/graph/neighbors/{path}`, `/stats`, `/figures`,
  `/figures/search`, `/figures/{id}`, `/figures/{id}/nodes` and
  `/nodes/{id}/figures`, each to the same path under upstream `/api/v1`.
  Reads are metered when `CLOCKCHAIN_METERING_ENABLED` is on.
- Writes: `/ingest/subgraph`, `/index`, `/figures`, `/figures/resolve`,
  `/figures/resolve/batch`, `/nodes/{id}/figures`,
  `/figures/{id}/visibility` (PATCH) and `/figures/{id}` (DELETE).

Unmatched `/api/v1/clockchain/*` paths fall through to the Flash catch-all in
`gateway/routes/flash.py`.

### Entities

`gateway/routes/entities.py` (`:48`, prefix `/api/v1/entities`) calls
`{CLOCKCHAIN_URL}/api/v1/figures/*` with `X-Service-Key` and `X-User-Id`. It
covers grounding status, create, visibility, share and permissions.

### Conductor tools

`gateway/conductor/engine.py` has three LLM tools, each sending `X-Service-Key`:

| Tool | Line | Upstream |
|---|---|---|
| `search_clockchain` | `:418` | `{CLOCKCHAIN_URL}/api/v1/search` |
| `get_moment_details` | `:431` | `/api/v1/moments/{path}` |
| `get_graph_connections` | `:471` | `/api/v1/graph/neighbors/{path}` |

### Failure behaviour today

`proxy_request` (`gateway/proxy.py`) is the shared path:

- It passes upstream status and JSON through unchanged, so clients receive the
  node's 401 or 404.
- It retries connection errors and timeouts up to `_MAX_RETRIES = 3` (`:18`),
  including POST, PATCH and DELETE.
- After the retries it answers 504 `clockchain service timeout` or 503
  `clockchain service unavailable`.
- A non-JSON body becomes 502 `clockchain returned malformed response` (`:155`).

Elsewhere:

- Entity grounding status maps any non-404 error to 502.
- Conductor tools return error dicts to the model. The 5 base credits are
  still charged.
- Read metering charges only 2xx responses, so failed reads cost nothing.

### v1 mapping

Each gateway read path maps onto `/public/v1` the same way as the timepoint-mcp
mapping above. The draft PR adds a separate read-only passthrough,
`/api/v1/clockchain/v1/{health,snapshot,subjects/{id},revisions/{id}/prose,support,receipts/{id}}`,
to `/public/v1`. It sends no service key, no user headers and no Bearer. The
legacy routes stay as they are.

## timepoint-web-app

### Configuration

Settings are pydantic `BaseSettings` (`app/config.py`):

| Setting | Line | Notes |
|---|---|---|
| `FLASH_API_URL` | `:5` | Default `http://localhost:8000`; production points it at the API gateway |
| `CLOCKCHAIN_API_URL` | `:10` | Default empty, which routes everything through the gateway |
| `CLOCKCHAIN_SERVICE_KEY` | `:11` | Secret; falls back to the Flash outbound key |

### Client and routes

`app/flash_client.py` holds the client:

- `_cc_prefix` (`:61-62`) is `/api/v1` when direct and `/api/v1/clockchain`
  through the gateway.
- Every request sends `X-Service-Key`.
- Methods at `:64-171` cover `browse`, `moments`, `moments?limit&offset`,
  `today`, `random`, `search`, `stats`, `graph/neighbors`, `figures`,
  `figures/{id}` and `figures/{id}/nodes`.

`app/routes/entities.py:47` builds a client on `FLASH_API_URL` for the
`/api/v1/clockchain/figures*` routes, both reads and writes.

### Failure behaviour today

| Page | What users see |
|---|---|
| Home | The Clockchain section has a 4 s deadline and silently disappears; HTTP 200 |
| `/clockchain` | "The Clockchain is temporarily unavailable" (`app/templates/clockchain.html`); HTTP 200 |
| `/search` | "Search unavailable"; HTTP 200 |
| `/moment/{path}` | Falls back to a Flash slug lookup, so Clockchain-only moments return 404 |
| `/entities` | Empty grids; entity detail pages return 404 |
| Entity writes | The upstream status is passed to the browser |
| MCP tools (`/mcp`) | Return `ToolError` |

### v1 mapping

| Page | v1 public |
|---|---|
| `/clockchain` | List from `/public/v1/snapshot` |
| A subject page | `/public/v1/subjects/{id}` plus `/public/v1/revisions/{rev}/prose` |
| Search, today, random | Client-side over the snapshot |
| Figures (entities) | No v1 equivalent |

## timepoint-beta

**Not a consumer.** A repository-wide search found only:

- documentation: `TT-BOUNDARY.md` and `CONTRACTS.md:243, :653-654`;
- taxonomy lineage strings: `ui/src/taxonomy.ts:5-6` and
  `crates/pro-api/tests/taxonomy_binding.rs:4`;
- comments.

Beta's own `/v1/entities*` routes are its own API (`crates/pro-api`), not
Clockchain calls. `CONTRACTS.md` confines outbound HTTP to `crates/tp-llm` and
`crates/tp-store`, and neither calls Clockchain. No `CLOCKCHAIN_*` setting
exists. Nothing to migrate and no PR.

## timepoint-flash (archived)

The public repository is archived. Its README and `docs/DEPLOY.md:5` say
production runs from a private Flash deploy fork.
**This repository has no `/api/v1/clockchain` proxy route.** The proxy that
timepoint-mcp and timepoint-web-app reach through `{FLASH_URL}/api/v1/clockchain`
is therefore either in that private fork or in the API gateway's Flash
catch-all. The fork was not available to this audit (see
[Unaudited repositories](#unaudited-repositories)).

### Configuration

Settings in `app/config.py`:

| Setting | Line | Notes |
|---|---|---|
| `CLOCKCHAIN_URL` | `:679` | |
| `CLOCKCHAIN_ENTITY_URL` | `:683` | |
| `CLOCKCHAIN_SERVICE_KEY` | `:687` | Secret, sent as `X-Service-Key` |
| `ENTITY_RESOLUTION_ENABLED` | `:663` | Flag, default `False` |
| `ENTITY_GROUNDING_ENABLED` | `:667` | Flag, default `False` |

### Calls

`app/core/entity_client.py` makes these calls:

- `POST /api/v1/figures/resolve/batch` (`:93`, `:163`)
- `GET /api/v1/figures/{id}` (`:241`)
- `GET /api/v1/figures/search` (`:308`)
- `PATCH /api/v1/figures/{id}/ground` (`:368`)

`app/api/v1/reground.py:113, :126, :227, :266` calls the same figure routes.

### Failure behaviour today

- Every `entity_client` function logs and returns empty or `False`.
- `GET /api/v1/entities/search` answers 200 with no results.
- Generation continues without entity data.
- Reground tasks end `failed`.

### v1 mapping

**None.** v1 has no figure registry, name resolution or grounding route, and
its writes are owner-signed envelopes. There is no switch a feature flag could
make, so this page records no patch for Flash. With its URL unset, Flash
already skips these calls. Whether the private deploy fork's `CLOCKCHAIN_*`
settings should be cleared is an owner decision.

## Route mapping, legacy to `/public/v1`

| Legacy | v1 public | Notes |
|---|---|---|
| `/health`, `/health/deep`, `/api/v1/stats` | `GET /public/v1/health` | The identity (`fold_version`, `filter_version`, `curators`, `max_hops`) without `instance`. `/ready` is not in the public contract |
| `/v1/entities/{id}`, `/api/v1/moments/{path}` | `GET /public/v1/subjects/{id}?as_of=` | 32-byte hex subject ids, not u64 entity ids or paths. `as_of` is a 32-byte coordinate, not decimal seconds; use `coordinate_from_seconds` / `coordinateFromSeconds` to convert |
| Moment or claim prose | `GET /public/v1/revisions/{rev}/prose` | Body text served only when its bytes hash to the signed body hash |
| `/v1/feasibility`, `/api/v1/graph/path` | `GET /public/v1/support?from=&to=&as_of=` | A two-valued support verdict (`Supported` with a path, or `Unsupported` with reasons) over curator-trusted pinned edges, bounded by `max_hops`. Not the legacy three-valued feasibility certificate and not a TT-claim check |
| `/v1/recents`, `/api/v1/browse`, `/api/v1/search`, `/today`, `/random`, `/graph/*` | `GET /public/v1/snapshot` | The whole projection: rows, subjects, revisions, edges, media, authority. List and filter client-side |
| `/v2/media`, `/v1/images/*` | `media` in the snapshot | Revision-scoped media records; no image bytes route |
| `/v1/events`, `/api/v1/index`, `/ingest/*`, `/figures` writes | None | No public writes. Owner-signed `cc-publisher v1` only |
| Admission receipts | `GET /public/v1/receipts/{event}` | `{event, receipts}`: each a signed G4 `NodeReceiptV1` with its digest, node key, `received_at` (Unix microseconds when the node saw the event) and initial admission result. `404 no_receipt` when the node holds none, which includes every event on a node without `CC_V1_NODE_SEED`. Never cached by the gateway |

## Found by code search

A read-only GitHub code search for `CLOCKCHAIN_URL` and `clockchain api/v1` ran
over the other repositories this session could reach. All of them are private
or internal, so this public page describes them generically; the owner has the
list and the search to repeat. None was audited line by line, and no draft PR
was opened in any of them, since they are outside the five the contract names.

| Kind of repository | Apparent use |
|---|---|
| Private simulation services (two) | Figure fetches and entity grounding against the legacy `/api/v1` prefix during runs |
| Internal operations and tooling repository | Scheduled health, report and end-to-end jobs and browser checks that read the Clockchain `/health`, legacy routes and the retired `/mcp/` endpoint; expect them to fail, or to see the v1 `/health` shape. Also demo and operations scripts and many documents |
| Internal format and benchmark libraries (two) | The name only; no `/api/v1` Clockchain HTTP call was found |

The owner should decide whether the scheduled jobs should be paused, or pointed
at `/public/v1` once public ingress opens.

## Unaudited repositories

Further private or internal repositories were neither audited nor
code-searched, because attaching them was refused or was outside the
supervisor's scope. The owner has the list and should confirm whether any of
them calls Clockchain. In priority order:

- **The private Flash deploy fork.** It probably holds the
  `/api/v1/clockchain` proxy that timepoint-mcp's writes and
  timepoint-web-app's default path use. Highest priority.
- Client applications and marketing sites.
- Other internal services and documentation repositories.
- Archived repositories, including the retired Python Clockchain service.
  Archived repositories cannot deploy changes.

## Clients

[`clients/`](../clients/README.md) holds typed Python and TypeScript clients for
the G5 contract. Both clients:

- send GET only, with no credential, no redirect following and no proxy taken
  from the environment;
- validate identifiers before any request;
- carry the gateway's `Retry-After` on a 429 `rate_limited` as `retry_after` /
  `retryAfter`, in seconds;
- fail closed on any response that does not match the contract, or that
  answers for a different subject, revision, coordinate or fold than the one
  asked.

Both are tested against [`clients/fixtures/v1/`](../clients/fixtures/v1). These
are responses that the merged G5 `cc-gateway` gave in front of a real v1 node
holding synthetic data, including a real 429. CI re-records them with
`record.py --check` and fails on any drift.

Recorded through the gateway, every body equals what the node's own read routes
answer minus the top-level `instance` on `/health`. In particular, the
snapshot's `rows[].envelope` keeps each envelope's `instance` as canonical
bytes, because the gateway strips only the top-level field.

## Draft pull requests

Each draft PR adds a `CLOCKCHAIN_V1_PUBLIC_ENABLED` flag, default **off**, and a
`CLOCKCHAIN_V1_PUBLIC_URL` setting, default empty. With the flag off, behaviour
is unchanged. Each PR vendors `clients/python/clockchain_public/client.py`
below a vendoring header that names the source commit; the body below that
header is byte-identical to the upstream file, and a test pins its SHA-256
(the header makes the whole-file hash differ). These repositories auto-deploy
from their default branch, so each merge was an owner decision (HOLD.md,
2026-10-09); the merges below landed with the flag off, and enabling a flag is a
separate owner step per repository.

To keep a deployment off, leave `CLOCKCHAIN_V1_PUBLIC_ENABLED` unset or set it
to `false`. An empty value may fail settings validation at boot. The flag takes
effect only together with a non-empty `CLOCKCHAIN_V1_PUBLIC_URL`; the published
value is `https://timepoint-clockchain-gateway.fly.dev/public/v1`.

| Repository | PR and status | With the flag on |
|---|---|---|
| timepoint-mcp | [timepoint-mcp#13](https://github.com/timepointai/timepoint-mcp/pull/13), merged 2026-10-09 flag off | v1 read tools replace the legacy read tools; write tools unchanged |
| timepoint-api-gateway | [timepoint-api-gateway#56](https://github.com/timepointai/timepoint-api-gateway/pull/56), merged 2026-10-09 flag off | Read-only `/api/v1/clockchain/v1/*` passthrough to `/public/v1` |
| timepoint-web-app | [timepoint-web-app#345](https://github.com/timepointai/timepoint-web-app/pull/345), merged 2026-10-09 flag off | `/clockchain` lists v1 subjects, and `/clockchain/v1/subjects/{id}` shows one. With the flag off that URL still reaches the legacy handler |

No PR was opened for timepoint-beta, which has nothing to migrate, or for
timepoint-flash, which is archived and has no v1 mapping.
