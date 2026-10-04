# Public read access

`cc-gateway` is the unauthenticated, read-only public face of the private v1
node. The contract is Stage (g) G5. The source is `crates/cc-gateway`; the Fly
app template is [deploy/public/](../deploy/public/README.md).

## Status

**Built, not deployed.** No public app, IP or secret exists. Exposing the node's
corpus to the internet is an **owner decision**. Under [HOLD.md](../HOLD.md) and
the Stage (g) boundary, opening public ingress and setting production secrets are
owner-run, one-command steps from the owner's workstation. No agent, CI job or
cloud session runs them. Items marked **Owner decision** below need an explicit
owner choice before enablement.

## Contract: `/public/v1`

Each route maps to exactly one node read route. The JSON equals the node's
answer minus the top-level `instance` key. Embedded projection values (`rows`,
`subjects`, `revision`, and the rest) pass through as the node's raw JSON text,
never re-encoded, so a verifier can recompute commitments from the served bytes.
The top-level object is re-emitted with its remaining keys in sorted order.

Only the top-level key is removed. Each signed envelope embedded in a snapshot's
`rows` keeps its own `instance` field, because removing it would make the
signature and canonical id unverifiable. Stripping is therefore presentation,
not confidentiality: the instance id remains readable from any non-empty
snapshot.

| Route | Notes |
| --- | --- |
| `GET /public/v1/health` | `{ledger, build, posture, fold_version{version,manifest}, filter_version, curators, max_hops, semantic}` |
| `GET /public/v1/snapshot` | optional fold params; 409 on mismatch |
| `GET /public/v1/subjects/{id}?as_of=` | |
| `GET /public/v1/revisions/{rev}/prose` | |
| `GET /public/v1/support?from=&to=&as_of=` | |
| `GET /public/v1/receipts/{event}` | only once G4 has merged; else 404 |

- `health` calls the node's anonymous `/health` without the read key. It is not
  cached and carries no `x-cache`.
- The other four are corpus reads, sent with the read key, cached by corpus
  digest, and answered with `x-cache: hit` or `x-cache: miss`.
- `receipts` is not mounted: it is `404 {"error":"no_such_route"}` until the
  node serves receipts (G4) and the route is added.
- The query string is forwarded verbatim. The node refuses an unknown,
  misspelled or repeated parameter with `400 invalid_query`.
- A path parameter is forwarded only if it is 1–128 ASCII alphanumerics.
  Anything else is replaced by the fixed token `invalid`, which the node
  refuses as it would the original (`400 invalid_subject_id` or
  `400 invalid_revision_id`).
- `HEAD` is served like `GET` without a body, at the same node cost.

### Status mapping

The gateway fails closed. A cached answer is never served in place of a failed
node read.

| Node outcome | Gateway answer |
| --- | --- |
| 200, 400, 404 or 409 with a JSON object body within the body cap | Same status, body minus `instance` |
| 503 | `503 {"error":"node_unavailable"}` |
| Unreachable, connect failure, timeout, or body cut off mid-read | `503 {"error":"node_unavailable"}` |
| Any other status: 401/403 (read key refused, logged at error level), 3xx (redirects are not followed), other 4xx, 5xx | `502 {"error":"bad_gateway"}` |
| Body that is not a JSON object, or exceeds `CC_GATEWAY_MAX_BODY_BYTES` | `502 {"error":"bad_gateway"}` |
| Digest probe (see [Cache](#cache)) that is not 200/404 or names no well-formed `corpus_digest` | `502 {"error":"bad_gateway"}` |

### Gateway-owned refusals

| Status | Body | Extra header | When |
| --- | --- | --- | --- |
| 405 | `{"error":"read_only"}` | `Allow: GET, HEAD, OPTIONS` | Any method other than GET, HEAD, OPTIONS, on any path, before routing |
| 429 | `{"error":"rate_limited"}` | `Retry-After`: whole seconds, rounded up, at least 1 | Per-client limit exceeded, or the client table is full |
| 404 | `{"error":"no_such_route"}` | | Any path not in the table above |
| 503 | `{"error":"node_unavailable"}` | | See status mapping |
| 502 | `{"error":"bad_gateway"}` | | See status mapping |

Order per request: response headers, then the rate limit, then the method
guard, then routing. Every request, including `OPTIONS`, a 405 and an unknown
path, spends one rate-limit token. A refused request makes no node call.

### Headers

Every response, refusals and preflights included, carries:

| Header | Value |
| --- | --- |
| `access-control-allow-origin` | `*` |
| `cache-control` | `no-store` |
| `x-content-type-options` | `nosniff` |
| `referrer-policy` | `no-referrer` |
| `content-security-policy` | `default-src 'none'; frame-ancestors 'none'` |
| `x-robots-tag` | `noindex, nofollow` |
| `access-control-expose-headers` | `retry-after, x-cache` |

Answers and refusals are `content-type: application/json`. No node header
reaches the client.

`OPTIONS` on any path is a CORS preflight: `204` with
`access-control-allow-methods: GET, HEAD, OPTIONS` and
`access-control-max-age: 600`. No `access-control-allow-headers` is sent, so a
preflight asking for a custom request header is not granted. A plain
cross-origin `GET` needs no preflight. No credentials are accepted or needed.

## Configuration

Read once at boot. Any missing, weak or out-of-range value exits 78
(`EX_CONFIG`) before the listener binds. Numbers must be canonical decimal: no
sign, leading zero, exponent or empty value. Startup does no node I/O, so the
gateway boots while the node is down and answers 503 until it is reachable.
The startup log line names the bind address, rate, freshness and client IP
header; never the node URL or the key.

| Variable | Default | Bounds | Meaning |
| --- | --- | --- | --- |
| `CC_GATEWAY_NODE_URL` | required | `http` or `https` origin; no path, query, fragment or userinfo | The private node |
| `CC_GATEWAY_READ_KEY` | required; Fly secret only | ≥ 32 characters, ≥ 8 distinct, visible ASCII, no leading or trailing whitespace | Sent to the node as `Authorization: Bearer` |
| `CC_GATEWAY_RATE_PER_MINUTE` | `60` | 1–100000 | Per-client limit; see [Abuse limits](#abuse-limits) |
| `CC_GATEWAY_FRESHNESS_MS` | `1000` | 0–60000 | How long an observed corpus digest is trusted; the staleness bound after an admit |
| `CC_GATEWAY_CLIENT_IP_HEADER` | unset: socket peer | A valid header name | Read the client address from this header when present and parseable, else the socket peer |
| `CC_GATEWAY_CACHE_BYTES` | `67108864` (64 MiB) | 0–4294967296 | Cache bound, keys plus bodies; `0` caches nothing |
| `CC_GATEWAY_MAX_BODY_BYTES` | `33554432` (32 MiB) | 1024–1073741824 | Largest node answer read; larger is 502 |
| `CC_GATEWAY_UPSTREAM_TIMEOUT_MS` | `10000` | 100–120000 | Whole node request, body included; expiry is 503 |
| `PORT` | `8080` | 1–65535 | Listens on `0.0.0.0:PORT` |

The key check is the node's boot rule without its placeholder-word list. The
node remains the authority: the gateway's key must be the node's read key.

The template ([deploy/public/fly.toml](../deploy/public/fly.toml)) sets
`CC_GATEWAY_NODE_URL=http://<node-app>.flycast`,
`CC_GATEWAY_CLIENT_IP_HEADER=fly-client-ip`, rate 60, freshness 1000 ms and
`PORT=8080`, on one `shared-cpu-1x` 256 MB machine with request concurrency soft
32 / hard 64.

## Abuse limits

- **Per-client rate (GCRA).** Each client may burst to
  `CC_GATEWAY_RATE_PER_MINUTE` requests at once, then sustain that rate, one
  request per `60 s / rate` (1 s at the default). The sustained rate is the
  limit; with the burst, any 60 s window holds at most `2 × rate − 1` requests
  from one client (119 at the default). It runs before the method guard and any
  node call.
- **Client key.** IPv4 and IPv4-mapped IPv6 addresses are keyed by full
  address. Other IPv6 addresses are keyed by their /64.
- **Bounded table.** At most 100000 clients are tracked. When full, idle clients
  are dropped; if none are idle, a new client is refused with 429
  (`Retry-After` one interval) rather than admitted unmetered.
- **Fly concurrency.** Soft 32 / hard 64 simultaneous requests through Fly Proxy
  to the gateway machine. The node's own soft 8 / hard 16 also applies, because
  Flycast traffic goes through Fly Proxy.
- **Body cap.** A node answer over `CC_GATEWAY_MAX_BODY_BYTES` is refused, not
  truncated. Each in-flight answer is held twice while it is stripped (the
  node's bytes and the re-emitted ones), so worst-case memory is roughly
  2 × hard limit × cap plus `CC_GATEWAY_CACHE_BYTES`. The defaults (64 × 32 MiB,
  64 MiB cache) exceed the template's 256 MB VM; today's snapshot is far below
  the cap. **Owner decision:** lower the cap or raise VM memory as the corpus
  grows.
- **Upstream timeout.** `CC_GATEWAY_UPSTREAM_TIMEOUT_MS` bounds each node
  request, so a slow node cannot hold gateway requests open indefinitely.

Limiter and cache state live in process memory. A restart clears both, and a
second machine would double every client's limit and split the cache.

## Cache

A v1 read is a pure function of rule identity, corpus and request, and the rule
identity is fixed for the life of a node. The cache holds entries for exactly
one corpus digest, the most recently observed one.

- **Key.** The node path plus the query string as sent. Different spellings of
  the same query are different keys.
- **Observation.** Every node read that names a well-formed `corpus_digest`
  (64 lowercase hex) updates the current digest. A different digest starts a new
  generation and drops every entry. An observation requested earlier than the
  current one cannot roll the generation back.
- **Probe.** When the current digest is older than `CC_GATEWAY_FRESHNESS_MS`, a
  corpus read first asks the node for
  `GET /v1/subjects/<64 zeros>`: no subject has that id, so the answer is 404
  `subject_unknown` naming the digest. One probe runs at a time, and every
  request that arrived before a probe started takes that probe's outcome,
  success or failure, without probing again. A request therefore waits for at
  most the probe in flight plus one more: about two upstream timeouts against a
  hung node, however many requests are queued. With freshness `0`, every
  corpus read probes first.
- **Admit visibility.** The gateway cannot see an admit. An admit is visible
  through it at most one freshness window after it commits. Every 200 or 404
  corpus read names its `corpus_digest`, so a client can tell which corpus it
  was served.
- **Failure.** A hit needs a digest observed within the freshness window. Once
  the window lapses, a failed probe or read is 502 or 503, never a cached
  answer. Within the window (1 s by default) a hit is served without a node
  call, so hits can continue for up to one window after the node fails.
- **What is stored.** Only 200 and 404 answers that name a digest, and only if
  that digest is still the current generation. 400, 409 and answers without a
  digest are passed through uncached. `health` is never cached.
- **Byte bound.** Key plus body bytes stay within `CC_GATEWAY_CACHE_BYTES`. A
  full cache evicts its least recently used entries to make room; an answer
  larger than the whole bound is not stored.

## Threat model

### Assets

- **The read key.** It opens every node read route (and receipts once G4 lands).
  It does not open `/v1/export` or any write: those need the write key.
- **Node availability.** The node is the single ledger writer on a small VM.
- **Integrity of served data.** The gateway is **not** a trust anchor. It strips
  `instance` and re-emits the top-level object; it could serve anything a
  compromised machine chose. Clients verify signatures, `filter_version`,
  curators, the corpus digest and the commitment from the served bytes (G6), and
  pin the expected identity out of band.
- **The node stays private.** Its only ingress remains Flycast; the gateway adds
  no public IP to the node.

### Adversaries

- Anonymous internet clients, at any rate and from many addresses.
- A compromised gateway machine, or anyone with Fly access to the gateway app
  (secrets are in its environment).
- Other apps in the same Fly organization, which can reach the gateway and the
  node over the private network.

### Mitigated

- **The read key never reaches a client or a log.** It is held only as a
  sensitive header value (`set_sensitive`), behind a redacting `Debug`
  (`ReadKey(<redacted>)`), with no `Display`. No client header, cookie or
  credential is forwarded: apart from what the HTTP client adds to every request
  (`host`), the node receives only `Accept` and, for corpus reads,
  `Authorization`. No node header is returned. The HTTP client ignores
  environment proxy settings (`no_proxy`) and follows no redirect, so the key
  cannot be sent to a host it was not issued for. The gateway logs no request
  lines, paths or client addresses.
- **Writes are unreachable.** The method guard refuses everything but GET, HEAD
  and OPTIONS. The gateway only ever issues `GET`. Only the five read paths are
  mapped; no route reaches `/v1/candidates`, `/v1/bodies` or `/v1/export`. The
  binary has no `cc-node`, `cc-ledger` or `sqlx` dependency (the tests use them
  as dev-dependencies). The read key is
  refused on write routes by the node anyway.
- **Path confusion.** Path parameters are sanitized (see [Contract](#contract-public-v1));
  the node origin has no path, query or userinfo; paths come from a fixed list.
- **Fail closed.** Any node answer outside the contract is 502; an unreachable
  node is 503. No misconfiguration boots.
- **Per-client limits**, a bounded client table, Fly concurrency, a body cap and
  an upstream timeout, as in [Abuse limits](#abuse-limits).

### Not mitigated

- **A compromised gateway holds the read key** and can read everything the read
  key can. That is the same data the gateway publishes, but it can also serve
  falsified data and reach the node directly over Flycast. Revoking it means
  rotating the node read key (see [Disable](#disable)).
- **Volumetric DDoS** beyond per-IP limits is Fly's edge and the owner's
  concern. **Owner decision:** spend and traffic caps.
- **The per-IP limit is evadable** by many addresses. IPv6 is keyed per /64, so
  a client with a larger allocation gets one bucket per /64.
- **The client IP header is trusted** only because Fly Proxy sets
  `fly-client-ip` on every request it forwards. A peer that reaches the gateway
  over the private network, not through Fly Proxy, can set any value. Without
  the header, every client behind the proxy would share one bucket.
- **Uncached reads cost the node a full fold.** Each probe and each miss is a
  full snapshot fold on the node. Varying `as_of`, subject ids or query
  spellings forces misses, bounded only by the per-IP rate, the number of
  addresses and the two concurrency limits. A flood of distinct keys also
  evicts popular entries, so their next reads miss too.
- **Staleness.** Up to one freshness window after an admit, the previous
  corpus's answers may be served.

## Owner decisions

- **Whether to expose the corpus publicly at all.**
- **Which read key.** The node accepts exactly one read key,
  `CC_NODE_READ_KEY` (`read_key: Option<KeyDigest>` in
  `crates/cc-node/src/config.rs`); the gallery, beta and telemetry keys open no
  v1 route. A dedicated gateway key is therefore not possible without a node
  change. The gateway shares the node's read key with every other holder of it. Options: share the current key,
  or rotate it first and redistribute the new value. Either way, revoking the
  gateway means rotating the key for everyone.
- **IPv4.** The template allocates no IPv4; IPv4-only clients cannot reach it.
- **Region, rate, freshness, VM size and concurrency** in
  [deploy/public/fly.toml](../deploy/public/fly.toml).
- **A custom domain**, out of scope here.

## Enable (owner, from the workstation)

After review, from the repo root of a clean checkout of the reviewed commit.
`<public-app>`, `<node-app>` and `<org>` are placeholders; edit them into
`deploy/public/fly.toml` first. The key value comes from a private file and
never appears in argv or shell history.

```sh
# 1. The node's Flycast address (CICD-FLY.md: it should already exist).
fly ips list --app <node-app>
# Only if no private IPv6 is listed:
fly ips allocate-v6 --private --app <node-app>

# 2. The gateway app, in the node's organization (Flycast is org-private).
fly apps create <public-app> --org <org>

# 3. The read key, staged through stdin.
printf 'CC_GATEWAY_READ_KEY=%s\n' "$(cat <PRIVATE_DIR>/node-read-key)" \
  | fly secrets import --app <public-app>
fly secrets list --app <public-app>

# 4. Deploy one machine with no public IPs.
fly deploy --config deploy/public/fly.toml --dockerfile deploy/public/Dockerfile \
  --app <public-app> --no-public-ips --ha=false
fly ips list --app <public-app>      # must list nothing
fly status --app <public-app>
```

At this point the gateway runs and nothing outside the organization can reach
it. The **one command** that opens public ingress:

```sh
fly ips allocate-v6 --app <public-app>
```

## Verify

```sh
PUBLIC_BASE=https://<public-host>
curl -fsS "$PUBLIC_BASE/public/v1/health" | jq 'has("instance")'      # false
curl -sSi "$PUBLIC_BASE/public/v1/snapshot" | grep -i '^x-cache'         # miss
curl -sSi "$PUBLIC_BASE/public/v1/snapshot" | grep -i '^x-cache'         # hit, same digest
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$PUBLIC_BASE/public/v1/snapshot"       # 405
curl -sS -o /dev/null -w '%{http_code}\n' "$PUBLIC_BASE/v1/export"                        # 404
curl -sS -o /dev/null -w '%{http_code}\n' "$PUBLIC_BASE/public/v1/receipts/<event>"       # 404 until G4
curl -sSI "$PUBLIC_BASE/public/v1/health" | grep -i '^authorization'     # nothing
```

The second `snapshot` is a hit only if no admit happened in between and the
cache had room. Each line spends one of your own rate-limit tokens.

## Disable

The **one command** that removes public ingress immediately, with `<ipv6>` the
public address `fly ips list --app <public-app>` shows:

```sh
fly ips release <ipv6> --app <public-app>
```

To stop serving as well: `fly scale count 0 --app <public-app>`. Neither
removes the read key from the app's secrets. If the gateway machine or app may
be compromised, revoke the key by rotating the node's `CC_NODE_READ_KEY` (a node
secret change restarts the node, and every other read consumer needs the new
value), then `fly apps destroy <public-app>`.
