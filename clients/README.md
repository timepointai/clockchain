# Clockchain v1 public clients

Typed clients for the G5 public read API, `/public/v1`
([STAGE-G.md](../docs/design/STAGE-G.md), G5). That API is unauthenticated,
GET-only, and its JSON equals the node's v1 read routes minus `instance`.

| Route | Python | TypeScript |
|---|---|---|
| `GET /public/v1/health` | `health()` | `health()` |
| `GET /public/v1/snapshot` | `snapshot(fold_version, fold_manifest)` | `snapshot(foldVersion, foldManifest)` |
| `GET /public/v1/subjects/{id}?as_of=` | `subject(id, as_of)` | `subject(id, asOf)` |
| `GET /public/v1/revisions/{rev}/prose` | `prose(rev)` | `prose(rev)` |
| `GET /public/v1/support?from=&to=&as_of=` | `support(from_, to, as_of)` | `support(from, to, asOf)` |
| `GET /public/v1/receipts/{event}` | `receipt(event)` | `receipt(event)` |

`receipt(event)` returns the node's receipts for one admitted event, typed as
`{event, receipts}`. Each receipt is a G4 `NodeReceiptV1`: the signed bytes as
hex (`receipt`), their SHA-256 (`receipt_digest`, checked by the client), the
node key, the event, `received_at` (Unix microseconds when the node saw the
event, not a historical time) and the decoded admission result. The clients
do not verify the node's signature; the bytes are what a verifier checks. An
event the node holds no receipt for answers `404 no_receipt`. That includes
every event on a node without a receipt key (`CC_V1_NODE_SEED`).

## Guarantees

Both clients do the following:

- **They send no credential.** Requests carry only `Accept: application/json`.
  No option exists to add a token, and cookies are omitted.
- **They refuse redirects.** A 3xx response is an error, so every answer
  comes from the URL that was asked.
- **They use no proxy from the environment.** The Python transport ignores
  `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and the rest. Node's `fetch` reads
  them only when `NODE_USE_ENV_PROXY` is set; leave it unset.
- **They check arguments before sending.** Ids, hashes and `as_of` must be
  exactly 64 lowercase hex characters. The two fold parameters go together or
  not at all.
- **They fail closed.** A response is refused with `ProtocolError` if it:
  - is not a JSON object;
  - lacks a required field or has a field of the wrong type;
  - carries a malformed hash;
  - answers for a different subject, revision, `as_of`, endpoint pair or
    pinned fold than the one requested;
  - has a status and visibility that disagree, or prose and availability that
    disagree;
  - serves a revision for a subject that is not visible;
  - has a support verdict other than `Supported` or `Unsupported`;
  - (for `/health` only) carries an `instance` or a `ledger` other than `v1`.
- **They return typed refusals.** A refusal such as `{"error":"invalid_query"}`
  becomes `PublicApiError(status, error)`, never an empty result.
- **They pass on `Retry-After`.** The gateway limits each client address
  (60 requests a minute by default). Over the limit it answers
  `429 {"error":"rate_limited"}` with a `Retry-After` header in seconds.
  The error carries it as `retry_after` (Python) or `retryAfter`
  (TypeScript), an integer, or null when the header is absent. Wait at least
  that long before the next request. Both clients also read the HTTP-date
  form.
- **An unknown subject is a read, not an error.** The 404 for an unknown
  subject carries a complete read, which is returned with `known` false.

What they do not do:

- **They do not verify anything.** A `corpus_digest` or `commitment` read
  through these clients is what the server answered, not a recomputation.
  Independent verification is G6's `cc-wasm-verify`.

## Formats

Direct hashes are lowercase hex. Projection objects in a snapshot keep the
node's canonical form, where a hash is a list of 32 byte values. The clients
convert the parts they type to hex: revisions, support paths and reasons, and
the subject summaries. The rest of a snapshot is returned as served.

`summarize_subjects` / `summarizeSubjects` lists each subject of a snapshot
with the subject key its Genesis signed (kind, namespace, value) and, for a
resolved subject, its current revision. There is no search route, so
consumers filter this list.

Coordinates (`as_of`, asserted times) are `cc_core::Tick::to_canon_bytes`:

- whole seconds since J2000.0, shifted left 64 bits;
- 256-bit two's complement, big-endian;
- top bit flipped.

The helpers convert to and from them: `coordinate_from_seconds` (the legacy
node's decimal `as_of`), `coordinate_from_date` (the same encoding as
`cc-publisher v1 genesis --asserted-time`), and their inverses. The tests pin
them to the publisher's own anchors in `crates/cc-publisher/tests/v1_offline.rs`.

## Python (`clients/python`)

The Python client uses only the standard library and needs Python 3.10 or
later. `PublicClient` blocks. `AsyncPublicClient` takes your async transport
`(url, headers) -> (status, response_headers, body)`. It must send a GET with
exactly those headers, must not follow redirects, and should not take a proxy
from the environment. `response_headers` maps lowercase names to values; only
`retry-after` is read. Both share the sans-IO calls
(`subject_call`, `parse`, and the rest).

```python
from clockchain_public import PublicClient, coordinate_from_date

c = PublicClient("https://public.example.invalid")
h = c.health()
s = c.subject(SUBJECT_HEX, as_of=coordinate_from_date(1969, 12, 31))
if s.known and s.revision:
    print(c.prose(s.revision.id).prose)
```

```sh
python3 -m unittest discover -s clients/python/tests -t clients/python
```

## TypeScript (`clients/typescript`)

The TypeScript client is ES modules with no runtime dependencies. It needs Node
22.18 or later, which runs `.ts` by type stripping, or any bundler. It also
runs in a browser, where `fetch` uses `redirect: "manual"` and
`credentials: "omit"`. Its methods are async. Ids and hashes are always
strings, never numbers.

```ts
import { PublicClient } from "./src/index.ts";
const c = new PublicClient("https://public.example.invalid");
const read = await c.subject(subjectHex);
```

```sh
cd clients/typescript && npm ci && npm run typecheck && npm test
```

## Fixtures

`fixtures/v1/*.json` hold what the merged G5 gateway answered in front of a
real v1 node:

- `cc-node` runs over a throwaway local PostgreSQL database holding two
  synthetic Genesis entries admitted with `cc-publisher v1`.
- `cc-gateway` sits in front of it and holds the node's read key.
- Each fixture is the request, status, kept headers (`retry-after`) and body.
- `rate_limited.json` is a real 429 from a second gateway allowed one
  request a minute.
- `receipt_no_receipt.json` is the `404 no_receipt` from the main node,
  which runs without `CC_V1_NODE_SEED`.
- `receipt.json` is a real 200 from a second node, given a synthetic
  receipt seed, that admits the same entry A.
- `fixtures/v1/_meta.json` lists the synthetic entries and the fixture index.
- `/health`'s `build` is the label the recording binaries were built with.

`fixtures/legacy-probes.json` records what the same node answers on the legacy
routes that consumers still call (see [INTEGRATIONS.md](../docs/INTEGRATIONS.md)).

```sh
CC_BUILD_REV=g7-synthetic-fixture cargo build -p cc-node --bin cc-node
cargo build -p cc-publisher --bin cc-publisher -p cc-gateway --bin cc-gateway
python3 clients/fixtures/record.py               # re-record through cc-gateway
python3 clients/fixtures/record.py --check       # CI: fail on any drift
python3 clients/fixtures/record.py --node-only   # node minus instance, no gateway
```

`--check` ignores three values that vary between runs:

- `/health`'s `build`;
- `_meta.json`'s `source`;
- the exact `retry-after` seconds, which must still be a positive whole number;
- a receipt's `received_at`, signed bytes and digest. The digest must still
  be the SHA-256 of the bytes, and the time a positive whole number.

Everything in the fixtures is synthetic:

- The curator seed, the node receipt seed and the instance are SHA-256 hashes
  of public labels in `record.py`.
- The node credentials are random for each run and never written.
- The local node and gateway listen on loopback and are stopped when
  recording ends.
