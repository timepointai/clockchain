# Clockchain explorer

A static, read-only explorer for the public read API (`/public/v1`, served by
`cc-gateway`), with an in-browser verifier built from
[`crates/cc-wasm-verify`](../../crates/cc-wasm-verify).

No framework, no build-time network fetches and nothing loaded from another
origin at runtime. The page is plain ES modules, one stylesheet, the verifier's
`.wasm` and a copy of the pinned TT taxonomy.

## Views

| View | Route | Reads |
| --- | --- | --- |
| Subjects | `#/` | `health`, `snapshot` |
| Subject: claim (prose), subject key, asserted time, revisions, frontier, events, edges, media, `as_of` | `#/subject/{id}` | `subjects/{id}?as_of=`, `revisions/{rev}/prose` |
| Causal DAG, whole corpus or one subject | `#/dag`, `#/dag/{id}` | `snapshot` |
| Edges and support query | `#/edges` | `snapshot`, `support?from=&to=&as_of=` |
| TT kind path of a subject's kind | `#/kind/{id}` | verifier tables, `taxonomy-v2.1.json` |
| Verify in your browser | `#/verify` | `health`, `snapshot`, optional export file |

Every page that displays a subject, prose or support read also passes that
read's exact response text, with the snapshot, to the verifier and shows the
result next to it: displayed prose is marked as hashing to its committed body
only when that check passed. Served strings reach the page only as text nodes
and attribute values. Asserted
times are rendered from their coordinates (proleptic Gregorian, astronomical
years, the publisher's `--asserted-time` mapping) for display and to build
`as_of` queries; the node decides visibility.

## What "Verify in your browser" checks

The module recomputes, from the served text:

- each row's canonical event id, from its envelope;
- signatures, only when signed bytes are supplied (an export manifest file);
  `/public/v1` serves envelopes without signatures, so without one the check is
  reported **not checked**, never passed;
- the corpus digest, from all served rows;
- `filter_version`, from the served curator keys and `max_hops`, this build's
  `fold_version` 1 and the pinned TT taxonomy hash;
- the view commitment, over the canonical `cc.view-rows.json.v1` bytes rebuilt
  from the served snapshot;
- on each page, that the reads shown name the snapshot's rule, corpus digest and
  commitment; a subject read's state, frontier, `as_of` visibility and revision
  are recomputed from the snapshot rows, and served prose must hash to its
  revision's body.

The projection readings are parsed strictly (no unknown or repeated fields),
and the whole snapshot is compared with its canonical re-encoding as JSON
values, which catches unknown keys at any depth. Whitespace, key order and
string escapes are not part of the commitment and are not checked.

A subject page shows prose as the subject's claim only when the snapshot
verified, the subject read answers the subject and `as_of` that were
requested, and the prose read is for that read's current revision and hashes
to its committed body.

It does **not** re-run the fold. Admission states, frontiers, revision
selection, authority, edge and media readings, and support verdicts (with
their `as_of` exclusions) are checked only for consistency with the commitment. A node that
folded wrongly but committed to its wrong rows passes. Re-running the fold in
the browser needs a wasm-clean projection crate, which is a future owner
decision. The page shows the module's own statement of these limits
(`cc_about`), not a paraphrase.

**Trust anchor.** The verifier does not authenticate the gateway or the
origin of the corpus: `/health`, the rule, the curator keys, the corpus digest
and the commitment all come from the same server. Without a signed export the
envelopes' signatures are unchecked, so a hostile server can serve a fully
self-consistent forged corpus under curator keys it names and still reach
**partial**. Even **verified** (with an export) means internal consistency
under the keys the server names. Authorship needs an export obtained out of
band, and the served curator keys compared with the owner's independently
published keys. An empty corpus, or an export with no envelopes, is reported as
**not checked** ("nothing to verify"), never as a pass.

The Subjects, Causal DAG, Edges and TT views render the served snapshot
directly and carry a banner with its verification state: "Not verified yet"
until a run, then that run's outcome for the same snapshot.

The verifier is only as independent as the module you run. To check with your
own build, run `cargo build -p cc-wasm-verify --target
wasm32-unknown-unknown --release` from source and load the `.wasm` through the
page's file input.

## Build and run

```sh
web/explorer/build.sh                      # dist/ for a same-origin /public/v1
web/explorer/build.sh --api-base https://<gateway-origin>/public/v1
web/explorer/build.sh --fixture            # include the synthetic fixture
```

`--api-base` on another origin is also written into the page's `connect-src`.
Serve `dist/` as static files with `application/wasm` for `.wasm`. With
`--fixture`, open `index.html?fixture=synthetic` to browse the recorded
synthetic fixture without a gateway; it answers only recorded reads.

## Tests

```sh
cargo build -p cc-wasm-verify --target wasm32-unknown-unknown --release
node --test web/explorer/test/*.test.mjs   # CI runs this
web/explorer/build.sh --fixture && node web/explorer/test/browser-smoke.mjs  # local, needs Playwright
```

`browser-smoke.mjs` also serves a tampered prose response and requires the
page to flag it. `fixtures/synthetic/` is recorded from the real v1 node over PostgreSQL by
`crates/cc-wasm-verify/tests/fixture.rs`, which fails whenever the node would
now serve something different. Re-record with
`CC_RECORD_FIXTURE=1 cargo test -p cc-wasm-verify --test fixture`. All of it is
synthetic: fictional subjects, test keys, a synthetic instance. `health.json`
omits `instance`, as the gateway contract does, and pins `build` to a fixed
string so the recording is stable; `export.json`
is the node's owner-scoped export, included only as the optional signature
input.
