# Authoring v1 content

How v1 content beyond a Genesis is built, reviewed, approved and submitted
with `cc-publisher v1`: corrections, edges, attestations and whole entry
packets. The contract is the G3 section of
[STAGE-G.md](design/STAGE-G.md); the Genesis flow, key files, tokens and node
URL rules are in [PUBLISHER-V1.md](PUBLISHER-V1.md) and apply unchanged.

Nothing here authorizes publication. [HOLD.md](../HOLD.md) still governs:
only the owner holds the curator key, approves a packet and submits it. The
tooling does no generation, calls no model and never reads or processes an
image; an artifact is named only by its SHA-256.

## The flow

```sh
# 1. Online, read only: save the node's verified corpus.
CC_NODE_API_KEY=... cc-publisher v1 context --node https://node.example --out ctx.json
# 2. Offline: build one packet against it (one of these).
cc-publisher v1 correction --key K --context ctx.json --subject S --revision R \
  --body new.txt --rationale "..." --evidence H --out pkt/
cc-publisher v1 edge assert --key K --context ctx.json --relation influence \
  --source S1 --source-revision R1 --target S2 --target-revision R2 \
  --rationale "..." --evidence H --out pkt/
cc-publisher v1 edge reaffirm --key K --context ctx.json --edge E \
  --source-revision R1 --target-revision R2 --rationale "..." --evidence H --out pkt/
cc-publisher v1 attest --key K --context ctx.json --revision R \
  --artifact-kind image/png --artifact-sha256 A --out pkt/
cc-publisher v1 entry --key K --context ctx.json --manifest manifest.json --out pkt/
# 3. Offline: the owner reviews the packet and notes its digest.
cc-publisher v1 review-packet --dir pkt/ --context ctx.json
# 4. Online: the owner submits exactly the approved packet.
CC_NODE_API_KEY=... cc-publisher v1 submit-packet --node https://node.example \
  --dir pkt/ --approve PACKET_DIGEST
```

No build command contacts a node or submits anything. Only `context` and
`submit-packet` use the network, both with the write token from the
environment (`GET /v1/export` is a write-scoped route). Words in capitals are
placeholders.

## Context

`context` reads `/health` and `GET /v1/export` and writes a new file (mode
0600; an existing file is never replaced) holding the instance and the
export's verified fields, unchanged: `encoding`, `rule`, `corpus_digest`,
`commitment` and `envelopes`. Anything else the node sends is dropped. The
node's fold must equal this build's `fold_v1()`.

Every builder loads the context and checks it before use: each envelope
decodes canonically with a valid signature, belongs to the instance, appears
once, and the set of event ids hashes to the export's corpus digest. All
readings then come from `cc_ledger::v1::project`, the node's own fold.
Before a packet is written, its events are classified with
`cc_ledger::v1::classify` over the context plus the packet; anything but
`valid` is refused.

A pin, a correction parent and a reviewed revision always mean the subject's
**current reading**: state `resolved` with exactly one frontier head. An
unknown, contested or `no_current_body` subject is refused; resolve it first.

## Commands

All builders take `--key` (a seed file, as in `genesis`), `--context` and
`--out` (absent or empty). Signed free text (`--rationale`, a source
`locator`) must be nonempty, at most 64 KiB, without leading or trailing
whitespace, without control characters other than newline, and without the
invisible or bidirectional characters `genesis` refuses. Every decision cites
at least one `--evidence` SHA-256 (64 hex; sorted; duplicates refused).

### correction

Replaces the body of subject `--subject`. `--revision` is the current
revision the author reviewed; if the subject has moved, the command refuses
and names the current one. The parent is the single head, the old body is
the current body, and the new body (`--body`, the `genesis` body rules) must
differ. The grant is the one active grant the signing key holds for the
subject (the root grant for its creator, or a delegated grant); pass
`--grant` if it holds several. `--asserted-time` is optional; when omitted,
the current revision's asserted time is carried, and the packet shows it.

### edge assert

Signs an `EdgeAssert` between two different subjects with one of the five
governed relations: `causation`, `co_occurrence`, `disputes`, `influence`,
`participation`. Any other name is refused.

- **Both endpoint pins.** `--source-revision` and `--target-revision` are
  both required. Each endpoint is pinned to `(subject, basis = its single
  head, revision, body)` from the context, and each reviewed revision must be
  that current revision, or the command refuses with `source_subject_changed`
  or `target_subject_changed`.
- **Disputes.** A `disputes` edge is a counterclaim: it is signed only by the
  creator (Genesis author) of its source subject, and never joins a subject
  to itself. A dispute is evidence, never support; the node excludes it from
  every support path (`disputes_not_support`).
- **Trust.** Support counts an edge only if its author and both endpoint
  creators are in the node's curator set. A delegated key outside that set
  can correct a subject but its edges are never support.
- Same-subject edges are refused: they never support anything.

### edge reaffirm

Re-pins an existing edge (`--edge`, its `EdgeAssert` id) after an endpoint
moved, which makes the edge `stale`. Only the original author may reaffirm.
The parents are all current heads of the edge's chain, each with its old
pins; the endpoints stay fixed; both new pins are current pins, with both
reviewed revisions required as above.

### attest

Signs an `Attestation` exactly as `cc.event.v1` encodes it: `--revision R`
(revision-scoped) or `--event E` (event-scoped: a valid subject or edge
event; never an attestation), an `--artifact-kind` (subject-key value rules)
and `--artifact-sha256`. The artifact itself is never read. The node binds an
attestation to the named revision, or to the revision its target event
created, and a later correction never moves it; `attest` prints which
revision it is bound to.

**Signed absence is not expressible in v1.** An attestation always names an
artifact hash, and the fold infers nothing from a missing one
(`media.inference=none`). There is no field or kind that records "this
revision deliberately has no image", and inventing an `artifact_kind`
convention would be a new encoding. `attest` therefore has no absence form.
A signed absence decision needs a future fold version and an owner decision.

### entry

Builds every envelope of one new entry from a manifest: the Genesis, then
each edge, in manifest order.

```json
{
  "schema": "cc.publisher.v1.entry",
  "instance": "INSTANCE_HEX",
  "subject": {"kind": "TT_NODE_ID", "namespace": "NAMESPACE", "value": "VALUE"},
  "asserted_time": "YYYY-MM-DD",
  "nonce": "64_HEX_CHOSEN_ONCE",
  "body": "body.txt",
  "sources": [
    {"id": "s1", "sha256": "CAPTURE_SHA256", "locator": "Where and which passage.",
     "capture": "captures/s1.html"}
  ],
  "edges": [
    {"relation": "influence", "source": "EXISTING_SUBJECT_HEX",
     "source_revision": "ITS_CURRENT_REVISION_HEX", "target": "entry",
     "rationale": "Why the relation holds.", "sources": ["s1"]}
  ]
}
```

- Unknown fields are refused. Paths are relative to the manifest, without
  `..` or a leading `/`. A symlink is followed, so keep the manifest
  directory free of links you did not make.
- `subject`, `asserted_time` and `body` follow the `genesis` rules. The
  Genesis evidence is the set of all source hashes.
- `nonce` is fixed in the manifest, so the same manifest, key and context
  rebuild byte-identical envelopes and the same packet digest. Choose it once
  from a random source; never reuse one across entries.
- At least one source. Each `sha256` is the SHA-256 of the retained capture.
  When `capture` names a file, its bytes must hash to `sha256` ("capture
  hash mismatch"); without it the hash is declared only, and the build says
  which sources were verified. Captures are never copied into the packet.
- Each edge has exactly one endpoint `"entry"` (the new subject) and one
  existing subject with its reviewed `*_revision`; the entry endpoint takes
  no revision. An edge cites only declared source ids ("support references
  undeclared source"); their hashes become its evidence. Relation, pin and
  dispute rules are those of `edge assert`; a `disputes` edge from an
  existing subject must be signed by that subject's creator.

## Packet format

Every builder writes the same directory:

| Path | Content |
|---|---|
| `events/NN.bin` | Signed `cc.event.v1` envelopes, in submission order |
| `bodies/SHA256.bin` | Each body a Genesis or Correction in the packet signs |
| `manifest.json` | `entry` only: the exact manifest bytes |
| `packet.json` | The review document, below |

`packet.json` (`cc.publisher.v1.packet`) is a pure function of the
envelopes, bodies, manifest and context digest: `command`, `instance`,
`author`, `context` (`corpus_digest`, `events`), `manifest_sha256`,
`sources` (`entry` only: each source's `id`, `sha256`, `locator` and
`capture` path, as the reviewer must read them), one entry
per event with every signed field and derived identifier (event, subject,
revision, edge, pins, decision rationale, evidence, old and new values,
attestation target), `bodies`, and `submitted` and `publication_authorized`,
both `false`. One packet has one author and one instance.

The **packet digest** is the SHA-256 of `packet.json`. Reloading a packet
(`review-packet`, `submit-packet`) decodes and verifies every envelope,
checks every body against its name and the bodies against the events, and
requires `packet.json` to be byte-identical to the recomputed one, and the
directory to hold no other file. For an `entry` packet, the manifest must
say exactly what the events sign: the Genesis instance, subject key,
asserted time, nonce and source set, and for each edge its relation,
rationale, cited sources, endpoints and reviewed revisions. A packet whose
`packet.json` would exceed 1 MiB, the most a reload reads, is never written.
Any edit to any file changes the digest or is refused.

## Review checklist

Run it separately for each event in the packet, and record pass, narrow,
withhold or reject for each. There is no bundle pass. Record the reviewer,
date and packet digest.

1. **Purpose.** Publish now, keep private for stronger sources, or leave the
   node unchanged.
2. **Sources adequate.** Read every cited passage against the retained,
   hash-verified capture. Literal matching does not establish adequacy, and
   repeated use of one source is not corroboration.
3. **Body says only what the sources support.** Separate what a source
   records from inference; label reconstructions.
4. **Relations no stronger than the evidence.** Direction, chronology, type
   and mechanism; keep `influence`, `participation` and `causation` distinct.
   A disagreement is a `disputes` edge from the disputing author's own
   subject, never a weakened positive edge.
5. **Pins are the reviewed readings.** Each reviewed revision in the packet is
   the revision whose body the reviewer read.
6. **Media decision.** An attestation names the exact revision it
   illustrates. Absence cannot be signed in v1; do not encode it.
7. **Scope stated.** What the record is not.
8. **Exact handoff.** Run `review-packet --context` and compare its
   `packet_digest` with the digest recorded at review; `context_matches` and
   `admissible` must be `true` (otherwise `admissible` gives the node rule's
   reason). Any change to any byte needs a new review.

`review-packet` prints `"status": "ready_for_owner_review"`. That is not
approval.

## Owner approval

The owner, and only the owner:

1. Reviews the packet and checklist record, and runs `review-packet` on the
   exact directory.
2. Approves by running `submit-packet --approve DIGEST` with the digest they
   reviewed. No other approval record exists, and nothing else submits.

`submit-packet` then, in order:

1. Reloads the packet; refuses unless its digest equals `--approve`.
2. Reads `/health`: ledger `v1`, not `frozen`, semantic `ready`, this build's
   fold; the instance, an author in `curators`, and a consistent
   `filter_version`. There is no override.
3. Reads the export again and refuses unless the corpus, minus this packet's
   own events, is exactly the packet's context. Anything admitted since the
   context was taken means: fetch a new context, rebuild, review again.
4. Classifies the packet over that corpus with the node's own rule.
5. Stores every body, then posts each envelope in order; each must be
   admitted `valid` (HTTP 201) with the matching event and input digest.
6. Reads `GET /v1/snapshot` back: every packet event is retained in state
   `head`, `superseded` or `branch` (never pending, invalid or absent); the
   status of every edge in the packet is reported.

Steps 1 to 4 only read; a refusal there writes nothing. A rerun after a
partial failure is safe: re-posting an admitted envelope is idempotent, and
the packet's own events do not count as a corpus change. Stdout is a
`cc.publisher.v1.packet-submission` JSON report; the token is redacted from
it and from every error. No receipt file is written; redirect stdout to keep
the report. A directory written by `genesis` still goes through `submit`
([PUBLISHER-V1.md](PUBLISHER-V1.md)).

## A future 1973 claim and influence edge

The 1973 claim, its influence edge and both images are private and held
([HOLD.md](../HOLD.md)). This section only describes how they would be
authored if the owner releases them; nothing here authors them, and no real
value appears in this repository.

1. The owner refreshes the context from the production node.
2. The owner writes a manifest outside this checkout: the 1973 subject key,
   asserted time and a fresh nonce; the body file; one source per retained
   capture, with its SHA-256 and the capture path so the hash is verified.
3. The manifest's one edge joins the new subject (`"entry"`) and the
   existing 1968 subject with relation `influence`, naming the 1968 subject's
   current revision as reviewed and citing only the sources that support the
   influence. The direction is the reviewer's claim and must match the
   evidence; support itself is undirected.
4. `entry` builds the Genesis and the edge, signed with the owner's curator
   key. The edge author and the new subject's creator are then the curator,
   and the 1968 subject was created by the curator too, so the edge can
   count as support.
5. The owner runs the checklist on the Genesis and the edge separately, then
   `review-packet --context`.
6. If approved, the owner runs `submit-packet --approve DIGEST`. Images are a
   separate decision: an `attest` packet per image, bound to the 1973
   revision, after the 1973 entry is admitted. Declining an image is not
   recorded in v1.

## Provenance

The offline parts of the salvage branch's authoring and review flow
(`salvage/live-brief-security-20261001`) were ported, rewritten for v1:

| Salvage piece | Ported as |
|---|---|
| Edge endpoint bindings and `source_subject_changed` / `destination_subject_changed` (`review::check_endpoint`) | Required reviewed revisions on both endpoints; `source_subject_changed` / `target_subject_changed` |
| Sources whose cited URLs must be captured (`source_support`) | Edges cite only declared sources ("support references undeclared source") |
| Capture bytes checked against their recorded hash (`source_window`) | Optional `capture` files verified against `sha256` |
| Digest-bound approval (`approve --digest`) and `dry_run`'s "ready for owner review is not approval", `publication_authorized: false`, `writes_performed: false` | Packet digest, `review-packet`, `submit-packet --approve` |
| `PUBLICATION-GATE.md` checklist | The review checklist above, without image generation |

Not ported: model and image generation, prompt building, image preparation
and checks, the browser and viewer tools, the database-backed staging,
approval and publication path, the v0 claim identity bindings, and every node
change on that branch.
