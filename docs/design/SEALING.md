# Sealing and anchoring v1 commitments

Status: design options only. Nothing here is implemented. An owner decision is
required. Refs #6.

This note lists ways to bind v1 commitments to an order and a time. It decides
nothing. The question for the owner is at the end.

## What exists today

| Artifact | What it binds | Limit |
| --- | --- | --- |
| `corpus_digest` | SHA-256 over the framed `cc.corpus.v1` domain, a count, and the sorted IDs of every retained candidate, pending and invalid included | Recomputed per read; nothing records past values |
| `commitment` | `view_commitment`: SHA-256 over the framed `cc.view.v1` domain, canonical encoding version, fold version and manifest, `filter_version`, corpus digest and canonical projection rows | As above |
| Every projection read | Names `rule`, `corpus_digest` and `commitment` | A reader learns the current values only |
| `GET /v1/export` | `ExportManifest`: rule, corpus digest, commitment and every envelope | Restore recomputes both digests and refuses a mismatch before admitting |
| Node receipts | With `CC_V1_NODE_SEED` set, a signed `NodeReceiptV1` per first admission, with `received_at` in Unix microseconds | One event, one node clock; no corpus state |
| Append-only triggers | `cc_v1` tables refuse `UPDATE`, `DELETE` and `TRUNCATE` | A database owner can drop a trigger; this guards against accidents, not the operator |
| Verified backups | A dump and a local restore check | Proves bytes, not time; held by the same operator |

The legacy v0 node had an anchoring path. `cc-anchor-tick` sealed an RFC 6962
Merkle root over the v0 log, recorded it as a signed v0 moment, submitted it to
an OpenTimestamps calendar, and later upgraded `Pending` to `Confirmed`. Pending
is a calendar's promise, not Bitcoin inclusion. Confirmation recorded the block
height the calendar's proof asserted; no code checked it against Bitcoin block
headers. v1 launched without the tick ([STAGE-F](STAGE-F.md)). Nothing in v1
seals or anchors.

## What is missing

- Nothing binds a commitment to a time.
- Nothing records which commitment was served, or when.
- An operator, or anyone holding the database, can build a different store that
  is internally consistent and re-serve it. Every digest then verifies against
  itself. Only a reader who saved an earlier value can tell.
- Receipts attest that the node saw an event. They do not attest corpus state.
  A receipt a reader saved is evidence that the event existed; a reader who saved
  nothing has nothing.
- A backup is evidence of bytes, not of time or uniqueness.

## Threat model

| Threat | Description | Detected today |
| --- | --- | --- |
| Equivocation (fork) | Serve different, internally consistent stores to different readers, or at different times | Only by readers who compare saved values |
| Rollback or truncation | Revert to an earlier store, or drop the most recent events | Only against a saved later value |
| Deletion | Remove one inconvenient candidate and re-serve | Only against a saved earlier value or receipt |
| Node key compromise | Forge receipts, and seals if the same key signs them | No; the node key has no revocation path |
| Seal key compromise | Forge or fork the seal log | Not applicable today |

Curator key compromise is an authority matter, handled by Revoke under fold v1
([MULTI-SIGNER](MULTI-SIGNER.md)). It is not a sealing matter.

Sealing does not prove:

- that any content is true;
- that history before the first seal is complete;
- that no parallel, unsealed store exists, for example under another instance;
- that any reader actually checked.

At best, sealing makes a later rewrite detectable to whoever holds an earlier
seal, and an external anchor bounds when that seal existed.

## Option A: signed seal log

The node signs a seal record, either per admission or on a schedule:

`(instance, rule, corpus_digest, commitment, previous seal digest, sequence, time)`

- Each seal names its predecessor's digest, so the log is a hash chain.
- `time` is the signer's clock, in Unix microseconds, like `received_at`.
- Seals are retained append-only, carried by backups and served read-only.
- The signer is the node receipt key or a separate seal key.

What it proves: the signer asserted this commitment at this position in its
chain. A rollback or deletion breaks the chain for anyone who holds an earlier
seal.

Costs:

- A new signed record type and domain. That is a new canonical record with its
  own vectors: new encoding work, not a change to fold v1.
- New storage. `Store::open` checks a stored schema hash of the v1 bootstrap
  and refuses any relation outside `cc_v1`. A new table therefore needs a
  governed schema-upgrade step; a file or a separate store avoids that.
- Key management for whichever key signs.

Risks:

- Only as strong as the key holder.
- The operator can sign two chains. Without external witnesses, a reader shown
  one chain cannot see the other.
- A seal must never enter a commitment. A commitment that covered seals would be
  circular and would change fold v1 outputs.

## Option B: transparency log

Append seal heads, or commitments, to a Merkle append-only log. That log can be
a public one (Certificate Transparency style, Trillian, Sigsum) or self-hosted.
It publishes signed tree heads, inclusion proofs and consistency proofs.
Ideally, independent witnesses cosign tree heads. The legacy `cc-anchor` crate
already implements RFC 6962 inclusion and consistency proofs for v0.

What it proves: every reader who checks against witnessed tree heads sees one
history. Equivocation then needs collusion between the log and its witnesses.

Costs:

- Higher operational burden: a log service or a third-party log, plus a witness
  network.
- More code. Proof verification is also needed in the browser verifier.
- Publication: only digests are logged, never content. Even so, digests reveal
  the timing and rate of change.

Risks:

- Dependence on an external log's availability and admission policy.
- Coordinating witnesses.
- It still proves only what was logged.

## Option C: external timestamping

Stamp a digest with OpenTimestamps over Bitcoin, or with an RFC 3161 timestamp
authority (TSA).

For v1 this means:

1. Stamp the seal-log head, or the bare commitment if there is no seal log.
2. Store the proof beside the seal or the backup.
3. Upgrade `Pending` to confirmed later.
4. Verify confirmation against Bitcoin block headers, which v0 never did.

The submission can run on the node, which then needs network egress, or as a
one-command step on the owner's workstation.

Costs:

- Low per stamp.
- Latency: Bitcoin confirmation takes hours.
- An external dependency and network egress.
- RFC 3161 needs trusted TSA certificates, and a story for their expiry and
  revocation.

Risks:

- A timestamp proves that bytes existed by a time. It does not prove uniqueness
  or truth: two forks can both be stamped.
- Confirmation latency, and calendar or TSA availability.

## Combining the options

A seal log (A) is what B and C would anchor efficiently. Stamping or logging one
seal head covers every commitment before it, so per-event anchoring is not
needed. A phased path is possible:

1. A, a seal log.
2. Then C, a periodic external timestamp of the seal head.
3. Then B, if public multi-party verification matters.

The minimal path stops at A, or at nothing. The stronger path goes through B.
Neither is recommended here.

| | No sealing (today) | A seal log | A + C timestamp | A + B log and witnesses |
| --- | --- | --- | --- | --- |
| Proves | Only what a reader saved | The signer's ordered assertions | Also: each sealed head existed by a time | Also: one history across readers |
| Must be trusted | The operator | The seal key holder | The seal key holder; Bitcoin or the TSA | The seal key holder; the log and witnesses not all colluding |
| Cost | None | Small | Small, plus stamp handling | Higher |
| Operational burden | None | Key custody | Plus upgrade and verification runs | Plus a log service and witness coordination |
| New external dependency | None | None | A calendar or TSA, and a block-header source | A log and witnesses |
| Effect on fold v1 | None | None | None | None |

## Constraints any option must keep

- Fold version 1 stays frozen. No commitment changes.
- Receipts and seals never enter a commitment, a corpus digest or an export
  root.
- No agent makes production writes or deploys.
- Anything run against production is a one-command step on the owner's
  workstation.
- No external anchoring is implemented in Stage (g) G4.

## Owner question

Which of these should v1 do?

1. No sealing for now.
2. A signed seal log only.
3. A seal log anchored by external timestamping. If so, which service:
   OpenTimestamps over Bitcoin, or a named RFC 3161 TSA?
4. A seal log plus a transparency log with witnesses.

If any sealing is chosen:

- Which key signs seals: the node receipt key (`CC_V1_NODE_SEED`), or a separate
  seal key?
- How often: per admission, or periodic (and at what interval)?
