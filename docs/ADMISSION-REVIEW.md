# Admission and read-only review

These are software contracts in this checkout. They do not report deployment or
authorize generation, staging, signing or publication.

## Frozen subjects and edge endpoints

New candidate edges must include `binding` on both `from` and `to`: exact decimal
`entity_id`, full `claim_identity` hash, `body_hash`, and declared `subject_kind`.
The body hash uses the publisher's `claim_v4` serialization. Subject kind comes
from `prov_asserted.subject_kind`; missing declarations remain null. This field
does not define TT taxonomy or infer a subject from prose.

Admission rejects missing bindings (`edge_binding_missing`), identity mismatches
(`edge_target_mismatch`), and changed destination/source bodies or kinds
(`destination_subject_changed` / `source_subject_changed`). The check runs during
validation, staging, approval and publication. Existing ledger subjects also
cannot change declared kind under the same identity (`subject_identity_reused`),
or acquire a different incident-edge body under an existing identity. Publication
rechecks under the existing projection lock. Endpoint bindings are retained in
the independently signed edge-evidence record.

`validate --base /private/frozen.json --path /private/proposed.json` additionally
compares the frozen subjects before and after, even if someone recalculates edge
bindings. A changed subject must use a separately reviewed content-derived
title/year identity and new relationships. Existing identity algorithms, event
bytes and applied migrations are unchanged. These checks enforce exact declared
subjects and bytes; they do not semantically classify prose or establish truth.

Generation attaches bindings only to newly model-authored edges, using Rust's
read-only `edge-bindings` calculation after measured claim fields are final.
Existing bindings are never silently refreshed. The calculator emits measurements,
not an admitted proposal. Old unbound private proposals remain readable but are
not eligible for new admission; do not rewrite frozen fixtures to upgrade them.

## Terminal attempts

`cc.generation-result.v1` has a closed status set: `proposal`, `media_plan`,
`needs_evidence`, `abstained`, `conflicting_evidence`, `failed`. New completed
receipts carry `terminal: true` and `retry_allowed: false`. A non-proposal evidence
result requires a reason and contains no candidate records. It writes a result
receipt, never an empty or repaired `proposal.json`.

Repeating the same completed non-proposal attempt returns its retained receipt
without accessing the model route, credentials, budget or transport. It does not
alter any file. Existing v1 terminal receipts remain readable without rewriting.
Malformed receipts fail closed. Interrupted attempts without a terminal receipt
are not restarted automatically.

New evidence after `needs_evidence` requires a new output directory and explicit
invocation with `--after /private/previous-attempt`. The runtime checks changed
captured evidence/passages; renamed files and metadata changes are insufficient.
New `needs_evidence` completions also record an evidence fingerprint in the shared
registry, preventing the same base/evidence from being retried under another
output directory. There is no automatic replacement or paid retry.

## Dry-run

```sh
cc-publisher dry-run --path /private/proposal.json \
  --brief /private/brief.json --attempt /private/attempt/result.json \
  --exclude-media
```

This prints `cc.admit-set.v1`: exact entity/claim/body hashes, proposed edge hashes
and endpoints, media or none, and blockers. A `needs_evidence` result prints the
set for inspection and exits nonzero with `dry_run_blocked`. A proposal receipt
must match the exact candidate file. `--exclude-media` computes a claims-only
inspection set without changing the file, reporting both input and inspected-set
digests. It does not override an images-required brief.

Edge proposal hashes are not signed event IDs: those are assigned only during
the owner's publication operation. Even `ready_for_owner_review` is not approval,
proof of historical adequacy, or a check of live database heads. Dry-run never
opens a database or signs, stages, approves, publishes, redirects credentials or
writes an absence decision. No write controls exist in the browser.

## Node review and media

The entity response returns each reading's exact retained `body` string beside
`body_hash`, with `body_status: retained` or `unavailable`. The browser displays
only those node bytes, escaped as text. Missing prose stays explicitly unavailable;
the local fixture is never consulted to reconstruct a deployed claim.

`/v2/media` returns only readings with admitted media records. A claims-only set
has `readings: []`, even when claim bodies exist. A nonempty media reading is
`generated`, `deliberately_unillustrated`, or `conflicting_media_records`; absence
requires a signed decision. Private files and failed reads cannot create one.
Stale bindings and conflicting records remain visible. No migration or deletion
of existing media records is required by this read change.
