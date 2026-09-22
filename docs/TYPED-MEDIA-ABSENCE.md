# Typed media absence

Contract: [Telemetry PR #4](https://github.com/timepointai/timepoint-telemetry/pull/4),
`docs/proposals/TYPED-MEDIA-ABSENCE.md`. Sean authorized preparing the contract
and consumer together on 2026-09-12. Merge and deployment are pending; this is
not a report of independent Telemetry verification or live availability.

`GET /v2/media?entity_id=...&as_of=...` returns schema `cc.media-readings.v2`.
It requires full/read credentials. Each exact entity/body reading reports:

| Images | Absence decisions | State |
|---|---|---|
| None | None | `no_generation_recorded` |
| None | Present | `deliberately_unillustrated` |
| Present | None | `generated` |
| Present | Present | `conflicting_media_records` |

Responses retain every signed record and its server admission coordinate. They
never choose a winner or truncate records before calculating state. Missing
media does not imply a queued job, failed attempt or a deliberate choice.
Multiple readings and different entities sharing a body remain distinct.
`/v1/images` keeps its existing `no_image`/`generated` contract unchanged.

The reading set includes current moment bodies whose event coordinate is at or
before `as_of`, plus bodies named by media records admitted by `as_of`. Before
all applicable records, the array is empty. `projection_basis: current` and each
reading's `source_binding` explicitly describe the current projection, not a
reconstruction of the projection at `as_of`. Stale records stay visible; they
do not transfer to a corrected or re-minted body. All media is outside historical
evidence, claim identity, TT envelopes, dedup, near-match and feasibility.

## Recording an explicit decision

`POST /v2/media/absence-decisions` accepts a signed manifest, requires a full
credential and refuses frozen posture. The manifest has exactly `schema`,
`kind`, `source_entity_id`, `source_body_hash`, `writer`, `reason`, and
`decided_at_ticks`. Schema is `cc.media-absence.v1`, kind is
`deliberately_unillustrated`. Entity ID and decision time are canonical decimal
i64 strings; time is whole ticks since J2000 and is writer-declared. Reason
must be nonblank and at most 4096 UTF-8 bytes. Body hash is lowercase SHA-256 hex.

The decision ID hashes the UTF-8 JCS manifest after the domain
`cc.media-absence.v1` plus a NUL byte. Ed25519 signs this 32-byte digest. The
signature authenticates the writer's choice, not consensus or historical truth.
The server locks the source entity/body projection through admission, records
its own admission coordinate and returns the decision ID. Duplicate submissions
are idempotent. A replay after withdrawal is refused. There is no revocation,
automatic resolution, or bulk inference of missing decisions.

`ops/submit_absence.py` signs locally by default. It uses the same `jcs` and
`cryptography` dependencies as the image submission tool and an existing private
32-byte writer seed. For example, with values obtained from an actual reading:

```sh
python3 ops/submit_absence.py --entity-id "$ENTITY_ID" --body-hash "$BODY_HASH" \
  --reason-file reason.txt --decided-at-ticks "$DECISION_TICKS" \
  --writer-key /private/path/writer.seed --output absence.json
```

Adding `--submit` sends the payload using `CC_NODE_API_KEY` to the canonical
node. The output file is created exclusively before the request so a timeout
leaves the exact signed artifact available. Do not create production decisions
without the owner's instruction for those decisions.

## Migration, validation and rollback

Migration `0013_media_absence_decisions.sql` adds an independent provenance
catalog, not a historical event kind. It does not rewrite existing claims,
images or signatures or backfill decisions. Back up this catalog with images.
It deliberately has no FK to mutable projections; withdrawn decisions survive.

The HTTP regression suite exercises the migration on real Postgres, signatures,
all states, as-of boundaries, correction/re-mint, multi-reading and cross-entity
isolation, 51 decisions, frozen posture and legacy compatibility. The credential
matrix covers both routes. A Python JCS/cryptography vector is verified by Rust.
The [image-orphan assertion](IMAGE-INTEGRITY.md) remains a separate failing check.

Before any decisions exist, the application can be rolled back while leaving
the additive table intact. After decisions are admitted, retain a v2 reader or
export the signed catalog for verification while disabling the writer; a rollback
must not make decisions disappear from every inspection surface. Never delete
provenance or edit an applied migration as a rollback.
