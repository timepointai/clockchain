# Image integrity

`GET /health/deep` evaluates the entire attachment catalog against current
moment projections in one SQL snapshot. Its `media` report includes:

- `image_attachment_count`: all admitted attachments, including stale ones.
- `orphan_image_attachment_count`: attachments whose source body is projected
  by no moment. A nonzero count sets `integrity: "fail"` and returns HTTP 503
  with `status: "degraded"`.
- `stale_image_attachment_count`: attachments whose original entity no longer
  projects the source body. This can exceed the orphan count when another
  entity still projects that body.
- `orphan_attachments`: attachment ID, decimal-string entity ID and source body
  hash for every orphan, ordered by attachment ID.

An empty catalog reports a measured zero and `integrity: "pass"`. An unreadable
catalog reports `integrity: "not_run"` and HTTP 503. `/health` remains a pure
liveness check. Neither endpoint repairs or deletes attachments or ledger rows.

Run the same assertion independently with an externally supplied connection:

```sh
CC_DATABASE_URL=postgres://localhost/clockchain python3 ops/check-media.py
```

Exit codes: 0 passes, 1 finds orphans, 2 could not run. `ops/validate.py` includes
this check and refuses an overall pass if it does not run. The checker requires
`CC_DATABASE_URL` and does not fall back to the retired Railway service.

This is a current-projection invariant, not an as-of reconstruction. Both
surfaces execute `crates/cc-node/sql/media-integrity.sql`; changes to a moment
are reflected at the next check. Existing admission locking prevents admitting
an already-unbound source but cannot guarantee it stays projected later.

This change requires no migration, no claim-envelope changes and no TT
`ALLOWED_FIELDS` changes. Reverting the code restores the previous health
behavior; it changes no stored records. Typed absence is implemented separately in the
[versioned media surface](TYPED-MEDIA-ABSENCE.md), following Telemetry PR #4.
