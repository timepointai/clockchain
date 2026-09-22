-- Remove two `ledger_stats` columns that no code path could ever keep true.
--
-- `root_height` was created with DEFAULT 0 and never incremented by anything, so
-- `/health/deep` published "no roots" while two were published and anchored. It
-- could not be repaired by incrementing it, either: `rebuild` truncates
-- `ledger_stats` and re-derives it from `events`, and a root publication commits
-- by `body_hash` — the height is not recoverable from the event stream, so any
-- maintained value would be destroyed by the next rebuild. `roots` is the table
-- that owns this fact, and `/health/deep` now reads it there.
--
-- `current_filter_version` is an `int`, and a filter version is a 32-byte hash
-- over the compiled support path. The column cannot hold its own value. The
-- version is published on `/health` from the filter this binary actually runs,
-- and recorded in the ledger as the genesis `protocol_constants_v0` moment,
-- which is where a governed constant belongs.
--
-- A column that is always wrong is worse than a missing one: it invites callers
-- to build on it. Dropping them is the fix.

DROP VIEW ledger_stats_public;

ALTER TABLE ledger_stats
    DROP COLUMN root_height,
    DROP COLUMN current_filter_version;

-- Recreated without the two columns; the vacuous-P(G) rule is unchanged.
CREATE VIEW ledger_stats_public AS
SELECT entity_count, moment_count, edge_count, attestation_count,
       contested_edges, cross_writer_contested,
       cross_writer_contested::float8 / NULLIF(contested_edges, 0) AS protected_fraction
FROM ledger_stats
WHERE id = true;
