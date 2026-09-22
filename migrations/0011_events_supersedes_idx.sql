-- M1b: the supersession chain-fold walks `supersedes` in BOTH directions.
--
-- Up (child -> parent) is already indexed: `supersedes` references
-- events(event_id), which is the primary key. Down (parent -> children) is the
-- new access path — "which events supersede this one?" — and without an index
-- it is a sequential scan of `events` per moment projected, i.e. the projector
-- degrades quadratically in the size of the ledger it is folding.
--
-- Partial, because the overwhelming majority of events supersede nothing: as of
-- this migration, 0 of 1176 rows on the live chain carry a value. The index
-- covers only rows that can ever match.
CREATE INDEX IF NOT EXISTS events_supersedes_idx
    ON events (supersedes)
    WHERE supersedes IS NOT NULL;
