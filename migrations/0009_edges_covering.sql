-- Make the reachability walk index-only.
--
-- `Known_k` asks for one entity's neighbours per frontier node, and the migrated
-- corpus has a mean degree near 48, so a 4-hop bidirectional walk issues
-- thousands of these. Each one was costing ~13 ms — not because the index was
-- missing, but because `edges_src_idx`/`edges_dst_idx` index only the endpoint
-- column. Postgres found the rows by index and then went to the heap for
-- `edge_id` and `event_time`, ~190 scattered blocks per lookup. Multiplied out,
-- a `Supported` verdict took 13-56 seconds, which is not an answer anyone can
-- use interactively.
--
-- These indexes carry every column the neighbour query reads, so the plan
-- becomes an Index Only Scan and the heap is not touched at all. Nothing about
-- the query, the filter, or any verdict changes — this is the same answer,
-- found without the detour.
--
-- The `event_time` column is second in the key rather than in INCLUDE because
-- the query filters on it (`event_time <= as_of`); an INCLUDE column can be
-- returned but not used to seek.

CREATE INDEX edges_src_cover ON edges (src_entity, event_time) INCLUDE (edge_id, dst_entity);
CREATE INDEX edges_dst_cover ON edges (dst_entity, event_time) INCLUDE (edge_id, src_entity);

-- The originals are now redundant: a composite index leading with the same
-- column serves every lookup they served. Keeping them would cost write
-- amplification on every edge insert for no read benefit.
DROP INDEX edges_src_idx;
DROP INDEX edges_dst_idx;

COMMENT ON INDEX edges_src_cover IS
    'Covers the Known_k neighbour query so the walk never touches the heap. '
    'If a column is added to that query, add it here too or the scan silently '
    'stops being index-only and the walk slows by an order of magnitude.';
