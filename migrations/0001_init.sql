-- Clockchain v2 — genesis schema (initiation phase, M0/M1).
--
-- Two populations of tables, and the asymmetry between them is the design:
--   * `events` is THE LEDGER: append-only, content-addressed, the source of truth.
--   * everything else is a MATERIALIZED VIEW of the event set — rebuildable from
--     `events`, discardable, NEVER the source of truth.
--
-- Append-only enforcement (triggers + the cc_app role) lives in 0002. This file
-- is pure DDL: no data seed, because every row of the view — node 0 included —
-- is born from a signed event through the projector, so a full `rebuild` from
-- `events` reproduces the view byte-for-byte (M3 seeds node 0 as a signed event).

-- ===========================================================================
-- events — the append-only ledger (INSERT-only forever; enforced in 0002).
-- event_id = H0 = SHA-256(canon(fields)); every column is either the content
-- address, the signed envelope, or the verbatim canon preimage.
-- ===========================================================================
CREATE TABLE events (
    event_id    bytea       PRIMARY KEY,                 -- H0 (32 bytes), content address
    kind        smallint    NOT NULL,                    -- typed discriminant, never a string
    author_key  bytea       NOT NULL,                    -- Ed25519 public key (32 bytes)
    signature   bytea       NOT NULL,                    -- Ed25519 signature over H0 (64 bytes)
    event_time  bytea       NOT NULL,                    -- b256 coordinate, canonical (offset-binary, 32 bytes)
    record_time bytea       NOT NULL,                    -- b256 record-time coordinate (32 bytes)
    payload     bytea       NOT NULL,                    -- canon(fields) preimage, verbatim
    supersedes  bytea,                                   -- correction/challenge lineage. SOFT pointer (no FK):
                                                         -- a correction may gossip in before its predecessor
    created_at  timestamptz NOT NULL DEFAULT now(),      -- THIS node's wall clock; operational, NOT canonical
    CONSTRAINT event_id_width    CHECK (octet_length(event_id)    = 32),
    CONSTRAINT author_key_width  CHECK (octet_length(author_key)  = 32),
    CONSTRAINT signature_width   CHECK (octet_length(signature)   = 64),
    CONSTRAINT event_time_width  CHECK (octet_length(event_time)  = 32),
    CONSTRAINT record_time_width CHECK (octet_length(record_time) = 32)
);

-- Range seeks over the temporal axis are O(log|V|+m): the offset-binary
-- event_time bytes sort in numeric order, so a plain btree gives the descent.
CREATE INDEX events_event_time_idx ON events (event_time);

-- ===========================================================================
-- Projection tables — a materialized VIEW of the event set. Rebuildable from
-- events, discardable, mutable. Endpoint/subject references to OTHER entities
-- are plain columns, NOT foreign keys, so projection tolerates a not-yet-seen
-- endpoint (gossip arrival order must not change the converged view). Only the
-- reference to the birth event itself is a hard FK (that event is always present
-- before its projection row is written).
-- ===========================================================================

-- entity_id is author-chosen and NOT a content address (unlike every other
-- projection PK), so two DISTINCT signed births can collide on it. The projector
-- resolves that deterministically by keeping the canonically-earliest birth —
-- min (event_time, event_id) — the SAME order rebuild folds in, so incremental
-- and batch agree. `birth_event_time` stores that ordering key (offset-binary
-- event_time of the birth event).
CREATE TABLE entities (
    entity_id        bigint   PRIMARY KEY,        -- author-chosen; 0 reserved for node 0 (M3)
    birth_event      bytea    NOT NULL REFERENCES events(event_id),
    birth_event_time bytea    NOT NULL,           -- offset-binary event_time of the birth; canonical-survivor key
    resolution_key   text     NOT NULL,           -- what makes two refs the SAME entity
    canonical_name   text     NOT NULL,           -- a view concern, not identity
    window_start     bytea    NOT NULL,           -- b256 (offset-binary), always known
    closure_state    smallint NOT NULL,           -- 0 known-open | 1 known-closed | 2 unknown-closure
    window_end       bytea    NOT NULL,           -- b256; sentinel = 0xff*32 for open/unknown
    asserter         bytea    NOT NULL,           -- AuthorKey of the birth event; attributed from birth
    CONSTRAINT entities_closure_range CHECK (closure_state BETWEEN 0 AND 2),
    CONSTRAINT entities_ws_width  CHECK (octet_length(window_start)     = 32),
    CONSTRAINT entities_we_width  CHECK (octet_length(window_end)       = 32),
    CONSTRAINT entities_bet_width CHECK (octet_length(birth_event_time) = 32)
);
-- NON-unique: a DB-unique resolution_key would fork the view when two distinct
-- births share a key (whichever projected first would win, arrival-dependent).
-- One-entity-per-resolution-key is enforced at ingest by the M2 resolve stage,
-- not by the projection; the index here is only the resolve-stage lookup.
CREATE INDEX entities_resolution_idx ON entities (resolution_key);

CREATE TABLE moments (
    root_event_id bytea    PRIMARY KEY REFERENCES events(event_id),  -- chain root: stable identity
    head_event_id bytea    NOT NULL REFERENCES events(event_id),     -- maximal element of the supersedes DAG
    subject       bigint   NOT NULL,            -- entity_id; NO FK (dangling tolerated)
    coord         bytea    NOT NULL,            -- order-preserving image of head event_time
    record_coord  bytea    NOT NULL,            -- order-preserving image of record_time
    posture       smallint NOT NULL,            -- sign(event_time - record_time): -1 past | 0 present | +1 future
    body_hash     bytea    NOT NULL,
    author_key    bytea    NOT NULL,            -- first-seen proposer
    CONSTRAINT moments_coord_width CHECK (octet_length(coord) = 32)
);
CREATE INDEX moments_coord_idx ON moments (coord);

CREATE TABLE edges (
    edge_id        bytea    PRIMARY KEY REFERENCES events(event_id),  -- H0 of the edge-birth event
    src_entity     bigint   NOT NULL,           -- entity_id; NO FK (dangling tolerated)
    dst_entity     bigint   NOT NULL,
    relation       smallint NOT NULL,           -- typed edge_relation; never a string
    evidence_class smallint NOT NULL,           -- from birth, so a challenge has a target
    asserter       bytea    NOT NULL,           -- proposer AuthorKey; attributed from birth
    event_time     bytea    NOT NULL,           -- b256 coordinate; time-pinned at birth
    status         smallint NOT NULL DEFAULT 0, -- 0 proposed | 1 verified | 2 challenged | 3 reconciled
    in_g           boolean  NOT NULL DEFAULT false,  -- both endpoints resolved: membership in the P(G) denominator
    cross_writer   boolean  NOT NULL DEFAULT false,  -- auth(src) != auth(dst); set at the in_g false->true flip
    CONSTRAINT no_self_loop CHECK (src_entity <> dst_entity)
);
CREATE INDEX edges_src_idx ON edges (src_entity);
CREATE INDEX edges_dst_idx ON edges (dst_entity);

CREATE TABLE attestations (
    event_id bytea PRIMARY KEY REFERENCES events(event_id),
    target   bytea NOT NULL,                    -- attested event_id (soft reference)
    author   bytea NOT NULL                     -- attester's Ed25519 public key
);
CREATE INDEX attestations_target_idx ON attestations (target);

-- Sparse per-lens taxonomy (populated by the migrator's classifier in M3; kept
-- here so the schema is complete and rebuild has a table to truncate).
CREATE TABLE taxonomy_tags (
    event_id bytea    NOT NULL REFERENCES events(event_id),
    lens     smallint NOT NULL,
    tag      text     NOT NULL,
    PRIMARY KEY (event_id, lens, tag)
);

-- Root/anchor projections (populated in M4). Empty in M1; present for schema
-- completeness and so rebuild's TRUNCATE list is stable.
CREATE TABLE roots (
    root_id   bytea  PRIMARY KEY,               -- Merkle root over the event set
    height    bigint NOT NULL,
    moment_id bytea  REFERENCES events(event_id)
);

CREATE TABLE anchors (
    root_id     bytea       PRIMARY KEY REFERENCES roots(root_id),
    status      smallint    NOT NULL DEFAULT 0, -- 0 pending | 1 confirmed
    anchored_at timestamptz NOT NULL DEFAULT now(),
    txid        bytea                           -- Bitcoin txid once inscribed
);

-- Single-row maintained aggregate, updated at the write-path choke point in the
-- same transaction as the projection, never COUNT(*) at read time (memo §6/§9).
-- Integer counters only; ratios (P(G), coverage) are derived at read by the view
-- below, so byte-identical rebuild never depends on float determinism.
CREATE TABLE ledger_stats (
    id                     boolean PRIMARY KEY DEFAULT true CHECK (id),  -- at most one row
    entity_count           bigint  NOT NULL DEFAULT 0,
    moment_count           bigint  NOT NULL DEFAULT 0,
    edge_count             bigint  NOT NULL DEFAULT 0,
    attestation_count      bigint  NOT NULL DEFAULT 0,
    contested_edges        bigint  NOT NULL DEFAULT 0,   -- |C|: in_g edges (P(G) denominator)
    cross_writer_contested bigint  NOT NULL DEFAULT 0,   -- auth(u) != auth(v) subset (numerator)
    current_filter_version int     NOT NULL DEFAULT 0,
    root_height            bigint  NOT NULL DEFAULT 0
);

-- Read-time ratios. protected_fraction is NULL when there are no contested edges
-- (vacuous, Prop. vacuity) — never a protective-looking 0.0 (memo §5).
CREATE VIEW ledger_stats_public AS
SELECT entity_count, moment_count, edge_count, attestation_count,
       contested_edges, cross_writer_contested,
       current_filter_version, root_height,
       cross_writer_contested::float8 / NULLIF(contested_edges, 0) AS protected_fraction
FROM ledger_stats
WHERE id = true;
