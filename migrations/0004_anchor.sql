-- M4: the commitment log, the root stream, and OpenTimestamps anchoring.
--
-- Whitepaper §4.1: "Graph state commits periodically to a Merkle root; any
-- client verifies leaf inclusion in O(log n) hashes, and consistency proofs
-- between successive roots establish non-removal, so a mirror can verify that a
-- later root extends an earlier one rather than quietly dropping leaves."
--
-- Everything here exists to make that sentence checkable by a stranger.

-- ===========================================================================
-- commitment_log — the append-only LEAF SEQUENCE the roots are taken over.
-- ===========================================================================
--
-- Why a separate table instead of ordering `events` at read time:
--
--   * A consistency proof only means "the first n leaves are unchanged" if the
--     leaf order is APPEND-ONLY. `events` is not: a frontier-mined *past*
--     moment lands in the middle of event_time order, and gossip can deliver an
--     event whose event_id sorts before every leaf already committed. Either
--     order, taken at read time, silently renumbers earlier leaves and every
--     published root becomes unverifiable (INITIATION-PLAN §5.5).
--   * `events.created_at` is this node's wall clock — operational, not
--     canonical, and not gap-free. A root taken over it is not reproducible.
--
-- So the leaf order is frozen once, here, at the moment an epoch is sealed, and
-- may never move again. Within one seal the newly-committed events are ordered
-- by `event_id` — a content address, so the order is a pure function of the
-- event SET and carries no local state. Two nodes that seal the same event set
-- therefore publish byte-identical roots; two nodes that seal at different
-- boundaries diverge in the root stream while their materialized views still
-- converge (Prop. converge is about the view; the root stream is the node's
-- local seq). Reconciling divergent root streams is the Growth-epoch problem
-- this schema deliberately does not solve.
CREATE TABLE commitment_log (
    seq      bigint PRIMARY KEY,                       -- gap-free, 0-based leaf index
    event_id bytea  NOT NULL UNIQUE REFERENCES events(event_id),
    epoch    bigint NOT NULL,                          -- the roots.height that first committed this leaf
    CONSTRAINT commitment_log_seq_nonneg   CHECK (seq >= 0),
    CONSTRAINT commitment_log_epoch_nonneg CHECK (epoch >= 0)
);

-- "Which leaves did epoch n add" is the question a consistency proof answers, so
-- index for it. No FK to roots(height): `cc-ledger::rebuild` TRUNCATEs the roots
-- projection, and Postgres refuses to truncate a table referenced from outside
-- the truncation set — an FK here would convert a routine rebuild into an abort.
CREATE INDEX commitment_log_epoch_idx ON commitment_log (epoch);

COMMENT ON TABLE commitment_log IS
    'The append-only leaf sequence every published root is taken over. Frozen at '
    'seal time and never reordered: renumbering one leaf invalidates every root '
    'published after it, including the ones already inscribed into Bitcoin.';

-- The same belt-and-suspenders the ledger gets in 0002, for the same reason: a
-- rewritten leaf order is indistinguishable from an honest one after the fact,
-- so the rewrite has to be impossible rather than merely against policy.
CREATE OR REPLACE FUNCTION commitment_log_reject_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'commitment_log is append-only: % would renumber published leaves', TG_OP
        USING ERRCODE = 'restrict_violation';
END $$;

CREATE TRIGGER commitment_log_no_update BEFORE UPDATE ON commitment_log
    FOR EACH ROW EXECUTE FUNCTION commitment_log_reject_mutation();
CREATE TRIGGER commitment_log_no_delete BEFORE DELETE ON commitment_log
    FOR EACH ROW EXECUTE FUNCTION commitment_log_reject_mutation();
CREATE TRIGGER commitment_log_no_truncate BEFORE TRUNCATE ON commitment_log
    FOR EACH STATEMENT EXECUTE FUNCTION commitment_log_reject_mutation();

-- ===========================================================================
-- roots — the published root stream (extends the 0001 projection).
-- ===========================================================================
--
-- 0001 gave `roots` its identity (root_id), its epoch index (height), and the
-- node-0 moment that recorded it (moment_id). M4 adds what a mirror needs in
-- order to CHECK a root instead of trusting it.
ALTER TABLE roots
    ADD COLUMN tree_size    bigint      NOT NULL DEFAULT 0,  -- n: leaves committed by this root
    ADD COLUMN prev_root    bytea       REFERENCES roots(root_id),
    ADD COLUMN consistency  bytea,                            -- RFC 6962 proof prev_root -> root_id
    ADD COLUMN published_at timestamptz NOT NULL DEFAULT now();

-- The DEFAULT existed only so the ALTER could be NOT NULL on a table that is
-- empty today; leaving it would let a future INSERT silently claim tree_size 0.
ALTER TABLE roots ALTER COLUMN tree_size DROP DEFAULT;

ALTER TABLE roots
    ADD CONSTRAINT roots_tree_size_positive CHECK (tree_size > 0),
    ADD CONSTRAINT roots_id_width           CHECK (octet_length(root_id) = 32),
    ADD CONSTRAINT roots_height_nonneg      CHECK (height >= 0),
    -- One root per epoch, and the genesis root is the only rootless one: a
    -- second chain head would fork the stream where the whole point is that it
    -- cannot be forked.
    ADD CONSTRAINT roots_height_unique      UNIQUE (height),
    ADD CONSTRAINT roots_chain_head CHECK (
        (height = 0 AND prev_root IS NULL     AND consistency IS NULL)
     OR (height > 0 AND prev_root IS NOT NULL AND consistency IS NOT NULL)
    );

COMMENT ON COLUMN roots.height IS
    'Epoch index of the root stream: 0 is the genesis root, n+1 extends n. The '
    'node-0 moment recording root n lands in the log AFTER root n is taken, so '
    'it is committed by root n+1 — the epoch boundary is what breaks the loop of '
    'a root that would have to include its own recording (section nodezero).';
COMMENT ON COLUMN roots.consistency IS
    'RFC 6962 consistency proof from prev_root to this root, stored as the '
    'concatenated 32-byte path. Non-removal, checkable by a mirror that holds '
    'only the two roots and this blob.';

-- ===========================================================================
-- anchor_proofs — the .ots blobs, content-addressed.
-- ===========================================================================
--
-- Memo §3 bans bytes-in-a-row because v1 put a gigabyte of base64 in a text
-- column. The rule it was drawn from is "media live outside the rows as
-- separately addressed blobs", and what makes that work is the ADDRESS, not the
-- filesystem: `anchors` carries a hash, and the bytes hang off that hash here,
-- verified by it. The size ceiling is the part that keeps the ban honest — an
-- OTS proof is a kilobyte of hash path, and a CHECK makes it impossible for this
-- table to quietly become the thing memo §3 warns about.
CREATE TABLE anchor_proofs (
    blob_hash  bytea       PRIMARY KEY,                -- SHA-256 over `bytes`; the reference anchors carries
    bytes      bytea       NOT NULL,                   -- a complete .ots detached timestamp file
    fetched_at timestamptz NOT NULL DEFAULT now(),     -- operational clock, never canonical
    CONSTRAINT anchor_proofs_hash_width CHECK (octet_length(blob_hash) = 32),
    CONSTRAINT anchor_proofs_bounded    CHECK (octet_length(bytes) BETWEEN 1 AND 65536)
);

COMMENT ON TABLE anchor_proofs IS
    'Content-addressed OpenTimestamps proofs. The row is verifiable against its '
    'own primary key, so a corrupted blob is detectable without consulting the '
    'operator who stored it.';

-- ===========================================================================
-- anchors — the OTS/Bitcoin inscription (extends the 0001 projection).
-- ===========================================================================
--
-- 0001 gave `anchors` the root it anchors, a pending/confirmed status, and the
-- Bitcoin txid. M4 adds the proof reference and the block height, plus the
-- node-0 moment that recorded the inscription — because an anchor an auditor
-- has to leave the corpus to check is an anchor the corpus does not settle
-- (section nodezero).
ALTER TABLE anchors
    ADD COLUMN ots_blob_hash bytea  REFERENCES anchor_proofs(blob_hash),
    ADD COLUMN calendar_url  text,
    ADD COLUMN block_height  bigint,
    ADD COLUMN moment_id     bytea  REFERENCES events(event_id);

ALTER TABLE anchors
    ADD CONSTRAINT anchors_status_range CHECK (status BETWEEN 0 AND 1),
    -- A pending anchor has a calendar commitment and nothing from Bitcoin yet; a
    -- confirmed one has a block height. Half a confirmation would read as
    -- settled while proving nothing.
    ADD CONSTRAINT anchors_confirmed_has_height CHECK (
        (status = 0 AND block_height IS NULL)
     OR (status = 1 AND block_height IS NOT NULL AND block_height >= 0)
    );

COMMENT ON COLUMN anchors.status IS
    '0 pending (calendar holds the commitment, Bitcoin has not confirmed it yet) '
    '| 1 confirmed. The lifecycle is two append-only node-0 moments, the second '
    'superseding the first; this row is the collapsed VIEW of them, never the fact.';
COMMENT ON COLUMN anchors.txid IS
    'Bitcoin txid, when an operator supplies one. It is NOT derivable from the '
    '.ots proof: a Bitcoin attestation commits to the block header merkle root '
    'and names the height, not the transaction. NULL means unknown, never zero.';

-- The application role appends to the commitment log and reads it; it may not
-- rewrite it, exactly as with `events`.
REVOKE UPDATE, DELETE, TRUNCATE ON commitment_log FROM cc_app;
GRANT  INSERT, SELECT            ON commitment_log TO   cc_app;
GRANT  SELECT, INSERT, DELETE    ON anchor_proofs  TO   cc_app;
