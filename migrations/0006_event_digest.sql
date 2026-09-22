-- A maintained commitment to the event SET, so naming the corpus a verdict was
-- taken over costs one row read instead of a full scan.
--
-- Every judgment carries a `corpus_digest` identifying its inputs: that is what
-- lets two nodes that disagree tell a gossip-horizon gap from a governance
-- event. Computing it by folding every `event_id` per request is exact but puts
-- an O(n) scan on the read path, and the read path is where the filter is
-- supposed to be cheap. Reusing the `ledger_stats` counters instead would be
-- worse than slow: two different event sets of the same size share their
-- counters, so a digest built from them can say "same corpus" when it is not.
--
-- ===========================================================================
-- Why a trigger on `events`, and not the projector
-- ===========================================================================
--
-- The fold below is order-independent but NOT idempotent — XOR is an
-- involution, so applying one event twice removes it. `cc-ledger`'s `apply()`
-- is deliberately re-runnable (`reproject` exists precisely to prove projector
-- idempotence), so maintaining the digest there would corrupt it the first time
-- anyone exercised that guarantee.
--
-- An INSERT trigger on `events` cannot have that bug. `events` is append-only
-- (0002 blocks UPDATE and DELETE), so a row is inserted exactly once, ever, and
-- the trigger fires exactly once for it. The place where double-application is
-- impossible is the place the fold belongs.
--
-- This also puts the digest outside `rebuild`'s TRUNCATE, which is correct: the
-- digest is a function of `events`, and `rebuild` never touches `events`.

CREATE TABLE event_digest (
    id     boolean PRIMARY KEY DEFAULT true CHECK (id),   -- at most one row
    n      bigint  NOT NULL DEFAULT 0,
    acc    bytea   NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
    CONSTRAINT event_digest_acc_width CHECK (octet_length(acc) = 32),
    CONSTRAINT event_digest_n_nonneg  CHECK (n >= 0)
);

INSERT INTO event_digest (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE event_digest IS
    'Incremental commitment to the event set. `acc` is the XOR of sha256(domain || event_id) '
    'over every event; `n` is the count. Order-independent by construction, so two nodes '
    'holding the same events agree regardless of arrival order. This is a HORIZON DIAGNOSTIC, '
    'not the ledger commitment: an XOR-based multiset hash is linear over GF(2), so an actor '
    'able to mint many valid signed events could solve for a colliding set. The commitment '
    'that resists that is the anchored Merkle root in `roots`; this value exists to make '
    '"we are looking at different corpora" cheap to detect between honest nodes.';

-- The element hash, not the raw id. Folding raw ids would let anyone who can
-- choose event ids work directly in the accumulator's own algebra; making them
-- pass through SHA-256 first means a chosen-set attack has to search rather
-- than solve, which for a diagnostic is the right amount of hardening.
CREATE OR REPLACE FUNCTION event_digest_elem(eid bytea) RETURNS bytea AS $$
    SELECT sha256('cc.corpus.elem.v0'::bytea || eid);
$$ LANGUAGE sql IMMUTABLE STRICT;

-- Postgres has no bytea XOR. Going byte by byte over 32 bytes is exact and
-- cheap, and beats casting through bit(256), which would make the width a
-- literal repeated in three places.
CREATE OR REPLACE FUNCTION bytea_xor(a bytea, b bytea) RETURNS bytea AS $$
DECLARE r bytea := a; i int;
BEGIN
    IF octet_length(a) <> octet_length(b) THEN
        RAISE EXCEPTION 'bytea_xor width mismatch: % vs %',
            octet_length(a), octet_length(b);
    END IF;
    FOR i IN 0 .. octet_length(a) - 1 LOOP
        r := set_byte(r, i, get_byte(a, i) # get_byte(b, i));
    END LOOP;
    RETURN r;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION event_digest_fold() RETURNS trigger AS $$
BEGIN
    UPDATE event_digest
       SET n   = n + 1,
           acc = bytea_xor(acc, event_digest_elem(NEW.event_id))
     WHERE id = true;
    RETURN NULL;                       -- AFTER trigger; the row is already in
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER events_fold_digest AFTER INSERT ON events
    FOR EACH ROW EXECUTE FUNCTION event_digest_fold();

-- Backfill whatever is already here, so an existing ledger does not have to be
-- replayed to get a digest. Order does not matter — that is the point, and it is
-- why this can be a plain loop with no ORDER BY.
DO $$
DECLARE v_acc bytea := '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea;
        rec record;
        v_n bigint := 0;
BEGIN
    FOR rec IN SELECT event_id FROM events LOOP
        v_acc := bytea_xor(v_acc, event_digest_elem(rec.event_id));
        v_n := v_n + 1;
    END LOOP;
    -- `v_`-prefixed locals: a plpgsql variable named `acc` is ambiguous against
    -- the column of the same name in the UPDATE below, and Postgres rejects it.
    UPDATE event_digest SET n = v_n, acc = v_acc WHERE id = true;
END $$;
