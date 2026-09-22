-- M3: the founding exhibit, and migrated entries' lineage back into it.
--
-- Whitepaper §bootstrap: a pre-existing corpus enters in TWO PERMANENTLY
-- DISTINCT ROLES. The exhibit is committed by one hash over its frozen bytes,
-- dirty, and is never recanonicalized. The ledger is born signed. This migration
-- adds the first and the pointer between them; it deliberately does NOT let an
-- exhibit become an event.

-- ===========================================================================
-- exhibits — committed corpora, immutable
-- ===========================================================================

CREATE TABLE exhibits (
    exhibit_id  bytea       PRIMARY KEY,            -- SHA-256 over frozen bytes (NOT canon)
    byte_len    bigint      NOT NULL,               -- length of the committed bytes
    source_note text        NOT NULL,               -- provenance in prose: what these bytes are
    committed_at timestamptz NOT NULL DEFAULT now(),-- THIS node's clock; operational, not canonical
    CONSTRAINT exhibit_id_width CHECK (octet_length(exhibit_id) = 32),
    CONSTRAINT exhibit_len_pos  CHECK (byte_len > 0)
);

COMMENT ON TABLE exhibits IS
    'Committed pre-signing-regime corpora. The commitment is plain SHA-256 over the '
    'frozen bytes so an external checksum written at capture time reproduces it. '
    'Never recanonicalized, never cleaned: a cleaned exhibit would destroy the object '
    'under measurement (whitepaper section bootstrap).';

-- An exhibit is a historical fact about bytes that already existed. Nothing may
-- edit or delete one, for the same reason the events log is append-only.
CREATE OR REPLACE FUNCTION exhibits_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'exhibits are immutable: % attempted on exhibit_id %',
        TG_OP, encode(COALESCE(OLD.exhibit_id, NEW.exhibit_id), 'hex');
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER exhibits_no_update BEFORE UPDATE ON exhibits
    FOR EACH ROW EXECUTE FUNCTION exhibits_immutable();
CREATE TRIGGER exhibits_no_delete BEFORE DELETE ON exhibits
    FOR EACH ROW EXECUTE FUNCTION exhibits_immutable();

-- ===========================================================================
-- events.provenance — lineage, not identity
-- ===========================================================================
--
-- Envelope, deliberately OUTSIDE canon_event and therefore outside H0. Two
-- writers asserting the same moment must converge on one H0 whether or not they
-- learned it from the same archive — the same reason author and record_time are
-- excluded. Storing it here keeps lineage checkable without making the archive
-- part of what the claim IS.

ALTER TABLE events
    ADD COLUMN provenance_exhibit bytea  REFERENCES exhibits(exhibit_id),
    ADD COLUMN provenance_offset  bigint;

-- Half a pointer is worse than none: it would look like lineage while resolving
-- to nothing. Both or neither.
ALTER TABLE events ADD CONSTRAINT events_provenance_paired CHECK (
    (provenance_exhibit IS NULL     AND provenance_offset IS NULL)
 OR (provenance_exhibit IS NOT NULL AND provenance_offset IS NOT NULL
     AND provenance_offset >= 0)
);

-- "Which ledger entries came from this exhibit, and are they all accounted for"
-- is the question M3's golden-set verification asks, so index for it.
CREATE INDEX events_provenance_idx ON events (provenance_exhibit)
    WHERE provenance_exhibit IS NOT NULL;

COMMENT ON COLUMN events.provenance_exhibit IS
    'Migrated entries point back to the committed exhibit they were replayed from. '
    'NULL for natively-authored events. Outside H0 by design.';
