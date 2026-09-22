-- Independent signed consumer provenance; never a historical event/claim field.
-- No FK to mutable projections: withdrawn decisions remain inspectable as stale.
CREATE TABLE media_absence_decisions (
    decision_id text PRIMARY KEY CHECK (length(decision_id) = 64),
    entity_id bigint NOT NULL,
    source_body_hash bytea NOT NULL CHECK (octet_length(source_body_hash) = 32),
    manifest text NOT NULL,
    author text NOT NULL,
    signature text NOT NULL,
    admitted_coord bytea NOT NULL CHECK (octet_length(admitted_coord) = 32),
    admitted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX media_absence_entity ON media_absence_decisions(entity_id, admitted_coord);
