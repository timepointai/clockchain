-- Fresh-store bootstrap only. Never run through the v0 migration runner.
CREATE SCHEMA cc_v1;
CREATE TABLE cc_v1.identity (
  singleton boolean PRIMARY KEY CHECK(singleton),
  instance bytea NOT NULL CHECK(octet_length(instance)=32),
  encoding smallint NOT NULL CHECK(encoding=1),
  schema_hash bytea NOT NULL CHECK(octet_length(schema_hash)=32)
);
CREATE TABLE cc_v1.candidates (
  event_id bytea PRIMARY KEY CHECK(octet_length(event_id)=32),
  envelope bytea NOT NULL CHECK(octet_length(envelope)<=1048576)
);
CREATE TABLE cc_v1.rejections (
  input_digest bytea PRIMARY KEY CHECK(octet_length(input_digest)=32),
  reason text NOT NULL
);
CREATE FUNCTION cc_v1.append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'v1 append-only evidence'; END;
$$;
CREATE TRIGGER immutable_identity BEFORE UPDATE OR DELETE OR TRUNCATE ON cc_v1.identity
FOR EACH STATEMENT EXECUTE FUNCTION cc_v1.append_only();
CREATE TRIGGER immutable_candidates BEFORE UPDATE OR DELETE OR TRUNCATE ON cc_v1.candidates
FOR EACH STATEMENT EXECUTE FUNCTION cc_v1.append_only();
CREATE TRIGGER immutable_rejections BEFORE UPDATE OR DELETE OR TRUNCATE ON cc_v1.rejections
FOR EACH STATEMENT EXECUTE FUNCTION cc_v1.append_only();

-- Stage (b) observations are separate from the semantic candidate set.
CREATE TABLE cc_v1.receipts (
    receipt_digest bytea PRIMARY KEY CHECK(octet_length(receipt_digest)=32),
    event_id bytea NOT NULL REFERENCES cc_v1.candidates(event_id),
    envelope bytea NOT NULL CHECK(octet_length(envelope)<=1048576)
);
CREATE TRIGGER immutable_receipts BEFORE UPDATE OR DELETE OR TRUNCATE ON cc_v1.receipts
FOR EACH STATEMENT EXECUTE FUNCTION cc_v1.append_only();

-- Stage (c): local body availability, excluded from the semantic event fold.
CREATE TABLE cc_v1.bodies (
    body_hash bytea PRIMARY KEY CHECK(octet_length(body_hash)=32),
    bytes bytea NOT NULL
);
CREATE TRIGGER immutable_bodies BEFORE UPDATE OR DELETE OR TRUNCATE ON cc_v1.bodies
FOR EACH STATEMENT EXECUTE FUNCTION cc_v1.append_only();

-- Stage (d): edges and attestations are reclassified from retained candidates;
-- no derived edge or media table is trusted. This contract marker changes the
-- interim schema hash so a Stage (c) store refuses silent reinterpretation.

-- Stage (e): the boot-pinned rule identity this store was bound to. Reopening
-- under another fold or filter identity fails semantic readiness.
CREATE TABLE cc_v1.rule_identity (
    singleton boolean PRIMARY KEY CHECK(singleton),
    fold_version smallint NOT NULL,
    fold_manifest bytea NOT NULL CHECK(octet_length(fold_manifest)=32),
    filter_identity bytea NOT NULL
);
CREATE TRIGGER immutable_rule_identity BEFORE UPDATE OR DELETE OR TRUNCATE ON cc_v1.rule_identity
FOR EACH STATEMENT EXECUTE FUNCTION cc_v1.append_only();
