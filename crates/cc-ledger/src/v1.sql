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
