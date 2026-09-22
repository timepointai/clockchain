-- Signed generated-media provenance; never part of historical claim identity.
-- PNG objects live on the media volume, not inline in this projection.
CREATE TABLE image_attachments (
    attachment_id text PRIMARY KEY CHECK (length(attachment_id) = 64),
    entity_id bigint NOT NULL,
    source_body_hash bytea NOT NULL CHECK (octet_length(source_body_hash) = 32),
    image_sha256 text NOT NULL CHECK (length(image_sha256) = 64),
    manifest text NOT NULL,
    author text NOT NULL,
    signature text NOT NULL,
    admitted_coord bytea NOT NULL CHECK (octet_length(admitted_coord) = 32),
    admitted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX image_attachments_entity ON image_attachments(entity_id, admitted_coord);
