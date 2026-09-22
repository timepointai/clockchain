-- Operational staging is outside the append-only ledger. Workers cannot approve.
CREATE TABLE generation_briefs (
 id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
 digest bytea NOT NULL CHECK (octet_length(digest)=32),
 payload text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE generation_candidates (
 id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
 brief_id text NOT NULL REFERENCES generation_briefs(id),
 digest bytea NOT NULL CHECK (octet_length(digest)=32),
 payload text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE generation_approvals (
 kind text NOT NULL CHECK (kind IN ('brief','candidate')),
 target_id text NOT NULL,
 digest bytea NOT NULL CHECK (octet_length(digest)=32),
 expected_heads jsonb,
 reviewer text NOT NULL CHECK (length(trim(reviewer))>0),
 approved_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (kind,target_id,digest)
);
CREATE TABLE publication_receipts (
 candidate_id text PRIMARY KEY REFERENCES generation_candidates(id),
 digest bytea NOT NULL CHECK (octet_length(digest)=32),
 receipt jsonb NOT NULL,
 published_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE edge_evidence (
 event_id bytea PRIMARY KEY REFERENCES events(event_id),
 candidate_id text NOT NULL REFERENCES publication_receipts(candidate_id) DEFERRABLE INITIALLY DEFERRED,
 admitted_coord bytea NOT NULL CHECK (octet_length(admitted_coord)=32),
 evidence text NOT NULL,
 evidence_sha256 bytea NOT NULL CHECK (octet_length(evidence_sha256)=32),
 author_key bytea NOT NULL CHECK (octet_length(author_key)=32),
 signature bytea NOT NULL CHECK (octet_length(signature)=64)
);
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='cc_generation_worker') THEN
  CREATE ROLE cc_generation_worker NOLOGIN;
 END IF;
END $$;
GRANT SELECT, INSERT ON generation_briefs,generation_candidates TO cc_generation_worker;
GRANT SELECT ON generation_approvals,publication_receipts TO cc_generation_worker;
-- No UPDATE/DELETE, approval INSERT, ledger access or signing credentials.
CREATE TABLE publication_control (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 paused boolean NOT NULL DEFAULT true,
 reason text NOT NULL DEFAULT 'initial operator enable required',
 updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO publication_control(singleton) VALUES(true);
GRANT SELECT ON publication_control TO cc_generation_worker;
