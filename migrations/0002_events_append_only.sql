-- Clockchain v2 — append-only enforcement for the ledger.
--
-- The `events` table is the source of truth and must be INSERT-only forever
-- (whitepaper §ledger; memo discipline #1-#2). Enforced two ways, deliberately
-- redundant:
--   1. a trigger that binds EVERY role (owner, superuser, app) — the belt;
--   2. a role grant that strips the application role of UPDATE/DELETE/TRUNCATE —
--      the suspenders, and one ALTER ROLE away from being the only thing left.
-- The projection tables are the opposite: rebuildable views the app may mutate.

-- ---------------------------------------------------------------------------
-- The trigger: fires for every role, including a table owner or a misconfigured
-- superuser session. It turns any attempt to mutate the ledger into a loud abort
-- (memo §10: "loud failure is a gift to your future self").
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION events_reject_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'events is append-only: % forbidden on the ledger', TG_OP
        USING ERRCODE = 'restrict_violation';
END $$;

CREATE TRIGGER events_no_update BEFORE UPDATE ON events
    FOR EACH ROW EXECUTE FUNCTION events_reject_mutation();
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION events_reject_mutation();
CREATE TRIGGER events_no_truncate BEFORE TRUNCATE ON events
    FOR EACH STATEMENT EXECUTE FUNCTION events_reject_mutation();

-- ---------------------------------------------------------------------------
-- The application role: append + read the ledger, full DML on the projections.
-- Created idempotently because roles are cluster-global — a fresh ephemeral test
-- database on a shared cluster must tolerate the role already existing.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cc_app') THEN
        CREATE ROLE cc_app NOLOGIN;
    END IF;
EXCEPTION WHEN duplicate_object THEN
    NULL;  -- created concurrently by a parallel migration; harmless
END $$;

-- events: append + read ONLY. The REVOKE is explicit intent (a fresh table
-- grants nothing to a non-owner by default); the GRANT is the whole privilege.
REVOKE UPDATE, DELETE, TRUNCATE ON events FROM cc_app;
GRANT  INSERT, SELECT            ON events TO   cc_app;

-- Projections are views the app rebuilds: full DML, including TRUNCATE (rebuild).
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE
    ON entities, moments, edges, attestations, taxonomy_tags, roots, anchors, ledger_stats
    TO cc_app;
GRANT SELECT ON ledger_stats_public TO cc_app;
GRANT USAGE ON SCHEMA public TO cc_app;
