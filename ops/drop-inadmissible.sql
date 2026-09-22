-- Remove entities the admission gate would refuse, from the PROJECTION only.
--
-- Sean's ruling, 2026-08-17 (Atlas d-20260817-1097b7):
--     "drop them and set an always-strict rule for clockchain;
--      every entry has to be perfect"
--
-- The always-strict rule lives in `crates/cc-migrator/src/admission.rs` and
-- governs everything minted from now on. This file is the other half: the
-- entries that were already in when the rule landed.
--
-- ---------------------------------------------------------------------------
-- WHAT THIS DOES NOT DO
-- ---------------------------------------------------------------------------
-- It does not delete events, and it could not: `events` is append-only, guarded
-- by a trigger that binds every role including a superuser session
-- (migrations/0002). The signed births of these entities stay in the ledger.
-- What is removed is the materialised VIEW — which is what every consumer
-- surface reads, so the claims are gone from anywhere a reader can reach them.
--
-- That distinction belongs in any summary of this change. The alternative,
-- rewriting the ledger so the drop looked total, would have been a worse
-- outcome than the defect it fixes.
--
-- ---------------------------------------------------------------------------
-- WHY IT IS IDEMPOTENT, AND WHY THAT MATTERS
-- ---------------------------------------------------------------------------
-- `cc_ledger::rebuild()` re-derives the whole projection from `events` and is
-- FAITHFUL by design — it is the discardability proof, and weakening it to
-- honour a policy would make node-local view state an illegible third way for
-- two nodes to disagree, alongside corpus_digest and filter_version. So a
-- rebuild WILL bring these rows back. That is not a bug to suppress; it is the
-- projector being what it claims to be.
--
-- The consequence is operational and must not be left to memory: **after any
-- rebuild, run this file again.** It is safe to run at any time and does
-- nothing when there is nothing to drop. `ops/check-admission.py` is the guard
-- that tells you it is needed rather than waiting for a reader to notice.
--
-- Note that a rebuild resurrects entities and moments but NOT `claim_bodies`,
-- which are an attachment keyed by body hash rather than a fold of `events`.
-- So the post-rebuild state is strictly worse than the pre-drop one: claims
-- with no readable body. One more reason the check runs against the database
-- rather than against anyone's recollection.
--
-- ---------------------------------------------------------------------------
-- THE PREDICATE
-- ---------------------------------------------------------------------------
-- `start_state <> 0` is `WindowStart::Unknown` — an entity whose existence
-- window has no known start. Every one of the 30 dropped on 2026-08-17 also
-- carried a specific year in its body and sat at `year_tick(year)` in its
-- moment, so each declared its date unknown while asserting one. That
-- contradiction is what the gate now refuses at the write path
-- (`date-not-known`).
--
-- This is the only inadmissible condition checkable from the projection alone.
-- The rest of the gate's rules need the claim body, which lives in
-- `claim_bodies`; `ops/check-admission.py` checks those too and reports rather
-- than deleting, because dropping on a body-level rule is a bigger decision
-- than this file should make on its own.

\set ON_ERROR_STOP on

BEGIN;

CREATE TEMP TABLE doomed ON COMMIT DROP AS
    SELECT entity_id, canonical_name FROM entities WHERE start_state <> 0;

\echo '-- to be dropped:'
SELECT count(*) AS entities_to_drop FROM doomed;
SELECT entity_id, canonical_name FROM doomed ORDER BY canonical_name;

DELETE FROM moments WHERE subject IN (SELECT entity_id FROM doomed);

-- Bodies are keyed by content hash and shared by construction: delete only the
-- ones no surviving moment still points at. A blanket delete keyed on the
-- doomed set would take out a body that a good claim also hashes to.
DELETE FROM claim_bodies b
    WHERE NOT EXISTS (SELECT 1 FROM moments m WHERE m.body_hash = b.body_hash);

DELETE FROM edges x
    WHERE x.src_entity IN (SELECT entity_id FROM doomed)
       OR x.dst_entity IN (SELECT entity_id FROM doomed);

DELETE FROM entities WHERE entity_id IN (SELECT entity_id FROM doomed);

-- ---------------------------------------------------------------------------
-- Resync `ledger_stats`, WITHOUT WHICH THIS FILE PUBLISHES A LIE
-- ---------------------------------------------------------------------------
-- `ledger_stats` is a maintained aggregate, bumped at the write-path choke
-- point in the same transaction as the projection. There is no decrement path,
-- because until this file existed nothing ever deleted a projection row. So the
-- DELETEs above leave the counters reading their pre-drop values — and
-- `/health/deep` serves them, which means the drop would otherwise have left a
-- live surface reporting 351 entities over a table holding 321.
--
-- That is the exact failure `migrations/0008` was written about: "a column that
-- is always wrong is worse than a missing one: it invites callers to build on
-- it." It was caught here by reading `/health/deep` back after the drop rather
-- than by trusting the DELETE's own row counts.
--
-- Recomputed from the tables rather than decremented by the number of rows
-- removed. A decrement assumes the counters were right to begin with; a
-- recompute repairs any prior drift as a side effect, and this file is the only
-- thing in the system that ever needs to.
--
-- The two contested columns mirror `refresh_edge`: an edge is in C once both
-- endpoints resolve (`in_g`), and is cross-writer when its endpoints carry
-- different asserters (`cross_writer`).
UPDATE ledger_stats SET
    entity_count           = (SELECT count(*) FROM entities),
    moment_count           = (SELECT count(*) FROM moments),
    edge_count             = (SELECT count(*) FROM edges),
    attestation_count      = (SELECT count(*) FROM attestations),
    contested_edges        = (SELECT count(*) FROM edges WHERE in_g),
    cross_writer_contested = (SELECT count(*) FROM edges WHERE in_g AND cross_writer)
WHERE id = true;

\echo '-- after:'
SELECT 'entities'     AS table, count(*) FROM entities
UNION ALL SELECT 'moments',      count(*) FROM moments
UNION ALL SELECT 'edges',        count(*) FROM edges
UNION ALL SELECT 'vocabulary',   count(*) FROM vocabulary
UNION ALL SELECT 'claim_bodies', count(*) FROM claim_bodies
UNION ALL SELECT 'events',       count(*) FROM events
UNION ALL SELECT 'undated',      count(*) FROM entities WHERE start_state <> 0;

\echo '-- the published counters must now agree with the tables:'
SELECT s.entity_count, s.moment_count, s.edge_count,
       s.entity_count = (SELECT count(*) FROM entities)
   AND s.moment_count = (SELECT count(*) FROM moments)
   AND s.edge_count   = (SELECT count(*) FROM edges) AS counters_agree
FROM ledger_stats_public s;

COMMIT;
