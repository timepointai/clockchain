-- Claim bodies: the bytes a moment's `body_hash` commits to.
--
-- The 135 claims minted on 2026-08-14 carry full provenance — generating model,
-- provider, run, method, TT release, plus the asserted historical claim — and
-- NONE of it is readable. `MomentBody` is `{subject, body_hash}`, so the JSON
-- was hashed and dropped. The ledger can prove a given blob matches; it cannot
-- produce the blob. In that one respect it was worse than v2, which at least had
-- `text_model` as a column you could query.
--
-- The fix is NOT to widen `MomentBody`. That would change `canon_event`, and
-- therefore `H0`, and therefore re-key every moment already minted — a hard fork
-- of identity to gain a readable field.
--
-- Instead this is the same rule the image design already uses: the hash lives in
-- the chain, the bytes live beside it, and the link is verifiable by rehashing.
-- A body is an ATTACHMENT to a claim, never part of its identity. Losing this
-- table degrades an attribute; it cannot break the chain or invalidate an anchor.
CREATE TABLE IF NOT EXISTS claim_bodies (
    -- `body_hash("claim_v4", body)`, exactly as the moment recorded it. The
    -- primary key IS the commitment, so a row that does not match its own hash
    -- cannot be inserted twice under different content.
    body_hash   bytea PRIMARY KEY CHECK (octet_length(body_hash) = 32),
    -- The canonical bytes. Stored as text rather than jsonb on purpose: jsonb
    -- normalises key order and whitespace, which would change the bytes and
    -- break the very rehash that makes this table trustworthy.
    body        text  NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE claim_bodies IS
    'Bytes a moment body_hash commits to. Verify by rehashing body; never trust '
    'this table over the ledger. Absence means the bytes were not kept, which is '
    'not the same as the claim being unattributed.';

-- Read path: a moment joins here on body_hash. Nothing enforces that a body
-- EXISTS for a given moment, deliberately — a moment whose bytes were never
-- kept is a real state, and a foreign key would make it unrepresentable rather
-- than visible.
CREATE INDEX IF NOT EXISTS claim_bodies_recorded_idx ON claim_bodies (recorded_at DESC);
