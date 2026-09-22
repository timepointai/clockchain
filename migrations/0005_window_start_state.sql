-- The existence window's START gains the discriminant its END already had.
--
-- 0001 declared `window_start bytea NOT NULL -- always known`, which is a claim
-- the record cannot support. An entity migrated from an exhibit whose source
-- date was unparseable has NO evidenced start; storing Clock Zero for it would
-- assert that the subject existed from the beginning of the coordinate axis.
-- That is a fabricated claim, and the filter's window factor cannot tell it
-- apart from a real one.
--
-- The fix is the same shape 0001 already used for the end: the arithmetic bound
-- collapses distinct states onto one coordinate, so the state rides in a tag
-- beside it. `window_start` keeps holding the coordinate; `start_state` holds
-- what the coordinate cannot say.

ALTER TABLE entities
    ADD COLUMN start_state smallint NOT NULL DEFAULT 0;   -- 0 known | 1 unknown

ALTER TABLE entities ADD CONSTRAINT entities_start_range
    CHECK (start_state BETWEEN 0 AND 1);

-- An unknown start MUST store the sentinel, exactly as an open/unknown end does
-- (0001: `window_end` sentinel = 0xff*32). Without this a row could carry
-- start_state = unknown beside a real-looking coordinate, and the two halves of
-- the same fact would disagree.
ALTER TABLE entities ADD CONSTRAINT entities_start_sentinel_paired CHECK (
    start_state = 0
 OR window_start = '\xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'::bytea
);

COMMENT ON COLUMN entities.start_state IS
    'Whether window_start is evidenced (0) or the record is silent (1). Silence '
    'stores the sentinel. Mirrors closure_state: the distinction is semantic and '
    'cannot live in the coordinate.';

-- The DEFAULT is a migration convenience only. Every write goes through the
-- projector, which always binds the column explicitly; drop the default so a
-- future INSERT that forgets it fails loudly instead of silently claiming the
-- start is known.
ALTER TABLE entities ALTER COLUMN start_state DROP DEFAULT;
