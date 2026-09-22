-- The governed vocabulary: what `Admiss(c, t_q)` reads.
--
-- Until now `admissibility()` returned `Unrecorded` for every claim type,
-- because nothing in the schema could answer the question. That is not a
-- neutral placeholder: `Unrecorded` vanishes the admissibility factor, so the
-- filter could only ever return `Unsupported` or `Contradicted`. `Supported`
-- was unreachable — not because the corpus lacked evidence, but because one of
-- the four factors had no store behind it.
--
-- A claim type carries a BAND of coordinates rather than an in/out flag, because
-- `Admiss` is asked at the queried coordinate. "Pitched battle" and "spaceflight"
-- are both real classifications and the second cannot apply to the year 1200, so
-- the vocabulary has to be able to say when a type applies — and to distinguish
-- "silent about this type here" from "records this type as outside its band",
-- which are absence and contrary evidence respectively.
--
-- Like `roots`, this is fed by signed events (`EventKind::VocabularyDeclare`) and
-- not by operator INSERTs: changing the vocabulary changes `Admiss`, which
-- changes verdicts, so it must be a settled event rather than a table edit.
-- Unlike `roots`, it IS a true projection — the declaration's payload carries
-- the whole entry, so `rebuild` re-derives it from `events` and it is correctly
-- in the TRUNCATE list.

CREATE TABLE vocabulary (
    claim_type    bigint   PRIMARY KEY,                            -- u32 code widened
    label         text     NOT NULL,
    declared_by   bytea    NOT NULL REFERENCES events(event_id),   -- the declaring event
    declared_at   bytea    NOT NULL,                               -- its event_time; survivor key
    band_start    bytea    NOT NULL,                               -- b256 offset-binary
    start_state   smallint NOT NULL,                               -- 0 known | 1 unknown
    band_end      bytea    NOT NULL,                               -- b256; sentinel when open/unknown
    closure_state smallint NOT NULL,                               -- 0 open | 1 closed | 2 unknown
    CONSTRAINT vocab_code_range   CHECK (claim_type > 0 AND claim_type <= 4294967295),
    CONSTRAINT vocab_start_range  CHECK (start_state   BETWEEN 0 AND 1),
    CONSTRAINT vocab_close_range  CHECK (closure_state BETWEEN 0 AND 2),
    CONSTRAINT vocab_bs_width     CHECK (octet_length(band_start)  = 32),
    CONSTRAINT vocab_be_width     CHECK (octet_length(band_end)    = 32),
    CONSTRAINT vocab_da_width     CHECK (octet_length(declared_at) = 32)
);

-- Claim type 0 is reserved: a query whose label failed to resolve must not
-- accidentally name a real type. The CHECK above enforces it at the store, and
-- the projector refuses it at the write path.
COMMENT ON TABLE vocabulary IS
    'The governed claim-type vocabulary Admiss(c, t_q) is evaluated against. Fed only by '
    'signed VocabularyDeclare events through the projector; a change here is a governance '
    'event, because it changes verdicts.';

CREATE INDEX vocabulary_label_idx ON vocabulary (label);
