//! `cc-ledger` — the append-only `events` log and the projector that folds it
//! into the materialized-view tables.
//!
//! **The write path is a choke point expressed as a type.** [`Signed`] is the
//! only value the ledger will store, and it has no public constructor other than
//! the verifying gate ([`Signed::seal`] / [`Signed::sign`]): an event that has
//! not had its `H0` recomputed and its signature checked is *unrepresentable* as
//! a storable value (memo §2, §11). Every writer — the migrator included —
//! shares this path; there is no privileged raw-insert bypass.
//!
//! **Postgres is the fold accumulator, not a second copy of truth** (memo §9).
//! The projector's running state is the view tables themselves; [`commit`]
//! appends an event and applies its projection delta in one transaction, and
//! [`rebuild`] proves the view is a discardable function of the event set by
//! re-deriving it byte-for-byte.
//!
//! The full six-stage funnel (`resolve` → `classify` → `screen`) wires the
//! `cc-filter` consensus rule in at **M2**; M1 is the gate + the projector + the
//! maintained aggregates.

use cc_core::{
    event_id, parse_event, verify, AuthorKey, EventBody, EventContent, EventId, EventKind,
    SecretKey, Signature, Tick,
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};

/// Connect to Postgres.
pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPool::connect(database_url).await
}

/// Apply the embedded, forward-only migrations. `sqlx::migrate!` embeds the
/// files at compile time, so this needs no database to *build*.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await
}

// ===========================================================================
// The gate: Signed is the only storable type.
// ===========================================================================

/// A gated, verified event — the ONLY thing [`commit`] will store. Its fields
/// are private and its only constructors verify, so an ungated event cannot be
/// appended.
#[derive(Clone)]
pub struct Signed {
    content: EventContent,
    id: EventId,
    signature: Signature,
}

impl Signed {
    /// The verifying gate: recompute `H0` and check the signature over it. Fails
    /// closed on a bad signature — there is no way to obtain a `Signed` that
    /// skipped this check.
    pub fn seal(content: EventContent, signature: Signature) -> Result<Signed, LedgerError> {
        let id = event_id(&content);
        verify(&content.author, id.as_bytes(), &signature)
            .map_err(|_| LedgerError::BadSignature)?;
        Ok(Signed {
            content,
            id,
            signature,
        })
    }

    /// Convenience for a writer holding its signing key: seal in one step. It
    /// **binds attribution to the actual signer** — `content.author` is
    /// overwritten with this key's public key before sealing — so the produced
    /// `Signed` always passes [`Signed::seal`]'s verification and can never be
    /// mis-attributed. (Author is excluded from a content kind's `H0`, so `id` is
    /// unchanged; for an attestation this correctly binds identity to the real
    /// signer.)
    pub fn sign(sk: &SecretKey, mut content: EventContent) -> Signed {
        content.author = sk.author();
        let (id, signature) = sk.seal(&content);
        Signed {
            content,
            id,
            signature,
        }
    }

    /// The event's content address (`H0`).
    pub fn id(&self) -> EventId {
        self.id
    }

    /// The typed kind.
    pub fn kind(&self) -> EventKind {
        self.content.body.kind()
    }

    /// The typed content.
    pub fn content(&self) -> &EventContent {
        &self.content
    }
}

/// The result of appending an event to the grow-only set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Appended {
    /// The event was new: it was inserted and its projection applied.
    New,
    /// A byte-identical event was already present: a CRDT union no-op
    /// (`ON CONFLICT DO NOTHING`), never an error (Prop. converge).
    Unioned,
}

impl Appended {
    /// Whether the event was new to this node.
    pub fn is_new(self) -> bool {
        self == Appended::New
    }
}

// ===========================================================================
// The single write fn: append + project in one transaction.
// ===========================================================================

/// The single write path: in one transaction, INSERT the signed event into the
/// append-only `events` log and, iff it was new, apply its projection delta.
/// Idempotent per `event_id` by the grow-only-set law.
pub async fn commit(pool: &PgPool, signed: &Signed) -> Result<Appended, LedgerError> {
    commit_with_provenance(pool, signed, None).await
}

/// The same write path, carrying an [`ExhibitRef`] for entries replayed from a
/// committed exhibit (whitepaper §bootstrap).
///
/// This is **not** a migrator bypass and grants nothing: it takes the identical
/// `Signed` every other writer must produce, walks the identical transaction,
/// and applies the identical projection. The only difference is an extra
/// envelope column recording *where the writer learned the claim*. There is
/// still no `Signed::from_trusted()` and no raw-insert path — "the migrator is
/// just another writer" stays a fact about which functions exist.
///
/// Provenance is deliberately outside `H0`: two writers asserting the same
/// moment converge on one identity whether or not they read the same archive.
pub async fn commit_with_provenance(
    pool: &PgPool,
    signed: &Signed,
    provenance: Option<cc_core::ExhibitRef>,
) -> Result<Appended, LedgerError> {
    let mut tx = pool.begin().await?;
    let appended = commit_in_tx(&mut tx, signed, provenance).await?;
    tx.commit().await?;
    Ok(appended)
}

/// Append and project using a caller-owned transaction. The caller must commit it.
/// This preserves the identical validated Signed choke point for atomic batches.
pub async fn commit_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    signed: &Signed,
    provenance: Option<cc_core::ExhibitRef>,
) -> Result<Appended, LedgerError> {
    let appended = append_tx(tx, signed, provenance).await?;
    if appended.is_new() {
        apply(tx, &signed.content, signed.id).await?;
    }
    Ok(appended)
}

/// Re-apply an already-stored event's projection delta. A no-op by construction
/// (every reducer is `ON CONFLICT DO NOTHING` and every counter moves on a
/// guarded transition), so this proves projector idempotence directly.
pub async fn reproject(pool: &PgPool, signed: &Signed) -> Result<(), LedgerError> {
    let mut tx = pool.begin().await?;
    apply(&mut tx, &signed.content, signed.id).await?;
    tx.commit().await?;
    Ok(())
}

async fn append_tx(
    tx: &mut Transaction<'_, Postgres>,
    s: &Signed,
    provenance: Option<cc_core::ExhibitRef>,
) -> Result<Appended, LedgerError> {
    let payload = cc_core::canon_event(&s.content);
    let supersedes: Option<Vec<u8>> = s.content.supersedes.map(|e| e.as_bytes().to_vec());
    let prov_exhibit: Option<Vec<u8>> = provenance.map(|p| p.exhibit.as_bytes().to_vec());
    let prov_offset: Option<i64> = provenance.map(|p| p.offset as i64);
    let res = sqlx::query(
        "INSERT INTO events \
         (event_id, kind, author_key, signature, event_time, record_time, payload, supersedes, \
          provenance_exhibit, provenance_offset) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(s.id.as_bytes().to_vec())
    .bind(s.kind().to_i16())
    .bind(s.content.author.to_bytes().to_vec())
    .bind(s.signature.to_bytes().to_vec())
    .bind(s.content.event_time.to_canon_bytes().to_vec())
    .bind(s.content.record_time.to_canon_bytes().to_vec())
    .bind(payload)
    .bind(supersedes)
    .bind(prov_exhibit)
    .bind(prov_offset)
    .execute(&mut **tx)
    .await?;
    Ok(if res.rows_affected() == 1 {
        Appended::New
    } else {
        Appended::Unioned
    })
}

// ===========================================================================
// The projector — deterministic fold, Postgres as accumulator.
// ===========================================================================

async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    c: &EventContent,
    id: EventId,
) -> Result<(), LedgerError> {
    ensure_stats_row(tx).await?;
    match &c.body {
        EventBody::EntityCreate(e) => project_entity(tx, c, id, e).await,
        EventBody::Moment(m) => project_moment(tx, c, id, m).await,
        EventBody::Edge(ed) => project_edge(tx, c, id, ed).await,
        EventBody::Attestation(a) => project_attestation(tx, c, id, a).await,
        EventBody::VocabularyDeclare(v) => project_vocabulary(tx, c, id, v).await,
    }
}

/// Ensure the single `ledger_stats` row exists (zeros). Called at the start of
/// every apply and of rebuild, so the row is owned by the projector and
/// reproduced by rebuild rather than seeded by the migration.
async fn ensure_stats_row(tx: &mut Transaction<'_, Postgres>) -> Result<(), LedgerError> {
    sqlx::query("INSERT INTO ledger_stats (id) VALUES (true) ON CONFLICT (id) DO NOTHING")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn bump(tx: &mut Transaction<'_, Postgres>, column: &str) -> Result<(), LedgerError> {
    // `column` is a fixed compile-time literal from the call sites below, never
    // user input — so this format is not an injection surface.
    let sql = format!("UPDATE ledger_stats SET {column} = {column} + 1 WHERE id = true");
    sqlx::query(&sql).execute(&mut **tx).await?;
    Ok(())
}

async fn project_entity(
    tx: &mut Transaction<'_, Postgres>,
    c: &EventContent,
    id: EventId,
    e: &cc_core::EntityBirth,
) -> Result<(), LedgerError> {
    let id_bytes = id.as_bytes().to_vec();
    let birth_event_time = c.event_time.to_canon_bytes().to_vec();
    let window_start = e.window.stored_start().to_canon_bytes().to_vec();
    let start_state = e.window.start_state() as i16;
    let closure = e.window.closure_state() as i16;
    let window_end = e.window.stored_end().to_canon_bytes().to_vec();
    let asserter = c.author.to_bytes().to_vec();

    // entity_id is author-chosen and NOT a content address, so two DISTINCT
    // signed births can claim it. Keep the canonically-earliest — min
    // (event_time, event_id) — so the survivor is a function of the event SET,
    // never arrival order. bytea lexicographic order equals the signed-integer /
    // H0 tiebreak that rebuild folds in, so incremental and batch agree.
    let existing: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT birth_event, birth_event_time FROM entities WHERE entity_id = $1")
            .bind(e.entity_id)
            .fetch_optional(&mut **tx)
            .await?;

    match existing {
        None => {
            sqlx::query(
                "INSERT INTO entities \
                 (entity_id, birth_event, birth_event_time, resolution_key, canonical_name, window_start, start_state, closure_state, window_end, asserter) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            )
            .bind(e.entity_id)
            .bind(&id_bytes)
            .bind(&birth_event_time)
            .bind(&e.resolution_key)
            .bind(&e.canonical_name)
            .bind(&window_start)
            .bind(start_state)
            .bind(closure)
            .bind(&window_end)
            .bind(&asserter)
            .execute(&mut **tx)
            .await?;
            bump(tx, "entity_count").await?;
            // A new entity may complete edges that were waiting on this endpoint.
            refresh_incident_edges(tx, e.entity_id).await?;
        }
        Some((existing_be, existing_bet)) => {
            if existing_be == id_bytes {
                return Ok(()); // idempotent re-apply of the same birth
            }
            // Distinct conflicting birth: keep the canonically-smaller one.
            if (&birth_event_time, &id_bytes) < (&existing_bet, &existing_be) {
                sqlx::query(
                    "UPDATE entities SET \
                       birth_event = $2, birth_event_time = $3, resolution_key = $4, \
                       canonical_name = $5, window_start = $6, start_state = $7, \
                       closure_state = $8, window_end = $9, asserter = $10 \
                     WHERE entity_id = $1",
                )
                .bind(e.entity_id)
                .bind(&id_bytes)
                .bind(&birth_event_time)
                .bind(&e.resolution_key)
                .bind(&e.canonical_name)
                .bind(&window_start)
                .bind(start_state)
                .bind(closure)
                .bind(&window_end)
                .bind(&asserter)
                .execute(&mut **tx)
                .await?;
                // The survivor's asserter may have changed — recompute
                // cross_writer for every in_g edge incident to this entity.
                refresh_incident_edges(tx, e.entity_id).await?;
            }
            // else: incoming is canonically larger — keep the sitting row (no-op).
        }
    }
    Ok(())
}

/// Project a governed vocabulary declaration.
///
/// `claim_type` is author-chosen and NOT content-addressed, so two DISTINCT
/// signed declarations can claim one code — the same hazard `entities` has with
/// `entity_id`, and resolved the same way: keep the canonically-earliest
/// declaration, `min (event_time, event_id)`, which is the order `rebuild`
/// folds in, so incremental and batch agree.
async fn project_vocabulary(
    tx: &mut Transaction<'_, Postgres>,
    c: &EventContent,
    id: EventId,
    v: &cc_core::VocabularyEntry,
) -> Result<(), LedgerError> {
    // Code 0 is reserved so a query whose label did not resolve cannot land on a
    // real type. A declaration claiming it is refused rather than dropped: it is
    // a signed statement that must not be silently ignored.
    if v.claim_type == 0 {
        return Err(LedgerError::Corruption(
            "vocabulary claim_type 0 is reserved and must not be declared",
        ));
    }
    let id_bytes = id.as_bytes().to_vec();
    let declared_at = c.event_time.to_canon_bytes().to_vec();
    let band_start = v.band.stored_start().to_canon_bytes().to_vec();
    let start_state = v.band.start_state() as i16;
    let band_end = v.band.stored_end().to_canon_bytes().to_vec();
    let closure = v.band.closure_state() as i16;
    let code = i64::from(v.claim_type);

    let existing: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT declared_by, declared_at FROM vocabulary WHERE claim_type = $1")
            .bind(code)
            .fetch_optional(&mut **tx)
            .await?;

    match existing {
        None => {
            sqlx::query(
                "INSERT INTO vocabulary \
                 (claim_type, label, declared_by, declared_at, band_start, start_state, band_end, closure_state) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(code)
            .bind(&v.label)
            .bind(&id_bytes)
            .bind(&declared_at)
            .bind(&band_start)
            .bind(start_state)
            .bind(&band_end)
            .bind(closure)
            .execute(&mut **tx)
            .await?;
        }
        Some((prev_by, prev_at)) => {
            if prev_by == id_bytes {
                return Ok(()); // idempotent re-apply of the same declaration
            }
            if (&declared_at, &id_bytes) < (&prev_at, &prev_by) {
                sqlx::query(
                    "UPDATE vocabulary SET \
                       label = $2, declared_by = $3, declared_at = $4, band_start = $5, \
                       start_state = $6, band_end = $7, closure_state = $8 \
                     WHERE claim_type = $1",
                )
                .bind(code)
                .bind(&v.label)
                .bind(&id_bytes)
                .bind(&declared_at)
                .bind(&band_start)
                .bind(start_state)
                .bind(&band_end)
                .bind(closure)
                .execute(&mut **tx)
                .await?;
            }
            // else: incoming is canonically larger — keep the sitting row.
        }
    }
    Ok(())
}

/// The bound on a supersedes walk in either direction.
///
/// A cycle is not reachable by an honest writer — `supersedes` rides inside
/// `H0`, so a loop would require finding a hash preimage — but a projector that
/// spins forever on a malformed ledger is a worse failure than one that stops
/// loudly. The bound is the stop.
///
/// **Calling it "the stop" undersells what it does, and telemetry was right to
/// say so.** `Corruption` here aborts the transaction `commit` opened, so the
/// EVENT ITSELF is refused storage — this is a write refusal, not only a
/// projection refusal. And *which* event gets refused depends on arrival order:
/// arriving forward, the chain stores 1024 links and refuses the next; arriving
/// backward, the deep links are held and stored and the refusal lands on an
/// ANCESTOR when the downward walk overruns. At the bound, "the view is a pure
/// function of the event set" degrades into "the event set is arrival-order
/// dependent" — the one place in this fold where that sentence stops holding.
///
/// It is astronomically unreachable by an honest writer (1024 successive
/// corrections of one moment) and is left as-is deliberately: every alternative
/// — an unbounded walk, a silent truncation, projecting a partial chain — is
/// worse than a loud refusal in a region no real corpus enters. `MAX_CHAIN` is
/// the ceiling in BOTH walks, so `chain_root` tolerates at most 1023 links: the
/// loop spends one iteration per ascent and a chain of length L needs L + 1.
const MAX_CHAIN: usize = 1024;

/// M1b — the supersession chain-fold.
///
/// A corrected moment is **one row**, keyed by the chain's root, carrying the
/// surviving reading at its head. The row is computed as a **pure function of
/// the event set**: both walks read `events`, never the projector's running
/// state, so applying any event of a chain yields the identical row. That is
/// what makes arrival order irrelevant, `reproject` a no-op, and `rebuild`
/// equal to the incremental fold — the three properties this fold has to have.
///
/// Four things are load-bearing, and none of them is the UPDATE:
///
/// 1. **Arrival order.** Gossip does not promise a correction arrives after
///    what it corrects. A moment whose ancestor is absent is **held** — no row,
///    no counter — and is picked up by the forward walk when the ancestor
///    lands. Projecting it as a root of its own instead would leave a second
///    live row that the ancestor's arrival could never merge away, so two nodes
///    with the same events would disagree.
/// 2. **Conflicting corrections.** Two events may supersede the same moment.
///    The chain follows the canonically-earliest child, `min (event_time,
///    event_id)` — the same rule conflicting entity births and vocabulary
///    declarations already use, and the order `rebuild` folds in, so the
///    incremental and batch paths cannot diverge.
///
///    **The operational consequence, which the rule states and does not
///    advertise: A CORRECTION MUST SUPERSEDE THE HEAD, NOT THE ROOT.**
///    Correcting a moment that has already been corrected, by naming the
///    original event again, produces a canonically-later sibling — and a later
///    sibling loses. It is stored, durable and signed, and it is invisible: no
///    row, no error, no counter, nothing on any surface saying a correction was
///    rejected. `ops/held-moments.py` prints the count so it is not silent, but
///    the real defence is that the minting pipeline reads the current
///    `head_event_id` and supersedes that. Pinned by
///    `correcting_a_stale_target_loses_silently`.
/// 3. **Counting.** `moment_count` counts *chains*, so it equals
///    `count(*) FROM moments` — the invariant `/health/deep` publishes against.
///    A supersession updates a row and must not bump it. `ledger_stats` has no
///    decrement path, which is survivable here only because a root can never
///    stop being a root: an event with a known parent is folded, and one with
///    an absent parent is held, so no row this projector inserts is ever
///    re-keyed or removed.
/// 4. **Attribution.** Every projected column comes from the **head**,
///    `author_key` included, because the API publishes the triple
///    (`head_event_id`, `author_key`, `signature`) under the sentence *"the
///    holder of author_key signed this event id"* — and the signature it
///    publishes is joined from the head event. Attributing the row to the root
///    would keep that sentence's shape and destroy its truth: a consumer
///    running Ed25519 over the published triple would get a verification
///    failure on every corrected moment. The original assertion stays reachable
///    the symmetric way, through `root_event_id` -> `events.author_key`.
///
///    The schema calls this column "first-seen proposer". First-seen is an
///    arrival-order fact and cannot survive a fold that must be a function of
///    the event set; the head's author is the canonical reading of the same
///    intent, and is identical to first-seen for every uncorrected moment.
///
/// For a chain of length one — every moment on the live chain at the time this
/// landed — both walks terminate immediately, no event is re-read, and the row
/// written is byte-identical to what M1 wrote.
///
/// **One policy question inside this fold is OPEN, not decided.** `subject` is
/// taken from the head like every other column, so a correction naming a
/// different entity moves the row to that entity. That is either the right
/// answer — mis-attribution is a real error class and supersession is how a
/// correction is expressed — or a silent data movement no consumer could
/// predict from what the API publishes. The permissive behaviour is what ships,
/// pinned by `a_correction_may_move_its_subject_and_that_is_undecided`, because
/// the alternatives both cost something real: refusing the fold re-introduces
/// two live readings, and enforcing sameness in both walks would need the
/// subject at every step, which lives inside `payload` and would put
/// `ops/held-moments.py`'s SQL walk permanently out of step with this one.
///
/// It affects **no stored data** — nothing on the chain carries `supersedes`,
/// and we are the only writer — so it is cheap to leave open and cheap to
/// change. Routed to timepoint-telemetry; tracked in `PLAN.md`. Do not treat
/// the test as an endorsement: it records what the code does so a change is
/// visible, which is not the same as agreeing with it.
async fn project_moment(
    tx: &mut Transaction<'_, Postgres>,
    c: &EventContent,
    id: EventId,
    _m: &cc_core::MomentBody,
) -> Result<(), LedgerError> {
    let Some(root) = chain_root(tx, id, c.supersedes).await? else {
        // Held: an ancestor is referenced but unseen. Deliberately silent and
        // deliberately not an error — the event is durably in `events`, and the
        // arrival that completes the chain projects it. `ops/held-moments.py`
        // reports what is currently in this state.
        return Ok(());
    };
    let head = chain_head(tx, root).await?;

    let (subject, coord, record_coord, posture, body_hash, author_key) =
        moment_columns(tx, head, id, c).await?;

    // Ask before writing rather than reading `rows_affected`, which an upsert
    // reports as 1 for an insert and for an update alike. The counter that
    // published 351 over a table holding 321 was a counter whose movement was
    // inferred from a write's return value instead of from the fact it claims.
    let existed: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM moments WHERE root_event_id = $1)")
            .bind(root.as_bytes().to_vec())
            .fetch_one(&mut **tx)
            .await?;

    sqlx::query(
        "INSERT INTO moments \
         (root_event_id, head_event_id, subject, coord, record_coord, posture, body_hash, author_key) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT (root_event_id) DO UPDATE SET \
           head_event_id = EXCLUDED.head_event_id, \
           subject       = EXCLUDED.subject, \
           coord         = EXCLUDED.coord, \
           record_coord  = EXCLUDED.record_coord, \
           posture       = EXCLUDED.posture, \
           body_hash     = EXCLUDED.body_hash, \
           author_key    = EXCLUDED.author_key",
    )
    .bind(root.as_bytes().to_vec())
    .bind(head.as_bytes().to_vec())
    .bind(subject)
    .bind(&coord)
    .bind(&record_coord)
    .bind(posture)
    .bind(&body_hash)
    .bind(&author_key)
    .execute(&mut **tx)
    .await?;

    if !existed {
        bump(tx, "moment_count").await?;
    }
    Ok(())
}

/// Walk `supersedes` up to the chain's root.
///
/// `None` means **hold**: an ancestor is referenced and this node has not seen
/// it. A moment whose parent exists but is not itself a moment has an
/// ill-formed lineage, which is treated as *no* lineage — it becomes its own
/// root rather than being discarded, because it is still a signed claim and
/// dropping it would make the projection lossy in a way `rebuild` could not
/// repair.
async fn chain_root(
    tx: &mut Transaction<'_, Postgres>,
    id: EventId,
    supersedes: Option<EventId>,
) -> Result<Option<EventId>, LedgerError> {
    let mut cur = id;
    let mut parent = supersedes;
    for _ in 0..MAX_CHAIN {
        let Some(p) = parent else {
            return Ok(Some(cur));
        };
        let row: Option<(i16, Option<Vec<u8>>)> =
            sqlx::query_as("SELECT kind, supersedes FROM events WHERE event_id = $1")
                .bind(p.as_bytes().to_vec())
                .fetch_optional(&mut **tx)
                .await?;
        let Some((kind, next)) = row else {
            return Ok(None);
        };
        if kind != EventKind::Moment.to_i16() {
            return Ok(Some(cur));
        }
        cur = p;
        parent = match next {
            Some(b) => Some(EventId::from_bytes(fixed32(b, "event_id")?)),
            None => None,
        };
    }
    Err(LedgerError::Corruption(
        "supersedes chain exceeds MAX_CHAIN",
    ))
}

/// Walk down from the root to the surviving head, taking the
/// canonically-earliest child at every step.
///
/// `ORDER BY event_time, event_id` is the same total order `rebuild` folds in.
/// `event_time` is offset-binary, so its byte order is chronological order
/// including negative pre-Clock-Zero coordinates.
async fn chain_head(
    tx: &mut Transaction<'_, Postgres>,
    root: EventId,
) -> Result<EventId, LedgerError> {
    let mut cur = root;
    for _ in 0..MAX_CHAIN {
        let next: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT event_id FROM events \
             WHERE supersedes = $1 AND kind = $2 \
             ORDER BY event_time, event_id LIMIT 1",
        )
        .bind(cur.as_bytes().to_vec())
        .bind(EventKind::Moment.to_i16())
        .fetch_optional(&mut **tx)
        .await?;
        match next {
            None => return Ok(cur),
            Some(b) => cur = EventId::from_bytes(fixed32(b, "event_id")?),
        }
    }
    Err(LedgerError::Corruption(
        "supersedes chain exceeds MAX_CHAIN",
    ))
}

/// The projected columns of one moment event: `(subject, coord, record_coord,
/// posture, body_hash, author_key)`.
///
/// Uses the in-hand content when `want` is the event being applied — the common
/// case, and the whole of the case for an uncorrected moment — and otherwise
/// re-reads and re-parses it from `events`. The re-read re-checks `H0`, so a
/// tampered payload reached through a chain walk is loud corruption rather than
/// a silently mis-projected head.
async fn moment_columns(
    tx: &mut Transaction<'_, Postgres>,
    want: EventId,
    have_id: EventId,
    have: &EventContent,
) -> Result<(i64, Vec<u8>, Vec<u8>, i16, Vec<u8>, Vec<u8>), LedgerError> {
    if want == have_id {
        let EventBody::Moment(m) = &have.body else {
            return Err(LedgerError::Corruption(
                "moment projector given a non-moment",
            ));
        };
        return Ok((
            m.subject,
            have.event_time.to_canon_bytes().to_vec(),
            have.record_time.to_canon_bytes().to_vec(),
            have.event_time.posture(have.record_time),
            m.body_hash.to_vec(),
            have.author.to_bytes().to_vec(),
        ));
    }

    let row = sqlx::query(
        "SELECT author_key, event_time, record_time, payload FROM events WHERE event_id = $1",
    )
    .bind(want.as_bytes().to_vec())
    .fetch_optional(&mut **tx)
    .await?
    // Unreachable: both walks only ever name rows they just read out of
    // `events`, inside this transaction, on an append-only table.
    .ok_or(LedgerError::Corruption(
        "chain names an event that is absent",
    ))?;

    let author = AuthorKey::from_bytes(&fixed32(
        row.try_get::<Vec<u8>, _>("author_key")?,
        "author_key",
    )?)
    .map_err(|_| LedgerError::Corruption("author_key not a valid ed25519 key"))?;
    let event_time = Tick::from_canon_bytes(fixed32(
        row.try_get::<Vec<u8>, _>("event_time")?,
        "event_time",
    )?);
    let record_time = Tick::from_canon_bytes(fixed32(
        row.try_get::<Vec<u8>, _>("record_time")?,
        "record_time",
    )?);
    let payload: Vec<u8> = row.try_get("payload")?;
    let content = parse_event(&payload, event_time, record_time, author)
        .map_err(|_| LedgerError::Corruption("payload failed to parse"))?;
    if event_id(&content) != want {
        return Err(LedgerError::Corruption("H0(payload) != stored event_id"));
    }
    let EventBody::Moment(m) = &content.body else {
        return Err(LedgerError::Corruption("chain names a non-moment event"));
    };
    Ok((
        m.subject,
        event_time.to_canon_bytes().to_vec(),
        record_time.to_canon_bytes().to_vec(),
        event_time.posture(record_time),
        m.body_hash.to_vec(),
        author.to_bytes().to_vec(),
    ))
}

async fn project_edge(
    tx: &mut Transaction<'_, Postgres>,
    c: &EventContent,
    id: EventId,
    ed: &cc_core::EdgeBody,
) -> Result<(), LedgerError> {
    let res = sqlx::query(
        "INSERT INTO edges \
         (edge_id, src_entity, dst_entity, relation, evidence_class, asserter, event_time, status, in_g, cross_writer) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,0,false,false) ON CONFLICT (edge_id) DO NOTHING",
    )
    .bind(id.as_bytes().to_vec())
    .bind(ed.src)
    .bind(ed.dst)
    .bind(ed.relation as i16)
    .bind(ed.evidence_class as i16)
    .bind(c.author.to_bytes().to_vec())
    .bind(c.event_time.to_canon_bytes().to_vec())
    .execute(&mut **tx)
    .await?;
    if res.rows_affected() == 1 {
        bump(tx, "edge_count").await?;
        // If both endpoints are already present, this edge joins C now.
        refresh_edge(tx, id).await?;
    }
    Ok(())
}

async fn project_attestation(
    tx: &mut Transaction<'_, Postgres>,
    c: &EventContent,
    id: EventId,
    a: &cc_core::AttestationBody,
) -> Result<(), LedgerError> {
    let res = sqlx::query(
        "INSERT INTO attestations (event_id, target, author) \
         VALUES ($1,$2,$3) ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(id.as_bytes().to_vec())
    .bind(a.target.as_bytes().to_vec())
    .bind(c.author.to_bytes().to_vec())
    .execute(&mut **tx)
    .await?;
    if res.rows_affected() == 1 {
        bump(tx, "attestation_count").await?;
    }
    Ok(())
}

/// Recompute one edge's `in_g` / `cross_writer` from the CURRENT endpoint
/// asserters and move the P(G) aggregates by the exact delta. Idempotent and
/// order-independent: it reads the current (canonical) asserters, so it yields
/// the same result whichever event triggered it — the edge's own projection, an
/// endpoint entity arriving, or an endpoint's canonical-survivor changing. An
/// edge joins `contested_edges` exactly once (guarded on the false->true
/// transition); a later survivor change moves only `cross_writer_contested`, by
/// its signed delta. So re-apply and rebuild reproduce both counters exactly.
async fn refresh_edge(
    tx: &mut Transaction<'_, Postgres>,
    edge_id: EventId,
) -> Result<(), LedgerError> {
    let row = sqlx::query(
        "SELECT src_entity, dst_entity, in_g, cross_writer FROM edges WHERE edge_id = $1",
    )
    .bind(edge_id.as_bytes().to_vec())
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(());
    };
    let src: i64 = row.try_get("src_entity")?;
    let dst: i64 = row.try_get("dst_entity")?;
    let was_in_g: bool = row.try_get("in_g")?;
    let was_cross: bool = row.try_get("cross_writer")?;

    let src_asserter: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT asserter FROM entities WHERE entity_id = $1")
            .bind(src)
            .fetch_optional(&mut **tx)
            .await?;
    let dst_asserter: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT asserter FROM entities WHERE entity_id = $1")
            .bind(dst)
            .fetch_optional(&mut **tx)
            .await?;
    let (Some(sa), Some(da)) = (src_asserter, dst_asserter) else {
        return Ok(()); // not both endpoints present yet — nothing to (re)compute
    };
    let cross = sa != da;

    if !was_in_g {
        // First time both endpoints resolved: the edge joins C.
        sqlx::query("UPDATE edges SET in_g = true, cross_writer = $2 WHERE edge_id = $1")
            .bind(edge_id.as_bytes().to_vec())
            .bind(cross)
            .execute(&mut **tx)
            .await?;
        sqlx::query(
            "UPDATE ledger_stats \
             SET contested_edges = contested_edges + 1, \
                 cross_writer_contested = cross_writer_contested + $1 \
             WHERE id = true",
        )
        .bind(if cross { 1i64 } else { 0i64 })
        .execute(&mut **tx)
        .await?;
    } else if was_cross != cross {
        // Already in C, but a canonical-survivor change flipped cross_writer.
        sqlx::query("UPDATE edges SET cross_writer = $2 WHERE edge_id = $1")
            .bind(edge_id.as_bytes().to_vec())
            .bind(cross)
            .execute(&mut **tx)
            .await?;
        sqlx::query(
            "UPDATE ledger_stats SET cross_writer_contested = cross_writer_contested + $1 WHERE id = true",
        )
        .bind(if cross { 1i64 } else { -1i64 })
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Refresh every edge incident to an entity — used when the entity is born (some
/// incident edges may now have both endpoints) or when its canonical survivor
/// changes (incident in_g edges may need cross_writer recomputed). Selects both
/// in_g states; `refresh_edge` is a no-op for an edge whose other endpoint is
/// still absent or whose verdict is unchanged.
async fn refresh_incident_edges(
    tx: &mut Transaction<'_, Postgres>,
    entity_id: i64,
) -> Result<(), LedgerError> {
    let edge_ids: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT edge_id FROM edges WHERE src_entity = $1 OR dst_entity = $1")
            .bind(entity_id)
            .fetch_all(&mut **tx)
            .await?;
    for eid in edge_ids {
        let arr: [u8; 32] = eid
            .try_into()
            .map_err(|_| LedgerError::Corruption("edge_id width != 32"))?;
        refresh_edge(tx, EventId::from_bytes(arr)).await?;
    }
    Ok(())
}

// ===========================================================================
// rebuild + view_root — the discardability proof.
// ===========================================================================

/// Drop the whole materialized view and re-derive it from `events` in canonical
/// fold order, then assert the result is byte-identical to the live view. That
/// assertion IS the proof that Postgres is discardable. Never touches `events`.
pub async fn rebuild(pool: &PgPool) -> Result<[u8; 32], LedgerError> {
    let before = view_root(pool).await?;

    let mut tx = pool.begin().await?;
    // TRUNCATE every projection — NEVER `events` (the append-only trigger would
    // convert an accidental ledger truncate into a loud abort).
    //
    // `roots` and `anchors` are deliberately NOT in this list, though they were
    // until cc-anchor landed and made the omission observable. They look like
    // projections and are described as such, but they are not folds of `events`:
    // a root publication is recorded as a node-0 moment whose payload is a
    // `body_hash`, i.e. a COMMITMENT to the publication rather than the
    // publication itself. That is enough to verify a `roots` row and not enough
    // to reconstruct one. Truncating them here therefore destroyed settlement
    // history that no amount of replaying `events` could bring back — the exact
    // opposite of what a discardability proof is for. cc-anchor detects the
    // resulting state and refuses to seal over it (`AnchorError::RootStreamLost`);
    // this keeps rebuild from being the thing that causes it.
    sqlx::query(
        "TRUNCATE entities, moments, edges, attestations, taxonomy_tags, vocabulary, ledger_stats",
    )
    .execute(&mut *tx)
    .await?;
    // Deliberately DO NOT seed ledger_stats here: apply() ensures the row on the
    // first folded event, so a non-empty ledger reproduces it, and an empty
    // ledger correctly leaves it ABSENT — so an empty rebuild's `after` (no row)
    // equals `before` (no row) instead of forking None vs a zeroed row.

    // Fold ALL events in canonical (event_time, event_id) order. event_time is
    // offset-binary, so the byte order IS the signed-integer chronological order
    // (negative pre-Clock-Zero coordinates sort first).
    let rows = sqlx::query(
        "SELECT event_id, author_key, signature, event_time, record_time, payload \
         FROM events ORDER BY event_time, event_id",
    )
    .fetch_all(&mut *tx)
    .await?;

    for r in rows {
        let id = EventId::from_bytes(fixed32(r.try_get::<Vec<u8>, _>("event_id")?, "event_id")?);
        let author = AuthorKey::from_bytes(&fixed32(
            r.try_get::<Vec<u8>, _>("author_key")?,
            "author_key",
        )?)
        .map_err(|_| LedgerError::Corruption("author_key not a valid ed25519 key"))?;
        let event_time = Tick::from_canon_bytes(fixed32(
            r.try_get::<Vec<u8>, _>("event_time")?,
            "event_time",
        )?);
        let record_time = Tick::from_canon_bytes(fixed32(
            r.try_get::<Vec<u8>, _>("record_time")?,
            "record_time",
        )?);
        let payload: Vec<u8> = r.try_get("payload")?;
        let signature = Signature::from_bytes(fixed64(r.try_get::<Vec<u8>, _>("signature")?)?);

        let content = parse_event(&payload, event_time, record_time, author)
            .map_err(|_| LedgerError::Corruption("payload failed to parse"))?;
        // Integrity: the stored id must equal H0 of the parsed content, and the
        // signature must verify under the stored author key — exactly as the
        // replay path recomputes H0 == event_id and re-checks the signature
        // (checklist B/F). A tampered row is loud corruption, not a silent fold.
        if event_id(&content) != id {
            return Err(LedgerError::Corruption("H0(payload) != stored event_id"));
        }
        verify(&author, id.as_bytes(), &signature)
            .map_err(|_| LedgerError::Corruption("stored signature does not verify"))?;
        apply(&mut tx, &content, id).await?;
    }
    tx.commit().await?;

    let after = view_root(pool).await?;
    if before != after {
        return Err(LedgerError::RebuildDivergence {
            before: hex::encode(before),
            after: hex::encode(after),
        });
    }
    Ok(after)
}

fn fixed32(v: Vec<u8>, what: &'static str) -> Result<[u8; 32], LedgerError> {
    v.try_into().map_err(|_| match what {
        "event_id" => LedgerError::Corruption("event_id width != 32"),
        "author_key" => LedgerError::Corruption("author_key width != 32"),
        "event_time" => LedgerError::Corruption("event_time width != 32"),
        _ => LedgerError::Corruption("record_time width != 32"),
    })
}

fn fixed64(v: Vec<u8>) -> Result<[u8; 64], LedgerError> {
    v.try_into()
        .map_err(|_| LedgerError::Corruption("signature width != 64"))
}

/// Canonical 32-byte digest of the entire materialized view. Byte-identical iff
/// the view is. Each table's rows are serialized (length-framed, fixed column
/// order) sorted by primary key, and the tables are folded in a fixed name
/// order — reusing the same SHA-256 that defines `H0`. `ledger_stats` is inside
/// the digest, so a drifted counter shows up as `before != after` in rebuild.
pub async fn view_root(pool: &PgPool) -> Result<[u8; 32], LedgerError> {
    let mut h = Sha256::new();

    h_str(&mut h, "entities");
    let rows = sqlx::query(
        "SELECT entity_id, birth_event, birth_event_time, resolution_key, canonical_name, window_start, start_state, closure_state, window_end, asserter \
         FROM entities ORDER BY entity_id",
    )
    .fetch_all(pool)
    .await?;
    h_i64(&mut h, rows.len() as i64);
    for r in &rows {
        h_i64(&mut h, r.try_get::<i64, _>("entity_id")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("birth_event")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("birth_event_time")?);
        h_str(&mut h, &r.try_get::<String, _>("resolution_key")?);
        h_str(&mut h, &r.try_get::<String, _>("canonical_name")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("window_start")?);
        h_i16(&mut h, r.try_get::<i16, _>("start_state")?);
        h_i16(&mut h, r.try_get::<i16, _>("closure_state")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("window_end")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("asserter")?);
    }

    h_str(&mut h, "vocabulary");
    let rows = sqlx::query(
        "SELECT claim_type, label, declared_by, declared_at, band_start, start_state, band_end, closure_state \
         FROM vocabulary ORDER BY claim_type",
    )
    .fetch_all(pool)
    .await?;
    h_i64(&mut h, rows.len() as i64);
    for r in &rows {
        h_i64(&mut h, r.try_get::<i64, _>("claim_type")?);
        h_str(&mut h, &r.try_get::<String, _>("label")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("declared_by")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("declared_at")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("band_start")?);
        h_i16(&mut h, r.try_get::<i16, _>("start_state")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("band_end")?);
        h_i16(&mut h, r.try_get::<i16, _>("closure_state")?);
    }

    h_str(&mut h, "moments");
    let rows = sqlx::query(
        "SELECT root_event_id, head_event_id, subject, coord, record_coord, posture, body_hash, author_key \
         FROM moments ORDER BY root_event_id",
    )
    .fetch_all(pool)
    .await?;
    h_i64(&mut h, rows.len() as i64);
    for r in &rows {
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("root_event_id")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("head_event_id")?);
        h_i64(&mut h, r.try_get::<i64, _>("subject")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("coord")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("record_coord")?);
        h_i16(&mut h, r.try_get::<i16, _>("posture")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("body_hash")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("author_key")?);
    }

    h_str(&mut h, "edges");
    let rows = sqlx::query(
        "SELECT edge_id, src_entity, dst_entity, relation, evidence_class, asserter, event_time, status, in_g, cross_writer \
         FROM edges ORDER BY edge_id",
    )
    .fetch_all(pool)
    .await?;
    h_i64(&mut h, rows.len() as i64);
    for r in &rows {
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("edge_id")?);
        h_i64(&mut h, r.try_get::<i64, _>("src_entity")?);
        h_i64(&mut h, r.try_get::<i64, _>("dst_entity")?);
        h_i16(&mut h, r.try_get::<i16, _>("relation")?);
        h_i16(&mut h, r.try_get::<i16, _>("evidence_class")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("asserter")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("event_time")?);
        h_i16(&mut h, r.try_get::<i16, _>("status")?);
        h_bool(&mut h, r.try_get::<bool, _>("in_g")?);
        h_bool(&mut h, r.try_get::<bool, _>("cross_writer")?);
    }

    h_str(&mut h, "attestations");
    let rows = sqlx::query("SELECT event_id, target, author FROM attestations ORDER BY event_id")
        .fetch_all(pool)
        .await?;
    h_i64(&mut h, rows.len() as i64);
    for r in &rows {
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("event_id")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("target")?);
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("author")?);
    }

    // taxonomy_tags / roots / anchors are empty in M1 (populated in M3/M4), but
    // hashing them now means the discardability proof already covers them the
    // moment they carry rows — no future edit to view_root can be forgotten.
    h_str(&mut h, "taxonomy_tags");
    let rows =
        sqlx::query("SELECT event_id, lens, tag FROM taxonomy_tags ORDER BY event_id, lens, tag")
            .fetch_all(pool)
            .await?;
    h_i64(&mut h, rows.len() as i64);
    for r in &rows {
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("event_id")?);
        h_i16(&mut h, r.try_get::<i16, _>("lens")?);
        h_str(&mut h, &r.try_get::<String, _>("tag")?);
    }

    h_str(&mut h, "roots");
    let rows = sqlx::query("SELECT root_id, height, moment_id FROM roots ORDER BY root_id")
        .fetch_all(pool)
        .await?;
    h_i64(&mut h, rows.len() as i64);
    for r in &rows {
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("root_id")?);
        h_i64(&mut h, r.try_get::<i64, _>("height")?);
        h_opt_bytes(&mut h, &r.try_get::<Option<Vec<u8>>, _>("moment_id")?);
    }

    h_str(&mut h, "anchors");
    let rows = sqlx::query("SELECT root_id, status, txid FROM anchors ORDER BY root_id")
        .fetch_all(pool)
        .await?;
    h_i64(&mut h, rows.len() as i64);
    for r in &rows {
        h_bytes(&mut h, &r.try_get::<Vec<u8>, _>("root_id")?);
        h_i16(&mut h, r.try_get::<i16, _>("status")?);
        h_opt_bytes(&mut h, &r.try_get::<Option<Vec<u8>>, _>("txid")?);
    }

    h_str(&mut h, "ledger_stats");
    let row = sqlx::query(
        "SELECT entity_count, moment_count, edge_count, attestation_count, contested_edges, \
                cross_writer_contested \
         FROM ledger_stats WHERE id = true",
    )
    .fetch_optional(pool)
    .await?;
    match row {
        None => h_i64(&mut h, 0),
        Some(r) => {
            h_i64(&mut h, 1);
            h_i64(&mut h, r.try_get::<i64, _>("entity_count")?);
            h_i64(&mut h, r.try_get::<i64, _>("moment_count")?);
            h_i64(&mut h, r.try_get::<i64, _>("edge_count")?);
            h_i64(&mut h, r.try_get::<i64, _>("attestation_count")?);
            h_i64(&mut h, r.try_get::<i64, _>("contested_edges")?);
            h_i64(&mut h, r.try_get::<i64, _>("cross_writer_contested")?);
        }
    }

    Ok(h.finalize().into())
}

fn h_bytes(h: &mut Sha256, x: &[u8]) {
    h.update((x.len() as u32).to_be_bytes());
    h.update(x);
}
fn h_str(h: &mut Sha256, s: &str) {
    h_bytes(h, s.as_bytes());
}
fn h_i64(h: &mut Sha256, v: i64) {
    h_bytes(h, &v.to_be_bytes());
}
fn h_i16(h: &mut Sha256, v: i16) {
    h_bytes(h, &v.to_be_bytes());
}
fn h_bool(h: &mut Sha256, v: bool) {
    h_bytes(h, &[v as u8]);
}
fn h_opt_bytes(h: &mut Sha256, x: &Option<Vec<u8>>) {
    match x {
        None => h.update([0u8]),
        Some(b) => {
            h.update([1u8]);
            h_bytes(h, b);
        }
    }
}
// ===========================================================================
// Read helper (the maintained aggregates; the M5 /health/deep source).
// ===========================================================================

/// The maintained aggregates, read as one indexed single-row lookup — never a
/// `COUNT(*)` over the projection tables (memo §6/§9).
#[derive(Debug, Clone, serde::Serialize)]
pub struct LedgerStats {
    pub entity_count: i64,
    pub moment_count: i64,
    pub edge_count: i64,
    pub attestation_count: i64,
    pub contested_edges: i64,
    pub cross_writer_contested: i64,
    /// `P(G)` — NULL (None) when there are no contested edges (vacuous, Prop.
    /// vacuity), never a protective-looking `0.0` (memo §5).
    pub protected_fraction: Option<f64>,
}

/// Read the maintained aggregates, or `None` on a ledger that has folded nothing
/// yet (distinct from a zeroed row — no-evidence vs empty, memo §5).
pub async fn read_stats(pool: &PgPool) -> Result<Option<LedgerStats>, LedgerError> {
    let row = sqlx::query(
        "SELECT entity_count, moment_count, edge_count, attestation_count, contested_edges, \
                cross_writer_contested, protected_fraction \
         FROM ledger_stats_public",
    )
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        None => None,
        Some(r) => Some(LedgerStats {
            entity_count: r.try_get("entity_count")?,
            moment_count: r.try_get("moment_count")?,
            edge_count: r.try_get("edge_count")?,
            attestation_count: r.try_get("attestation_count")?,
            contested_edges: r.try_get("contested_edges")?,
            cross_writer_contested: r.try_get("cross_writer_contested")?,
            protected_fraction: r.try_get("protected_fraction")?,
        }),
    })
}

// ===========================================================================
// Errors
// ===========================================================================

/// Errors from the ledger write path and projector. A `Reject` (a fact about a
/// submission) is not yet distinguished from infra here — that split lands with
/// the full ingest funnel in M2; M1's failures are a bad signature, a DB fault,
/// or ledger corruption detected during rebuild.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("signature verification failed")]
    BadSignature,
    #[error("ledger corruption: {0}")]
    Corruption(&'static str),
    #[error("rebuild divergence: incremental view {before} != batch view {after}")]
    RebuildDivergence { before: String, after: String },
}
