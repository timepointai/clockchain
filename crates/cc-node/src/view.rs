//! `PgCorpusView` — the Postgres side of the `CorpusView` seam.
//!
//! The filter is the consensus rule. `cc-node` therefore never re-implements a
//! feasibility predicate in SQL: it implements the *evidence* trait the filter
//! reads through, and the verdict comes out of the same compiled logic a wasm
//! mirror would run over `SnapshotCorpus`. Everything in this file is a query
//! that returns evidence; nothing in it decides anything.
//!
//! # The `as_of` bound is the whole file
//!
//! Every query carries `<= as_of` on the coordinate the evidence takes effect
//! at. That clause is not an optimization and not a convenience filter: it is
//! what makes a `t_q`-pinned verdict monotone, because a moment recorded later
//! cannot touch it if the view never yields it. There is deliberately no method
//! here — public or private — that reads the projection without the bound.
//!
//! # Errors are never verdicts
//!
//! Every failure to *reach or decode* the store becomes [`ViewError`], which the
//! filter propagates as `Err` and the HTTP layer maps to `503 Unavailable`. An
//! empty result from a query that succeeded is the opposite thing: a real,
//! evidenced silence that yields `Unsupported`. A handler that reported a
//! connection error as `Unsupported` would bill a caller a certain verdict for a
//! void, so the two never merge.
//!
//! # Why the trait methods block
//!
//! `CorpusView` is a synchronous trait — it has to be, because it also has to
//! compile to `wasm32` inside a mirror with no executor. The bridge is
//! deliberate and narrow: the async query bodies are the real implementations,
//! and each sync method drives one on a runtime handle. Every caller must
//! therefore run the filter inside [`tokio::task::spawn_blocking`]; calling it
//! from an async task instead panics loudly (`block_on` from within a runtime),
//! which is the correct failure — a silently starved executor would be worse.

use std::collections::BTreeMap;

use cc_core::{EventId, Tick, WindowEnd};
use cc_filter::{
    Admitted, ClaimType, CorpusDigest, CorpusView, Edge, EntityId, Start, ViewError, Windowed,
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

/// Domain separation for this view's corpus digest, so it can never collide with
/// a digest taken over a snapshot corpus by the same hash function.
const DST_PG_CORPUS: &[u8] = b"cc.node.pgcorpus.v0";

/// A time-sliced read-only view of the projection tables.
///
/// Constructed per request. Construction establishes the identity of the event
/// set being projected, and **failing to establish it is a construction
/// failure** — fail-closed lives above the filter, so a view that cannot say
/// what inputs it holds never gets to judge with them.
#[derive(Clone)]
pub struct PgCorpusView {
    pool: PgPool,
    rt: tokio::runtime::Handle,
    digest: CorpusDigest,
}

impl PgCorpusView {
    /// Open a view over the current event set.
    ///
    /// # The digest is a single-row read, and has to be
    ///
    /// The digest names the *inputs* a verdict was taken over, so a node
    /// comparing verdicts with a peer can tell a gossip-horizon gap from a
    /// governance event. This used to fold every `event_id` in the database on
    /// every request: exact, but an `O(n)` scan on the read path, which is the
    /// one path that is supposed to stay cheap. At 47,904 events that was
    /// already the dominant cost of answering a query.
    ///
    /// The maintained counters were never an option — two different event sets
    /// of the same size share their counters, and a digest that *falsely
    /// matches* is worse than an expensive one, because it reports agreement
    /// that does not exist. What replaced the scan is a real commitment to the
    /// set, folded once per event by an `AFTER INSERT` trigger on the
    /// append-only `events` table (migration `0006`), so it is exact, it is
    /// order-independent, and reading it costs one row.
    pub async fn open(pool: &PgPool) -> Result<PgCorpusView, ViewError> {
        let row = sqlx::query("SELECT n, acc FROM event_digest WHERE id = true")
            .fetch_optional(pool)
            .await
            .map_err(|e| ViewError::Backend(e.to_string()))?
            // The row is created by the migration and never deleted. Its absence
            // means the schema is not what this binary was built against, which
            // is a construction failure, not an empty corpus — answering `0
            // events` here would let a mis-migrated node judge confidently.
            .ok_or_else(|| {
                ViewError::Backend("event_digest row is missing; run migrations".into())
            })?;

        let n: i64 = row.try_get("n").map_err(decode)?;
        let acc: Vec<u8> = row.try_get("acc").map_err(decode)?;

        // The count is folded in beside the accumulator so an empty corpus and a
        // corpus whose element hashes happen to XOR to zero are not the same 32
        // bytes. The outer SHA-256 also means the published digest is not the
        // raw accumulator, so a peer cannot read the internal state off a
        // verdict and work in its algebra directly.
        let mut buf = Vec::with_capacity(DST_PG_CORPUS.len() + 40);
        buf.extend_from_slice(DST_PG_CORPUS);
        buf.extend_from_slice(&n.to_be_bytes());
        buf.extend_from_slice(&acc);
        let digest = CorpusDigest::from_bytes(Sha256::digest(&buf).into());

        Ok(PgCorpusView {
            pool: pool.clone(),
            rt: tokio::runtime::Handle::current(),
            digest,
        })
    }

    /// Co-occurrence neighbours, ascending by `(other, via)`.
    ///
    /// # What plays the part of `B(t)` here
    ///
    /// The plan's `cooccurrence` projection does not exist in the schema yet, so
    /// the co-occurrence relation is read off `edges` — the only projection that
    /// relates two entities at a coordinate. An edge event *is* an evidenced
    /// co-location of its endpoints at its `event_time`, so this is the honest
    /// reading of the corpus as it stands, not a substitute rule. When the
    /// maintained `cooccurrence` table lands (it also wants moments with several
    /// participants, which the current `moments.subject` column cannot express)
    /// this query moves to it and nothing else here changes.
    ///
    /// `event_time` is stored as offset-binary canonical bytes, so `bytea`
    /// comparison *is* signed-integer comparison on the coordinate axis — the
    /// `<= as_of` clause needs no decoding and rides the btree.
    async fn neighbors_at(&self, entity: EntityId, as_of: Tick) -> Result<Vec<Edge>, ViewError> {
        let bound = as_of.to_canon_bytes().to_vec();
        let rows = sqlx::query(
            "SELECT dst_entity AS other, edge_id AS via FROM edges \
               WHERE src_entity = $1 AND event_time <= $2 \
             UNION ALL \
             SELECT src_entity AS other, edge_id AS via FROM edges \
               WHERE dst_entity = $1 AND event_time <= $2 \
             ORDER BY other, via",
        )
        .bind(entity.to_i64())
        .bind(&bound)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let other: i64 = r.try_get("other").map_err(decode)?;
            let via: Vec<u8> = r.try_get("via").map_err(decode)?;
            out.push(Edge {
                other: EntityId::from_i64(other),
                via: EventId::from_bytes(fixed32(via, "edges.edge_id")?),
            });
        }
        Ok(out)
    }

    /// One query for a whole BFS level.
    ///
    /// Identical in meaning to calling [`PgCorpusView::neighbors_at`] per entity
    /// — same relation, same `as_of` bound, same rows — and that equivalence is
    /// the contract, not an optimisation detail. What changes is the number of
    /// round trips: a four-hop walk over this corpus visits thousands of
    /// entities, and one query per entity made the network the cost of a
    /// verdict.
    ///
    /// Entities with no recorded neighbours are simply absent from the map;
    /// `expand` reads that as an empty neighbour list, which is what a
    /// per-entity call would have returned.
    async fn neighbors_many_at(
        &self,
        entities: &[EntityId],
        as_of: Tick,
    ) -> Result<BTreeMap<EntityId, Vec<Edge>>, ViewError> {
        if entities.is_empty() {
            return Ok(BTreeMap::new());
        }
        let ids: Vec<i64> = entities.iter().map(|e| e.to_i64()).collect();
        let bound = as_of.to_canon_bytes().to_vec();
        // `= ANY($1)` rather than an IN-list built by string concatenation: the
        // ids are bound, so a frontier of any size is one prepared statement
        // instead of a new query plan per level.
        let rows = sqlx::query(
            "SELECT src_entity AS anchor, dst_entity AS other, edge_id AS via FROM edges \
               WHERE src_entity = ANY($1) AND event_time <= $2 \
             UNION ALL \
             SELECT dst_entity AS anchor, src_entity AS other, edge_id AS via FROM edges \
               WHERE dst_entity = ANY($1) AND event_time <= $2",
        )
        .bind(&ids)
        .bind(&bound)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;

        let mut out: BTreeMap<EntityId, Vec<Edge>> = BTreeMap::new();
        for r in &rows {
            let anchor: i64 = r.try_get("anchor").map_err(decode)?;
            let other: i64 = r.try_get("other").map_err(decode)?;
            let via: Vec<u8> = r.try_get("via").map_err(decode)?;
            out.entry(EntityId::from_i64(anchor))
                .or_default()
                .push(Edge {
                    other: EntityId::from_i64(other),
                    via: EventId::from_bytes(fixed32(via, "edges.edge_id")?),
                });
        }
        Ok(out)
    }

    /// The entity's existence window as this view records it at `as_of`.
    ///
    /// The `as_of` gate is on `birth_event_time` — the coordinate at which the
    /// window *became recorded* — not on the window's own start. An entity born
    /// into the ledger with an event-time after `as_of` is invisible here, which
    /// is exactly the guarantee that keeps a later-discovered cessation from
    /// touching an earlier-pinned verdict.
    ///
    /// An entity the projection has never seen is [`Windowed::unrecorded`]: a
    /// real evidenced silence yielding `Unsupported`, never an error and never a
    /// `Contradicted`.
    pub async fn window_at(&self, entity: EntityId, as_of: Tick) -> Result<Windowed, ViewError> {
        let bound = as_of.to_canon_bytes().to_vec();
        let row = sqlx::query(
            "SELECT window_start, start_state, closure_state, window_end, birth_event \
             FROM entities WHERE entity_id = $1 AND birth_event_time <= $2",
        )
        .bind(entity.to_i64())
        .bind(&bound)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;

        let Some(r) = row else {
            return Ok(Windowed::unrecorded());
        };
        decode_window(&r)
    }

    /// `Admiss(c, t_q)` against the governed vocabulary snapshot.
    ///
    /// Three outcomes, and the difference between the last two is the whole
    /// reason this returns [`Admitted`] rather than a `bool`:
    ///
    /// * the type is in the vocabulary and `as_of` is inside its band → `Valid`;
    /// * the vocabulary has no such type, **or has one whose band has not begun
    ///   by `as_of`** → `Unrecorded`. Silence. A type declared to apply from 1957
    ///   says nothing about the year 1200; it does not contradict it;
    /// * the vocabulary records a band that *ended* before `as_of` →
    ///   `OutsideValidity`. That is positive contrary evidence — the record
    ///   asserts this classification had been retired — and it earns
    ///   `Contradicted`, not `Unsupported`.
    ///
    /// A declaration with an `Unknown` band start is treated as *not yet begun*,
    /// for the same reason an entity with an unknown start is: an unevidenced
    /// beginning must not be read as a beginning at Clock Zero.
    ///
    /// Note this is the only factor whose store is keyed by the claim type
    /// rather than by an entity, so it stays `O(1)` on a primary-key lookup —
    /// which is what lets the filter evaluate it before the expensive walk.
    async fn admissibility_at(&self, c: ClaimType, as_of: Tick) -> Result<Admitted, ViewError> {
        let row = sqlx::query(
            "SELECT declared_by, band_start, start_state, band_end, closure_state \
             FROM vocabulary WHERE claim_type = $1",
        )
        .bind(i64::from(c.to_u32()))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;

        let Some(r) = row else {
            return Ok(Admitted::Unrecorded);
        };

        let declared_by = EventId::from_bytes(fixed32(
            r.try_get("declared_by").map_err(decode)?,
            "vocabulary.declared_by",
        )?);
        let derived_from = vec![declared_by];

        let start_state: i16 = r.try_get("start_state").map_err(decode)?;
        if start_state != 0 {
            // No evidenced beginning: silence, not a band starting at ORIGIN.
            return Ok(Admitted::Unrecorded);
        }
        let band_start = Tick::from_canon_bytes(fixed32(
            r.try_get("band_start").map_err(decode)?,
            "vocabulary.band_start",
        )?);
        if as_of < band_start {
            return Ok(Admitted::Unrecorded);
        }

        // The recorded-retirement arm is checked before the open arms, so
        // contrary evidence dominates silence — the same ordering `cc-filter`'s
        // window factor uses, and for the same reason.
        let closure: i16 = r.try_get("closure_state").map_err(decode)?;
        if closure == 1 {
            let band_end = Tick::from_canon_bytes(fixed32(
                r.try_get("band_end").map_err(decode)?,
                "vocabulary.band_end",
            )?);
            if as_of > band_end {
                return Ok(Admitted::OutsideValidity {
                    band_end,
                    derived_from,
                });
            }
        }
        Ok(Admitted::Valid { derived_from })
    }

    /// Resolve a human label to its governed code.
    ///
    /// The API takes labels because a caller should not have to know a `u32`,
    /// but the code is what rides in the verdict and the version hash. An
    /// unresolvable label yields `None` and the caller must refuse the query:
    /// substituting a default would answer a question nobody asked, and code `0`
    /// is reserved precisely so a failed resolution cannot land on a real type.
    pub async fn claim_type_for_label(&self, label: &str) -> Result<Option<ClaimType>, ViewError> {
        let code: Option<i64> =
            sqlx::query_scalar("SELECT claim_type FROM vocabulary WHERE label = $1")
                .bind(label)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| ViewError::Backend(e.to_string()))?;
        Ok(code.map(|c| ClaimType::from_u32(c as u32)))
    }

    /// The descriptive projection columns for one entity, under the identical
    /// `as_of` gate [`PgCorpusView::window_at`] applies.
    ///
    /// Split out rather than folded into the window read so that the window this
    /// endpoint publishes is literally the value the filter sees — one code path,
    /// not two that agree today.
    pub async fn entity_projection(
        &self,
        entity: EntityId,
        as_of: Tick,
    ) -> Result<Option<EntityRow>, ViewError> {
        let bound = as_of.to_canon_bytes().to_vec();
        let row = sqlx::query(
            "SELECT entity_id, canonical_name, resolution_key, birth_event, birth_event_time, asserter \
             FROM entities WHERE entity_id = $1 AND birth_event_time <= $2",
        )
        .bind(entity.to_i64())
        .bind(&bound)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;

        let Some(r) = row else { return Ok(None) };
        Ok(Some(EntityRow {
            entity_id: r.try_get("entity_id").map_err(decode)?,
            canonical_name: r.try_get("canonical_name").map_err(decode)?,
            resolution_key: r.try_get("resolution_key").map_err(decode)?,
            birth_event: EventId::from_bytes(fixed32(
                r.try_get("birth_event").map_err(decode)?,
                "entities.birth_event",
            )?),
            birth_coord: Tick::from_canon_bytes(fixed32(
                r.try_get("birth_event_time").map_err(decode)?,
                "entities.birth_event_time",
            )?),
            asserter: hex::encode(r.try_get::<Vec<u8>, _>("asserter").map_err(decode)?),
        }))
    }

    /// A range of moments at or before `as_of`, newest first.
    ///
    /// One btree descent plus `limit` sequential rows on `moments_coord_idx`.
    /// `from` is an optional lower bound so a caller can walk a window rather
    /// than only the tail; both bounds are canonical coordinate bytes, so the
    /// comparison is the same order the coordinate axis has.
    pub async fn moments_before(
        &self,
        as_of: Tick,
        from: Option<Tick>,
        limit: i64,
    ) -> Result<Vec<MomentRow>, ViewError> {
        let upper = as_of.to_canon_bytes().to_vec();
        // A NULL lower bound is a real "no lower bound", kept as SQL rather than
        // as two query strings so there is one statement to read and audit.
        let lower: Option<Vec<u8>> = from.map(|t| t.to_canon_bytes().to_vec());
        let rows = sqlx::query(
            "SELECT root_event_id, head_event_id, subject, coord, record_coord, posture, \
                    body_hash, author_key \
             FROM moments \
             WHERE coord <= $1 AND ($2::bytea IS NULL OR coord >= $2) \
             ORDER BY coord DESC, root_event_id DESC \
             LIMIT $3",
        )
        .bind(&upper)
        .bind(&lower)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(MomentRow {
                root_event_id: EventId::from_bytes(fixed32(
                    r.try_get("root_event_id").map_err(decode)?,
                    "moments.root_event_id",
                )?),
                head_event_id: EventId::from_bytes(fixed32(
                    r.try_get("head_event_id").map_err(decode)?,
                    "moments.head_event_id",
                )?),
                subject: r.try_get("subject").map_err(decode)?,
                coord: Tick::from_canon_bytes(fixed32(
                    r.try_get("coord").map_err(decode)?,
                    "moments.coord",
                )?),
                record_coord: Tick::from_canon_bytes(fixed32(
                    r.try_get("record_coord").map_err(decode)?,
                    "moments.record_coord",
                )?),
                posture: r.try_get("posture").map_err(decode)?,
                body_hash: hex::encode(r.try_get::<Vec<u8>, _>("body_hash").map_err(decode)?),
                author_key: hex::encode(r.try_get::<Vec<u8>, _>("author_key").map_err(decode)?),
            });
        }
        Ok(out)
    }

    /// The most recently *recorded* moments at or before `as_of_record`.
    ///
    /// Ordered on `record_coord`, not `coord`: this answers "what did this
    /// ledger learn most recently", which is a different question from "what
    /// happened most recently". A gallery of fresh mints wants the former.
    ///
    /// The `root_event_id` tiebreaker is load-bearing rather than defensive.
    /// Two moments can share a `record_coord`, and without a total order the
    /// same query would return them in an arbitrary and unstable sequence —
    /// a caller polling the feed would see rows permute for no reason.
    ///
    /// Edges incident to an entity, with each endpoint's stored `claim_type`.
    ///
    /// The types come back with the edge because the TT context is derived from
    /// them: fetching the edge and then looking its endpoints up separately
    /// would let the two drift within one response.
    pub async fn incident_edges(
        &self,
        entity: EntityId,
        as_of: Tick,
    ) -> Result<Vec<(i64, i64, i16, i16, Option<String>, Option<String>)>, ViewError> {
        let bound = as_of.to_canon_bytes().to_vec();
        let rows = sqlx::query(
            "SELECT x.src_entity, x.dst_entity, x.relation, x.evidence_class, \
                    sb.body::json ->> 'claim_type' AS src_type, \
                    db.body::json ->> 'claim_type' AS dst_type \
             FROM edges x \
             LEFT JOIN LATERAL ( \
               SELECT cb.body FROM moments m JOIN claim_bodies cb ON cb.body_hash = m.body_hash \
               WHERE m.subject = x.src_entity AND m.coord <= $2 \
               ORDER BY m.record_coord DESC LIMIT 1) sb ON true \
             LEFT JOIN LATERAL ( \
               SELECT cb.body FROM moments m JOIN claim_bodies cb ON cb.body_hash = m.body_hash \
               WHERE m.subject = x.dst_entity AND m.coord <= $2 \
               ORDER BY m.record_coord DESC LIMIT 1) db ON true \
             WHERE (x.src_entity = $1 OR x.dst_entity = $1) AND x.event_time <= $2 \
             ORDER BY x.event_time DESC LIMIT 200",
        )
        .bind(entity.to_i64())
        .bind(&bound)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push((
                r.try_get("src_entity").map_err(decode)?,
                r.try_get("dst_entity").map_err(decode)?,
                r.try_get("relation").map_err(decode)?,
                r.try_get("evidence_class").map_err(decode)?,
                r.try_get("src_type").map_err(decode)?,
                r.try_get("dst_type").map_err(decode)?,
            ));
        }
        Ok(out)
    }

    /// The newest claim body for an entity at or before `as_of`.
    ///
    /// The entity projection carries identity only — name, window, birth event.
    /// The TT layer a reader needs (claim type, lens, bundle citation) lives in
    /// the claim body, and until this existed the TT layer was **write-path-real
    /// and reader-invisible**: enforced on every mint and projected to nobody.
    /// Telemetry found that by probing three entities and getting back seven
    /// identity fields and no TT at all.
    ///
    /// `None` is a real answer — a moment whose bytes were not retained — and is
    /// rendered as a typed absence rather than an empty object.
    pub async fn claim_body_for(
        &self,
        entity: EntityId,
        as_of: Tick,
    ) -> Result<Option<String>, ViewError> {
        let bound = as_of.to_canon_bytes().to_vec();
        let row = sqlx::query(
            "SELECT cb.body \
             FROM moments m \
             JOIN claim_bodies cb ON cb.body_hash = m.body_hash \
             WHERE m.subject = $1 AND m.coord <= $2 \
             ORDER BY m.record_coord DESC, m.root_event_id DESC \
             LIMIT 1",
        )
        .bind(entity.to_i64())
        .bind(&bound)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;
        Ok(match row {
            None => None,
            Some(r) => Some(r.try_get("body").map_err(decode)?),
        })
    }

    /// Every live reading of this entity's claim, newest first.
    ///
    /// **Two rows are not two claims.** Entity identity is content-derived from
    /// `(title, year)`, and `content_hash` is a function of the same pair, so
    /// every moment on one subject describes the same claim by construction.
    /// What can differ is the *reading* — summary, provenance, classification —
    /// all of which sit outside the hash.
    ///
    /// Three entities carry two readings each today, from a pilot run and a
    /// later regeneration. Until this existed the surface returned one of them,
    /// chosen by `record_coord`, and said nothing about the other: a reader met
    /// a single body with no way to tell it was one of several, and a reader who
    /// found both met what looked like a duplication bug. **The fix is to say
    /// what they are, not to edit the record until the relation disappears** —
    /// preserve the distinction rather than assert it away. No mint, no
    /// deletion, `rebuild()` unaffected, and it covers the next such pair on the
    /// day it appears rather than needing an intervention each time.
    pub async fn readings_for(
        &self,
        entity: EntityId,
        as_of: Tick,
    ) -> Result<Vec<(String, Option<String>)>, ViewError> {
        let bound = as_of.to_canon_bytes().to_vec();
        let rows = sqlx::query(
            "SELECT encode(m.body_hash, 'hex') AS bh, cb.body \
             FROM moments m \
             LEFT JOIN claim_bodies cb ON cb.body_hash = m.body_hash \
             WHERE m.subject = $1 AND m.coord <= $2 \
             ORDER BY m.record_coord DESC, m.root_event_id DESC",
        )
        .bind(entity.to_i64())
        .bind(&bound)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push((
                r.try_get("bh").map_err(decode)?,
                r.try_get("body").map_err(decode)?,
            ));
        }
        Ok(out)
    }

    /// `as_of_record` is required by the same rule every other read obeys: a
    /// read with no coordinate is malformed, never an implicit read of now.
    /// It also lets a caching consumer record *which* coordinate produced its
    /// snapshot, so a stale cache is detectable rather than merely old.
    pub async fn recents(
        &self,
        as_of_record: Tick,
        limit: i64,
    ) -> Result<Vec<RecentRow>, ViewError> {
        let upper = as_of_record.to_canon_bytes().to_vec();
        let rows = sqlx::query(
            "SELECT m.root_event_id, m.head_event_id, m.subject, m.coord, \
                    m.record_coord, m.posture, m.body_hash, m.author_key, \
                    e.signature, en.canonical_name, en.resolution_key, \
                    cb.body \
             FROM moments m \
             JOIN events e ON e.event_id = m.head_event_id \
             JOIN entities en ON en.entity_id = m.subject \
             LEFT JOIN claim_bodies cb ON cb.body_hash = m.body_hash \
             WHERE m.record_coord <= $1 \
             ORDER BY m.record_coord DESC, m.root_event_id DESC \
             LIMIT $2",
        )
        .bind(&upper)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ViewError::Backend(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(RecentRow {
                root_event_id: EventId::from_bytes(fixed32(
                    r.try_get("root_event_id").map_err(decode)?,
                    "moments.root_event_id",
                )?),
                head_event_id: EventId::from_bytes(fixed32(
                    r.try_get("head_event_id").map_err(decode)?,
                    "moments.head_event_id",
                )?),
                subject: r.try_get("subject").map_err(decode)?,
                coord: Tick::from_canon_bytes(fixed32(
                    r.try_get("coord").map_err(decode)?,
                    "moments.coord",
                )?),
                record_coord: Tick::from_canon_bytes(fixed32(
                    r.try_get("record_coord").map_err(decode)?,
                    "moments.record_coord",
                )?),
                posture: r.try_get("posture").map_err(decode)?,
                body_hash: hex::encode(r.try_get::<Vec<u8>, _>("body_hash").map_err(decode)?),
                author_key: hex::encode(r.try_get::<Vec<u8>, _>("author_key").map_err(decode)?),
                signature: hex::encode(r.try_get::<Vec<u8>, _>("signature").map_err(decode)?),
                canonical_name: r.try_get("canonical_name").map_err(decode)?,
                resolution_key: r.try_get("resolution_key").map_err(decode)?,
                body: r.try_get("body").map_err(decode)?,
            });
        }
        Ok(out)
    }

    /// The identity of the event set, for echoing beside a verdict.
    pub fn digest(&self) -> CorpusDigest {
        self.digest
    }
}

impl CorpusView for PgCorpusView {
    fn neighbors(&self, entity: EntityId, as_of: Tick) -> Result<Vec<Edge>, ViewError> {
        self.rt.block_on(self.neighbors_at(entity, as_of))
    }

    fn neighbors_many(
        &self,
        entities: &[EntityId],
        as_of: Tick,
    ) -> Result<BTreeMap<EntityId, Vec<Edge>>, ViewError> {
        self.rt.block_on(self.neighbors_many_at(entities, as_of))
    }

    fn window(&self, entity: EntityId, as_of: Tick) -> Result<Windowed, ViewError> {
        self.rt.block_on(self.window_at(entity, as_of))
    }

    fn admissibility(&self, c: ClaimType, as_of: Tick) -> Result<Admitted, ViewError> {
        self.rt.block_on(self.admissibility_at(c, as_of))
    }

    fn corpus_digest(&self) -> CorpusDigest {
        self.digest
    }
}

/// The projection columns of one entity row, rendered for the read surface.
pub struct EntityRow {
    pub entity_id: i64,
    pub canonical_name: String,
    pub resolution_key: String,
    pub birth_event: EventId,
    pub birth_coord: Tick,
    pub asserter: String,
}

/// The projection columns of one moment row.
pub struct MomentRow {
    pub root_event_id: EventId,
    pub head_event_id: EventId,
    pub subject: i64,
    pub coord: Tick,
    pub record_coord: Tick,
    pub posture: i16,
    pub body_hash: String,
    pub author_key: String,
}

/// One row of the recents feed: a moment, its subject's name, and the signature
/// over its head event.
///
/// The name and the signature come from joins rather than from `moments`,
/// because neither is a property of a moment: a title belongs to the *subject*,
/// and a signature belongs to the *event*. Denormalising either would make the
/// feed cheaper and the model wrong.
pub struct RecentRow {
    pub root_event_id: EventId,
    pub head_event_id: EventId,
    pub subject: i64,
    pub coord: Tick,
    pub record_coord: Tick,
    pub posture: i16,
    pub body_hash: String,
    pub author_key: String,
    /// Hex Ed25519 signature over the 32 raw bytes of `head_event_id`, so a
    /// reader can check the claim instead of trusting it.
    pub signature: String,
    pub canonical_name: String,
    pub resolution_key: String,
    /// The bytes `body_hash` commits to, when they were kept. `None` is a real
    /// state — the claim is attributed in the ledger's hash but its attribution
    /// was not retained — and must never be rendered as "no generator".
    pub body: Option<String>,
}

/// Lift one `entities` row into the filter's three-state window type.
///
/// Both ends of the window are tagged, and both tags are honoured here. The
/// arithmetic collapses `known_open` and `unknown_closure` onto the same
/// sentinel, and an unknown start onto the same sentinel again — so the
/// coordinate columns alone cannot say which is which, and reconstructing the
/// window from them would silently turn "the record is silent about when this
/// began" into "this began at the sentinel". The discriminants are what stop
/// that, so an out-of-range one is corruption rather than a defaulted state.
fn decode_window(r: &sqlx::postgres::PgRow) -> Result<Windowed, ViewError> {
    let stored_start = Tick::from_canon_bytes(fixed32(
        r.try_get("window_start").map_err(decode)?,
        "entities.window_start",
    )?);
    let start_state: i16 = r.try_get("start_state").map_err(decode)?;
    let start = match start_state {
        0 => Start::Known(stored_start),
        // Silence, and it must stay silence: an unevidenced start yields
        // `Unsupported`, never `Contradicted`, because absence of a record is
        // not a record of absence.
        1 => Start::Unknown,
        other => {
            return Err(ViewError::Decode(format!(
                "entities.start_state = {other}, which is not a start state"
            )))
        }
    };
    let closure: i16 = r.try_get("closure_state").map_err(decode)?;
    let stored_end = Tick::from_canon_bytes(fixed32(
        r.try_get("window_end").map_err(decode)?,
        "entities.window_end",
    )?);
    let birth = EventId::from_bytes(fixed32(
        r.try_get("birth_event").map_err(decode)?,
        "entities.birth_event",
    )?);

    // The closure discriminant carries what the arithmetic cannot: `KnownOpen`
    // and `UnknownClosure` both store the sentinel, and collapsing them would
    // turn "confirmed still active" and "we have no cessation record" into the
    // same sentence. An out-of-range discriminant is corruption, and corruption
    // is as loud as an outage — never a defaulted-to-open window.
    let end = match closure {
        0 => WindowEnd::KnownOpen,
        1 => WindowEnd::KnownClosed(stored_end),
        2 => WindowEnd::UnknownClosure,
        other => {
            return Err(ViewError::Decode(format!(
                "entities.closure_state = {other}, which is not a closure state"
            )))
        }
    };

    Ok(Windowed {
        start,
        end,
        derived_from: vec![birth],
    })
}

/// A `bytea` column that must be exactly 32 bytes wide.
///
/// A short or long value is a corrupt projection, which must be as loud as an
/// outage rather than truncated into something that looks like an id.
fn fixed32(v: Vec<u8>, what: &'static str) -> Result<[u8; 32], ViewError> {
    let n = v.len();
    v.try_into()
        .map_err(|_| ViewError::Decode(format!("{what} is {n} bytes wide, expected 32")))
}

/// A row that came back but could not be read as the typed value it must be.
fn decode(e: sqlx::Error) -> ViewError {
    ViewError::Decode(e.to_string())
}
