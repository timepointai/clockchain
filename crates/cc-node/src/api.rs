//! The read surface, plus the single write path a frozen node refuses.
//!
//! # No route sprawl
//!
//! v1 accreted twenty-four write routes because adding one was cheaper than
//! asking whether the write model had grown incoherent. What is here is a
//! deliberate list, and adding to it is a design decision:
//!
//! | route | job |
//! |---|---|
//! | `GET /v1/entities/{id}` | one entity as the projection records it at `as_of` |
//! | `GET /v1/moments` | a coordinate range of moments at or before `as_of` |
//! | `POST /v1/feasibility` | the filter's verdict, with the rule and inputs that produced it |
//! | `POST /v1/events` | append one signed event through the ledger's choke point |
//!
//! # Every read is pinned
//!
//! `as_of` is required on all three reads. There is no "current" reading of this
//! corpus available through this API, deliberately: the `CorpusView` trait makes
//! the bound mandatory so a later moment cannot leak into a pinned verdict, and
//! an HTTP layer that substituted the wall clock for a missing parameter would
//! reintroduce exactly that leak one level up.
//!
//! # The verdict is the filter's, not this module's
//!
//! Nothing here computes feasibility. [`feasibility`] builds a `CorpusView` over
//! Postgres and hands it to `cc-filter`; the same compiled logic answers on a
//! server, in a batch job and inside a wasm mirror. A SQL predicate that
//! reproduced the rule would fork it the first time one of the three changed.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use cc_core::{AuthorKey, Signature, Tick};
use cc_filter::{
    Certificate, ClaimType, EntityId, FeasibilityQuery, FilterError, HopBound, QueryError, Verdict,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::coord::{parse_as_of, render};
use crate::error::ApiError;
use crate::protocol::hex_version;
use crate::state::AppState;
use crate::view::PgCorpusView;

/// The most moments one request may ask for.
///
/// A larger `limit` is **refused, not clamped**. Clamping would answer a
/// different question than the one asked and report it as the answer to the
/// original — the same class of quiet substitution as defaulting `as_of`.
const MAX_LIMIT: i64 = 500;

/// The default page size when the caller does not choose one.
const DEFAULT_LIMIT: i64 = 50;

// ===========================================================================
// GET /v1/entities/{entity_id}
// ===========================================================================

/// Query parameters shared by the pinned reads.
#[derive(Deserialize)]
pub struct AsOfParams {
    /// Required. Absent is a malformed request, never "now".
    as_of: Option<String>,
}

/// The relation between an entity's readings — FOUR states, emptiness first.
///
/// Extracted as a pure function so it can be verified **with no database at
/// all**. timepoint-telemetry could confirm the shipped logic only by reading
/// it: `tests/api.rs` needs `TEST_DATABASE_URL` and their machine has none, so
/// their claim was "the code says the right thing" rather than "I watched it do
/// the right thing". That is a weaker claim than the ones they make about the
/// corpus, and they said so rather than glossing it. A state machine over a
/// slice of `Option<String>` needs no Postgres to exercise, and now doesn't.
///
/// **Emptiness is checked BEFORE anything is compared**, and that ordering is
/// the whole defence. `windows(2).all(..)` is vacuously true on an empty slice,
/// so a comparison-first version publishes `one_claim_many_readings` over zero
/// readings. Three defects this month share that shape — `grep -c` over a
/// command that produced no output, `if total` treating a count of zero as
/// absent, and this — and telemetry's through-line names them as one thing:
/// **an aggregate over an empty input is indistinguishable from an aggregate
/// over a real one.** The defence is structural, not vigilance: check emptiness
/// before you compute, because afterwards the two cannot be told apart.
fn readings_relation(hashes: &[Option<String>]) -> &'static str {
    if hashes.is_empty() {
        // Not a relation at all. Distinct from every state below.
        "no_readings"
    } else if hashes.iter().any(Option::is_none) {
        // A body was not retained, so nothing can be compared. Saying
        // "different" here would invent a distinction as surely as saying
        // "same" would invent an identity.
        "cannot_compare"
    } else if hashes.windows(2).all(|w| w[0] == w[1]) {
        "one_claim_many_readings"
    } else {
        // Same entity, different claims — their titles normalise together.
        // `claim_identity` hashes a NORMALISED title, `content_hash` the raw
        // one, so this is reachable by design rather than by accident.
        "several_claims_sharing_an_entity"
    }
}

/// One entity, as the projection records it at the pinned coordinate.
///
/// The `window` reported here is produced by `CorpusView::window` — the *same*
/// call the filter makes — so what a caller sees and what a verdict was computed
/// over cannot drift apart. The descriptive columns come from a second read
/// under the identical `as_of` gate.
pub async fn get_entity(
    State(state): State<AppState>,
    Path(entity_id): Path<i64>,
    Query(q): Query<AsOfParams>,
) -> Result<Json<Value>, ApiError> {
    let as_of = parse_as_of(q.as_of.as_deref())?;
    let view = PgCorpusView::open(&state.pool).await?;
    let id = EntityId::from_i64(entity_id);

    let Some(row) = view.entity_projection(id, as_of).await? else {
        return Err(ApiError::NotFound(format!(
            "no entity {entity_id} recorded at or before this coordinate"
        )));
    };
    let window = view.window_for_response(id, as_of).await?;

    // The TT layer, DERIVED from the stored claim body — nothing here is
    // minted and no stored byte changes. Until this existed the TT layer was
    // write-path-real and reader-invisible: enforced on every mint, projected
    // to nobody. A TT-integrated chain nobody can read is not integrated.
    let readings = view.readings_for(id, as_of).await?;
    // Each reading's content_hash, COMPUTED from its own stored title and year.
    // `None` means the body was not retained, which is a third state and not a
    // variant of "different".
    let reading_hashes: Vec<Option<String>> = readings
        .iter()
        .map(|(_, body)| {
            let b: Value = serde_json::from_str(body.as_deref()?).ok()?;
            let title = b.get("title").and_then(Value::as_str)?.to_string();
            let year = b.get("year").and_then(Value::as_i64)?;
            crate::tt::content_hash(&title, year).ok()
        })
        .collect();
    let relation = readings_relation(&reading_hashes);
    let readings_json: Vec<Value> = readings
        .iter()
        .zip(&reading_hashes)
        .map(|((bh, _), ch)| json!({"body_hash": bh, "content_hash": ch}))
        .collect();
    let tt_layer = match view.claim_body_for(id, as_of).await? {
        None => json!({"present": false,
                       "reason": "no claim body retained for this entity at this coordinate"}),
        Some(body) => match serde_json::from_str::<Value>(&body) {
            Err(e) => json!({"present": false, "reason": format!("stored body is not JSON: {e}")}),
            Ok(b) => {
                let title = b.get("title").and_then(Value::as_str).unwrap_or_default();
                let year = b.get("year").and_then(Value::as_i64);
                let claim_type = b.get("claim_type").and_then(Value::as_str);
                // The envelope is a pure function of the STORED title and year.
                // Both are returned beside the hash so a verifier recomputes
                // from what the surface returned rather than from our
                // description of it — telemetry asked for exactly that.
                let (payload, content_hash) = match year {
                    Some(y) => (
                        Some(crate::tt::payload(title, y)),
                        crate::tt::content_hash(title, y).ok(),
                    ),
                    None => (None, None),
                };
                // The §4 profile. When the stored body carries one it is
                // returned as stored; otherwise it is DERIVED from the claim
                // type — one entry at mass 1.0 — and says which it is. The
                // field was previously projected as `null` on every claim,
                // which reads as "no reading exists" when in fact there is one
                // and it is a confident single type.
                let (classification, classification_source) = match b.get("classification") {
                    Some(c) if !c.is_null() => (c.clone(), "stored"),
                    _ => match claim_type.and_then(crate::tt::classification_from_claim_type) {
                        Some(c) => (c, "derived from claim_type at mass 1.0"),
                        None => (Value::Null, "unavailable: claim type is not a bundle node"),
                    },
                };
                json!({
                    "present": true,
                    "claim_type": claim_type,
                    "lens": b.get("lens"),
                    "claim_type_alternatives": b.get("claim_type_alternatives"),
                    "alternatives_cross_lens": b.get("alternatives_cross_lens"),
                    "classification": classification,
                    "classification_source": classification_source,
                    // The citation a validator accepts, derived from the pinned
                    // bundle. Distinct from `tt_release_as_stored` below: the
                    // stored string is our own internal spelling and TT's
                    // validator rejects it with `bundle-mismatch`. Returning
                    // only the stored one taught readers a spelling that fails.
                    "bundle": cc_filter::version::TT_VERSION_STRING,
                    "tt_release_as_stored": b.get("tt_release"),
                    "tt_bundle_sha256": b.get("tt_bundle_sha256"),
                    "envelope": {
                        "content_hash": content_hash,
                        "payload": payload,
                        "canonical": year.and_then(|y| crate::tt::content_canonical(title, y).ok()),
                        "renderings": "label <- title verbatim; occurs_at <- unpadded decimal \
                                       year; participants <- [] (the record holds none)",
                    },
                    "shadow": claim_type.map(crate::tt::shadow_of),
                })
            }
        },
    };

    // Incident edges, each carrying its DERIVED TT context. The edge's own
    // relation stays Causation/Influence — Clockchain's axis, because TT labels
    // nodes and defines no event-to-event vocabulary. What TT contributes is
    // context about the endpoints: their types, whether the edge crosses lenses,
    // the taxonomic distance between the KINDS, and whether the pair is a
    // bundle bridge.
    let rel_name = |r: i16| match r {
        0 => "CoOccurrence",
        1 => "Influence",
        2 => "Causation",
        3 => "Participation",
        4 => "Attestation",
        5 => "Supersession",
        _ => "unknown",
    };
    let ev_name = |e: i16| match e {
        0 => "PrimaryDocument",
        1 => "SecondarySource",
        2 => "Inference",
        3 => "Assertion",
        _ => "unknown",
    };
    let edges: Vec<Value> = view
        .incident_edges(id, as_of)
        .await?
        .into_iter()
        .map(|(src, dst, rel, ev, st, dt)| {
            json!({
                "src_entity": src.to_string(),
                "dst_entity": dst.to_string(),
                "direction": if src == entity_id { "outgoing" } else { "incoming" },
                "relation": rel_name(rel),
                "evidence_class": ev_name(ev),
                "relation_axis": "Clockchain's own; TT defines no event-to-event vocabulary",
                "tt": crate::tt::edge_context(st.as_deref(), dt.as_deref()),
            })
        })
        .collect();

    Ok(Json(json!({
        "as_of": render(as_of),
        "corpus_digest": hex::encode(view.digest().as_bytes()),
        "entity": {
            "entity_id": row.entity_id,
            "canonical_name": row.canonical_name,
            "resolution_key": row.resolution_key,
            "birth_event": row.birth_event.to_hex(),
            "birth_coord": render(row.birth_coord),
            "asserter": row.asserter,
            "window": window,
        },
        "tt": tt_layer,
        // Claim-identity siblings — COMPUTED, never assumed.
        //
        // The first version asserted `same_claim: true` on the premise that
        // "entity identity and content_hash are both functions of (title,
        // year)". They are functions of DIFFERENT things, and the difference is
        // a deliberate, tested feature:
        //
        //   claim_identity  hashes normalise(title) | year   — lowercase, ASCII
        //                   alphanumerics, runs collapsed, trimmed
        //   content_hash    hashes the RAW title as `label`
        //
        // So presentational noise is inside one and outside the other, and
        // `claim_identity_is_stable_and_normalises_the_title` asserts exactly
        // the collapse the premise assumed impossible: "  the FALL, of
        // Constantinople!  " and "the fall of constantinople" share an
        // entity_id and do NOT share a content_hash.
        //
        // Publishing "these are readings of one claim" when the hashes differ
        // would be a surface asserting an identity TT does not grant — an
        // over-merge on a normalisation basin, which is the Ctesiphon failure in
        // new clothes, committed by the block written to honour the doctrine.
        // And it would have shipped GREEN: all three current pairs have equal
        // hashes, so the sentence is true of today's corpus and false in
        // general, staying true until the first title-variant pair arrives.
        // Caught by timepoint-telemetry before deploy.
        //
        // So: compare, then report the verdict. `validate.py` already did this
        // correctly; the assertion here was the second copy that drifted.
        "readings": {
            "count": readings.len(),
            "this": readings.first().map(|(h, _)| h.clone()),
            "all": readings_json,
            "relation": relation,
            "note": "`relation` is computed from each reading's stored title and \
                     year, never assumed. entity_id hashes a NORMALISED title and \
                     content_hash hashes the raw one, so two rows can share an \
                     entity and not a claim — their titles normalise together. \
                     one_claim_many_readings: same content_hash, differing only \
                     outside it. several_claims_sharing_an_entity: distinct \
                     claims, and no sameness is asserted. cannot_compare: a body \
                     was not retained, which is neither. no_readings: none at \
                     this coordinate, which is not a relation at all. Count \
                     claims by content_hash, never by rows.",
        },
        "edge_count": edges.len(),
        "edges": edges,
    })))
}

// ===========================================================================
// GET /v1/moments
// ===========================================================================

/// Query parameters for the moment range read.
#[derive(Deserialize)]
pub struct MomentParams {
    as_of: Option<String>,
    /// Optional inclusive lower bound on the coordinate, same spelling as
    /// `as_of`.
    from: Option<String>,
    limit: Option<i64>,
}

/// A coordinate range of moments at or before `as_of`, newest first.
pub async fn list_moments(
    State(state): State<AppState>,
    Query(q): Query<MomentParams>,
) -> Result<Json<Value>, ApiError> {
    let as_of = parse_as_of(q.as_of.as_deref())?;
    let from = match q.from.as_deref() {
        None => None,
        Some(f) => Some(parse_as_of(Some(f))?),
    };
    let limit = match q.limit {
        None => DEFAULT_LIMIT,
        Some(n) if (1..=MAX_LIMIT).contains(&n) => n,
        Some(n) => {
            return Err(ApiError::BadRequest(format!(
                "limit must be between 1 and {MAX_LIMIT}; got {n}. It is refused rather than \
                 clamped, so the answer always describes the question that was asked."
            )))
        }
    };

    let view = PgCorpusView::open(&state.pool).await?;
    let rows = view.moments_before(as_of, from, limit).await?;
    let moments: Vec<Value> = rows
        .iter()
        .map(|m| {
            json!({
                "root_event_id": m.root_event_id.to_hex(),
                "head_event_id": m.head_event_id.to_hex(),
                "subject": m.subject,
                "coord": render(m.coord),
                "record_coord": render(m.record_coord),
                // sign(event_time - record_time): -1 mined-past,
                // 0 witnessed-present, +1 staked-future.
                //
                // NOT frozen at birth — this comment said so and M1b made it
                // false. `posture`, `coord` and `record_coord` all follow the
                // chain HEAD, so a correction can move all three. A correction
                // that changes `event_time` MOVES THE ROW ACROSS `as_of`
                // WINDOWS: a consumer paging this endpoint by coordinate can
                // watch a moment appear in or vanish from a window with no
                // event inside that window to explain it. That is a real
                // consumer-visible consequence of the fold, and it is why a
                // coordinate-moving correction is a recorded decision at mint
                // time (CLOCKCHAIN-CONSUMER-CONTRACT.md), not a routine re-mint.
                "posture": m.posture,
                "body_hash": m.body_hash,
                // Head-attributed, and it must STAY head-attributed. This
                // endpoint publishes the pair without a signature, so it cannot
                // itself mis-verify — but a reader holding this `author_key`
                // and a signature obtained anywhere else is assembling the
                // verification triple across two surfaces. Root attribution
                // here would reopen, cross-surface, the defect caught inside
                // /v1/recents.
                "author_key": m.author_key,
            })
        })
        .collect();

    Ok(Json(json!({
        "as_of": render(as_of),
        "from": from.map(render),
        "limit": limit,
        "corpus_digest": hex::encode(view.digest().as_bytes()),
        "count": moments.len(),
        "moments": moments,
    })))
}

// ===========================================================================
// Flexible scalar deserialization
// ===========================================================================

/// Accept an `i64` written as a JSON number **or** a JSON string.
///
/// Entity ids exceed JavaScript's safe integer range, where `JSON.parse`
/// silently rounds. The contract therefore tells consumers to send them as
/// strings — and the deserializer used to reject exactly that, so a caller
/// following our own documentation got a 422. Beta found it by exercising the
/// contract rather than reading it.
///
/// Both spellings are accepted because refusing either punishes a consumer for
/// a choice we made: numbers are what a naive client sends, strings are what a
/// correct JS client must send.
fn de_i64_flex<'de, D: serde::Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    use serde::de::{Error, Unexpected};
    match Value::deserialize(d)? {
        Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| D::Error::custom("entity id is not an i64")),
        Value::String(s) => s.parse::<i64>().map_err(|_| {
            D::Error::invalid_value(Unexpected::Str(&s), &"an i64 written as a string")
        }),
        other => Err(D::Error::custom(format!(
            "entity id must be a number or a string, got {other}"
        ))),
    }
}

/// Same, for a pair of subjects.
fn de_subjects<'de, D: serde::Deserializer<'de>>(d: D) -> Result<(i64, i64), D::Error> {
    #[derive(Deserialize)]
    struct Pair(
        #[serde(deserialize_with = "de_i64_flex")] i64,
        #[serde(deserialize_with = "de_i64_flex")] i64,
    );
    let Pair(a, b) = Pair::deserialize(d)?;
    Ok((a, b))
}

/// A coordinate, as a string or a number.
///
/// `as_of` is a string everywhere else in this API because a coordinate can
/// exceed i64 and the canonical spelling is hex. Requiring a string in the body
/// while requiring a number for `subjects` in the SAME body is an asymmetry no
/// consumer can guess, so both are accepted here.
fn de_as_of_flex<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    use serde::de::Error;
    match Option::<Value>::deserialize(d)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(other) => Err(D::Error::custom(format!(
            "as_of must be a string or a number, got {other}"
        ))),
    }
}

// ===========================================================================
// GET /v1/recents
// ===========================================================================

/// The public gallery feed's ceiling. Deliberately far below `MAX_LIMIT`: this
/// surface exists to show the freshest mints, and a caller asking for hundreds
/// wants `/v1/moments` instead.
const RECENTS_MAX: i64 = 50;
const RECENTS_DEFAULT: i64 = 10;

/// Query parameters for the recents feed.
#[derive(Deserialize)]
pub struct RecentsParams {
    as_of: Option<String>,
    limit: Option<i64>,
}

/// The most recently *recorded* moments — the freshest mints, newest first.
///
/// Ordered on record coordinate rather than event coordinate: "what this ledger
/// learned most recently" is a different question from "what happened most
/// recently", and a gallery of fresh mints is asking the first.
///
/// Every field a reader needs to *check* the claim is present — `head_event_id`
/// (the signed preimage), `author_key`, and `signature` — because a card that
/// can only be trusted is weaker than one that can be verified. None of the
/// three is secret: `author_key` is an Ed25519 *verifying* key.
pub async fn list_recents(
    State(state): State<AppState>,
    Query(q): Query<RecentsParams>,
) -> Result<Json<Value>, ApiError> {
    let as_of = parse_as_of(q.as_of.as_deref())?;
    let limit = match q.limit {
        None => RECENTS_DEFAULT,
        Some(n) if (1..=RECENTS_MAX).contains(&n) => n,
        Some(n) => {
            return Err(ApiError::BadRequest(format!(
                "limit must be between 1 and {RECENTS_MAX}; got {n}. It is refused rather than \
                 clamped, so the answer always describes the question that was asked."
            )))
        }
    };

    let view = PgCorpusView::open(&state.pool).await?;
    let rows = view.recents(as_of, limit).await?;
    let entries: Vec<Value> = rows
        .iter()
        .map(|m| {
            json!({
                "root_event_id": m.root_event_id.to_hex(),
                // The exact 32 bytes the signature is over.
                "head_event_id": m.head_event_id.to_hex(),
                "subject": m.subject,
                "title": m.canonical_name,
                "resolution_key": m.resolution_key,
                "coord": render(m.coord),
                "record_coord": render(m.record_coord),
                // sign(event_time - record_time): -1 mined-past,
                // 0 witnessed-present, +1 staked-future. NOT frozen at birth:
                // posture, coord and record_coord follow the chain head, so a
                // correction can move them. See /v1/moments for the `as_of`
                // consequence.
                "posture": m.posture,
                "body_hash": m.body_hash,
                "author_key": m.author_key,
                "signature": m.signature,
                // `subject` is a u64-width id and exceeds JS's safe integer
                // range, where JSON.parse silently rounds. A rounded identifier
                // is worse than an absent one: it looks checkable and is not.
                // Sent as a string so it survives every parser intact.
                "subject_id": m.subject.to_string(),
                // The bytes `body_hash` commits to, when kept. Absent is a REAL
                // state — attributed in the hash, not retained — and a consumer
                // must render nothing rather than infer authorship from a gap.
                "body": m.body.as_deref()
                    .and_then(|b| serde_json::from_str::<Value>(b).ok()),
            })
        })
        .collect();

    Ok(Json(json!({
        "as_of": render(as_of),
        "limit": limit,
        "corpus_digest": hex::encode(view.digest().as_bytes()),
        "count": entries.len(),
        // How to check any entry, stated beside the data rather than assumed.
        // Level 1 only: this binds a key to a hash, NOT the hash to the text.
        "verification": {
            "signature_over": "head_event_id, as 32 raw bytes (hex-decode it)",
            "algorithm": "Ed25519",
            "strictness": "signed with verify_strict semantics; a stock verify accepts these",
            "proves": "the holder of author_key signed this event id",
            "does_not_prove":
                "that these fields are the content behind that id — that requires recomputing \
                 SHA-256(canon_event(content)), which needs the canon, not a browser",
        },
        "entries": entries,
    })))
}

// ===========================================================================
// POST /v1/feasibility
// ===========================================================================

/// One feasibility question.
#[derive(Deserialize)]
pub struct FeasibilityRequest {
    /// `(f_i, f_j)` — the two subjects. A number or a string; see
    /// [`de_i64_flex`].
    #[serde(deserialize_with = "de_subjects")]
    subjects: (i64, i64),
    /// `t_q`. Required, same spelling as every other pinned read. A string or
    /// a number; see [`de_as_of_flex`].
    #[serde(default, deserialize_with = "de_as_of_flex")]
    as_of: Option<String>,
    /// `c` — the claimed manner of interaction. **A TT id string, or the legacy
    /// numeric code.** Send the string.
    claim: ClaimRef,
    /// The hop bound to search under. Absent means the governed maximum; a
    /// larger value is refused by the filter as malformed, never silently
    /// searched at the maximum.
    k: Option<u8>,
}

/// How a caller names the claim type.
///
/// **The string spelling exists because the numeric one destroys information.**
/// The code is the first four bytes of `sha256(label)`, so a typo'd id and a
/// valid-but-undeclared id both reach this boundary as well-formed `u32`s that
/// are merely absent from the vocabulary. No check placed here can separate
/// them: what would distinguish them was gone before the request arrived. That
/// is TT conformance gap 2, and the fix is a boundary that can still see the
/// label.
///
/// With the label in hand the two cases separate cleanly, and they must:
///
///   * an id that is **not in the bundle** never existed — a loud `400` naming
///     it, because it is not a question about the world;
///   * an id that is **in the bundle and not in our vocabulary** is a real
///     question this corpus cannot answer — evaluated normally, which yields
///     silence rather than an error. Coverage is honestly ours to assert;
///     validity never is.
///
/// Returning the same outcome for both is the gap/finding collapse.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum ClaimRef {
    /// The legacy numeric code. **Retained with its limitation intact**, which
    /// cannot be repaired at this layer: a numeric claim naming nothing gets the
    /// same silence as one naming a real-but-undeclared type. Documented rather
    /// than quietly true.
    Code(u32),
    /// A TT node id, e.g. `"conflict-and-warfare"`.
    Label(String),
}

impl ClaimRef {
    /// Resolve to the governed code, or refuse loudly.
    ///
    /// Retirement resolves on read (TT `CONSUMERS.md` obligation 3): a query
    /// citing a retired id is answered through its successor rather than
    /// refused, because the stored reading was true when it was made.
    fn resolve(&self) -> Result<u32, ApiError> {
        match self {
            ClaimRef::Code(c) => Ok(*c),
            ClaimRef::Label(l) => {
                if !cc_filter::version::is_valid_tt_id(l) {
                    return Err(ApiError::UnknownClaimType(l.clone()));
                }
                Ok(cc_filter::version::claim_code(
                    cc_filter::version::resolve_tt_id(l),
                ))
            }
        }
    }
}

/// Evaluate the consensus rule and return its three-valued verdict.
///
/// The audit path (`certify`) is used rather than the short-circuiting hot path
/// because the response enumerates the events the verdict consulted, and that
/// list is the attribution seam a Merkle multiproof later replaces — it cannot
/// be reconstructed after the fact for a verdict already given. The two paths
/// agree on the verdict kind by construction; they differ only in how complete
/// the witness list is.
pub async fn feasibility(
    State(state): State<AppState>,
    Json(req): Json<FeasibilityRequest>,
) -> Result<Json<Value>, ApiError> {
    let t_q = parse_as_of(req.as_of.as_deref())?;
    let query = FeasibilityQuery {
        subjects: (
            EntityId::from_i64(req.subjects.0),
            EntityId::from_i64(req.subjects.1),
        ),
        t_q,
        claim: ClaimType::from_u32(req.claim.resolve()?),
        k: HopBound::new(req.k.unwrap_or(state.filter.params().k_max.get())),
    };

    let certificate = judge(&state, query).await?;
    Ok(Json(render_certificate(&certificate, t_q)))
}

/// Run the filter over a Postgres-backed view.
///
/// `CorpusView` is synchronous by necessity (it compiles to wasm, where there is
/// no executor), and its Postgres implementation must issue async queries. The
/// bridge is confined to exactly here: the whole evaluation is moved onto a
/// blocking thread, and the view drives its queries on the runtime handle from
/// there. Running the filter on an async worker instead would starve the
/// executor, and the `block_on` inside the view would panic rather than do it
/// quietly.
pub async fn judge(state: &AppState, query: FeasibilityQuery) -> Result<Certificate, ApiError> {
    // Construction failure is fail-closed and happens before the filter is ever
    // called: a view that cannot establish what it holds does not judge.
    let view = PgCorpusView::open(&state.pool).await?;
    let filter = state.filter.clone();

    let outcome = tokio::task::spawn_blocking(move || filter.certify(&view, &query))
        .await
        .map_err(|e| ApiError::Unavailable(format!("the evaluation task did not complete: {e}")))?;

    outcome.map_err(|e| match e {
        // A view failure is `Unavailable`, never a verdict.
        FilterError::View(v) => ApiError::from(v),
        // A question the governed rule does not sanction. Answering it anyway
        // under a different bound would make the version hash a lie about the
        // search that produced the answer, so it is refused.
        FilterError::Malformed(q) => ApiError::BadRequest(match q {
            QueryError::HopBoundExceedsGoverned {
                requested,
                governed,
            } => format!(
                "k={} exceeds the governed hop bound k_max={}. The bound is bound into the \
                 filter-version hash, so a verdict searched under a larger k would carry a \
                 version that does not describe it.",
                requested.get(),
                governed.get()
            ),
            QueryError::QueryTimeIsSentinel => q.to_string(),
        }),
    })
}

/// Render a certificate as the wire verdict.
///
/// Φ's **magnitude is deliberately absent**, and so is the hop count it is
/// computed from: the v0 smoothing is `1 / (1 + hops)`, so publishing the hop
/// count would hand every consumer the magnitude in a different spelling and let
/// them threshold it. Hard decisions consume `phi_support` — a boolean — and the
/// evidence list; nothing here can be turned into a score.
pub fn render_certificate(c: &Certificate, t_q: Tick) -> Value {
    let j = &c.judgment;
    let common = json!({
        "as_of": render(t_q),
        "evidence_scope": "recorded_graph_feasibility",
        "verdict_policy": "first_zero_in_factor_order",
        "factual_verification": "not_assessed",
        "audit": {
            "schema": "cc.evidence-audit.v1",
            "absences": c.absences.iter().map(absence_json).collect::<Vec<_>>(),
            "contradictions": c.contradictions.iter().map(contrary_json).collect::<Vec<_>>(),
        },
        "filter_version": hex_version(j.filter_version),
        "corpus_digest": hex::encode(j.corpus_digest.as_bytes()),
        // The moments this verdict consulted, deduplicated and in canonical
        // order. This is the attribution channel a metered economy later routes
        // over; the Merkle multiproof that binds it to a published root is not
        // built yet (see the crate docs).
        "consulted": c.consulted.iter().map(|e| e.to_hex()).collect::<Vec<_>>(),
    });
    let mut out = common.as_object().cloned().unwrap_or_default();

    match &j.verdict {
        Verdict::Supported { .. } => {
            out.insert("result".into(), json!("Supported"));
            out.insert("phi_support".into(), json!(true));
        }
        Verdict::Unsupported { because } => {
            out.insert("result".into(), json!("Unsupported"));
            // Non-empty by construction: a zero product is a *certain* witness
            // of missing evidence, and the filter reports which factor vanished.
            out.insert(
                "vanished".into(),
                Value::Array(because.iter().map(absence_json).collect()),
            );
        }
        Verdict::Contradicted { by } => {
            out.insert("result".into(), json!("Contradicted"));
            out.insert("contradicted_by".into(), contrary_json(by));
        }
    }
    Value::Object(out)
}

/// Which factor went to zero through silence.
fn absence_json(w: &cc_filter::AbsenceWitness) -> Value {
    use cc_filter::AbsenceWitness as A;
    match w {
        A::NoRecordedStart { entity } => json!({
            "factor": "existence_window",
            "reason": "no_recorded_start",
            "entity": entity.to_i64(),
        }),
        A::BeforeRecordedStart { entity, start } => json!({
            "factor": "existence_window",
            "reason": "before_recorded_start",
            "entity": entity.to_i64(),
            "recorded_start": render(*start),
        }),
        A::ClaimTypeUnrecorded { claim } => json!({
            "factor": "admissibility",
            "reason": "claim_type_unrecorded",
            "claim": claim.to_u32(),
        }),
        A::NoEvidencedWalk { from, to, within } => json!({
            "factor": "known_k",
            "reason": "no_evidenced_walk",
            "from": from.to_i64(),
            "to": to.to_i64(),
            // "Unreachable" only means something relative to the bound it was
            // searched under, and the bound is governed — so it is reported.
            "within_hops": within.get(),
        }),
    }
}

/// Positive contrary evidence — the record says no rather than saying nothing.
fn contrary_json(w: &cc_filter::ContraryWitness) -> Value {
    use cc_filter::ContraryWitness as C;
    match w {
        C::AfterRecordedCessation {
            entity,
            ceased,
            derived_from,
        } => json!({
            "factor": "existence_window",
            "reason": "after_recorded_cessation",
            "entity": entity.to_i64(),
            "ceased": render(*ceased),
            "derived_from": derived_from.iter().map(|e| e.to_hex()).collect::<Vec<_>>(),
        }),
        C::ClaimTypeOutsideValidity {
            claim,
            band_end,
            derived_from,
        } => json!({
            "factor": "admissibility",
            "reason": "claim_type_outside_validity",
            "claim": claim.to_u32(),
            "band_end": render(*band_end),
            "derived_from": derived_from.iter().map(|e| e.to_hex()).collect::<Vec<_>>(),
        }),
    }
}

// ===========================================================================
// POST /v1/events — the write path
// ===========================================================================

/// One signed event, in exactly the shape the ledger stores and `rebuild` reads
/// back: the canon preimage plus the envelope that authenticates it.
///
/// This is a *relay* of an already-signed event, not native authorship. Native
/// authorship stamps `record_time` from the node's own clock at arrival, which
/// is a different path with a different trust story; it is not built here.
#[derive(Deserialize)]
pub struct SubmitRequest {
    /// `canon(fields)` — the identity-bearing preimage, hex.
    payload: String,
    /// The coordinate the assertion is about, canonical bytes, hex.
    event_time: String,
    /// The writer's own asserted record-time, canonical bytes, hex.
    record_time: String,
    /// Ed25519 public key (32 bytes), hex.
    author: String,
    /// Ed25519 signature over `H0` (64 bytes), hex.
    signature: String,
}

/// The response to a successful append.
#[derive(Serialize)]
pub struct SubmitResponse {
    event_id: String,
    /// `new` (inserted and projected) or `unioned` (already held — a grow-only
    /// set no-op, never an error).
    appended: &'static str,
}

/// Append one signed event through `cc-ledger`'s single write choke point.
///
/// Everything that makes the write safe already lives below this handler:
/// `Signed::seal` recomputes `H0` and verifies the signature, and it is the only
/// constructor of the only type `commit` will store, so an unverified event is
/// not representable as a storable value. This function adds no bypass — it
/// decodes hex and calls the same gate every other writer calls.
pub async fn submit_event(
    State(state): State<AppState>,
    Json(req): Json<SubmitRequest>,
) -> Result<(StatusCode, Json<SubmitResponse>), ApiError> {
    let payload = hexbytes(&req.payload, "payload")?;
    let event_time = Tick::from_canon_bytes(hex32(&req.event_time, "event_time")?);
    let record_time = Tick::from_canon_bytes(hex32(&req.record_time, "record_time")?);
    let author = AuthorKey::from_bytes(&hex32(&req.author, "author")?)
        .map_err(|_| ApiError::BadRequest("author is not a valid ed25519 key".into()))?;
    let signature = Signature::from_bytes(hex64(&req.signature)?);

    let content = cc_core::parse_event(&payload, event_time, record_time, author)
        .map_err(|_| ApiError::BadRequest("payload is not a canonical event preimage".into()))?;
    let signed = cc_ledger::Signed::seal(content, signature).map_err(|_| {
        ApiError::BadRequest(
            "the signature does not verify over H0 of this payload under this author key".into(),
        )
    })?;
    let event_id = signed.id().to_hex();

    match cc_ledger::commit(&state.pool, &signed).await {
        Ok(appended) => Ok((
            StatusCode::CREATED,
            Json(SubmitResponse {
                event_id,
                appended: if appended.is_new() { "new" } else { "unioned" },
            }),
        )),
        // A write that could not reach the store is `Unavailable`, loudly — the
        // caller must be able to retry knowing nothing was recorded.
        Err(e) => Err(ApiError::Unavailable(format!(
            "the event could not be appended: {e}"
        ))),
    }
}

/// `POST /v1/events` on a frozen node.
///
/// Registered at the same path as the live handler so the route list is
/// identical in both postures — a frozen node answers "this exists and is
/// refused because I am frozen", never a `404` that would read as "this node
/// never had a write path". Dying well is a config change, and the shape of the
/// facade is decided here rather than under pressure later.
///
/// It takes no body extractor at all: the refusal is a property of the node, so
/// there is nothing about the request worth parsing, and a malformed body must
/// not turn a `403 frozen` into a `422`.
pub async fn refuse_frozen() -> ApiError {
    ApiError::Frozen
}

// ---------------------------------------------------------------------------
// hex decoding — refusals, never truncations
// ---------------------------------------------------------------------------

fn hexbytes(s: &str, what: &'static str) -> Result<Vec<u8>, ApiError> {
    hex::decode(s).map_err(|_| ApiError::BadRequest(format!("{what} is not hex")))
}

fn hex32(s: &str, what: &'static str) -> Result<[u8; 32], ApiError> {
    hexbytes(s, what)?
        .try_into()
        .map_err(|_| ApiError::BadRequest(format!("{what} must be exactly 32 bytes of hex")))
}

fn hex64(s: &str) -> Result<[u8; 64], ApiError> {
    hexbytes(s, "signature")?
        .try_into()
        .map_err(|_| ApiError::BadRequest("signature must be exactly 64 bytes of hex".into()))
}

/// The wire rendering of a three-state existence window.
///
/// Both ends are tagged rather than collapsed to coordinates. `known_open` and
/// `unknown_closure` produce identical arithmetic — both bound the end at the
/// sentinel — but "confirmed still active" and "we have no cessation record" are
/// different sentences about the record, and a client that could not tell them
/// apart would have to guess which one it was holding.
#[derive(Serialize)]
pub struct WindowJson {
    pub start: Value,
    pub end: Value,
    /// The events this window was derived from, so the answer names its
    /// evidence.
    pub derived_from: Vec<String>,
}

impl PgCorpusView {
    /// The window the filter would read, rendered for a response.
    ///
    /// Deliberately routed through `CorpusView::window`'s own async body rather
    /// than a bespoke query, so the endpoint cannot publish a window that
    /// disagrees with the one a verdict was computed over.
    pub async fn window_for_response(
        &self,
        entity: EntityId,
        as_of: Tick,
    ) -> Result<WindowJson, ApiError> {
        let w = self.window_at(entity, as_of).await?;
        Ok(WindowJson {
            start: match w.start {
                cc_filter::Start::Known(t) => json!({ "state": "known", "coord": render(t) }),
                cc_filter::Start::Unknown => json!({ "state": "unknown" }),
            },
            end: match w.end {
                cc_core::WindowEnd::KnownOpen => json!({ "state": "known_open" }),
                cc_core::WindowEnd::UnknownClosure => json!({ "state": "unknown_closure" }),
                cc_core::WindowEnd::KnownClosed(t) => {
                    json!({ "state": "known_closed", "coord": render(t) })
                }
            },
            derived_from: w.derived_from.iter().map(|e| e.to_hex()).collect(),
        })
    }
}

#[cfg(test)]
mod readings_relation_tests {
    use super::readings_relation;

    fn h(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    /// **No database, no HTTP, no fixtures.** That is the point: the shipped
    /// four-state logic is now verifiable by anyone who can run `cargo test`,
    /// including a reviewer with no `TEST_DATABASE_URL`. timepoint-telemetry
    /// could previously only *read* it and said so plainly rather than claiming
    /// more than they had checked.
    #[test]
    fn every_state_is_reachable_and_emptiness_wins() {
        // Emptiness FIRST. A comparison-first version returns
        // "one_claim_many_readings" here, because windows(2).all(..) is
        // vacuously true on an empty slice — the defect this ordering exists to
        // prevent, and the third instance this month of an aggregate over an
        // empty input reading like an aggregate over a real one.
        assert_eq!(readings_relation(&[]), "no_readings");

        // A single reading is one claim, and says so rather than being silent.
        assert_eq!(
            readings_relation(&[h("sha256:aa")]),
            "one_claim_many_readings"
        );
        assert_eq!(
            readings_relation(&[h("sha256:aa"), h("sha256:aa")]),
            "one_claim_many_readings"
        );

        // Different hashes are different claims however the entity resolved.
        assert_eq!(
            readings_relation(&[h("sha256:aa"), h("sha256:bb")]),
            "several_claims_sharing_an_entity"
        );

        // An unretained body beats both comparisons: it is not "different".
        assert_eq!(readings_relation(&[None]), "cannot_compare");
        assert_eq!(readings_relation(&[h("sha256:aa"), None]), "cannot_compare");
        // ...and beats them even when every *present* hash agrees, which is the
        // case a comparison-first implementation would silently call the same.
        assert_eq!(
            readings_relation(&[h("sha256:aa"), None, h("sha256:aa")]),
            "cannot_compare"
        );

        // Emptiness outranks cannot_compare too — there is no [None] to find in
        // an empty slice, but the ordering is asserted rather than assumed.
        assert_eq!(
            readings_relation(&Vec::<Option<String>>::new()),
            "no_readings"
        );
    }

    /// Order-independence, because `windows(2)` compares neighbours: a
    /// mismatched pair must be found wherever it sits, not only when adjacent
    /// elements happen to differ at the front.
    #[test]
    fn a_mismatch_anywhere_is_found() {
        for i in 0..5 {
            let mut v = vec![h("sha256:aa"); 5];
            v[i] = h("sha256:zz");
            assert_eq!(
                readings_relation(&v),
                "several_claims_sharing_an_entity",
                "a differing hash at position {i} must be detected"
            );
        }
    }
}
