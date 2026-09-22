//! Typed absence is a signed decision, never inferred from a missing image.
//! Consumer contract: Telemetry docs/proposals/TYPED-MEDIA-ABSENCE.md.
use crate::{
    coord::parse_as_of,
    error::ApiError,
    media::{bad, hash, source_entity, text, unavailable, verify_manifest, ListParams},
    state::AppState,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::time::{SystemTime, UNIX_EPOCH};

const DOMAIN: &[u8] = b"cc.media-absence.v1\0";
const FIELDS: [&str; 7] = [
    "schema",
    "kind",
    "source_entity_id",
    "source_body_hash",
    "writer",
    "reason",
    "decided_at_ticks",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub manifest: Value,
    pub author: String,
    pub signature: String,
}

fn validate(s: &Submission) -> Result<(String, String), ApiError> {
    let m = &s.manifest;
    let fields = m
        .as_object()
        .ok_or_else(|| bad("manifest must be an object"))?;
    if fields.len() != FIELDS.len() || fields.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(bad("unexpected absence manifest fields"));
    }
    if m["schema"] != "cc.media-absence.v1" || m["kind"] != "deliberately_unillustrated" {
        return Err(bad("unsupported absence manifest"));
    }
    source_entity(m)?;
    hash(text(m, "source_body_hash")?)?;
    if text(m, "writer")? != s.author {
        return Err(bad("writer mismatch"));
    }
    let reason = text(m, "reason")?;
    if reason.trim().is_empty() || reason.len() > 4096 {
        return Err(bad("reason must be nonblank and at most 4096 UTF-8 bytes"));
    }
    let decided_at = text(m, "decided_at_ticks")?;
    let ticks = decided_at
        .parse::<i64>()
        .map_err(|_| bad("invalid decision time"))?;
    if ticks.to_string() != decided_at {
        return Err(bad(
            "decision time must be canonical whole ticks since J2000",
        ));
    }
    verify_manifest(m, &s.author, &s.signature, DOMAIN)
}

pub async fn submit(
    State(state): State<AppState>,
    Json(s): Json<Submission>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if !state.posture.writes_permitted() {
        return Err(ApiError::Frozen);
    }
    let (id, canonical) = validate(&s)?;
    let entity = source_entity(&s.manifest)?;
    let source = hash(text(&s.manifest, "source_body_hash")?)?;
    let mut tx = state.pool.begin().await.map_err(unavailable)?;
    let bound =
        sqlx::query("SELECT body_hash FROM moments WHERE subject=$1 AND body_hash=$2 FOR SHARE")
            .bind(entity)
            .bind(&source)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
    if bound.is_none() {
        return Err(bad(
            "source body is not currently projected for this entity",
        ));
    }
    let ticks = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(unavailable)?
        .as_secs() as i64
        - 946728000;
    let coord = parse_as_of(Some(&ticks.to_string()))?;
    let inserted = sqlx::query("INSERT INTO media_absence_decisions (decision_id,entity_id,source_body_hash,manifest,author,signature,admitted_coord) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
        .bind(&id).bind(entity).bind(source).bind(canonical).bind(s.author).bind(s.signature)
        .bind(coord.to_canon_bytes().to_vec()).execute(&mut *tx).await.map_err(unavailable)?.rows_affected();
    tx.commit().await.map_err(unavailable)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"decision_id":id,
        "appended":if inserted == 1 {"new"}else{"existing"},
        "kind":"deliberately_unillustrated", "historical_ledger_event":false})),
    ))
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MediaState {
    NoGenerationRecorded,
    DeliberatelyUnillustrated,
    Generated,
    ConflictingMediaRecords,
}

/// State is per exact entity/body reading, independent of record order/count.
pub fn media_state(has_images: bool, has_absences: bool) -> MediaState {
    match (has_images, has_absences) {
        (false, false) => MediaState::NoGenerationRecorded,
        (false, true) => MediaState::DeliberatelyUnillustrated,
        (true, false) => MediaState::Generated,
        (true, true) => MediaState::ConflictingMediaRecords,
    }
}

pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListParams>,
) -> Result<Json<Value>, ApiError> {
    let coord = parse_as_of(q.as_of.as_deref())?;
    let rows = sqlx::query(include_str!("../sql/media-readings.sql"))
        .bind(q.entity_id)
        .bind(coord.to_canon_bytes().to_vec())
        .fetch_all(&state.pool)
        .await
        .map_err(unavailable)?;
    let mut readings = Vec::new();
    for row in rows {
        let images: Vec<Value> =
            serde_json::from_str(row.try_get::<&str, _>("images").map_err(unavailable)?)
                .map_err(unavailable)?;
        let absences: Vec<Value> = serde_json::from_str(
            row.try_get::<&str, _>("absence_decisions")
                .map_err(unavailable)?,
        )
        .map_err(unavailable)?;
        readings.push(json!({
            "source_body_hash":row.try_get::<String,_>("source_body_hash").map_err(unavailable)?,
            "source_binding":if row.try_get::<bool,_>("current").map_err(unavailable)? {"currently_projected"} else {"stale_source"},
            "state":media_state(!images.is_empty(), !absences.is_empty()),
            "images":images, "absence_decisions":absences,
        }));
    }
    Ok(Json(
        json!({"schema":"cc.media-readings.v2", "entity_id":q.entity_id.to_string(),
        "as_of":q.as_of, "projection_basis":"current", "historical_evidence":false,
        "readings":readings}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_signature_preserves_unicode_and_exact_ids() {
        let vector: Value =
            serde_json::from_str(include_str!("../../../ops/fixtures/media-absence-v1.json"))
                .unwrap();
        let submission: Submission = serde_json::from_value(vector["submission"].clone()).unwrap();
        let (id, _) = validate(&submission).unwrap();
        assert_eq!(id, vector["decision_id"]);
        let mut neighbour = submission;
        neighbour.manifest["source_entity_id"] = json!("3582419940486658630");
        assert!(validate(&neighbour).is_err());
    }

    #[test]
    fn every_presence_pair_has_a_distinct_state() {
        for (images, absences, expected) in [
            (false, false, "no_generation_recorded"),
            (false, true, "deliberately_unillustrated"),
            (true, false, "generated"),
            (true, true, "conflicting_media_records"),
        ] {
            assert_eq!(
                serde_json::to_value(media_state(images, absences)).unwrap(),
                expected
            );
        }
    }
}
