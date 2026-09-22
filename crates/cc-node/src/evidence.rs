//! Independently signed causal provenance, separate from historical event bytes.
use crate::{
    coord::parse_as_of,
    error::ApiError,
    media::{hash, unavailable},
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
#[derive(Deserialize)]
pub struct At {
    pub as_of: Option<String>,
}
pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<At>,
) -> Result<Json<Value>, ApiError> {
    let at = parse_as_of(q.as_of.as_deref())?;
    let key = hash(&id)?;
    let row=sqlx::query("SELECT p.evidence,p.evidence_sha256,p.author_key,p.signature FROM edge_evidence p JOIN events e ON e.event_id=p.event_id WHERE p.event_id=$1 AND e.event_time<=$2 AND p.admitted_coord<=$2")
 .bind(key).bind(at.to_canon_bytes().to_vec()).fetch_optional(&state.pool).await.map_err(unavailable)?
 .ok_or_else(||ApiError::NotFound("edge evidence not recorded at as_of".into()))?;
    Ok(Json(json!({"schema":"cc.edge-evidence.v1","event_id":id,
 "evidence":row.get::<String,_>("evidence"),"evidence_sha256":hex::encode(row.get::<Vec<u8>,_>("evidence_sha256")),
 "author":hex::encode(row.get::<Vec<u8>,_>("author_key")),"signature":hex::encode(row.get::<Vec<u8>,_>("signature")),
 "signature_contract":"Ed25519(cc.edge-evidence.v1 NUL || event_id bytes || evidence_sha256 bytes)",
 "anchor_scope":"independent evidence signature; not included in historical event bytes"})))
}
