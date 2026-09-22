//! Signed generated-media attachments, outside historical identity and anchors.
use crate::{coord::parse_as_of, error::ApiError, state::AppState};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const DOMAIN: &[u8] = b"cc.image-attachment.v1\0";
const LICENSE: &str = "19b6998b569b53ac1fc2158a8a3202c8699a9a4605b47075715d9c96be7fb6d0";
const WEIGHTS: [(&str, &str); 4] = [
    (
        "text_encoder/model.fp16.safetensors",
        "660c6f5b1abae9dc498ac2d21e1347d2abdb0cf6c0c0c8576cd796491d9a6cdd",
    ),
    (
        "text_encoder_2/model.fp16.safetensors",
        "ec310df2af79c318e24d20511b601a591ca8cd4f1fce1d8dff822a356bcdb1f4",
    ),
    (
        "unet/diffusion_pytorch_model.fp16.safetensors",
        "83e012a805b84c7ca28e5646747c90a243c65c8ba4f070e2d7ddc9d74661e139",
    ),
    (
        "vae/diffusion_pytorch_model.fp16.safetensors",
        "bcb60880a46b63dea58e9bc591abe15f8350bde47b405f9c38f4be70c6161e68",
    ),
];
pub(crate) fn bad(s: &str) -> ApiError {
    ApiError::BadRequest(s.into())
}
pub(crate) fn unavailable(error: impl std::fmt::Display) -> ApiError {
    tracing::warn!(%error, "media operation unavailable");
    ApiError::Unavailable("media storage unavailable".into())
}
pub(crate) fn hash(s: &str) -> Result<Vec<u8>, ApiError> {
    let b = hex::decode(s).map_err(|_| bad("invalid hash"))?;
    if b.len() != 32 || hex::encode(&b) != s {
        return Err(bad("expected lowercase 32-byte hash"));
    }
    Ok(b)
}
pub(crate) fn text<'a>(m: &'a Value, key: &str) -> Result<&'a str, ApiError> {
    m.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("missing manifest field"))
}
fn directory() -> Result<PathBuf, ApiError> {
    std::env::var_os("CC_MEDIA_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| unavailable("not configured"))
}

pub(crate) fn source_entity(m: &Value) -> Result<i64, ApiError> {
    // Entity IDs exceed JSON's exact IEEE-754 range. A decimal string keeps
    // the JCS signature bound to the exact ID, never a rounded neighbour.
    let value = text(m, "source_entity_id")?;
    let id = value
        .parse::<i64>()
        .map_err(|_| bad("invalid source entity id"))?;
    if id.to_string() != value {
        return Err(bad("source entity id must be canonical decimal text"));
    }
    Ok(id)
}

fn validate_profile(m: &Value) -> Result<(), ApiError> {
    if m["permission_profile"] == "flux-klein-4b-apache-local-v1" {
        let pinned: Value = serde_json::from_str(include_str!("../../../ops/flux_profile.json"))
            .expect("checked-in FLUX profile is valid JSON");
        for field in [
            "model",
            "model_revision",
            "license_sha256",
            "license_url",
            "weights_sha256",
        ] {
            if m[field] != pinned[field] {
                return Err(bad(
                    "FLUX checkpoint or license does not match pinned Apache profile",
                ));
            }
        }
        return Ok(());
    }
    for (field, expected) in [
        ("permission_profile", "sdxl-openrail++-m-local-v1"),
        ("model", "stabilityai/stable-diffusion-xl-base-1.0"),
        ("model_revision", "462165984030d82259a11f4367a4eed129e94a7b"),
        ("license_sha256", LICENSE),
    ] {
        if m[field] != expected {
            return Err(bad("unsupported media or permission profile"));
        }
    }
    let weights = m["weights_sha256"]
        .as_object()
        .ok_or_else(|| bad("missing weight provenance"))?;
    for (file, expected) in WEIGHTS {
        if weights.get(file).and_then(Value::as_str) != Some(expected) {
            return Err(bad("checkpoint weight hash does not match pinned SDXL"));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub manifest: Value,
    pub author: String,
    pub signature: String,
    pub image_base64: String,
}

/// Validate actual PNG bytes, permission profile and signature before any write.
fn validate(s: &Submission) -> Result<(String, String, Vec<u8>), ApiError> {
    let m = &s.manifest;
    for (k, v) in [
        ("schema", "cc.image-attachment.v1"),
        ("kind", "generated_interpretation_of_claim"),
        ("historical_verification", "not_assessed"),
        ("provider", "local_inference"),
    ] {
        if m.get(k).and_then(Value::as_str) != Some(v) {
            return Err(bad("unsupported media or permission profile"));
        }
    }
    validate_profile(m)?;
    if text(m, "writer")? != s.author || m["prompt_in_training"] != false {
        return Err(bad("writer or prompt scope mismatch"));
    }
    text(m, "prompt")?;
    text(m, "generated_at")?;
    source_entity(m)?;
    if m["seed"].as_u64().is_none_or(|seed| seed > u32::MAX as u64) {
        return Err(bad("missing source or seed"));
    }
    hash(text(m, "source_body_hash")?)?;
    let image_hash = text(m, "image_sha256")?;
    hash(image_hash)?;
    let raw = STANDARD
        .decode(&s.image_base64)
        .map_err(|_| bad("invalid image encoding"))?;
    if raw.len() > 8 * 1024 * 1024
        || raw.len() < 33
        || !raw.starts_with(b"\x89PNG\r\n\x1a\n")
        || &raw[12..16] != b"IHDR"
    {
        return Err(bad("expected PNG up to 8 MiB"));
    }
    if hex::encode(Sha256::digest(&raw)) != image_hash
        || m["byte_count"].as_u64() != Some(raw.len() as u64)
    {
        return Err(bad("image digest or size mismatch"));
    }
    let mut decoder = png::Decoder::new(std::io::Cursor::new(&raw));
    decoder.set_limits(png::Limits {
        bytes: 64 * 1024 * 1024,
    });
    let mut reader = decoder
        .read_info()
        .map_err(|_| bad("PNG does not decode"))?;
    if reader.output_buffer_size() > 64 * 1024 * 1024 {
        return Err(bad("decoded PNG exceeds size limit"));
    }
    reader
        .next_frame(&mut vec![0; reader.output_buffer_size()])
        .map_err(|_| bad("PNG frame does not decode"))?;
    let (id, canonical) = verify_manifest(m, &s.author, &s.signature, DOMAIN)?;
    Ok((id, canonical, raw))
}

/// Independent media signature domains never authorize historical events.
pub(crate) fn verify_manifest(
    m: &Value,
    author: &str,
    signature: &str,
    domain: &[u8],
) -> Result<(String, String), ApiError> {
    let canonical = tt_core::canonicalize(m);
    let mut h = Sha256::new();
    h.update(domain);
    h.update(canonical.as_bytes());
    let digest = h.finalize();
    let author: [u8; 32] = hash(author)?
        .try_into()
        .map_err(|_| bad("invalid writer"))?;
    let sig = hex::decode(signature).map_err(|_| bad("invalid signature"))?;
    let sig = Signature::from_slice(&sig).map_err(|_| bad("invalid signature"))?;
    VerifyingKey::from_bytes(&author)
        .map_err(|_| bad("invalid writer"))?
        .verify_strict(&digest, &sig)
        .map_err(|_| bad("signature does not verify"))?;
    Ok((hex::encode(digest), canonical))
}

pub async fn submit(
    State(state): State<AppState>,
    Json(s): Json<Submission>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if !state.posture.writes_permitted() {
        return Err(ApiError::Frozen);
    }
    let (id, canonical, raw) = validate(&s)?;
    let source = hash(text(&s.manifest, "source_body_hash")?)?;
    let entity = source_entity(&s.manifest)?;
    let image_hash = text(&s.manifest, "image_sha256")?;
    let mut tx = state.pool.begin().await.map_err(unavailable)?;
    // Hold the projection stable until the attachment is committed.
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
    let dir = directory()?;
    std::fs::create_dir_all(&dir).map_err(unavailable)?;
    store_object(&dir, image_hash, &raw).map_err(unavailable)?;
    let ticks = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(unavailable)?
        .as_secs() as i64
        - 946728000;
    let coord = parse_as_of(Some(&ticks.to_string()))?;
    let inserted=sqlx::query("INSERT INTO image_attachments (attachment_id,entity_id,source_body_hash,image_sha256,manifest,author,signature,admitted_coord) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
        .bind(&id).bind(entity).bind(source).bind(image_hash).bind(canonical).bind(s.author).bind(s.signature)
        .bind(coord.to_canon_bytes().to_vec()).execute(&mut *tx).await.map_err(unavailable)?.rows_affected();
    tx.commit().await.map_err(unavailable)?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"attachment_id":id,"appended":if inserted==1 {"new"}else{"existing"},"kind":"generated_interpretation_of_claim","historical_ledger_event":false}),
        ),
    ))
}

/// Free space the media volume must retain after a write, as a percent of the
/// volume. Twenty percent of the dedicated production volume by default;
/// `CC_MEDIA_FREE_RESERVE_PERCENT` lowers it for development and CI, where the
/// media directory shares a much larger host disk and a proportional reserve
/// would refuse every write. Values above 100 are ignored.
fn reserve_percent() -> u64 {
    match std::env::var("CC_MEDIA_FREE_RESERVE_PERCENT") {
        Ok(raw) => raw.trim().parse::<u64>().ok().filter(|p| *p <= 100),
        Err(_) => None,
    }
    .unwrap_or(20)
}

/// Write bytes durably before publishing their catalog row. A SQL failure may
/// leave an unreferenced content object, never a catalog entry without bytes.
/// Unreferenced objects are retained for explicit recovery, not deleted while
/// another attachment may be committing the same hash.
fn store_object(dir: &std::path::Path, digest: &str, raw: &[u8]) -> std::io::Result<()> {
    let percent = reserve_percent();
    let total = fs2::total_space(dir)?;
    let available = fs2::available_space(dir)?;
    if total == 0 || available.saturating_sub(raw.len() as u64) < total / 100 * percent {
        return Err(std::io::Error::other(format!(
            "media storage below {percent}% free-space reserve"
        )));
    }
    let destination = dir.join(format!("{digest}.png"));
    let temporary = dir.join(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(raw)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &destination)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Check each distinct admitted object, including files no reader requested.
/// No catalog rows is a measured empty set, not an unavailable filesystem.
pub(crate) async fn object_integrity(pool: &sqlx::PgPool) -> Result<Value, ApiError> {
    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT image_sha256 FROM image_attachments ORDER BY image_sha256",
    )
    .fetch_all(pool)
    .await
    .map_err(unavailable)?;
    if hashes.is_empty() {
        return Ok(json!({"integrity":"pass", "checked":0, "findings":[]}));
    }
    let dir = directory()?;
    tokio::task::spawn_blocking(move || {
        let mut findings = Vec::new();
        for digest in &hashes {
            // Catalog data cannot escape the content directory, even if damaged.
            if hash(digest).is_err() {
                findings.push(json!({"sha256":digest,"reason":"invalid_catalog_hash"}));
                continue;
            }
            match std::fs::read(dir.join(format!("{digest}.png"))) {
                Ok(bytes) if hex::encode(Sha256::digest(&bytes)) == *digest => {}
                Ok(_) => findings.push(json!({"sha256":digest,"reason":"digest_mismatch"})),
                Err(error) => findings.push(
                    json!({"sha256":digest,"reason":"unreadable", "error":error.to_string()}),
                ),
            }
        }
        json!({"integrity":if findings.is_empty(){"pass"}else{"fail"},
            "checked":hashes.len(), "findings":findings})
    })
    .await
    .map_err(unavailable)
}

#[derive(Deserialize)]
pub struct ListParams {
    pub entity_id: i64,
    pub as_of: Option<String>,
}
pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListParams>,
) -> Result<Json<Value>, ApiError> {
    let coord = parse_as_of(q.as_of.as_deref())?;
    let rows=sqlx::query("SELECT a.attachment_id,a.manifest,a.author,a.signature,EXISTS(SELECT 1 FROM moments m WHERE m.subject=a.entity_id AND m.body_hash=a.source_body_hash) AS current FROM image_attachments a WHERE a.entity_id=$1 AND a.admitted_coord<=$2 ORDER BY a.attachment_id LIMIT 50")
        .bind(q.entity_id).bind(coord.to_canon_bytes().to_vec()).fetch_all(&state.pool).await.map_err(unavailable)?;
    let mut images = Vec::new();
    for row in rows {
        let manifest: Value =
            serde_json::from_str(row.try_get::<&str, _>("manifest").map_err(unavailable)?)
                .map_err(unavailable)?;
        images.push(json!({"attachment_id":row.try_get::<String,_>("attachment_id").map_err(unavailable)?,"manifest":manifest,
            "author":row.try_get::<String,_>("author").map_err(unavailable)?,"signature":row.try_get::<String,_>("signature").map_err(unavailable)?,
            "source_binding":if row.try_get::<bool,_>("current").map_err(unavailable)? {"currently_projected"}else{"stale_source"}}));
    }
    Ok(Json(
        json!({"state":if images.is_empty(){"no_image"}else{"generated"},"images":images,"as_of":q.as_of,"historical_evidence":false}),
    ))
}

pub async fn image(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<([(header::HeaderName, &'static str); 2], Bytes), ApiError> {
    hash(&sha)?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM image_attachments WHERE image_sha256=$1)")
            .bind(&sha)
            .fetch_one(&state.pool)
            .await
            .map_err(unavailable)?;
    if !exists {
        return Err(ApiError::NotFound("image not admitted".into()));
    }
    let bytes = std::fs::read(directory()?.join(format!("{sha}.png"))).map_err(unavailable)?;
    if hex::encode(Sha256::digest(&bytes)) != sha {
        return Err(unavailable("image integrity failure"));
    }
    Ok((
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        Bytes::from(bytes),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apache_profile_rejects_other_flux_variants_and_unpinned_weights() {
        let pinned: Value =
            serde_json::from_str(include_str!("../../../ops/flux_profile.json")).unwrap();
        assert!(validate_profile(&pinned).is_ok());
        for (field, replacement) in [
            ("model", "black-forest-labs/FLUX.2-klein-9B"),
            ("model_revision", "main"),
            ("license_sha256", LICENSE),
            ("license_url", "https://example.com/license"),
            ("permission_profile", "apache-any-model"),
        ] {
            let mut wrong = pinned.clone();
            wrong[field] = json!(replacement);
            assert!(validate_profile(&wrong).is_err(), "{field}");
        }
        let mut wrong = pinned.clone();
        wrong["weights_sha256"]["vae/diffusion_pytorch_model.safetensors"] = json!("0".repeat(64));
        assert!(validate_profile(&wrong).is_err());
        let mut extra = pinned;
        extra["weights_sha256"]["unreviewed-lora.safetensors"] = json!("0".repeat(64));
        assert!(validate_profile(&extra).is_err());
    }
    #[test]
    fn source_ids_keep_all_bits_in_canonical_signatures() {
        let a = json!({"source_entity_id":"3582419940486658630"});
        let b = json!({"source_entity_id":"3582419940486658631"});
        assert_eq!(source_entity(&a).unwrap(), 3582419940486658630);
        assert_ne!(tt_core::canonicalize(&a), tt_core::canonicalize(&b));
        assert!(source_entity(&json!({"source_entity_id":3582419940486658630i64})).is_err());
        assert!(source_entity(&json!({"source_entity_id":"01"})).is_err());
    }
}
