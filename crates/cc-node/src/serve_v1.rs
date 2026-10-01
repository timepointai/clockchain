//! v1 serving mode, selected by `CC_NODE_LEDGER=v1`.
//!
//! The legacy v0 routes are not mounted. Every route below is censused by
//! `tests/credential_scope.rs`, which reads this file's route literals.
//!
//! # Identity before anything else
//!
//! `serve` never provisions or binds. [`open_store`] reopens a store that
//! `cc-node provision-v1` already set up, read-only, and refuses on any
//! difference between the configured and the stored instance or rule identity.
//! There is therefore no state in which this router runs over a store whose
//! identity it has not verified.
//!
//! # Wire encoding
//!
//! Hashes that are direct fields of a response (or direct lists of them) are
//! lowercase hex. Projection content embedded in a response (`rows`,
//! `subjects`, `revisions`, `edges`, `media`, `authority`, `revision`,
//! `support`) and the admission `Outcome` keep their canonical serde form, the
//! one the pinned `cc.view-rows.json.v1` vector fixes, where a hash is a list of
//! 32 byte values.

use axum::{
    body::Bytes,
    extract::{rejection::QueryRejection, DefaultBodyLimit, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use cc_core::v1::{receipt::FoldRef, Hash, MAX_ENVELOPE};
use cc_ledger::v1::{Error, RuleId, Snapshot, State as Admission, Store};
use serde::Serialize;
use serde_json::{json, Value};

use crate::auth::{self, Credentials};
use crate::config::{Config, KeyDigest, Posture, V1Config};
use crate::security;

/// Everything a v1 handler may reach, assembled once at boot.
#[derive(Clone)]
pub struct V1State {
    /// Opened by [`open_store`]: provisioned, bound and verified.
    pub store: Store,
    pub posture: Posture,
    /// The frozen `/health` bytes; no clock, no database, no fold.
    pub health_body: Bytes,
    pub api_key: KeyDigest,
    pub read_key: Option<KeyDigest>,
    /// Legacy scoped credentials. No v1 route accepts them; the write guard
    /// answers them 403 as it does on the legacy router.
    pub gallery_key: Option<KeyDigest>,
    pub beta_key: Option<KeyDigest>,
    pub telemetry_key: Option<KeyDigest>,
}

impl Credentials for V1State {
    fn api_key(&self) -> &KeyDigest {
        &self.api_key
    }
    fn read_key(&self) -> Option<&KeyDigest> {
        self.read_key.as_ref()
    }
    fn gallery_key(&self) -> Option<&KeyDigest> {
        self.gallery_key.as_ref()
    }
    fn beta_key(&self) -> Option<&KeyDigest> {
        self.beta_key.as_ref()
    }
    fn telemetry_key(&self) -> Option<&KeyDigest> {
        self.telemetry_key.as_ref()
    }
}

impl V1State {
    pub fn build(store: Store, config: &Config, v1: &V1Config) -> V1State {
        V1State {
            health_body: health_body(v1, config.posture),
            store,
            posture: config.posture,
            api_key: config.api_key,
            read_key: config.read_key,
            gallery_key: config.gallery_key,
            beta_key: config.beta_key,
            telemetry_key: config.telemetry_key,
        }
    }
}

/// Why a v1 subcommand could not start, with its process exit code.
#[derive(Debug, thiserror::Error)]
pub enum BootError {
    #[error("{0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("DATABASE_URL is not a usable Postgres URL: {0}")]
    Url(sqlx::Error),
    #[error("{0}")]
    Store(#[from] Error),
    #[error("rule identity bound but semantic readiness is {0:?}")]
    NotReady(String),
}

impl BootError {
    /// `sysexits.h` codes, so a supervisor can tell the cases apart:
    /// 78 configuration, 73 a non-empty (foreign) database, 65 a store whose
    /// identity differs from the configuration or is not provisioned and bound,
    /// 69 the database is unreachable, 70 anything else.
    pub fn exit_code(&self) -> i32 {
        match self {
            BootError::Config(_) | BootError::Url(_) => 78,
            BootError::Store(Error::NotEmpty) => 73,
            BootError::Store(Error::Database(_)) => 69,
            BootError::Store(
                Error::Identity
                | Error::RuleIdentity
                | Error::UnsupportedFoldVersion
                | Error::Unbound
                | Error::Unprovisioned,
            ) => 65,
            BootError::Store(_) | BootError::NotReady(_) => 70,
        }
    }
}

fn pool(v1: &V1Config) -> Result<sqlx::PgPool, BootError> {
    sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_lazy(&v1.database_url)
        .map_err(BootError::Url)
}

/// `serve`: reopen and verify, never initialize.
pub async fn open_store(v1: &V1Config) -> Result<Store, BootError> {
    Ok(Store::open(pool(v1)?, v1.instance, v1.filter.clone()).await?)
}

/// What `cc-node provision-v1` prints on success.
#[derive(Debug, Serialize)]
pub struct ProvisionReport {
    pub instance: String,
    pub fold_version: FoldJson,
    pub filter_version: String,
    pub semantic: String,
}

#[derive(Debug, Serialize)]
pub struct FoldJson {
    pub version: u16,
    pub manifest: String,
}

/// `provision-v1`: idempotent `Store::provision` then `bind`. A fresh database
/// is initialized; a database provisioned and bound to exactly this identity
/// is accepted unchanged; anything else is refused.
pub async fn provision(v1: &V1Config) -> Result<ProvisionReport, BootError> {
    let store = Store::provision(pool(v1)?, v1.instance)
        .await?
        .bind(v1.filter.clone())
        .await?;
    let readiness = store.semantic_readiness().await?;
    if !readiness.serving {
        return Err(BootError::NotReady(readiness.semantic));
    }
    Ok(ProvisionReport {
        instance: hex::encode(v1.instance),
        fold_version: FoldJson {
            version: v1.filter.fold.version,
            manifest: hex::encode(v1.filter.fold.manifest),
        },
        filter_version: hex::encode(v1.filter.version()),
        semantic: readiness.semantic,
    })
}

#[derive(Serialize)]
struct Health {
    ledger: &'static str,
    build: &'static str,
    posture: &'static str,
    instance: String,
    fold_version: FoldJson,
    filter_version: String,
    curators: Vec<String>,
    max_hops: u16,
    semantic: &'static str,
}

/// The `/health` document, assembled once. `semantic` is the readiness
/// [`open_store`] verified at boot; `/ready` re-checks the store per request.
pub fn health_body(v1: &V1Config, posture: Posture) -> Bytes {
    let f = &v1.filter;
    let doc = Health {
        ledger: "v1",
        build: crate::protocol::BUILD_REV,
        posture: posture.as_str(),
        instance: hex::encode(v1.instance),
        fold_version: FoldJson {
            version: f.fold.version,
            manifest: hex::encode(f.fold.manifest),
        },
        filter_version: hex::encode(f.version()),
        curators: f.curators.iter().map(hex::encode).collect(),
        max_hops: f.max_hops,
        semantic: "ready",
    };
    Bytes::from(serde_json::to_vec(&doc).expect("the health document is plain JSON"))
}

/// Build the v1 router. Same shape as the legacy one: public liveness, then a
/// read boundary that owns the fallback, then a write boundary, each wrapped
/// by the shared guards in [`crate::auth`].
pub fn router(state: V1State) -> Router {
    let live = state.posture.writes_permitted();

    let readable = Router::new()
        .route("/v1/snapshot", get(snapshot))
        .route("/v1/subjects/:subject_id", get(subject))
        .route("/v1/revisions/:revision/prose", get(prose))
        .route("/v1/support", get(support))
        .fallback(not_found)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_read::<V1State>,
        ))
        .with_state(state.clone());

    let writable = Router::new()
        .route(
            "/v1/candidates",
            if live {
                post(submit).layer(DefaultBodyLimit::max(MAX_ENVELOPE))
            } else {
                post(refuse_frozen)
            },
        )
        .route(
            "/v1/bodies/:sha256",
            if live {
                put(retain_body).layer(DefaultBodyLimit::max(MAX_ENVELOPE))
            } else {
                put(refuse_frozen)
            },
        )
        .route("/v1/export", get(export))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_write::<V1State>,
        ))
        .with_state(state.clone());

    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/robots.txt", get(security::robots))
        .with_state(state)
        .merge(readable)
        .merge(writable)
        .layer(axum::middleware::from_fn(security::response_headers))
}

fn refusal(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

/// Map a store refusal. A requested fold this build cannot answer is the
/// caller's 409; everything else means the node cannot serve right now.
fn store_refusal(e: Error) -> Response {
    match e {
        Error::UnsupportedFoldVersion => refusal(StatusCode::CONFLICT, "unsupported_fold_version"),
        Error::Database(_) => refusal(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable"),
        other => refusal(StatusCode::SERVICE_UNAVAILABLE, &other.to_string()),
    }
}

/// Exactly 64 lowercase hex characters.
fn hex32(s: &str) -> Option<Hash> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

fn rule_json(r: &RuleId) -> Value {
    json!({
        "fold_version": r.fold_version,
        "fold_manifest": hex::encode(r.fold_manifest),
        "filter_version": hex::encode(r.filter_version),
    })
}

/// The three names every read carries.
fn named(s: &Snapshot) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("rule".into(), rule_json(&s.rule));
    m.insert("corpus_digest".into(), hex::encode(s.corpus_digest).into());
    m.insert("commitment".into(), hex::encode(s.commitment).into());
    m
}

fn to_value(v: impl Serialize) -> Value {
    serde_json::to_value(v).expect("projection readings serialize")
}

async fn health(State(state): State<V1State>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.health_body.clone(),
    )
        .into_response()
}

async fn ready(State(state): State<V1State>) -> Response {
    let posture = state.posture.as_str();
    match state.store.semantic_readiness().await {
        Ok(r) if r.serving => Json(json!({ "serving": true, "posture": posture })).into_response(),
        Ok(r) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "serving": false, "posture": posture, "reason": r.semantic })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "serving": false, "posture": posture, "reason": "store_unavailable" })),
        )
            .into_response(),
    }
}

async fn refuse_frozen() -> Response {
    refusal(StatusCode::SERVICE_UNAVAILABLE, "frozen")
}

async fn not_found() -> Response {
    refusal(StatusCode::NOT_FOUND, "no_such_route")
}

async fn submit(State(state): State<V1State>, body: Bytes) -> Response {
    match state.store.admit(&body).await {
        Ok(outcome) => {
            let code = match outcome.status.state {
                Admission::Valid => StatusCode::CREATED,
                Admission::Pending => StatusCode::ACCEPTED,
                Admission::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
            };
            (code, Json(outcome)).into_response()
        }
        Err(_) => refusal(StatusCode::SERVICE_UNAVAILABLE, "admission_unavailable"),
    }
}

async fn retain_body(
    State(state): State<V1State>,
    Path(sha256): Path<String>,
    body: Bytes,
) -> Response {
    let Some(expected) = hex32(&sha256) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_body_hash");
    };
    match state.store.retain_body(expected, &body).await {
        Ok(new) => (
            if new {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            Json(json!({ "body_hash": sha256, "new": new })),
        )
            .into_response(),
        Err(Error::BodyHash) => refusal(StatusCode::UNPROCESSABLE_ENTITY, "body_hash_mismatch"),
        Err(e) => store_refusal(e),
    }
}

/// Query strings are strict: an unknown, misspelled or repeated parameter is a
/// 400, never a read answered as if it were absent.
type Strict<T> = Result<Query<T>, QueryRejection>;

fn query<T>(q: Strict<T>) -> Option<T> {
    q.ok().map(|Query(q)| q)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FoldQuery {
    fold_version: Option<String>,
    fold_manifest: Option<String>,
}

async fn snapshot(State(state): State<V1State>, q: Strict<FoldQuery>) -> Response {
    let Some(q) = query(q) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_query");
    };
    let requested = match (q.fold_version, q.fold_manifest) {
        (None, None) => None,
        (Some(v), Some(m)) => match (v.parse::<u16>(), hex32(&m)) {
            // Canonical decimal only: no sign, padding or leading zeros.
            (Ok(version), Some(manifest)) if version.to_string() == v => {
                Some(FoldRef { version, manifest })
            }
            _ => return refusal(StatusCode::BAD_REQUEST, "invalid_fold_request"),
        },
        _ => return refusal(StatusCode::BAD_REQUEST, "invalid_fold_request"),
    };
    let s = match state.store.snapshot(requested.as_ref()).await {
        Ok(s) => s,
        Err(e) => return store_refusal(e),
    };
    let mut m = named(&s);
    let p = s.projection;
    let a = p.authority;
    m.insert("rows".into(), to_value(&p.rows));
    m.insert("subjects".into(), to_value(&p.subjects));
    m.insert("revisions".into(), to_value(&p.revisions));
    m.insert("edges".into(), to_value(&p.edges));
    m.insert("media".into(), to_value(&p.media));
    m.insert(
        "authority".into(),
        json!({
            "grants": to_value(a.grants.into_iter().collect::<Vec<_>>()),
            "active": to_value(a.active),
            "tombstones": to_value(a.tombstones),
            "effective_revokes": to_value(a.effective_revokes),
            "canceled": to_value(a.canceled),
        }),
    );
    Json(Value::Object(m)).into_response()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AsOfQuery {
    as_of: Option<String>,
}

/// `Some(None)` when absent, `None` when malformed.
fn as_of(raw: Option<String>) -> Option<Option<Hash>> {
    match raw {
        None => Some(None),
        Some(h) => hex32(&h).map(Some),
    }
}

async fn subject(
    State(state): State<V1State>,
    Path(subject_id): Path<String>,
    q: Strict<AsOfQuery>,
) -> Response {
    let Some(q) = query(q) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_query");
    };
    let Some(id) = hex32(&subject_id) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_subject_id");
    };
    let Some(as_of) = as_of(q.as_of) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_as_of");
    };
    let s = match state.store.snapshot(None).await {
        Ok(s) => s,
        Err(e) => return store_refusal(e),
    };
    let read = s.entity(id, as_of);
    let mut m = named(&s);
    m.insert("as_of".into(), read.as_of.map(hex::encode).into());
    m.insert("subject".into(), hex::encode(read.subject).into());
    m.insert("state".into(), read.state.into());
    m.insert(
        "frontier".into(),
        read.frontier
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .into(),
    );
    m.insert("revision".into(), to_value(&read.revision));
    let unknown = read.visibility == "subject_unknown";
    m.insert("visibility".into(), read.visibility.into());
    let code = if unknown {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::OK
    };
    (code, Json(Value::Object(m))).into_response()
}

async fn prose(State(state): State<V1State>, Path(revision): Path<String>) -> Response {
    let Some(id) = hex32(&revision) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_revision_id");
    };
    let s = match state.store.snapshot(None).await {
        Ok(s) => s,
        Err(e) => return store_refusal(e),
    };
    match prose_of(&state.store, &s, id).await {
        Ok(mut body) => {
            body.extend(named(&s));
            Json(Value::Object(body)).into_response()
        }
        Err((status, error)) => refusal(status, error),
    }
}

/// `{revision, availability, prose}` for one revision of a committed
/// snapshot. Body bytes are verified against their hash before they are
/// served; a tampered body is a 503, never prose.
pub(crate) async fn prose_of(
    store: &Store,
    s: &Snapshot,
    id: Hash,
) -> Result<serde_json::Map<String, Value>, (StatusCode, &'static str)> {
    let Some(r) = s.projection.revisions.iter().find(|r| r.id == id) else {
        return Err((StatusCode::NOT_FOUND, "revision_unknown"));
    };
    let bytes = store
        .body_bytes(r.body)
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "body_verification_failed"))?;
    let (availability, prose) = match bytes {
        None => ("unavailable", None),
        Some(b) => match String::from_utf8(b) {
            Ok(s) => ("available", Some(s)),
            Err(_) => ("not_utf8", None),
        },
    };
    let mut m = serde_json::Map::new();
    m.insert("revision".into(), to_value(r));
    m.insert("availability".into(), availability.into());
    m.insert("prose".into(), prose.into());
    Ok(m)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportQuery {
    from: Option<String>,
    to: Option<String>,
    as_of: Option<String>,
}

async fn support(State(state): State<V1State>, q: Strict<SupportQuery>) -> Response {
    let Some(q) = query(q) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_query");
    };
    let (Some(from), Some(to)) = (
        q.from.as_deref().and_then(hex32),
        q.to.as_deref().and_then(hex32),
    ) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_support_query");
    };
    let Some(as_of) = as_of(q.as_of) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_as_of");
    };
    let s = match state.store.snapshot(None).await {
        Ok(s) => s,
        Err(e) => return store_refusal(e),
    };
    let verdict = s.verdict(from, to, as_of);
    let mut m = named(&s);
    m.insert("as_of".into(), verdict.as_of.map(hex::encode).into());
    m.insert("from".into(), hex::encode(from).into());
    m.insert("to".into(), hex::encode(to).into());
    m.insert("support".into(), to_value(&verdict.support));
    Json(Value::Object(m)).into_response()
}

async fn export(State(state): State<V1State>) -> Response {
    match state.store.export(None).await {
        Ok(m) => Json(json!({
            "encoding": m.encoding,
            "rule": rule_json(&m.rule),
            "corpus_digest": hex::encode(m.corpus_digest),
            "commitment": hex::encode(m.commitment),
            "envelopes": m.envelopes.iter().map(hex::encode).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => store_refusal(e),
    }
}
