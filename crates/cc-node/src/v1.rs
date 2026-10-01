//! Review-only v1 ingress adapter. Deliberately not wired into the node binary.
//! Full event, edge, media and prose review only; no runtime serving or verdicts.
use crate::config::KeyDigest;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use cc_core::v1::MAX_ENVELOPE;
use cc_ledger::v1::{State as AdmissionState, Store};

#[derive(Clone)]
struct Ingress {
    store: Store,
    writer: KeyDigest,
    reader: KeyDigest,
}

/// Used by operator integration tests against fresh synthetic stores. This does
/// not enable v1 on the legacy router or grant readiness.
pub fn review_router(store: Store, writer: KeyDigest, reader: KeyDigest) -> Router {
    let state = Ingress {
        store,
        writer,
        reader,
    };
    Router::new()
        .route("/v1/candidates", post(submit))
        .route("/v1/review", get(review))
        .route("/health", get(health))
        .route("/v1/revisions/:revision/prose", get(prose))
        .route_layer(middleware::from_fn_with_state(state.clone(), authorize))
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE))
        .route(
            "/ready",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "stage_e_non_serving") }),
        )
        .with_state(state)
}
async fn authorize(State(state): State<Ingress>, request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !token.is_some_and(|v| {
        state.writer.matches(v) || (request.method() == Method::GET && state.reader.matches(v))
    }) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    next.run(request).await
}
async fn submit(State(state): State<Ingress>, body: Bytes) -> Response {
    match state.store.admit(&body).await {
        Ok(outcome) => {
            let code = match outcome.status.state {
                AdmissionState::Valid => StatusCode::CREATED,
                AdmissionState::Pending => StatusCode::ACCEPTED,
                AdmissionState::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
            };
            (code, Json(outcome)).into_response()
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "admission_unavailable").into_response(),
    }
}

#[derive(serde::Deserialize)]
struct Requested {
    fold_version: Option<u16>,
    fold_manifest: Option<String>,
}
/// A requested rule identity this build cannot implement is refused, never
/// answered under the current fold. `None` means a malformed request.
fn requested(q: &Requested) -> Option<Option<cc_core::v1::receipt::FoldRef>> {
    match (q.fold_version, &q.fold_manifest) {
        (None, None) => Some(None),
        (Some(version), Some(m)) => {
            let manifest = hex::decode(m).ok()?.try_into().ok()?;
            Some(Some(cc_core::v1::receipt::FoldRef { version, manifest }))
        }
        _ => None,
    }
}
fn refusal(e: cc_ledger::v1::Error) -> Response {
    use cc_ledger::v1::Error::*;
    let code = match e {
        UnsupportedFoldVersion | RuleIdentity => StatusCode::CONFLICT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    (code, e.to_string()).into_response()
}
async fn health(State(state): State<Ingress>) -> Response {
    match state.store.semantic_readiness().await {
        Ok(r) => {
            let snapshot = state.store.snapshot(None).await.ok();
            Json(serde_json::json!({"readiness":r,
                "corpus_digest":snapshot.as_ref().map(|s| hex::encode(s.corpus_digest)),
                "commitment":snapshot.map(|s| hex::encode(s.commitment))}))
            .into_response()
        }
        Err(e) => refusal(e),
    }
}
async fn review(
    State(state): State<Ingress>,
    axum::extract::Query(q): axum::extract::Query<Requested>,
) -> Response {
    let Some(fold) = requested(&q) else {
        return (StatusCode::CONFLICT, "unsupported_fold_version").into_response();
    };
    match state.store.snapshot(fold.as_ref()).await {
        Ok(s) => Json(serde_json::json!({
            "boundary":"stage_e_non_serving", "rule":s.rule,
            "corpus_digest":hex::encode(s.corpus_digest), "commitment":hex::encode(s.commitment),
            "rows":s.projection.rows,
            "subjects":s.projection.subjects,
            "revisions":s.projection.revisions, "edges":s.projection.edges,
            "media":s.projection.media, "authority":{
                "grants":s.projection.authority.grants.into_iter().collect::<Vec<_>>(),
                "active":s.projection.authority.active,
                "tombstones":s.projection.authority.tombstones,
                "effective_revokes":s.projection.authority.effective_revokes,
                "canceled":s.projection.authority.canceled
            }
        }))
        .into_response(),
        Err(e) => refusal(e),
    }
}
async fn prose(State(state): State<Ingress>, Path(revision): Path<String>) -> Response {
    let id: [u8; 32] = match hex::decode(&revision).ok().and_then(|b| b.try_into().ok()) {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "invalid_revision_id").into_response(),
    };
    let view = match state.store.review_projection().await {
        Ok(v) => v,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "review_unavailable").into_response(),
    };
    let Some(r) = view.revisions.iter().find(|r| r.id == id) else {
        return (StatusCode::NOT_FOUND, "revision_unknown").into_response();
    };
    match state.store.body_bytes(r.body).await {
        Ok(bytes) => {
            let (availability, prose) = match bytes {
                None => ("unavailable", None),
                Some(b) => match String::from_utf8(b) {
                    Ok(s) => ("available", Some(s)),
                    Err(_) => ("not_utf8", None),
                },
            };
            Json(serde_json::json!({"revision":r,"availability":availability,"prose":prose}))
                .into_response()
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "body_verification_failed").into_response(),
    }
}
