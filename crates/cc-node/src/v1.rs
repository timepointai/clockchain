//! Review-only v1 ingress adapter. Deliberately not wired into the node binary.
//! No entity/filter/media read or serving readiness exists in Stage (a).
use crate::config::KeyDigest;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
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
}

/// Used by operator integration tests against fresh synthetic stores. This does
/// not enable v1 on the legacy router, choose a ship order, or grant readiness.
pub fn review_router(store: Store, writer: KeyDigest) -> Router {
    let state = Ingress { store, writer };
    Router::new()
        .route("/v1/candidates", post(submit))
        .route_layer(middleware::from_fn_with_state(state.clone(), authorize))
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE))
        .route(
            "/ready",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "stage_a_non_serving") }),
        )
        .with_state(state)
}
async fn authorize(State(state): State<Ingress>, request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !token.is_some_and(|v| state.writer.matches(v)) {
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
