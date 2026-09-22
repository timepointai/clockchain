//! `cc-node` — the server: the read surface over the ledger, the health
//! contract, and the frozen posture.
//!
//! # What this crate is responsible for
//!
//! Everything below it is already true by the time a request arrives:
//! `cc-core` decides identity, `cc-ledger` owns the only write path, `cc-filter`
//! *is* the consensus rule. This crate wires them to a socket and is responsible
//! for exactly four things it cannot delegate:
//!
//! 1. **Serving verdicts that came out of the filter.** Not out of SQL that
//!    reproduces the filter. A feasibility answer is `cc-filter` evaluated
//!    against a `CorpusView` backed by Postgres, so the verdict a caller gets
//!    here is bit-identical to the one a wasm mirror computes over the same
//!    evidence. That is what makes "same Φ everywhere" a build property.
//! 2. **Publishing which rule is running.** `/health` carries the
//!    filter-version hash, the governed b256 constants, the genesis exhibit
//!    commitment and the build revision, so two nodes that disagree on a verdict
//!    are diagnosed by comparing strings.
//! 3. **Refusing.** No credential is `401`; no `as_of` is `400`; a frozen node
//!    refuses writes with `403` and says why; a store that cannot be read is
//!    `503` and never a verdict.
//! 4. **Failing closed at boot.** A missing or weak API key, an unstated
//!    posture, or an absent `DATABASE_URL` stops the process before it listens.
//!
//! # What is deliberately not here
//!
//! * **No MCP tool surface.** The plan mirrors the read routes as MCP tools; the
//!   tools are not built, and a tool list is a contract, so listing an unbuilt
//!   tool would be exactly the maintenance stub that fakes success.
//! * **No `get_inclusion_proof` / `get_consistency_proof`.** Those are
//!   `cc-anchor`'s proofs; a feasibility verdict here enumerates the events it
//!   consulted, which is the attribution seam, but the Merkle multiproof binding
//!   that list to a published root is not wired.
//! * **No background work.** `serve` does request/response and nothing
//!   autonomous. Long-running work is a subcommand invoked by the platform's own
//!   job primitive, because a detached process tree does not survive a deploy.

#![forbid(unsafe_code)]

pub mod api;
pub mod auth;
pub mod config;
pub mod coord;
pub mod error;
mod evidence;
pub mod health;
pub mod media;
pub mod media_absence;
pub mod protocol;
pub mod state;
pub mod view;

/// The TT layer, derived at read time from stored fields. Nothing minted.
pub mod tt;

use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use crate::state::AppState;

/// Build the router.
///
/// # The auth boundary is a shape, not a habit
///
/// `/health` is added to one router; everything else is added to a second one
/// that is then wrapped in the bearer layer. Because the layer wraps the route
/// *service*, it completes before any handler extractor runs — which is the
/// structural fix for the `422`-before-`401` bug: there is no point in the
/// pipeline at which a body could be parsed by an unauthenticated caller.
///
/// `Router::layer` (not `route_layer`) is used so the protected router's
/// fallback is covered too. A probe of an unknown path from **below read
/// scope** — unauthenticated, or authenticated with a narrower credential —
/// therefore gets `401` rather than a `404` that would enumerate which paths
/// exist. At read scope or above it is a `404`; the per-credential split is a
/// column of `tests/credential_scope.rs` and was measured on production.
///
/// # The posture is baked in here, once
///
/// The write route is registered in both postures, at the same path, with a
/// different handler. That keeps the route list identical whether the node is
/// live or frozen — a facade answers "refused, because I am frozen", never "no
/// such thing" — and it means the refusal cannot drift from the posture
/// `/health` published, because the two are decided by the same boot value.
/// **Every route registered here owns a column in
/// `tests/credential_scope.rs`**, and that test censuses this function's source
/// in both directions: a new route with no column fails, and a column whose
/// route was deleted fails. Adding a route therefore means deciding, for every
/// named credential, whether it is accepted — which is the decision that used
/// to be made by whichever layer the `.route` call happened to be typed into.
pub fn router(state: AppState) -> Router {
    let write_route = if state.posture.writes_permitted() {
        post(api::submit_event)
    } else {
        post(api::refuse_frozen)
    };

    // Two boundaries, so the scope is visible in the router's shape rather than
    // buried in a condition inside a handler. The fallback sits on the read
    // boundary: a probe of an unknown path from below read scope still gets 401
    // rather than a 404 that would confirm which paths exist. Split per
    // credential in `tests/credential_scope.rs`, unknown-path column.
    let readable = Router::new()
        .route("/health/deep", get(health::health_deep))
        .route("/v1/moments", get(api::list_moments))
        .route("/v1/edges/:id/evidence", get(evidence::get))
        .route("/v1/images", get(media::list))
        .route("/v2/media", get(media_absence::list))
        .route("/v1/images/:sha", get(media::image))
        .fallback(not_found)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_read,
        ))
        .with_state(state.clone());

    // A third scope, narrower than read, carrying exactly one route. The
    // gallery credential is accepted here and nowhere else — not by a
    // condition inside a handler, but because no other router mounts this
    // layer. Landing's page needs one query shape; this is that shape and
    // nothing adjacent to it.
    //
    // No `.fallback` here on purpose: unknown paths belong to the read
    // boundary's fallback, so a gallery credential probing for other routes
    // gets the same 401 a stranger does rather than a 404 that would map the
    // surface for it.
    let gallery = Router::new()
        .route("/v1/recents", get(api::list_recents))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_gallery,
        ))
        .with_state(state.clone());

    // The entity-read scope: two routes, on their own layer for the same reason
    // the gallery has one — the scope is visible in the router's shape. Two
    // holders now (beta and telemetry) with separate secrets; the layer is the
    // same because the scope is. No fallback here either: unknown paths belong
    // to the read boundary, so a scoped credential probing elsewhere gets the
    // same 401 a stranger does rather than a 404 that would map the surface.
    let entity_read = Router::new()
        .route("/v1/entities/:entity_id", get(api::get_entity))
        .route("/v1/feasibility", post(api::feasibility))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_entity_read,
        ))
        .with_state(state.clone());

    let writable = Router::new()
        .route(
            "/v2/media/absence-decisions",
            if state.posture.writes_permitted() {
                post(media_absence::submit).layer(axum::extract::DefaultBodyLimit::max(32 * 1024))
            } else {
                post(api::refuse_frozen)
            },
        )
        .route("/v1/events", write_route)
        .route(
            "/v1/images",
            if state.posture.writes_permitted() {
                post(media::submit).layer(axum::extract::DefaultBodyLimit::max(12 * 1024 * 1024))
            } else {
                post(api::refuse_frozen)
            },
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_write,
        ))
        .with_state(state.clone());

    Router::new()
        .route("/health", get(health::health))
        .with_state(state)
        .merge(readable)
        .merge(gallery)
        .merge(entity_read)
        .merge(writable)
}

/// The fallback, which sits *inside* the auth boundary.
async fn not_found() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "no_such_route",
            "detail": "the genesis surface is /health, /health/deep, /v1/entities/{id}, \
                       /v1/moments, /v1/recents, /v1/feasibility, /v1/events",
        })),
    )
}
