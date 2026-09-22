//! Bearer authentication for every endpoint except `/health`.
//!
//! # Why this is a layer and not an extractor
//!
//! v2 returned `422` to unauthenticated callers because its framework validated
//! the request body before it authenticated the caller — so a stranger with no
//! credential learned the shape of a schema they had no right to see, and every
//! monitor that keyed on `401` missed the refusal. The fix is structural rather
//! than careful: authentication is a `tower` layer wrapped *around* the route
//! service, so it completes before any handler extractor runs. A body cannot be
//! parsed, and therefore cannot be rejected, ahead of the credential check.
//!
//! # Two credentials, two layers, and no fallback
//!
//! There is exactly one thing this module reads: the `Authorization: Bearer`
//! header, compared against key digests fixed at boot. No query parameter, no
//! cookie, no second header, no per-route exemption list, no "allow if unset".
//! [`crate::config::Config::from_env`] refuses to boot without a strong key, so
//! there is no state in which either layer passes a request through for want of
//! configuration.
//!
//! The scope is enforced by **which layer wraps which routes**, not by a check
//! inside a handler. [`require_read`] wraps the read surface and accepts either
//! credential; [`require_write`] wraps the write path and accepts only the full
//! key. A route cannot accidentally become writable by a reader, because the
//! read layer is not mounted on the write path at all — the distinction is in
//! the router's shape, where it can be seen, rather than in a condition someone
//! must remember to write.
//!
//! The layer is applied with `Router::layer` rather than `route_layer` on
//! purpose: `layer` covers the fallback too, so a probe of an unknown path from
//! **below read scope** gets `401` instead of a `404` that confirms which paths
//! exist. That covers an unauthenticated caller and equally an authenticated one
//! holding a narrower credential — a gallery, beta or telemetry key probing
//! `/v1/nope` gets exactly what a stranger gets. At read scope or above it is a
//! `404`, because the boundary passed and the route genuinely is not there.
//! The measured split per credential is a column of `tests/credential_scope.rs`.

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::state::AppState;

/// The read surface: the full key **or** the read-only key.
///
/// The token itself is never logged, never echoed, and never included in the
/// refusal body — a 401 that quoted the presented credential would move the
/// secret into whatever aggregates the response.
pub async fn require_read(State(state): State<AppState>, req: Request, next: Next) -> Response {
    match presented(&req) {
        Some(t) if state.api_key.matches(t) => next.run(req).await,
        Some(t) if state.read_key.as_ref().is_some_and(|k| k.matches(t)) => next.run(req).await,
        _ => unauthorized(),
    }
}

/// The gallery feed: the full key, the read key, **or** the gallery key.
///
/// This layer is mounted on exactly one route. The gallery key is accepted
/// nowhere else — not by widening a condition here, but because no other
/// router carries this layer.
///
/// **Scope is read from `tests/credential_scope.rs`, not from this comment.**
/// It used to be read from the router's shape, which worked while every scoped
/// key appeared in exactly one guard; the moment one key appears in two, scope
/// becomes "the set of guards naming it" and stops being legible without a
/// grep. Rather than let the discipline erode into prose, it moved into a
/// matrix that is driven through the real router and can fail. Changing a scope
/// means changing an arm here AND a cell there, in one diff.
///
/// The wider credentials are accepted too: a caller holding the read key can
/// already read this data by other routes, so refusing it here would be
/// ceremony rather than a boundary.
pub async fn require_gallery(State(state): State<AppState>, req: Request, next: Next) -> Response {
    match presented(&req) {
        Some(t) if state.api_key.matches(t) => next.run(req).await,
        Some(t) if state.read_key.as_ref().is_some_and(|k| k.matches(t)) => next.run(req).await,
        Some(t) if state.gallery_key.as_ref().is_some_and(|k| k.matches(t)) => next.run(req).await,
        // Telemetry, added on Sean's direct authorisation 2026-08-18.
        //
        // Their daily gate verifies the published `(head_event_id, author_key,
        // signature)` triple under stock Ed25519, and that check is worth less
        // run on my credential against my own output than run on theirs against
        // the live surface — a producer validating itself proves the validator
        // ran, not that the thing is right. This route is the only one carrying
        // all three fields.
        //
        // No re-mint: this is the SAME holder gaining a route, not a new one.
        // Issuing a second telemetry secret would mean revoking telemetry
        // requires revoking two, and would put one holder behind two keys —
        // worse revocation and a less attributable leak, which is the opposite
        // of what "two holders, two secrets" buys.
        Some(t) if state.telemetry_key.as_ref().is_some_and(|k| k.matches(t)) => {
            next.run(req).await
        }
        _ => unauthorized(),
    }
}

/// Entity lookup and feasibility: the full key, the read key, **or** one of the
/// credentials scoped to exactly these two routes.
///
/// Mounted on exactly two routes. Beta asked for these two and nothing else,
/// and the read key would additionally hand them `/v1/moments` and
/// `/health/deep` — a scope that grants more than was asked for is not a scope.
///
/// **Two holders, two secrets, overlapping but not identical scopes.**
/// Telemetry needs these same routes to check the TT conformance gaps against
/// the live boundary rather than against my report of it — and as of
/// 2026-08-18 also holds `/v1/recents`, which beta does not. The secrets stay
/// distinct for the reason they always were: either holder revocable alone, and
/// a leaked key names its leaker. Reusing beta's key would have been one fewer
/// variable and would have cost two properties that exist only while the
/// secrets are distinct: either holder can be revoked without breaking the
/// other, and a leaked key names who leaked it.
///
/// Named for the scope, not the holder. It was `require_beta` while beta was
/// the only consumer; a guard named after one of its two consumers is a comment
/// that goes stale without anything failing — the same drift that let a config
/// value describe a corpus the node no longer served.
pub async fn require_entity_read(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    match presented(&req) {
        Some(t) if state.api_key.matches(t) => next.run(req).await,
        Some(t) if state.read_key.as_ref().is_some_and(|k| k.matches(t)) => next.run(req).await,
        Some(t) if state.beta_key.as_ref().is_some_and(|k| k.matches(t)) => next.run(req).await,
        Some(t) if state.telemetry_key.as_ref().is_some_and(|k| k.matches(t)) => {
            next.run(req).await
        }
        _ => unauthorized(),
    }
}

/// The write path: the full key only.
///
/// A valid read key here earns **403, not 401**. The distinction is the whole
/// point of having two credentials: 401 says "I do not know who you are", and
/// repeating it to a caller who authenticated correctly would tell them their
/// key was rejected as unknown — sending them to rotate a perfectly good
/// credential instead of asking for the right scope.
pub async fn require_write(State(state): State<AppState>, req: Request, next: Next) -> Response {
    match presented(&req) {
        Some(t) if state.api_key.matches(t) => next.run(req).await,
        Some(t) if state.read_key.as_ref().is_some_and(|k| k.matches(t)) => forbidden_read_only(),
        Some(t) if state.gallery_key.as_ref().is_some_and(|k| k.matches(t)) => {
            forbidden_read_only()
        }
        Some(t) if state.beta_key.as_ref().is_some_and(|k| k.matches(t)) => forbidden_read_only(),
        // Every scoped credential must be listed here, not just the ones that
        // existed when this was written. A new scope that is added to its own
        // guard and forgotten here still gets refused — but with 401, telling a
        // holder of a valid key that they are unknown and sending them to
        // rotate a good credential. Telemetry's key was 401ing here for exactly
        // that reason, caught by probing production rather than by the test,
        // which asserted the intended behaviour and could not run without a
        // database.
        //
        // This paragraph is now also a TEST: the write column of
        // `tests/credential_scope.rs` spells out 403-not-401 for every scoped
        // credential, and `AppState`'s exhaustive initializer there means a new
        // credential field will not compile until someone decides its cells. A
        // rule stated in a comment is a rule that drifts; the comment survives
        // because it explains the test, not because it enforces anything.
        Some(t) if state.telemetry_key.as_ref().is_some_and(|k| k.matches(t)) => {
            forbidden_read_only()
        }
        _ => unauthorized(),
    }
}

fn presented(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token)
}

/// A known credential without the scope. Names the scope it lacks, so the
/// caller can ask for the right thing rather than guess.
fn forbidden_read_only() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "read_only_credential",
            "detail": "this credential is read-only; the write path requires the full key",
        })),
    )
        .into_response()
}

/// Extract the token from an `Authorization` header value.
///
/// The scheme name is matched case-insensitively (RFC 7235 says schemes are
/// case-insensitive) but nothing else is normalized: a token with stray
/// whitespace is a different token, and quietly trimming it would authenticate a
/// credential that is not the one in the secret store.
fn bearer_token(raw: &str) -> Option<&str> {
    let (scheme, rest) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    // Exactly one separating space, and a non-empty remainder.
    if rest.is_empty() || rest.starts_with(' ') {
        return None;
    }
    Some(rest)
}

/// The refusal. `401` with a `WWW-Authenticate` challenge — never `403` (which
/// would say "your identity is known and insufficient") and never `422` (which
/// would say a body was read).
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(json!({
            "error": "unauthorized",
            "detail": "a valid bearer token is required on every endpoint except /health",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::bearer_token;

    #[test]
    fn scheme_is_case_insensitive_token_is_not_normalized() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer abc"), Some("abc"));
        assert_eq!(bearer_token("BEARER abc"), Some("abc"));
        // Not trimmed: a padded token is a different token.
        assert_eq!(bearer_token("Bearer abc "), Some("abc "));
    }

    #[test]
    fn other_schemes_and_shapes_are_refused() {
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Token abc"), None);
        assert_eq!(bearer_token("abc"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("Bearer  abc"), None);
        assert_eq!(bearer_token(""), None);
    }
}
