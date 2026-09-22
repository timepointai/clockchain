//! The response envelope for everything that is not a verdict.
//!
//! **Status semantics are a financial API.** A gateway meters on `2xx`, so which
//! status a refusal carries decides whether a caller is billed for it. That
//! makes the mapping below a design decision rather than a formatting choice:
//!
//! * `400` — the caller asked a question this rule cannot answer (a missing or
//!   malformed `as_of`, a hop bound past the governed one, a limit past the
//!   ceiling). No work was done and none should be charged, and the fault is the
//!   caller's, so it is not a `5xx`.
//! * `403` — the node is frozen. The path exists, the credential was good, and
//!   the refusal is a stated posture rather than an outage.
//! * `404` — the projection is silent about this identifier *at the pinned
//!   coordinate*. Distinct from `Unsupported`, which is a filter verdict.
//! * `503` — the node could not answer: the store was unreachable or returned
//!   something undecodable. This is `Unavailable`, and it is **never** a
//!   verdict. A view failure reported as `Unsupported` would sell a certain
//!   witness of missing evidence to a caller who was actually handed an outage,
//!   and a fail-closed consumer would then amplify that ambiguity forever.
//!
//! There is no arm that degrades a failure into an empty list.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::coord::CoordError;

/// Everything the read surface can refuse with.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The request is not a question this node can answer.
    #[error("{0}")]
    BadRequest(String),

    /// The node is running as a read-only witness.
    #[error("node posture is frozen: writes are refused")]
    Frozen,

    /// Nothing recorded under this identifier at the pinned coordinate.
    #[error("{0}")]
    NotFound(String),

    /// The node could not answer. Not a verdict.
    #[error("{0}")]
    Unavailable(String),

    /// The claim type named is not a node in the pinned TT bundle.
    ///
    /// **Deliberately distinct from silence.** A valid-but-undeclared id is a
    /// real question this corpus cannot answer and is evaluated normally; an id
    /// that is not in the bundle never existed and is refused loudly, naming it.
    /// Collapsing the two is the gap/finding collapse TT's obligation 2 exists
    /// to prevent.
    #[error("claim type {0:?} is not a node in the pinned TT bundle")]
    UnknownClaimType(String),
}

impl ApiError {
    /// The stable machine-readable tag. Clients switch on this, not on prose.
    fn tag(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "malformed_request",
            ApiError::Frozen => "frozen",
            ApiError::NotFound(_) => "not_recorded",
            ApiError::Unavailable(_) => "unavailable",
            ApiError::UnknownClaimType(_) => "claim_type_not_in_bundle",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Frozen => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            // 400, not 404: an id absent from the taxonomy is a malformed
            // question, not an absent answer. A 404 would put it in the same
            // bucket as a valid id this corpus has not declared, which is the
            // exact collapse the string spelling exists to prevent.
            ApiError::UnknownClaimType(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let tag = self.tag();
        // The frozen refusal says *why* in the body, not only in the status: a
        // 403 alone is indistinguishable from a permissions problem, and an
        // operator staring at a facade during a wind-down should not have to
        // guess which one they are looking at.
        let body = match &self {
            ApiError::Frozen => json!({
                "error": tag,
                "posture": "frozen",
                "detail": "this node is a read-only witness: the write path is refused by boot \
                           configuration, not by a transient condition. Reads are unaffected.",
            }),
            other => json!({ "error": tag, "detail": other.to_string() }),
        };
        (status, Json(body)).into_response()
    }
}

impl From<CoordError> for ApiError {
    fn from(e: CoordError) -> ApiError {
        ApiError::BadRequest(e.to_string())
    }
}

impl From<cc_filter::ViewError> for ApiError {
    /// A view failure is `Unavailable`, full stop. The detail is carried so an
    /// operator can see whether the store was unreachable or the projection was
    /// undecodable, because those need different responses.
    fn from(e: cc_filter::ViewError) -> ApiError {
        ApiError::Unavailable(format!("the corpus could not be consulted: {e}"))
    }
}
