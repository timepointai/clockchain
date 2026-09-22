//! The two health endpoints, which have sharply different jobs.
//!
//! `/health` answers **liveness**: is this process up, and which rule is it
//! running? It is I/O-free, clock-free, credential-free and byte-exact — served
//! from a string assembled once at boot. A database outage must never take it
//! down, because liveness is not capability, and a probe that dies with the
//! store cannot tell an operator which of the two failed.
//!
//! `/health/deep` answers **capability**: can this node actually serve reads,
//! and what does the ledger contain? It touches the database, so it needs a
//! credential like every other endpoint, and it reports `503` when it cannot
//! answer rather than a cheerful `200` with an error inside.
//!
//! Ledger counters are maintained at the write choke point. Media integrity
//! checks the attachment catalog against current moment projections in one
//! snapshot: a correction can orphan an attachment after admission.

use sqlx::Row;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::protocol::{hex_version, BUILD_REV};
use crate::state::AppState;

/// `GET /health` — liveness. No database, no clock, no credential.
///
/// The bytes are a frozen contract: a monitor pins them for a deploy, and the
/// deploy-truth check compares `filter_version` and `build` against what it
/// expects to be running. v1 used its OpenAPI listing as a deploy signal and
/// that listing lied once during an incident; these two fields cannot, because
/// the code that changes them is the code being verified.
pub async fn health(State(state): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.health_body.clone(),
    )
        .into_response()
}

/// `GET /health/deep` — capability plus the maintained aggregates.
///
/// `posture` is repeated here (it is already on `/health`) because it is what
/// lets a monitor apply the right rule to `event_count`: a non-growing ledger is
/// critical for a `live` node and expected for a `frozen` one. v1's database
/// check had no way to know which system it was watching and misfired on a
/// deliberate freeze.
pub async fn health_deep(State(state): State<AppState>) -> Response {
    let posture = state.posture.as_str();
    let filter_version = hex_version(state.filter.version());

    // Settlement state, read from the tables that own it. A failure here is
    // reported as `null` rather than propagated: /health/deep answers "can I
    // reach my dependencies", and a node whose ledger reads fine but whose
    // anchor table is unreadable should say so, not return nothing at all.
    let settlement = match cc_anchor::latest_root(&state.pool).await {
        Ok(Some(r)) => {
            let anchor = match cc_anchor::latest_anchor(&state.pool).await {
                Ok(Some(a)) => json!({
                    "status": format!("{:?}", a.status),
                    "age_seconds": a.age_seconds,
                    "block_height": a.block_height,
                }),
                Ok(None) => json!(null),
                Err(e) => json!({ "error": e.to_string() }),
            };
            json!({
                "root_height": r.height,
                "root": r.root.to_hex(),
                "tree_size": r.tree_size,
                "recorded_by": r.moment.map(|m| m.to_hex()),
                "anchor": anchor,
            })
        }
        Ok(None) => json!({ "root_height": null, "detail": "no root published yet" }),
        Err(e) => json!({ "error": e.to_string() }),
    };

    // What the LEDGER actually committed, as opposed to what the operator
    // pinned in config. `/health`'s `genesis_exhibit` is the latter and cannot
    // be trusted as evidence of the former: a stale config value was once read
    // as proof this chain attested a predecessor corpus it never committed.
    // Published here, from the table, so the claim has a source.
    let exhibit_committed: serde_json::Value =
        match sqlx::query("SELECT exhibit_id FROM exhibits ORDER BY exhibit_id LIMIT 1")
            .fetch_optional(&state.pool)
            .await
        {
            Ok(Some(row)) => {
                let id: Vec<u8> = row.get(0);
                json!(hex::encode(id))
            }
            // A chain that committed no exhibit says so. `null` is the honest
            // answer and is not the same as "not checked".
            Ok(None) => serde_json::Value::Null,
            Err(e) => json!({ "error": e.to_string() }),
        };

    let media = match sqlx::query_scalar::<_, String>(include_str!("../sql/media-integrity.sql"))
        .fetch_one(&state.pool)
        .await
    {
        Ok(report) => serde_json::from_str::<serde_json::Value>(&report).ok(),
        Err(error) => {
            tracing::warn!(%error, "media integrity check unavailable");
            None
        }
    };
    let media = match media {
        Some(mut report) => {
            let objects = crate::media::object_integrity(&state.pool)
                .await
                .unwrap_or_else(
                    |_| json!({"integrity":"not_run", "error":"media object check unavailable"}),
                );
            if objects["integrity"] != "pass" {
                report["integrity"] = objects["integrity"].clone();
            }
            report["objects"] = objects;
            Some(report)
        }
        None => None,
    };
    let media = match media {
        Some(report) if report["integrity"] == "pass" => report,
        report => {
            let status = if report.is_some() {
                "degraded"
            } else {
                "unavailable"
            };
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": status, "service": "cc-node", "build": BUILD_REV,
                    "posture": posture, "filter_version": filter_version,
                    "media": report.unwrap_or_else(|| json!({"integrity":"not_run", "error":"media catalog unavailable"})),
                })),
            ).into_response();
        }
    };
    let event_count = match sqlx::query_scalar::<_, i64>("SELECT count(*) FROM events")
        .fetch_one(&state.pool)
        .await
    {
        Ok(count) => count,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status":"unavailable", "event_count":null})),
            )
                .into_response()
        }
    };
    match cc_ledger::read_stats(&state.pool).await {
        Ok(Some(s)) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "event_count": event_count,
                "service": "cc-node",
                "build": BUILD_REV,
                "posture": posture,
                "filter_version": filter_version,
                "exhibit_committed": exhibit_committed,
                "ledger": {
                    "entity_count": s.entity_count,
                    "moment_count": s.moment_count,
                    "edge_count": s.edge_count,
                    "attestation_count": s.attestation_count,
                    "contested_edges": s.contested_edges,
                    "cross_writer_contested": s.cross_writer_contested,
                    // NULL, not 0.0, when there are no contested edges: 2-of-2
                    // co-attestation over a single-author region constrains
                    // nothing, so the honest published value is "vacuous", never
                    // a protective-looking zero.
                    "protected_fraction": s.protected_fraction,
                },
                // Read from `roots`, never from a counter.
                //
                // `ledger_stats.root_height` was published here and was always
                // 0, because nothing ever incremented it — this endpoint
                // reported "no roots" while two were published and anchored. It
                // could not be fixed by incrementing it either: `rebuild`
                // truncates `ledger_stats` and re-derives it from `events`, and
                // a root publication commits by `body_hash`, so the height is
                // not recoverable from the event stream. The authoritative
                // table is the only honest source.
                "settlement": settlement,
                "media": media,
            })),
        )
            .into_response(),

        // The row is absent, which is not the same fact as a zeroed row: this
        // ledger has folded nothing yet. Reporting zeros here would invent a
        // measurement of an empty corpus.
        Ok(None) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "event_count": event_count,
                "service": "cc-node",
                "build": BUILD_REV,
                "posture": posture,
                "filter_version": filter_version,
                "ledger": null,
                "detail": "no ledger_stats row: this node has folded no events yet",
                "media": media,
            })),
        )
            .into_response(),

        // Could not answer. `503`, loudly, never a 200 carrying an error — a
        // gateway meters on 2xx and this read did no work.
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "unavailable",
                "service": "cc-node",
                "build": BUILD_REV,
                "posture": posture,
                "filter_version": filter_version,
                "detail": format!("the projection store could not be read: {e}"),
            })),
        )
            .into_response(),
    }
}
