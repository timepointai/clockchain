//! The shared state every handler is built over, assembled once at boot.
//!
//! Two things in here are boot-frozen on purpose. The **posture** is a value,
//! not a lookup: a per-request read of the environment or a table would let the
//! running posture drift away from the one `/health` published, and a monitor
//! keying its alarms off that published posture would then be watching a system
//! that had quietly changed. The **health body** is likewise assembled once, so
//! its bytes are a function of the binary and the boot config and nothing else —
//! no clock, no database, no allocation on the hot path.

use axum::body::Bytes;
use cc_filter::Filter;
use sqlx::PgPool;
use std::sync::Arc;

use crate::config::{Config, KeyDigest, Posture};

/// Everything a handler may reach.
#[derive(Clone)]
pub struct AppState {
    /// A **lazy** pool: created at boot, connected on first use. Boot therefore
    /// performs no I/O, which is what lets `/health` answer on a node whose
    /// database is down — liveness is not capability.
    pub pool: PgPool,
    /// The compiled consensus rule. `Arc` because the filter is cloned into a
    /// blocking task for every verdict.
    pub filter: Arc<Filter>,
    pub posture: Posture,
    /// The frozen `/health` bytes. `Bytes` clones by refcount, so serving
    /// liveness allocates nothing.
    pub health_body: Bytes,
    /// The single credential, as a digest. The plaintext key did not survive
    /// `Config::from_env`.
    pub api_key: KeyDigest,
    /// The optional read-only credential. `None` means no read-only access
    /// exists — never "anyone may read".
    pub read_key: Option<KeyDigest>,
    /// Opens the gallery feed and nothing else.
    pub gallery_key: Option<KeyDigest>,
    /// Opens entity lookup and feasibility only.
    pub beta_key: Option<KeyDigest>,
    /// Telemetry's credential on beta's two routes; separately revocable.
    pub telemetry_key: Option<KeyDigest>,
}

impl AppState {
    /// Build the state from validated config.
    ///
    /// Fallible only in the pool constructor, which parses the URL without
    /// dialling it — a malformed `DATABASE_URL` is a boot failure (fail closed),
    /// while an *unreachable* database is not (liveness must survive it).
    pub fn build(config: &Config) -> Result<AppState, sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            // sqlx defaults to thirty seconds, which on a dead database means a
            // caller waits half a minute to be told the node cannot answer.
            // Five seconds is long enough to ride out a failover and short
            // enough that `503 Unavailable` arrives while it is still useful.
            // It shortens the wait, it does not soften the answer: the timeout
            // still produces a loud refusal, never an empty result.
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_lazy(&config.database_url)?;
        let filter = Filter::new(crate::protocol::genesis_filter_params());
        let doc =
            crate::protocol::health_doc(&filter, config.posture.as_str(), config.genesis_exhibit);
        // `to_string` on a plain struct of strings and integers cannot fail; the
        // expect names the invariant rather than hiding a `unwrap_or_default`
        // that would serve an empty body during an incident.
        let health_body =
            serde_json::to_string(&doc).expect("the health document is plain JSON-safe scalars");

        Ok(AppState {
            pool,
            filter: Arc::new(filter),
            posture: config.posture,
            health_body: Bytes::from(health_body),
            api_key: config.api_key,
            read_key: config.read_key,
            gallery_key: config.gallery_key,
            beta_key: config.beta_key,
            telemetry_key: config.telemetry_key,
        })
    }
}
