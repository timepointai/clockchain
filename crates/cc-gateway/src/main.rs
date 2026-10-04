//! `cc-gateway`: serve the public read-only API in front of a private v1 node.
//!
//! Configuration is `CC_GATEWAY_*` and `PORT`; see `docs/PUBLIC-ACCESS.md`. A
//! missing node URL, a missing or weak read key, or an out-of-range setting
//! exits 78 (`EX_CONFIG`) before the listener is bound. The process does no
//! node I/O at startup, so it boots while the node is down and answers 503
//! until the node is reachable.

use std::net::SocketAddr;

use cc_gateway::{config::Config, router, Gateway};

const EX_CONFIG: i32 = 78;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cc-gateway: refusing to start — {e}");
            std::process::exit(EX_CONFIG);
        }
    };
    // Neither the node URL nor the key is logged.
    tracing::info!(
        bind = %config.bind,
        rate_per_minute = config.rate_per_minute,
        freshness_ms = config.freshness.as_millis() as u64,
        client_ip_header = config.client_ip_header.as_ref().map(|h| h.as_str()),
        "cc-gateway starting"
    );
    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cc-gateway: could not bind {}: {e}", config.bind);
            std::process::exit(1);
        }
    };
    let app = router(Gateway::new(&config));
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("serve");
}
