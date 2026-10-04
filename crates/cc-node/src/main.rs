//! `cc-node` — the server binary.
//!
//! Subcommands:
//!   * `cc-node serve` (or no argument) — run the axum server.
//!   * `cc-node migrate` — connect using `DATABASE_URL`, run migrations, exit.
//!   * `cc-node provision-v1` — v1 mode only: provision and bind the v1 store.
//!
//! `CC_NODE_LEDGER` selects the ledger. Absent, everything below the dispatch
//! is the legacy v0 node, unchanged. `v1` serves the v1 store instead and
//! refuses `migrate`, which would put v0 tables into the v1 database.
//!
//! **The server performs no I/O at startup.** The pool is lazy, so boot cannot
//! be blocked by a database that is down and `/health` answers regardless —
//! liveness is not capability. What boot *does* do is refuse: a missing or weak
//! API key, an unstated posture or an absent `DATABASE_URL` exits non-zero
//! before the listener is bound, so there is no state in which this process
//! serves an open surface.
//!
//! **Nothing autonomous runs in here.** No lifespan worker, no anchoring loop,
//! no background task that "outlives" a request — Railway kills detached process
//! trees on disconnect, and v1 proved that five different ways in one afternoon.
//! Long-running work is a subcommand invoked by the platform's job primitive.

use cc_node::{
    config::{Config, Ledger, V1Config, V1Serving},
    router, serve_v1,
    state::AppState,
};

/// `EX_CONFIG` from `sysexits.h`: the process could not start because its
/// configuration is wrong. A distinct code so a supervisor can tell "this will
/// never start until a human fixes a variable" from "this crashed".
const EX_CONFIG: i32 = 78;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let ledger = match Ledger::from_env() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cc-node: refusing to start — {e}");
            std::process::exit(EX_CONFIG);
        }
    };

    match (std::env::args().nth(1).as_deref(), ledger) {
        (Some("migrate"), Ledger::Legacy) => run_migrate().await,
        (None | Some("serve"), Ledger::Legacy) => run_server().await,
        (Some("migrate"), Ledger::V1) => {
            eprintln!(
                "cc-node: refusing `migrate` with CC_NODE_LEDGER=v1 — the v0 migrations must \
                 never run against the v1 database. Use `cc-node provision-v1`."
            );
            std::process::exit(EX_CONFIG);
        }
        (Some("provision-v1"), Ledger::V1) => run_provision_v1().await,
        (None | Some("serve"), Ledger::V1) => run_server_v1().await,
        (Some("provision-v1"), Ledger::Legacy) => {
            eprintln!("cc-node: `provision-v1` requires CC_NODE_LEDGER=v1");
            std::process::exit(EX_CONFIG);
        }
        (Some(other), _) => {
            eprintln!("cc-node: unknown subcommand {other:?}; expected `serve` or `migrate`");
            std::process::exit(EX_CONFIG);
        }
    }
}

/// `cc-node provision-v1`: provision and bind the v1 store, idempotently.
///
/// Prints the identity as JSON and exits 0 only when semantic readiness is
/// `ready`. Needs only `DATABASE_URL` and the `CC_V1_*` variables: it is the
/// release command, and it serves nothing.
async fn run_provision_v1() {
    let v1 = match V1Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cc-node: refusing to provision — {e}");
            std::process::exit(EX_CONFIG);
        }
    };
    match serve_v1::provision(&v1).await {
        Ok(report) => println!(
            "{}",
            serde_json::to_string(&report).expect("the report is plain JSON")
        ),
        Err(e) => {
            eprintln!("cc-node: provision-v1 refused — {e}");
            std::process::exit(e.exit_code());
        }
    }
}

/// `serve` in v1 mode. Unlike the legacy node this does I/O before binding:
/// the stored identity is verified first, and any mismatch stops the process.
/// It never provisions or binds; `provision-v1` does that.
async fn run_server_v1() {
    let configured = Config::from_env().and_then(|c| {
        let v1 = V1Config::from_env()?;
        let serving = V1Serving::from_env(&v1)?;
        Ok((c, v1, serving))
    });
    let (config, v1, serving) = match configured {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cc-node: refusing to start — {e}");
            std::process::exit(EX_CONFIG);
        }
    };
    let (store, readiness) = match serve_v1::open_store(&v1).await {
        Ok(opened) => opened,
        Err(e) => {
            eprintln!("cc-node: refusing to serve v1 — {e}");
            std::process::exit(e.exit_code());
        }
    };
    let state = serve_v1::V1State::build(store, &readiness, &config, &v1);
    let read_concurrency = serving.read_concurrency;
    let serving = serve_v1::Serving::from_config(serving);

    tracing::info!(
        bind = %config.bind,
        posture = config.posture.as_str(),
        build = cc_node::protocol::BUILD_REV,
        ledger = "v1",
        instance = %hex::encode(v1.instance),
        filter_version = %hex::encode(v1.filter.version()),
        read_concurrency,
        // The public key only, or "off"; the seed is never formatted.
        node_key = %serving.node_key().map_or("off".into(), hex::encode),
        "cc-node starting"
    );

    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cc-node: could not bind {}: {e}", config.bind);
            std::process::exit(1);
        }
    };

    axum::serve(listener, serve_v1::router_with(state, serving))
        .await
        .expect("serve");
}

/// `cc-node migrate`: apply migrations to `DATABASE_URL`, then exit.
///
/// Deliberately not posture-gated. A schema migration is an operator action on
/// the projection store, not a ledger write, and a frozen node still needs to be
/// restorable — refusing it here would make a facade unrecoverable rather than
/// read-only.
async fn run_migrate() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(u) => u,
        Err(_) => {
            eprintln!("cc-node: DATABASE_URL must be set for `migrate`");
            std::process::exit(EX_CONFIG);
        }
    };
    let pool = cc_ledger::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    cc_ledger::run_migrations(&pool)
        .await
        .expect("run migrations");
    println!("migrations applied ok");
}

/// Run the axum server. No database access on startup.
async fn run_server() {
    // Fail closed, loudly, before anything is bound. The error messages say what
    // to set and why, because a boot refusal a human cannot act on is just an
    // outage with extra steps.
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cc-node: refusing to start — {e}");
            std::process::exit(EX_CONFIG);
        }
    };

    let state = match AppState::build(&config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "cc-node: refusing to start — DATABASE_URL is not a usable Postgres URL: {e}"
            );
            std::process::exit(EX_CONFIG);
        }
    };

    // The one startup line. It names the posture and the rule identity because
    // those are what an operator reading a deploy log needs to confirm; it names
    // no credential, and `Config`'s `Debug` redacts both secrets if anything
    // else ever formats it.
    tracing::info!(
        bind = %config.bind,
        posture = config.posture.as_str(),
        build = cc_node::protocol::BUILD_REV,
        "cc-node starting"
    );

    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cc-node: could not bind {}: {e}", config.bind);
            std::process::exit(1);
        }
    };

    axum::serve(listener, router(state)).await.expect("serve");
}
