//! `cc-node` — the server binary.
//!
//! Subcommands:
//!   * `cc-node serve` (or no argument) — run the axum server.
//!   * `cc-node migrate` — connect using `DATABASE_URL`, run migrations, exit.
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

use cc_node::{config::Config, router, state::AppState};

/// `EX_CONFIG` from `sysexits.h`: the process could not start because its
/// configuration is wrong. A distinct code so a supervisor can tell "this will
/// never start until a human fixes a variable" from "this crashed".
const EX_CONFIG: i32 = 78;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    match std::env::args().nth(1).as_deref() {
        Some("migrate") => run_migrate().await,
        None | Some("serve") => run_server().await,
        Some(other) => {
            eprintln!("cc-node: unknown subcommand {other:?}; expected `serve` or `migrate`");
            std::process::exit(EX_CONFIG);
        }
    }
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
