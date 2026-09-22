//! The read surface, exercised end to end against a real Postgres.
//!
//! **No mocks, and no `oneshot` against a bare router.** Every test here boots
//! the actual `router()` on a real socket and talks to it over HTTP, because the
//! properties under test live in the middleware stack and the status codes, not
//! in the handler bodies: v2 shipped `422`-before-`401` precisely because its
//! tests exercised handlers rather than the pipeline in front of them. The
//! database is a fresh ephemeral one per test, migrated from `migrations/`.
//!
//! The boot-refusal tests run the compiled binary as a subprocess. Configuration
//! is process-global, so asserting "the node refuses to start" is only honest if
//! a whole process actually declines to start.

use cc_core::{
    EdgeBody, EdgeRelation, EntityBirth, EventBody, EventContent, EvidenceClass, ExistenceWindow,
    MomentBody, SecretKey, Tick, WindowEnd, WindowStart,
};
use cc_filter::{ClaimType, EntityId, FeasibilityQuery, Filter};
use cc_ledger::Signed;
use cc_node::{
    config::{Config, KeyDigest, Posture},
    protocol::{genesis_filter_params, split},
    router,
    state::AppState,
    view::PgCorpusView,
};
use serde_json::Value;
use sqlx::PgPool;
use std::net::{Ipv4Addr, SocketAddr};

/// A key that passes the boot policy. Not a real secret; it never leaves this
/// test binary and the databases it talks to are ephemeral.
/// A read-only credential, distinct from TEST_KEY.
const READ_KEY: &str = "9d3c7a1e64b8f025ac91de37b04f6c8215ae90d47f3b62c1e805a9f4c76d31be";

const BETA_KEY: &str = "5e12c4a7d8b30f96e2417ca85d0b3f7196e4c802a5d71fb3908c6e24da517b3f";
const TELEMETRY_KEY: &str = "c47f0b91d2e6a35847bc1f0e93a5d7268b4e0c1a97f3d582e6b40a19c73f5d82";

const GALLERY_KEY: &str = "3ac81f60d29b47e5081cfa63b7d940e2158c7fb03d64a91e2c8570df46b1a9e3";

const TEST_KEY: &str = "1f4b9c7e05a2d836be1904cf72ad5e3b8c60d94f17e2a5b3c8d70e916f24a3b5";

/// A running node plus the database behind it.
struct Node {
    base: String,
    pool: PgPool,
    cleanup: Option<cc_testkit::Cleanup>,
    /// The serving task, aborted before teardown. Without this the server's
    /// clone of the pool reconnects between `pg_terminate_backend` and
    /// `DROP DATABASE`, and the ephemeral database survives the test run.
    server: tokio::task::JoinHandle<()>,
    http: reqwest::Client,
}

impl Node {
    /// Boot a node over a fresh ephemeral database.
    async fn boot(posture: Posture) -> Node {
        let (pool, cleanup) = cc_testkit::ephemeral_db().await;
        let (base, server) = serve(pool.clone(), posture).await;
        Node {
            base,
            pool,
            cleanup: Some(cleanup),
            server,
            http: reqwest::Client::new(),
        }
    }

    /// Boot a node whose database can never be reached, to prove `/health` does
    /// not depend on one.
    async fn boot_without_db(posture: Posture) -> Node {
        // A syntactically valid URL pointing at a port nothing listens on. The
        // pool is lazy, so this is only discovered when a handler actually
        // queries — which is the property under test.
        let config = config_for("postgres://nobody:nobody@127.0.0.1:1/nothing", posture);
        let state = AppState::build(&config).expect("a valid URL builds a lazy pool");
        let pool = state.pool.clone();
        let (base, server) = spawn(state).await;
        Node {
            base,
            pool,
            cleanup: None,
            server,
            http: reqwest::Client::new(),
        }
    }

    async fn get(&self, path: &str, key: Option<&str>) -> (u16, Value, reqwest::header::HeaderMap) {
        let mut req = self.http.get(format!("{}{path}", self.base));
        if let Some(k) = key {
            req = req.header("Authorization", format!("Bearer {k}"));
        }
        let resp = req.send().await.expect("request");
        finish(resp).await
    }

    async fn post(
        &self,
        path: &str,
        key: Option<&str>,
        body: &str,
    ) -> (u16, Value, reqwest::header::HeaderMap) {
        let mut req = self
            .http
            .post(format!("{}{path}", self.base))
            .header("Content-Type", "application/json")
            .body(body.to_string());
        if let Some(k) = key {
            req = req.header("Authorization", format!("Bearer {k}"));
        }
        let resp = req.send().await.expect("request");
        finish(resp).await
    }

    async fn done(mut self) {
        self.server.abort();
        if let Some(c) = self.cleanup.take() {
            self.pool.close().await;
            c.cleanup().await;
        }
    }
}

async fn finish(resp: reqwest::Response) -> (u16, Value, reqwest::header::HeaderMap) {
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap_or_default();
    let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, body, headers)
}

fn config_for(database_url: &str, posture: Posture) -> Config {
    Config {
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        database_url: database_url.to_string(),
        posture,
        api_key: KeyDigest::of(TEST_KEY),
        read_key: Some(KeyDigest::of(READ_KEY)),
        gallery_key: Some(KeyDigest::of(GALLERY_KEY)),
        beta_key: Some(KeyDigest::of(BETA_KEY)),
        telemetry_key: Some(KeyDigest::of(TELEMETRY_KEY)),
        genesis_exhibit: None,
    }
}

/// Bind port 0, serve in the background, return the base URL.
///
/// The state is built from a placeholder URL and then handed the ephemeral
/// pool, so the server and the test share exactly one database rather than each
/// re-deriving its generated name.
async fn serve(pool: PgPool, posture: Posture) -> (String, tokio::task::JoinHandle<()>) {
    let config = config_for("postgres://unused:unused@127.0.0.1:1/unused", posture);
    let mut state = AppState::build(&config).expect("state");
    state.pool = pool;
    spawn(state).await
}

async fn spawn(state: AppState) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    (format!("http://{addr}"), handle)
}

// ===========================================================================
// Seeding — real signed events through the real write path.
// ===========================================================================

fn t(whole: i64) -> Tick {
    Tick::from_whole_ticks(whole, split())
}

async fn birth(
    pool: &PgPool,
    sk: &SecretKey,
    entity_id: i64,
    name: &str,
    start: WindowStart,
    end: WindowEnd,
    at: Tick,
) {
    let content = EventContent {
        event_time: at,
        record_time: at,
        author: sk.author(),
        supersedes: None,
        body: EventBody::EntityCreate(EntityBirth {
            entity_id,
            resolution_key: format!("test:{entity_id}"),
            canonical_name: name.to_string(),
            window: ExistenceWindow { start, end },
        }),
    };
    let signed = Signed::sign(sk, content);
    cc_ledger::commit(pool, &signed)
        .await
        .expect("commit birth");
}

/// An edge event: the co-occurrence evidence `neighbors` reads.
async fn edge(pool: &PgPool, sk: &SecretKey, src: i64, dst: i64, at: Tick) {
    let content = EventContent {
        event_time: at,
        record_time: at,
        author: sk.author(),
        supersedes: None,
        body: EventBody::Edge(EdgeBody {
            src,
            dst,
            relation: EdgeRelation::CoOccurrence,
            evidence_class: EvidenceClass::PrimaryDocument,
        }),
    };
    let signed = Signed::sign(sk, content);
    cc_ledger::commit(pool, &signed).await.expect("commit edge");
}

async fn moment(pool: &PgPool, sk: &SecretKey, subject: i64, at: Tick, tag: u8) {
    let content = EventContent {
        event_time: at,
        record_time: at,
        author: sk.author(),
        supersedes: None,
        body: EventBody::Moment(MomentBody {
            subject,
            body_hash: [tag; 32],
        }),
    };
    let signed = Signed::sign(sk, content);
    cc_ledger::commit(pool, &signed)
        .await
        .expect("commit moment");
}

/// A small corpus with one of every window shape the filter distinguishes.
///
/// * 1, 2 — open windows, joined by an edge at t=10.
/// * 3 — closed at t=50, so a query at t=100 is *contradicted*, not merely
///   unsupported.
/// * 4 — no evidenced start, so a query about it is silence.
async fn seed(pool: &PgPool) {
    let sk = SecretKey::from_seed([7u8; 32]);
    birth(
        pool,
        &sk,
        1,
        "Entity One",
        WindowStart::Known(t(0)),
        WindowEnd::KnownOpen,
        t(0),
    )
    .await;
    birth(
        pool,
        &sk,
        2,
        "Entity Two",
        WindowStart::Known(t(0)),
        WindowEnd::KnownOpen,
        t(0),
    )
    .await;
    birth(
        pool,
        &sk,
        3,
        "Entity Three",
        WindowStart::Known(t(0)),
        WindowEnd::KnownClosed(t(50)),
        t(0),
    )
    .await;
    birth(
        pool,
        &sk,
        4,
        "Entity Four",
        WindowStart::Unknown,
        WindowEnd::UnknownClosure,
        t(0),
    )
    .await;
    edge(pool, &sk, 1, 2, t(10)).await;
    moment(pool, &sk, 1, t(20), 0xa1).await;
    moment(pool, &sk, 2, t(30), 0xa2).await;
    // A moment after the coordinates the tests pin to, so the `as_of` bound has
    // something to exclude.
    moment(pool, &sk, 1, t(9_000), 0xa3).await;
}

// ===========================================================================
// /health — no database, no credential, byte-stable
// ===========================================================================

#[tokio::test]
async fn health_needs_no_database_and_no_credential() {
    let node = Node::boot_without_db(Posture::Live).await;

    let (status, body, _) = node.get("/health", None).await;
    assert_eq!(status, 200, "liveness must survive an unreachable database");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "cc-node");
    assert_eq!(body["posture"], "live");
    assert!(body["build"].is_string());

    // The protocol identity: everything two nodes compare to explain a
    // disagreement about a verdict.
    let p = &body["protocol"];
    let fv = p["filter_version"].as_str().expect("filter_version is hex");
    assert_eq!(fv.len(), 64, "filter version is 32 bytes of hex");
    assert!(fv.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(p["b256"]["clock_zero"], "J2000.0 (TCB)");
    assert_eq!(p["b256"]["tick"], "1 SI second");
    assert_eq!(p["b256"]["split"], 64);
    assert_eq!(p["b256"]["anchor_chain"], "bitcoin");
    assert!(body["genesis_exhibit"].is_null());

    // It publishes the version of the rule this binary actually compiled, not a
    // constant that claims to describe it.
    let compiled = Filter::new(genesis_filter_params());
    assert_eq!(fv, hex::encode(compiled.version().as_bytes()));

    // And the deep check, which does need a database, reports that it cannot
    // answer — 503, never a cheerful 200 with an error inside.
    let (status, body, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(status, 503);
    assert_eq!(body["status"], "unavailable");

    node.done().await;
}

/// A rollback must skip the old release command, not weaken sqlx's checks.
/// Apply a genuinely additive future migration and retain both it and the
/// ledger while the existing binary serves the newer schema.
#[tokio::test]
async fn old_migrator_refuses_new_schema_but_server_reads_it() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    seed(&pool).await;
    let old = sqlx::migrate!("../../migrations");
    let version = old.iter().map(|m| m.version).max().unwrap() + 1;
    let migration = sqlx::migrate::Migration::new(
        version,
        "rollback compatibility probe".into(),
        sqlx::migrate::MigrationType::Simple,
        "CREATE TABLE rollback_probe (id integer PRIMARY KEY); INSERT INTO rollback_probe VALUES (7);".into(),
        false,
    );
    let mut newer = sqlx::migrate::Migrator::DEFAULT;
    let mut migrations: Vec<_> = old.iter().cloned().collect();
    migrations.push(migration);
    newer.migrations = migrations.into();
    newer
        .run(&pool)
        .await
        .expect("apply future additive migration");

    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut url = reqwest::Url::parse(&std::env::var("TEST_DATABASE_URL").unwrap()).unwrap();
    url.set_path(&database);
    let failed = std::process::Command::new(env!("CARGO_BIN_EXE_cc-node"))
        .arg("migrate")
        .env("DATABASE_URL", url.as_str())
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(101));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("VersionMissing"));

    let (base, server) = serve(pool.clone(), Posture::Live).await;
    let node = Node {
        base,
        pool,
        cleanup: Some(cleanup),
        server,
        http: reqwest::Client::new(),
    };
    let (status, body, _) = node.get("/health/deep", Some(READ_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(body["ledger"]["entity_count"], 4);
    let (status, body, _) = node.get("/v1/entities/1?as_of=100", Some(READ_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(body["entity"]["canonical_name"], "Entity One");
    let retained: i32 = sqlx::query_scalar("SELECT id FROM rollback_probe")
        .fetch_one(&node.pool)
        .await
        .unwrap();
    assert_eq!(retained, 7, "rollback retains post-migration data");
    let applied: bool = sqlx::query_scalar("SELECT success FROM _sqlx_migrations WHERE version=$1")
        .bind(version)
        .fetch_one(&node.pool)
        .await
        .unwrap();
    assert!(applied, "rollback never rewinds migration history");
    node.done().await;
}

#[tokio::test]
async fn health_bytes_are_stable_across_requests() {
    let node = Node::boot(Posture::Frozen).await;
    let first = node.http.get(format!("{}/health", node.base)).send().await;
    let second = node.http.get(format!("{}/health", node.base)).send().await;
    let a = first.unwrap().text().await.unwrap();
    let b = second.unwrap().text().await.unwrap();
    // A monitor pins these bytes for a deploy, so two reads a moment apart must
    // be identical — a clock anywhere in the body would make that impossible.
    assert_eq!(a, b, "/health is a frozen contract, byte for byte");
    assert!(a.contains("\"posture\":\"frozen\""));
    node.done().await;
}

// ===========================================================================
// Access control
// ===========================================================================

/// Every route except `/health`, including one that does not exist.
const PROTECTED: &[(&str, &str)] = &[
    ("GET", "/health/deep"),
    ("GET", "/v1/entities/1?as_of=100"),
    ("GET", "/v1/moments?as_of=100"),
    ("GET", "/v1/recents?as_of=100"),
    ("POST", "/v1/feasibility"),
    ("POST", "/v1/events"),
    ("GET", "/v1/definitely-not-a-route"),
];

#[tokio::test]
async fn every_protected_route_is_401_without_a_credential() {
    let node = Node::boot(Posture::Live).await;
    for (method, path) in PROTECTED {
        let (status, body, headers) = match *method {
            "GET" => node.get(path, None).await,
            _ => node.post(path, None, "{}").await,
        };
        assert_eq!(status, 401, "{method} {path} must be 401 unauthenticated");
        assert_eq!(body["error"], "unauthorized");
        assert_eq!(
            headers.get("www-authenticate").map(|v| v.to_str().unwrap()),
            Some("Bearer")
        );
    }
    node.done().await;
}

#[tokio::test]
async fn a_malformed_body_without_a_credential_is_401_not_422() {
    // The regression this whole layer exists for. v2 validated the body before
    // it authenticated the caller, so a stranger got a 422 describing a schema
    // they had no right to see and every 401-keyed monitor missed the refusal.
    let node = Node::boot(Posture::Live).await;
    for body in ["not json at all", "{}", r#"{"subjects": "wrong type"}"#] {
        let (status, _, _) = node.post("/v1/feasibility", None, body).await;
        assert_eq!(status, 401, "body {body:?} must not be parsed before auth");
    }
    // With a credential, the same malformed bodies are a 4xx about the body.
    let (status, _, _) = node
        .post("/v1/feasibility", Some(TEST_KEY), "not json at all")
        .await;
    assert!(
        (400..500).contains(&status) && status != 401,
        "an authenticated caller with a bad body gets a body error, got {status}"
    );
    node.done().await;
}

#[tokio::test]
async fn a_wrong_or_malformed_credential_is_401() {
    let node = Node::boot(Posture::Live).await;
    let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
    let (status, _, _) = node.get("/health/deep", Some(wrong)).await;
    assert_eq!(status, 401);

    // A prefix of the real key must not authenticate.
    let (status, _, _) = node.get("/health/deep", Some(&TEST_KEY[..16])).await;
    assert_eq!(status, 401);

    // No second credential path exists: not a query parameter, not a bespoke
    // header, not a cookie.
    for probe in [
        format!("/health/deep?api_key={TEST_KEY}"),
        format!("/health/deep?token={TEST_KEY}"),
    ] {
        let (status, _, _) = node.get(&probe, None).await;
        assert_eq!(status, 401, "{probe} must not be a second way in");
    }
    let resp = node
        .http
        .get(format!("{}/health/deep", node.base))
        .header("X-API-Key", TEST_KEY)
        .header("Cookie", format!("api_key={TEST_KEY}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);

    // And the wrong scheme with the right token is still 401.
    let resp = node
        .http
        .get(format!("{}/health/deep", node.base))
        .header("Authorization", format!("Basic {TEST_KEY}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);

    node.done().await;
}

#[tokio::test]
async fn the_credential_opens_every_protected_route() {
    let node = Node::boot(Posture::Live).await;

    // Before anything is folded there is no `ledger_stats` row at all, and that
    // is a different fact from a zeroed one: "this node has seen nothing" must
    // not render as a measurement of an empty corpus.
    let (status, body, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert!(body["ledger"].is_null());

    seed(&node.pool).await;

    let (status, body, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(body["ledger"]["entity_count"], 4);
    assert_eq!(body["ledger"]["moment_count"], 3);
    // One contested edge, written by a single author, so P(G) is a *measured*
    // zero over a real denominator — not the vacuous NULL, which is what a
    // ledger with no contested edges publishes instead.
    assert_eq!(body["ledger"]["contested_edges"], 1);
    assert_eq!(body["ledger"]["cross_writer_contested"], 0);
    assert_eq!(body["ledger"]["protected_fraction"], 0.0);

    let (status, body, _) = node.get("/v1/entities/1?as_of=100", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(body["entity"]["canonical_name"], "Entity One");
    assert_eq!(body["entity"]["window"]["start"]["state"], "known");
    assert_eq!(body["entity"]["window"]["end"]["state"], "known_open");

    let (status, body, _) = node.get("/v1/moments?as_of=100", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    // The moment at t=9000 is excluded by the bound; the two at t<=100 are not.
    assert_eq!(body["count"], 2);

    let (status, _, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":[1,2],"as_of":"100","claim":1}"#,
        )
        .await;
    assert_eq!(status, 200);

    node.done().await;
}

// ===========================================================================
// `as_of` is mandatory
// ===========================================================================

#[tokio::test]
async fn a_read_without_as_of_is_refused_not_answered_at_now() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    for path in ["/v1/entities/1", "/v1/moments"] {
        let (status, body, _) = node.get(path, Some(TEST_KEY)).await;
        assert_eq!(status, 400, "{path} without as_of must be refused");
        assert_eq!(body["error"], "malformed_request");
        assert!(body["detail"].as_str().unwrap().contains("as_of"));
    }

    let (status, body, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":[1,2],"claim":1}"#,
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "malformed_request");

    // A coordinate that is not a coordinate is refused, never coerced.
    for bad in ["now", "today", "2026-08-12", "1.5", "0xdeadbeef"] {
        let (status, _, _) = node
            .get(&format!("/v1/moments?as_of={bad}"), Some(TEST_KEY))
            .await;
        assert_eq!(status, 400, "as_of={bad} must be refused");
    }

    // A limit past the ceiling is refused rather than clamped, so the answer
    // always describes the question that was asked.
    let (status, _, _) = node
        .get("/v1/moments?as_of=100&limit=100000", Some(TEST_KEY))
        .await;
    assert_eq!(status, 400);

    node.done().await;
}

#[tokio::test]
async fn the_as_of_bound_actually_slices_the_corpus() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    // Entity 1 is born at t=0, so it is invisible at a coordinate before that.
    let (status, _, _) = node.get("/v1/entities/1?as_of=-1", Some(TEST_KEY)).await;
    assert_eq!(
        status, 404,
        "an entity born after the pinned coordinate is not visible at it"
    );

    let (status, body, _) = node.get("/v1/moments?as_of=25", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["count"], 1,
        "only the t=20 moment is at or before t=25"
    );

    let (status, body, _) = node.get("/v1/moments?as_of=100000", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(body["count"], 3);

    node.done().await;
}

// ===========================================================================
// GET /v1/recents — the public gallery feed
// ===========================================================================

#[tokio::test]
async fn recents_refuses_a_read_with_no_coordinate() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    // The same rule every other read obeys. A gallery is the most tempting
    // place to quietly default to "now", which is exactly why it must not.
    let (status, body, _) = node.get("/v1/recents", Some(TEST_KEY)).await;
    assert_eq!(status, 400, "a read with no coordinate is malformed");
    assert_eq!(body["error"], "malformed_request");

    node.done().await;
}

#[tokio::test]
async fn recents_orders_by_record_coordinate_and_carries_the_proof_fields() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    let (status, body, _) = node.get("/v1/recents?as_of=100000", Some(TEST_KEY)).await;
    assert_eq!(status, 200);

    let entries = body["entries"].as_array().expect("entries is an array");
    assert!(!entries.is_empty(), "the seed writes moments");
    assert_eq!(body["count"], entries.len());

    // Newest-recorded first. This is the axis a fresh-mints gallery sorts on,
    // and it is NOT the same axis as `coord`.
    let mut prev: Option<i64> = None;
    for e in entries {
        // A coordinate renders as both spellings; the seed sits on the
        // whole-tick lattice, so the lossy-but-readable one is present.
        let rc = e["record_coord"]["whole_ticks"]
            .as_i64()
            .expect("the test seed uses whole-tick coordinates");
        assert!(
            e["record_coord"]["canonical"]
                .as_str()
                .is_some_and(|s| s.starts_with("0x")),
            "the canonical spelling must always be present, so a caller can replay it exactly"
        );
        if let Some(p) = prev {
            assert!(
                rc <= p,
                "record_coord must be non-increasing, got {rc} after {p}"
            );
        }
        prev = Some(rc);

        // Every field a reader needs to check the claim rather than trust it.
        for k in ["head_event_id", "author_key", "signature", "title"] {
            assert!(
                e[k].as_str().is_some_and(|s| !s.is_empty()),
                "entry is missing {k}, so the card could only be trusted"
            );
        }
        // The signed preimage is 32 bytes; the signature is 64.
        assert_eq!(e["head_event_id"].as_str().unwrap().len(), 64);
        assert_eq!(e["signature"].as_str().unwrap().len(), 128);
    }

    // The recipe travels with the data, and is honest about its own limit.
    assert_eq!(body["verification"]["algorithm"], "Ed25519");
    assert!(body["verification"]["does_not_prove"]
        .as_str()
        .expect("the feed states what it does not prove")
        .contains("canon"));

    node.done().await;
}

#[tokio::test]
async fn recents_refuses_an_out_of_range_limit_rather_than_clamping() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    // Refused, not clamped: the answer must always describe the question asked.
    let (status, _, _) = node
        .get("/v1/recents?as_of=100000&limit=10000", Some(TEST_KEY))
        .await;
    assert_eq!(status, 400);

    let (status, body, _) = node
        .get("/v1/recents?as_of=100000&limit=1", Some(TEST_KEY))
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["count"], 1);

    node.done().await;
}

// ===========================================================================
// The verdict is the filter's
// ===========================================================================

#[tokio::test]
async fn a_served_verdict_equals_the_filter_run_directly() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    // Three questions covering three different outcomes: a reachable pair, a
    // pair whose subject is past a recorded cessation, and a subject with no
    // evidenced start.
    let cases: &[(i64, i64, i64)] = &[
        (1, 2, 100),
        (1, 3, 100),
        (1, 4, 100),
        (4, 3, 100),
        (3, 4, 100),
    ];

    for &(a, b, at) in cases {
        let (status, body, _) = node
            .post(
                "/v1/feasibility",
                Some(TEST_KEY),
                &format!(r#"{{"subjects":[{a},{b}],"as_of":"{at}","claim":1}}"#),
            )
            .await;
        assert_eq!(status, 200, "a verdict is a metered 2xx read");

        assert_eq!(body["evidence_scope"], "recorded_graph_feasibility");
        assert_eq!(body["factual_verification"], "not_assessed");
        assert_eq!(body["verdict_policy"], "first_zero_in_factor_order");
        assert_eq!(body["audit"]["schema"], "cc.evidence-audit.v1");
        if (a, b) == (4, 3) || (a, b) == (3, 4) {
            assert_eq!(body["audit"]["contradictions"].as_array().unwrap().len(), 1);
            assert!(!body["audit"]["absences"].as_array().unwrap().is_empty());
        }

        // Now run the exact same rule over the exact same view, in-process.
        let filter = Filter::new(genesis_filter_params());
        let query = FeasibilityQuery {
            subjects: (EntityId::from_i64(a), EntityId::from_i64(b)),
            t_q: t(at),
            claim: ClaimType::from_u32(1),
            k: filter.params().k_max,
        };
        let pool = node.pool.clone();
        let view = PgCorpusView::open(&pool).await.expect("open view");
        let direct = tokio::task::spawn_blocking(move || filter.certify(&view, &query))
            .await
            .unwrap()
            .expect("the filter judged");

        let kind = match direct.judgment.verdict {
            cc_filter::Verdict::Supported { .. } => "Supported",
            cc_filter::Verdict::Unsupported { .. } => "Unsupported",
            cc_filter::Verdict::Contradicted { .. } => "Contradicted",
        };
        assert_eq!(
            body["result"], kind,
            "the API must not compute a different verdict from the filter for ({a},{b},{at})"
        );
        assert_eq!(
            body["filter_version"],
            hex::encode(direct.judgment.filter_version.as_bytes())
        );
        assert_eq!(
            body["corpus_digest"],
            hex::encode(direct.judgment.corpus_digest.as_bytes())
        );
        let consulted: Vec<String> = direct.consulted.iter().map(|e| e.to_hex()).collect();
        assert_eq!(
            body["consulted"],
            serde_json::to_value(&consulted).unwrap(),
            "the evidence list must be the filter's, not a re-derived one"
        );
    }

    node.done().await;
}

#[tokio::test]
async fn three_valued_verdicts_survive_the_wire() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    let ask = |a: i64, b: i64, at: i64| {
        let node = &node;
        async move {
            node.post(
                "/v1/feasibility",
                Some(TEST_KEY),
                &format!(r#"{{"subjects":[{a},{b}],"as_of":"{at}","claim":1}}"#),
            )
            .await
        }
    };

    // Entity 3 closed at t=50: at t=100 the record *contradicts*, and that must
    // not be flattened into mere silence.
    let (status, body, _) = ask(1, 3, 100).await;
    assert_eq!(status, 200);
    assert_eq!(body["result"], "Contradicted");
    assert_eq!(
        body["contradicted_by"]["reason"],
        "after_recorded_cessation"
    );
    assert_eq!(body["contradicted_by"]["entity"], 3);

    // Entity 4 has no evidenced start: silence, and the witness says which
    // factor vanished and how.
    let (status, body, _) = ask(1, 4, 100).await;
    assert_eq!(status, 200);
    assert_eq!(body["result"], "Unsupported");
    let vanished = body["vanished"].as_array().expect("a non-empty witness");
    assert!(!vanished.is_empty(), "a zero product names its zero factor");
    assert!(vanished
        .iter()
        .any(|w| w["reason"] == "no_recorded_start" && w["entity"] == 4));

    // The magnitude is not on the wire in any spelling, so no consumer can
    // threshold it — including via the *measured* hop count, which under the v0
    // smoothing `1/(1+hops)` is the magnitude in a different notation. The
    // governed bound a search ran under (`within_hops`) is a different thing: it
    // is a published constant, and "unreachable" means nothing without it.
    let raw = serde_json::to_string(&body).unwrap();
    assert!(!raw.contains("magnitude"));
    assert!(!raw.contains("\"hops\""));

    // A hop bound past the governed one is a malformed question, not a slower
    // one: a verdict searched under an unsanctioned k would carry a version hash
    // that does not describe it.
    let (status, body, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":[1,2],"as_of":"100","claim":1,"k":200}"#,
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "malformed_request");

    node.done().await;
}

#[tokio::test]
async fn a_view_failure_is_unavailable_and_never_a_verdict() {
    // The store cannot be reached at all. The filter must not be handed an empty
    // corpus and must not report `Unsupported` — "the record does not support
    // this" and "I could not read the record" have to stay distinguishable, or a
    // fail-closed caller amplifies the ambiguity.
    let node = Node::boot_without_db(Posture::Live).await;
    let (status, body, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":[1,2],"as_of":"100","claim":1}"#,
        )
        .await;
    assert_eq!(
        status, 503,
        "an outage is a 5xx, so a gateway does not bill it"
    );
    assert_eq!(body["error"], "unavailable");
    assert!(body.get("result").is_none(), "an error is never a verdict");

    let (status, body, _) = node.get("/v1/moments?as_of=100", Some(TEST_KEY)).await;
    assert_eq!(status, 503);
    assert!(
        body.get("moments").is_none(),
        "a failure must not degrade into an empty list"
    );

    node.done().await;
}

// ===========================================================================
// Frozen posture
// ===========================================================================

#[tokio::test]
async fn frozen_refuses_writes_and_keeps_reads_alive() {
    let node = Node::boot(Posture::Frozen).await;
    seed(&node.pool).await;

    // Reads are entirely unaffected.
    let (status, _, _) = node.get("/v1/entities/1?as_of=100", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    let (status, _, _) = node.get("/v1/moments?as_of=100", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    let (status, body, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":[1,2],"as_of":"100","claim":1}"#,
        )
        .await;
    assert_eq!(status, 200, "a frozen node still judges");
    assert!(body["result"].is_string());

    // The write path is refused, with a body that says why.
    let (status, body, _) = node
        .post("/v1/events", Some(TEST_KEY), r#"{"payload":"00"}"#)
        .await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "frozen");
    assert_eq!(body["posture"], "frozen");
    assert!(body["detail"].as_str().unwrap().contains("read-only"));

    // 403 and not 404: the route list is identical in both postures, so a
    // facade answers "refused because frozen", never "this never existed".
    let (status, body, _) = node.get("/v1/definitely-not-a-route", Some(TEST_KEY)).await;
    assert_eq!(status, 404);
    assert_eq!(body["error"], "no_such_route");

    // And the refusal precedes any body parsing, so garbage in still gets the
    // honest posture answer rather than a 422 about a schema.
    let (status, body, _) = node.post("/v1/events", Some(TEST_KEY), "}{").await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "frozen");

    // The posture is still what /health published.
    let (_, health, _) = node.get("/health", None).await;
    assert_eq!(health["posture"], "frozen");

    node.done().await;
}

#[tokio::test]
async fn live_accepts_a_signed_event_through_the_choke_point() {
    let node = Node::boot(Posture::Live).await;

    // A real signed event, in the shape the ledger stores.
    let sk = SecretKey::from_seed([9u8; 32]);
    let content = EventContent {
        event_time: t(1234),
        record_time: t(1234),
        author: sk.author(),
        supersedes: None,
        body: EventBody::EntityCreate(EntityBirth {
            entity_id: 42,
            resolution_key: "test:42".into(),
            canonical_name: "Submitted Entity".into(),
            window: ExistenceWindow {
                start: WindowStart::Known(t(0)),
                end: WindowEnd::KnownOpen,
            },
        }),
    };
    let signed = Signed::sign(&sk, content.clone());
    let payload = cc_core::canon_event(&content);
    let (_, signature) = sk.seal(&content);

    let body = serde_json::json!({
        "payload": hex::encode(&payload),
        "event_time": hex::encode(t(1234).to_canon_bytes()),
        "record_time": hex::encode(t(1234).to_canon_bytes()),
        "author": hex::encode(sk.author().to_bytes()),
        "signature": hex::encode(signature.to_bytes()),
    })
    .to_string();

    let (status, resp, _) = node.post("/v1/events", Some(TEST_KEY), &body).await;
    assert_eq!(status, 201, "a live node appends");
    assert_eq!(resp["event_id"], signed.id().to_hex());
    assert_eq!(resp["appended"], "new");

    // Re-submitting the identical event is a grow-only-set union no-op, never an
    // error.
    let (status, resp, _) = node.post("/v1/events", Some(TEST_KEY), &body).await;
    assert_eq!(status, 201);
    assert_eq!(resp["appended"], "unioned");

    // It really landed, and it is readable through the pinned read surface.
    let (status, read, _) = node.get("/v1/entities/42?as_of=2000", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(read["entity"]["canonical_name"], "Submitted Entity");

    // A tampered signature is refused by the gate, not stored and flagged.
    let mut bad = signature.to_bytes();
    bad[0] ^= 0xff;
    let body = serde_json::json!({
        "payload": hex::encode(&payload),
        "event_time": hex::encode(t(1234).to_canon_bytes()),
        "record_time": hex::encode(t(1234).to_canon_bytes()),
        "author": hex::encode(sk.author().to_bytes()),
        "signature": hex::encode(bad),
    })
    .to_string();
    let (status, _, _) = node.post("/v1/events", Some(TEST_KEY), &body).await;
    assert_eq!(status, 400, "an unverified event is not storable");

    node.done().await;
}

// ===========================================================================
// Boot refusal — a whole process must decline to start
// ===========================================================================

/// Run the compiled binary with a controlled environment and return
/// `(exit code, stderr)`.
fn boot_attempt(vars: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_cc-node"));
    cmd.arg("serve").env_clear();
    // A PATH is needed for nothing here, but an empty environment on macOS can
    // upset the loader; keep it minimal and explicit.
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    for (k, v) in vars {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run cc-node");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn the_node_refuses_to_start_without_a_usable_key() {
    let db = "postgres://u:p@127.0.0.1:5432/x";

    // No key at all: the v1 failure mode, where auth fell open when its vars
    // were unset.
    let (code, err) = boot_attempt(&[("DATABASE_URL", db), ("CC_NODE_POSTURE", "live")]);
    assert_eq!(
        code,
        Some(78),
        "a missing key is a config exit, not a serve"
    );
    assert!(err.contains("CC_NODE_API_KEY"), "stderr was: {err}");

    // Present but weak, in each of the ways the policy names.
    for weak in [
        "short",
        &"a".repeat(64),
        "changeme-changeme-changeme-changeme",
        &format!(" {TEST_KEY} "),
    ] {
        let (code, err) = boot_attempt(&[
            ("DATABASE_URL", db),
            ("CC_NODE_POSTURE", "live"),
            ("CC_NODE_API_KEY", weak),
        ]);
        assert_eq!(code, Some(78), "a weak key must not boot: {weak:?}");
        assert!(err.contains("CC_NODE_API_KEY"));
        // The refusal must not quote the credential back into a log — including
        // the padded case, where the presented value contains a real key.
        assert!(!err.contains(TEST_KEY), "the key leaked into stderr: {err}");
    }
}

#[test]
fn the_node_refuses_to_start_without_a_stated_posture_or_store() {
    let (code, err) = boot_attempt(&[
        ("DATABASE_URL", "postgres://u:p@127.0.0.1:5432/x"),
        ("CC_NODE_API_KEY", TEST_KEY),
    ]);
    assert_eq!(code, Some(78));
    assert!(err.contains("CC_NODE_POSTURE"), "stderr was: {err}");

    let (code, err) = boot_attempt(&[
        ("DATABASE_URL", "postgres://u:p@127.0.0.1:5432/x"),
        ("CC_NODE_API_KEY", TEST_KEY),
        ("CC_NODE_POSTURE", "readonly"),
    ]);
    assert_eq!(code, Some(78), "an unrecognized posture is not a fallback");
    assert!(err.contains("CC_NODE_POSTURE"));

    let (code, err) = boot_attempt(&[("CC_NODE_API_KEY", TEST_KEY), ("CC_NODE_POSTURE", "live")]);
    assert_eq!(code, Some(78));
    assert!(err.contains("DATABASE_URL"), "stderr was: {err}");
}

// ===========================================================================
// Admiss(c, t_q) — the factor that made `Supported` unreachable
// ===========================================================================

/// Declare a claim type over a band of coordinates, through the write path.
async fn declare(
    pool: &PgPool,
    sk: &SecretKey,
    code: u32,
    label: &str,
    band: cc_core::ExistenceWindow,
    at: Tick,
) {
    let content = EventContent {
        event_time: at,
        record_time: at,
        author: sk.author(),
        supersedes: None,
        body: EventBody::VocabularyDeclare(cc_core::VocabularyEntry {
            claim_type: code,
            label: label.to_string(),
            band,
        }),
    };
    let signed = Signed::sign(sk, content);
    cc_ledger::commit(pool, &signed)
        .await
        .expect("commit vocabulary declaration");
}

fn band(from: i64, end: cc_core::WindowEnd) -> cc_core::ExistenceWindow {
    cc_core::ExistenceWindow {
        start: cc_core::WindowStart::Known(t(from)),
        end,
    }
}

/// **`Supported` is reachable.**
///
/// This is the test the whole vocabulary change exists for. All four factors
/// have to hold at once — both entity windows open at `t_q`, the claim type
/// admissible at `t_q`, and an evidenced walk within `k` — and until the
/// `vocabulary` projection existed the third could never hold, so no corpus and
/// no query could produce this verdict. Green here means the filter's positive
/// branch is real rather than theoretical.
#[tokio::test]
async fn a_query_with_every_factor_holding_returns_supported() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;
    declare(
        &node.pool,
        &SecretKey::from_seed([31u8; 32]),
        7,
        "tax:co-located",
        band(0, cc_core::WindowEnd::KnownOpen),
        t(1),
    )
    .await;

    let (status, body, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":[1,2],"as_of":"100","claim":7}"#,
        )
        .await;

    assert_eq!(status, 200, "body: {body}");
    assert_eq!(
        body["result"], "Supported",
        "every factor holds, so this must be Supported: {body}"
    );

    node.done().await;
}

/// A band that has not begun by `as_of` is silence, not contradiction.
///
/// "Spaceflight" is a real classification that says nothing about the year 1200.
/// Reading a not-yet-begun band as contrary evidence would let the vocabulary
/// manufacture `Contradicted` verdicts about eras it simply does not cover.
#[tokio::test]
async fn a_claim_type_whose_band_has_not_begun_is_unrecorded_not_contradicted() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;
    declare(
        &node.pool,
        &SecretKey::from_seed([32u8; 32]),
        9,
        "tax:spaceflight",
        band(5_000, cc_core::WindowEnd::KnownOpen),
        t(1),
    )
    .await;

    let (status, body, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":[1,2],"as_of":"100","claim":9}"#,
        )
        .await;

    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["result"], "Unsupported", "body: {body}");
    assert!(
        body["vanished"]
            .as_array()
            .expect("vanished")
            .iter()
            .any(|r| r["reason"] == "claim_type_unrecorded"),
        "a band that has not begun must read as silence: {body}"
    );

    node.done().await;
}

/// A band the record says ENDED before `as_of` is contrary evidence.
///
/// This is the arm that must not collapse into the one above: the vocabulary
/// positively asserts this classification had been retired by then, which is
/// evidence of absence rather than absence of evidence.
#[tokio::test]
async fn a_retired_claim_type_contradicts_rather_than_merely_failing() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;
    declare(
        &node.pool,
        &SecretKey::from_seed([33u8; 32]),
        11,
        "tax:retired",
        band(0, cc_core::WindowEnd::KnownClosed(t(50))),
        t(1),
    )
    .await;

    let (status, body, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":[1,2],"as_of":"100","claim":11}"#,
        )
        .await;

    assert_eq!(status, 200, "body: {body}");
    assert_eq!(
        body["result"], "Contradicted",
        "a recorded retirement is contrary evidence: {body}"
    );

    node.done().await;
}

// ===========================================================================
// The read-only scope
// ===========================================================================

/// A read-only credential opens the read surface.
#[tokio::test]
async fn the_read_key_opens_reads() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;
    for path in [
        "/health/deep",
        "/v1/moments?as_of=100",
        "/v1/entities/1?as_of=100",
    ] {
        let (status, body, _) = node.get(path, Some(READ_KEY)).await;
        assert_eq!(status, 200, "{path} with the read key: {body}");
    }
    node.done().await;
}

/// ...and is refused at the write path with **403, not 401**.
///
/// 401 would tell a caller who authenticated correctly that their credential
/// was unknown, sending them to rotate a perfectly good key instead of asking
/// for the right scope. The status is the difference between "who are you" and
/// "not with that".
#[tokio::test]
async fn the_read_key_cannot_write_and_is_told_why() {
    let node = Node::boot(Posture::Live).await;
    let (status, body, _) = node
        .post("/v1/events", Some(READ_KEY), r#"{"anything":true}"#)
        .await;
    assert_eq!(status, 403, "body: {body}");
    assert_eq!(body["error"], "read_only_credential", "body: {body}");
    node.done().await;
}

/// The full key still opens the write path — the scope narrowed one credential,
/// not the surface.
#[tokio::test]
async fn the_full_key_still_reaches_the_write_path() {
    let node = Node::boot(Posture::Live).await;
    let (status, _, _) = node
        .post("/v1/events", Some(TEST_KEY), r#"{"malformed":true}"#)
        .await;
    assert_ne!(
        status, 401,
        "the full key must authenticate at the write path"
    );
    assert_ne!(status, 403, "the full key must not be scope-refused");
    node.done().await;
}

/// An unknown credential is still 401 everywhere, including the write path.
#[tokio::test]
async fn an_unknown_credential_is_still_401_at_both_boundaries() {
    let node = Node::boot(Posture::Live).await;
    let (r, _, _) = node
        .get("/health/deep", Some("not-a-real-key-at-all-not-a-real-key"))
        .await;
    let (w, _, _) = node
        .post(
            "/v1/events",
            Some("not-a-real-key-at-all-not-a-real-key"),
            "{}",
        )
        .await;
    assert_eq!((r, w), (401, 401));
    node.done().await;
}

// ===========================================================================
// The gallery scope
// ===========================================================================

#[tokio::test]
async fn the_gallery_key_opens_the_feed_and_nothing_else() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    // The one route it is for.
    let (status, body, _) = node
        .get("/v1/recents?as_of=100000", Some(GALLERY_KEY))
        .await;
    assert_eq!(status, 200, "the gallery credential opens the gallery");
    assert!(body["entries"].is_array());

    // Every other read route is closed to it. 401, not 403: on the read
    // boundary this credential is simply not known, and saying "known but
    // insufficient" would tell a holder they had a rejected key to rotate.
    for path in [
        "/v1/moments?as_of=100000",
        "/v1/entities/1?as_of=100",
        "/health/deep",
        "/v1/definitely-not-a-route",
    ] {
        let (status, _, _) = node.get(path, Some(GALLERY_KEY)).await;
        assert_eq!(status, 401, "{path} must not open to the gallery key");
    }

    // On the write path it IS known, and lacks the scope.
    let (status, body, _) = node.post("/v1/events", Some(GALLERY_KEY), "{}").await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "read_only_credential");

    // The wider credentials still work here — refusing them would be ceremony,
    // since both can already read this data by other routes.
    for k in [TEST_KEY, READ_KEY] {
        let (status, _, _) = node.get("/v1/recents?as_of=100000", Some(k)).await;
        assert_eq!(status, 200);
    }

    node.done().await;
}

/// Telemetry holds the same scope as beta through a **different secret**.
///
/// The point of a second credential rather than a shared one is that it can be
/// revoked alone and that a leak names its holder. Both are properties of the
/// secrets being distinct, and neither is visible from reading the router — so
/// they are asserted here.
/// TT conformance gap 2: a typo'd id and a valid-but-undeclared id must NOT
/// produce the same outcome.
///
/// This is the whole gap in one test. Both arrive at the legacy `u32` boundary
/// as well-formed numbers absent from the vocabulary — indistinguishable, because
/// the code is a truncated hash of the label and the label is gone. With the
/// string spelling the boundary can still see it:
///
///   * not in the bundle      -> 400 `claim_type_not_in_bundle`, naming the id
///   * in the bundle, not ours -> evaluated normally; silence, no error
#[tokio::test]
async fn a_typod_claim_type_and_an_undeclared_one_are_different_answers() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    async fn ask(node: &Node, claim: &str) -> (u16, serde_json::Value) {
        let body = format!(r#"{{"subjects":[1,2],"as_of":"100","claim":{claim}}}"#);
        let (s, b, _) = node.post("/v1/feasibility", Some(TEST_KEY), &body).await;
        (s, b)
    }

    // Not a node in the bundle. Loud, and it names the id.
    let (status, body) = ask(&node, r#""courtship-and-fallng-in-love""#).await;
    assert_eq!(status, 400, "a typo'd id is a malformed question");
    assert_eq!(body["error"], "claim_type_not_in_bundle");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("courtship-and-fallng-in-love"),
        "the rejection must name the id: {body}"
    );

    // A real bundle node this corpus has never declared. Silence, not an error.
    let (status, body) = ask(&node, r#""aging-and-eldership""#).await;
    assert_eq!(
        status, 200,
        "a valid-but-undeclared id is a real question: {body}"
    );
    assert!(
        body.get("result").is_some(),
        "it gets a verdict, not a refusal"
    );

    // The two outcomes are visibly different — the point of the whole gap.
    let (typo, _) = ask(&node, r#""courtship-and-fallng-in-love""#).await;
    let (undeclared, _) = ask(&node, r#""aging-and-eldership""#).await;
    assert_ne!(
        typo, undeclared,
        "identical outcomes would be the gap/finding collapse"
    );

    // A declared type still works by label, and by its legacy code.
    let (status, _) = ask(&node, r#""conflict-and-warfare""#).await;
    assert_eq!(status, 200);
    let code = cc_filter::version::claim_code("conflict-and-warfare");
    let (status, _) = ask(&node, &code.to_string()).await;
    assert_eq!(status, 200, "the legacy numeric spelling keeps working");

    // Retirement resolves on read rather than being refused.
    let (status, _) = ask(&node, r#""everyday-movement-and-commute""#).await;
    assert_eq!(status, 200, "a retired id resolves through its successor");

    node.done().await;
}

/// Telemetry's scope, which is beta's two routes PLUS `/v1/recents`.
///
/// This test was `telemetry_holds_the_same_scope_through_a_different_secret`
/// and it caught the change that made its own name false — `/v1/recents` moved
/// from the closed list to the open one on 2026-08-18. Renamed rather than
/// patched: a test whose name asserts sameness, while its body asserts a
/// difference, is a comment that has gone stale without anything failing.
#[tokio::test]
async fn telemetry_holds_betas_routes_plus_recents_through_a_different_secret() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    // The two routes it was issued for.
    let (status, _, _) = node
        .get("/v1/entities/1?as_of=100", Some(TELEMETRY_KEY))
        .await;
    assert_eq!(status, 200, "entity lookup is in telemetry's scope");
    let (status, _, _) = node
        .post(
            "/v1/feasibility",
            Some(TELEMETRY_KEY),
            r#"{"subjects":[1,2],"as_of":"100","claim":1}"#,
        )
        .await;
    assert_eq!(status, 200, "feasibility is in telemetry's scope");

    // The third route, which beta does NOT hold: telemetry's daily gate verifies
    // the published (head_event_id, author_key, signature) triple under stock
    // Ed25519, and this is the only route carrying all three fields.
    let (status, _, _) = node
        .get("/v1/recents?as_of=100&limit=1", Some(TELEMETRY_KEY))
        .await;
    assert_eq!(
        status, 200,
        "recents is in telemetry's scope as of 2026-08-18"
    );

    // And everything else stays shut. One route was added, not a tier.
    for path in ["/v1/moments?as_of=100", "/health/deep"] {
        let (status, _, _) = node.get(path, Some(TELEMETRY_KEY)).await;
        assert_eq!(status, 401, "{path} must stay closed to the telemetry key");
    }
    // Beta did not inherit it. The two credentials are separate scopes now, not
    // one scope behind two secrets, and that is the assertion that would fail if
    // someone "simplified" the guards by merging them.
    let (status, _, _) = node
        .get("/v1/recents?as_of=100&limit=1", Some(BETA_KEY))
        .await;
    assert_eq!(status, 401, "beta must not have gained recents");
    let (status, body, _) = node.post("/v1/events", Some(TELEMETRY_KEY), "{}").await;
    assert_eq!(status, 403, "known credential, wrong scope");
    assert_eq!(body["error"], "read_only_credential");

    // The two secrets are genuinely different. If a refactor ever collapsed
    // them onto one value every assertion above would still pass, and the
    // revocability this credential exists for would be silently gone.
    assert_ne!(
        BETA_KEY, TELEMETRY_KEY,
        "one secret for two holders is not two credentials"
    );

    node.done().await;
}

#[tokio::test]
async fn the_beta_key_opens_exactly_two_routes() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    // The two beta asked for.
    let (status, _, _) = node.get("/v1/entities/1?as_of=100", Some(BETA_KEY)).await;
    assert_eq!(status, 200, "entity lookup is beta's");
    let (status, _, _) = node
        .post(
            "/v1/feasibility",
            Some(BETA_KEY),
            r#"{"subjects":[1,2],"as_of":"100","claim":1}"#,
        )
        .await;
    assert_eq!(status, 200, "feasibility is beta's");

    // Everything else is closed. A scope that grants more than was asked for
    // is not a scope — the read key would have handed them these too, which is
    // exactly why beta did not get the read key.
    for path in [
        "/v1/moments?as_of=100",
        "/health/deep",
        "/v1/recents?as_of=100",
    ] {
        let (status, _, _) = node.get(path, Some(BETA_KEY)).await;
        assert_eq!(status, 401, "{path} must stay closed to the beta key");
    }

    // Known credential, wrong scope, on the write path.
    let (status, body, _) = node.post("/v1/events", Some(BETA_KEY), "{}").await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "read_only_credential");

    // The gallery key must NOT open beta's routes, and vice versa: two scopes
    // that leak into each other are one scope with extra steps.
    let (status, _, _) = node
        .get("/v1/entities/1?as_of=100", Some(GALLERY_KEY))
        .await;
    assert_eq!(status, 401, "the gallery key is not a beta key");

    node.done().await;
}

#[tokio::test]
async fn feasibility_accepts_both_spellings_of_ids_and_coordinates() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    // Entity ids exceed JS's safe integer range, so the contract tells
    // consumers to send strings. The deserializer used to 422 exactly that —
    // a caller following our own documentation was punished for it.
    for body in [
        r#"{"subjects":[1,2],"as_of":"100","claim":1}"#,
        r#"{"subjects":["1","2"],"as_of":"100","claim":1}"#,
        r#"{"subjects":[1,"2"],"as_of":"100","claim":1}"#,
        // as_of as a number: requiring a string here while requiring numbers
        // for subjects in the SAME body is an asymmetry nobody can guess.
        r#"{"subjects":[1,2],"as_of":100,"claim":1}"#,
        r#"{"subjects":["1","2"],"as_of":100,"claim":1}"#,
    ] {
        let (status, _, _) = node.post("/v1/feasibility", Some(TEST_KEY), body).await;
        assert_eq!(status, 200, "should have been accepted: {body}");
    }

    // A missing coordinate is still the documented refusal, not a
    // deserializer message — the sentence is the contract.
    let (status, b, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":[1,2],"claim":1}"#,
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(b["error"], "malformed_request");

    // Garbage is still refused rather than coerced.
    let (status, _, _) = node
        .post(
            "/v1/feasibility",
            Some(TEST_KEY),
            r#"{"subjects":["not-a-number",2],"as_of":"100","claim":1}"#,
        )
        .await;
    assert_eq!(status, 422, "a non-numeric string is not an id");

    node.done().await;
}

/// Two rows on one subject must read as **one claim with two readings**, not as
/// two claims and not as a duplication bug.
///
/// Three entities on the live chain carry two readings each — a pilot body and a
/// later regeneration. Entity identity is derived from `(title, year)` and so is
/// `content_hash`, so both rows describe the same claim by construction; they
/// differ only outside the hash. Until this block existed the surface returned
/// one body chosen by `record_coord` and said nothing about the other, so a
/// reader met a single body with no way to know it was one of several, and a
/// reader who found both met what looked like a defect.
///
/// Sean's decision `d-20260821-7b2eed`, on timepoint-telemetry's proposal, chose
/// this over de-projecting a row: **say what the rows are rather than edit the
/// record until the relation disappears.** No mint, no deletion, `rebuild()`
/// untouched.
///
/// `count: 1` is asserted too. One reading and "we did not look" must not render
/// the same, which is the presence-versus-value distinction this repo keeps
/// paying for.
#[tokio::test]
async fn two_rows_on_one_subject_report_as_one_claim_with_two_readings() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;
    let sk = SecretKey::from_seed([7u8; 32]);
    // A second reading of entity 2's claim, inside the as_of bound.
    moment(&node.pool, &sk, 2, t(31), 0xb7).await;

    let (status, body, _) = node.get("/v1/entities/2?as_of=100", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    let r = &body["readings"];
    assert_eq!(r["count"], 2, "two live moments on one subject");
    // No claim body is retained in this fixture, so the honest verdict is that
    // the readings CANNOT be compared — not that they are the same. Asserting
    // sameness here is the defect this block was rewritten to remove.
    assert_eq!(
        r["relation"], "cannot_compare",
        "with no retained bodies the relation is unknown, never 'same claim'"
    );
    assert_eq!(
        r["all"].as_array().expect("all is an array").len(),
        2,
        "both readings are named, not just counted — a count says something is \
         there and a list says what to go and look at"
    );
    assert_eq!(
        r["this"], r["all"][0]["body_hash"],
        "the body returned above is the first reading listed"
    );

    // The ordinary case still states itself rather than being omitted.
    let (status, body, _) = node.get("/v1/entities/1?as_of=25", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["readings"]["count"], 1,
        "one reading is reported as one, never as an absent field"
    );

    node.done().await;
}

/// Two titles that **normalise together but hash apart** must report as several
/// claims, never as one.
///
/// `claim_identity` hashes `normalise(title) | year` — lowercase, ASCII
/// alphanumerics, runs collapsed, trimmed. `content_hash` hashes the RAW title
/// as `label`. Presentational noise is inside one and outside the other, and
/// `claim_identity_is_stable_and_normalises_the_title` asserts that collapse
/// deliberately.
///
/// So two rows can share an entity and not a claim. The `readings` block first
/// published `same_claim: true` on the premise that this was impossible, which
/// would have been a surface asserting an identity TT does not grant — an
/// over-merge on a normalisation basin. It would have shipped green: every pair
/// on the live chain today has equal hashes, so the premise is true of this
/// corpus and false in general, and would have stayed true until the first
/// title-variant pair arrived and was silently mislabelled.
///
/// Found by timepoint-telemetry before deploy. This is the case that must fail.
#[tokio::test]
async fn titles_that_normalise_together_are_not_one_claim() {
    let node = Node::boot(Posture::Live).await;
    let sk = SecretKey::from_seed([7u8; 32]);

    // Both titles normalise to "the fall of constantinople", so both derive the
    // same entity_id — the entity is created once and carries both readings.
    let raw_a = "  the FALL, of  Constantinople!  ";
    let raw_b = "the fall of constantinople";
    let eid = 3_570_146_037_395_080_199_i64;
    birth(
        &node.pool,
        &sk,
        eid,
        raw_a,
        WindowStart::Known(t(0)),
        WindowEnd::KnownOpen,
        t(0),
    )
    .await;

    // Two bodies, two raw titles, one entity.
    for (tag, title) in [(0xc1u8, raw_a), (0xc2u8, raw_b)] {
        moment(&node.pool, &sk, eid, t(20), tag).await;
        let body = format!(r#"{{"title":{},"year":1453}}"#, serde_json::json!(title));
        sqlx::query(
            "INSERT INTO claim_bodies (body_hash, body) VALUES ($1, $2) \
                     ON CONFLICT (body_hash) DO NOTHING",
        )
        .bind(vec![tag; 32])
        .bind(&body)
        .execute(&node.pool)
        .await
        .expect("store claim body");
    }

    let (status, body, _) = node
        .get(&format!("/v1/entities/{eid}?as_of=100"), Some(TEST_KEY))
        .await;
    assert_eq!(status, 200);
    let r = &body["readings"];
    assert_eq!(r["count"], 2);
    assert_eq!(
        r["relation"], "several_claims_sharing_an_entity",
        "different content_hash means different claims, whatever the entity says"
    );
    let hashes: Vec<&str> = r["all"]
        .as_array()
        .expect("all")
        .iter()
        .map(|e| e["content_hash"].as_str().expect("a computed hash"))
        .collect();
    assert_ne!(
        hashes[0], hashes[1],
        "the two raw titles must hash apart — that is the whole premise"
    );

    node.done().await;
}

/// An entity with **no readings at this coordinate** must say so, not be
/// published as one claim.
///
/// `windows(2).all(..)` is vacuously true on an empty vec, so before this the
/// block returned `count: 0` beside `relation: one_claim_many_readings` — a
/// relation computed over nothing, indistinguishable from a relation that holds,
/// inside the block written to stop a relation being asserted.
///
/// Entity 4 is the fixture case: born with `WindowStart::Unknown` and carrying no
/// moments. Not reachable on the live corpus, where all 380 entities have a known
/// start and the admission gate refuses undated entries — but that is a fact
/// about the data, and the branch would sit waiting for the existence predicate
/// to change. Condition handed over by timepoint-telemetry, who could not reach
/// a `date_is_known: false` entity from their scope and declined to guess.
#[tokio::test]
async fn an_entity_with_no_readings_is_not_one_claim() {
    let node = Node::boot(Posture::Live).await;
    seed(&node.pool).await;

    let (status, body, _) = node.get("/v1/entities/4?as_of=100", Some(TEST_KEY)).await;
    assert_eq!(status, 200, "entity 4 resolves; it simply has no moments");
    let r = &body["readings"];
    assert_eq!(r["count"], 0);
    assert_eq!(
        r["relation"], "no_readings",
        "zero readings is its own state, never a vacuous 'one claim'"
    );
    assert_eq!(r["this"], serde_json::Value::Null);
    assert!(r["all"].as_array().expect("all").is_empty());

    node.done().await;
}

fn signed_absence(entity: i64, body: u8, reason: &str) -> Value {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    let key = SigningKey::from_bytes(&[47; 32]);
    let author = hex::encode(key.verifying_key().to_bytes());
    let manifest = serde_json::json!({
        "schema":"cc.media-absence.v1", "kind":"deliberately_unillustrated",
        "source_entity_id":entity.to_string(), "source_body_hash":hex::encode([body;32]),
        "writer":author, "reason":reason, "decided_at_ticks":"842832000",
    });
    let mut digest = Sha256::new();
    digest.update(b"cc.media-absence.v1\0");
    digest.update(tt_core::canonicalize(&manifest));
    serde_json::json!({"manifest":manifest, "author":author,
        "signature":hex::encode(key.sign(&digest.finalize()).to_bytes())})
}

/// Exercise the CLI's exit contract against the same real fixture as HTTP.
async fn media_check_exit(pool: &PgPool) -> i32 {
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .unwrap();
    let mut url = reqwest::Url::parse(&std::env::var("TEST_DATABASE_URL").unwrap()).unwrap();
    url.set_path(&database);
    std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../ops/check-media.py"
        ))
        .env("CC_DATABASE_URL", url.as_str())
        .output()
        .expect("run media assertion")
        .status
        .code()
        .unwrap()
}

#[tokio::test]
async fn image_attachment_is_signed_bound_and_never_a_historical_event() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    let directory = std::env::temp_dir().join(format!("cc-media-test-{}", uuid::Uuid::new_v4()));
    std::env::set_var("CC_MEDIA_DIR", &directory);
    let node = Node::boot(Posture::Live).await;
    let historical = SecretKey::from_seed([17; 32]);
    birth(
        &node.pool,
        &historical,
        1,
        "Test",
        WindowStart::Known(t(0)),
        WindowEnd::UnknownClosure,
        t(0),
    )
    .await;
    moment(&node.pool, &historical, 1, t(1), 9).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&node.pool)
        .await
        .unwrap();
    let mut raw = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut raw, 1, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&[20, 40, 60])
            .unwrap();
    }
    let key = SigningKey::from_bytes(&[37; 32]);
    let author = hex::encode(key.verifying_key().to_bytes());
    let mut manifest = json!({
    "schema":"cc.image-attachment.v1","kind":"generated_interpretation_of_claim",
    "historical_verification":"not_assessed","provider":"local_inference",
    "model":"stabilityai/stable-diffusion-xl-base-1.0","model_revision":"462165984030d82259a11f4367a4eed129e94a7b",
    "permission_profile":"sdxl-openrail++-m-local-v1","license_sha256":"19b6998b569b53ac1fc2158a8a3202c8699a9a4605b47075715d9c96be7fb6d0",
    "source_entity_id":"1","source_body_hash":hex::encode([9u8;32]),"writer":author,
    "prompt_in_training":false,"prompt":"test fixture","generated_at":"2026-09-08T00:00:00Z","seed":1,
    "image_sha256":hex::encode(Sha256::digest(&raw)),"byte_count":raw.len(),
    "weights_sha256":{
        "text_encoder/model.fp16.safetensors":"660c6f5b1abae9dc498ac2d21e1347d2abdb0cf6c0c0c8576cd796491d9a6cdd",
        "text_encoder_2/model.fp16.safetensors":"ec310df2af79c318e24d20511b601a591ca8cd4f1fce1d8dff822a356bcdb1f4",
        "unet/diffusion_pytorch_model.fp16.safetensors":"83e012a805b84c7ca28e5646747c90a243c65c8ba4f070e2d7ddc9d74661e139",
        "vae/diffusion_pytorch_model.fp16.safetensors":"bcb60880a46b63dea58e9bc591abe15f8350bde47b405f9c38f4be70c6161e68"
    }});
    let sign = |m: &Value| {
        let mut h = Sha256::new();
        h.update(b"cc.image-attachment.v1\0");
        h.update(tt_core::canonicalize(m));
        json!({"manifest":m,"author":author,"signature":hex::encode(key.sign(&h.finalize()).to_bytes()),"image_base64":STANDARD.encode(&raw)})
    };
    let valid = sign(&manifest);
    // The free-space reserve refuses the write rather than half-storing it: no
    // bytes on disk and no catalog row, so a full volume is a typed pause and
    // never a missing-object corruption. This test is the only media writer in
    // this binary, so the process-global reserve is safe to move here.
    std::env::set_var("CC_MEDIA_FREE_RESERVE_PERCENT", "100");
    let (status, refused, _) = node
        .post("/v1/images", Some(TEST_KEY), &valid.to_string())
        .await;
    assert_eq!(status, 503, "{refused}");
    assert_eq!(refused["error"], "unavailable");
    assert_eq!(
        std::fs::read_dir(&directory)
            .map(|d| d.count())
            .unwrap_or(0),
        0,
        "refused write must leave no object behind"
    );
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM image_attachments")
        .fetch_one(&node.pool)
        .await
        .unwrap();
    assert_eq!(stored, 0, "refused write must leave no catalog row");
    std::env::set_var("CC_MEDIA_FREE_RESERVE_PERCENT", "0");
    let (status, receipt, _) = node
        .post("/v1/images", Some(TEST_KEY), &valid.to_string())
        .await;
    assert_eq!(status, 201, "{receipt}");
    assert_eq!(receipt["appended"], "new");
    assert_eq!(receipt["historical_ledger_event"], false);
    let (_, duplicate, _) = node
        .post("/v1/images", Some(TEST_KEY), &valid.to_string())
        .await;
    assert_eq!(duplicate["appended"], "existing");
    let (status, _, _) = node
        .post("/v1/images", Some(READ_KEY), &valid.to_string())
        .await;
    assert_eq!(status, 403);
    let (status, _, _) = node.post("/v1/images", None, "bad json").await;
    assert_eq!(status, 401);
    let mut tampered = valid.clone();
    tampered["manifest"]["prompt"] = json!("tampered");
    assert_eq!(
        node.post("/v1/images", Some(TEST_KEY), &tampered.to_string())
            .await
            .0,
        400
    );
    manifest["permission_profile"] = json!("unrestricted");
    assert_eq!(
        node.post("/v1/images", Some(TEST_KEY), &sign(&manifest).to_string())
            .await
            .0,
        400
    );
    manifest["permission_profile"] = json!("sdxl-openrail++-m-local-v1");
    manifest["source_body_hash"] = json!(hex::encode([8u8; 32]));
    assert_eq!(
        node.post("/v1/images", Some(TEST_KEY), &sign(&manifest).to_string())
            .await
            .0,
        400
    );
    let (_, old, _) = node
        .get("/v1/images?entity_id=1&as_of=0", Some(READ_KEY))
        .await;
    assert_eq!(old["state"], "no_image");
    assert_eq!(
        node.get("/v1/images?entity_id=1", Some(READ_KEY)).await.0,
        400
    );
    let (_, current, _) = node
        .get("/v1/images?entity_id=1&as_of=9999999999", Some(READ_KEY))
        .await;
    assert_eq!(
        current["images"][0]["source_binding"],
        "currently_projected"
    );
    let result = node
        .http
        .get(format!(
            "{}/v1/images/{}",
            node.base,
            valid["manifest"]["image_sha256"].as_str().unwrap()
        ))
        .bearer_auth(READ_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), 200);
    assert_eq!(result.bytes().await.unwrap().as_ref(), raw);
    let (_, typed, _) = node
        .get("/v2/media?entity_id=1&as_of=9999999999", Some(READ_KEY))
        .await;
    assert_eq!(typed["readings"][0]["state"], "generated");
    // More than the legacy image page size: state must see every decision.
    for i in 0..51 {
        let (status, _, _) = node
            .post(
                "/v2/media/absence-decisions",
                Some(TEST_KEY),
                &signed_absence(1, 9, &format!("Decision {i}")).to_string(),
            )
            .await;
        assert_eq!(status, 201);
    }
    let (_, typed, _) = node
        .get("/v2/media?entity_id=1&as_of=9999999999", Some(READ_KEY))
        .await;
    assert_eq!(typed["readings"][0]["state"], "conflicting_media_records");
    assert_eq!(
        typed["readings"][0]["absence_decisions"]
            .as_array()
            .unwrap()
            .len(),
        51
    );
    // The v1 enum remains unchanged even when an explicit decision coexists.
    let (_, legacy, _) = node
        .get("/v1/images?entity_id=1&as_of=9999999999", Some(READ_KEY))
        .await;
    assert_eq!(legacy["state"], "generated");
    // A separately signed Apache contribution coexists with the SDXL entry.
    let profile: Value =
        serde_json::from_str(include_str!("../../../ops/flux_profile.json")).unwrap();
    let mut apache = valid["manifest"].clone();
    for (field, value) in profile.as_object().unwrap() {
        apache[field] = value.clone();
    }
    apache["execution_platform"] = json!("huggingface_jobs");
    let (status, receipt, _) = node
        .post("/v1/images", Some(TEST_KEY), &sign(&apache).to_string())
        .await;
    assert_eq!(status, 201, "{receipt}");
    assert_eq!(receipt["historical_ledger_event"], false);
    let (_, both, _) = node
        .get("/v1/images?entity_id=1&as_of=9999999999", Some(READ_KEY))
        .await;
    assert_eq!(both["images"].as_array().unwrap().len(), 2);
    let (status, health, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(health["media"]["image_attachment_count"], 2);
    assert_eq!(health["media"]["orphan_image_attachment_count"], 0);
    assert_eq!(health["media"]["integrity"], "pass");
    assert_eq!(media_check_exit(&node.pool).await, 0);
    assert_eq!(health["media"]["objects"]["checked"], 1);
    let object_path = directory.join(format!(
        "{}.png",
        manifest["image_sha256"].as_str().unwrap()
    ));
    std::fs::write(&object_path, b"corrupt object").unwrap();
    let (status, broken, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(status, 503);
    assert_eq!(
        broken["media"]["objects"]["findings"][0]["reason"],
        "digest_mismatch"
    );
    std::fs::remove_file(&object_path).unwrap();
    let (status, missing, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(status, 503);
    assert_eq!(
        missing["media"]["objects"]["findings"][0]["reason"],
        "unreadable"
    );
    std::fs::write(&object_path, &raw).unwrap();
    // Local fixture: withdrawn source must be visible as stale, not reassigned.
    sqlx::query("DELETE FROM moments WHERE subject=1")
        .execute(&node.pool)
        .await
        .unwrap();
    let (_, stale, _) = node
        .get("/v1/images?entity_id=1&as_of=9999999999", Some(READ_KEY))
        .await;
    assert_eq!(stale["images"][0]["source_binding"], "stale_source");
    let (status, health, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(
        status, 503,
        "withdrawn images must fail the aggregate assertion"
    );
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["media"]["image_attachment_count"], 2);
    assert_eq!(health["media"]["orphan_image_attachment_count"], 2);
    assert_eq!(health["media"]["stale_image_attachment_count"], 2);
    assert_eq!(health["media"]["integrity"], "fail");
    assert_eq!(media_check_exit(&node.pool).await, 1);
    assert_eq!(
        health["media"]["orphan_attachments"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        health["media"]["orphan_attachments"][0]["source_body_hash"],
        hex::encode([9u8; 32])
    );
    // A different entity still projecting the same body satisfies the exact
    // PLAN invariant, while both entity-specific attachments remain stale.
    birth(
        &node.pool,
        &historical,
        2,
        "Other",
        WindowStart::Known(t(0)),
        WindowEnd::UnknownClosure,
        t(0),
    )
    .await;
    moment(&node.pool, &historical, 2, t(2), 9).await;
    let (status, health, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(health["media"]["orphan_image_attachment_count"], 0);
    assert_eq!(health["media"]["stale_image_attachment_count"], 2);

    assert_eq!(
        node.post("/v1/images", Some(TEST_KEY), &valid.to_string())
            .await
            .0,
        400
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&node.pool)
        .await
        .unwrap();
    assert_eq!(before + 2, after);
    node.done().await;
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn media_integrity_empty_and_unreadable_are_distinct() {
    let node = Node::boot(Posture::Live).await;
    let (status, health, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(status, 200);
    assert_eq!(health["media"]["image_attachment_count"], 0);
    assert_eq!(health["media"]["orphan_attachments"], serde_json::json!([]));
    assert_eq!(health["media"]["integrity"], "pass");
    assert_eq!(media_check_exit(&node.pool).await, 0);
    sqlx::query("ALTER TABLE image_attachments RENAME TO unavailable_images")
        .execute(&node.pool)
        .await
        .unwrap();
    let (status, health, _) = node.get("/health/deep", Some(TEST_KEY)).await;
    assert_eq!(status, 503);
    assert_eq!(health["media"]["integrity"], "not_run");
    assert_eq!(media_check_exit(&node.pool).await, 2);
    assert_eq!(node.get("/health", None).await.0, 200);
    node.done().await;
}

#[tokio::test]
async fn absence_is_signed_body_scoped_visible_and_never_inferred() {
    use serde_json::json;
    let node = Node::boot(Posture::Live).await;
    let key = SecretKey::from_seed([18; 32]);
    // These adjacent ids lose their distinction if passed through an f64.
    let entity = 3582419940486658630i64;
    let other = entity + 1;
    for id in [entity, other] {
        birth(
            &node.pool,
            &key,
            id,
            "Exact ID",
            WindowStart::Known(t(0)),
            WindowEnd::UnknownClosure,
            t(0),
        )
        .await;
        moment(&node.pool, &key, id, t(1), 9).await;
    }
    moment(&node.pool, &key, entity, t(2), 8).await;
    let path = format!("/v2/media?entity_id={entity}&as_of=9999999999");
    let (_, empty, _) = node
        .get("/v2/media?entity_id=999&as_of=0", Some(READ_KEY))
        .await;
    assert_eq!(empty["readings"], json!([]));
    assert_eq!(
        node.get(&format!("/v2/media?entity_id={entity}"), Some(READ_KEY))
            .await
            .0,
        400
    );
    let (_, no_records, _) = node.get(&path, Some(READ_KEY)).await;
    assert_eq!(no_records["readings"].as_array().unwrap().len(), 2);
    assert!(no_records["readings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["state"] == "no_generation_recorded"));
    let before: Vec<Vec<u8>> = sqlx::query_scalar("SELECT event_id FROM events ORDER BY event_id")
        .fetch_all(&node.pool)
        .await
        .unwrap();
    let payload = signed_absence(entity, 9, "Do not add a speculative depiction");
    let (status, receipt, _) = node
        .post(
            "/v2/media/absence-decisions",
            Some(TEST_KEY),
            &payload.to_string(),
        )
        .await;
    assert_eq!(status, 201, "{receipt}");
    assert_eq!(receipt["appended"], "new");
    assert_eq!(receipt["historical_ledger_event"], false);
    let (_, replay, _) = node
        .post(
            "/v2/media/absence-decisions",
            Some(TEST_KEY),
            &payload.to_string(),
        )
        .await;
    assert_eq!(replay["decision_id"], receipt["decision_id"]);
    assert_eq!(replay["appended"], "existing");
    let (_, typed, _) = node.get(&path, Some(READ_KEY)).await;
    assert_eq!(typed["projection_basis"], "current");
    assert_eq!(typed["readings"][0]["state"], "no_generation_recorded");
    assert_eq!(typed["readings"][1]["state"], "deliberately_unillustrated");
    let decision = &typed["readings"][1]["absence_decisions"][0];
    assert_eq!(decision["manifest"], payload["manifest"]);
    assert_eq!(decision["signature"], payload["signature"]);
    assert!(decision["admitted_coord"]
        .as_str()
        .unwrap()
        .starts_with("0x"));
    // Before admission the reading exists, but the decision is not visible.
    let (_, earlier, _) = node
        .get(
            &format!("/v2/media?entity_id={entity}&as_of=10"),
            Some(READ_KEY),
        )
        .await;
    assert_eq!(earlier["readings"][1]["state"], "no_generation_recorded");
    let at_admission = format!(
        "/v2/media?entity_id={entity}&as_of={}",
        decision["admitted_coord"].as_str().unwrap()
    );
    assert_eq!(
        node.get(&at_admission, Some(READ_KEY)).await.1["readings"][1]["state"],
        "deliberately_unillustrated"
    );
    let (_, sibling, _) = node
        .get(
            &format!("/v2/media?entity_id={other}&as_of=9999999999"),
            Some(READ_KEY),
        )
        .await;
    assert_eq!(sibling["readings"][0]["state"], "no_generation_recorded");
    let (_, legacy, _) = node
        .get(
            &format!("/v1/images?entity_id={entity}&as_of=9999999999"),
            Some(READ_KEY),
        )
        .await;
    assert_eq!(legacy["state"], "no_image");
    // Signed-but-invalid records and valid signatures over the wrong identity.
    for invalid in [
        signed_absence(entity, 7, "unprojected"),
        signed_absence(99, 9, "wrong entity"),
        signed_absence(entity, 9, "  "),
        signed_absence(entity, 9, &"x".repeat(4097)),
    ] {
        assert_eq!(
            node.post(
                "/v2/media/absence-decisions",
                Some(TEST_KEY),
                &invalid.to_string()
            )
            .await
            .0,
            400
        );
    }
    for (field, replacement) in [
        ("reason", json!("tampered")),
        ("source_entity_id", json!(other.to_string())),
        ("source_entity_id", json!(entity)),
        ("source_body_hash", json!(hex::encode([8u8; 32]))),
        ("schema", json!("cc.image-attachment.v1")),
        ("decided_at_ticks", json!("0842832000")),
        ("extra", json!("unreviewed")),
    ] {
        let mut invalid = payload.clone();
        invalid["manifest"][field] = replacement;
        assert_eq!(
            node.post(
                "/v2/media/absence-decisions",
                Some(TEST_KEY),
                &invalid.to_string()
            )
            .await
            .0,
            400,
            "{field}"
        );
    }
    // A signature over the image domain must not authenticate absence.
    {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};
        let mut invalid = payload.clone();
        let mut digest = Sha256::new();
        digest.update(b"cc.image-attachment.v1\0");
        digest.update(tt_core::canonicalize(&invalid["manifest"]));
        invalid["signature"] = json!(hex::encode(
            SigningKey::from_bytes(&[47; 32])
                .sign(&digest.finalize())
                .to_bytes()
        ));
        assert_eq!(
            node.post(
                "/v2/media/absence-decisions",
                Some(TEST_KEY),
                &invalid.to_string()
            )
            .await
            .0,
            400
        );
    }
    let after: Vec<Vec<u8>> = sqlx::query_scalar("SELECT event_id FROM events ORDER BY event_id")
        .fetch_all(&node.pool)
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "absence must never mint or rewrite a historical event"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM media_absence_decisions")
        .fetch_one(&node.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    // Legal 4096-byte text can require 24 KiB when JSON escapes controls.
    let escaped_reason = format!("{}x", "\u{0001}".repeat(4095));
    assert_eq!(
        node.post(
            "/v2/media/absence-decisions",
            Some(TEST_KEY),
            &signed_absence(entity, 9, &escaped_reason).to_string()
        )
        .await
        .0,
        201
    );
    // Katherine Johnson shape: withdraw and re-mint. Another entity keeps the
    // old body, but that cannot transfer this entity's deliberate decision.
    sqlx::query("DELETE FROM moments WHERE subject=$1 AND body_hash=$2")
        .bind(entity)
        .bind(vec![9u8; 32])
        .execute(&node.pool)
        .await
        .unwrap();
    moment(&node.pool, &key, entity, t(3), 7).await;
    let (_, corrected, _) = node.get(&path, Some(READ_KEY)).await;
    assert_eq!(corrected["readings"][0]["state"], "no_generation_recorded");
    assert_eq!(
        corrected["readings"][0]["source_binding"],
        "currently_projected"
    );
    assert_eq!(
        corrected["readings"][2]["state"],
        "deliberately_unillustrated"
    );
    assert_eq!(corrected["readings"][2]["source_binding"], "stale_source");
    assert_eq!(
        node.post(
            "/v2/media/absence-decisions",
            Some(TEST_KEY),
            &payload.to_string()
        )
        .await
        .0,
        400
    );
    node.done().await;
    let frozen = Node::boot(Posture::Frozen).await;
    assert_eq!(
        frozen
            .post(
                "/v2/media/absence-decisions",
                Some(TEST_KEY),
                &payload.to_string()
            )
            .await
            .0,
        403
    );
    frozen.done().await;
}
