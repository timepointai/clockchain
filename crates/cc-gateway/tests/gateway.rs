//! The served gateway (`cc_gateway::router`) on a real socket, in front of the
//! served v1 node (`cc_node::serve_v1::router`) on a real socket over a real
//! PostgreSQL store. The node is wrapped in a recording layer, so every claim
//! about what did or did not reach it is read from the node side.
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use cc_core::v1::*;
use cc_gateway::{config::Config, router, Gateway, RESPONSE_HEADERS};
use cc_ledger::v1::Store;
use cc_node::config::{KeyDigest, Posture, V1Config};
use cc_node::serve_v1::{self, health_body, Serving, V1State};
use cc_testkit::v1::*;
use reqwest::{header::HeaderMap, Method, StatusCode as S};
use serde_json::{json, Value as Json};

const WRITE: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const READ: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
/// Strong, but not a key the node accepts.
const WRONG: &str = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const PROSE: &str = "Synthetic prose retained for the gateway test.";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------- logging --

/// Every log line any test in this binary emits, at every level.
static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn logs() -> Arc<Mutex<Vec<u8>>> {
    LOGS.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = buf.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || Capture(sink.clone()))
            .init();
        buf
    })
    .clone()
}

// ------------------------------------------------------------------- node --

/// `(method, path and query, authorization)` for every request the node saw.
type Seen = Arc<Mutex<Vec<(String, String, Option<String>)>>>;
/// Every request header name the node saw.
type Names = Arc<Mutex<BTreeSet<String>>>;

async fn record(State((seen, names)): State<(Seen, Names)>, req: Request, next: Next) -> Response {
    let seen_names = req.headers().keys().map(|k| k.as_str().to_string());
    names.lock().unwrap().extend(seen_names);
    let auth = req
        .headers()
        .get("authorization")
        .map(|v| v.to_str().unwrap().to_string());
    let path = req.uri().path_and_query().unwrap().to_string();
    seen.lock()
        .unwrap()
        .push((req.method().to_string(), path, auth));
    next.run(req).await
}

struct Node {
    base: String,
    seen: Seen,
    names: Names,
    server: tokio::task::JoinHandle<()>,
}

impl Node {
    fn seen(&self) -> Vec<(String, String, Option<String>)> {
        self.seen.lock().unwrap().clone()
    }
    fn paths(&self) -> Vec<String> {
        self.seen().into_iter().map(|(_, p, _)| p).collect()
    }
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let make = app.into_make_service_with_connect_info::<SocketAddr>();
    let server = tokio::spawn(async move { axum::serve(listener, make).await.unwrap() });
    (base, server)
}

async fn boot_node(store: &Store, serving: Serving) -> Node {
    let semantic = store.semantic_readiness().await.unwrap().semantic;
    let v1 = V1Config {
        database_url: "postgres://unused".into(),
        instance: INSTANCE,
        filter: filter(),
    };
    let state = V1State {
        health_body: health_body(&v1, Posture::Live, &semantic),
        ready_gate: Default::default(),
        store: store.clone(),
        posture: Posture::Live,
        api_key: KeyDigest::of(WRITE),
        read_key: Some(KeyDigest::of(READ)),
        gallery_key: None,
        beta_key: None,
        telemetry_key: None,
    };
    let (seen, names) = (Seen::default(), Names::default());
    let log = (seen.clone(), names.clone());
    let app = serve_v1::router_with(state, serving)
        .layer(axum::middleware::from_fn_with_state(log, record));
    let (base, server) = serve(app).await;
    Node {
        base,
        seen,
        names,
        server,
    }
}

struct Rig {
    pool: sqlx::PgPool,
    cleanup: cc_testkit::Cleanup,
    store: Store,
    node: Node,
}

async fn rig() -> Rig {
    rig_with(Serving::default()).await
}

/// A rig whose node issues receipts under `seed`'s key.
async fn seeded_rig(seed: cc_core::SecretKey) -> Rig {
    rig_with(Serving::new(8, Some(seed))).await
}

async fn rig_with(serving: Serving) -> Rig {
    logs();
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let fresh = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    fresh.bind(filter()).await.unwrap();
    let store = Store::open(pool.clone(), INSTANCE, filter()).await.unwrap();
    let node = boot_node(&store, serving).await;
    Rig {
        pool,
        cleanup,
        store,
        node,
    }
}

impl Rig {
    async fn done(self) {
        self.node.server.abort();
        let _ = self.node.server.await;
        self.pool.close().await;
        self.cleanup.cleanup().await;
    }

    /// The node's own answer to a read, with the read key.
    async fn direct(&self, path: &str) -> (S, Json) {
        let r = http()
            .get(format!("{}{path}", self.node.base))
            .bearer_auth(READ)
            .send()
            .await
            .unwrap();
        (
            r.status(),
            serde_json::from_slice(&r.bytes().await.unwrap()).unwrap(),
        )
    }

    /// Submit through the node's own write route, as a publisher does, so a
    /// seeded node issues its receipt.
    async fn submit(&self, e: &Signed) {
        let r = http()
            .post(format!("{}/v1/candidates", self.node.base))
            .bearer_auth(WRITE)
            .body(e.bytes().to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::CREATED);
    }

    async fn admit(&self, e: &Signed) {
        let o = self.store.admit(e.bytes()).await.unwrap();
        assert_eq!(o.event, Some(e.id()));
    }
}

// ---------------------------------------------------------------- gateway --

fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

struct Gw {
    base: String,
    server: tokio::task::JoinHandle<()>,
}

type Raw = (S, HeaderMap, Vec<u8>);

async fn gateway(node: &str, key: &str, extra: &[(&str, &str)]) -> Gw {
    logs();
    let mut env = vec![("CC_GATEWAY_NODE_URL", node), ("CC_GATEWAY_READ_KEY", key)];
    env.extend_from_slice(extra);
    let config = Config::from_lookup(|k| {
        env.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.to_string())
    })
    .unwrap();
    let (base, server) = serve(router(Gateway::new(&config))).await;
    Gw { base, server }
}

/// No rate limit worth hitting and no freshness window: every corpus read
/// first asks the node for its digest.
const EAGER: [(&str, &str); 2] = [
    ("CC_GATEWAY_RATE_PER_MINUTE", "100000"),
    ("CC_GATEWAY_FRESHNESS_MS", "0"),
];

/// Every gateway response in this file passes these checks: the fixed
/// headers, and no trace of the read key in any header or in the body.
fn audited(m: &Method, path: &str, status: S, headers: &HeaderMap, body: &[u8]) {
    for (name, value) in RESPONSE_HEADERS {
        let got = headers.get(name).map(|v| v.to_str().unwrap());
        assert_eq!(got, Some(value), "{name} on {m} {path}");
    }
    let leaks = |hay: &[u8]| {
        hay.windows(READ.len()).any(|w| w == READ.as_bytes())
            || hay.windows(WRONG.len()).any(|w| w == WRONG.as_bytes())
    };
    for (name, value) in headers {
        assert!(!leaks(value.as_bytes()), "key in {name} on {m} {path}");
        assert_ne!(name.as_str(), "authorization", "{m} {path}");
    }
    assert!(!leaks(body), "key in the body of {status} {m} {path}");
}

impl Gw {
    async fn raw(&self, m: Method, path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Raw {
        let mut req = http()
            .request(m.clone(), format!("{}{path}", self.base))
            .body(body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let r = req.send().await.unwrap();
        let (status, headers) = (r.status(), r.headers().clone());
        let body = r.bytes().await.unwrap().to_vec();
        audited(&m, path, status, &headers, &body);
        (status, headers, body)
    }
    async fn get(&self, path: &str) -> (S, Json) {
        let (s, _, b) = self.raw(Method::GET, path, &[], vec![]).await;
        (s, serde_json::from_slice(&b).unwrap())
    }
    async fn cached(&self, path: &str) -> (S, String, Json) {
        let (s, h, b) = self.raw(Method::GET, path, &[], vec![]).await;
        let cache = h["x-cache"].to_str().unwrap().to_string();
        (s, cache, serde_json::from_slice(&b).unwrap())
    }
    async fn stop(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

fn refusal(status: S, error: &str) -> (S, Json) {
    (status, json!({ "error": error }))
}

fn without_instance(mut v: Json) -> Json {
    v.as_object_mut().unwrap().remove("instance");
    v
}

/// A genesis whose body hash names real UTF-8 prose.
fn prose_genesis() -> Signed {
    let mut e = genesis().envelope().clone();
    if let Payload::Genesis { body, .. } = &mut e.payload {
        *body = hash(PROSE.as_bytes());
    }
    Signed::sign(&key(0), e).unwrap()
}

fn revision(g: &Signed) -> String {
    hex::encode(revision_id(g.id(), g.id()))
}

// ------------------------------------------------------------------ tests --

#[tokio::test]
async fn every_route_matches_the_node_minus_instance() {
    let rig = rig().await;
    let g = prose_genesis();
    let b = subject(1, 50, 51);
    assert!(rig
        .store
        .retain_body(hash(PROSE.as_bytes()), PROSE.as_bytes())
        .await
        .unwrap());
    rig.admit(&g).await;
    rig.admit(&b).await;
    let gw = gateway(&rig.node.base, READ, &EAGER).await;

    let health = rig.direct("/health").await.1;
    assert_eq!(health["instance"], hex::encode(INSTANCE), "{health}");
    let fold = &health["fold_version"];
    let (version, manifest) = (
        fold["version"].to_string(),
        fold["manifest"].as_str().unwrap(),
    );
    let (gid, bid, rev) = (hex::encode(g.id()), hex::encode(b.id()), revision(&g));
    let at = hex::encode([60; 32]);
    // (public path, node path, expected status): the status pins that each
    // case exercises the branch it names, not merely that the two agree.
    let cases: Vec<(String, String, S)> = vec![
        ("/public/v1/health".into(), "/health".into(), S::OK),
        ("/public/v1/snapshot".into(), "/v1/snapshot".into(), S::OK),
        (
            format!("/public/v1/snapshot?fold_version={version}&fold_manifest={manifest}"),
            format!("/v1/snapshot?fold_version={version}&fold_manifest={manifest}"),
            S::OK,
        ),
        (
            format!("/public/v1/snapshot?fold_version=9&fold_manifest={ZERO}"),
            format!("/v1/snapshot?fold_version=9&fold_manifest={ZERO}"),
            S::CONFLICT,
        ),
        (
            "/public/v1/snapshot?fold_version=1".into(),
            "/v1/snapshot?fold_version=1".into(),
            S::BAD_REQUEST,
        ),
        (
            "/public/v1/snapshot?nope=1".into(),
            "/v1/snapshot?nope=1".into(),
            S::BAD_REQUEST,
        ),
        (
            format!("/public/v1/subjects/{gid}"),
            format!("/v1/subjects/{gid}"),
            S::OK,
        ),
        (
            format!("/public/v1/subjects/{bid}"),
            format!("/v1/subjects/{bid}"),
            S::OK,
        ),
        (
            format!("/public/v1/subjects/{gid}?as_of={at}"),
            format!("/v1/subjects/{gid}?as_of={at}"),
            S::OK,
        ),
        (
            format!("/public/v1/subjects/{ZERO}"),
            format!("/v1/subjects/{ZERO}"),
            S::NOT_FOUND,
        ),
        (
            "/public/v1/subjects/xyz".into(),
            "/v1/subjects/xyz".into(),
            S::BAD_REQUEST,
        ),
        (
            format!("/public/v1/subjects/{}", gid.to_uppercase()),
            format!("/v1/subjects/{}", gid.to_uppercase()),
            S::BAD_REQUEST,
        ),
        (
            format!("/public/v1/subjects/{gid}?as_of=nope"),
            format!("/v1/subjects/{gid}?as_of=nope"),
            S::BAD_REQUEST,
        ),
        (
            format!("/public/v1/subjects/{gid}?when=1"),
            format!("/v1/subjects/{gid}?when=1"),
            S::BAD_REQUEST,
        ),
        // A traversal attempt is refused as the invalid id it is.
        (
            "/public/v1/subjects/..%2F..%2Fexport".into(),
            "/v1/subjects/zz".into(),
            S::BAD_REQUEST,
        ),
        (
            format!("/public/v1/revisions/{rev}/prose"),
            format!("/v1/revisions/{rev}/prose"),
            S::OK,
        ),
        (
            format!("/public/v1/revisions/{ZERO}/prose"),
            format!("/v1/revisions/{ZERO}/prose"),
            S::NOT_FOUND,
        ),
        (
            "/public/v1/revisions/%2E%2E%2Fsnapshot/prose".into(),
            "/v1/revisions/zz/prose".into(),
            S::BAD_REQUEST,
        ),
        (
            format!("/public/v1/support?from={gid}&to={bid}"),
            format!("/v1/support?from={gid}&to={bid}"),
            S::OK,
        ),
        (
            format!("/public/v1/support?from={gid}&to={bid}&as_of={at}"),
            format!("/v1/support?from={gid}&to={bid}&as_of={at}"),
            S::OK,
        ),
        (
            format!("/public/v1/support?from={gid}"),
            format!("/v1/support?from={gid}"),
            S::BAD_REQUEST,
        ),
        // This node has no seed, so it holds no receipt for any event.
        (
            format!("/public/v1/receipts/{gid}"),
            format!("/v1/receipts/{gid}"),
            S::NOT_FOUND,
        ),
        (
            "/public/v1/receipts/zz".into(),
            "/v1/receipts/zz".into(),
            S::BAD_REQUEST,
        ),
        (
            "/public/v1/receipts/%2E%2E%2Fexport".into(),
            "/v1/receipts/zz".into(),
            S::BAD_REQUEST,
        ),
    ];
    for (public, private, expected) in &cases {
        let (status, node) = rig.direct(private).await;
        assert_eq!(status, *expected, "{private}: {node}");
        let served = gw.get(public).await;
        assert_eq!(served, (status, without_instance(node)), "{public}");
        assert!(served.1.get("instance").is_none(), "{public}");
    }
    let prose = gw.get(&format!("/public/v1/revisions/{rev}/prose")).await.1;
    assert_eq!(prose["prose"], PROSE);
    let snapshot = gw.get("/public/v1/snapshot").await.1;
    assert_eq!(snapshot["rows"].as_array().unwrap().len(), 2);
    // Only the top-level field goes. The signed envelopes embedded in `rows`
    // keep theirs, or no client could check a signature or a canonical id.
    let embedded = &snapshot["rows"][0]["envelope"]["instance"];
    assert_eq!(embedded, &json!(INSTANCE));
    assert_eq!(
        gw.get("/public/v1/nope").await,
        refusal(S::NOT_FOUND, "no_such_route")
    );
    // Nothing but the mapped read routes ever reached the node.
    for path in rig.node.paths() {
        let mapped = [
            "/health",
            "/v1/snapshot",
            "/v1/subjects/",
            "/v1/revisions/",
            "/v1/support",
            "/v1/receipts/",
        ];
        assert!(mapped.iter().any(|p| path.starts_with(p)), "{path}");
    }
    gw.stop().await;
    rig.done().await;
}

#[tokio::test]
async fn embedded_projection_json_is_passed_through_as_the_nodes_text() {
    let rig = rig().await;
    rig.admit(&prose_genesis()).await;
    let gw = gateway(&rig.node.base, READ, &EAGER).await;
    let node = http()
        .get(format!("{}/v1/snapshot", rig.node.base))
        .bearer_auth(READ)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let served = gw
        .raw(Method::GET, "/public/v1/snapshot", &[], vec![])
        .await
        .2;
    let served = String::from_utf8(served).unwrap();
    // The node writes keys in sorted order, so the two documents are the same
    // text, not merely equal JSON.
    assert_eq!(served, node);
    gw.stop().await;
    rig.done().await;
}

#[tokio::test]
async fn the_read_key_never_leaks_and_client_credentials_never_pass() {
    let rig = rig().await;
    let g = prose_genesis();
    rig.admit(&g).await;
    let gw = gateway(&rig.node.base, READ, &EAGER).await;
    let gid = hex::encode(g.id());
    let paths = [
        "/public/v1/health".to_string(),
        "/public/v1/snapshot".into(),
        "/public/v1/snapshot?bad=1".into(),
        format!("/public/v1/subjects/{gid}"),
        format!("/public/v1/subjects/{ZERO}"),
        format!("/public/v1/revisions/{}/prose", revision(&g)),
        format!("/public/v1/support?from={gid}&to={gid}"),
        "/public/v1/nope".into(),
        format!("/public/v1/receipts/{gid}"),
    ];
    // A client presenting the node's write key, a cookie or a forwarding
    // header gets the public answer; none of it is forwarded.
    let hostile = [
        ("authorization", &*format!("Bearer {WRITE}")),
        ("cookie", "session=x"),
        ("x-forwarded-for", "192.0.2.9"),
    ];
    for path in &paths {
        for m in [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::POST,
            Method::DELETE,
        ] {
            gw.raw(m, path, &hostile, vec![]).await;
        }
    }
    let seen = rig.node.seen();
    assert!(seen.len() > paths.len(), "{seen:?}");
    // Only what the gateway itself sends: no cookie, no forwarding header.
    let names = rig.node.names.lock().unwrap().clone();
    let allowed: BTreeSet<String> = ["accept", "authorization", "host"].map(String::from).into();
    assert!(names.is_subset(&allowed), "{names:?}");
    assert!(names.contains("authorization"), "{names:?}");
    for (m, path, auth) in seen {
        assert_eq!(m, "GET", "{path}");
        if path == "/health" {
            assert_eq!(auth, None);
        } else {
            assert_eq!(auth.as_deref(), Some(&*format!("Bearer {READ}")), "{path}");
        }
    }

    // The failure paths: a node that refuses the key (502) and a node that is
    // gone (503). Both are audited for the key like every response.
    let refused = gateway(&rig.node.base, WRONG, &EAGER).await;
    assert_eq!(
        refused.get("/public/v1/snapshot").await,
        refusal(S::BAD_GATEWAY, "bad_gateway")
    );
    refused.stop().await;
    let dead = dead_origin().await;
    let gone = gateway(&dead, READ, &EAGER).await;
    for path in &paths[..6] {
        assert_eq!(
            gone.get(path).await,
            refusal(S::SERVICE_UNAVAILABLE, "node_unavailable")
        );
    }
    gone.stop().await;

    // Logs, at every level, from every test in this binary so far. The
    // refusal above must have been logged, or this check proves nothing.
    let logs = String::from_utf8(logs().lock().unwrap().clone()).unwrap();
    assert!(logs.contains("node refused the gateway read key"), "{logs}");
    assert!(logs.contains("node unreachable"), "{logs}");
    for key in [READ, WRONG] {
        assert!(!logs.contains(key), "a key reached the logs");
    }
    gw.stop().await;
    rig.done().await;
}

/// An origin nothing listens on.
async fn dead_origin() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    base
}

#[tokio::test]
async fn writes_are_refused_before_routing_and_never_reach_the_node() {
    let rig = rig().await;
    let g = prose_genesis();
    rig.admit(&g).await;
    let gw = gateway(&rig.node.base, READ, &EAGER).await;
    let before = rig.store.snapshot(None).await.unwrap();
    let b = subject(1, 50, 51);
    let body = hash(PROSE.as_bytes());
    let targets = [
        "/public/v1/snapshot".to_string(),
        format!("/public/v1/subjects/{}", hex::encode(g.id())),
        "/public/v1/candidates".into(),
        "/v1/candidates".into(),
        format!("/public/v1/bodies/{}", hex::encode(body)),
        format!("/v1/bodies/{}", hex::encode(body)),
        "/public/v1/export".into(),
    ];
    for path in &targets {
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let wire = if path.contains("bodies") {
                PROSE.as_bytes().to_vec()
            } else {
                b.bytes().to_vec()
            };
            let (status, headers, bytes) = gw.raw(m.clone(), path, &[], wire).await;
            assert_eq!(status, S::METHOD_NOT_ALLOWED, "{m} {path}");
            assert_eq!(headers["allow"], "GET, HEAD, OPTIONS");
            let refused: Json = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(refused, json!({ "error": "read_only" }), "{m} {path}");
        }
    }
    // There is no read route to a write or export path either.
    for path in &targets[2..] {
        assert_eq!(gw.get(path).await, refusal(S::NOT_FOUND, "no_such_route"));
    }
    for path in ["/v1/export", "/public/v1/export", "/v1/snapshot"] {
        assert_eq!(gw.get(path).await, refusal(S::NOT_FOUND, "no_such_route"));
    }
    let (status, headers, _) = gw
        .raw(Method::OPTIONS, "/public/v1/snapshot", &[], vec![])
        .await;
    assert_eq!(status, S::NO_CONTENT);
    assert_eq!(
        headers["access-control-allow-methods"],
        "GET, HEAD, OPTIONS"
    );
    // Nothing above reached the node, and the store did not change.
    assert_eq!(rig.node.count(), 0, "{:?}", rig.node.seen());
    let after = rig.store.snapshot(None).await.unwrap();
    assert_eq!(after.corpus_digest, before.corpus_digest);
    assert_eq!(rig.store.body_bytes(body).await.unwrap(), None);
    gw.stop().await;
    rig.done().await;
}

#[tokio::test]
async fn the_rate_limit_triggers_per_client_before_the_node_is_asked() {
    let rig = rig().await;
    // The default is a burst of 60, then 60 a minute: one more each second.
    let gw = gateway(&rig.node.base, READ, &[]).await;
    let start = Instant::now();
    for i in 0..60 {
        assert_eq!(gw.get("/public/v1/health").await.0, S::OK, "request {i}");
    }
    let mut refilled = 0;
    let (headers, body) = loop {
        let (status, headers, body) = gw.raw(Method::GET, "/public/v1/health", &[], vec![]).await;
        if status == S::TOO_MANY_REQUESTS {
            break (headers, body);
        }
        assert_eq!(status, S::OK);
        refilled += 1;
        assert!(refilled <= 10, "no limit after {} requests", 60 + refilled);
    };
    // Any request past the 60th was a token refilled while this test ran.
    assert!(
        refilled <= start.elapsed().as_secs() + 1,
        "{refilled} refills"
    );
    assert_eq!(headers["retry-after"], "1");
    assert_eq!(
        serde_json::from_slice::<Json>(&body).unwrap(),
        json!({"error": "rate_limited"})
    );
    let first = 60 + refilled as usize;
    assert_eq!(rig.node.count(), first);
    gw.stop().await;

    // A configured limit, metered per client address from a trusted header.
    let header = [
        ("CC_GATEWAY_RATE_PER_MINUTE", "3"),
        ("CC_GATEWAY_CLIENT_IP_HEADER", "x-client-ip"),
    ];
    let gw = gateway(&rig.node.base, READ, &header).await;
    let from = |ip| [("x-client-ip", ip)];
    for _ in 0..3 {
        let r = gw
            .raw(Method::GET, "/public/v1/health", &from("192.0.2.1"), vec![])
            .await;
        assert_eq!(r.0, S::OK);
    }
    // Refused methods spend the same budget, and are refused as rate limited.
    let r = gw
        .raw(
            Method::POST,
            "/public/v1/health",
            &from("192.0.2.1"),
            vec![],
        )
        .await;
    assert_eq!(
        (r.0, r.1["retry-after"].to_str().unwrap()),
        (S::TOO_MANY_REQUESTS, "20")
    );
    let r = gw
        .raw(Method::GET, "/public/v1/health", &from("192.0.2.1"), vec![])
        .await;
    assert_eq!(r.0, S::TOO_MANY_REQUESTS);
    // Another client, and the socket peer when the header is absent, have
    // their own budgets.
    let r = gw
        .raw(Method::GET, "/public/v1/health", &from("192.0.2.2"), vec![])
        .await;
    assert_eq!(r.0, S::OK);
    assert_eq!(gw.get("/public/v1/health").await.0, S::OK);
    assert_eq!(rig.node.count(), first + 5);
    gw.stop().await;
    rig.done().await;
}

#[tokio::test]
async fn the_cache_serves_hits_and_invalidates_after_a_new_admit() {
    let rig = rig().await;
    let g = prose_genesis();
    let gw = gateway(&rig.node.base, READ, &EAGER).await;
    let path = format!("/public/v1/subjects/{}", hex::encode(g.id()));
    let private = path.trim_start_matches("/public");
    let probe = cc_gateway::PROBE.to_string();

    let (status, cache, unknown) = gw.cached(&path).await;
    assert_eq!((status, cache.as_str()), (S::NOT_FOUND, "miss"));
    assert_eq!(unknown["visibility"], "subject_unknown");
    assert_eq!(rig.node.paths(), [probe.clone(), private.to_string()]);
    let (status, cache, again) = gw.cached(&path).await;
    assert_eq!(
        (status, cache.as_str(), &again),
        (S::NOT_FOUND, "hit", &unknown)
    );
    // A hit costs one digest probe and no read.
    assert_eq!(rig.node.paths().len(), 3);
    assert_eq!(rig.node.paths()[2], probe);
    let snapshot = gw.cached("/public/v1/snapshot").await;
    assert_eq!(snapshot.1, "miss");
    assert_eq!(gw.cached("/public/v1/snapshot").await.1, "hit");

    rig.admit(&g).await;
    let (status, cache, visible) = gw.cached(&path).await;
    assert_eq!((status, cache.as_str()), (S::OK, "miss"));
    assert_eq!(visible["visibility"], "visible");
    assert_ne!(visible["corpus_digest"], unknown["corpus_digest"]);
    assert_eq!((status, visible), (S::OK, rig.direct(private).await.1));
    // Caching resumes under the new digest.
    let (status, cache, _) = gw.cached(&path).await;
    assert_eq!((status, cache.as_str()), (S::OK, "hit"));
    let (_, cache, fresh) = gw.cached("/public/v1/snapshot").await;
    assert_eq!(cache, "miss");
    assert_eq!(fresh, rig.direct("/v1/snapshot").await.1);
    assert_ne!(fresh, snapshot.2);
    gw.stop().await;

    // Within a freshness window the node is not asked at all, so an admit
    // becomes visible only once the window has passed: the documented bound.
    let slow = gateway(
        &rig.node.base,
        READ,
        &[("CC_GATEWAY_FRESHNESS_MS", "60000")],
    )
    .await;
    let first = slow.cached(&path).await;
    assert_eq!(first.1, "miss");
    let seen = rig.node.count();
    rig.admit(&subject(1, 50, 51)).await;
    let second = slow.cached(&path).await;
    assert_eq!((second.1.as_str(), &second.2), ("hit", &first.2));
    assert_eq!(rig.node.count(), seen);
    slow.stop().await;
    rig.done().await;
}

#[tokio::test]
async fn a_cached_answer_is_never_served_for_a_failed_node_read() {
    let rig = rig().await;
    let gw = gateway(&rig.node.base, READ, &EAGER).await;
    assert_eq!(gw.cached("/public/v1/snapshot").await.1, "miss");
    assert_eq!(gw.cached("/public/v1/snapshot").await.1, "hit");
    // The node stays up but its store goes away, so it answers reads 503.
    rig.pool.close().await;
    let (status, node) = rig.direct("/v1/snapshot").await;
    assert_eq!(
        (status, node),
        refusal(S::SERVICE_UNAVAILABLE, "store_unavailable")
    );
    let gone = refusal(S::SERVICE_UNAVAILABLE, "node_unavailable");
    assert_eq!(gw.get("/public/v1/snapshot").await, gone);
    gw.stop().await;
    rig.done().await;
}

/// A stand-in node for the answers a real node does not give on demand.
async fn odd_node(
    status: u16,
    body: &'static str,
    extra: Option<(&'static str, &'static str)>,
) -> (String, tokio::task::JoinHandle<()>) {
    let handler = move || async move {
        let mut r = (S::from_u16(status).unwrap(), body).into_response();
        if let Some((k, v)) = extra {
            r.headers_mut().insert(k, v.parse().unwrap());
        }
        r
    };
    serve(Router::new().route("/*any", get(handler))).await
}

#[tokio::test]
async fn node_answers_outside_the_contract_fail_closed() {
    let big: &'static str =
        Box::leak(format!("{{\"pad\":\"{}\"}}", "x".repeat(4096)).into_boxed_str());
    let digest: &'static str = Box::leak(
        format!("{{\"corpus_digest\":\"{}\",\"x\":1}}", "ab".repeat(32)).into_boxed_str(),
    );
    let cases = [
        (500, "{\"error\":\"boom\"}", None, S::BAD_GATEWAY),
        (401, "{\"error\":\"unauthorized\"}", None, S::BAD_GATEWAY),
        (
            403,
            "{\"error\":\"read_only_credential\"}",
            None,
            S::BAD_GATEWAY,
        ),
        (
            302,
            "",
            Some(("location", "http://127.0.0.1:9/elsewhere")),
            S::BAD_GATEWAY,
        ),
        (200, "not json", None, S::BAD_GATEWAY),
        (200, "[1,2]", None, S::BAD_GATEWAY),
        (200, big, None, S::BAD_GATEWAY),
        (503, "{\"error\":\"busy\"}", None, S::SERVICE_UNAVAILABLE),
        (418, digest, None, S::BAD_GATEWAY),
    ];
    for (status, body, extra, expected) in cases {
        let (base, server) = odd_node(status, body, extra).await;
        let cap = [("CC_GATEWAY_MAX_BODY_BYTES", "1024"), EAGER[0], EAGER[1]];
        let gw = gateway(&base, READ, &cap).await;
        let receipt = format!("/public/v1/receipts/{}", "ab".repeat(32));
        for path in ["/public/v1/health", "/public/v1/snapshot", &receipt] {
            let error = if expected == S::BAD_GATEWAY {
                "bad_gateway"
            } else {
                "node_unavailable"
            };
            assert_eq!(
                gw.get(path).await,
                refusal(expected, error),
                "{status} {path}"
            );
        }
        gw.stop().await;
        server.abort();
    }
    // The control: the same stand-in answering within the contract is served.
    let (base, server) = odd_node(200, digest, Some(("x-node-only", "1"))).await;
    let gw = gateway(&base, READ, &EAGER).await;
    let (status, headers, body) = gw
        .raw(Method::GET, "/public/v1/snapshot", &[], vec![])
        .await;
    assert_eq!(status, S::OK);
    assert!(headers.get("x-node-only").is_none());
    assert_eq!(
        serde_json::from_slice::<Json>(&body).unwrap(),
        serde_json::from_str::<Json>(digest).unwrap()
    );
    gw.stop().await;
    server.abort();
}

/// Answers the digest probe within the contract and every other read with the
/// given status and body.
async fn probe_only_node(status: u16, body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
    let digest = format!("{{\"corpus_digest\":\"{}\"}}", "ab".repeat(32));
    let probe = move || async move { (S::NOT_FOUND, digest) };
    let other = move || async move { (S::from_u16(status).unwrap(), body) };
    let app = Router::new()
        .route(cc_gateway::PROBE, get(probe))
        .route("/*any", get(other));
    serve(app).await
}

#[tokio::test]
async fn a_read_that_fails_after_a_good_probe_fails_closed() {
    let cases = [
        (401, "{\"error\":\"unauthorized\"}", S::BAD_GATEWAY),
        (500, "{\"error\":\"boom\"}", S::BAD_GATEWAY),
        (200, "not json", S::BAD_GATEWAY),
        (503, "{\"error\":\"busy\"}", S::SERVICE_UNAVAILABLE),
    ];
    for (status, body, expected) in cases {
        let (base, server) = probe_only_node(status, body).await;
        let gw = gateway(&base, READ, &EAGER).await;
        let error = if expected == S::BAD_GATEWAY {
            "bad_gateway"
        } else {
            "node_unavailable"
        };
        for path in ["/public/v1/snapshot", "/public/v1/support?from=a&to=b"] {
            assert_eq!(
                gw.get(path).await,
                refusal(expected, error),
                "{status} {path}"
            );
        }
        gw.stop().await;
        server.abort();
    }
    // The control: the same probe, and a read within the contract, is served.
    let answer = "{\"corpus_digest\":\"abababababababababababababababababababababababababababababababab\",\"n\":1}";
    let (base, server) = probe_only_node(200, answer).await;
    let gw = gateway(&base, READ, &EAGER).await;
    let (status, read) = gw.get("/public/v1/snapshot").await;
    assert_eq!((status, read["n"].clone()), (S::OK, json!(1)));
    gw.stop().await;
    server.abort();
}

#[tokio::test]
async fn requests_queued_behind_a_hung_probe_share_its_failure() {
    let probes = Arc::new(AtomicUsize::new(0));
    let counter = probes.clone();
    let hang = move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(6)).await;
            "{}"
        }
    };
    let (base, server) = serve(Router::new().route("/*any", get(hang))).await;
    let timeout = [
        ("CC_GATEWAY_UPSTREAM_TIMEOUT_MS", "1500"),
        EAGER[0],
        EAGER[1],
    ];
    let gw = gateway(&base, READ, &timeout).await;
    let snapshot = |base: &str| {
        let url = format!("{base}/public/v1/snapshot");
        tokio::spawn(async move {
            let r = http().get(url).send().await.unwrap();
            let status = r.status();
            let body = r.bytes().await.unwrap();
            (status, serde_json::from_slice::<Json>(&body).unwrap())
        })
    };
    let start = Instant::now();
    let mut waiters = vec![snapshot(&gw.base)];
    // Once the first probe is in flight, seven more requests queue behind it.
    while probes.load(Ordering::SeqCst) == 0 {
        assert!(start.elapsed() < Duration::from_secs(2), "no probe");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    waiters.extend((0..7).map(|_| snapshot(&gw.base)));
    for w in waiters {
        let answer = w.await.unwrap();
        assert_eq!(answer, refusal(S::SERVICE_UNAVAILABLE, "node_unavailable"));
    }
    // The first request's probe timed out; the seven that arrived while it ran
    // share one more probe rather than timing out one after another (which
    // would take eight timeouts, 12 s).
    assert_eq!(probes.load(Ordering::SeqCst), 2);
    assert!(
        start.elapsed() < Duration::from_millis(4_500),
        "{:?}",
        start.elapsed()
    );
    gw.stop().await;
    server.abort();
}

#[tokio::test]
async fn a_client_that_disconnects_cannot_cancel_the_probe() {
    let probes = Arc::new(AtomicUsize::new(0));
    let counter = probes.clone();
    let digest = format!("{{\"corpus_digest\":\"{}\"}}", "cd".repeat(32));
    let slow_probe = {
        let digest = digest.clone();
        move || {
            let (counter, digest) = (counter.clone(), digest.clone());
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(400)).await;
                (S::NOT_FOUND, digest)
            }
        }
    };
    let read = move || {
        let digest = digest.clone();
        async move { (S::OK, digest) }
    };
    let app = Router::new()
        .route(cc_gateway::PROBE, get(slow_probe))
        .route("/*any", get(read));
    let (base, server) = serve(app).await;
    let fresh = [("CC_GATEWAY_FRESHNESS_MS", "60000"), EAGER[0]];
    let gw = gateway(&base, READ, &fresh).await;
    // A client that gives up while the probe is in flight.
    let impatient = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let url = format!("{}/public/v1/snapshot", gw.base);
    assert!(impatient.get(&url).send().await.is_err());
    assert_eq!(probes.load(Ordering::SeqCst), 1);
    // The probe finishes anyway and its digest is recorded, so the next
    // request within the freshness window does not probe again.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let (status, cache, _) = gw.cached("/public/v1/snapshot").await;
    assert_eq!((status, cache.as_str()), (S::OK, "miss"));
    assert_eq!(probes.load(Ordering::SeqCst), 1);
    gw.stop().await;
    server.abort();
}

#[tokio::test]
async fn spoofed_client_ip_headers_are_ignored_without_a_configured_header() {
    let answer: &'static str =
        Box::leak(format!("{{\"corpus_digest\":\"{}\"}}", "ab".repeat(32)).into_boxed_str());
    let (base, server) = odd_node(200, answer, None).await;
    let limit = [("CC_GATEWAY_RATE_PER_MINUTE", "3")];
    let statuses = |gw: Gw, spoof: bool| async move {
        let mut seen = Vec::new();
        for i in 1..=6 {
            let ip = format!("192.0.2.{i}");
            let claims = [
                ("x-forwarded-for", ip.as_str()),
                ("fly-client-ip", ip.as_str()),
                ("x-client-ip", ip.as_str()),
                ("x-real-ip", ip.as_str()),
            ];
            let headers: &[(&str, &str)] = if spoof { &claims } else { &[] };
            seen.push(
                gw.raw(Method::GET, "/public/v1/health", headers, vec![])
                    .await
                    .0,
            );
        }
        gw.stop().await;
        seen
    };
    let limited = [S::OK, S::OK, S::OK]
        .into_iter()
        .chain([S::TOO_MANY_REQUESTS; 3])
        .collect::<Vec<_>>();
    // From one socket peer, unspoofed requests get the configured three.
    let plain = statuses(gateway(&base, READ, &limit).await, false).await;
    assert_eq!(plain, limited);
    // Claiming a different client on every request changes nothing, because
    // no client-IP header is configured: all six share the peer's bucket.
    let spoofed = statuses(gateway(&base, READ, &limit).await, true).await;
    assert_eq!(spoofed, limited);
    server.abort();
}

#[tokio::test]
async fn the_cache_key_separates_queries() {
    let rig = rig().await;
    let (g, b) = (prose_genesis(), subject(1, 50, 51));
    rig.admit(&g).await;
    rig.admit(&b).await;
    let fresh = [EAGER[0], ("CC_GATEWAY_FRESHNESS_MS", "60000")];
    let gw = gateway(&rig.node.base, READ, &fresh).await;
    let (gid, bid) = (hex::encode(g.id()), hex::encode(b.id()));
    let at = hex::encode([60; 32]);
    let pairs = [
        (
            format!("/public/v1/support?from={gid}&to={bid}"),
            format!("/public/v1/support?from={bid}&to={gid}"),
        ),
        (
            format!("/public/v1/subjects/{gid}?as_of={at}"),
            format!("/public/v1/subjects/{gid}"),
        ),
    ];
    for (first, second) in &pairs {
        let (status, cache, one) = gw.cached(first).await;
        assert_eq!((status, cache.as_str()), (S::OK, "miss"), "{first}");
        // Same route, same digest, different query: a different answer, read
        // from the node rather than served from the first one's entry.
        let (status, cache, two) = gw.cached(second).await;
        assert_eq!((status, cache.as_str()), (S::OK, "miss"), "{second}");
        assert_ne!(one, two, "{first} vs {second}");
        let private = second.trim_start_matches("/public");
        assert_eq!(two, rig.direct(private).await.1, "{second}");
        // Both are cached, each under its own query.
        assert_eq!(gw.cached(first).await, (S::OK, "hit".into(), one));
        assert_eq!(gw.cached(second).await, (S::OK, "hit".into(), two));
    }
    gw.stop().await;
    rig.done().await;
}

#[tokio::test]
async fn receipts_pass_through_with_and_without_a_node_seed() {
    // A synthetic node seed, never an operator key.
    let seed = || cc_core::SecretKey::from_seed([0x5e; 32]);
    let g = prose_genesis();
    let gid = hex::encode(g.id());
    let path = format!("/public/v1/receipts/{gid}");
    let private = path.trim_start_matches("/public").to_string();
    for seeded in [true, false] {
        let rig = if seeded {
            seeded_rig(seed()).await
        } else {
            rig().await
        };
        let gw = gateway(&rig.node.base, READ, &[EAGER[0]]).await;
        let none = refusal(S::NOT_FOUND, "no_receipt");
        assert_eq!(gw.get(&path).await, none, "seeded={seeded}");
        rig.submit(&g).await;

        let (status, node) = rig.direct(&private).await;
        let (served_status, headers, bytes) = gw.raw(Method::GET, &path, &[], vec![]).await;
        let served: Json = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            (served_status, &served),
            (status, &without_instance(node.clone()))
        );
        if seeded {
            assert_eq!(status, S::OK, "{served}");
            assert_eq!(served["event"], gid);
            let receipts = served["receipts"].as_array().unwrap();
            assert_eq!(receipts.len(), 1);
            let r = &receipts[0];
            assert_eq!(r["event"], gid);
            assert_eq!(r["node_key"], hex::encode(seed().author().to_bytes()));
            assert_eq!(r["initial_admission_result"]["state"], "valid");
            // The signed bytes come through intact and still verify; the
            // instance lives inside them, untouched.
            let wire = hex::decode(r["receipt"].as_str().unwrap()).unwrap();
            let signed = cc_core::v1::receipt::SignedReceipt::decode(&wire).unwrap();
            assert_eq!(signed.receipt().event, g.id());
            assert_eq!(signed.receipt().instance, INSTANCE);
        } else {
            // Without a seed the node keeps no receipt, even after admission.
            assert_eq!((status, node), none);
        }

        // Never cached and never probed: each read is exactly one node read.
        assert!(headers.get("x-cache").is_none());
        let before = rig.node.count();
        assert_eq!(gw.get(&path).await, (served_status, served.clone()));
        assert_eq!(gw.get(&path).await, (served_status, served));
        assert_eq!(
            rig.node.paths()[before..],
            [private.clone(), private.clone()]
        );

        // The node's own refusals pass through; writes never reach it.
        let bad_id = refusal(S::BAD_REQUEST, "invalid_event_id");
        assert_eq!(gw.get("/public/v1/receipts/zz").await, bad_id);
        assert_eq!(gw.get("/public/v1/receipts/%2E%2E%2Fexport").await, bad_id);
        let extra = format!("{path}?as_of={ZERO}");
        assert_eq!(
            gw.get(&extra).await,
            refusal(S::BAD_REQUEST, "invalid_query")
        );
        let reads = rig.node.count();
        for m in [Method::POST, Method::PUT, Method::DELETE] {
            let (status, _, _) = gw.raw(m.clone(), &path, &[], g.bytes().to_vec()).await;
            assert_eq!(status, S::METHOD_NOT_ALLOWED, "{m}");
        }
        assert_eq!(rig.node.count(), reads);
        gw.stop().await;
        rig.done().await;
    }
}
