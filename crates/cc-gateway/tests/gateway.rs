//! The served gateway (`cc_gateway::router`) on a real socket, in front of the
//! served v1 node (`cc_node::serve_v1::router`) on a real socket over a real
//! PostgreSQL store. The node is wrapped in a recording layer, so every claim
//! about what did or did not reach it is read from the node side.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

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
use cc_node::serve_v1::{self, health_body, V1State};
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

async fn record(State(seen): State<Seen>, req: Request, next: Next) -> Response {
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

async fn boot_node(store: &Store) -> Node {
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
    let seen = Seen::default();
    let app =
        serve_v1::router(state).layer(axum::middleware::from_fn_with_state(seen.clone(), record));
    let (base, server) = serve(app).await;
    Node { base, seen, server }
}

struct Rig {
    pool: sqlx::PgPool,
    cleanup: cc_testkit::Cleanup,
    store: Store,
    node: Node,
}

async fn rig() -> Rig {
    logs();
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let fresh = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    fresh.bind(filter()).await.unwrap();
    let store = Store::open(pool.clone(), INSTANCE, filter()).await.unwrap();
    let node = boot_node(&store).await;
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
    // Receipts are not served until the node serves them (Stage (g) G4).
    let receipt = gw.get(&format!("/public/v1/receipts/{gid}")).await;
    assert_eq!(receipt, refusal(S::NOT_FOUND, "no_such_route"));
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
    // The default is 60 a minute.
    let gw = gateway(&rig.node.base, READ, &[]).await;
    for i in 0..60 {
        assert_eq!(gw.get("/public/v1/health").await.0, S::OK, "request {i}");
    }
    let (status, headers, body) = gw.raw(Method::GET, "/public/v1/health", &[], vec![]).await;
    assert_eq!(status, S::TOO_MANY_REQUESTS);
    assert_eq!(headers["retry-after"], "1");
    assert_eq!(
        serde_json::from_slice::<Json>(&body).unwrap(),
        json!({"error": "rate_limited"})
    );
    assert_eq!(rig.node.count(), 60);
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
    assert_eq!(rig.node.count(), 60 + 5);
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
        for path in ["/public/v1/health", "/public/v1/snapshot"] {
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
