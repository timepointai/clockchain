//! Online `cc-publisher v1` tests over real PostgreSQL. Synthetic keys and
//! data only.
//!
//! Until the v1 serving node (STAGE-F W1) merges, the node under test is the
//! test-only `cc_node::v1::review_router` for `POST /v1/candidates` and
//! revision prose, behind in-process contract routes for `GET /health`,
//! `PUT /v1/bodies/{sha256}` and `GET /v1/subjects/{id}`. All of them call the
//! same bound `cc_ledger::v1::Store`. A response-rewriting layer injects the
//! faults a misconfigured or lying node would show.
use axum::{
    body::{Body, Bytes},
    extract::{Path as UrlPath, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, put},
    Json, Router,
};
use cc_core::v1::{hash, Hash};
use cc_core::SecretKey;
use cc_ledger::v1::{State as Admission, Store};
use cc_node::config::KeyDigest;
use cc_publisher::v1::genesis::{self, Genesis, GenesisInput};
use cc_publisher::v1::node::{self, Node, RECEIPT_FILE};
use cc_publisher::v1::{hash_json, key, time};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

const WRITE: &str = "synthetic-write";
const READ: &str = "synthetic-read";
const INSTANCE: Hash = [9; 32];

/// Faults injected into responses, as a misconfigured or lying node.
#[derive(Clone, Default)]
struct Faults {
    /// `/health` reports a fold manifest with one bit flipped.
    fold: bool,
    /// `/health` reports the frozen posture.
    frozen: bool,
    /// Served prose has one byte changed.
    prose: bool,
    /// An unknown subject is a 404 rather than `visibility: subject_unknown`.
    unknown_404: bool,
}

#[derive(Clone)]
struct Contract {
    store: Store,
    curators: Vec<Hash>,
    max_hops: u16,
    instance: Hash,
    faults: Arc<Mutex<Faults>>,
}

struct TestNode {
    url: String,
    store: Store,
    pool: sqlx::PgPool,
    faults: Arc<Mutex<Faults>>,
    cleanup: cc_testkit::Cleanup,
}
impl TestNode {
    async fn start(instance: Hash, mut curators: Vec<Hash>) -> Self {
        curators.sort();
        let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
        let filter = cc_filter::v1::FilterIdentity::governed(curators.clone(), 4).unwrap();
        let store = Store::provision(pool.clone(), instance)
            .await
            .unwrap()
            .bind(filter)
            .await
            .unwrap();
        let faults = Arc::new(Mutex::new(Faults::default()));
        let contract = Contract {
            store: store.clone(),
            curators,
            max_hops: 4,
            instance,
            faults: faults.clone(),
        };
        let review =
            cc_node::v1::review_router(store.clone(), KeyDigest::of(WRITE), KeyDigest::of(READ));
        let app = Router::new()
            .route("/health", get(health))
            .route("/v1/bodies/:sha", put(put_body))
            .route("/v1/subjects/:id", get(subject))
            .with_state(contract)
            .fallback_service(review)
            .layer(middleware::from_fn_with_state(faults.clone(), inject));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            url,
            store,
            pool,
            faults,
            cleanup,
        }
    }
    fn fault(&self, f: impl FnOnce(&mut Faults)) {
        f(&mut self.faults.lock().unwrap());
    }
    fn client(&self, token: &str) -> Node {
        Node::new(&self.url, Some(token)).unwrap()
    }
    /// Retained candidates, retained rejections and whether `body` is stored.
    async fn writes(&self, body: &[u8]) -> (usize, i64, bool) {
        let rejections: i64 = sqlx::query_scalar("SELECT count(*) FROM cc_v1.rejections")
            .fetch_one(&self.pool)
            .await
            .unwrap();
        (
            self.store.review().await.unwrap().len(),
            rejections,
            self.store.body_bytes(hash(body)).await.unwrap().is_some(),
        )
    }
}

fn authorized(headers: &axum::http::HeaderMap, write: bool) -> bool {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    token.is_some_and(|t| {
        KeyDigest::of(WRITE).matches(t) || (!write && KeyDigest::of(READ).matches(t))
    })
}
async fn health(State(c): State<Contract>) -> Json<Value> {
    let r = c.store.semantic_readiness().await.unwrap();
    let rule = cc_filter::v1::FilterIdentity::governed(c.curators.clone(), c.max_hops).unwrap();
    Json(json!({
        "ledger": "v1",
        "build": "synthetic-test",
        "posture": "live",
        "instance": hex::encode(c.instance),
        "fold_version": {"version": rule.fold.version, "manifest": hex::encode(rule.fold.manifest)},
        "filter_version": hex::encode(rule.version()),
        "curators": c.curators.iter().map(hex::encode).collect::<Vec<_>>(),
        "max_hops": c.max_hops,
        "semantic": r.semantic,
    }))
}
async fn put_body(
    State(c): State<Contract>,
    headers: axum::http::HeaderMap,
    UrlPath(sha): UrlPath<String>,
    body: Bytes,
) -> Response {
    if !authorized(&headers, true) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(expected) = cc_publisher::v1::hex32(&sha) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let existed = c.store.body_bytes(expected).await.unwrap().is_some();
    match c.store.retain_body(expected, &body).await {
        Ok(()) if existed => StatusCode::OK.into_response(),
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(_) => (StatusCode::UNPROCESSABLE_ENTITY, "body_hash_mismatch").into_response(),
    }
}
async fn subject(
    State(c): State<Contract>,
    headers: axum::http::HeaderMap,
    UrlPath(id): UrlPath<String>,
) -> Response {
    if !authorized(&headers, false) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(id) = cc_publisher::v1::hex32(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let snapshot = c.store.snapshot(None).await.unwrap();
    let read = snapshot.entity(id, None);
    if read.visibility == "subject_unknown" && c.faults.lock().unwrap().unknown_404 {
        return StatusCode::NOT_FOUND.into_response();
    }
    // `EntityRead` serializes hashes as integer arrays; the client accepts both.
    let mut v = serde_json::to_value(&read).unwrap();
    v["commitment"] = json!(hex::encode(snapshot.commitment));
    Json(v).into_response()
}
/// Rewrite responses according to the active faults.
async fn inject(State(faults): State<Arc<Mutex<Faults>>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let response = next.run(req).await;
    let f = faults.lock().unwrap().clone();
    let health = path == "/health" && (f.fold || f.frozen);
    let prose = path.ends_with("/prose") && f.prose;
    if !health && !prose {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let mut v: Value = serde_json::from_slice(&bytes).unwrap();
    if health && f.fold {
        let mut m = hash_json(&v["fold_version"]["manifest"]).unwrap();
        m[31] ^= 1;
        v["fold_version"]["manifest"] = json!(hex::encode(m));
    }
    if health && f.frozen {
        v["posture"] = json!("frozen");
    }
    if prose {
        let mut text = v["prose"].as_str().unwrap().to_owned();
        let last = text.pop().unwrap();
        text.push(if last == 'X' { 'Y' } else { 'X' });
        v["prose"] = json!(text);
    }
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(serde_json::to_vec(&v).unwrap()))
}

/// A synthetic curator key written by the real `keygen` path.
fn curator(dir: &Path) -> (std::path::PathBuf, SecretKey) {
    let path = dir.join("curator.seed");
    key::keygen(&path).unwrap();
    let k = key::load_key(&path).unwrap();
    (path, k)
}
fn signed_genesis(k: &SecretKey, instance: Hash, value: &str, out: &Path) -> Genesis {
    let g = genesis::build(
        k,
        GenesisInput {
            instance,
            kind: "scientific-discovery".into(),
            namespace: "synthetic.publisher".into(),
            value: value.into(),
            body: format!("Synthetic online body for {value}.\nSecond line.\n").into_bytes(),
            asserted_time: time::parse("1901-02-03").unwrap(),
            evidence: vec![[0xaa; 32]],
            nonce: key::os_random().unwrap(),
        },
    )
    .unwrap();
    g.write_dir(out).unwrap();
    g
}
fn publisher() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cc-publisher"));
    c.env_remove("CC_NODE_API_KEY")
        .env_remove("CC_NODE_READ_KEY")
        .env_remove("RUST_BACKTRACE");
    c
}
fn error_text(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_admits_reads_back_and_rerun_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let author = k.author().to_bytes();
    let other = SecretKey::from_seed([0x31; 32]).author().to_bytes();
    let n = TestNode::start(INSTANCE, vec![author, other]).await;
    let dir = tmp.path().join("entry");
    let g = signed_genesis(&k, INSTANCE, "online-1", &dir);
    assert_eq!(n.writes(&g.body).await, (0, 0, false));

    // First run through the binary: the token comes from the environment.
    let out = publisher()
        .args(["v1", "submit", "--node", &n.url, "--dir"])
        .arg(&dir)
        .env("CC_NODE_API_KEY", WRITE)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stored = std::fs::read(dir.join(RECEIPT_FILE)).unwrap();
    let receipt: Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(
        receipt,
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    );
    assert_eq!(receipt["event"], json!(hex::encode(g.id())));
    assert_eq!(receipt["subject"], json!(hex::encode(g.subject())));
    assert_eq!(receipt["revision"], json!(hex::encode(g.revision())));
    assert_eq!(
        receipt["body"],
        json!({"http_status": 201, "result": "stored"})
    );
    assert_eq!(receipt["admission"]["result"], "admitted");
    assert_eq!(receipt["admission"]["http_status"], 201);
    assert_eq!(receipt["admission"]["outcome"]["state"], "valid");
    assert_eq!(
        receipt["trust"],
        json!({"instance_matches": true, "fold_matches": true, "author_is_curator": true,
               "filter_version_consistent": true, "allow_untrusted": false})
    );
    assert_eq!(receipt["readback"]["prose_equals_body_bin"], true);
    assert_eq!(receipt["readback"]["prose_bytes"], g.body.len());
    assert_eq!(receipt["readback"]["asserted_time"], "1901-02-03");
    let snapshot = n.store.snapshot(None).await.unwrap();
    assert_eq!(
        receipt["readback"]["commitment"],
        json!(hex::encode(snapshot.commitment))
    );

    // The node holds exactly this envelope, valid, and these body bytes.
    let review = n.store.review().await.unwrap();
    assert_eq!(review.len(), 1);
    assert_eq!(review[&g.id()].state, Admission::Valid);
    assert_eq!(
        n.store.body_bytes(hash(&g.body)).await.unwrap(),
        Some(g.body.clone())
    );

    // Rerun: reported as existing, never re-posted, receipt left unchanged.
    let again = node::submit(&n.client(WRITE), &dir, false).await.unwrap();
    assert!(!again.receipt_written);
    assert_eq!(
        again.receipt["body"],
        json!({"http_status": 200, "result": "already_present"})
    );
    assert_eq!(
        again.receipt["admission"],
        json!({"result": "already_admitted", "http_status": null, "outcome": null})
    );
    assert_eq!(n.writes(&g.body).await, (1, 0, true));
    assert_eq!(std::fs::read(dir.join(RECEIPT_FILE)).unwrap(), stored);

    // Read-only verification, with and without the local directory.
    let (ok, report) = node::verify(&n.client(READ), g.subject(), Some(&dir))
        .await
        .unwrap();
    assert!(ok, "{report}");
    assert_eq!(report["prose"]["matches_revision_body"], true);
    let out = publisher()
        .args(["v1", "verify", "--node", &n.url, "--subject"])
        .arg(hex::encode(g.subject()))
        .env("CC_NODE_READ_KEY", READ)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_refuses_instance_mismatch_before_any_write() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let n = TestNode::start([8; 32], vec![k.author().to_bytes()]).await;
    let dir = tmp.path().join("entry");
    let g = signed_genesis(&k, INSTANCE, "online-instance", &dir);
    let e = error_text(
        node::submit(&n.client(WRITE), &dir, false)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("instance mismatch"), "{e}");
    assert!(e.contains("nothing was written"), "{e}");
    assert_eq!(n.writes(&g.body).await, (0, 0, false));
    assert!(!dir.join(RECEIPT_FILE).exists());

    // Overridden, the node itself rejects the foreign instance after the
    // body PUT: the check above is what kept the node untouched.
    let e = error_text(
        node::submit(&n.client(WRITE), &dir, true)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("wrong_instance"), "{e}");
    assert_eq!(n.writes(&g.body).await, (0, 1, true));
    assert!(!dir.join(RECEIPT_FILE).exists());
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_refuses_curator_mismatch_before_any_write() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let stranger = SecretKey::from_seed([0x32; 32]).author().to_bytes();
    let n = TestNode::start(INSTANCE, vec![stranger]).await;
    n.fault(|f| f.unknown_404 = true);
    let dir = tmp.path().join("entry");
    let g = signed_genesis(&k, INSTANCE, "online-curator", &dir);
    let e = error_text(
        node::submit(&n.client(WRITE), &dir, false)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("is not in the node's curator set"), "{e}");
    assert_eq!(n.writes(&g.body).await, (0, 0, false));

    // Overridden: admitted (Genesis validity does not depend on curators),
    // and the receipt records the failed check and the override.
    let done = node::submit(&n.client(WRITE), &dir, true).await.unwrap();
    assert_eq!(done.warnings.len(), 1, "{:?}", done.warnings);
    assert_eq!(done.receipt["trust"]["author_is_curator"], false);
    assert_eq!(done.receipt["trust"]["allow_untrusted"], true);
    assert_eq!(done.receipt["admission"]["result"], "admitted");
    assert_eq!(n.writes(&g.body).await, (1, 0, true));
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fold_mismatch_is_refused_by_submit_and_node_info() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let n = TestNode::start(INSTANCE, vec![k.author().to_bytes()]).await;
    let dir = tmp.path().join("entry");
    let g = signed_genesis(&k, INSTANCE, "online-fold", &dir);

    let out = publisher()
        .args(["v1", "node-info", "--node", &n.url])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let info: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(info["fold_matches_build"], true);
    assert_eq!(info["health"]["instance"], json!(hex::encode(INSTANCE)));
    assert_eq!(info["health"]["max_hops"], 4);
    assert_eq!(
        info["health"]["curators"],
        json!([hex::encode(k.author().to_bytes())])
    );

    n.fault(|f| f.fold = true);
    let out = publisher()
        .args(["v1", "node-info", "--node", &n.url])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let info: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(info["fold_matches_build"], false);
    let e = error_text(
        node::submit(&n.client(WRITE), &dir, false)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("fold_version mismatch"), "{e}");
    assert_eq!(n.writes(&g.body).await, (0, 0, false));
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readback_detects_tampered_prose() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let n = TestNode::start(INSTANCE, vec![k.author().to_bytes()]).await;
    let dir = tmp.path().join("entry");
    let g = signed_genesis(&k, INSTANCE, "online-tamper", &dir);
    n.fault(|f| f.prose = true);
    let e = error_text(
        node::submit(&n.client(WRITE), &dir, false)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("differs from body.bin"), "{e}");
    assert!(!dir.join(RECEIPT_FILE).exists());
    let (ok, report) = node::verify(&n.client(READ), g.subject(), Some(&dir))
        .await
        .unwrap();
    assert!(!ok);
    assert!(
        report["failures"]
            .to_string()
            .contains("served prose does not hash to the revision body"),
        "{report}"
    );

    // An honest readback completes the receipt without re-posting.
    n.fault(|f| f.prose = false);
    let done = node::submit(&n.client(WRITE), &dir, false).await.unwrap();
    assert!(done.receipt_written);
    assert_eq!(done.receipt["admission"]["result"], "already_admitted");
    assert_eq!(n.writes(&g.body).await, (1, 0, true));
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_needs_the_env_token_and_a_writable_node() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let n = TestNode::start(INSTANCE, vec![k.author().to_bytes()]).await;
    let dir = tmp.path().join("entry");
    let g = signed_genesis(&k, INSTANCE, "online-token", &dir);

    let out = publisher()
        .args(["v1", "submit", "--node", &n.url, "--dir"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("CC_NODE_API_KEY must be set"));
    let e = error_text(
        node::submit(&n.client(READ), &dir, false)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("401"), "{e}");
    n.fault(|f| f.frozen = true);
    let e = error_text(
        node::submit(&n.client(WRITE), &dir, true)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("posture is frozen"), "{e}");
    assert_eq!(n.writes(&g.body).await, (0, 0, false));
    n.cleanup.cleanup().await;
}

#[test]
fn node_url_rules() {
    for ok in [
        "https://node.example",
        "https://node.example/prefix",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "http://localhost:8080",
        "http://cc-accept-v1-0123456789ab-app:8080",
    ] {
        assert!(Node::new(ok, Some("t")).is_ok(), "{ok}");
    }
    for (bad, why) in [
        ("http://node.example", "plain http"),
        ("http://10.0.0.8:8080", "plain http"),
        ("http://[2001:db8::1]:8080", "plain http"),
        ("ftp://node.example", "scheme"),
        ("https://user:pw@node.example", "credentials"),
        ("https://node.example/?q=1", "query"),
        ("https://node.example/#f", "fragment"),
        ("node.example", "invalid node URL"),
    ] {
        let e = Node::new(bad, Some("t")).err().map(error_text).unwrap();
        assert!(e.contains(why), "{bad}: {e}");
    }
    let e = Node::new("https://node.example", Some(" "))
        .err()
        .map(error_text);
    assert!(e.unwrap().contains("token is empty"));
}
