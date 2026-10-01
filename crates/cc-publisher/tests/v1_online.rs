//! Online `cc-publisher v1` tests over real PostgreSQL. Synthetic keys and
//! data only.
//!
//! The node under test is the real v1 serving router (`cc_node::serve_v1`),
//! booted in-process the way `cc-node serve` boots it: a provisioned and bound
//! store, reopened and verified with `Store::open`. A response-rewriting layer
//! in front of it makes the node answer as a misconfigured or lying node would,
//! which the real node cannot be configured to do.
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    Router,
};
use cc_core::v1::{hash, Hash};
use cc_core::SecretKey;
use cc_ledger::v1::{ProjectionState, Store};
use cc_node::config::{KeyDigest, Posture, V1Config};
use cc_node::serve_v1::{self, V1State};
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

/// One response rewrite: status, headers and JSON body.
type Rewrite = Arc<dyn Fn(&mut StatusCode, &mut HeaderMap, &mut Value) + Send + Sync>;
/// Active rewrites, each applied to responses whose path contains its key.
type Rewrites = Arc<Mutex<Vec<(String, Rewrite)>>>;

struct TestNode {
    url: String,
    store: Store,
    pool: sqlx::PgPool,
    rewrites: Rewrites,
    cleanup: cc_testkit::Cleanup,
}
impl TestNode {
    async fn start(instance: Hash, curators: Vec<Hash>) -> Self {
        Self::boot(instance, curators, Posture::Live).await
    }
    async fn boot(instance: Hash, mut curators: Vec<Hash>, posture: Posture) -> Self {
        curators.sort();
        let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
        let filter = cc_filter::v1::FilterIdentity::governed(curators, 4).unwrap();
        // What `cc-node provision-v1` does, then what `cc-node serve` does.
        Store::provision(pool.clone(), instance)
            .await
            .unwrap()
            .bind(filter.clone())
            .await
            .unwrap();
        let store = Store::open(pool.clone(), instance, filter.clone())
            .await
            .unwrap();
        let readiness = store.semantic_readiness().await.unwrap();
        assert!(readiness.serving, "{readiness:?}");
        let v1 = V1Config {
            database_url: String::new(),
            instance,
            filter,
        };
        let state = V1State {
            store: store.clone(),
            posture,
            health_body: serve_v1::health_body(&v1, posture, &readiness.semantic),
            ready_gate: Default::default(),
            api_key: KeyDigest::of(WRITE),
            read_key: Some(KeyDigest::of(READ)),
            gallery_key: None,
            beta_key: None,
            telemetry_key: None,
        };
        let rewrites = Rewrites::default();
        let app =
            serve_v1::router(state).layer(middleware::from_fn_with_state(rewrites.clone(), inject));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            url,
            store,
            pool,
            rewrites,
            cleanup,
        }
    }
    /// Rewrite every later response whose path contains `key`.
    fn rewrite(
        &self,
        key: &str,
        f: impl Fn(&mut StatusCode, &mut HeaderMap, &mut Value) + Send + Sync + 'static,
    ) {
        self.rewrites
            .lock()
            .unwrap()
            .push((key.to_owned(), Arc::new(f)));
    }
    /// Answer honestly again.
    fn honest(&self) {
        self.rewrites.lock().unwrap().clear();
    }
    fn client(&self, token: &str) -> Node {
        Node::new(&self.url, Some(token)).unwrap()
    }
    async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM cc_v1.{table}"))
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    /// Retained candidates, retained rejections and whether `body` is stored.
    async fn writes(&self, body: &[u8]) -> (i64, i64, bool) {
        (
            self.count("candidates").await,
            self.count("rejections").await,
            self.store.body_bytes(hash(body)).await.unwrap().is_some(),
        )
    }
}

/// Apply the active rewrites to a response.
async fn inject(State(rewrites): State<Rewrites>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let active: Vec<Rewrite> = rewrites
        .lock()
        .unwrap()
        .iter()
        .filter(|(key, _)| path.contains(key.as_str()))
        .map(|(_, f)| f.clone())
        .collect();
    let response = next.run(req).await;
    if active.is_empty() {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let mut v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    for f in &active {
        f(&mut parts.status, &mut parts.headers, &mut v);
    }
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(serde_json::to_vec(&v).unwrap()))
}
/// The same 32-byte value with one bit changed, in the same JSON encoding.
fn flipped(v: &Value) -> Value {
    let mut h = hash_json(v).expect("a 32-byte JSON value");
    h[31] ^= 1;
    match v {
        Value::String(_) => json!(hex::encode(h)),
        _ => json!(h.to_vec()),
    }
}
/// Served prose with its last character changed.
fn tampered_prose(_: &mut StatusCode, _: &mut HeaderMap, v: &mut Value) {
    let mut text = v["prose"].as_str().unwrap().to_owned();
    let last = text.pop().unwrap();
    text.push(if last == 'X' { 'Y' } else { 'X' });
    v["prose"] = json!(text);
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
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("body      stored (HTTP 201)"), "{stderr}");
    assert!(
        stderr.contains("envelope  admitted as valid (HTTP 201)"),
        "{stderr}"
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
               "filter_version_consistent": true, "allow_untrusted": false, "overridden": []})
    );
    assert_eq!(receipt["readback"]["prose_equals_body_bin"], true);
    assert_eq!(receipt["readback"]["prose_bytes"], g.body.len());
    assert_eq!(receipt["readback"]["asserted_time"], "1901-02-03");
    let snapshot = n.store.snapshot(None).await.unwrap();
    assert_eq!(
        receipt["readback"]["commitment"],
        json!(hex::encode(snapshot.commitment))
    );

    // The node holds exactly this envelope, as the subject's head, and these
    // body bytes.
    assert_eq!(n.writes(&g.body).await, (1, 0, true));
    assert_eq!(snapshot.projection.rows.len(), 1);
    let row = &snapshot.projection.rows[0];
    assert_eq!(row.event, g.id());
    assert_eq!(row.state, ProjectionState::Head);
    assert_eq!(row.revision, Some(g.revision()));
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
    let lines = node::summary(&again, &dir).join("\n");
    assert!(
        lines.contains("body      already present on the node (HTTP 200)"),
        "{lines}"
    );
    assert!(
        lines.contains("envelope  already admitted; not re-posted"),
        "{lines}"
    );
    assert!(lines.contains("already exists; left unchanged"), "{lines}");

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
    let overridden = done.receipt["trust"]["overridden"].to_string();
    assert!(
        overridden.contains("is not in the node's curator set"),
        "{overridden}"
    );
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

    n.rewrite("/health", |_, _, v| {
        v["fold_version"]["manifest"] = flipped(&v["fold_version"]["manifest"])
    });
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
    n.rewrite("/prose", tampered_prose);
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
    n.honest();
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
    // An unknown token is refused at the first authenticated read, the read
    // key at the first write.
    let e = error_text(
        node::submit(&n.client("not-a-node-token"), &dir, false)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("401"), "{e}");
    let e = error_text(
        node::submit(&n.client(READ), &dir, false)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("403"), "{e}");
    assert_eq!(n.writes(&g.body).await, (0, 0, false));
    n.cleanup.cleanup().await;

    // A really frozen node is refused before any write, even overridden.
    let frozen = TestNode::boot(INSTANCE, vec![k.author().to_bytes()], Posture::Frozen).await;
    let e = error_text(
        node::submit(&frozen.client(WRITE), &dir, true)
            .await
            .err()
            .unwrap(),
    );
    assert!(e.contains("posture is frozen"), "{e}");
    assert_eq!(frozen.writes(&g.body).await, (0, 0, false));
    frozen.cleanup.cleanup().await;
}

/// Node states in which nothing is written whatever the flags, and the filter
/// consistency check, which only `--allow-untrusted` overrides.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_claims_are_refused_before_any_write() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let n = TestNode::start(INSTANCE, vec![k.author().to_bytes()]).await;
    let dir = tmp.path().join("entry");
    let g = signed_genesis(&k, INSTANCE, "online-health", &dir);
    type Claim = fn(&mut StatusCode, &mut HeaderMap, &mut Value);
    let hard: [(Claim, &str); 3] = [
        (
            |_, _, v| v["ledger"] = json!("v0"),
            r#"node reports ledger "v0", not "v1""#,
        ),
        (
            |_, _, v| v["semantic"] = json!("rule_identity_unbound"),
            r#"node semantic readiness is "rule_identity_unbound", not "ready""#,
        ),
        (
            |_, _, v| v["posture"] = json!("frozen"),
            "node posture is frozen; it refuses writes",
        ),
    ];
    for (claim, needle) in hard {
        n.rewrite("/health", claim);
        for allow in [false, true] {
            let e = error_text(
                node::submit(&n.client(WRITE), &dir, allow)
                    .await
                    .err()
                    .unwrap(),
            );
            assert!(e.contains(needle), "{e}");
        }
        n.honest();
    }
    n.rewrite("/health", |_, _, v| {
        v["filter_version"] = flipped(&v["filter_version"])
    });
    let e = error_text(
        node::submit(&n.client(WRITE), &dir, false)
            .await
            .err()
            .unwrap(),
    );
    assert!(
        e.contains("is not this build's governed identity for its curators and max_hops"),
        "{e}"
    );
    assert!(e.contains("nothing was written"), "{e}");
    assert_eq!(n.writes(&g.body).await, (0, 0, false));
    assert!(!dir.join(RECEIPT_FILE).exists());
    n.cleanup.cleanup().await;
}

/// The admission answer must be HTTP 201, state valid, for this event and
/// these exact bytes; anything else fails without a receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_must_be_201_valid_for_this_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let n = TestNode::start(INSTANCE, vec![k.author().to_bytes()]).await;
    type Answer = fn(&mut StatusCode, &mut HeaderMap, &mut Value);
    let answers: [(&str, Answer, &str); 4] = [
        (
            "accepted",
            |status, _, _| *status = StatusCode::ACCEPTED,
            "node did not admit the envelope as valid: HTTP 202",
        ),
        (
            "pending",
            |_, _, v| v["status"]["state"] = json!("pending"),
            r#"state "pending""#,
        ),
        (
            "event",
            |_, _, v| v["event"] = flipped(&v["event"]),
            "node acknowledged a different envelope",
        ),
        (
            "digest",
            |_, _, v| v["input_digest"] = flipped(&v["input_digest"]),
            "node acknowledged a different envelope",
        ),
    ];
    for (case, answer, needle) in answers {
        // A fresh envelope per case: each POST really admits it.
        let dir = tmp.path().join(case);
        signed_genesis(&k, INSTANCE, &format!("online-admission-{case}"), &dir);
        n.rewrite("/v1/candidates", answer);
        let e = error_text(
            node::submit(&n.client(WRITE), &dir, false)
                .await
                .err()
                .unwrap(),
        );
        assert!(e.contains(needle), "{case}: {e}");
        assert!(!dir.join(RECEIPT_FILE).exists(), "{case}");
        n.honest();
    }
    n.cleanup.cleanup().await;
}

/// The read-back must name exactly this subject, revision, event, body hash
/// and asserted time, and serve this revision's bytes; `verify --dir` reports
/// a node that differs from the reviewed directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readback_requires_this_revision_and_these_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let n = TestNode::start(INSTANCE, vec![k.author().to_bytes()]).await;
    let dir = tmp.path().join("entry");
    let g = signed_genesis(&k, INSTANCE, "online-readback", &dir);
    type Lie = fn(&mut StatusCode, &mut HeaderMap, &mut Value);
    let lies: [(&str, Lie, &str); 11] = [
        (
            "/v1/subjects/",
            |_, _, v| v["subject"] = flipped(&v["subject"]),
            "readback: node answered for another subject",
        ),
        (
            "/v1/subjects/",
            |_, _, v| v["state"] = json!("contested"),
            "not resolved/visible",
        ),
        (
            "/v1/subjects/",
            |_, _, v| v["visibility"] = json!("after_as_of"),
            "not resolved/visible",
        ),
        (
            "/v1/subjects/",
            |_, _, v| v["revision"] = Value::Null,
            "readback: subject has no current revision",
        ),
        (
            "/v1/subjects/",
            |_, _, v| v["revision"]["id"] = flipped(&v["revision"]["id"]),
            "readback: current revision is",
        ),
        (
            "/v1/subjects/",
            |_, _, v| v["revision"]["creating_event"] = flipped(&v["revision"]["creating_event"]),
            "does not bind this event and body hash",
        ),
        (
            "/v1/subjects/",
            |_, _, v| v["revision"]["body"] = flipped(&v["revision"]["body"]),
            "does not bind this event and body hash",
        ),
        (
            "/v1/subjects/",
            |_, _, v| v["revision"]["subject"] = flipped(&v["revision"]["subject"]),
            "does not bind this event and body hash",
        ),
        (
            "/v1/subjects/",
            |_, _, v| v["revision"]["asserted_time"]["precision"] = json!("year"),
            "readback: revision asserted time differs from the envelope",
        ),
        (
            "/prose",
            |_, _, v| v["revision"]["id"] = flipped(&v["revision"]["id"]),
            "readback: prose answered for another revision",
        ),
        (
            "/prose",
            |_, _, v| v["availability"] = json!("unavailable"),
            r#"readback: prose availability is Some("unavailable")"#,
        ),
    ];
    for (route, lie, needle) in lies {
        n.rewrite(route, lie);
        let e = error_text(
            node::submit(&n.client(WRITE), &dir, false)
                .await
                .err()
                .unwrap(),
        );
        assert!(e.contains(needle), "{needle}: {e}");
        assert!(!dir.join(RECEIPT_FILE).exists(), "{needle}");
        n.honest();
    }
    // Honest again: the receipt is completed without re-posting.
    let done = node::submit(&n.client(WRITE), &dir, false).await.unwrap();
    assert!(done.receipt_written);
    assert_eq!(done.receipt["admission"]["result"], "already_admitted");
    assert_eq!(n.writes(&g.body).await, (1, 0, true));

    // verify --dir names each way the node differs from the directory.
    type Differ = (&'static str, Lie, &'static str);
    let differ: [Differ; 3] = [
        (
            "/health",
            |_, _, v| v["instance"] = flipped(&v["instance"]),
            "node instance differs from the --dir envelope",
        ),
        (
            "/health",
            |_, _, v| v["curators"] = json!([hex::encode([0x77; 32])]),
            "--dir author is not in the node's curator set",
        ),
        (
            "/prose",
            tampered_prose,
            "node does not serve the --dir Genesis revision with body.bin's exact bytes",
        ),
    ];
    let (ok, report) = node::verify(&n.client(READ), g.subject(), Some(&dir))
        .await
        .unwrap();
    assert!(ok, "{report}");
    for (route, lie, needle) in differ {
        n.rewrite(route, lie);
        let (ok, report) = node::verify(&n.client(READ), g.subject(), Some(&dir))
            .await
            .unwrap();
        assert!(!ok);
        assert!(
            report["failures"].to_string().contains(needle),
            "{needle}: {report}"
        );
        n.honest();
    }
    n.cleanup.cleanup().await;
}

/// Records every request and answers HTTP 500 echoing its Authorization header.
async fn echo_server() -> (String, Arc<Mutex<Vec<(String, Option<String>)>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let app = Router::new().fallback(move |req: Request| {
        let log = log.clone();
        async move {
            let auth = req
                .headers()
                .get(header::AUTHORIZATION)
                .map(|v| v.to_str().unwrap().to_owned());
            log.lock()
                .unwrap()
                .push((req.uri().path().to_owned(), auth.clone()));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("echo: {}", auth.unwrap_or_else(|| "none".into())),
            )
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, seen)
}

/// The token goes only to authenticated routes, never appears in an error,
/// and is never replayed to a redirect target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_stays_on_authenticated_routes_and_redirects_are_refused() {
    let (echo, seen) = echo_server().await;
    let token = "synthetic-token-must-not-print";
    let c = Node::new(&echo, Some(token)).unwrap();
    let e = error_text(c.health().await.err().unwrap());
    assert!(e.contains("HTTP 500") && e.contains("echo: none"), "{e}");
    let e = error_text(c.subject([7; 32]).await.err().unwrap());
    assert!(e.contains("echo: Bearer <redacted>"), "{e}");
    assert!(!e.contains(token), "{e}");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            ("/health".to_owned(), None),
            (
                format!("/v1/subjects/{}", hex::encode([7; 32])),
                Some(format!("Bearer {token}"))
            ),
        ]
    );

    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let n = TestNode::start(INSTANCE, vec![k.author().to_bytes()]).await;
    let target = format!("{echo}/health");
    n.rewrite("/health", move |status, headers, _| {
        *status = StatusCode::FOUND;
        headers.insert(header::LOCATION, target.parse().unwrap());
    });
    let e = error_text(n.client(WRITE).health().await.err().unwrap());
    assert!(e.contains("GET /health: HTTP 302"), "{e}");
    assert_eq!(seen.lock().unwrap().len(), 2, "the redirect was followed");
    n.cleanup.cleanup().await;
}

/// Plain http goes direct even when every proxy variable names a proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_ignores_proxy_variables() {
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let connections = Arc::new(Mutex::new(0usize));
    let counted = connections.clone();
    tokio::spawn(async move {
        // Accept and drop: a request routed here fails at once.
        while let Ok((socket, _)) = proxy.accept().await {
            *counted.lock().unwrap() += 1;
            drop(socket);
        }
    });
    let tmp = tempfile::tempdir().unwrap();
    let (_, k) = curator(tmp.path());
    let n = TestNode::start(INSTANCE, vec![k.author().to_bytes()]).await;
    let mut cmd = publisher();
    cmd.args(["v1", "node-info", "--node", &n.url])
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    for var in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        cmd.env(var, &proxy_url);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(*connections.lock().unwrap(), 0);
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
    let e = Node::new("https://node.example", Some("token\n"))
        .err()
        .map(error_text);
    assert!(e.unwrap().contains("must not start or end with whitespace"));
}
