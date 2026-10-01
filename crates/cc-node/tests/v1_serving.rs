//! The served v1 router (`serve_v1::router`) over a real socket and Postgres:
//! credential scope, frozen posture, body limits, fold negotiation, export and
//! restore roots, static `/health`, per-request `/ready`, the read contract,
//! and the privacy headers on every response, refusals included.
use cc_core::v1::rule::fold_v1;
use cc_core::v1::*;
use cc_ledger::v1::{Error, ExportManifest, Outcome, State, Store};
use cc_node::config::{KeyDigest, Posture, V1Config};
use cc_node::serve_v1::{health_body, router, V1State};
use cc_testkit::v1::*;
use reqwest::{header::HeaderMap, Method, StatusCode as S};
use serde_json::{json, Value as Json};
use std::collections::BTreeSet;

const WRITE: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const READ: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
const STRANGER: &str = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const PROSE: &str = "Synthetic prose retained for the v1 serving test.";
const CANDIDATES: &str = "/v1/candidates";
const CSP: &str = "default-src 'none'; frame-ancestors 'none'";
const PRIVATE: [(&str, &str); 5] = [
    ("cache-control", "private, no-store"),
    ("x-robots-tag", "noindex, nofollow, noarchive"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("content-security-policy", CSP),
];

fn v1() -> V1Config {
    let database_url = "postgres://unused".into();
    V1Config {
        database_url,
        instance: INSTANCE,
        filter: filter(),
    }
}

/// A fresh database, provisioned and bound, reopened as `serve` does and
/// served by a live node.
async fn live() -> (sqlx::PgPool, cc_testkit::Cleanup, Store, Node) {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let fresh = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    fresh.bind(filter()).await.unwrap();
    let store = Store::open(pool.clone(), INSTANCE, filter()).await.unwrap();
    let node = boot(&store, Posture::Live).await;
    (pool, cleanup, store, node)
}

async fn done(node: Node, pool: sqlx::PgPool, cleanup: cc_testkit::Cleanup) {
    node.stop().await;
    pool.close().await;
    cleanup.cleanup().await;
}

/// A curator-authored genesis whose body hash names real UTF-8 prose.
fn prose_genesis() -> Signed {
    let mut e = genesis().envelope().clone();
    if let Payload::Genesis { body, .. } = &mut e.payload {
        *body = hash(PROSE.as_bytes());
    }
    Signed::sign(&key(0), e).unwrap()
}

fn subject_path(id: Hash) -> String {
    format!("/v1/subjects/{}", hex::encode(id))
}

fn prose_path(g: &Signed) -> String {
    let revision = revision_id(g.id(), g.id());
    format!("/v1/revisions/{}/prose", hex::encode(revision))
}

fn body_path(h: Hash) -> String {
    format!("/v1/bodies/{}", hex::encode(h))
}

fn refusal(status: S, error: &str) -> (S, Json) {
    (status, json!({ "error": error }))
}

struct Node {
    base: String,
    http: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
}

async fn boot(store: &Store, posture: Posture) -> Node {
    let state = V1State {
        health_body: health_body(&v1(), posture),
        store: store.clone(),
        posture,
        api_key: KeyDigest::of(WRITE),
        read_key: Some(KeyDigest::of(READ)),
        gallery_key: None,
        beta_key: None,
        telemetry_key: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = reqwest::Client::new();
    Node { base, http, server }
}

type Raw = (S, HeaderMap, Vec<u8>);

impl Node {
    /// Every response in this file, refusals included, passes this header check.
    async fn raw(&self, m: Method, path: &str, token: Option<&str>, body: Vec<u8>) -> Raw {
        let url = format!("{}{path}", self.base);
        let mut req = self.http.request(m.clone(), url).body(body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let r = req.send().await.unwrap();
        for (name, value) in PRIVATE {
            let got = r.headers().get(name).map(|v| v.to_str().unwrap());
            assert_eq!(got, Some(value), "{name} on {m} {path}");
        }
        let (status, headers) = (r.status(), r.headers().clone());
        (status, headers, r.bytes().await.unwrap().to_vec())
    }
    async fn call(&self, m: Method, path: &str, token: Option<&str>, body: Vec<u8>) -> (S, Json) {
        let (status, _, bytes) = self.raw(m, path, token, body).await;
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn fetch(&self, path: &str, token: Option<&str>) -> Raw {
        self.raw(Method::GET, path, token, vec![]).await
    }
    async fn get(&self, path: &str, token: &str) -> (S, Json) {
        self.call(Method::GET, path, Some(token), vec![]).await
    }
    async fn public(&self, path: &str) -> (S, Json) {
        self.call(Method::GET, path, None, vec![]).await
    }
    async fn submit(&self, e: &Signed) -> (S, Json) {
        let wire = e.bytes().to_vec();
        self.call(Method::POST, CANDIDATES, Some(WRITE), wire).await
    }
    async fn put_body(&self, h: Hash, bytes: &[u8]) -> (S, Json) {
        let (path, wire) = (body_path(h), bytes.to_vec());
        self.call(Method::PUT, &path, Some(WRITE), wire).await
    }
    async fn ok(&self, path: &str, token: &str) -> Json {
        let (status, body) = self.get(path, token).await;
        assert_eq!(status, S::OK, "{path}: {body}");
        body
    }
    async fn stop(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

#[tokio::test]
async fn retained_prose_and_admitted_genesis_are_served_under_one_commitment() {
    let (pool, cleanup, store, node) = live().await;
    let g = prose_genesis();
    let body = hash(PROSE.as_bytes());
    let before = node.ok("/v1/snapshot", READ).await;
    assert_eq!(before["rows"], json!([]));
    let (status, unknown) = node.get(&subject_path(g.id()), READ).await;
    assert_eq!(status, S::NOT_FOUND);
    assert_eq!(unknown["visibility"], "subject_unknown");
    let unknown = node.get(&prose_path(&g), READ).await;
    assert_eq!(unknown, refusal(S::NOT_FOUND, "revision_unknown"));

    let (status, put) = node.put_body(body, PROSE.as_bytes()).await;
    assert_eq!(status, S::CREATED);
    assert_eq!(put, json!({ "body_hash": hex::encode(body), "new": true }));
    let (status, outcome) = node.submit(&g).await;
    assert_eq!(status, S::CREATED);
    let outcome: Outcome = serde_json::from_value(outcome).unwrap();
    assert_eq!(outcome.status.state, State::Valid);
    assert_eq!(outcome.event, Some(g.id()));
    assert_eq!(outcome.input_digest, hash(g.bytes()));

    let stored = store.snapshot(None).await.unwrap();
    let commitment = hex::encode(stored.commitment);
    let corpus = hex::encode(stored.corpus_digest);
    let revision = json!({
        "id": revision_id(g.id(), g.id()),
        "subject": g.id(),
        "creating_event": g.id(),
        "body": body,
        "asserted_time": null,
    });
    let expected = json!({
        "rule": before["rule"], "corpus_digest": corpus, "commitment": commitment,
        "as_of": null, "subject": hex::encode(g.id()), "state": "resolved",
        "frontier": [hex::encode(g.id())], "revision": revision, "visibility": "visible",
    });
    let read = node.get(&subject_path(g.id()), READ).await;
    assert_eq!(read, (S::OK, expected));
    let at = hex::encode([60; 32]);
    let path = format!("{}?as_of={at}", subject_path(g.id()));
    let dated = node.ok(&path, READ).await;
    assert_eq!(dated["as_of"], at);
    assert_eq!(dated["visibility"], "asserted_time_unknown");
    assert!(dated["revision"].is_null());
    assert_eq!(dated["frontier"], json!([hex::encode(g.id())]));
    let expected = json!({
        "revision": revision, "availability": "available", "prose": PROSE,
        "rule": before["rule"], "corpus_digest": corpus, "commitment": commitment,
    });
    assert_eq!(node.get(&prose_path(&g), READ).await, (S::OK, expected));

    let after = node.ok("/v1/snapshot", READ).await;
    assert_eq!(after["commitment"], commitment);
    assert_eq!(after["corpus_digest"], corpus);
    assert_ne!(after["commitment"], before["commitment"]);
    assert_ne!(after["corpus_digest"], before["corpus_digest"]);
    assert_eq!(after["rows"].as_array().unwrap().len(), 1);
    assert_eq!(after["revisions"], json!([revision]));

    // The same bytes again are idempotent.
    let (status, again) = node.put_body(body, PROSE.as_bytes()).await;
    assert_eq!((status, &again["new"]), (S::OK, &json!(false)));
    let (status, again) = node.submit(&g).await;
    assert_eq!((status, &again["event"]), (S::CREATED, &json!(g.id())));
    assert_eq!(node.ok("/v1/snapshot", READ).await, after);
    done(node, pool, cleanup).await;
}

#[tokio::test]
async fn every_route_is_scoped_and_refused_writes_store_nothing() {
    let (pool, cleanup, store, node) = live().await;
    let g = prose_genesis();
    let b = subject(1, 50, 51);
    let body = hash(PROSE.as_bytes());
    assert_eq!(node.submit(&g).await.0, S::CREATED);
    let before = node.ok("/v1/snapshot", WRITE).await;
    assert_eq!(before["rows"].as_array().unwrap().len(), 1);
    let (from, to) = (hex::encode(g.id()), hex::encode(b.id()));
    let support = format!("/v1/support?from={from}&to={to}");
    let snapshot = "/v1/snapshot".to_string();
    let reads = [snapshot, subject_path(g.id()), prose_path(&g), support];
    let writes = [
        (Method::POST, CANDIDATES.to_string(), b.bytes().to_vec()),
        (Method::PUT, body_path(body), PROSE.as_bytes().to_vec()),
        (Method::GET, "/v1/export".to_string(), vec![]),
    ];
    let every = (reads.iter().map(|p| (Method::GET, p.clone(), vec![])))
        .chain(writes.clone())
        .chain([(Method::GET, "/v1/nope".to_string(), vec![])]);
    for (m, path, payload) in every {
        for token in [None, Some(STRANGER)] {
            let (status, headers, bytes) = node.raw(m.clone(), &path, token, payload.clone()).await;
            assert_eq!(status, S::UNAUTHORIZED, "{m} {path}");
            assert_eq!(headers["www-authenticate"], "Bearer");
            let refused: Json = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(refused["error"], "unauthorized");
        }
    }
    for (m, path, payload) in writes {
        let (status, refused) = node.call(m.clone(), &path, Some(READ), payload).await;
        assert_eq!(status, S::FORBIDDEN, "{m} {path}");
        assert_eq!(refused["error"], "read_only_credential");
    }
    for (path, token) in reads.iter().flat_map(|p| [(p, READ), (p, WRITE)]) {
        assert_eq!(node.get(path, token).await.0, S::OK, "{path}");
    }
    for token in [READ, WRITE] {
        let probe = node.get("/v1/nope", token).await;
        assert_eq!(probe, refusal(S::NOT_FOUND, "no_such_route"));
    }
    assert_eq!(node.ok("/v1/snapshot", WRITE).await, before);
    let (_, prose) = node.get(&prose_path(&g), READ).await;
    assert_eq!(prose["availability"], "unavailable");
    assert_eq!(store.body_bytes(body).await.unwrap(), None);
    done(node, pool, cleanup).await;
}

#[tokio::test]
async fn frozen_posture_refuses_writes_and_keeps_serving_reads() {
    let (pool, cleanup, store, node) = live().await;
    let g = prose_genesis();
    let body = hash(PROSE.as_bytes());
    assert_eq!(node.submit(&g).await.0, S::CREATED);
    let frozen = boot(&store, Posture::Frozen).await;
    let health = frozen.fetch("/health", None).await.2;
    assert_eq!(health, health_body(&v1(), Posture::Frozen).to_vec());
    let health: Json = serde_json::from_slice(&health).unwrap();
    assert_eq!(health["posture"], "frozen");
    let ready = json!({ "serving": true, "posture": "frozen" });
    assert_eq!(frozen.public("/ready").await, (S::OK, ready));
    let before = frozen.ok("/v1/snapshot", READ).await;
    let b = subject(1, 50, 51);
    let refused = refusal(S::SERVICE_UNAVAILABLE, "frozen");
    for (m, path, payload) in [
        (Method::POST, CANDIDATES.to_string(), b.bytes().to_vec()),
        (Method::PUT, body_path(body), PROSE.as_bytes().to_vec()),
    ] {
        let p = payload.clone();
        assert_eq!(frozen.call(m.clone(), &path, Some(WRITE), p).await, refused);
        // Scope is still decided before the posture.
        let scoped = frozen.call(m.clone(), &path, Some(READ), payload).await;
        assert_eq!(scoped.0, S::FORBIDDEN);
        assert_eq!(frozen.call(m, &path, None, vec![]).await.0, S::UNAUTHORIZED);
    }
    assert_eq!(frozen.ok("/v1/snapshot", READ).await, before);
    assert_eq!(store.body_bytes(body).await.unwrap(), None);
    let prose = frozen.ok(&prose_path(&g), READ).await;
    assert_eq!(prose["availability"], "unavailable");
    assert!(prose["prose"].is_null());
    let (status, read) = frozen.get(&subject_path(g.id()), READ).await;
    assert_eq!((status, &read["visibility"]), (S::OK, &json!("visible")));
    let export = frozen.ok("/v1/export", WRITE).await;
    assert_eq!(export["envelopes"], json!([hex::encode(g.bytes())]));
    assert_eq!(export["commitment"], before["commitment"]);

    // The refused body was never retained: the live node stores it as new.
    let (status, put) = node.put_body(body, PROSE.as_bytes()).await;
    assert_eq!((status, &put["new"]), (S::CREATED, &json!(true)));
    let (_, prose) = frozen.get(&prose_path(&g), READ).await;
    assert_eq!(prose["prose"], PROSE);
    assert_eq!(frozen.ok("/v1/snapshot", READ).await, before);
    frozen.stop().await;
    done(node, pool, cleanup).await;
}

#[tokio::test]
async fn oversized_mismatched_or_malformed_writes_are_refused_and_not_retained() {
    let (pool, cleanup, store, node) = live().await;
    let g = prose_genesis();
    let body = hash(PROSE.as_bytes());
    let other = b"Synthetic bytes that do not hash to the path.";
    assert_eq!(node.submit(&g).await.0, S::CREATED);
    let before = node.ok("/v1/snapshot", READ).await;
    let mismatch = refusal(S::UNPROCESSABLE_ENTITY, "body_hash_mismatch");
    assert_eq!(node.put_body(body, other).await, mismatch);
    let lower = hex::encode(body);
    let (upper, long) = (lower.to_uppercase(), lower.clone() + "0");
    for bad in [upper, long, lower[1..].into(), "z".repeat(64)] {
        let (path, wire) = (format!("/v1/bodies/{bad}"), PROSE.as_bytes().to_vec());
        let put = node.call(Method::PUT, &path, Some(WRITE), wire).await;
        assert_eq!(put, refusal(S::BAD_REQUEST, "invalid_body_hash"), "{bad}");
    }
    let over = vec![0x5a; MAX_ENVELOPE + 1];
    let put = body_path(hash(&over));
    for (m, path) in [(Method::POST, CANDIDATES), (Method::PUT, put.as_str())] {
        let (status, _, _) = node.raw(m, path, Some(WRITE), over.clone()).await;
        assert_eq!(status, S::PAYLOAD_TOO_LARGE, "{path}");
    }
    for h in [body, hash(other), hash(&over)] {
        assert_eq!(store.body_bytes(h).await.unwrap(), None);
    }
    let prose = node.ok(&prose_path(&g), READ).await;
    assert_eq!(prose["availability"], "unavailable");
    assert!(prose["prose"].is_null());
    assert_eq!(node.ok("/v1/snapshot", READ).await, before);

    // Exactly at the limit is read and judged on its content.
    let at = vec![0x5a; MAX_ENVELOPE];
    let (status, put) = node.put_body(hash(&at), &at).await;
    assert_eq!((status, &put["new"]), (S::CREATED, &json!(true)));
    let (status, outcome) = node.call(Method::POST, CANDIDATES, Some(WRITE), at).await;
    assert_eq!(status, S::UNPROCESSABLE_ENTITY);
    assert_eq!(outcome["status"]["state"], "invalid");
    assert!(outcome["event"].is_null());
    assert_eq!(node.put_body(body, PROSE.as_bytes()).await.0, S::CREATED);
    let prose = node.ok(&prose_path(&g), READ).await;
    assert_eq!(prose["availability"], "available");
    assert_eq!(node.ok("/v1/snapshot", READ).await, before);
    done(node, pool, cleanup).await;
}

#[tokio::test]
async fn snapshot_fold_negotiation() {
    let (pool, cleanup, _, node) = live().await;
    assert_eq!(node.submit(&genesis()).await.0, S::CREATED);
    let plain = node.ok("/v1/snapshot", READ).await;
    let f = fold_v1();
    let (version, hexed) = (f.version.to_string(), hex::encode(f.manifest));
    let rule = json!({
        "fold_version": f.version,
        "fold_manifest": hexed,
        "filter_version": hex::encode(filter().version()),
    });
    assert_eq!(plain["rule"], rule);
    let q = |v: &str, m: &str| format!("/v1/snapshot?fold_version={v}&fold_manifest={m}");
    let explicit = node.get(&q(&version, &hexed), READ).await;
    assert_eq!(explicit, (S::OK, plain));
    let mut flipped = f.manifest;
    flipped[31] ^= 1;
    let (next, flipped) = ((f.version + 1).to_string(), hex::encode(flipped));
    for path in [q(&next, &hexed), q("0", &hexed), q(&version, &flipped)] {
        let conflict = refusal(S::CONFLICT, "unsupported_fold_version");
        assert_eq!(node.get(&path, READ).await, conflict, "{path}");
    }
    for path in [
        format!("/v1/snapshot?fold_version={version}"),
        format!("/v1/snapshot?fold_manifest={hexed}"),
        q("", &hexed),
        q("x", &hexed),
        q(&format!("%2B{version}"), &hexed),
        q("65536", &hexed),
        q(&version, &hexed.to_uppercase()),
        q(&version, &hexed[..62]),
        q(&format!("0{version}"), &hexed),
    ] {
        let invalid = refusal(S::BAD_REQUEST, "invalid_fold_request");
        assert_eq!(node.get(&path, READ).await, invalid, "{path}");
    }
    // A misspelled or repeated parameter is refused, never ignored.
    for path in [
        format!("/v1/snapshot?fold_versoin={next}&fold_manifest={hexed}"),
        format!("{}&fold_version={version}", q(&version, &hexed)),
    ] {
        let invalid = refusal(S::BAD_REQUEST, "invalid_query");
        assert_eq!(node.get(&path, READ).await, invalid, "{path}");
    }
    done(node, pool, cleanup).await;
}

#[tokio::test]
async fn export_restores_to_the_same_served_commitment() {
    let (pool, cleanup, store, node) = live().await;
    let g = genesis();
    let c = correction(&g, &g, 0, 5);
    let b = subject(1, 50, 51);
    let (source, target) = (pin(&[&g, &c], &c), pin(&[&b], &b));
    let e = edge(0, "influence", Pins { source, target });
    for event in [&g, &c, &b, &e] {
        assert_eq!(node.submit(event).await.0, S::CREATED);
    }
    let export = node.ok("/v1/export", WRITE).await;
    let served = node.ok("/v1/snapshot", READ).await;
    for field in ["rule", "corpus_digest", "commitment"] {
        assert_eq!(export[field], served[field], "{field}");
    }
    // Hex on the wire, canonical byte arrays in the manifest.
    let bytes = |v: &Json| json!(hex::decode(v.as_str().unwrap()).unwrap());
    let (rule, envelopes) = (&export["rule"], export["envelopes"].as_array().unwrap());
    let manifest: ExportManifest = serde_json::from_value(json!({
        "encoding": export["encoding"],
        "rule": {
            "fold_version": rule["fold_version"],
            "fold_manifest": bytes(&rule["fold_manifest"]),
            "filter_version": bytes(&rule["filter_version"]),
        },
        "corpus_digest": bytes(&export["corpus_digest"]),
        "commitment": bytes(&export["commitment"]),
        "envelopes": envelopes.iter().map(bytes).collect::<Vec<_>>(),
    }))
    .unwrap();
    assert_eq!(manifest, store.export(None).await.unwrap());
    let sent: BTreeSet<_> = [&g, &c, &b, &e].map(|x| x.bytes().to_vec()).into();
    let exported: BTreeSet<_> = manifest.envelopes.iter().cloned().collect();
    assert_eq!(exported, sent);

    // A tampered root is refused before anything is admitted.
    let (pool2, cleanup2, replica_store, replica) = live().await;
    let empty = replica_store.snapshot(None).await.unwrap();
    assert!(empty.projection.rows.is_empty());
    let mut tampered = [manifest.clone(), manifest.clone(), manifest.clone()];
    tampered[0].commitment[0] ^= 1;
    tampered[1].corpus_digest[0] ^= 1;
    tampered[2].envelopes.pop();
    for m in &tampered {
        let refused = replica_store.restore_export(m).await;
        assert!(matches!(refused, Err(Error::RootMismatch)), "{refused:?}");
    }
    assert_eq!(replica_store.snapshot(None).await.unwrap(), empty);

    // Restore admits in manifest (event id) order, so a per-admission outcome
    // may be pending; the restored root is what must match.
    let outcomes = replica_store.restore_export(&manifest).await.unwrap();
    assert_eq!(outcomes.len(), manifest.envelopes.len());
    assert!(outcomes.iter().all(|o| o.status.state != State::Invalid));
    let restored = replica_store.snapshot(None).await.unwrap();
    assert_eq!(restored.commitment, manifest.commitment);
    assert_eq!(replica.ok("/v1/snapshot", READ).await, served);
    assert_eq!(replica.ok("/v1/export", WRITE).await, export);
    done(node, pool, cleanup).await;
    done(replica, pool2, cleanup2).await;
}

#[tokio::test]
async fn health_is_static_and_ready_tracks_the_store() {
    let (pool, cleanup, _, node) = live().await;
    let (status, headers, health) = node.fetch("/health", None).await;
    assert_eq!(status, S::OK);
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(health, health_body(&v1(), Posture::Live).to_vec());
    let mut curators: Vec<_> = (0..4).map(|k| key(k).author().to_bytes()).collect();
    curators.sort();
    let fold = fold_v1();
    let expected = json!({
        "ledger": "v1",
        "build": cc_node::protocol::BUILD_REV,
        "posture": "live",
        "instance": hex::encode(INSTANCE),
        "fold_version": { "version": fold.version, "manifest": hex::encode(fold.manifest) },
        "filter_version": hex::encode(filter().version()),
        "curators": curators.iter().map(hex::encode).collect::<Vec<_>>(),
        "max_hops": 4,
        "semantic": "ready",
    });
    assert_eq!(serde_json::from_slice::<Json>(&health).unwrap(), expected);
    // Public routes ignore whatever credential is presented.
    let (status, _, bytes) = node.fetch("/health", Some(STRANGER)).await;
    assert_eq!((status, &bytes), (S::OK, &health));
    let ready = json!({ "serving": true, "posture": "live" });
    assert_eq!(node.public("/ready").await, (S::OK, ready));
    let (status, headers, robots) = node.fetch("/robots.txt", None).await;
    assert_eq!(status, S::OK);
    assert_eq!(robots, b"User-agent: *\nDisallow: /\n");
    assert_eq!(headers["content-type"], "text/plain; charset=utf-8");

    // A tampered stored rule identity: /ready names it, reads refuse, and the
    // boot-time /health bytes do not move.
    let tamper = "ALTER TABLE cc_v1.rule_identity DISABLE TRIGGER immutable_rule_identity; \
                  UPDATE cc_v1.rule_identity SET filter_identity='\\x00'::bytea;";
    sqlx::raw_sql(tamper).execute(&pool).await.unwrap();
    let not_ready = |reason: &str| {
        let body = json!({ "serving": false, "posture": "live", "reason": reason });
        (S::SERVICE_UNAVAILABLE, body)
    };
    let ready = node.public("/ready").await;
    assert_eq!(ready, not_ready("incompatible_rule_identity"));
    let refused = refusal(S::SERVICE_UNAVAILABLE, "incompatible_rule_identity");
    assert_eq!(node.get("/v1/snapshot", READ).await, refused);
    assert_eq!(node.fetch("/health", None).await.2, health);

    // Closing the shared pool takes the store away; /health never touches it.
    pool.close().await;
    assert_eq!(node.public("/ready").await, not_ready("store_unavailable"));
    for (path, token) in [("/v1/snapshot", READ), ("/v1/export", WRITE)] {
        let refused = refusal(S::SERVICE_UNAVAILABLE, "store_unavailable");
        assert_eq!(node.get(path, token).await, refused, "{path}");
    }
    assert_eq!(node.fetch("/health", None).await.2, health);
    done(node, pool, cleanup).await;
}

#[tokio::test]
async fn support_between_curated_subjects_and_query_refusals() {
    let (pool, cleanup, store, node) = live().await;
    let g = genesis();
    let b = subject(1, 50, 51);
    let (source, target) = (pin(&[&g], &g), pin(&[&b], &b));
    let e = edge(0, "influence", Pins { source, target });
    for event in [&g, &b, &e] {
        assert_eq!(node.submit(event).await.0, S::CREATED);
    }
    let (from, to) = (hex::encode(g.id()), hex::encode(b.id()));
    let query = format!("/v1/support?from={from}&to={to}");
    let s = store.snapshot(None).await.unwrap();
    let v = node.ok(&query, READ).await;
    let supported = json!({ "Supported": { "path": [e.id()], "excluded": [] } });
    assert_eq!(v["support"], supported);
    let direct = s.verdict(g.id(), b.id(), None).support;
    assert_eq!(v["support"], serde_json::to_value(direct).unwrap());
    assert_eq!((&v["from"], &v["to"]), (&json!(from), &json!(to)));
    assert!(v["as_of"].is_null());
    assert_eq!(v["commitment"], hex::encode(s.commitment));

    // No asserted coordinate is visible under any as_of.
    let at = [60; 32];
    let dated = format!("{query}&as_of={}", hex::encode(at));
    let dated = node.ok(&dated, READ).await;
    assert_eq!(dated["as_of"], hex::encode(at));
    let direct = s.verdict(g.id(), b.id(), Some(at)).support;
    assert_eq!(dated["support"], serde_json::to_value(direct).unwrap());
    let reason = &dated["support"]["Unsupported"]["reasons"][0];
    assert_eq!(reason["code"], "asserted_time_unknown");
    let absent: Hash = [7; 32];
    let path = format!("/v1/support?from={from}&to={}", hex::encode(absent));
    let unknown = node.ok(&path, READ).await;
    let reason = &unknown["support"]["Unsupported"]["reasons"][0];
    assert_eq!(reason["code"], "subject_unknown");
    assert_eq!(reason["subject"], json!(absent));

    let (upper, short, bad) = (from.to_uppercase(), &from[..62], "invalid_support_query");
    let dated = format!("{}?as_of=60", subject_path(g.id()));
    for (path, error) in [
        ("/v1/support".to_string(), bad),
        (format!("/v1/support?from={from}"), bad),
        (format!("/v1/support?to={to}"), bad),
        (format!("/v1/support?from={upper}&to={to}"), bad),
        (format!("/v1/support?from={short}&to={to}"), bad),
        (format!("{query}&as_of=60"), "invalid_as_of"),
        (format!("/v1/subjects/{short}"), "invalid_subject_id"),
        (dated, "invalid_as_of"),
        ("/v1/revisions/nothex/prose".into(), "invalid_revision_id"),
        (format!("{query}&asof={}", hex::encode(at)), "invalid_query"),
        (format!("{query}&from={from}"), "invalid_query"),
        (format!("{}?at=0", subject_path(g.id())), "invalid_query"),
    ] {
        let invalid = refusal(S::BAD_REQUEST, error);
        assert_eq!(node.get(&path, READ).await, invalid, "{path}");
    }
    done(node, pool, cleanup).await;
}
