//! `GET /v1/seal` over the served v1 router, a real socket and real
//! PostgreSQL: the seal verifies under the node key, names exactly the
//! identity `/health` publishes and the digests `/v1/snapshot` serves, follows
//! admissions, changes no commitment, is read-key gated and GET-only, is
//! counted under the read limit, and is `503 no_seal_key` without a seed.
use cc_core::v1::seal::{verify_seal, NodeSealV1, SealCounts};
use cc_core::v1::{receipt::FoldRef, Hash};
use cc_ledger::v1::Store;
use cc_node::config::{KeyDigest, Posture, V1Config};
use cc_node::serve_v1::{health_body, router_with, Serving, V1State};
use cc_testkit::v1::*;
use reqwest::{Method, StatusCode as S};
use serde_json::{json, Value as Json};

const WRITE: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const READ: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
const STRANGER: &str = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
/// A synthetic, visibly patterned node seed for these tests only.
const SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn seed_key() -> cc_core::SecretKey {
    cc_core::SecretKey::from_seed(SEED)
}

fn v1() -> V1Config {
    V1Config {
        database_url: "postgres://unused".into(),
        instance: INSTANCE,
        filter: filter(),
    }
}

async fn bound() -> (sqlx::PgPool, cc_testkit::Cleanup, Store) {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    Store::provision(pool.clone(), INSTANCE)
        .await
        .unwrap()
        .bind(filter())
        .await
        .unwrap();
    let store = Store::open(pool.clone(), INSTANCE, filter()).await.unwrap();
    (pool, cleanup, store)
}

struct Node {
    base: String,
    http: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
}

async fn boot(store: &Store, serving: Serving) -> Node {
    let semantic = store.semantic_readiness().await.unwrap().semantic;
    let state = V1State {
        health_body: health_body(&v1(), Posture::Live, &semantic),
        ready_gate: Default::default(),
        store: store.clone(),
        posture: Posture::Live,
        api_key: KeyDigest::of(WRITE),
        read_key: Some(KeyDigest::of(READ)),
        gallery_key: None,
        beta_key: None,
        telemetry_key: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router_with(state, serving);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Node {
        base,
        http: reqwest::Client::new(),
        server,
    }
}

impl Node {
    async fn raw(&self, m: Method, path: &str, token: Option<&str>) -> (S, Vec<u8>) {
        let mut req = self.http.request(m, format!("{}{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let r = req.send().await.unwrap();
        (r.status(), r.bytes().await.unwrap().to_vec())
    }
    async fn json(&self, path: &str, token: Option<&str>) -> (S, Json) {
        let (s, b) = self.raw(Method::GET, path, token).await;
        (s, serde_json::from_slice(&b).unwrap())
    }
    async fn submit(&self, bytes: &[u8]) -> S {
        self.http
            .post(format!("{}/v1/candidates", self.base))
            .bearer_auth(WRITE)
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap()
            .status()
    }
    async fn stop(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

fn h32(v: &Json) -> Hash {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// The served seal document rebuilt as the Rust type, so `verify_seal` runs
/// over exactly the fields a caller sees.
fn seal_of(doc: &Json) -> (NodeSealV1, [u8; 64]) {
    let s = &doc["seal"];
    let seal = NodeSealV1 {
        instance: h32(&s["instance"]),
        node_key: h32(&s["node_key"]),
        fold_version: FoldRef {
            version: u16::try_from(s["fold_version"]["version"].as_u64().unwrap()).unwrap(),
            manifest: h32(&s["fold_version"]["manifest"]),
        },
        filter_version: h32(&s["filter_version"]),
        corpus_digest: h32(&s["corpus_digest"]),
        commitment: h32(&s["commitment"]),
        counts: SealCounts {
            candidates: s["counts"]["candidates"].as_u64().unwrap(),
        },
        build: s["build"].as_str().unwrap().to_string(),
        sealed_at_us: s["sealed_at_us"].as_u64().unwrap(),
    };
    let signature = hex::decode(doc["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (seal, signature)
}

/// A seal verifies under the node key and names exactly what `/health` and
/// `/v1/snapshot` serve, before and after admissions; sealing changes nothing.
#[tokio::test]
async fn a_seal_verifies_and_names_the_served_identity_and_digests() {
    let (pool, cleanup, store) = bound().await;
    let node = boot(&store, Serving::new(8, Some(seed_key()))).await;
    let (status, health) = node.json("/health", None).await;
    assert_eq!(status, S::OK);
    let public = hex::encode(seed_key().author().to_bytes());
    let f = view_fixture();
    let mut previous: Option<NodeSealV1> = None;
    // Empty, then after each fixture admission: a pending correction first,
    // then its genesis, then a repeat that admits nothing.
    for (step, admit) in [None, Some(&f[1]), Some(&f[0]), Some(&f[0])]
        .into_iter()
        .enumerate()
    {
        if let Some(e) = admit {
            node.submit(e.bytes()).await;
        }
        let (status, before) = node.json("/v1/snapshot", Some(READ)).await;
        assert_eq!(status, S::OK);
        let (status, doc) = node.json("/v1/seal", Some(READ)).await;
        assert_eq!(status, S::OK, "{doc}");
        let (status, after) = node.json("/v1/snapshot", Some(READ)).await;
        assert_eq!(status, S::OK);
        assert_eq!(before, after, "step {step}: sealing changed a read");

        let (seal, signature) = seal_of(&doc);
        verify_seal(&seal, &signature).unwrap_or_else(|e| panic!("step {step}: {e}"));
        assert_eq!(
            doc.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["node_key", "seal", "signature"],
        );
        assert_eq!(doc["node_key"], public);
        assert_eq!(doc["seal"]["node_key"], public);
        assert_eq!(doc["seal"]["instance"], health["instance"]);
        assert_eq!(doc["seal"]["fold_version"], health["fold_version"]);
        assert_eq!(doc["seal"]["filter_version"], health["filter_version"]);
        assert_eq!(doc["seal"]["build"], health["build"]);
        assert_eq!(doc["seal"]["corpus_digest"], before["corpus_digest"]);
        assert_eq!(doc["seal"]["commitment"], before["commitment"]);
        assert_eq!(
            doc["seal"]["fold_version"]["manifest"],
            before["rule"]["fold_manifest"]
        );
        assert_eq!(
            doc["seal"]["counts"],
            json!({ "candidates": before["rows"].as_array().unwrap().len() })
        );
        let expected_count = match step {
            0 => 0,
            1 => 1,
            _ => 2,
        };
        assert_eq!(seal.counts.candidates, expected_count, "step {step}");
        if let Some(p) = &previous {
            assert!(seal.sealed_at_us >= p.sealed_at_us, "step {step}");
            assert!(seal.counts.candidates >= p.counts.candidates);
            if seal.counts.candidates == p.counts.candidates {
                assert_eq!(seal.commitment, p.commitment, "step {step}");
                assert_eq!(seal.corpus_digest, p.corpus_digest, "step {step}");
            } else {
                assert_ne!(seal.commitment, p.commitment, "step {step}");
                assert_ne!(seal.corpus_digest, p.corpus_digest, "step {step}");
            }
        }
        // A signature over a different seal, or under a different key, fails.
        let mut other = seal.clone();
        other.counts.candidates += 1;
        assert!(verify_seal(&other, &signature).is_err());
        let mut other = seal.clone();
        other.node_key = cc_core::SecretKey::from_seed([9; 32]).author().to_bytes();
        assert!(verify_seal(&other, &signature).is_err());
        previous = Some(seal);
    }
    // Two seals of the same state differ only in the clock and signature.
    let (_, a) = node.json("/v1/seal", Some(READ)).await;
    let (_, b) = node.json("/v1/seal", Some(READ)).await;
    let (sa, _) = seal_of(&a);
    let (sb, _) = seal_of(&b);
    assert!(sb.sealed_at_us >= sa.sealed_at_us);
    let strip = |mut s: NodeSealV1| {
        s.sealed_at_us = 0;
        s
    };
    assert_eq!(strip(sa), strip(sb));
    node.stop().await;
    pool.close().await;
    cleanup.cleanup().await;
}

/// Without a node seed the route exists, is still gated, and answers
/// `503 no_seal_key`; reads and `/health` are unchanged.
#[tokio::test]
async fn without_a_seed_the_seal_route_answers_no_seal_key() {
    let (pool, cleanup, store) = bound().await;
    let node = boot(&store, Serving::default()).await;
    assert_eq!(
        node.json("/v1/seal", Some(READ)).await,
        (S::SERVICE_UNAVAILABLE, json!({ "error": "no_seal_key" }))
    );
    assert_eq!(
        node.json("/v1/seal", Some(WRITE)).await,
        (S::SERVICE_UNAVAILABLE, json!({ "error": "no_seal_key" }))
    );
    assert_eq!(node.json("/v1/seal", None).await.0, S::UNAUTHORIZED);
    assert_eq!(node.json("/v1/snapshot", Some(READ)).await.0, S::OK);
    node.stop().await;
    pool.close().await;
    cleanup.cleanup().await;
}

/// Read-key gated like every other v1 read, strict about its query, GET-only,
/// and counted under the read limit.
#[tokio::test]
async fn the_seal_route_is_read_gated_get_only_and_read_limited() {
    let (pool, cleanup, store) = bound().await;
    let serving = Serving::new(1, Some(seed_key()));
    let permits = serving.read_permits();
    let node = boot(&store, serving).await;
    assert_eq!(node.json("/v1/seal", None).await.0, S::UNAUTHORIZED);
    assert_eq!(
        node.json("/v1/seal", Some(STRANGER)).await.0,
        S::UNAUTHORIZED
    );
    assert_eq!(node.json("/v1/seal", Some(READ)).await.0, S::OK);
    assert_eq!(node.json("/v1/seal", Some(WRITE)).await.0, S::OK);
    assert_eq!(
        node.json("/v1/seal?as_of=00", Some(READ)).await,
        (S::BAD_REQUEST, json!({ "error": "invalid_query" }))
    );
    for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        let (status, _) = node.raw(m.clone(), "/v1/seal", Some(READ)).await;
        assert_eq!(status, S::METHOD_NOT_ALLOWED, "{m}");
        let (status, _) = node.raw(m.clone(), "/v1/seal", Some(WRITE)).await;
        assert_eq!(status, S::METHOD_NOT_ALLOWED, "{m}");
        // Authentication still comes first.
        let (status, _) = node.raw(m, "/v1/seal", None).await;
        assert_eq!(status, S::UNAUTHORIZED);
    }
    // The one permit held: the seal is busy like any read, while /health
    // still answers. Released, it seals again.
    let held = permits.clone().try_acquire_owned().unwrap();
    let r = node
        .http
        .get(format!("{}/v1/seal", node.base))
        .bearer_auth(READ)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), S::SERVICE_UNAVAILABLE);
    assert_eq!(r.headers()["retry-after"], "1");
    let body: Json = serde_json::from_slice(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(body, json!({ "error": "busy" }));
    assert_eq!(node.json("/health", None).await.0, S::OK);
    drop(held);
    assert_eq!(node.json("/v1/seal", Some(READ)).await.0, S::OK);
    assert_eq!(permits.available_permits(), 1);
    node.stop().await;
    pool.close().await;
    cleanup.cleanup().await;
}
