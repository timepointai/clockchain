//! Stage (g) G4 over the served v1 router, a real socket and real PostgreSQL:
//! cached reads are byte-identical to uncached ones across admissions, a full
//! read limit answers `503 busy` while `/health`, `/ready` and writes still
//! answer, receipts are served only when a node seed is set and never change
//! a commitment, and the binary parses the new configuration strictly and
//! never prints the seed.
use cc_core::v1::receipt::SignedReceipt;
use cc_core::v1::rule::fold_v1;
use cc_core::v1::*;
use cc_ledger::v1::Store;
use cc_node::config::{ConfigError, KeyDigest, Posture, V1Config, V1Serving};
use cc_node::serve_v1::{health_body, router_with, Serving, V1State};
use cc_testkit::v1::*;
use reqwest::{Method, StatusCode as S};
use serde_json::{json, Value as Json};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const WRITE: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const READ: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
const STRANGER: &str = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
/// A synthetic, visibly patterned node seed for these tests only. It has the
/// 16 distinct characters the placeholder check asks for.
const SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn seed_key() -> cc_core::SecretKey {
    cc_core::SecretKey::from_seed(hex::decode(SEED).unwrap().try_into().unwrap())
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
    async fn raw(&self, m: Method, path: &str, token: Option<&str>, body: &[u8]) -> (S, Vec<u8>) {
        let mut req = self
            .http
            .request(m, format!("{}{path}", self.base))
            .body(body.to_vec());
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let r = req.send().await.unwrap();
        (r.status(), r.bytes().await.unwrap().to_vec())
    }
    async fn read(&self, path: &str) -> (S, Vec<u8>) {
        self.raw(Method::GET, path, Some(READ), &[]).await
    }
    async fn json(&self, path: &str, token: Option<&str>) -> (S, Json) {
        let (s, b) = self.raw(Method::GET, path, token, &[]).await;
        (s, serde_json::from_slice(&b).unwrap())
    }
    async fn submit(&self, bytes: &[u8]) -> (S, Json) {
        let (s, b) = self
            .raw(Method::POST, "/v1/candidates", Some(WRITE), bytes)
            .await;
        (s, serde_json::from_slice(&b).unwrap())
    }
    async fn stop(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

/// Every read route, with ids that exist in the view fixture and ids that
/// do not, so both the found and the refused answers are compared.
fn read_paths() -> Vec<String> {
    let f = view_fixture();
    let (g, c, b) = (f[0].id(), f[1].id(), f[2].id());
    let h = hex::encode;
    let fold = fold_v1();
    vec![
        "/v1/snapshot".into(),
        format!(
            "/v1/snapshot?fold_version={}&fold_manifest={}",
            fold.version,
            h(fold.manifest)
        ),
        format!("/v1/subjects/{}", h(g)),
        format!("/v1/subjects/{}?as_of={}", h(g), h([60; 32])),
        format!("/v1/subjects/{}", h(b)),
        format!("/v1/subjects/{}", h([5; 32])),
        format!("/v1/revisions/{}/prose", h(revision_id(g, c))),
        format!("/v1/support?from={}&to={}", h(g), h(b)),
        format!(
            "/v1/support?from={}&to={}&as_of={}",
            h(b),
            h(g),
            h([60; 32])
        ),
    ]
}

/// The property over HTTP: after every admission, every read answered by the
/// caching node (twice: once filling, once from the cache) is byte-identical
/// to the same read answered by a node over the same database that never
/// caches.
#[tokio::test]
async fn served_reads_are_byte_identical_with_and_without_the_cache() {
    let (pool, cleanup, store) = bound().await;
    let cached = boot(&store, Serving::default()).await;
    let uncached = boot(&store.clone().uncached(), Serving::default()).await;
    let mut compared = 0usize;
    let mut admissions: Vec<Vec<u8>> = view_fixture().iter().map(|e| e.bytes().to_vec()).collect();
    // Out of order, a repeat and a rejection: pending, then valid, then no-ops.
    admissions.swap(0, 1);
    admissions.push(admissions[0].clone());
    admissions.push(b"not an envelope".to_vec());
    for (n, bytes) in admissions.iter().enumerate() {
        cached.submit(bytes).await;
        for path in read_paths() {
            let filling = cached.read(&path).await;
            let hit = cached.read(&path).await;
            let folded = uncached.read(&path).await;
            assert_eq!(filling, folded, "after admission {n}: {path}");
            assert_eq!(hit, folded, "after admission {n}: {path}");
            compared += 2;
        }
    }
    assert_eq!(compared, 2 * admissions.len() * read_paths().len());
    // The equality above was between a cache and a fold, not two folds.
    let (hits, misses) = store.cache_stats();
    assert!(hits > misses, "hits {hits}, misses {misses}");
    // One miss per admission at most: every later read on that corpus hit.
    assert!(misses <= admissions.len() as u64 + 1, "misses {misses}");
    cached.stop().await;
    uncached.stop().await;
    pool.close().await;
    cleanup.cleanup().await;
}

/// With every read permit held, reads are `503 busy` with `Retry-After`, at
/// once; the public probes and the write boundary still answer, and an
/// unauthenticated read is still 401. Releasing one permit restores reads.
#[tokio::test]
async fn a_full_read_limit_answers_busy_and_spares_health_ready_and_writes() {
    let (pool, cleanup, store) = bound().await;
    let serving = Serving::new(2, None);
    assert_eq!(Serving::default().read_permits().available_permits(), 8);
    let permits = serving.read_permits();
    let node = boot(&store, serving).await;
    assert_eq!(node.json("/v1/snapshot", Some(READ)).await.0, S::OK);

    let held = permits.clone().try_acquire_many_owned(2).unwrap();
    for path in read_paths()
        .into_iter()
        .chain(["/v1/receipts/00".into(), "/v1/no-such-route".into()])
    {
        let started = Instant::now();
        let r = node
            .http
            .get(format!("{}{path}", node.base))
            .bearer_auth(READ)
            .send()
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2), "{path} queued");
        assert_eq!(r.status(), S::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(r.headers()["retry-after"], "1", "{path}");
        let body: Json = serde_json::from_slice(&r.bytes().await.unwrap()).unwrap();
        assert_eq!(body, json!({"error": "busy"}));
    }
    // Authentication runs first: a stranger never reaches the limit.
    assert_eq!(
        node.json("/v1/snapshot", Some(STRANGER)).await.0,
        S::UNAUTHORIZED
    );
    assert_eq!(node.json("/v1/snapshot", None).await.0, S::UNAUTHORIZED);
    assert_eq!(node.json("/health", None).await.0, S::OK);
    assert_eq!(
        node.json("/ready", None).await,
        (S::OK, json!({"serving": true, "posture": "live"}))
    );
    let (status, _) = node.submit(genesis().bytes()).await;
    assert_eq!(status, S::CREATED);
    assert_eq!(node.json("/v1/export", Some(WRITE)).await.0, S::OK);

    drop(held);
    let one = permits.clone().try_acquire_owned().unwrap();
    assert_eq!(node.json("/v1/snapshot", Some(READ)).await.0, S::OK);
    drop(one);
    assert_eq!(permits.available_permits(), 2);
    node.stop().await;
    pool.close().await;
    cleanup.cleanup().await;
}

/// Two databases, the same submissions: one node with a seed, one without.
/// Submit answers and served snapshots are byte-identical; only the seeded
/// node serves a receipt, and it verifies and names its admission.
#[tokio::test]
async fn receipts_are_served_only_with_a_seed_and_change_no_commitment() {
    let (pool_on, cleanup_on, on_store) = bound().await;
    let (pool_off, cleanup_off, off_store) = bound().await;
    let on = boot(&on_store, Serving::new(8, Some(seed_key()))).await;
    let off = boot(&off_store, Serving::default()).await;
    let f = view_fixture();
    let (g, c) = (&f[0], &f[1]);
    // The correction first: pending on its missing genesis.
    for e in [c, g, g] {
        let a = on.submit(e.bytes()).await;
        assert_eq!(a, off.submit(e.bytes()).await);
    }
    for path in read_paths() {
        assert_eq!(on.read(&path).await, off.read(&path).await, "{path}");
    }

    let h = hex::encode;
    for (e, state, reason, missing) in [
        (g, "valid", "", vec![]),
        (c, "pending", "parent_missing", vec![h(g.id())]),
    ] {
        let path = format!("/v1/receipts/{}", h(e.id()));
        let (status, body) = on.json(&path, Some(READ)).await;
        assert_eq!(status, S::OK, "{body}");
        let receipts = body["receipts"].as_array().unwrap();
        assert_eq!(receipts.len(), 1, "a repeat submission was receipted");
        let r = &receipts[0];
        let bytes = hex::decode(r["receipt"].as_str().unwrap()).unwrap();
        let signed = SignedReceipt::decode(&bytes).unwrap();
        let n = signed.receipt();
        assert_eq!(n.node_key, seed_key().author().to_bytes());
        assert_eq!(n.event, e.id());
        assert_eq!(n.instance, INSTANCE);
        let expected = json!({
            "event": h(e.id()),
            "receipts": [{
                "receipt": hex::encode(&bytes),
                "receipt_digest": h(hash(&bytes)),
                "node_key": h(seed_key().author().to_bytes()),
                "event": h(e.id()),
                "received_at": n.received_at,
                "encoding_version": 1,
                "fold_version": {"version": 1, "manifest": h(fold_v1().manifest)},
                "initial_admission_result": {"state": state, "reason": reason, "missing": missing},
            }],
        });
        assert_eq!(body, expected);
        assert_eq!(
            off.json(&path, Some(READ)).await,
            (S::NOT_FOUND, json!({"error": "no_receipt"}))
        );
    }
    let unknown = format!("/v1/receipts/{}", h([7; 32]));
    assert_eq!(
        on.json(&unknown, Some(READ)).await,
        (S::NOT_FOUND, json!({"error": "no_receipt"}))
    );
    assert_eq!(
        on.json("/v1/receipts/zz", Some(READ)).await,
        (S::BAD_REQUEST, json!({"error": "invalid_event_id"}))
    );
    let extra = format!("/v1/receipts/{}?as_of=00", h(g.id()));
    assert_eq!(
        on.json(&extra, Some(READ)).await,
        (S::BAD_REQUEST, json!({"error": "invalid_query"}))
    );
    on.stop().await;
    off.stop().await;
    for p in [pool_on, pool_off] {
        p.close().await;
    }
    cleanup_on.cleanup().await;
    cleanup_off.cleanup().await;
}

fn env_of(pairs: &[(&'static str, &str)]) -> HashMap<&'static str, String> {
    let mut curators: Vec<String> = (0..4)
        .map(|k| hex::encode(key(k).author().to_bytes()))
        .collect();
    curators.sort();
    let mut env = HashMap::from([
        ("CC_V1_INSTANCE", hex::encode(INSTANCE)),
        ("CC_V1_CURATORS", curators.join(",")),
        ("DATABASE_URL", "postgres://unused".to_string()),
    ]);
    for (k, v) in pairs {
        env.insert(*k, v.to_string());
    }
    env
}

fn serving(pairs: &[(&'static str, &str)]) -> Result<V1Serving, ConfigError> {
    let env = env_of(pairs);
    let v1 = V1Config::from_lookup(|k| env.get(k).cloned()).unwrap();
    V1Serving::from_lookup(|k| env.get(k).cloned(), &v1)
}

#[test]
fn serving_configuration_is_parsed_strictly() {
    let default = serving(&[]).unwrap();
    assert_eq!(default.read_concurrency, 8);
    assert!(default.node_seed.is_none());
    for good in ["1", "8", "64"] {
        let c = serving(&[("CC_V1_READ_CONCURRENCY", good)]).unwrap();
        assert_eq!(c.read_concurrency.to_string(), good);
    }
    for bad in ["0", "65", "1024", "08", "+8", " 8", "8 ", "-1", "", "eight"] {
        assert!(
            matches!(
                serving(&[("CC_V1_READ_CONCURRENCY", bad)]),
                Err(ConfigError::V1ReadConcurrencyMalformed(_))
            ),
            "{bad:?}"
        );
    }
    let seeded = serving(&[("CC_V1_NODE_SEED", SEED)]).unwrap();
    let seed = seeded.node_seed.unwrap();
    assert_eq!(seed.public(), seed_key().author().to_bytes());
    // Debug names the public key and never the seed.
    let shown = format!("{seed:?}");
    assert!(shown.contains(&hex::encode(seed.public())));
    assert!(!shown.contains(SEED));
    let upper = SEED.to_uppercase();
    let padded = format!("{SEED} ");
    for bad in [&SEED[..62], &upper, &padded, "", &format!("{SEED}00")] {
        assert!(
            matches!(
                serving(&[("CC_V1_NODE_SEED", bad)]),
                Err(ConfigError::V1NodeSeedMalformed)
            ),
            "{bad:?}"
        );
    }
    assert!(matches!(
        serving(&[("CC_V1_NODE_SEED", &"ab".repeat(32))]),
        Err(ConfigError::V1NodeSeedWeak)
    ));
}

/// The curator check, with a curator set that holds the node seed's own key.
#[test]
fn a_seed_whose_key_is_a_curator_is_refused() {
    let mut curators = [seed_key().author().to_bytes(), key(0).author().to_bytes()];
    curators.sort();
    let joined = curators
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(",");
    let env = env_of(&[("CC_V1_CURATORS", &joined), ("CC_V1_NODE_SEED", SEED)]);
    let v1 = V1Config::from_lookup(|k| env.get(k).cloned()).unwrap();
    assert!(matches!(
        V1Serving::from_lookup(|k| env.get(k).cloned(), &v1),
        Err(ConfigError::V1NodeSeedIsCurator)
    ));
}

/// The URL of the ephemeral database behind `pool`.
async fn url_of(pool: &sqlx::PgPool) -> String {
    let base = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap();
    let name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .unwrap();
    format!("{}/{name}", base.rsplit_once('/').unwrap().0)
}

fn cc_node(env: &HashMap<&'static str, String>) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cc-node"));
    c.arg("serve")
        .env_clear()
        .envs(env)
        .env("CC_NODE_LEDGER", "v1")
        .env("CC_NODE_API_KEY", WRITE)
        .env("CC_NODE_READ_KEY", READ)
        .env("CC_NODE_POSTURE", "live")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

/// A spawned `cc-node`, killed when dropped, so a failing assertion never
/// leaves a server running.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Everything the process printed, with terminal colour codes removed.
fn output_of(child: &mut std::process::Child) -> String {
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut out).unwrap();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut out).unwrap();
    let mut plain = String::new();
    let mut chars = out.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // An SGR sequence: ESC '[' parameters 'm'.
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
}

/// The real binary: a malformed seed, a curator seed or a bad read limit is
/// exit 78 before binding, for the stated reason, and no refusal prints the
/// seed.
#[test]
fn the_binary_refuses_bad_serving_configuration_without_printing_the_seed() {
    let upper = SEED.to_uppercase();
    let mut curators = [seed_key().author().to_bytes(), key(0).author().to_bytes()];
    curators.sort();
    let joined = curators
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(",");
    for (env, reason) in [
        (
            env_of(&[("CC_V1_NODE_SEED", &upper)]),
            "CC_V1_NODE_SEED must be exactly 64 lowercase hex characters",
        ),
        (
            env_of(&[("CC_V1_NODE_SEED", &SEED[..63])]),
            "CC_V1_NODE_SEED must be exactly 64 lowercase hex characters",
        ),
        (
            env_of(&[("CC_V1_NODE_SEED", SEED), ("CC_V1_CURATORS", &joined)]),
            "CC_V1_NODE_SEED derives a curator key",
        ),
        (
            env_of(&[("CC_V1_READ_CONCURRENCY", "0")]),
            "CC_V1_READ_CONCURRENCY=\"0\" is not a read limit",
        ),
    ] {
        let mut child = Running(cc_node(&env).spawn().unwrap());
        let child = &mut child.0;
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            assert!(Instant::now() < deadline, "serve did not refuse");
            std::thread::sleep(Duration::from_millis(50));
        };
        let out = output_of(child);
        assert_eq!(status.code(), Some(78), "{out}");
        assert!(out.contains(reason), "{out}");
        assert!(!out.to_lowercase().contains(SEED), "the seed was printed");
        assert!(!out.contains(&SEED[..63]), "the seed was printed");
    }
}

/// The real binary with a seed: it boots, logs the public node key (never the
/// seed), and receipts a submission end to end; without one it logs `off`.
#[tokio::test]
async fn the_binary_receipts_with_a_seed_and_logs_only_the_public_key() {
    for seeded in [true, false] {
        let (pool, cleanup, _store) = bound().await;
        let url = url_of(&pool).await;
        let http = reqwest::Client::new();
        // A free port is found by binding and releasing it, so another
        // process can take it first; the child then fails to bind and exits,
        // and the attempt is repeated on a fresh port.
        let mut attempts = 0;
        let (mut child, base) = loop {
            attempts += 1;
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let port_s = port.to_string();
            let mut pairs = vec![("DATABASE_URL", url.as_str()), ("PORT", port_s.as_str())];
            if seeded {
                pairs.push(("CC_V1_NODE_SEED", SEED));
            }
            let mut child = Running(cc_node(&env_of(&pairs)).spawn().unwrap());
            let base = format!("http://127.0.0.1:{port}");
            let deadline = Instant::now() + Duration::from_secs(30);
            let listening = loop {
                // Only this child's identity counts as listening.
                if let Ok(r) = http.get(format!("{base}/health")).send().await {
                    let bytes = r.bytes().await.unwrap_or_default();
                    let health: Json = serde_json::from_slice(&bytes).unwrap_or_default();
                    if health["instance"] == hex::encode(INSTANCE) {
                        break true;
                    }
                }
                if child.0.try_wait().unwrap().is_some() {
                    break false;
                }
                assert!(Instant::now() < deadline, "serve never listened");
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            if listening {
                break (child, base);
            }
            let out = output_of(&mut child.0);
            assert!(out.contains("could not bind") && attempts < 3, "{out}");
        };
        let g = genesis();
        let posted = http
            .post(format!("{base}/v1/candidates"))
            .bearer_auth(WRITE)
            .body(g.bytes().to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(posted.status(), S::CREATED);
        let got = http
            .get(format!("{base}/v1/receipts/{}", hex::encode(g.id())))
            .bearer_auth(READ)
            .send()
            .await
            .unwrap();
        let expected = if seeded { S::OK } else { S::NOT_FOUND };
        assert_eq!(got.status(), expected);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let out = output_of(&mut child.0);
        let public = hex::encode(seed_key().author().to_bytes());
        let logged = if seeded { public.as_str() } else { "off" };
        assert!(out.contains(&format!("node_key={logged}")), "{out}");
        assert!(out.contains("read_concurrency=8"), "{out}");
        assert!(!out.contains(SEED), "the seed was printed");
        pool.close().await;
        cleanup.cleanup().await;
    }
}
