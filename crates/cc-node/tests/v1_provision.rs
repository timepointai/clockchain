//! v1 mode boot: `provision-v1` is idempotent and prints the identity, `serve`
//! reopens and verifies without initializing, every identity mismatch fails
//! closed, a database holding v0 tables is refused, `migrate` refuses in v1
//! mode, and configuration is parsed strictly. Driven through the real binary
//! (exit codes, stdout) and the library entry points over real PostgreSQL.
use cc_core::v1::rule::fold_v1;
use cc_ledger::v1::{Error, Store};
use cc_node::config::{ConfigError, Ledger, V1Config};
use cc_node::serve_v1::{self, BootError};
use cc_testkit::v1::{filter, key, INSTANCE};
use sqlx::PgPool;
use std::collections::HashMap;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const WRITE: &str = "7c1e9a52d04b38f6a1e5c9d2b7f04a63e8d1c5b9a2f7e04d6c3b8a1f5e9d2c7b";
const READ: &str = "8d2f0b63e15c49a7b2f6d0e3c8a15b74f9e2d6c0b3a8f15e7d4c9b2a6f0e3d8c";

/// The URL of the ephemeral database behind `pool`.
async fn url_of(pool: &PgPool) -> String {
    let base = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap();
    let name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .unwrap();
    format!("{}/{name}", base.rsplit_once('/').unwrap().0)
}

fn curators(keys: std::ops::Range<u8>) -> String {
    let mut hex: Vec<String> = keys
        .map(|k| hex::encode(key(k).author().to_bytes()))
        .collect();
    hex.sort();
    hex.join(",")
}

/// The v1 environment matching `cc_testkit::v1::filter()`.
fn v1_env(url: &str) -> HashMap<&'static str, String> {
    HashMap::from([
        ("CC_NODE_LEDGER", "v1".to_string()),
        ("DATABASE_URL", url.to_string()),
        ("CC_V1_INSTANCE", hex::encode(INSTANCE)),
        ("CC_V1_CURATORS", curators(0..4)),
    ])
}

fn config(env: &HashMap<&'static str, String>) -> Result<V1Config, ConfigError> {
    V1Config::from_lookup(|k| env.get(k).cloned())
}

fn cc_node(args: &[&str], env: &HashMap<&'static str, String>) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cc-node"));
    c.args(args).env_clear().envs(env).stdin(Stdio::null());
    c
}

fn run(args: &[&str], env: &HashMap<&'static str, String>) -> Output {
    cc_node(args, env).output().unwrap()
}

/// `serve` must exit on its own, before binding; a server still running after
/// the deadline has accepted a store it should have refused. Returns the exit
/// code and everything it printed, stdout and stderr.
fn serve_exit(env: &HashMap<&'static str, String>) -> (i32, String) {
    let mut env = env.clone();
    env.insert("CC_NODE_API_KEY", WRITE.into());
    env.insert("CC_NODE_READ_KEY", READ.into());
    env.insert("CC_NODE_POSTURE", "live".into());
    env.insert("PORT", "0".into());
    let mut child = cc_node(&["serve"], &env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut out = String::new();
            std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut out).unwrap();
            std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut out).unwrap();
            return (status.code().unwrap(), out);
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("serve kept running over a store it must refuse");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn rule_rows(pool: &PgPool) -> Vec<Vec<u8>> {
    sqlx::query_scalar("SELECT filter_identity FROM cc_v1.rule_identity")
        .fetch_all(pool)
        .await
        .unwrap()
}

/// Every stored identity byte: instance, encoding and schema hash, and the
/// full rule identity row.
async fn stored_identity(pool: &PgPool) -> Vec<String> {
    let sql = "SELECT concat_ws('|', encode(instance,'hex'), encoding, encode(schema_hash,'hex')) \
               FROM cc_v1.identity UNION ALL \
               SELECT concat_ws('|', fold_version, encode(fold_manifest,'hex'), \
               encode(filter_identity,'hex')) FROM cc_v1.rule_identity";
    sqlx::query_scalar(sql).fetch_all(pool).await.unwrap()
}

async fn has_v1_schema(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT to_regclass('cc_v1.identity') IS NOT NULL")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn provision_v1_is_idempotent_and_prints_the_identity() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let env = v1_env(&url_of(&pool).await);
    let first = run(&["provision-v1"], &env);
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let f = filter();
    assert_eq!(
        report,
        serde_json::json!({
            "instance": hex::encode(INSTANCE),
            "fold_version": {"version": fold_v1().version, "manifest": hex::encode(fold_v1().manifest)},
            "filter_version": hex::encode(f.version()),
            "semantic": "ready",
        })
    );
    // Repeating is a no-op with identical output.
    let second = run(&["provision-v1"], &env);
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(second.stdout, first.stdout);
    assert_eq!(rule_rows(&pool).await, vec![f.canonical()]);
    // And through the library entry point too.
    let again = serve_v1::provision(&config(&env).unwrap()).await.unwrap();
    assert_eq!(again.semantic, "ready");
    assert_eq!(rule_rows(&pool).await.len(), 1);
    // What serve opens is exactly what was provisioned.
    let (store, readiness) = serve_v1::open_store(&config(&env).unwrap()).await.unwrap();
    assert_eq!(readiness.semantic, "ready");
    assert_eq!(store.readiness().await.unwrap().filter_version, f.version());
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn identity_mismatch_fails_closed_in_provision_and_serve() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let env = v1_env(&url_of(&pool).await);
    assert_eq!(run(&["provision-v1"], &env).status.code(), Some(0));
    let bound = stored_identity(&pool).await;
    assert_eq!(bound.len(), 2);

    let mut fewer_curators = env.clone();
    fewer_curators.insert("CC_V1_CURATORS", curators(0..3));
    let mut other_instance = env.clone();
    other_instance.insert("CC_V1_INSTANCE", hex::encode([8u8; 32]));
    let mut other_hops = env.clone();
    other_hops.insert("CC_V1_MAX_HOPS", "5".into());

    for (label, bad, expected) in [
        ("curators", &fewer_curators, "incompatible_rule_identity"),
        ("instance", &other_instance, "v1_store_identity_mismatch"),
        ("max_hops", &other_hops, "incompatible_rule_identity"),
    ] {
        let cfg = config(bad).unwrap();
        // Library: provision and open both refuse, and say why.
        let p = serve_v1::provision(&cfg).await.unwrap_err();
        let o = serve_v1::open_store(&cfg).await.err().unwrap();
        for e in [&p, &o] {
            assert_eq!(e.exit_code(), 65, "{label}: {e}");
            assert_eq!(e.to_string(), expected, "{label}");
        }
        // Binary: provision-v1 exits non-zero; serve exits before binding.
        let out = run(&["provision-v1"], bad);
        assert_eq!(out.status.code(), Some(65), "{label}");
        assert!(out.stdout.is_empty(), "{label}");
        assert!(String::from_utf8_lossy(&out.stderr).contains(expected));
        let (code, err) = serve_exit(bad);
        assert_eq!(code, 65, "{label}: {err}");
        assert!(err.contains(expected), "{label}: {err}");
        // Nothing was rebound: every stored identity byte is unchanged.
        assert_eq!(stored_identity(&pool).await, bound, "{label}");
    }
    assert!(matches!(
        Store::open(pool.clone(), [8; 32], filter()).await,
        Err(Error::Identity)
    ));
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn serve_never_initializes_a_store() {
    // Empty database: no schema is created.
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let env = v1_env(&url_of(&pool).await);
    let (code, err) = serve_exit(&env);
    assert_eq!(code, 65, "{err}");
    assert!(err.contains("v1_store_unprovisioned"), "{err}");
    assert!(!has_v1_schema(&pool).await);

    // Provisioned but never bound: no rule identity is recorded.
    Store::provision(pool.clone(), INSTANCE).await.unwrap();
    let (code, err) = serve_exit(&env);
    assert_eq!(code, 65, "{err}");
    assert!(err.contains("rule_identity_unbound"), "{err}");
    assert!(rule_rows(&pool).await.is_empty());
    assert!(matches!(
        Store::open(pool.clone(), INSTANCE, filter()).await,
        Err(Error::Unbound)
    ));
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn a_database_with_v0_tables_is_refused() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let env = v1_env(&url_of(&pool).await);
    let out = run(&["provision-v1"], &env);
    assert_eq!(out.status.code(), Some(73));
    assert!(String::from_utf8_lossy(&out.stderr).contains("v1_requires_fresh_store"));
    assert!(!has_v1_schema(&pool).await);
    let e = serve_v1::open_store(&config(&env).unwrap())
        .await
        .err()
        .unwrap();
    assert!(matches!(e, BootError::Store(Error::NotEmpty)), "{e}");
    let (code, _) = serve_exit(&env);
    assert_eq!(code, 73);
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn migrate_refuses_in_v1_mode() {
    let migrations = |pool: PgPool| async move {
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let env = v1_env(&url_of(&pool).await);
    let out = run(&["migrate"], &env);
    assert_eq!(out.status.code(), Some(78));
    assert!(String::from_utf8_lossy(&out.stderr).contains("provision-v1"));
    assert!(!migrations(pool.clone()).await);

    // Control: the same database without CC_NODE_LEDGER is migrated, so the
    // probe above can see migrations when they happen.
    let mut legacy = env.clone();
    legacy.remove("CC_NODE_LEDGER");
    let out = run(&["migrate"], &legacy);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(migrations(pool.clone()).await);
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn serve_v1_mounts_only_the_v1_surface() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let mut env = v1_env(&url_of(&pool).await);
    assert_eq!(run(&["provision-v1"], &env).status.code(), Some(0));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    env.insert("CC_NODE_API_KEY", WRITE.into());
    env.insert("CC_NODE_READ_KEY", READ.into());
    env.insert("CC_NODE_POSTURE", "frozen".into());
    env.insert("PORT", port.to_string());
    let mut child = cc_node(&["serve"], &env)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let health = loop {
        if let Ok(r) = client.get(format!("{base}/health")).send().await {
            break r;
        }
        assert!(child.try_wait().unwrap().is_none(), "serve exited");
        assert!(Instant::now() < deadline, "serve never answered");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let health: serde_json::Value = serde_json::from_slice(&health.bytes().await.unwrap()).unwrap();
    let f = filter();
    assert_eq!(health["ledger"], "v1");
    assert_eq!(health["posture"], "frozen");
    assert_eq!(health["instance"], hex::encode(INSTANCE));
    assert_eq!(health["filter_version"], hex::encode(f.version()));
    assert_eq!(health["max_hops"], 4);
    assert_eq!(health["semantic"], "ready");
    assert_eq!(
        health["curators"],
        serde_json::json!(f.curators.iter().map(hex::encode).collect::<Vec<_>>())
    );
    let ready = client.get(format!("{base}/ready")).send().await.unwrap();
    assert_eq!(ready.status(), 200);
    // v0 routes are not mounted: the full key gets the v1 fallback's 404.
    for (method, path) in [
        ("GET", "/v1/moments?as_of=0"),
        ("GET", "/health/deep"),
        ("POST", "/v1/events"),
    ] {
        let r = client
            .request(method.parse().unwrap(), format!("{base}{path}"))
            .bearer_auth(WRITE)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{path}");
    }
    // Frozen: a write is refused by the real binary too.
    let r = client
        .post(format!("{base}/v1/candidates"))
        .bearer_auth(WRITE)
        .body(vec![0u8; 8])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    child.kill().unwrap();
    let _ = child.wait();
    pool.close().await;
    cleanup.cleanup().await;
}

#[test]
fn v1_configuration_is_strict() {
    let ledger = |v: Option<&str>| Ledger::from_lookup(|_| v.map(str::to_string));
    assert_eq!(ledger(None).unwrap(), Ledger::Legacy);
    assert_eq!(ledger(Some("v1")).unwrap(), Ledger::V1);
    for bad in ["V1", "v0", "", " v1", "legacy"] {
        assert!(
            matches!(ledger(Some(bad)), Err(ConfigError::LedgerUnrecognized(_))),
            "{bad:?}"
        );
    }

    let good = v1_env("postgres://synthetic/db");
    let c = config(&good).unwrap();
    assert_eq!(c.instance, INSTANCE);
    assert_eq!(c.filter, filter());
    assert_eq!(c.filter.max_hops, 4);
    let with = |k: &'static str, v: &str| {
        let mut e = good.clone();
        e.insert(k, v.to_string());
        config(&e)
    };
    let without = |k: &'static str| {
        let mut e = good.clone();
        e.remove(k);
        config(&e)
    };
    assert_eq!(with("CC_V1_MAX_HOPS", "6").unwrap().filter.max_hops, 6);
    assert!(matches!(
        without("DATABASE_URL"),
        Err(ConfigError::DatabaseAbsent)
    ));
    assert!(matches!(
        without("CC_V1_INSTANCE"),
        Err(ConfigError::V1InstanceAbsent)
    ));
    assert!(matches!(
        without("CC_V1_CURATORS"),
        Err(ConfigError::V1CuratorsAbsent)
    ));
    let upper = hex::encode(INSTANCE).to_uppercase().replace('9', "A");
    for bad in [
        &hex::encode([9u8; 31]),
        &upper,
        &format!(" {}", hex::encode(INSTANCE)),
    ] {
        assert!(
            matches!(
                with("CC_V1_INSTANCE", bad),
                Err(ConfigError::V1InstanceMalformed)
            ),
            "{bad:?}"
        );
    }
    let sorted: Vec<String> = curators(0..4).split(',').map(str::to_string).collect();
    for bad in [
        format!("{}, {}", sorted[0], sorted[1]),
        format!("{},", sorted[0]),
        String::new(),
        sorted[0].to_uppercase(),
    ] {
        assert!(
            matches!(
                with("CC_V1_CURATORS", &bad),
                Err(ConfigError::V1CuratorsMalformed)
            ),
            "{bad:?}"
        );
    }
    for bad in [
        format!("{},{}", sorted[1], sorted[0]),
        format!("{},{}", sorted[0], sorted[0]),
        hex::encode([2u8; 32]),
    ] {
        assert!(
            matches!(
                with("CC_V1_CURATORS", &bad),
                Err(ConfigError::V1FilterIdentity(_))
            ),
            "{bad:?}"
        );
    }
    assert!(matches!(
        with("CC_V1_MAX_HOPS", "0"),
        Err(ConfigError::V1FilterIdentity(_))
    ));
    for bad in ["+4", " 4", "4 ", "04", "four", "", "65536", "-1"] {
        assert!(
            matches!(
                with("CC_V1_MAX_HOPS", bad),
                Err(ConfigError::V1MaxHopsMalformed(_))
            ),
            "{bad:?}"
        );
    }

    // The binary exits 78 on bad configuration, whatever the subcommand.
    let mut bogus = good.clone();
    bogus.insert("CC_NODE_LEDGER", "v2".into());
    for args in [&["migrate"][..], &["provision-v1"], &["serve"]] {
        assert_eq!(run(args, &bogus).status.code(), Some(78), "{args:?}");
    }
    let mut unsorted = good.clone();
    unsorted.insert("CC_V1_CURATORS", format!("{},{}", sorted[1], sorted[0]));
    assert_eq!(run(&["provision-v1"], &unsorted).status.code(), Some(78));
    let (code, err) = serve_exit(&unsorted);
    assert_eq!(code, 78, "{err}");
    let mut legacy = good.clone();
    legacy.remove("CC_NODE_LEDGER");
    assert_eq!(run(&["provision-v1"], &legacy).status.code(), Some(78));
    // A set but non-UTF-8 ledger value is refused, never read as absent.
    use std::os::unix::ffi::OsStrExt;
    let mut c = cc_node(&["migrate"], &legacy);
    c.env("CC_NODE_LEDGER", std::ffi::OsStr::from_bytes(b"v1\xff"));
    assert_eq!(c.output().unwrap().status.code(), Some(78));
    // A database that cannot be reached is 69, not a configuration error.
    let mut unreachable = good.clone();
    unreachable.insert(
        "DATABASE_URL",
        "postgres://synthetic:synthetic@127.0.0.1:9/none".into(),
    );
    assert_eq!(run(&["provision-v1"], &unreachable).status.code(), Some(69));
}

#[tokio::test]
async fn a_partial_identity_is_an_identity_refusal() {
    // Identity row missing.
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let env = v1_env(&url_of(&pool).await);
    assert_eq!(run(&["provision-v1"], &env).status.code(), Some(0));
    let gut = "ALTER TABLE cc_v1.identity DISABLE TRIGGER immutable_identity; \
               DELETE FROM cc_v1.identity;";
    sqlx::raw_sql(gut).execute(&pool).await.unwrap();
    assert_eq!(run(&["provision-v1"], &env).status.code(), Some(65));
    assert_eq!(serve_exit(&env).0, 65);
    pool.close().await;
    cleanup.cleanup().await;

    // Rule identity table missing.
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let env = v1_env(&url_of(&pool).await);
    assert_eq!(run(&["provision-v1"], &env).status.code(), Some(0));
    sqlx::raw_sql("DROP TABLE cc_v1.rule_identity")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(run(&["provision-v1"], &env).status.code(), Some(65));
    assert_eq!(serve_exit(&env).0, 65);
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn boot_failures_print_no_credentials() {
    const PASSWORD: &str = "SyntheticDatabasePassw0rdXq7";
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let real = url_of(&pool).await;
    let (head, tail) = real.split_once('@').unwrap();
    let user = head.rsplit_once(':').unwrap().0;
    let unreachable = format!("postgres://synthetic:{PASSWORD}@127.0.0.1:9/none");
    let wrong_password = format!("{user}:{PASSWORD}@{tail}");
    let mut bad_config = v1_env(&unreachable);
    bad_config.insert("CC_V1_CURATORS", "not-a-key".into());
    let leaked = |label: &str, out: &str| {
        for secret in [PASSWORD, WRITE, READ] {
            assert!(!out.contains(secret), "{label} printed a credential: {out}");
        }
    };
    for (label, env, expected) in [
        ("unreachable", v1_env(&unreachable), 69),
        ("wrong password", v1_env(&wrong_password), 69),
        ("bad config", bad_config, 78),
    ] {
        let out = run(&["provision-v1"], &env);
        assert_eq!(out.status.code(), Some(expected), "provision {label}");
        let printed = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        leaked(label, &printed);
        let (code, printed) = serve_exit(&env);
        assert_eq!(code, expected, "serve {label}: {printed}");
        leaked(label, &printed);
    }
    pool.close().await;
    cleanup.cleanup().await;
}
