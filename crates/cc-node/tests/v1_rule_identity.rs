//! Stage (e) I8: every commitment names the full rule identity; unknown or
//! incompatible fold/filter identities are refused, never reinterpreted.
use cc_core::v1::receipt::FoldRef;
use cc_core::v1::rule::{fold_v1, view_commitment};
use cc_core::v1::*;
use cc_ledger::v1::{Error, Snapshot, Store};
use cc_testkit::v1::*;
use reqwest::StatusCode;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

fn parse(bytes: impl AsRef<[u8]>) -> Json {
    serde_json::from_slice(bytes.as_ref()).unwrap()
}

#[tokio::test]
async fn i8_versioned_commitments_and_unknown_refusal() {
    let g = genesis();
    let c = correction(&g, &g, 0, 5);
    let b = subject(1, 50, 51);
    let e = edge(
        0,
        "influence",
        Pins {
            source: pin(&[&g, &c], &c),
            target: pin(&[&b], &b),
        },
    );
    let events: BTreeMap<_, _> = [&g, &c, &b, &e].map(|e| (e.id(), e.clone())).into();
    let base = filter();

    // Commitment, filter version and cache key are sensitive to every
    // identity component with the event set held fixed.
    let mut variants = vec![base.clone()];
    let mut push = |f: fn(&mut cc_filter::v1::FilterIdentity)| {
        let mut v = base.clone();
        f(&mut v);
        variants.push(v);
    };
    push(|v| v.fold.version = 2);
    push(|v| v.fold.manifest[0] ^= 1);
    push(|v| v.encoding = 0);
    push(|v| v.constants = 1);
    push(|v| v.ontology[0] ^= 1);
    push(|v| v.curators.truncate(3));
    push(|v| v.trust_policy.push('x'));
    push(|v| v.max_hops = 5);
    let snapshots: Vec<_> = variants.iter().map(|v| Snapshot::of(v, &events)).collect();
    for (field, set) in [
        (
            "filter_version",
            snapshots
                .iter()
                .map(|s| s.rule.filter_version)
                .collect::<BTreeSet<_>>(),
        ),
        (
            "commitment",
            snapshots.iter().map(|s| s.commitment).collect(),
        ),
        (
            "cache_key",
            snapshots.iter().map(|s| s.cache_key(b"q")).collect(),
        ),
    ] {
        assert_eq!(set.len(), variants.len(), "{field}");
    }
    // Corpus and rows are committed too.
    let mut fewer = events.clone();
    fewer.remove(&e.id());
    let s = &snapshots[0];
    let smaller = Snapshot::of(&base, &fewer);
    assert_ne!(
        (smaller.corpus_digest, smaller.commitment),
        (s.corpus_digest, s.commitment)
    );
    assert_ne!(
        view_commitment(&base.fold, s.rule.filter_version, s.corpus_digest, b"rows"),
        view_commitment(&base.fold, s.rule.filter_version, s.corpus_digest, b"rows'")
    );
    assert!(cc_filter::v1::FilterIdentity::governed(vec![], 4).is_err());

    // Store binding: unknown fold refused; another filter identity refused.
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let fresh = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    assert!(matches!(
        fresh.clone().bind(variants[1].clone()).await,
        Err(Error::UnsupportedFoldVersion)
    ));
    let store = fresh.clone().bind(base.clone()).await.unwrap();
    assert!(matches!(
        fresh.bind(variants[6].clone()).await,
        Err(Error::RuleIdentity)
    ));
    store
        .import(
            &events
                .values()
                .map(|e| e.bytes().to_vec())
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap();
    let stored = store.snapshot(Some(&fold_v1())).await.unwrap();
    assert_eq!(stored.commitment, s.commitment);
    for requested in [&variants[1].fold, &variants[2].fold] {
        assert!(matches!(
            store.snapshot(Some(requested)).await,
            Err(Error::UnsupportedFoldVersion)
        ));
    }

    // HTTP: health names the identity; an unknown requested fold is refused.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = cc_node::v1::review_router(
        store.clone(),
        cc_node::config::KeyDigest::of("synthetic-write"),
        cc_node::config::KeyDigest::of("synthetic-read"),
    );
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let get = |path: String| {
        client
            .get(format!("http://{address}{path}"))
            .bearer_auth("synthetic-read")
            .send()
    };
    let health: Json = parse(get("/health".into()).await.unwrap().bytes().await.unwrap());
    assert_eq!(health["readiness"]["semantic"], "ready");
    assert_eq!(health["readiness"]["serving"], false);
    assert_eq!(health["readiness"]["boundary"], "stage_e_non_serving");
    assert_eq!(health["commitment"], hex::encode(s.commitment));
    let manifest = |f: &FoldRef| {
        format!(
            "/v1/review?fold_version={}&fold_manifest={}",
            f.version,
            hex::encode(f.manifest)
        )
    };
    for f in [&variants[1].fold, &variants[2].fold] {
        let r = get(manifest(f)).await.unwrap();
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(r.text().await.unwrap(), "unsupported_fold_version");
    }
    let r: Json = parse(
        get(manifest(&fold_v1()))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    );
    assert_eq!(r["commitment"], hex::encode(s.commitment));
    let ready = client
        .get(format!("http://{address}/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ready.text().await.unwrap(), "stage_e_non_serving");
    assert!(matches!(store.readiness(), Err(Error::NonServing)));

    // Export/restore: unknown versions, tampered roots and another rule's
    // roots are refused before any admission; the exact root restores.
    let export = store.export(None).await.unwrap();
    let (pool2, cleanup2) = cc_testkit::ephemeral_empty_db().await;
    let target = Store::provision(pool2.clone(), INSTANCE).await.unwrap();
    let other = target.clone().bind(base.clone()).await.unwrap();
    let mut tampered = vec![];
    for f in 0..4 {
        let mut m = export.clone();
        match f {
            0 => m.rule.fold_version = 2,
            1 => m.rule.fold_manifest[0] ^= 1,
            2 => m.commitment[0] ^= 1,
            _ => m.rule.filter_version = Snapshot::of(&variants[6], &events).rule.filter_version,
        }
        tampered.push(m);
    }
    assert!(matches!(
        other.restore_export(&tampered[0]).await,
        Err(Error::UnsupportedFoldVersion)
    ));
    assert!(matches!(
        other.restore_export(&tampered[1]).await,
        Err(Error::UnsupportedFoldVersion)
    ));
    assert!(matches!(
        other.restore_export(&tampered[2]).await,
        Err(Error::RootMismatch)
    ));
    assert!(matches!(
        other.restore_export(&tampered[3]).await,
        Err(Error::RuleIdentity)
    ));
    assert_eq!(other.snapshot(None).await.unwrap().projection.rows.len(), 0);
    other.restore_export(&export).await.unwrap();
    assert_eq!(other.snapshot(None).await.unwrap().commitment, s.commitment);

    // An incompatible or unknown stored identity fails semantic readiness and
    // every versioned read; health still explains it.
    sqlx::raw_sql("ALTER TABLE cc_v1.rule_identity DISABLE TRIGGER immutable_rule_identity; UPDATE cc_v1.rule_identity SET filter_identity='\\x00'::bytea;")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store.semantic_readiness().await.unwrap().semantic,
        "incompatible_rule_identity"
    );
    assert!(matches!(
        store.snapshot(None).await,
        Err(Error::RuleIdentity)
    ));
    assert!(matches!(store.export(None).await, Err(Error::RuleIdentity)));
    let health: Json = parse(get("/health".into()).await.unwrap().bytes().await.unwrap());
    assert_eq!(
        health["readiness"]["semantic"],
        "incompatible_rule_identity"
    );
    assert!(health["commitment"].is_null());
    assert_eq!(
        get("/v1/review".into()).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE cc_v1.rule_identity SET fold_version=2, filter_identity=$1")
        .bind(base.canonical())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store.semantic_readiness().await.unwrap().semantic,
        "unsupported_fold_version"
    );
    assert!(matches!(
        store.snapshot(None).await,
        Err(Error::UnsupportedFoldVersion)
    ));
    // Unbound stores never produce a versioned read.
    let unbound = Store::provision(pool2.clone(), INSTANCE).await.unwrap();
    assert!(matches!(unbound.snapshot(None).await, Err(Error::Unbound)));
    assert_eq!(
        unbound.semantic_readiness().await.unwrap().semantic,
        "rule_identity_unbound"
    );
    server.abort();
    let _ = server.await;
    pool.close().await;
    pool2.close().await;
    cleanup.cleanup().await;
    cleanup2.cleanup().await;
}
