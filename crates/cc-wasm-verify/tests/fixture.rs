//! Records the explorer's synthetic fixture from the real v1 node over real
//! PostgreSQL, and verifies what the node actually serves.
//!
//! The corpus is synthetic: fictional subjects under real TT kinds, keys from
//! `cc-testkit` seeds, a synthetic instance. It covers the reading kinds the
//! explorer renders: a corrected subject with prose and an asserted time, a
//! second subject, a delegation, an edge in each direction (one a dispute), a
//! revision attestation, a pending candidate and an invalid one.
//!
//! Without `CC_RECORD_FIXTURE=1` the test compares every recorded file with
//! what the node serves now (as JSON values), so a change in the node's read
//! contract or projection fails here. With it, the files are rewritten.
mod common;
use cc_core::v1::rule::fold_v1;
use cc_testkit::v1::{filter, INSTANCE};
use cc_wasm_verify::{verify, Input, Outcome, Read, Status};
use common::*;
use serde_json::Value;

#[tokio::test(flavor = "multi_thread")]
async fn recorded_fixture_is_what_the_node_serves_and_verifies() {
    let Live {
        pool,
        cleanup,
        store,
        corpus: c,
        node,
        server,
    } = live().await;

    // `/health` minus `instance`, with the build pinned: the G5 contract.
    let (status, health) = node.get("/health", READ).await;
    assert_eq!(status, 200);
    let mut health: Value = serde_json::from_slice(&health).unwrap();
    assert_eq!(health["instance"], hex::encode(INSTANCE));
    health.as_object_mut().unwrap().remove("instance");
    health["build"] = BUILD.into();
    let mut recorded = vec![(
        "health.json".to_string(),
        serde_json::to_vec(&health).unwrap(),
    )];

    let (_, snapshot) = node.get("/v1/snapshot", READ).await;
    let snapshot_json: Value = serde_json::from_slice(&snapshot).unwrap();
    for (file, path) in routes(&c, &snapshot_json) {
        let (status, body) = node.get(&path, READ).await;
        assert_eq!(status, 200, "{path}");
        recorded.push((file, body));
    }
    // The as_of reads exercise both answers of the visibility rule.
    let mut visibility: Vec<(String, String)> = recorded
        .iter()
        .filter(|(f, _)| f.contains(".as_of."))
        .map(|(f, b)| {
            let v: Value = serde_json::from_slice(b).unwrap();
            let day = &f[f.len() - 69..f.len() - 5];
            (
                day.to_string(),
                v["visibility"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    visibility.sort();
    let after = visibility
        .iter()
        .filter(|(_, v)| v == "after_as_of")
        .count();
    let visible = visibility.iter().filter(|(_, v)| v == "visible").count();
    assert_eq!((after, visible), (3, 3), "{visibility:?}");
    // Not a /public/v1 route: the owner's export, the optional signature input.
    let (status, export) = node.get("/v1/export", WRITE).await;
    assert_eq!(status, 200);
    recorded.push(("export.json".into(), export.clone()));

    // The corpus exercises what the explorer renders.
    let rows = snapshot_json["rows"].as_array().unwrap();
    let states: Vec<&str> = rows.iter().map(|r| r["state"].as_str().unwrap()).collect();
    for s in ["head", "superseded", "pending", "invalid"] {
        assert!(states.contains(&s), "fixture lacks a {s} row: {states:?}");
    }
    assert_eq!(rows.len(), c.events.len());
    assert_eq!(snapshot_json["edges"].as_array().unwrap().len(), 2);
    assert_eq!(snapshot_json["media"].as_array().unwrap().len(), 1);

    // What the node serves verifies, under every check that can run.
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).unwrap();
    let reads: Vec<Read> = recorded
        .iter()
        .filter_map(|(f, b)| {
            let kind = if f.starts_with("subjects/") {
                "subject"
            } else if f.starts_with("revisions/") {
                "prose"
            } else if f.starts_with("support/") {
                "support"
            } else {
                return None;
            };
            Some(Read {
                kind: kind.into(),
                body: text(b),
            })
        })
        .collect();
    let input = Input {
        health: text(&recorded[0].1),
        snapshot: text(&snapshot),
        export: Some(text(&export)),
        reads,
    };
    let report = verify(&input);
    assert_eq!(report.outcome, Outcome::Verified, "{report:#?}");
    assert_eq!(report.recomputed.events, c.events.len());
    assert_eq!(report.recomputed.signatures, c.events.len());
    // The recomputed roots are the node's own, computed by the ledger.
    let s = store.snapshot(Some(&fold_v1())).await.unwrap();
    assert_eq!(
        report.recomputed.commitment,
        Some(hex::encode(s.commitment))
    );
    assert_eq!(
        report.recomputed.corpus_digest,
        Some(hex::encode(s.corpus_digest))
    );
    assert_eq!(
        report.recomputed.filter_version,
        Some(hex::encode(filter().version()))
    );
    // Without the export, signatures are reported as not checked, not passed.
    let report = verify(&Input {
        export: None,
        ..input
    });
    assert_eq!(report.outcome, Outcome::Partial);
    assert_eq!(report.status("signatures"), Some(Status::NotChecked));

    let dir = fixture_dir();
    if std::env::var("CC_RECORD_FIXTURE").as_deref() == Ok("1") {
        let _ = std::fs::remove_dir_all(&dir);
        for (file, body) in &recorded {
            let path = dir.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
    } else {
        for (file, body) in &recorded {
            let path = dir.join(file);
            let committed = std::fs::read(&path)
                .unwrap_or_else(|_| panic!("{file} is not recorded; run with CC_RECORD_FIXTURE=1"));
            let a: Value = serde_json::from_slice(&committed).unwrap();
            let b: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(a, b, "{file} differs from what the node serves now");
        }
        let count = walk(&dir);
        assert_eq!(count, recorded.len(), "unexpected extra fixture files");
    }

    server.abort();
    pool.close().await;
    cleanup.cleanup().await;
}

fn walk(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p)
            } else {
                1
            }
        })
        .sum()
}
