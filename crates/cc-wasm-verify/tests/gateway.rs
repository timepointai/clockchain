//! The explorer's contract, end to end: the real `cc-gateway` on a loopback
//! socket in front of the real v1 node over real PostgreSQL. Every recorded
//! fixture file must equal what the gateway serves on the matching
//! `/public/v1` route, and what the gateway serves must verify.
mod common;
use cc_gateway::{config::Config, router, Gateway};
use cc_wasm_verify::{verify, Input, Outcome, Read, Status};
use common::*;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;

/// The `/public/v1` route a recorded fixture file stands for.
fn route(file: &str) -> Option<String> {
    let p = "/public/v1";
    let name = file.strip_suffix(".json")?;
    Some(match name.split('/').collect::<Vec<_>>()[..] {
        ["health"] => format!("{p}/health"),
        ["snapshot"] => format!("{p}/snapshot"),
        ["export"] => return None,
        ["subjects", s] => match s.split_once(".as_of.") {
            Some((id, q)) => format!("{p}/subjects/{id}?as_of={q}"),
            None => format!("{p}/subjects/{s}"),
        },
        ["revisions", r, "prose"] => format!("{p}/revisions/{r}/prose"),
        ["support", pair] => {
            let (f, t) = pair.split_once('-')?;
            format!("{p}/support?from={f}&to={t}")
        }
        _ => panic!("unmapped fixture file {file}"),
    })
}

fn files(dir: &Path, base: &Path, out: &mut Vec<String>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            files(&p, base, out);
        } else {
            out.push(p.strip_prefix(base).unwrap().to_str().unwrap().to_string());
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_serves_the_recorded_fixture_and_it_verifies() {
    let live = live().await;
    let env = [
        ("CC_GATEWAY_NODE_URL", live.node.base.clone()),
        ("CC_GATEWAY_READ_KEY", READ.to_string()),
        ("CC_GATEWAY_RATE_PER_MINUTE", "100000".to_string()),
        ("CC_GATEWAY_FRESHNESS_MS", "0".to_string()),
    ];
    let config =
        Config::from_lookup(|k| env.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(Gateway::new(&config)).into_make_service_with_connect_info::<SocketAddr>();
    let gateway = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = reqwest::Client::new();

    let dir = fixture_dir();
    let mut recorded = vec![];
    files(&dir, &dir, &mut recorded);
    recorded.sort();
    let mut served = std::collections::BTreeMap::new();
    for file in &recorded {
        let Some(path) = route(file) else { continue };
        // No credential: the public surface.
        let r = http.get(format!("{base}{path}")).send().await.unwrap();
        let (status, text) = (r.status().as_u16(), r.text().await.unwrap());
        assert_eq!(status, 200, "{path}: {text}");
        let mut got: Value = serde_json::from_str(&text).unwrap();
        let want: Value = serde_json::from_slice(&std::fs::read(dir.join(file)).unwrap()).unwrap();
        if file == "health.json" {
            assert!(got.get("instance").is_none(), "the gateway strips instance");
            got["build"] = want["build"].clone();
        }
        assert_eq!(got, want, "{file} differs from {path} on the gateway");
        served.insert(file.clone(), text);
    }
    assert_eq!(
        served.len(),
        recorded.len() - 1,
        "every file but the export is a public route"
    );

    let reads: Vec<Read> = served
        .iter()
        .filter_map(|(f, body)| {
            let kind = match f.split('/').next()? {
                "subjects" => "subject",
                "revisions" => "prose",
                "support" => "support",
                _ => return None,
            };
            Some(Read {
                kind: kind.into(),
                body: body.clone(),
            })
        })
        .collect();
    assert_eq!(reads.len(), served.len() - 2);
    let input = Input {
        health: served["health.json"].clone(),
        snapshot: served["snapshot.json"].clone(),
        export: None,
        reads,
    };
    // Public reads alone: every check but signatures passes.
    let r = verify(&input);
    assert_eq!(r.outcome, Outcome::Partial, "{r:#?}");
    for c in &r.checks {
        let want = if c.name == "signatures" {
            Status::NotChecked
        } else {
            Status::Pass
        };
        assert_eq!(c.status, want, "{c:?}");
    }
    // With the owner's export from the node, signatures verify too.
    let (_, export) = live.node.get("/v1/export", WRITE).await;
    let r = verify(&Input {
        export: Some(String::from_utf8(export).unwrap()),
        ..input
    });
    assert_eq!(r.outcome, Outcome::Verified, "{r:#?}");

    gateway.abort();
    live.stop().await;
}
