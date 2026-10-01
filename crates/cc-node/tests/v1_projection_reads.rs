use cc_core::v1::*;
use cc_ledger::v1::Store;
use cc_testkit::v1::*;
use reqwest::StatusCode;
use serde_json::Value as Json;

#[tokio::test]
async fn i3_all_event_review_and_verified_revision_prose_stay_non_serving() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let store = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    let text = b"Synthetic body for software tests.";
    let mut e = genesis().envelope().clone();
    if let Payload::Genesis { body, .. } = &mut e.payload {
        *body = hash(text);
    }
    let g = Signed::sign(&key(0), e).unwrap();
    let a = correction(&g, &g, 0, 7);
    let b = correction(&g, &g, 0, 8);
    let s = resolve(
        &g,
        &[&a, &b],
        0,
        root_grant(g.id()),
        Selection::Revision(revision_id(g.id(), g.id())),
    );
    let wrong = correction(&g, &g, 1, 9);
    let absent = correction(&g, &a, 0, 10);
    let pending = correction(&g, &absent, 0, 11);
    store
        .import(&[
            s.bytes().to_vec(),
            pending.bytes().to_vec(),
            wrong.bytes().to_vec(),
            b.bytes().to_vec(),
            a.bytes().to_vec(),
            g.bytes().to_vec(),
        ])
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = cc_node::v1::review_router(
        store.clone(),
        cc_node::config::KeyDigest::of("synthetic-write"),
        cc_node::config::KeyDigest::of("synthetic-read"),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::new();
    let base = format!("http://{address}");
    for path in [
        "/v1/review",
        &format!(
            "/v1/revisions/{}/prose",
            hex::encode(revision_id(g.id(), g.id()))
        ),
    ] {
        assert_eq!(
            client
                .get(format!("{base}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        client
            .post(format!("{base}/v1/candidates"))
            .bearer_auth("synthetic-read")
            .body(g.bytes().to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let review: Json = serde_json::from_slice(
        &client
            .get(format!("{base}/v1/review"))
            .bearer_auth("synthetic-read")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    let rows = review["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    let find = |id| {
        rows.iter()
            .find(|r| r["event"] == serde_json::json!(id))
            .unwrap()
    };
    assert_eq!(find(s.id())["state"], "head");
    assert_eq!(find(g.id())["state"], "superseded");
    assert_eq!(find(wrong.id())["reason"], "parent_authority");
    assert_eq!(find(pending.id())["state"], "pending");
    assert_eq!(
        find(s.id())["envelope"],
        serde_json::to_value(s.envelope()).unwrap()
    );
    let url = format!(
        "{base}/v1/revisions/{}/prose",
        hex::encode(revision_id(g.id(), g.id()))
    );
    let prose: Json = serde_json::from_slice(
        &client
            .get(&url)
            .bearer_auth("synthetic-read")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(prose["availability"], "unavailable");
    assert!(prose["prose"].is_null());
    let before = store.review_projection().await.unwrap();
    assert!(store
        .retain_body(hash(text), b"mismatching bytes")
        .await
        .is_err());
    store.retain_body(hash(text), text).await.unwrap();
    store.retain_body(hash(text), text).await.unwrap();
    assert_eq!(before, store.review_projection().await.unwrap());
    let prose: Json = serde_json::from_slice(
        &client
            .get(&url)
            .bearer_auth("synthetic-read")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(prose["availability"], "available");
    assert_eq!(prose["prose"], std::str::from_utf8(text).unwrap());
    assert_eq!(
        client
            .get(format!(
                "{base}/v1/revisions/{}/prose",
                hex::encode([44; 32])
            ))
            .bearer_auth("synthetic-read")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .get(format!("{base}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(store.readiness().is_err());
    assert!(sqlx::query("DELETE FROM cc_v1.bodies")
        .execute(&pool)
        .await
        .is_err());
    // A DB owner can tamper; the read verifies bytes instead of trusting storage.
    sqlx::raw_sql("ALTER TABLE cc_v1.bodies DISABLE TRIGGER immutable_bodies; UPDATE cc_v1.bodies SET bytes='corrupt'::bytea;").execute(&pool).await.unwrap();
    assert_eq!(
        client
            .get(&url)
            .bearer_auth("synthetic-read")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    server.abort();
    let _ = server.await;
    pool.close().await;
    cleanup.cleanup().await;
}
