use cc_core::v1::*;
use cc_ledger::v1::{Outcome, Store};
use cc_testkit::v1::*;
use reqwest::StatusCode;

#[tokio::test]
async fn i7_http_import_admission_differential() {
    let (a, ca) = cc_testkit::ephemeral_empty_db().await;
    let (b, cb) = cc_testkit::ephemeral_empty_db().await;
    let (c, cc) = cc_testkit::ephemeral_empty_db().await;
    let http = Store::provision(a.clone(), INSTANCE).await.unwrap();
    let import = Store::provision(b.clone(), INSTANCE).await.unwrap();
    let restore = Store::provision(c.clone(), INSTANCE).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = cc_node::v1::review_router(
        http.clone(),
        cc_node::config::KeyDigest::of("synthetic-write"),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::new();
    let url = format!("http://{address}/v1/candidates");
    let g = genesis();
    let correction = correction(&g, &g, 0, 5);
    let wrong = cc_testkit::v1::correction(&g, &g, 1, 6);
    let mut bad = correction.bytes().to_vec();
    *bad.last_mut().unwrap() ^= 1;
    let mut changed = correction.envelope().clone();
    changed.subject_key.as_mut().unwrap().kind = "document".into();
    let changed = Signed::sign(&key(0), changed).unwrap();
    let mut foreign = g.envelope().clone();
    foreign.instance = [44; 32];
    let foreign = Signed::sign(&key(0), foreign).unwrap();
    let d = delegate(&g, &g, 0, root_grant(g.id()), 1);
    let sub = delegate(&g, &d, 1, d.id(), 2);
    let inner = revoke(&g, &sub, 1, d.id(), sub.id(), true);
    let outer = revoke(&g, &sub, 0, root_grant(g.id()), d.id(), false);
    let inputs = vec![
        inner.bytes().to_vec(),
        sub.bytes().to_vec(),
        correction.bytes().to_vec(),
        vec![0; 200],
        g.bytes().to_vec(),
        bad,
        correction.bytes().to_vec(),
        wrong.bytes().to_vec(),
        changed.bytes().to_vec(),
        foreign.bytes().to_vec(),
        g.bytes().to_vec(),
        d.bytes().to_vec(),
        outer.bytes().to_vec(),
        inner.bytes().to_vec(),
        sub.bytes().to_vec(),
    ];
    // Transport authentication is checked before decoding and adds no candidate.
    for token in [None, Some("synthetic-read")] {
        let mut req = client.post(&url).body(vec![0; 50]);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        assert_eq!(req.send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
    assert!(http.review().await.unwrap().is_empty());
    for wire in inputs {
        let response = client
            .post(&url)
            .bearer_auth("synthetic-write")
            .body(wire.clone())
            .send()
            .await
            .unwrap();
        let code = response.status();
        let outcome: Outcome = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let expected = import
            .import(std::slice::from_ref(&wire))
            .await
            .unwrap()
            .remove(0);
        let restored = restore
            .restore(std::slice::from_ref(&wire))
            .await
            .unwrap()
            .remove(0);
        assert_eq!(outcome, expected);
        assert_eq!(outcome, restored);
        let expected_code = match outcome.status.state {
            cc_ledger::v1::State::Valid => StatusCode::CREATED,
            cc_ledger::v1::State::Pending => StatusCode::ACCEPTED,
            cc_ledger::v1::State::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
        };
        assert_eq!(code, expected_code);
        assert_eq!(
            http.review_authority().await.unwrap(),
            import.review_authority().await.unwrap()
        );
        assert_eq!(
            http.review_authority().await.unwrap(),
            restore.review_authority().await.unwrap()
        );
        assert_eq!(http.review().await.unwrap(), import.review().await.unwrap());
        assert_eq!(
            http.review().await.unwrap(),
            restore.review().await.unwrap()
        );
    }
    assert_eq!(
        client
            .get(format!("http://{address}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        client
            .get(format!("http://{address}/v2/media"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    server.abort();
    let _ = server.await;
    a.close().await;
    b.close().await;
    c.close().await;
    ca.cleanup().await;
    cb.cleanup().await;
    cc.cleanup().await;
}
