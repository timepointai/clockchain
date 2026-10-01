//! Stage (d) I7: edge, reaffirmation and media admission is identical through
//! HTTP, import and restore on real PostgreSQL; review shows edge reasons.
use cc_core::v1::*;
use cc_ledger::v1::{support_graph, Outcome, Store};
use cc_testkit::v1::*;
use reqwest::StatusCode;
use serde_json::Value as Json;
use std::collections::BTreeSet;

#[tokio::test]
async fn i7_edge_http_import_restore_admission_parity() {
    let (a_pool, ca) = cc_testkit::ephemeral_empty_db().await;
    let (b_pool, cb) = cc_testkit::ephemeral_empty_db().await;
    let (c_pool, cc) = cc_testkit::ephemeral_empty_db().await;
    let http = Store::provision(a_pool.clone(), INSTANCE).await.unwrap();
    let import = Store::provision(b_pool.clone(), INSTANCE).await.unwrap();
    let restore = Store::provision(c_pool.clone(), INSTANCE).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = cc_node::v1::review_router(
        http.clone(),
        cc_node::config::KeyDigest::of("synthetic-write"),
        cc_node::config::KeyDigest::of("synthetic-read"),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::new();
    let base = format!("http://{address}");

    let a = genesis();
    let b = subject(1, 50, 51);
    let pins = Pins {
        source: pin(&[&a], &a),
        target: pin(&[&b], &b),
    };
    let e = edge(0, "influence", pins.clone());
    let same = correction(&a, &a, 0, 3);
    let moved = Pins {
        source: pin(&[&a, &same], &same),
        target: pins.target.clone(),
    };
    let r1 = reaffirm(0, &e, &[&e], moved.clone());
    let r2 = reaffirm(0, &e, &[&e], pins.clone());
    let join = reaffirm(0, &e, &[&r1, &r2], moved.clone());
    let foreign = reaffirm(1, &e, &[&e], moved.clone());
    let mut wrong = pins.clone();
    wrong.target.body = [9; 32];
    let bad_pin = edge(0, "influence", wrong);
    let counter = subject(2, 70, 71);
    let dispute = edge(
        2,
        "disputes",
        Pins {
            source: pin(&[&counter], &counter),
            target: pins.source.clone(),
        },
    );
    let image = attest(
        0,
        TargetKind::Revision,
        revision_id(a.id(), a.id()),
        "image/png",
        60,
    );
    let late_media = attest(0, TargetKind::Event, same.id(), "image/png", 61);
    let mut bad_sig = e.bytes().to_vec();
    *bad_sig.last_mut().unwrap() ^= 1;
    let inputs = vec![
        join.bytes().to_vec(),
        r1.bytes().to_vec(),
        e.bytes().to_vec(),
        late_media.bytes().to_vec(),
        image.bytes().to_vec(),
        bad_sig,
        a.bytes().to_vec(),
        b.bytes().to_vec(),
        e.bytes().to_vec(),
        bad_pin.bytes().to_vec(),
        foreign.bytes().to_vec(),
        same.bytes().to_vec(),
        r2.bytes().to_vec(),
        dispute.bytes().to_vec(),
        counter.bytes().to_vec(),
        r1.bytes().to_vec(),
    ];
    let mut outcomes = vec![];
    for wire in inputs {
        let response = client
            .post(format!("{base}/v1/candidates"))
            .bearer_auth("synthetic-write")
            .body(wire.clone())
            .send()
            .await
            .unwrap();
        let code = response.status();
        let outcome: Outcome = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let imported = import
            .import(std::slice::from_ref(&wire))
            .await
            .unwrap()
            .remove(0);
        let restored = restore
            .restore(std::slice::from_ref(&wire))
            .await
            .unwrap()
            .remove(0);
        assert_eq!(outcome, imported);
        assert_eq!(outcome, restored);
        assert_eq!(
            code,
            match outcome.status.state {
                cc_ledger::v1::State::Valid => StatusCode::CREATED,
                cc_ledger::v1::State::Pending => StatusCode::ACCEPTED,
                cc_ledger::v1::State::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
            }
        );
        let view = http.review_projection().await.unwrap();
        assert_eq!(view, import.review_projection().await.unwrap());
        assert_eq!(view, restore.review_projection().await.unwrap());
        outcomes.push((outcome.status.state, outcome.status.reason));
    }
    use cc_ledger::v1::State::*;
    let expected = [
        (Pending, "parent_missing"),
        (Pending, "parent_missing"),
        (Pending, "pin_missing"),
        (Pending, "target_missing"),
        (Pending, "revision_missing"),
        (Invalid, "bad_signature"),
        (Valid, ""),
        (Valid, ""),
        (Valid, ""),
        (Invalid, "pin_body"),
        (Invalid, "edge_author"),
        (Valid, ""),
        (Valid, ""),
        (Pending, "pin_missing"),
        (Valid, ""),
        (Valid, ""),
    ];
    assert_eq!(outcomes, expected.map(|(s, r)| (s, r.to_owned())).to_vec());
    // Arrival results differ while dependencies are missing; final readings do not.
    let view = http.review_projection().await.unwrap();
    let edge = view.edges.iter().find(|x| x.edge == e.id()).unwrap();
    assert_eq!(
        (edge.status.as_str(), edge.heads.clone()),
        ("current", [join.id()].into())
    );
    assert_eq!(view.media.len(), 2);
    let curators: BTreeSet<_> = (0..4).map(|k| key(k).author().to_bytes()).collect();
    let graph = support_graph(&view, &curators);
    assert_eq!(
        graph,
        support_graph(&import.review_projection().await.unwrap(), &curators)
    );
    assert_eq!(graph.neighbors(a.id()).len(), 1);
    assert!(graph
        .excluded
        .iter()
        .any(|x| x.edge == bad_pin.id() && x.reasons == ["invalid:pin_body"]));
    assert!(graph.excluded.iter().any(|x| x.edge == dispute.id()
        && x.reasons == ["stale", "target:revision_changed", "disputes_not_support"]));

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
    assert_eq!(review["boundary"], "stage_d_non_serving");
    assert_eq!(review["edges"].as_array().unwrap().len(), 2);
    assert_eq!(review["media"].as_array().unwrap().len(), 2);
    let ready = client.get(format!("{base}/ready")).send().await.unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ready.text().await.unwrap(), "stage_d_non_serving");
    assert!(http.readiness().is_err());
    server.abort();
    let _ = server.await;
    for pool in [a_pool, b_pool, c_pool] {
        pool.close().await;
    }
    for c in [ca, cb, cc] {
        c.cleanup().await;
    }
}
