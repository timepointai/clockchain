//! G3 content authoring against the real v1 node (`cc_node::serve_v1`, booted
//! in-process over real PostgreSQL). Synthetic keys and data only.
//!
//! Every packet goes through `submit-packet` (library or binary) with the
//! owner's approval digest; the node's own snapshot and support routes are the
//! oracle for staleness, dispute exclusion and media binding.
use axum::{
    body::Body,
    extract::{Request, State},
    http::header,
    middleware::{self, Next},
    response::Response,
};
use cc_core::v1::{hash, revision_id, Hash, Kind, Signed, TargetKind};
use cc_core::SecretKey;
use cc_ledger::v1::Store;
use cc_node::config::{KeyDigest, Posture, V1Config};
use cc_node::serve_v1::{self, V1State};
use cc_publisher::v1::attest::{self, AttestInput};
use cc_publisher::v1::correction::{self, CorrectionInput};
use cc_publisher::v1::edge::{self, AssertInput, ReaffirmInput};
use cc_publisher::v1::entry_context::Context;
use cc_publisher::v1::entry_packet::Packet;
use cc_publisher::v1::genesis::{self, GenesisInput};
use cc_publisher::v1::node::Node;
use cc_publisher::v1::{entry, entry_submit, hash_json, key, time};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

const WRITE: &str = "synthetic-write";
const READ: &str = "synthetic-read";
const INSTANCE: Hash = [7; 32];
const EVIDENCE: Hash = [0xee; 32];

/// How the node's `/v1/snapshot` and `/v1/export` answer: honestly, with
/// every snapshot row pending, or echoing the write token into edge reasons
/// and unverified export fields.
const HONEST: u8 = 0;
const ROWS_PENDING: u8 = 1;
const ECHO_TOKEN: u8 = 2;

struct TestNode {
    url: String,
    lie: Arc<AtomicU8>,
    _cleanup: cc_testkit::Cleanup,
}
/// Rewrite `/v1/snapshot` as a misbehaving node would; the real node cannot
/// be configured to.
async fn lying(State(lie): State<Arc<AtomicU8>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let response = next.run(req).await;
    let mode = lie.load(Ordering::SeqCst);
    if !matches!(path.as_str(), "/v1/snapshot" | "/v1/export") || mode == HONEST {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let mut v: Value = serde_json::from_slice(&bytes).unwrap();
    if path == "/v1/export" {
        if mode == ECHO_TOKEN {
            v["commitment"] = json!(WRITE);
            v["encoding"] = json!(WRITE);
            v["rule"]["echo"] = json!(WRITE);
        }
    } else if mode == ROWS_PENDING {
        for r in v["rows"].as_array_mut().unwrap() {
            r["state"] = json!("pending");
        }
    } else {
        for e in v["edges"].as_array_mut().unwrap() {
            e["reasons"] = json!([WRITE]);
        }
    }
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(serde_json::to_vec(&v).unwrap()))
}
impl TestNode {
    async fn start(mut curators: Vec<Hash>) -> Self {
        curators.sort();
        let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
        let filter = cc_filter::v1::FilterIdentity::governed(curators, 4).unwrap();
        Store::provision(pool.clone(), INSTANCE)
            .await
            .unwrap()
            .bind(filter.clone())
            .await
            .unwrap();
        let store = Store::open(pool, INSTANCE, filter.clone()).await.unwrap();
        let readiness = store.semantic_readiness().await.unwrap();
        assert!(readiness.serving, "{readiness:?}");
        let v1 = V1Config {
            database_url: String::new(),
            instance: INSTANCE,
            filter,
        };
        let state = V1State {
            store,
            posture: Posture::Live,
            health_body: serve_v1::health_body(&v1, Posture::Live, &readiness.semantic),
            ready_gate: Default::default(),
            api_key: KeyDigest::of(WRITE),
            read_key: Some(KeyDigest::of(READ)),
            gallery_key: None,
            beta_key: None,
            telemetry_key: None,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let lie = Arc::new(AtomicU8::new(HONEST));
        let app = serve_v1::router(state).layer(middleware::from_fn_with_state(lie.clone(), lying));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            url,
            lie,
            _cleanup: cleanup,
        }
    }
    fn writer(&self) -> Node {
        Node::new(&self.url, Some(WRITE)).unwrap()
    }
    async fn context(&self) -> Context {
        entry_submit::fetch(&self.writer()).await.unwrap().2
    }
    async fn get(&self, path: &str) -> Value {
        let r = reqwest::Client::new()
            .get(format!("{}/{path}", self.url))
            .bearer_auth(READ)
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success(), "GET {path}: {}", r.status());
        serde_json::from_slice(&r.bytes().await.unwrap()).unwrap()
    }
    async fn snapshot(&self) -> Value {
        self.get("v1/snapshot").await
    }
    async fn support(&self, from: Hash, to: Hash) -> Value {
        self.get(&format!(
            "v1/support?from={}&to={}",
            hex::encode(from),
            hex::encode(to)
        ))
        .await["support"]
            .clone()
    }
    async fn edge(&self, id: Hash) -> Value {
        self.snapshot().await["edges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| hash_json(&e["edge"]) == Some(id))
            .cloned()
            .expect("edge in snapshot")
    }
    /// Admit a synthetic Genesis directly; returns (subject, revision).
    async fn genesis(&self, k: &SecretKey, value: &str) -> (Hash, Hash) {
        let g = genesis::build(
            k,
            GenesisInput {
                instance: INSTANCE,
                kind: "scientific-discovery".into(),
                namespace: "synthetic.g3".into(),
                value: value.into(),
                body: format!("Synthetic body for {value}.\n").into_bytes(),
                asserted_time: time::parse("1950").unwrap(),
                evidence: vec![EVIDENCE],
                nonce: hash(value.as_bytes()),
            },
        )
        .unwrap();
        let n = self.writer();
        n.put_body(&g.body).await.unwrap();
        let (status, outcome) = n.post_candidate(g.signed.bytes()).await.unwrap();
        assert_eq!((status.as_u16(), outcome.state.as_str()), (201, "valid"));
        (g.subject(), g.revision())
    }
    /// Write, reload, approve and submit a packet; returns the submission.
    async fn submit(&self, p: &Packet, dir: &Path) -> Value {
        let digest = p.write_dir(dir).unwrap();
        entry_submit::submit(&self.writer(), dir, digest)
            .await
            .unwrap()
    }
}

fn key(byte: u8) -> SecretKey {
    SecretKey::from_seed([byte; 32])
}
fn author(k: &SecretKey) -> Hash {
    k.author().to_bytes()
}
fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}
fn assert_input(relation: &str, s: (Hash, Hash), t: (Hash, Hash)) -> AssertInput {
    AssertInput {
        relation: relation.into(),
        source: s.0,
        target: t.0,
        source_revision: s.1,
        target_revision: t.1,
        rationale: "Synthetic rationale.".into(),
        evidence: vec![EVIDENCE],
    }
}
fn correction_input(subject: (Hash, Hash), text: &str) -> CorrectionInput {
    CorrectionInput {
        subject: subject.0,
        revision: subject.1,
        body: text.as_bytes().to_vec(),
        rationale: "Synthetic correction.".into(),
        evidence: vec![EVIDENCE],
        asserted_time: None,
        grant: None,
    }
}
fn codes(support: &Value) -> Vec<String> {
    support["Unsupported"]["reasons"]
        .as_array()
        .map(|r| {
            r.iter()
                .map(|x| x["code"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Correction then edge: an edge pinned to the old revision goes stale, the
/// stale context refuses a new pin and a pending packet, and a reaffirmation
/// by the original author restores support.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correction_makes_the_edge_stale_until_reaffirmed() {
    let tmp = tempfile::tempdir().unwrap();
    let k = key(0x11);
    let n = TestNode::start(vec![author(&k)]).await;
    let a = n.genesis(&k, "a").await;
    let b = n.genesis(&k, "b").await;

    let ctx = n.context().await;
    let p = edge::build_assert(&k, &ctx, assert_input("influence", a, b)).unwrap();
    let edge_id = p.events[0].id();
    let done = n.submit(&p, &tmp.path().join("edge")).await;
    assert_eq!(done["edges"][0]["status"], "current");
    assert!(n.support(a.0, b.0).await.get("Supported").is_some());

    // An edge packet built now but submitted after the correction is refused.
    let late = edge::build_assert(&k, &ctx, assert_input("causation", b, a)).unwrap();
    let late_dir = tmp.path().join("late");
    let late_digest = late.write_dir(&late_dir).unwrap();

    let ctx = n.context().await;
    let c = correction::build(
        &k,
        &ctx,
        correction_input(b, "Corrected synthetic body for b.\n"),
    )
    .unwrap();
    let b2 = revision_id(b.0, c.events[0].id());
    n.submit(&c, &tmp.path().join("correction")).await;

    let e = n.edge(edge_id).await;
    assert_eq!(e["status"], "stale", "{e}");
    let reasons: Vec<&str> = e["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(
        reasons.iter().all(|r| r.starts_with("target:")),
        "{reasons:?}"
    );
    assert!(reasons.contains(&"target:revision_changed"), "{reasons:?}");
    let support = n.support(a.0, b.0).await;
    assert!(
        codes(&support).contains(&"excluded_edge:stale".to_owned()),
        "{support}"
    );

    let refused = entry_submit::submit(&n.writer(), &late_dir, late_digest).await;
    assert!(err(refused.unwrap_err()).contains("corpus changed since the packet's context"));

    // The old revision is no longer current: a pin to it is refused.
    let ctx = n.context().await;
    let moved = edge::build_assert(&k, &ctx, assert_input("causation", b, a)).map(|_| ());
    assert!(err(moved.unwrap_err()).contains("source_subject_changed"));
    let moved = correction::build(&k, &ctx, correction_input(b, "Again.\n")).map(|_| ());
    assert!(err(moved.unwrap_err()).contains("has moved"));

    let r = edge::build_reaffirm(
        &k,
        &ctx,
        ReaffirmInput {
            edge: edge_id,
            source_revision: a.1,
            target_revision: b2,
            rationale: "Reviewed against the corrected body.".into(),
            evidence: vec![EVIDENCE],
        },
    )
    .unwrap();
    n.submit(&r, &tmp.path().join("reaffirm")).await;
    let e = n.edge(edge_id).await;
    assert_eq!(e["status"], "current", "{e}");
    assert!(n.support(a.0, b.0).await.get("Supported").is_some());
}

/// A `disputes` edge is admitted and visible but never support, while an
/// `influence` edge between the same subjects is; only the source subject's
/// creator may sign the dispute.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dispute_is_never_support() {
    let tmp = tempfile::tempdir().unwrap();
    let (k1, k2) = (key(0x21), key(0x22));
    let n = TestNode::start(vec![author(&k1), author(&k2)]).await;
    let a = n.genesis(&k1, "claim").await;
    let b = n.genesis(&k2, "counterclaim").await;

    let ctx = n.context().await;
    // k1 created `a`, not `b`: it may not dispute from `b`.
    let refused = edge::build_assert(&k1, &ctx, assert_input("disputes", b, a)).map(|_| ());
    assert!(err(refused.unwrap_err())
        .contains("may be signed only by the creator of its source subject"),);
    // The node enforces the same rule: a hand-signed non-creator dispute
    // (bypassing the publisher's check) is classified invalid.
    let pins = cc_core::v1::Pins {
        source: ctx.current(b.0).unwrap().pin(),
        target: ctx.current(a.0).unwrap().pin(),
    };
    let forged = edge::assert_envelope(
        INSTANCE,
        author(&k1),
        "disputes",
        pins,
        "Forged.".into(),
        vec![EVIDENCE],
    )
    .unwrap();
    let forged = Signed::sign(&k1, forged).unwrap();
    let (status, outcome) = n.writer().post_candidate(forged.bytes()).await.unwrap();
    assert_eq!(
        (
            status.as_u16(),
            outcome.state.as_str(),
            outcome.reason.as_str()
        ),
        (422, "invalid", "dispute_counterclaim")
    );
    // k2 created `b`: its dispute of `a` is admitted.
    let ctx = n.context().await;
    let p = edge::build_assert(&k2, &ctx, assert_input("disputes", b, a)).unwrap();
    let dispute = p.events[0].id();
    let done = n.submit(&p, &tmp.path().join("dispute")).await;
    assert_eq!(done["events"][0]["state"], "valid");
    assert_eq!(n.edge(dispute).await["status"], "current");
    for (from, to) in [(a.0, b.0), (b.0, a.0)] {
        let s = n.support(from, to).await;
        assert!(s.get("Supported").is_none(), "{s}");
        assert!(
            codes(&s).contains(&"excluded_edge:disputes_not_support".to_owned()),
            "{s}"
        );
    }

    // Control: a positive relation between the same subjects is support, so
    // the dispute's exclusion is the relation, not the endpoints.
    let ctx = n.context().await;
    let p = edge::build_assert(&k1, &ctx, assert_input("influence", a, b)).unwrap();
    n.submit(&p, &tmp.path().join("influence")).await;
    let s = n.support(a.0, b.0).await;
    let path = s["Supported"]["path"].as_array().expect("supported");
    assert!(!path.iter().any(|e| hash_json(e) == Some(dispute)), "{s}");
}

/// An attestation is bound to the revision it names (or that its target event
/// created) and stays there after a correction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attest_is_bound_to_its_revision() {
    let tmp = tempfile::tempdir().unwrap();
    let k = key(0x31);
    let n = TestNode::start(vec![author(&k)]).await;
    let a = n.genesis(&k, "attested").await;
    let ctx = n.context().await;
    let body1 = ctx.current(a.0).unwrap().body;
    let by_revision = attest::build(
        &k,
        &ctx,
        AttestInput {
            target_kind: TargetKind::Revision,
            target: a.1,
            artifact_kind: "image/png".into(),
            artifact: [0x51; 32],
        },
    )
    .unwrap();
    let by_event = attest::build(
        &k,
        &ctx,
        AttestInput {
            target_kind: TargetKind::Event,
            target: a.0,
            artifact_kind: "image/png".into(),
            artifact: [0x52; 32],
        },
    )
    .unwrap();
    assert_eq!(
        attest::bound_revision(&ctx, TargetKind::Event, a.0),
        Some(a.1)
    );
    let ids = [by_revision.events[0].id(), by_event.events[0].id()];
    n.submit(&by_revision, &tmp.path().join("r")).await;
    // The by-event packet was built against the context before the first
    // attestation; it is refused, rebuilt and resubmitted.
    let stale = by_event.write_dir(&tmp.path().join("e")).unwrap();
    let refused = entry_submit::submit(&n.writer(), &tmp.path().join("e"), stale).await;
    assert!(err(refused.unwrap_err()).contains("corpus changed since the packet's context"));
    let ctx = n.context().await;
    let rebuilt = attest::build(
        &k,
        &ctx,
        AttestInput {
            target_kind: TargetKind::Event,
            target: a.0,
            artifact_kind: "image/png".into(),
            artifact: [0x52; 32],
        },
    )
    .unwrap();
    assert_eq!(rebuilt.events[0].id(), ids[1], "signing is deterministic");
    n.submit(&rebuilt, &tmp.path().join("e2")).await;

    let ctx = n.context().await;
    let c = correction::build(&k, &ctx, correction_input(a, "Corrected attested body.\n")).unwrap();
    let a2 = revision_id(a.0, c.events[0].id());
    n.submit(&c, &tmp.path().join("c")).await;

    let snap = n.snapshot().await;
    let media = snap["media"].as_array().unwrap();
    for id in ids {
        let m = media
            .iter()
            .find(|m| hash_json(&m["attestation"]) == Some(id))
            .expect("media reading");
        assert_eq!(hash_json(&m["revision"]), Some(a.1), "{m}");
        assert_eq!(hash_json(&m["body"]), Some(body1), "{m}");
    }
    // Control: an attestation of the corrected revision binds to it.
    let ctx = n.context().await;
    let p = attest::build(
        &k,
        &ctx,
        AttestInput {
            target_kind: TargetKind::Revision,
            target: a2,
            artifact_kind: "image/png".into(),
            artifact: [0x53; 32],
        },
    )
    .unwrap();
    let id = p.events[0].id();
    n.submit(&p, &tmp.path().join("r2")).await;
    let snap = n.snapshot().await;
    let m = snap["media"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| hash_json(&m["attestation"]) == Some(id))
        .cloned()
        .unwrap();
    assert_eq!(hash_json(&m["revision"]), Some(a2));
    // Attestations cannot target attestations, and unknown revisions are refused.
    let bad = attest::build(
        &k,
        &ctx,
        AttestInput {
            target_kind: TargetKind::Event,
            target: ids[0],
            artifact_kind: "image/png".into(),
            artifact: [0x54; 32],
        },
    )
    .map(|_| ());
    assert!(err(bad.unwrap_err()).contains("cannot target an attestation"));
}

/// Mutation targets: both endpoint pins, the relation allowlist and the
/// dispute author rule each refuse with the publisher's own message, before
/// the node's classification would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edge_rules_refuse_with_the_publishers_own_checks() {
    let (k1, k2) = (key(0x41), key(0x42));
    let n = TestNode::start(vec![author(&k1), author(&k2)]).await;
    let a = n.genesis(&k1, "x").await;
    let b = n.genesis(&k2, "y").await;
    let ctx = n.context().await;
    let wrong = [0x99; 32];

    // Both pins: a wrong reviewed revision on either side is refused.
    let e = edge::build_assert(&k1, &ctx, assert_input("influence", (a.0, wrong), b)).map(|_| ());
    assert!(err(e.unwrap_err()).contains("source_subject_changed"));
    let e = edge::build_assert(&k1, &ctx, assert_input("influence", a, (b.0, wrong))).map(|_| ());
    assert!(err(e.unwrap_err()).contains("target_subject_changed"));
    let e = edge::build_assert(&k1, &ctx, assert_input("influence", a, (wrong, b.1))).map(|_| ());
    assert!(err(e.unwrap_err()).contains("target endpoint"));
    // The pins it builds are both current pins of both endpoints.
    let p = edge::build_assert(&k1, &ctx, assert_input("influence", a, b)).unwrap();
    let cc_core::v1::Payload::EdgeAssert { pins, .. } = &p.events[0].envelope().payload else {
        panic!()
    };
    assert_eq!(pins.source, ctx.current(a.0).unwrap().pin());
    assert_eq!(pins.target, ctx.current(b.0).unwrap().pin());

    // Relation allowlist: exactly the five governed relations.
    for r in ["causation", "co_occurrence", "influence", "participation"] {
        edge::build_assert(&k1, &ctx, assert_input(r, a, b)).unwrap();
    }
    for r in ["supports", "Influence", "", "influence "] {
        let e = edge::build_assert(&k1, &ctx, assert_input(r, a, b)).map(|_| ());
        assert!(
            err(e.unwrap_err()).contains("is not a governed v1 relation"),
            "{r:?}"
        );
    }

    // Dispute author: only the source subject's creator.
    let e = edge::build_assert(&k2, &ctx, assert_input("disputes", a, b)).map(|_| ());
    assert!(err(e.unwrap_err()).contains("may be signed only by the creator"));
    edge::build_assert(&k1, &ctx, assert_input("disputes", a, b)).unwrap();

    // Reaffirm: the original author only.
    let tmp = tempfile::tempdir().unwrap();
    let edge_id = p.events[0].id();
    n.submit(&p, &tmp.path().join("p")).await;
    let ctx = n.context().await;
    let r = |k: &SecretKey| {
        edge::build_reaffirm(
            k,
            &ctx,
            ReaffirmInput {
                edge: edge_id,
                source_revision: a.1,
                target_revision: b.1,
                rationale: "Reaffirmed.".into(),
                evidence: vec![EVIDENCE],
            },
        )
        .map(|_| ())
    };
    assert!(err(r(&k2).unwrap_err()).contains("only the edge's original author"));
    r(&k1).unwrap();
}

/// A contested subject (two corrections of one head) has no single current
/// reading: no pin, correction or entry edge may be built against it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contested_endpoints_are_refused() {
    let k = key(0x81);
    let n = TestNode::start(vec![author(&k)]).await;
    let a = n.genesis(&k, "forked").await;
    let b = n.genesis(&k, "plain").await;
    let ctx = n.context().await;
    // Two corrections of the same head, admitted directly: a fork.
    for text in ["Fork one.\n", "Fork two.\n"] {
        let c = correction::build(&k, &ctx, correction_input(a, text)).unwrap();
        let w = n.writer();
        w.put_body(text.as_bytes()).await.unwrap();
        let (status, outcome) = w.post_candidate(c.events[0].bytes()).await.unwrap();
        assert_eq!((status.as_u16(), outcome.state.as_str()), (201, "valid"));
    }
    let snap = n.snapshot().await;
    let reading = snap["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| hash_json(&s["subject"]) == Some(a.0))
        .cloned()
        .unwrap();
    assert_eq!(reading["state"], "contested", "{reading}");
    let ctx = n.context().await;
    let refused = |r: anyhow::Result<Packet>| {
        let e = err(r.map(|_| ()).unwrap_err());
        assert!(e.contains("a pin needs one resolved head"), "{e}");
    };
    refused(edge::build_assert(
        &k,
        &ctx,
        assert_input("influence", b, a),
    ));
    refused(edge::build_assert(
        &k,
        &ctx,
        assert_input("influence", a, b),
    ));
    refused(correction::build(&k, &ctx, correction_input(a, "Third.\n")));
    // Control: the resolved subject still pins.
    assert!(ctx.current(b.0).is_ok());
}

/// A context is the node's export, verified: a corpus digest that does not
/// match the envelopes, a tampered envelope, another instance or another fold
/// is refused before anything is built.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_context_is_refused() {
    let k = key(0x91);
    let n = TestNode::start(vec![author(&k)]).await;
    n.genesis(&k, "one").await;
    n.genesis(&k, "two").await;
    let (_, export, ctx) = entry_submit::fetch(&n.writer()).await.unwrap();
    assert_eq!(ctx.events.len(), 2);
    let refuse = |e: Value, instance: Hash, want: &str| {
        let got = err(Context::from_export(instance, &e).map(|_| ()).unwrap_err());
        assert!(got.contains(want), "want {want:?}, got {got:?}");
    };
    // One envelope dropped: the named digest no longer matches.
    let mut dropped = export.clone();
    dropped["envelopes"].as_array_mut().unwrap().pop();
    refuse(dropped, INSTANCE, "corpus digest does not match");
    let mut digest = export.clone();
    digest["corpus_digest"] = json!(hex::encode([0u8; 32]));
    refuse(digest, INSTANCE, "corpus digest does not match");
    let mut flipped = export.clone();
    let mut bytes = hex::decode(flipped["envelopes"][0].as_str().unwrap()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    flipped["envelopes"][0] = json!(hex::encode(bytes));
    refuse(flipped, INSTANCE, "export envelope 0");
    refuse(export.clone(), [8; 32], "another instance");
    let mut fold = export.clone();
    fold["rule"]["fold_version"] = json!(2);
    refuse(fold, INSTANCE, "fold differs");
    // Control: the export as served loads.
    Context::from_export(INSTANCE, &export).unwrap();
}

/// The read-back after submission trusts nothing the node did not show: a
/// snapshot that does not list the packet's events as retained and valid is a
/// failure, and a node echoing the token never gets it into the report.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_readback_and_redaction() {
    let tmp = tempfile::tempdir().unwrap();
    let k = key(0xa1);
    let n = TestNode::start(vec![author(&k)]).await;
    let a = n.genesis(&k, "p").await;
    let b = n.genesis(&k, "q").await;
    let ctx = n.context().await;
    let p = edge::build_assert(&k, &ctx, assert_input("influence", a, b)).unwrap();
    let dir = tmp.path().join("edge");
    let digest = p.write_dir(&dir).unwrap();
    n.lie.store(ROWS_PENDING, Ordering::SeqCst);
    let e = err(entry_submit::submit(&n.writer(), &dir, digest)
        .await
        .unwrap_err());
    assert!(e.contains("readback:") && e.contains("is pending"), "{e}");
    // The envelope was admitted; an honest rerun completes, and the token a
    // node echoes is redacted from the report.
    n.lie.store(ECHO_TOKEN, Ordering::SeqCst);
    let report = entry_submit::submit(&n.writer(), &dir, digest)
        .await
        .unwrap();
    let text = report.to_string();
    assert!(!text.contains(WRITE), "{text}");
    assert_eq!(report["edges"][0]["reasons"], json!(["<redacted>"]));
    // A context keeps only what was verified: the echoed export fields never
    // reach the saved file.
    let (_, export, _) = entry_submit::fetch(&n.writer()).await.unwrap();
    assert!(!export.to_string().contains(WRITE), "{export}");
    let file = tmp.path().join("ctx.json");
    entry_submit::save_context(&n.writer(), &file)
        .await
        .unwrap();
    let saved = std::fs::read_to_string(&file).unwrap();
    assert!(!saved.contains(WRITE));
    Context::load(&file).unwrap();
}

// ---- entry packets ----------------------------------------------------------

fn seed_file(dir: &Path, byte: u8) -> PathBuf {
    let p = dir.join(format!("k{byte:02x}.seed"));
    std::fs::write(&p, format!("{}\n", hex::encode([byte; 32]))).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}
fn manifest(dir: &Path, edges: Value, capture: Option<&str>) -> PathBuf {
    std::fs::write(
        dir.join("body.txt"),
        "Synthetic entry body.\nA second line.\n",
    )
    .unwrap();
    std::fs::write(dir.join("capture.txt"), "synthetic capture bytes").unwrap();
    let mut source = json!({
        "id": "s1",
        "sha256": hex::encode(hash(b"synthetic capture bytes")),
        "locator": "Synthetic capture, paragraph 2.",
    });
    if let Some(c) = capture {
        source["capture"] = json!(c);
    }
    let m = json!({
        "schema": "cc.publisher.v1.entry",
        "instance": hex::encode(INSTANCE),
        "subject": {"kind": "scientific-discovery", "namespace": "synthetic.g3", "value": "entry"},
        "asserted_time": "1960-05",
        "nonce": hex::encode([0x77; 32]),
        "body": "body.txt",
        "sources": [source, {"id": "s2", "sha256": hex::encode([0x62; 32]), "locator": "Second synthetic source."}],
        "edges": edges,
    });
    let p = dir.join("manifest.json");
    std::fs::write(&p, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    p
}
fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    for sub in ["", "events", "bodies"] {
        let mut names: Vec<_> = std::fs::read_dir(dir.join(sub))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.is_file())
            .collect();
        names.sort();
        for p in names {
            out.push((
                p.strip_prefix(dir).unwrap().display().to_string(),
                std::fs::read(&p).unwrap(),
            ));
        }
    }
    out
}
fn s_id(dir: &Path) -> Hash {
    Signed::decode(&std::fs::read(dir.join("events/00.bin")).unwrap())
        .unwrap()
        .id()
}
fn publisher() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cc-publisher"));
    c.env_remove("CC_NODE_API_KEY")
        .env_remove("CC_NODE_READ_KEY");
    c
}

/// `entry` builds byte-identical packets from the same manifest, key and
/// context; any change to the reviewed bytes changes the digest; the reload
/// refuses tampering; submit refuses any digest but the approved one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entry_packet_builds_deterministic_envelopes() {
    let tmp = tempfile::tempdir().unwrap();
    let seed = seed_file(tmp.path(), 0x51);
    let k = key::load_key(&seed).unwrap();
    let n = TestNode::start(vec![author(&k)]).await;
    let other = n.genesis(&k, "existing").await;
    let edges = json!([{
        "relation": "influence", "source": "entry", "target": hex::encode(other.0),
        "target_revision": hex::encode(other.1),
        "rationale": "Synthetic influence.", "sources": ["s1", "s2"],
    }]);
    let m = manifest(tmp.path(), edges, Some("capture.txt"));
    let ctx = n.context().await;

    let one = entry::build(&k, &ctx, &m).unwrap();
    assert_eq!(one.verified_captures, ["s1"]);
    assert_eq!(one.unverified_captures, ["s2"]);
    let two = entry::build(&k, &ctx, &m).unwrap().packet;
    let (d1, d2) = (tmp.path().join("p1"), tmp.path().join("p2"));
    let digest = one.packet.write_dir(&d1).unwrap();
    assert_eq!(two.write_dir(&d2).unwrap(), digest);
    assert_eq!(files(&d1), files(&d2));
    let kinds: Vec<Kind> = one
        .packet
        .events
        .iter()
        .map(|e| e.envelope().payload.kind())
        .collect();
    assert_eq!(kinds, [Kind::Genesis, Kind::EdgeAssert]);
    let packet: Value =
        serde_json::from_slice(&std::fs::read(d1.join("packet.json")).unwrap()).unwrap();
    assert_eq!(
        packet["events"][1]["pins"]["source"]["subject"],
        json!(hex::encode(one.packet.events[0].id()))
    );
    assert_eq!(packet["publication_authorized"], false);
    assert_eq!(Packet::load_dir(&d1).unwrap().digest().unwrap(), digest);

    // Any reviewed byte changes the digest; the nonce fixes the subject.
    std::fs::write(
        tmp.path().join("body.txt"),
        "Synthetic entry body.\nA second line!\n",
    )
    .unwrap();
    let changed = entry::build(&k, &ctx, &m).unwrap().packet;
    assert_ne!(changed.digest().unwrap(), digest);
    std::fs::write(
        tmp.path().join("body.txt"),
        "Synthetic entry body.\nA second line.\n",
    )
    .unwrap();

    // Tampering with a packet file is refused on reload.
    let t = tmp.path().join("tampered");
    one.packet.write_dir(&t).unwrap();
    let pj = t.join("packet.json");
    let text = std::fs::read_to_string(&pj)
        .unwrap()
        .replace("Synthetic influence.", "Synthetic influence!");
    std::fs::remove_file(&pj).unwrap();
    std::fs::write(&pj, text).unwrap();
    assert!(err(Packet::load_dir(&t).map(|_| ()).unwrap_err()).contains("does not match"));
    // A changed body, in an otherwise untouched packet, is refused too.
    let t = tmp.path().join("tampered-body");
    one.packet.write_dir(&t).unwrap();
    let body = std::fs::read_dir(t.join("bodies"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(&body).unwrap();
    std::fs::write(&body, "Synthetic entry body.\nA second line!\n").unwrap();
    assert!(
        err(Packet::load_dir(&t).map(|_| ()).unwrap_err()).contains("does not hash to its name")
    );

    // The manifest must say exactly what the events sign: a manifest whose
    // bytes are consistent with its own hash but not with the events is refused.
    let original: Value = serde_json::from_slice(one.packet.manifest.as_ref().unwrap()).unwrap();
    for (path, value, want) in [
        (
            "/sources/1/sha256",
            json!(hex::encode([0x63; 32])),
            "source set",
        ),
        ("/edges/0/relation", json!("causation"), "edges[0] relation"),
        ("/edges/0/sources", json!(["s1"]), "edges[0] sources"),
        (
            "/edges/0/target_revision",
            json!(hex::encode([1u8; 32])),
            "edges[0] target",
        ),
        ("/subject/value", json!("other"), "subject key"),
        ("/nonce", json!(hex::encode([0x78; 32])), "nonce"),
    ] {
        let mut m = original.clone();
        *m.pointer_mut(path).unwrap() = value;
        let bytes = serde_json::to_vec(&m).unwrap();
        let e = Packet::new(
            "entry",
            &ctx,
            one.packet.events.clone(),
            vec![one.packet.bodies.values().next().unwrap().clone()],
            Some(bytes),
        )
        .map(|_| ())
        .unwrap_err();
        assert!(err(e).contains(want), "{path}: want {want:?}");
    }
    // The reviewed locators appear in packet.json.
    assert_eq!(
        packet["sources"][0]["locator"],
        "Synthetic capture, paragraph 2."
    );
    // An unlisted file riding along is refused too.
    let x = tmp.path().join("extra");
    one.packet.write_dir(&x).unwrap();
    std::fs::write(x.join("events/02.bin"), b"unreviewed").unwrap();
    assert!(err(Packet::load_dir(&x).map(|_| ()).unwrap_err()).contains("does not list"));

    // Submission needs the exact approved digest; nothing is written otherwise.
    let wrong = entry_submit::submit(&n.writer(), &d1, [0; 32]).await;
    assert!(err(wrong.unwrap_err()).contains("is not this packet's digest"));
    assert_eq!(n.context().await.events.len(), 1);
    let done = entry_submit::submit(&n.writer(), &d1, digest)
        .await
        .unwrap();
    assert_eq!(done["events"].as_array().unwrap().len(), 2);
    assert_eq!(done["edges"][0]["status"], "current");
    // A rerun is safe: the packet's own events are not "other changes".
    entry_submit::submit(&n.writer(), &d1, digest)
        .await
        .unwrap();
    assert!(n
        .support(one.packet.events[0].id(), other.0)
        .await
        .get("Supported")
        .is_some());
}

/// A packet whose packet.json would exceed what a reload reads is never
/// written, even when its manifest is within the manifest cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreloadable_packet_is_never_written() {
    let tmp = tempfile::tempdir().unwrap();
    let k = key(0xb1);
    let n = TestNode::start(vec![author(&k)]).await;
    let other = n.genesis(&k, "big").await;
    let ctx = n.context().await;
    let cap = cc_publisher::v1::entry_packet::MAX_PACKET_JSON;
    // Sixteen edges whose rationales fill the manifest to just under its cap.
    let edges = |len: usize| {
        json!((0..16)
            .map(|i| json!({
                "relation": "influence", "source": "entry", "target": hex::encode(other.0),
                "target_revision": hex::encode(other.1),
                "rationale": format!("{i:02}{}", "r".repeat(len - 2)), "sources": ["s1"],
            }))
            .collect::<Vec<_>>())
    };
    let mut len = 65_536;
    let m = loop {
        let m = manifest(tmp.path(), edges(len), None);
        if std::fs::metadata(&m).unwrap().len() as usize <= cap - 64 {
            break m;
        }
        len -= 256;
    };
    let e = err(entry::build(&k, &ctx, &m).map(|_| ()).unwrap_err());
    assert!(
        e.contains("packet.json would be") && e.contains("split the packet"),
        "{e}"
    );
    // Control: a quarter of the edges builds and reloads.
    let small = manifest(tmp.path(), json!(edges(len).as_array().unwrap()[..4]), None);
    let p = entry::build(&k, &ctx, &small).unwrap().packet;
    let dir = tmp.path().join("small");
    p.write_dir(&dir).unwrap();
    Packet::load_dir(&dir).unwrap();
}

/// Manifest refusals ported from the salvage review flow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entry_manifest_refusals() {
    let tmp = tempfile::tempdir().unwrap();
    let (k, k2) = (key(0x61), key(0x62));
    let n = TestNode::start(vec![author(&k), author(&k2)]).await;
    let other = n.genesis(&k2, "theirs").await;
    let ctx = n.context().await;
    let edge = |extra: Value| {
        let mut e = json!({"relation": "influence", "source": "entry", "target": hex::encode(other.0),
            "target_revision": hex::encode(other.1), "rationale": "Synthetic.", "sources": ["s1"]});
        for (k, v) in extra.as_object().unwrap() {
            e[k] = v.clone();
        }
        json!([e])
    };
    let refuse = |edges: Value, capture: Option<&str>, want: &str| {
        let m = manifest(tmp.path(), edges, capture);
        let e = entry::build(&k, &ctx, &m).map(|_| ()).unwrap_err();
        assert!(err(e).contains(want), "want {want:?}");
    };
    refuse(edge(json!({"sources": ["s9"]})), None, "undeclared source");
    refuse(
        edge(json!({"target_revision": hex::encode([1u8; 32])})),
        None,
        "target_subject_changed",
    );
    refuse(
        edge(json!({"target_revision": null})),
        None,
        "target_revision is required",
    );
    refuse(
        edge(json!({"relation": "supports"})),
        None,
        "is not a governed v1 relation",
    );
    // The existing subject belongs to k2: k may not dispute from it.
    refuse(
        edge(
            json!({"relation": "disputes", "source": hex::encode(other.0), "target": "entry",
                    "source_revision": hex::encode(other.1), "target_revision": null}),
        ),
        None,
        "may be signed only by the creator",
    );
    refuse(
        edge(json!({"source": hex::encode(other.0), "source_revision": hex::encode(other.1)})),
        None,
        "exactly one endpoint",
    );
    std::fs::write(tmp.path().join("bad.txt"), "not the capture").unwrap();
    refuse(json!([]), Some("bad.txt"), "capture hash mismatch");
    refuse(json!([]), Some("../capture.txt"), "without '..'");
    // Absolute paths and symlinks never pull in bytes from outside the
    // manifest directory, even bytes that would hash correctly.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("capture.txt"),
        "synthetic capture bytes",
    )
    .unwrap();
    std::fs::write(outside.path().join("body.txt"), "Outside synthetic body.\n").unwrap();
    let abs = outside.path().join("capture.txt");
    refuse(json!([]), Some(abs.to_str().unwrap()), "without '..'");
    let link =
        |to: PathBuf, name: &str| std::os::unix::fs::symlink(to, tmp.path().join(name)).unwrap();
    link(outside.path().join("capture.txt"), "link-capture.txt");
    link(outside.path().join("body.txt"), "link-body.txt");
    link(outside.path().to_path_buf(), "linkdir");
    for capture in ["link-capture.txt", "linkdir/capture.txt"] {
        refuse(
            json!([]),
            Some(capture),
            "must not be or pass through a symlink",
        );
    }
    let with_body = |body: &str| {
        let m = manifest(tmp.path(), json!([]), None);
        let mut v: Value = serde_json::from_slice(&std::fs::read(&m).unwrap()).unwrap();
        v["body"] = json!(body);
        std::fs::write(&m, serde_json::to_vec(&v).unwrap()).unwrap();
        entry::build(&k, &ctx, &m).map(|b| b.packet)
    };
    let abs_body = outside.path().join("body.txt");
    for (body, want) in [
        ("link-body.txt", "must not be or pass through a symlink"),
        ("linkdir/body.txt", "must not be or pass through a symlink"),
        (abs_body.to_str().unwrap(), "without '..'"),
    ] {
        let e = err(with_body(body).map(|_| ()).unwrap_err());
        assert!(e.contains(want), "{body}: want {want:?}, got {e:?}");
    }
    // Control: a regular body in a regular subdirectory is accepted and signed.
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    std::fs::write(tmp.path().join("sub/body.txt"), "Synthetic nested body.\n").unwrap();
    let p = with_body("sub/body.txt").unwrap();
    assert!(p.bodies.contains_key(&hash(b"Synthetic nested body.\n")));
    // A dispute from the entry itself is the entry author's own counterclaim.
    let m = manifest(tmp.path(), edge(json!({"relation": "disputes"})), None);
    entry::build(&k, &ctx, &m).unwrap();
}

/// The binary end to end: context, entry, review-packet, submit-packet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_context_entry_review_and_submit() {
    let tmp = tempfile::tempdir().unwrap();
    let seed = seed_file(tmp.path(), 0x71);
    let k = key::load_key(&seed).unwrap();
    let n = TestNode::start(vec![author(&k)]).await;
    let ctx_file = tmp.path().join("context.json");
    let ok = |c: &mut Command| {
        let out = c.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    // `context` needs the write token from the environment.
    let out = publisher()
        .args(["v1", "context", "--node", &n.url, "--out"])
        .arg(&ctx_file)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    ok(publisher()
        .args(["v1", "context", "--node", &n.url, "--out"])
        .arg(&ctx_file)
        .env("CC_NODE_API_KEY", WRITE));
    let m = manifest(tmp.path(), json!([]), Some("capture.txt"));
    let dir = tmp.path().join("packet");
    let printed = ok(publisher()
        .args(["v1", "entry", "--key"])
        .arg(&seed)
        .arg("--context")
        .arg(&ctx_file)
        .arg("--manifest")
        .arg(&m)
        .arg("--out")
        .arg(&dir));
    assert!(printed.contains("nothing was submitted"), "{printed}");
    let digest = hex::encode(Packet::load_dir(&dir).unwrap().digest().unwrap());
    assert!(printed.contains(&digest));
    // A second build from the same manifest, key and context file is
    // byte-identical.
    let again = tmp.path().join("again");
    ok(publisher()
        .args(["v1", "entry", "--key"])
        .arg(&seed)
        .arg("--context")
        .arg(&ctx_file)
        .arg("--manifest")
        .arg(&m)
        .arg("--out")
        .arg(&again));
    assert_eq!(files(&again), files(&dir));
    let review: Value = serde_json::from_str(&ok(publisher()
        .args(["v1", "review-packet", "--dir"])
        .arg(&dir)
        .arg("--context")
        .arg(&ctx_file)))
    .unwrap();
    assert_eq!(review["packet_digest"], json!(digest));
    assert_eq!(review["context_matches"], true);
    assert_eq!(review["admissible"], true);
    assert_eq!(review["admission_reason"], Value::Null);
    assert_eq!(review["writes_performed"], false);
    // Nothing has been submitted by any of the above.
    assert_eq!(n.context().await.events.len(), 0);
    let sub: Value = serde_json::from_str(&ok(publisher()
        .args([
            "v1",
            "submit-packet",
            "--node",
            &n.url,
            "--approve",
            &digest,
            "--dir",
        ])
        .arg(&dir)
        .env("CC_NODE_API_KEY", WRITE)))
    .unwrap();
    assert_eq!(sub["events"][0]["state"], "valid");
    assert_eq!(n.context().await.events.len(), 1);
    // A correction through the binary, against a fresh context.
    let subject = hex::encode(s_id(&dir));
    let revision = hex::encode(revision_id(s_id(&dir), s_id(&dir)));
    let ctx2 = tmp.path().join("context2.json");
    ok(publisher()
        .args(["v1", "context", "--node", &n.url, "--out"])
        .arg(&ctx2)
        .env("CC_NODE_API_KEY", WRITE));
    std::fs::write(
        tmp.path().join("new.txt"),
        "Corrected synthetic entry body.\n",
    )
    .unwrap();
    let cdir = tmp.path().join("correction");
    let flags = |c: &mut Command| {
        c.arg("--key")
            .arg(&seed)
            .arg("--context")
            .arg(&ctx2)
            .args([
                "--rationale",
                "Synthetic correction.",
                "--evidence",
                &hex::encode(EVIDENCE),
            ])
            .arg("--out")
            .arg(&cdir);
    };
    let mut c = publisher();
    c.args([
        "v1",
        "correction",
        "--subject",
        &subject,
        "--revision",
        &revision,
        "--body",
    ])
    .arg(tmp.path().join("new.txt"));
    flags(&mut c);
    ok(&mut c);
    let cdigest = hex::encode(Packet::load_dir(&cdir).unwrap().digest().unwrap());
    let sub: Value = serde_json::from_str(&ok(publisher()
        .args([
            "v1",
            "submit-packet",
            "--node",
            &n.url,
            "--approve",
            &cdigest,
            "--dir",
        ])
        .arg(&cdir)
        .env("CC_NODE_API_KEY", WRITE)))
    .unwrap();
    assert_eq!(sub["events"][0]["kind"], "correction");
    assert_eq!(sub["events"][0]["state"], "valid");
    // Reviewed against the older (empty) context, the correction's parent is
    // unknown: not admissible, with the node rule's reason.
    let review: Value = serde_json::from_str(&ok(publisher()
        .args(["v1", "review-packet", "--dir"])
        .arg(tmp.path().join("correction"))
        .arg("--context")
        .arg(&ctx_file)))
    .unwrap();
    assert_eq!(review["context_matches"], false);
    assert_eq!(review["admissible"], false);
    assert!(
        review["admission_reason"]
            .as_str()
            .unwrap()
            .contains("parent_missing"),
        "{review}"
    );
    // The saved context holds only the verified fields.
    let saved: Value = serde_json::from_slice(&std::fs::read(&ctx2).unwrap()).unwrap();
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&saved), ["export", "instance", "schema"]);
    assert_eq!(
        keys(&saved["export"]),
        ["corpus_digest", "envelopes", "rule"]
    );
    assert_eq!(
        keys(&saved["export"]["rule"]),
        ["fold_manifest", "fold_version"]
    );
    // Parser-level refusal: with every other flag present, omitting the
    // reviewed target revision is exit 2.
    let mut c = publisher();
    c.args([
        "v1",
        "edge",
        "assert",
        "--relation",
        "influence",
        "--source",
        &subject,
    ])
    .args(["--target", &subject, "--source-revision", &revision]);
    let cdir = tmp.path().join("unused");
    let out = c
        .arg("--key")
        .arg(&seed)
        .arg("--context")
        .arg(&ctx2)
        .args(["--rationale", "x", "--evidence", &hex::encode(EVIDENCE)])
        .arg("--out")
        .arg(&cdir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--target-revision"));
    let s = Signed::decode(&std::fs::read(dir.join("events/00.bin")).unwrap()).unwrap();
    assert_eq!(s.envelope().payload.kind(), Kind::Genesis);
}
