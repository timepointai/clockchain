//! Shared by the fixture and gateway tests: the synthetic corpus, and a real
//! v1 node over real PostgreSQL serving it.
#![allow(dead_code)]
use cc_core::v1::*;
use cc_core::{B256Constants, Tick};
use cc_ledger::v1::Store;
use cc_node::config::{KeyDigest, Posture, V1Config};
use cc_node::serve_v1::{health_body, router, V1State};
use cc_testkit::v1::{filter, key, pin, INSTANCE};
use serde_json::Value;
use std::path::PathBuf;

pub const READ: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
pub const WRITE: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
/// `/health` names the build revision; the fixture pins this instead.
pub const BUILD: &str = "synthetic-fixture";

pub const PROSE_A1: &str =
    "A fictional printing house opens in a fictional harbour town. Synthetic test prose.";
pub const PROSE_A2: &str = "A fictional printing house opens in a fictional harbour town, with two presses. Synthetic test prose, corrected.";
pub const PROSE_B: &str =
    "A fictional reading society is founded in the same fictional town. Synthetic test prose.";

pub fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../web/explorer/fixtures/synthetic")
}

/// Days since 1970-01-01 (Hinnant's days_from_civil), for a day-precision
/// coordinate: whole seconds since J2000.0 shifted by the governed split.
pub fn day(year: i64, month: i64, d: i64) -> AssertedTime {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 - 946_728_000;
    AssertedTime {
        coordinate: Tick::from_whole_ticks(seconds, B256Constants::V0.split).to_canon_bytes(),
        precision: "day".into(),
    }
}

pub fn genesis(
    signer: u8,
    kind: &str,
    value: &str,
    nonce: u8,
    prose: &str,
    at: AssertedTime,
) -> Signed {
    Signed::sign(
        &key(signer),
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: None,
            subject_key: Some(SubjectKey {
                kind: kind.into(),
                namespace: "synthetic".into(),
                value: value.into(),
            }),
            grant: None,
            parents: Set(vec![]),
            asserted_time: Some(at),
            payload: Payload::Genesis {
                nonce: [nonce; 32],
                body: hash(prose.as_bytes()),
                evidence: Set(vec![[4; 32]]),
            },
        },
    )
    .unwrap()
}

pub fn subject_event(
    g: &Signed,
    parent: Hash,
    signer: u8,
    grant: Hash,
    payload: Payload,
    at: Option<AssertedTime>,
) -> Signed {
    Signed::sign(
        &key(signer),
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: Some(g.id()),
            subject_key: g.envelope().subject_key.clone(),
            grant: Some(grant),
            parents: Set(vec![parent]),
            asserted_time: at,
            payload,
        },
    )
    .unwrap()
}

pub fn correction(g: &Signed, parent: Hash, old: Hash, prose: &str, at: AssertedTime) -> Signed {
    let body = hash(prose.as_bytes());
    let payload = Payload::Correction {
        body,
        decision: Decision {
            kind: Kind::Correction,
            rationale: "Synthetic correction: adds a detail".into(),
            evidence: Set(vec![[4; 32]]),
            parents: Set(vec![parent]),
            old: Value_::Body(old),
            new: Value_::Body(body),
        },
    };
    subject_event(g, parent, 0, root_grant(g.id()), payload, Some(at))
}
use cc_core::v1::Value as Value_;

pub fn edge(signer: u8, relation: &str, pins: Pins) -> Signed {
    let decision = Decision {
        kind: Kind::EdgeAssert,
        rationale: "Synthetic edge assertion".into(),
        evidence: Set(vec![[4; 32]]),
        parents: Set(vec![]),
        old: Value_::None,
        new: Value_::Pins(pins.clone()),
    };
    Signed::sign(
        &key(signer),
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: None,
            subject_key: None,
            grant: None,
            parents: Set(vec![]),
            asserted_time: None,
            payload: Payload::EdgeAssert {
                relation: relation.into(),
                pins,
                decision,
            },
        },
    )
    .unwrap()
}

pub struct Corpus {
    pub events: Vec<Signed>,
    pub bodies: Vec<&'static str>,
    pub a: Hash,
    pub b: Hash,
}

pub fn corpus() -> Corpus {
    let g = genesis(
        0,
        "printing-and-publishing",
        "harbour-press",
        21,
        PROSE_A1,
        day(1901, 3, 4),
    );
    let c = correction(
        &g,
        g.id(),
        hash(PROSE_A1.as_bytes()),
        PROSE_A2,
        day(1901, 3, 5),
    );
    let grantee = key(6).author().to_bytes();
    let issuer = root_grant(g.id());
    let d = subject_event(
        &g,
        c.id(),
        0,
        issuer,
        Payload::Delegate {
            grantee,
            issuer,
            decision: Decision {
                kind: Kind::Delegate,
                rationale: "Synthetic delegation to an editing key".into(),
                evidence: Set(vec![[4; 32]]),
                parents: Set(vec![c.id()]),
                old: Value_::None,
                new: Value_::Grant { issuer, grantee },
            },
        },
        None,
    );
    let b = genesis(
        1,
        "learning-institutions",
        "reading-society",
        22,
        PROSE_B,
        day(1902, 6, 1),
    );
    let pa = pin(&[&g, &c, &d], &d);
    let pb = pin(&[&b], &b);
    let influence = edge(
        0,
        "influence",
        Pins {
            source: pa.clone(),
            target: pb.clone(),
        },
    );
    // The dispute author must be the source subject's creator.
    let dispute = edge(
        1,
        "disputes",
        Pins {
            source: pb,
            target: pa,
        },
    );
    let attest = Signed::sign(
        &key(0),
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: None,
            subject_key: None,
            grant: None,
            parents: Set(vec![]),
            asserted_time: None,
            payload: Payload::Attestation {
                target_kind: TargetKind::Revision,
                target: revision_id(g.id(), c.id()),
                artifact_kind: "image/png".into(),
                artifact: [60; 32],
            },
        },
    )
    .unwrap();
    // Pending: its parent was never submitted.
    let absent = correction(
        &g,
        [77; 32],
        hash(PROSE_A2.as_bytes()),
        "never retained",
        day(1901, 3, 6),
    );
    // Invalid: a Genesis may not carry a grant.
    let mut bad = genesis(
        2,
        "printing-and-publishing",
        "malformed",
        23,
        "never retained",
        day(1903, 1, 1),
    )
    .envelope()
    .clone();
    bad.grant = Some([8; 32]);
    let invalid = Signed::sign(&key(2), bad).unwrap();
    Corpus {
        a: g.id(),
        b: b.id(),
        events: vec![g, c, d, b, influence, dispute, attest, absent, invalid],
        bodies: vec![PROSE_A1, PROSE_A2, PROSE_B],
    }
}

pub struct Node {
    pub base: String,
    pub http: reqwest::Client,
}
impl Node {
    pub async fn get(&self, path: &str, token: &str) -> (u16, Vec<u8>) {
        let r = self
            .http
            .get(format!("{}{path}", self.base))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.bytes().await.unwrap().to_vec())
    }
}

/// Public read routes, as the gateway names them, and the node path behind each.
pub fn routes(c: &Corpus, snapshot: &Value) -> Vec<(String, String)> {
    let mut out = vec![("snapshot.json".into(), "/v1/snapshot".into())];
    for s in [c.a, c.b] {
        let h = hex::encode(s);
        out.push((format!("subjects/{h}.json"), format!("/v1/subjects/{h}")));
        // Before, on and after the current revision's asserted day, so the
        // verifier's as_of visibility is checked against the node's.
        for (y, m, d) in [(1901, 3, 4), (1901, 3, 5), (1903, 1, 1)] {
            let q = hex::encode(day(y, m, d).coordinate);
            out.push((
                format!("subjects/{h}.as_of.{q}.json"),
                format!("/v1/subjects/{h}?as_of={q}"),
            ));
        }
    }
    for r in snapshot["revisions"].as_array().unwrap() {
        let id: Vec<u8> = serde_json::from_value(r["id"].clone()).unwrap();
        let h = hex::encode(id);
        out.push((
            format!("revisions/{h}/prose.json"),
            format!("/v1/revisions/{h}/prose"),
        ));
    }
    for (f, t) in [(c.a, c.b), (c.b, c.a)] {
        let (f, t) = (hex::encode(f), hex::encode(t));
        out.push((
            format!("support/{f}-{t}.json"),
            format!("/v1/support?from={f}&to={t}"),
        ));
    }
    out
}

/// A provisioned, bound store holding the synthetic corpus, served by the
/// real v1 router on a loopback socket.
pub struct Live {
    pub pool: sqlx::PgPool,
    pub cleanup: cc_testkit::Cleanup,
    pub store: Store,
    pub corpus: Corpus,
    pub node: Node,
    pub server: tokio::task::JoinHandle<()>,
}
impl Live {
    pub async fn stop(self) {
        self.server.abort();
        self.pool.close().await;
        self.cleanup.cleanup().await;
    }
}

pub async fn live() -> Live {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    Store::provision(pool.clone(), INSTANCE)
        .await
        .unwrap()
        .bind(filter())
        .await
        .unwrap();
    let store = Store::open(pool.clone(), INSTANCE, filter()).await.unwrap();
    let corpus = corpus();
    for e in &corpus.events {
        store.admit(e.bytes()).await.unwrap();
    }
    for p in &corpus.bodies {
        store
            .retain_body(hash(p.as_bytes()), p.as_bytes())
            .await
            .unwrap();
    }

    let v1 = V1Config {
        database_url: "postgres://unused".into(),
        instance: INSTANCE,
        filter: filter(),
    };
    let semantic = store.semantic_readiness().await.unwrap().semantic;
    let state = V1State {
        health_body: health_body(&v1, Posture::Live, &semantic),
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
    let server = tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    let node = Node {
        base,
        http: reqwest::Client::new(),
    };

    Live {
        pool,
        cleanup,
        store,
        corpus,
        node,
        server,
    }
}
