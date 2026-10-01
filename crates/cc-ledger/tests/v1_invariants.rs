//! Stage (e): named invariant-table tests not covered by earlier stage files.
use cc_core::v1::*;
use cc_ledger::v1::{classify, support_graph, Error, ProjectionState as P, State, Store, Support};
use cc_testkit::v1::*;
use std::collections::{BTreeMap, BTreeSet};

async fn bound_store() -> (sqlx::PgPool, cc_testkit::Cleanup, Store) {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let store = Store::provision(pool.clone(), INSTANCE)
        .await
        .unwrap()
        .bind(filter())
        .await
        .unwrap();
    (pool, cleanup, store)
}
fn reparent(e: &Signed, parent: &Signed, grant: Hash, signer: u8) -> Signed {
    let mut env = e.envelope().clone();
    env.parents = Set(vec![parent.id()]);
    env.grant = Some(grant);
    if let Payload::Correction { decision, .. } = &mut env.payload {
        decision.parents = env.parents.clone();
    }
    Signed::sign(&key(signer), env).unwrap()
}

#[tokio::test]
async fn i3_total_auditable_classification() {
    let (pool, cleanup, store) = bound_store().await;
    let g = genesis();
    let root = root_grant(g.id());
    let c1 = correction(&g, &g, 0, 5);
    let c2 = correction(&g, &c1, 0, 6);
    let wrong = correction(&g, &g, 1, 9);
    let d = delegate(&g, &c2, 0, root, 1);
    let r = revoke(&g, &d, 0, root, d.id(), false);
    // K's out-of-cut correction at the revoked parent: visible, never contending.
    let k = reparent(&correction(&g, &c2, 1, 7), &d, d.id(), 1);
    let orphan = correction(&g, &correction(&g, &g, 0, 30), 0, 31);
    let mut bad_sig = c1.bytes().to_vec();
    *bad_sig.last_mut().unwrap() ^= 1;
    let mut legacy = g.bytes().to_vec();
    legacy[15..17].copy_from_slice(&0u16.to_be_bytes()); // canon version word 0
    let mut foreign = g.envelope().clone();
    foreign.instance = [44; 32];
    let foreign = Signed::sign(&key(0), foreign).unwrap();
    // Child before parent: c2 is pending until c1 arrives, then wakes.
    assert_eq!(
        store.admit(c2.bytes()).await.unwrap().status.state,
        State::Pending
    );
    let malformed = [vec![1; 70], bad_sig, legacy, foreign.bytes().to_vec()];
    for bytes in &malformed {
        let o = store.admit(bytes).await.unwrap();
        assert_eq!((o.event, o.status.state), (None, State::Invalid));
    }
    for e in [&g, &c1, &wrong, &d, &r, &k, &orphan, &c2, &g] {
        store.admit(e.bytes()).await.unwrap();
    }
    let ids: BTreeSet<Hash> =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT event_id FROM cc_v1.candidates")
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|b| b.try_into().unwrap())
            .collect();
    let rejections: i64 = sqlx::query_scalar("SELECT count(*) FROM cc_v1.rejections")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejections, malformed.len() as i64);
    let view = store.snapshot(None).await.unwrap().projection;
    // Projection IDs are exactly the retained candidate IDs, one row each.
    assert_eq!(view.rows.len(), ids.len());
    assert_eq!(
        view.rows.iter().map(|r| r.event).collect::<BTreeSet<_>>(),
        ids
    );
    let state = |e: &Signed| {
        let row = view.rows.iter().find(|r| r.event == e.id()).unwrap();
        (row.state.clone(), row.reason.clone())
    };
    assert_eq!(state(&r), (P::Head, String::new()));
    assert_eq!(state(&c2), (P::Superseded, String::new()));
    assert_eq!(state(&k), (P::Branch, "revoked_concurrent".into()));
    assert_eq!(state(&wrong), (P::Invalid, "parent_authority".into()));
    assert_eq!(state(&orphan), (P::Pending, "parent_missing".into()));
    // A semantic reject retains its signed decision for audit.
    let row = view.rows.iter().find(|r| r.event == wrong.id()).unwrap();
    assert_eq!(row.envelope, wrong.envelope().clone());
    let frontier = |v: &cc_ledger::v1::Projection| v.subjects[0].frontier.clone();
    assert_eq!(frontier(&view), [r.id()].into());
    // A late eligible sibling reopens review; the revoked branch did not.
    let late = correction(&g, &g, 0, 40);
    store.admit(late.bytes()).await.unwrap();
    let view = store.snapshot(None).await.unwrap().projection;
    assert_eq!(frontier(&view), [r.id(), late.id()].into());
    assert_eq!(view.subjects[0].state, "contested");
    pool.close().await;
    cleanup.cleanup().await;
}

#[test]
fn v1_curator_root_is_not_subject_authority() {
    // Keys 0..4 are boot-pinned curators; key 5 is not.
    let outsider = subject(5, 70, 71);
    let curated = genesis();
    let by_curator = |s: &Signed, signer: u8| {
        reparent(&correction(s, s, signer, 9), s, root_grant(s.id()), signer)
    };
    let attempts = [by_curator(&outsider, 0), by_curator(&curated, 1)];
    let note = attest(0, TargetKind::Event, outsider.id(), "curator_note", 1);
    let b = subject(1, 50, 51);
    let pins = |s: &Signed| Pins {
        source: pin(&[s], s),
        target: pin(&[&b], &b),
    };
    let trusted = edge(0, "influence", pins(&curated));
    let untrusted = edge(0, "influence", pins(&outsider));
    let mut all: BTreeMap<_, _> = [&outsider, &curated, &note, &b, &trusted, &untrusted]
        .into_iter()
        .chain(&attempts)
        .map(|e| (e.id(), e.clone()))
        .collect();
    let admission = classify(&all);
    for a in &attempts {
        assert_eq!(admission[&a.id()].reason, "parent_authority");
    }
    let view = cc_ledger::v1::project(&all);
    for s in [&outsider, &curated] {
        let reading = view.subjects.iter().find(|x| x.subject == s.id()).unwrap();
        assert_eq!(reading.frontier, [s.id()].into());
    }
    let curators = filter().curators.into_iter().collect();
    let graph = support_graph(&view, &curators);
    assert_eq!(graph.subjects[&outsider.id()], "untrusted_origin");
    assert_eq!(graph.neighbors(b.id()).len(), 1);
    assert!(graph
        .excluded
        .iter()
        .any(|x| x.edge == untrusted.id() && x.reasons == ["source:untrusted_origin"]));
    // Removing the attestation changes nothing about authority or frontier.
    all.remove(&note.id());
    let without = cc_ledger::v1::project(&all);
    assert_eq!(without.authority, view.authority);
    assert_eq!(without.subjects, view.subjects);
}

#[test]
fn v1_decision_payload_matches_transition() {
    let g = genesis();
    let root = root_grant(g.id());
    let a = correction(&g, &g, 0, 7);
    let b2 = correction(&g, &g, 0, 8);
    let d = delegate(&g, &g, 0, root, 1);
    let r = revoke(&g, &d, 0, root, d.id(), false);
    let s = resolve(&g, &[&a, &b2], 0, root, Selection::MergedBody([10; 32]));
    let b = subject(1, 50, 51);
    let pins = Pins {
        source: pin(&[&g], &g),
        target: pin(&[&b], &b),
    };
    let e = edge(0, "influence", pins.clone());
    let re = reaffirm(0, &e, &[&e], pins.clone());
    let base = [&g, &a, &b2, &d, &r, &b, &e];
    let mut checked = 0;
    for (event, mutations) in [(&a, 6), (&d, 3), (&r, 3), (&s, 3), (&e, 3), (&re, 3)] {
        for m in 0..mutations {
            let mut env = event.envelope().clone();
            let dec = match &mut env.payload {
                Payload::Correction { decision, .. }
                | Payload::Delegate { decision, .. }
                | Payload::Revoke { decision, .. }
                | Payload::Resolve { decision, .. }
                | Payload::EdgeAssert { decision, .. }
                | Payload::EdgeReaffirm { decision, .. } => decision,
                _ => unreachable!(),
            };
            match m {
                0 => dec.old = Value::Body([99; 32]),
                1 => dec.new = Value::Revision([99; 32]),
                2 => dec.kind = Kind::Correction,
                3 => dec.rationale.clear(),
                4 => dec.evidence = Set(vec![]),
                _ => dec.parents = Set(vec![]),
            }
            if dec.kind == event.envelope().payload.kind() && m == 2 {
                dec.kind = Kind::Attestation;
            }
            let bad = Signed::sign(&key(0), env).unwrap();
            let mut all: BTreeMap<_, _> = base.iter().map(|e| (e.id(), (*e).clone())).collect();
            all.insert(bad.id(), bad.clone());
            assert_eq!(
                classify(&all)[&bad.id()].reason,
                "decision_mismatch",
                "{:?} mutation {m}",
                event.envelope().payload.kind()
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 21);
}

/// Operational failure is unavailable/retryable, never an invalid verdict, and
/// leaves no partial semantic state.
#[tokio::test]
async fn v1_resource_exhaustion_is_not_invalid() {
    let (pool, cleanup, store) = bound_store().await;
    let options = (*pool.connect_options()).clone();
    let g = genesis();
    pool.close().await;
    assert!(matches!(
        store.admit(g.bytes()).await,
        Err(Error::Database(_))
    ));
    assert!(matches!(
        store.snapshot(None).await,
        Err(Error::Database(_))
    ));
    let reopened = sqlx::PgPool::connect_with(options).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cc_v1.candidates")
        .fetch_one(&reopened)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let store = Store::provision(reopened.clone(), INSTANCE)
        .await
        .unwrap()
        .bind(filter())
        .await
        .unwrap();
    assert_eq!(
        store.admit(g.bytes()).await.unwrap().status.state,
        State::Valid
    );
    reopened.close().await;
    cleanup.cleanup().await;
}

/// `as_of` is applied after the authority/conflict fold: it hides a current
/// revision asserted after the query time but never selects an older body,
/// re-authorizes a revoked writer or changes the frontier.
#[tokio::test]
async fn as_of_reads_follow_the_fold_and_never_reauthorize() {
    let (pool, cleanup, store) = bound_store().await;
    let at = |t: u8| AssertedTime {
        coordinate: [t; 32],
        precision: "synthetic".into(),
    };
    let timed = |e: &Signed, t: u8, signer: u8| {
        let mut env = e.envelope().clone();
        env.asserted_time = Some(at(t));
        Signed::sign(&key(signer), env).unwrap()
    };
    let g = timed(&genesis(), 10, 0);
    let root = root_grant(g.id());
    let c = timed(&correction(&g, &g, 0, 5), 50, 0);
    let d = delegate(&g, &c, 0, root, 1);
    let r = revoke(&g, &d, 0, root, d.id(), false);
    // K's backdated out-of-cut correction stays suppressed at every as_of.
    let k = timed(&reparent(&correction(&g, &c, 1, 6), &d, d.id(), 1), 1, 1);
    let b = timed(&subject(1, 50, 51), 10, 1);
    let e = edge(
        0,
        "influence",
        Pins {
            source: pin(&[&g, &c, &d, &r], &r),
            target: pin(&[&b], &b),
        },
    );
    store
        .import(&[&g, &c, &d, &r, &k, &b, &e].map(|e| e.bytes().to_vec()))
        .await
        .unwrap();
    let s = store.snapshot(None).await.unwrap();
    let k_row = s
        .projection
        .rows
        .iter()
        .find(|x| x.event == k.id())
        .unwrap();
    assert_eq!(k_row.reason, "revoked_concurrent");
    let late = s.entity(g.id(), Some([60; 32]));
    let early = s.entity(g.id(), Some([20; 32]));
    assert_eq!(late.visibility, "visible");
    assert_eq!(late.revision.unwrap().id, revision_id(g.id(), c.id()));
    assert_eq!(
        (early.visibility.as_str(), early.revision),
        ("after_as_of", None)
    );
    assert_eq!(early.frontier, [r.id()].into());
    assert_eq!(early.frontier, late.frontier);
    assert!(matches!(
        s.verdict(g.id(), b.id(), Some([60; 32])).support,
        Support::Supported { .. }
    ));
    match s.verdict(g.id(), b.id(), Some([20; 32])).support {
        Support::Unsupported { reasons } => {
            let codes: Vec<_> = reasons.iter().map(|r| r.code.as_str()).collect();
            assert_eq!(codes[0], "after_as_of");
            assert!(codes.contains(&"excluded_edge:as_of:after_as_of"));
        }
        other => panic!("{other:?}"),
    }
    // Reads differ only in visibility; the committed fold is unchanged.
    assert_eq!(store.snapshot(None).await.unwrap(), s);
    assert_ne!(s.cache_key(b"as_of=20"), s.cache_key(b"as_of=60"));
    pool.close().await;
    cleanup.cleanup().await;
}
