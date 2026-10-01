use cc_core::v1::*;
use cc_ledger::v1::{project, Projection, ProjectionState as P};
use cc_testkit::v1::*;
use std::collections::BTreeMap;
fn view(events: &[&Signed]) -> Projection {
    project(&events.iter().map(|e| (e.id(), (*e).clone())).collect())
}
fn row(v: &Projection, id: Hash) -> &cc_ledger::v1::EventReading {
    v.rows.iter().find(|r| r.event == id).unwrap()
}
#[test]
fn i3_partial_competing_resolutions_and_late_eligible_reopening() {
    let g = genesis();
    let root = root_grant(g.id());
    let a = correction(&g, &g, 0, 7);
    let b = correction(&g, &g, 0, 8);
    let c = correction(&g, &g, 0, 9);
    let s = resolve(&g, &[&a, &b], 0, root, Selection::MergedBody([10; 32]));
    let t = resolve(&g, &[&a, &b], 0, root, Selection::MergedBody([11; 32]));
    let u = resolve(&g, &[&s, &t], 0, root, Selection::MergedBody([12; 32]));
    assert_eq!(
        view(&[&g, &a, &b, &s]).subjects[0].frontier,
        [s.id()].into()
    );
    let v = view(&[&g, &a, &b, &s, &c]);
    assert_eq!(v.subjects[0].frontier, [s.id(), c.id()].into());
    assert_eq!(row(&v, a.id()).reason, "contested");
    assert_eq!(row(&v, g.id()).state, P::Superseded);
    assert_eq!(
        view(&[&g, &a, &b, &s, &t]).subjects[0].frontier,
        [s.id(), t.id()].into()
    );
    assert_eq!(
        view(&[&g, &a, &b, &s, &t, &u]).subjects[0].frontier,
        [u.id()].into()
    );
    // Child-first never loses the retained event; its decision stays inspectable.
    let pending = view(&[&u]);
    assert_eq!(pending.rows[0].state, P::Pending);
    assert_eq!(pending.rows[0].envelope, u.envelope().clone());
}
#[test]
fn i4_revision_selection_is_immutable_and_does_not_omit_authority() {
    let g = genesis();
    let root = root_grant(g.id());
    let original = revision_id(g.id(), g.id());
    let a = correction(&g, &g, 0, 7);
    let mut b = correction(&g, &g, 0, 7).envelope().clone();
    if let Payload::Correction { decision, .. } = &mut b.payload {
        decision.rationale = "Distinct synthetic evidence for identical body bytes".into();
    }
    let b = Signed::sign(&key(0), b).unwrap();
    let s = resolve(&g, &[&a, &b], 0, root, Selection::Revision(original));
    let d = delegate(&g, &s, 0, root, 1);
    let r = revoke(&g, &d, 0, root, d.id(), false);
    let v = view(&[&g, &a, &b, &s, &d, &r]);
    assert_eq!(v.revisions.len(), 3);
    assert_ne!(revision_id(g.id(), a.id()), revision_id(g.id(), b.id()));
    for e in [&s, &d, &r] {
        assert_eq!(row(&v, e.id()).revision, Some(original));
    }
    assert!(v.authority.tombstones.contains(&d.id()));
    let selected = resolve(&g, &[&a, &r], 0, root, Selection::Revision(original));
    // Comparable parents rejected even if the selected body is old and valid.
    assert_eq!(
        row(&view(&[&g, &a, &b, &s, &d, &r, &selected]), selected.id()).reason,
        "comparable_parents"
    );
    let late = correction(&g, &g, 0, 13);
    let join = resolve(&g, &[&r, &late], 0, root, Selection::Revision(original));
    let v = view(&[&g, &a, &b, &s, &d, &r, &late, &join]);
    assert_eq!(row(&v, join.id()).state, P::Head);
    assert!(!v.authority.active.contains(&d.id()));
    let mut changed = correction(&g, &g, 0, 14).envelope().clone();
    changed.parents = Set(vec![join.id()]);
    if let Payload::Correction { decision, .. } = &mut changed.payload {
        decision.parents = changed.parents.clone();
    }
    let changed = Signed::sign(&key(0), changed).unwrap();
    assert_eq!(
        row(
            &view(&[&g, &a, &b, &s, &d, &r, &late, &join, &changed]),
            changed.id()
        )
        .state,
        P::Head
    );
}
#[test]
fn resolve_decisions_and_reachable_eligible_revision_are_checked() {
    let g = genesis();
    let root = root_grant(g.id());
    let a = correction(&g, &g, 0, 7);
    let b = correction(&g, &g, 0, 8);
    let s = resolve(&g, &[&a, &b], 0, root, Selection::MergedBody([10; 32]));
    for mutation in 0..9 {
        let mut e = s.envelope().clone();
        if let Payload::Resolve {
            decision,
            dispositions,
            selection,
        } = &mut e.payload
        {
            match mutation {
                0 => decision.old = Value::None,
                1 => decision.new = Value::Body([99; 32]),
                2 => decision.parents = Set(vec![]),
                3 => {
                    dispositions.0.pop();
                }
                4 => dispositions.0[0].rationale.clear(),
                5 => {
                    for d in &mut dispositions.0 {
                        d.action = DispositionKind::NotSelected;
                    }
                }
                6 => dispositions.0[0].action = DispositionKind::Selected,
                7 => {
                    *selection = Selection::Revision([99; 32]);
                    decision.new = Value::Revision([99; 32]);
                }
                _ => e.subject_key.as_mut().unwrap().value = "another".into(),
            }
        }
        let bad = Signed::sign(&key(0), e).unwrap();
        assert_eq!(
            row(&view(&[&g, &a, &b, &bad]), bad.id()).state,
            P::Invalid,
            "mutation {mutation}"
        );
    }
    // A selected parent must contain the named revision; a sibling is insufficient.
    let mut selecting = resolve(
        &g,
        &[&a, &b],
        0,
        root,
        Selection::Revision(revision_id(g.id(), a.id())),
    )
    .envelope()
    .clone();
    let bad = Signed::sign(&key(0), selecting.clone()).unwrap();
    assert_eq!(
        row(&view(&[&g, &a, &b, &bad]), bad.id()).reason,
        "disposition_mismatch"
    );
    if let Payload::Resolve { dispositions, .. } = &mut selecting.payload {
        dispositions
            .0
            .iter_mut()
            .find(|d| d.parent == b.id())
            .unwrap()
            .action = DispositionKind::NotSelected;
    }
    let good = Signed::sign(&key(0), selecting.clone()).unwrap();
    assert_eq!(row(&view(&[&g, &a, &b, &good]), good.id()).state, P::Head);
    selecting.asserted_time = Some(AssertedTime {
        coordinate: [8; 32],
        precision: "synthetic".into(),
    });
    let bad = Signed::sign(&key(0), selecting).unwrap();
    assert_eq!(
        row(&view(&[&g, &a, &b, &bad]), bad.id()).reason,
        "selection_time_edit"
    );
}
#[test]
fn freeze_and_counterclaim_have_independent_subject_authority() {
    let g = genesis();
    let root = root_grant(g.id());
    let r = revoke(&g, &g, 0, root, root, true);
    let mut counter = g.envelope().clone();
    if let Payload::Genesis { nonce, .. } = &mut counter.payload {
        *nonce = [88; 32];
    }
    let counter = Signed::sign(&key(1), counter).unwrap();
    let mut c = correction(&g, &g, 1, 7).envelope().clone();
    c.parents = Set(vec![r.id()]);
    if let Payload::Correction { decision, .. } = &mut c.payload {
        decision.parents = c.parents.clone();
    }
    let c = Signed::sign(&key(1), c).unwrap();
    let v = view(&[&g, &r, &counter, &c]);
    let frozen = v.subjects.iter().find(|s| s.subject == g.id()).unwrap();
    assert!(frozen.frozen);
    assert_eq!(frozen.state, "no_current_body");
    assert_eq!(row(&v, c.id()).reason, "parent_authority");
    assert_eq!(row(&v, counter.id()).state, P::Head);
    assert_eq!(v.subjects.len(), 2);
}
#[test]
fn suppressed_revision_cannot_be_selected_even_by_a_surviving_resolver() {
    let g = genesis();
    let root = root_grant(g.id());
    let d = delegate(&g, &g, 0, root, 1);
    let mut a = correction(&g, &g, 1, 7).envelope().clone();
    a.parents = Set(vec![d.id()]);
    a.grant = Some(d.id());
    if let Payload::Correction { decision, .. } = &mut a.payload {
        decision.parents = a.parents.clone();
    }
    let a = Signed::sign(&key(1), a).unwrap();
    let r = revoke(&g, &d, 0, root, d.id(), false);
    let s = resolve(
        &g,
        &[&a, &r],
        0,
        root,
        Selection::Revision(revision_id(g.id(), a.id())),
    );
    let v = view(&[&g, &d, &a, &r, &s]);
    assert_eq!(row(&v, s.id()).reason, "revision_ineligible");
    assert_eq!(row(&v, a.id()).reason, "revoked_concurrent");
    assert_eq!(v.subjects[0].frontier, [r.id()].into());
}
#[test]
fn deep_authority_only_selection_is_iterative() {
    let g = genesis();
    let mut candidates = BTreeMap::from([(g.id(), g.clone())]);
    let mut last = g.clone();
    for i in 1..80 {
        let d = delegate(
            &g,
            &last,
            if i == 1 { 0 } else { i - 1 },
            if i == 1 {
                root_grant(g.id())
            } else {
                last.id()
            },
            i,
        );
        candidates.insert(d.id(), d.clone());
        last = d;
    }
    let v = project(&candidates);
    assert_eq!(
        row(&v, last.id()).revision,
        Some(revision_id(g.id(), g.id()))
    );
}

#[tokio::test]
async fn earlier_stage_stores_refuse_silent_stage_e_reinterpretation() {
    // Stage (b), (c) and (d) interim schema hashes.
    for old in [
        "512ac326efd97b6c27b6a2ff6fb37d3a5cb4be6bf13a36fd08f0d445a719d9d4",
        "3bd85f59908a58175af6f5d675d2539b6259fca20dd42d62192a7be2d3f727f0",
        "01e03b64df9c36fed05cc77c3a71c9293fc1afbd0cf945a0828b4d27b5f2b540",
    ] {
        let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
        sqlx::raw_sql("CREATE SCHEMA cc_v1; CREATE TABLE cc_v1.identity(singleton boolean,instance bytea,encoding smallint,schema_hash bytea)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO cc_v1.identity VALUES(true,$1,1,$2)")
            .bind(INSTANCE.to_vec())
            .bind(hex::decode(old).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            cc_ledger::v1::Store::provision(pool.clone(), INSTANCE).await,
            Err(cc_ledger::v1::Error::Identity)
        ));
        pool.close().await;
        cleanup.cleanup().await;
    }
}
