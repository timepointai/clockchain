//! Stage (d): pinned edges, reaffirmation, enforced neighbors and media binding.
use cc_core::v1::*;
use cc_ledger::v1::{
    classify, project, support_graph, EdgeReading, Projection, ProjectionState as P, State, Support,
};
use cc_testkit::v1::*;
use std::collections::BTreeSet;

fn view(events: &[&Signed]) -> Projection {
    project(&events.iter().map(|e| (e.id(), (*e).clone())).collect())
}
fn row(v: &Projection, id: Hash) -> &cc_ledger::v1::EventReading {
    v.rows.iter().find(|r| r.event == id).unwrap()
}
fn edge_of(v: &Projection, id: Hash) -> &EdgeReading {
    v.edges.iter().find(|e| e.edge == id).unwrap()
}
fn curators() -> BTreeSet<Hash> {
    (0..4).map(|k| key(k).author().to_bytes()).collect()
}
fn neighbors(v: &Projection, subject: &Signed) -> Vec<Hash> {
    support_graph(v, &curators())
        .neighbors(subject.id())
        .iter()
        .map(|n| n.edge)
        .collect()
}
fn codes(s: Support) -> Vec<String> {
    match s {
        Support::Unsupported { reasons } => reasons.into_iter().map(|r| r.code).collect(),
        Support::Supported { .. } => panic!("unexpected support"),
    }
}
fn binding(v: &Projection, attestation: &Signed) -> (Option<Hash>, Option<Hash>) {
    let m = v
        .media
        .iter()
        .find(|m| m.attestation == attestation.id())
        .unwrap();
    (m.revision, m.body)
}

#[test]
fn i5_pins_survive_correction_resolution_and_reaffirmation() {
    let a = genesis();
    let root = root_grant(a.id());
    let b = subject(1, 50, 51);
    let original = revision_id(a.id(), a.id());
    let pins = Pins {
        source: pin(&[&a], &a),
        target: pin(&[&b], &b),
    };
    let e = edge(0, "influence", pins.clone());
    let image = attest(0, TargetKind::Revision, original, "image/png", 60);
    let base = [&a, &b, &e, &image];
    let v = view(&base);
    assert_eq!(edge_of(&v, e.id()).status, "current");
    assert_eq!(neighbors(&v, &a), vec![e.id()]);
    assert_eq!(neighbors(&v, &b), vec![e.id()]);
    assert_eq!(
        support_graph(&v, &curators()).query(a.id(), b.id(), 1),
        Support::Supported { path: vec![e.id()] }
    );
    assert_eq!(binding(&v, &image), (Some(original), Some([3; 32])));

    // Authority-only transitions on both endpoints keep the edge current.
    let d = delegate(&a, &a, 0, root, 4);
    let bd = delegate(&b, &b, 1, root_grant(b.id()), 5);
    let v = view(&[&a, &b, &e, &image, &d, &bd]);
    assert_eq!(row(&v, d.id()).state, P::Head);
    assert_eq!(edge_of(&v, e.id()).status, "current");
    assert_eq!(neighbors(&v, &a), vec![e.id()]);

    // Identical bytes in a new revision are a different identity: stale, not retargeted.
    let same = correction(&a, &a, 0, 3);
    let same_rev = revision_id(a.id(), same.id());
    let v = view(&[&a, &b, &e, &image, &same]);
    let r = edge_of(&v, e.id());
    assert_eq!(
        (r.status.as_str(), r.reasons.clone()),
        ("stale", vec!["source:revision_changed".to_owned()])
    );
    assert_eq!(r.pins, vec![pins.clone()]);
    assert_eq!(row(&v, e.id()).state, P::Head);
    assert!(neighbors(&v, &a).is_empty() && neighbors(&v, &b).is_empty());
    assert_eq!(
        codes(support_graph(&v, &curators()).query(a.id(), b.id(), 3)),
        [
            "no_current_support_path",
            "excluded_edge:stale",
            "excluded_edge:source:revision_changed"
        ]
    );
    // The prior image stays on the original revision; the new one has zero media.
    assert_eq!(binding(&v, &image), (Some(original), Some([3; 32])));
    assert!(!v.media.iter().any(|m| m.revision == Some(same_rev)));

    // A target correction stales the target pin too.
    let bc = correction(&b, &b, 1, 52);
    let v = view(&[&a, &b, &e, &bc]);
    assert_eq!(edge_of(&v, e.id()).reasons, ["target:revision_changed"]);

    // Correction followed by selecting the old revision does not restore the edge.
    let c7 = correction(&a, &a, 0, 7);
    let c8 = correction(&a, &a, 0, 8);
    let back = resolve(&a, &[&c7, &c8], 0, root, Selection::Revision(original));
    let contested = view(&[&a, &b, &e, &image, &c7, &c8]);
    let r = edge_of(&contested, e.id());
    assert_eq!(r.status, "endpoint_contested");
    assert_eq!(r.reasons, ["source:subject_contested"]);
    assert_eq!(r.pins, vec![pins.clone()]);
    assert!(neighbors(&contested, &b).is_empty());
    let q = codes(support_graph(&contested, &curators()).query(a.id(), b.id(), 3));
    assert_eq!(q[0], "subject_contested");
    assert!(q.contains(&"excluded_edge:endpoint_contested".to_owned()));
    let all = [&a, &b, &e, &image, &c7, &c8, &back];
    let v = view(&all);
    assert_eq!(row(&v, back.id()).revision, Some(original));
    assert_eq!(
        edge_of(&v, e.id()).reasons,
        ["source:revision_created_since_basis"]
    );
    assert!(neighbors(&v, &a).is_empty());
    assert_eq!(binding(&v, &image), (Some(original), Some([3; 32])));

    // Only the original author's reaffirmation advances the basis, even to the
    // original body; endpoint subjects and relation stay fixed.
    let new = Pins {
        source: pin(&all, &back),
        target: pins.target.clone(),
    };
    assert_eq!(new.source.revision, original);
    let r1 = reaffirm(0, &e, &[&e], new.clone());
    let v = view(&[&a, &b, &e, &image, &c7, &c8, &back, &r1]);
    let r = edge_of(&v, e.id());
    assert_eq!(
        (r.status.as_str(), r.heads.clone()),
        ("current", [r1.id()].into())
    );
    assert_eq!(r.history, [e.id(), r1.id()].into());
    assert_eq!(row(&v, e.id()).state, P::Superseded);
    assert_eq!(neighbors(&v, &a), vec![e.id()]);
    let stranger = reaffirm(1, &e, &[&e], new.clone());
    let mut moved = new.clone();
    moved.target = pin(&[&a], &a);
    let moved = reaffirm(0, &e, &[&e], moved);
    let v = view(&[&a, &b, &e, &c7, &c8, &back, &stranger, &moved]);
    assert_eq!(row(&v, stranger.id()).reason, "edge_author");
    assert_eq!(row(&v, moved.id()).reason, "endpoint_changed");
    assert_eq!(edge_of(&v, e.id()).heads, [e.id()].into());

    // Competing reaffirmations conflict and withdraw support until the author
    // signs one multi-parent reaffirmation with one old-pin pair per head.
    let after = delegate(&a, &same, 0, root, 6);
    let set = [&a, &b, &e, &same, &after];
    let p1 = Pins {
        source: pin(&set, &same),
        target: pins.target.clone(),
    };
    let p2 = Pins {
        source: pin(&set, &after),
        target: pins.target.clone(),
    };
    let r1 = reaffirm(0, &e, &[&e], p1);
    let r2 = reaffirm(0, &e, &[&e], p2.clone());
    let v = view(&[&a, &b, &e, &same, &after, &r1, &r2]);
    let r = edge_of(&v, e.id());
    assert_eq!(r.status, "edge_conflict");
    assert_eq!(r.heads, [r1.id(), r2.id()].into());
    assert_eq!(r.pins.len(), 2);
    assert_eq!(row(&v, r1.id()).reason, "edge_conflict");
    assert!(neighbors(&v, &a).is_empty());
    let join = reaffirm(0, &e, &[&r1, &r2], p2.clone());
    let foreign_join = reaffirm(1, &e, &[&r1, &r2], p2.clone());
    let comparable = reaffirm(0, &e, &[&e, &r1], p2.clone());
    let v = view(&[
        &a,
        &b,
        &e,
        &same,
        &after,
        &r1,
        &r2,
        &join,
        &foreign_join,
        &comparable,
    ]);
    assert_eq!(edge_of(&v, e.id()).heads, [join.id()].into());
    assert_eq!(edge_of(&v, e.id()).status, "current");
    assert_eq!(row(&v, foreign_join.id()).reason, "edge_author");
    assert_eq!(row(&v, comparable.id()).reason, "comparable_parents");
    assert_eq!(neighbors(&v, &a), vec![e.id()]);
    // Historical readings stay addressable; old heads are superseded, not erased.
    assert_eq!(
        edge_of(&v, e.id()).history,
        [e.id(), r1.id(), r2.id(), join.id()].into()
    );
    assert_eq!(row(&v, r1.id()).state, P::Superseded);
    // Without the author's key no other signer can clear the conflict.
    let v = view(&[&a, &b, &e, &same, &after, &r1, &r2, &foreign_join]);
    assert_eq!(edge_of(&v, e.id()).status, "edge_conflict");
}

#[test]
fn edge_admission_pins_disputes_and_media_are_exact() {
    let a = genesis();
    let b = subject(1, 50, 51);
    let same = correction(&a, &a, 0, 3);
    let set = [&a, &b, &same];
    let good = Pins {
        source: pin(&set, &a),
        target: pin(&set, &b),
    };
    let classify_one = |e: &Signed, extra: &[&Signed]| {
        let mut all: Vec<&Signed> = set.to_vec();
        all.extend(extra);
        all.push(e);
        classify(&all.iter().map(|e| (e.id(), (*e).clone())).collect())[&e.id()].clone()
    };
    let mut wrong = good.clone();
    wrong.source.body = [9; 32];
    assert_eq!(
        classify_one(&edge(0, "influence", wrong), &[]).reason,
        "pin_body"
    );
    // Identical body bytes do not make another revision the basis's selection.
    let mut wrong = good.clone();
    wrong.source.revision = revision_id(a.id(), same.id());
    assert_eq!(
        classify_one(&edge(0, "influence", wrong), &[]).reason,
        "pin_revision"
    );
    let mut wrong = good.clone();
    wrong.source.basis = b.id();
    assert_eq!(
        classify_one(&edge(0, "influence", wrong), &[]).reason,
        "pin_subject"
    );
    let mut missing = good.clone();
    missing.target.basis = [77; 32];
    let s = classify_one(&edge(0, "influence", missing), &[]);
    assert_eq!(
        (s.state, s.reason, s.missing),
        (State::Pending, "pin_missing".into(), vec![[77; 32]])
    );
    assert_eq!(
        classify_one(&edge(0, "supersession", good.clone()), &[]).reason,
        "relation"
    );
    let unknown = reaffirm(0, &edge(0, "influence", good.clone()), &[], good.clone());
    assert_eq!(classify_one(&unknown, &[]).reason, "parents");

    // Counterclaim: the disputer's own new subject names the exact revision.
    let counter = subject(2, 70, 71);
    let dispute = Pins {
        source: pin(&[&counter], &counter),
        target: good.source.clone(),
    };
    let ok = edge(2, "disputes", dispute.clone());
    let v = view(&[&a, &b, &counter, &ok]);
    assert_eq!(row(&v, ok.id()).state, P::Head);
    assert_eq!(edge_of(&v, ok.id()).status, "current");
    assert_eq!(row(&v, a.id()).state, P::Head);
    let g = support_graph(&v, &curators());
    assert!(g.neighbors(a.id()).is_empty());
    assert_eq!(g.excluded[0].reasons, ["disputes_not_support"]);
    assert_eq!(
        classify_one(&edge(0, "disputes", dispute), &[&counter]).reason,
        "dispute_counterclaim"
    );
    let selfish = Pins {
        source: good.source.clone(),
        target: pin(&set, &same),
    };
    assert_eq!(
        classify_one(&edge(0, "disputes", selfish), &[]).reason,
        "dispute_counterclaim"
    );

    // Trust root: an untrusted author or origin cannot supply support.
    let untrusted = edge(5, "influence", good.clone());
    let outsider = subject(5, 80, 81);
    let from_outsider = edge(
        0,
        "influence",
        Pins {
            source: pin(&[&outsider], &outsider),
            target: good.target.clone(),
        },
    );
    let v = view(&[&a, &b, &untrusted, &outsider, &from_outsider]);
    let g = support_graph(&v, &curators());
    assert!(g.neighbors(b.id()).is_empty());
    assert_eq!(g.excluded[0].reasons.len(), 1);
    assert!(g
        .excluded
        .iter()
        .any(|x| x.reasons == ["untrusted_edge_author"]));
    assert!(g
        .excluded
        .iter()
        .any(|x| x.reasons == ["source:untrusted_origin"]));
    assert_eq!(
        codes(g.query(outsider.id(), b.id(), 2))[0],
        "untrusted_origin"
    );

    // Media: exact revision or creating event only, never inferred or retargeted.
    let png = attest(0, TargetKind::Event, same.id(), "image/png", 61);
    let absence = attest(
        0,
        TargetKind::Revision,
        revision_id(a.id(), a.id()),
        "signed_absence",
        62,
    );
    let dl = delegate(&a, &a, 0, root_grant(a.id()), 4);
    let authority = attest(0, TargetKind::Event, dl.id(), "image/png", 63);
    let early = attest(
        0,
        TargetKind::Revision,
        revision_id(a.id(), [55; 32]),
        "image/png",
        64,
    );
    let bad = attest(0, TargetKind::Event, png.id(), "image/png", 65);
    let v = view(&[&a, &b, &same, &png, &absence, &authority, &early, &bad]);
    assert_eq!(
        binding(&v, &png),
        (Some(revision_id(a.id(), same.id())), Some([3; 32]))
    );
    assert_eq!(
        binding(&v, &absence),
        (Some(revision_id(a.id(), a.id())), Some([3; 32]))
    );
    assert_eq!(row(&v, authority.id()).reason, "target_missing");
    let v3 = view(&[&a, &dl, &authority]);
    assert_eq!(binding(&v3, &authority), (None, None));
    assert_eq!(row(&v, early.id()).reason, "revision_missing");
    assert_eq!(row(&v, bad.id()).reason, "attestation_target");
    let c = correction(&a, &same, 0, 12);
    let v2 = view(&[&a, &b, &same, &png, &absence, &c]);
    assert_eq!(binding(&v2, &png), binding(&v, &png));
    assert!(!v2
        .media
        .iter()
        .any(|m| m.revision == Some(revision_id(a.id(), c.id()))));
}
