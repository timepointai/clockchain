//! Stage (d) I1/I3 over edges: set invariants for every subset and generated
//! partition part; delivery-order convergence through the real PostgreSQL store.
use cc_core::v1::*;
use cc_ledger::v1::{
    classify, project, support_graph, Projection, ProjectionState, Store, SupportGraph,
};
use cc_testkit::v1::*;
use std::collections::{BTreeMap, BTreeSet};

type Set = BTreeMap<Hash, Signed>;
fn set(events: &[&Signed]) -> Set {
    events.iter().map(|e| (e.id(), (*e).clone())).collect()
}
fn curators() -> BTreeSet<Hash> {
    (0..4).map(|k| key(k).author().to_bytes()).collect()
}
fn read(s: &Set) -> (Projection, SupportGraph) {
    let v = project(s);
    let g = support_graph(&v, &curators());
    (v, g)
}

/// Structural invariants for any retained subset, compared against the full set.
fn check(s: &Set, v: &Projection, g: &SupportGraph, full: &Projection) {
    // I3: exactly one row per retained candidate, including edges and media.
    assert_eq!(
        v.rows.iter().map(|r| r.event).collect::<BTreeSet<_>>(),
        s.keys().copied().collect()
    );
    let selected = |subject: Hash| {
        let reading = v.subjects.iter().find(|x| x.subject == subject).unwrap();
        (reading.state == "resolved").then(|| {
            let head = reading.frontier.first().unwrap();
            v.rows.iter().find(|r| r.event == *head).unwrap().revision
        })
    };
    for e in &v.edges {
        // Pins are exactly the signed pins at the chain heads; never retargeted.
        for (head, pins) in e.heads.iter().zip(&e.pins) {
            match &s[head].envelope().payload {
                Payload::EdgeAssert { pins: p, .. } | Payload::EdgeReaffirm { new: p, .. } => {
                    assert_eq!(p, pins)
                }
                _ => panic!("edge head is not an edge event"),
            }
        }
        if e.status == "current" {
            for pin in [&e.pins[0].source, &e.pins[0].target] {
                assert_eq!(selected(pin.subject), Some(Some(pin.revision)));
            }
        }
        if e.heads.len() > 1 {
            assert_eq!(e.status, "edge_conflict");
        }
    }
    // Enforced neighbors: only current, non-dispute edges between resolved subjects.
    for (subject, ns) in &g.neighbors {
        assert_eq!(g.subjects[subject], "resolved");
        for n in ns {
            let e = v.edges.iter().find(|e| e.edge == n.edge).unwrap();
            assert_eq!(e.status, "current");
            assert_ne!(e.relation, "disputes");
        }
    }
    // Media bindings never follow a correction: identical whenever valid.
    for m in &v.media {
        assert_eq!(
            Some(m),
            full.media.iter().find(|f| f.attestation == m.attestation)
        );
    }
    for r in &v.rows {
        if r.state == ProjectionState::Pending || r.state == ProjectionState::Invalid {
            assert!(!g.neighbors.values().flatten().any(|n| n.edge == r.event));
        }
    }
}

/// Six named seven-event cases.
fn named_cases() -> Vec<Vec<Signed>> {
    let a = genesis();
    let root = root_grant(a.id());
    let b = subject(1, 50, 51);
    let pins = Pins {
        source: pin(&[&a], &a),
        target: pin(&[&b], &b),
    };
    let e = edge(0, "influence", pins.clone());
    let original = revision_id(a.id(), a.id());
    let mut cases = vec![];
    let mut case = |events: &[&Signed]| cases.push(events.iter().map(|e| (*e).clone()).collect());

    // 1. Same-bytes correction, reaffirmation and media that does not follow.
    let same = correction(&a, &a, 0, 3);
    let moved = Pins {
        source: pin(&[&a, &same], &same),
        target: pins.target.clone(),
    };
    let r = reaffirm(0, &e, &[&e], moved.clone());
    let image = attest(0, TargetKind::Revision, original, "image/png", 60);
    let png = attest(0, TargetKind::Event, same.id(), "image/png", 61);
    case(&[&a, &b, &e, &same, &r, &image, &png]);

    // 2. Competing reaffirmations and their multi-parent resolution.
    let after = delegate(&a, &same, 0, root, 6);
    let late = Pins {
        source: pin(&[&a, &same, &after], &after),
        target: pins.target.clone(),
    };
    let competing = reaffirm(0, &e, &[&e], late);
    case(&[&a, &b, &e, &same, &after, &r, &competing]);
    let r2 = reaffirm(0, &e, &[&e], pins.clone());
    let join = reaffirm(0, &e, &[&r, &r2], moved.clone());
    case(&[&a, &b, &e, &same, &r, &r2, &join]);

    // 3. Contested endpoint, then selecting the old revision (still stale).
    let c7 = correction(&a, &a, 0, 7);
    let c8 = correction(&a, &a, 0, 8);
    let back = resolve(&a, &[&c7, &c8], 0, root, Selection::Revision(original));
    let all = [&a, &b, &c7, &c8, &back];
    let again = reaffirm(
        0,
        &e,
        &[&e],
        Pins {
            source: pin(&all, &back),
            target: pins.target.clone(),
        },
    );
    case(&[&a, &b, &e, &c7, &c8, &back, &again]);

    // 4. Counterclaim dispute, authority-only target change and target media.
    let counter = subject(2, 70, 71);
    let dispute = edge(
        2,
        "disputes",
        Pins {
            source: pin(&[&counter], &counter),
            target: pins.source.clone(),
        },
    );
    let bd = delegate(&b, &b, 1, root_grant(b.id()), 5);
    let absence = attest(
        1,
        TargetKind::Revision,
        revision_id(b.id(), b.id()),
        "signed_absence",
        62,
    );
    case(&[&a, &b, &e, &counter, &dispute, &bd, &absence]);

    // 5. Pending and invalid edge events: wrong body, foreign reaffirmation,
    //    child-before-parent and unknown revision media.
    let mut wrong = pins.clone();
    wrong.target.body = [9; 32];
    let bad = edge(0, "influence", wrong);
    let foreign = reaffirm(1, &e, &[&e], pins.clone());
    let early = attest(
        0,
        TargetKind::Revision,
        revision_id(b.id(), [5; 32]),
        "image/png",
        63,
    );
    case(&[&r, &e, &bad, &foreign, &early, &a, &b]);
    cases
}

/// Set-function invariants (I3 over edges): every subset of each named case and
/// every part of seeded partitions of generated DAGs, read independently.
/// Union of a partition is the same `BTreeMap` as the full set, so union
/// equality is not claimed here; order dependence is tested through the store.
#[test]
fn i3_edge_subset_and_partition_invariants() {
    let mut subsets = 0;
    for events in named_cases() {
        let full = read(&set(&events.iter().collect::<Vec<_>>())).0;
        for mask in 0..(1u32 << events.len()) {
            let part: Vec<_> = (0..events.len())
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| &events[i])
                .collect();
            let s = set(&part);
            let (v, g) = read(&s);
            check(&s, &v, &g, &full);
            subsets += 1;
        }
    }
    assert_eq!(subsets, 6 * 128);
    let mut rng = Rng(20261002);
    let (mut parts_checked, mut edges) = (0, 0);
    let mut statuses: BTreeMap<String, usize> = BTreeMap::new();
    let dags = generated_dags();
    for events in &dags {
        let full_set = set(&events.iter().collect::<Vec<_>>());
        let (full, full_graph) = read(&full_set);
        check(&full_set, &full, &full_graph, &full);
        edges += full.edges.len();
        for e in &full.edges {
            *statuses.entry(e.status.clone()).or_default() += 1;
        }
        for r in &full.rows {
            if matches!(r.envelope.payload, Payload::EdgeReaffirm { .. }) {
                let key = format!("reaffirm:{:?}:{}", r.state, r.reason);
                *statuses.entry(key).or_default() += 1;
            }
        }
        for _ in 0..8 {
            let count = 2 + rng.below(2);
            let mut split = vec![Set::new(); count];
            for e in events {
                split[rng.below(count)].insert(e.id(), e.clone());
            }
            for part in &split {
                let (v, g) = read(part);
                check(part, &v, &g, &full);
                parts_checked += 1;
            }
        }
    }
    assert_eq!(dags.len(), 60);
    assert!(edges > 60, "generator must exercise edges");
    for status in ["current", "stale", "endpoint_contested", "edge_conflict"] {
        assert!(statuses.contains_key(status), "generator missed {status}");
    }
    eprintln!(
        "Stage (d) set invariants: {subsets} named subsets; {} DAGs, {parts_checked} partition parts; {edges} generated edges; {statuses:?}",
        dags.len()
    );
}

/// I1 over edges through a path that could depend on order: each delivery is a
/// separate `Store::admit` transaction against real PostgreSQL that rereads
/// retained bytes. Child-before-parent (reverse) and duplicate redelivery are
/// included. Each arrival result must equal the set function of what has been
/// delivered so far, and the stored projection must equal the full set's.
#[tokio::test]
async fn i1_edge_store_delivery_order_convergence() {
    let mut rng = Rng(20261003);
    let mut samples: Vec<(Vec<Signed>, usize)> =
        named_cases().into_iter().map(|c| (c, 6)).collect();
    samples.extend(generated_dags().into_iter().take(10).map(|c| (c, 2)));
    let (mut orders, mut deliveries) = (0, 0);
    for (events, count) in samples {
        let full_set = set(&events.iter().collect::<Vec<_>>());
        let full = read(&full_set);
        for k in 0..count {
            let mut order: Vec<usize> = (0..events.len()).collect();
            match k {
                0 => {}
                1 => order.reverse(),
                _ => {
                    for i in (1..order.len()).rev() {
                        order.swap(i, rng.below(i + 1));
                    }
                }
            }
            order.extend([order[0], order[order.len() / 2]]);
            let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
            let store = Store::provision(pool.clone(), INSTANCE).await.unwrap();
            let mut delivered = Set::new();
            for &i in &order {
                let e = &events[i];
                delivered.insert(e.id(), e.clone());
                let outcome = store.admit(e.bytes()).await.unwrap();
                assert_eq!(outcome.status, classify(&delivered)[&e.id()]);
                deliveries += 1;
            }
            let stored = store.review_projection().await.unwrap();
            let graph = support_graph(&stored, &curators());
            assert_eq!((stored, graph), full);
            // Restore of the same bytes in another order is idempotent.
            let replay: Vec<_> = order
                .iter()
                .rev()
                .map(|&i| events[i].bytes().to_vec())
                .collect();
            store.restore(&replay).await.unwrap();
            assert_eq!(store.review().await.unwrap(), classify(&full_set));
            pool.close().await;
            cleanup.cleanup().await;
            orders += 1;
        }
    }
    assert_eq!(orders, 6 * 6 + 10 * 2);
    eprintln!("Stage (d) store delivery: {orders} orders, {deliveries} admissions");
}

struct Rng(u64);
impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

/// Seeded larger DAGs: forks, merges, authority-only steps, edges, disputes,
/// reaffirmation forks/joins, non-author reaffirmations and media.
fn generated_dags() -> Vec<Vec<Signed>> {
    let mut out = vec![];
    let mut rng = Rng(20261001);
    for case in 0..60u8 {
        let subjects = [
            genesis(),
            subject(1, 100 + case, 3),
            subject(2, 200u8.wrapping_add(case), 3),
        ];
        let mut events: Vec<Signed> = subjects.to_vec();
        let mut fresh = 10u8;
        let mut edges: Vec<(Signed, Vec<Signed>)> = vec![];
        for step in 0..14 {
            let pick = rng.below(7);
            let s = rng.below(3);
            let g = &subjects[s];
            let own: Vec<Signed> = events
                .iter()
                .filter(|e| {
                    matches!(
                        e.envelope().payload,
                        Payload::Genesis { .. }
                            | Payload::Correction { .. }
                            | Payload::Delegate { .. }
                    ) && e.envelope().subject.unwrap_or(e.id()) == g.id()
                })
                .cloned()
                .collect();
            let refs: Vec<&Signed> = events.iter().collect();
            let next = match pick {
                0 | 1 => {
                    let p = &own[rng.below(own.len())];
                    let body = [3, 3, 40 + step][rng.below(3)];
                    let mut e = correction(g, g, s as u8, body).envelope().clone();
                    e.parents = cc_core::v1::Set(vec![p.id()]);
                    if let Payload::Correction { decision, .. } = &mut e.payload {
                        decision.parents = e.parents.clone();
                        decision.old = Value::Body(body_at(&refs, p));
                    }
                    Signed::sign(&key(s as u8), e).unwrap()
                }
                2 => {
                    let p = &own[rng.below(own.len())];
                    fresh += 1;
                    delegate(g, p, s as u8, root_grant(g.id()), fresh)
                }
                3 => {
                    let frontier = &project(&set(&refs))
                        .subjects
                        .into_iter()
                        .find(|x| x.subject == g.id())
                        .unwrap()
                        .frontier;
                    if frontier.len() < 2 {
                        continue;
                    }
                    let ps: Vec<&Signed> = frontier
                        .iter()
                        .take(2)
                        .map(|id| refs.iter().find(|e| e.id() == *id).copied().unwrap())
                        .collect();
                    resolve(
                        g,
                        &ps,
                        s as u8,
                        root_grant(g.id()),
                        Selection::MergedBody([90 + step; 32]),
                    )
                }
                4 => {
                    let t = (s + 1 + rng.below(2)) % 3;
                    let target = &subjects[t];
                    let other: Vec<&Signed> = own_events(&refs, target.id()).into_iter().collect();
                    let pins = Pins {
                        source: pin(&refs, &own[rng.below(own.len())]),
                        target: pin(&refs, other[rng.below(other.len())]),
                    };
                    let relation = if rng.below(4) == 0 && s == 2 {
                        "disputes"
                    } else {
                        "influence"
                    };
                    let e = edge(s as u8, relation, pins);
                    edges.push((e.clone(), vec![e.clone()]));
                    e
                }
                5 if !edges.is_empty() => {
                    let i = rng.below(edges.len());
                    let (base, chain) = edges[i].clone();
                    let author = rng.below(5) as u8; // occasionally a non-author
                    let ends = match &base.envelope().payload {
                        Payload::EdgeAssert { pins, .. } => {
                            (pins.source.subject, pins.target.subject)
                        }
                        _ => unreachable!(),
                    };
                    let a_ev = own_events(&refs, ends.0);
                    let b_ev = own_events(&refs, ends.1);
                    let new = Pins {
                        source: pin(&refs, a_ev[rng.below(a_ev.len())]),
                        target: pin(&refs, b_ev[rng.below(b_ev.len())]),
                    };
                    let parents: Vec<&Signed> = if chain.len() > 2 && rng.below(2) == 0 {
                        heads(&chain).into_iter().collect()
                    } else {
                        vec![&chain[rng.below(chain.len())]]
                    };
                    let signer = if author == 4 {
                        3
                    } else {
                        edge_author_key(&base)
                    };
                    let r = reaffirm(signer, &base, &parents, new);
                    edges[i].1.push(r.clone());
                    r
                }
                _ => {
                    let target = &events[rng.below(events.len())];
                    if rng.below(2) == 0 {
                        attest(s as u8, TargetKind::Event, target.id(), "image/png", step)
                    } else {
                        let r = revision_id(g.id(), own[rng.below(own.len())].id());
                        attest(s as u8, TargetKind::Revision, r, "signed_absence", step)
                    }
                }
            };
            events.push(next);
        }
        out.push(events);
    }
    out
}

fn own_events<'a>(refs: &[&'a Signed], subject: Hash) -> Vec<&'a Signed> {
    refs.iter()
        .filter(|e| {
            matches!(
                e.envelope().payload,
                Payload::Genesis { .. }
                    | Payload::Correction { .. }
                    | Payload::Delegate { .. }
                    | Payload::Resolve { .. }
            ) && e.envelope().subject.unwrap_or(e.id()) == subject
        })
        .copied()
        .collect()
}
fn body_at(refs: &[&Signed], p: &Signed) -> Hash {
    let v = project(&set(refs));
    let revision = v
        .rows
        .iter()
        .find(|r| r.event == p.id())
        .unwrap()
        .revision
        .unwrap();
    v.revisions.iter().find(|r| r.id == revision).unwrap().body
}
fn heads(chain: &[Signed]) -> Vec<&Signed> {
    let parents: BTreeSet<Hash> = chain
        .iter()
        .flat_map(|e| e.envelope().parents.0.clone())
        .collect();
    chain
        .iter()
        .filter(|e| !parents.contains(&e.id()))
        .collect()
}
fn edge_author_key(edge: &Signed) -> u8 {
    (0..5)
        .find(|k| key(*k).author().to_bytes() == edge.envelope().author)
        .unwrap()
}
