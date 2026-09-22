//! Algebraic properties of the filter, over a generated in-memory corpus.
//!
//! These are not mocked-database tests. The no-mocks rule targets tests that
//! fake a *service*; `cc-filter` is a pure function of a `CorpusView`, and
//! generating inputs over its domain is the only way to exercise the algebra it
//! is supposed to obey. The adapter equivalence test — that `cc-ledger`'s
//! Postgres view answers byte-identically to this one on the same event set —
//! belongs in `cc-testkit` against a real database and is the no-mocks
//! integration half of this pair.

use cc_core::{EventId, FractionalBits, Tick, WindowEnd};
use cc_filter::{
    known_k, B256Constants, ClaimType, CooccurrenceRuleId, CorpusDigest, CorpusView, Edge,
    EntityId, FeasibilityQuery, Filter, FilterError, FilterParams, HopBound, Reachability, Record,
    Ruling, SmoothingId, SnapshotCorpus, Start, TimeScaleId, Verdict, VerdictKind, ViewError,
    VocabularyVersion, SUPPORT_PATH_LOGIC_TAG,
};
use proptest::prelude::*;
use std::collections::BTreeSet;

// ===========================================================================
// Fixtures and helpers
// ===========================================================================

/// The governed bound every generated query is searched under.
const K_MAX: u8 = 4;

fn params() -> FilterParams {
    FilterParams {
        cooccurrence_rule: CooccurrenceRuleId::from_bytes([0x11; 32]),
        k_max: HopBound::new(K_MAX),
        smoothing: SmoothingId::from_bytes([0x22; 32]),
        vocabulary: VocabularyVersion::from_bytes([0x33; 32]),
        b256: B256Constants {
            clock_zero_scale: TimeScaleId::TCB,
            tick_attoseconds: 1_000_000_000_000_000_000,
            split: FractionalBits(64),
        },
        logic_tag: SUPPORT_PATH_LOGIC_TAG,
    }
}

fn ev(n: u8) -> EventId {
    EventId::from_bytes([n; 32])
}

fn t(n: i64) -> Tick {
    Tick::from_i64(n)
}

fn e(n: i64) -> EntityId {
    EntityId::from_i64(n)
}

/// Verdict kind plus `supp(Φ)` — the projection two nodes must agree on. The
/// corpus digest is excluded on purpose: it necessarily differs once an event is
/// added, and comparing it would make every accretion test fail for the wrong
/// reason.
fn projection(
    j: &Result<cc_filter::Judgment, FilterError>,
) -> Option<cc_filter::ConsensusProjection> {
    j.as_ref().ok().map(|j| j.consensus_projection())
}

fn kind_of(f: &Filter, c: &SnapshotCorpus, q: &FeasibilityQuery) -> Option<VerdictKind> {
    f.feasibility(c, q).ok().map(|j| j.verdict.kind())
}

// ===========================================================================
// Generators
// ===========================================================================

const N_ENTITIES: i64 = 6;
const MAX_TICK: i64 = 200;

fn any_entity() -> impl Strategy<Value = EntityId> {
    (1i64..=N_ENTITIES).prop_map(e)
}

fn any_tick() -> impl Strategy<Value = Tick> {
    (0i64..=MAX_TICK).prop_map(t)
}

fn any_event() -> impl Strategy<Value = EventId> {
    (0u8..=200u8).prop_map(ev)
}

fn any_start() -> impl Strategy<Value = Start> {
    prop_oneof![Just(Start::Unknown), any_tick().prop_map(Start::Known),]
}

fn any_end() -> impl Strategy<Value = WindowEnd> {
    prop_oneof![
        Just(WindowEnd::KnownOpen),
        Just(WindowEnd::UnknownClosure),
        any_tick().prop_map(WindowEnd::KnownClosed),
    ]
}

/// A co-occurrence between two *distinct* entities: `b` is drawn from a range one
/// short and shifted past `a`, so a self-co-occurrence is not generable rather
/// than generated-and-filtered.
fn any_cooccurrence() -> impl Strategy<Value = Record> {
    (
        (1i64..=N_ENTITIES),
        (1i64..N_ENTITIES),
        any_tick(),
        any_event(),
    )
        .prop_map(|(a, b_raw, at, via)| {
            let b = if b_raw >= a { b_raw + 1 } else { b_raw };
            Record::CoOccurrence {
                a: e(a),
                b: e(b),
                at,
                via,
            }
        })
}

fn any_window_record() -> impl Strategy<Value = Record> {
    (
        any_entity(),
        any_tick(),
        any_event(),
        any_start(),
        any_end(),
    )
        .prop_map(|(entity, recorded_at, via, start, end)| Record::Window {
            entity,
            recorded_at,
            via,
            start,
            end,
        })
}

fn any_admissibility_record() -> impl Strategy<Value = Record> {
    (
        (1u32..=3u32),
        any_tick(),
        any_event(),
        prop_oneof![
            Just(Ruling::Valid),
            any_tick().prop_map(|band_end| Ruling::OutsideValidity { band_end }),
        ],
    )
        .prop_map(|(claim, recorded_at, via, ruling)| Record::Admissibility {
            claim: ClaimType::from_u32(claim),
            recorded_at,
            via,
            ruling,
        })
}

fn any_record() -> impl Strategy<Value = Record> {
    prop_oneof![
        3 => any_cooccurrence(),
        2 => any_window_record(),
        1 => any_admissibility_record(),
    ]
}

/// Well-formed record sets: at most one record per `(kind, key)`.
///
/// The generator deliberately does **not** produce contradictory corpora — two
/// records disagreeing about one evidence event. `SnapshotCorpus` refuses those,
/// and a property about the filter's algebra should not be derailed by input the
/// constructor rejects before the filter ever runs. Rejection has its own test:
/// `contradictory_records_are_refused_in_either_order`.
fn any_records() -> impl Strategy<Value = Vec<Record>> {
    prop::collection::vec(any_record(), 0..24).prop_map(well_formed)
}

/// Keep at most one record per `(kind, key)`, first wins.
///
/// `SnapshotCorpus` refuses a set that disagrees with itself about one evidence
/// event, so a generator that produced such sets would derail every property
/// about the filter's algebra at construction, before the filter ever ran.
/// Re-stamping records onto a shared coordinate — which the accretion property
/// does — collides keys that were distinct, so this is applied there too.
fn well_formed(records: Vec<Record>) -> Vec<Record> {
    let mut seen = std::collections::BTreeSet::new();
    records
        .into_iter()
        .filter(|r| match r {
            Record::CoOccurrence { .. } => true,
            Record::Window {
                entity,
                recorded_at,
                via,
                ..
            } => seen.insert((0u8, entity.to_i64(), *recorded_at, *via)),
            Record::Admissibility {
                claim,
                recorded_at,
                via,
                ..
            } => seen.insert((1u8, i64::from(claim.to_u32()), *recorded_at, *via)),
        })
        .collect()
}

fn any_query() -> impl Strategy<Value = FeasibilityQuery> {
    (
        any_entity(),
        any_entity(),
        any_tick(),
        (1u32..=3u32),
        (0u8..=K_MAX),
    )
        .prop_map(|(a, b, t_q, claim, k)| FeasibilityQuery {
            subjects: (a, b),
            t_q,
            claim: ClaimType::from_u32(claim),
            k: HopBound::new(k),
        })
}

// ===========================================================================
// 1. Replay determinism — the consensus rule itself
// ===========================================================================

proptest! {
    /// Same events, same rule, same verdict — including `supp(Φ)` and the version.
    #[test]
    fn determinism_same_events_same_verdict(records in any_records(), q in any_query()) {
        let f = Filter::new(params());
        let a = SnapshotCorpus::from_records(records.clone()).unwrap();
        let b = SnapshotCorpus::from_records(records).unwrap();
        prop_assert_eq!(projection(&f.feasibility(&a, &q)), projection(&f.feasibility(&b, &q)));
    }
}

// ===========================================================================
// 2. Order independence — CRDT convergence at the filter level
// ===========================================================================

proptest! {
    /// Insert the same event set in shuffled orders; the view, its digest, and
    /// every verdict must be identical. This is the guard against insertion order
    /// or hash-map iteration leaking into an emitted bit.
    #[test]
    fn order_independence(records in any_records(), q in any_query()) {
        let f = Filter::new(params());
        let reversed: Vec<Record> = records.iter().rev().copied().collect();
        let forward = SnapshotCorpus::from_records(records.clone());
        let backward = SnapshotCorpus::from_records(reversed);

        // The property is that the OUTCOME is a function of the record set —
        // which includes rejection. A set carrying two different rulings for one
        // evidence event is contradictory, and must be refused in both orders
        // rather than resolved differently depending on which arrived last.
        match (forward, backward) {
            (Ok(forward), Ok(backward)) => {
                prop_assert_eq!(forward.corpus_digest(), backward.corpus_digest());
                prop_assert_eq!(
                    projection(&f.feasibility(&forward, &q)),
                    projection(&f.feasibility(&backward, &q))
                );
            }
            (Err(a), Err(b)) => prop_assert_eq!(format!("{a}"), format!("{b}")),
            (a, b) => prop_assert!(
                false,
                "one order accepted and the other refused: {:?} vs {:?}",
                a.is_ok(),
                b.is_ok()
            ),
        }
    }
}

// ===========================================================================
// 3. Monotonicity under non-revocable accretion
// ===========================================================================

proptest! {
    /// Adding co-occurrence evidence at or before `t_q` can only relax a verdict
    /// from reject toward accept: a `Supported` stays `Supported`.
    ///
    /// The delta is co-occurrence only because that is what "non-revocable"
    /// means here — a later window or vocabulary record can *tighten*, and
    /// tightening is revocation, which two-valued monotonicity explicitly does
    /// not cover.
    #[test]
    fn supported_survives_non_revocable_accretion(
        records in any_records(),
        q in any_query(),
        delta in prop::collection::vec(any_cooccurrence(), 0..8),
    ) {
        let f = Filter::new(params());
        let before = SnapshotCorpus::from_records(records.clone()).unwrap();
        if kind_of(&f, &before, &q) != Some(VerdictKind::Supported) {
            return Ok(());
        }

        let mut accreted = records;
        for r in delta {
            if let Record::CoOccurrence { a, b, via, .. } = r {
                // Pinned at or before t_q: this is evidence the query's own time
                // slice is allowed to see.
                accreted.push(Record::CoOccurrence { a, b, at: q.t_q, via });
            }
        }
        let after = SnapshotCorpus::from_records(well_formed(accreted)).unwrap();
        prop_assert_eq!(kind_of(&f, &after, &q), Some(VerdictKind::Supported));
    }
}

proptest! {
    /// The sharpest case: an event with event-time *after* `t_q` changes nothing
    /// about a `t_q`-pinned verdict. A 2017 moment cannot touch a 2016-pinned
    /// verdict, because the view never yields it.
    #[test]
    fn future_events_cannot_touch_a_pinned_verdict(
        records in any_records(),
        q in any_query(),
        delta in any_records(),
    ) {
        let f = Filter::new(params());
        let before = SnapshotCorpus::from_records(records.clone()).unwrap();

        let future = t(MAX_TICK + 1_000);
        prop_assume!(q.t_q < future);
        let mut accreted = records;
        for r in delta {
            accreted.push(match r {
                Record::CoOccurrence { a, b, via, .. } =>
                    Record::CoOccurrence { a, b, at: future, via },
                Record::Window { entity, via, start, end, .. } =>
                    Record::Window { entity, recorded_at: future, via, start, end },
                Record::Admissibility { claim, via, ruling, .. } =>
                    Record::Admissibility { claim, recorded_at: future, via, ruling },
            });
        }
        let after = SnapshotCorpus::from_records(well_formed(accreted)).unwrap();

        prop_assert_eq!(
            projection(&f.feasibility(&before, &q)),
            projection(&f.feasibility(&after, &q))
        );
    }
}

// ===========================================================================
// 4. Revocation is three-valued — the exoneration case
// ===========================================================================

/// A three-entity chain with open windows and a valid claim: `1 — 2 — 3`.
fn chain_records() -> Vec<Record> {
    let mut r = Vec::new();
    for n in 1..=3 {
        r.push(Record::Window {
            entity: e(n),
            recorded_at: t(0),
            via: ev(n as u8),
            start: Start::Known(t(0)),
            end: WindowEnd::KnownOpen,
        });
    }
    r.push(Record::CoOccurrence {
        a: e(1),
        b: e(2),
        at: t(10),
        via: ev(20),
    });
    r.push(Record::CoOccurrence {
        a: e(2),
        b: e(3),
        at: t(10),
        via: ev(21),
    });
    r.push(Record::Admissibility {
        claim: ClaimType::from_u32(1),
        recorded_at: t(0),
        via: ev(30),
        ruling: Ruling::Valid,
    });
    r
}

fn chain_query(a: i64, b: i64, t_q: i64) -> FeasibilityQuery {
    FeasibilityQuery {
        subjects: (e(a), e(b)),
        t_q: t(t_q),
        claim: ClaimType::from_u32(1),
        k: HopBound::new(K_MAX),
    }
}

#[test]
fn discovered_cessation_moves_supported_to_contradicted_not_unsupported() {
    let f = Filter::new(params());
    let base = chain_records();
    let q = chain_query(1, 3, 100);

    let supported = SnapshotCorpus::from_records(base.clone()).unwrap();
    assert_eq!(kind_of(&f, &supported, &q), Some(VerdictKind::Supported));

    // A tightened window for entity 3: the record now says it ended at t=50.
    let mut revoked = base;
    revoked.push(Record::Window {
        entity: e(3),
        recorded_at: t(60),
        via: ev(40),
        start: Start::Known(t(0)),
        end: WindowEnd::KnownClosed(t(50)),
    });
    let revoked = SnapshotCorpus::from_records(revoked).unwrap();
    assert_eq!(kind_of(&f, &revoked, &q), Some(VerdictKind::Contradicted));
}

#[test]
fn absence_only_stays_unsupported_never_contradicted() {
    let f = Filter::new(params());
    // Entity 4 has no record at all: the corpus is silent, not contrary.
    let corpus = SnapshotCorpus::from_records(chain_records()).unwrap();
    let q = chain_query(1, 4, 100);
    assert_eq!(kind_of(&f, &corpus, &q), Some(VerdictKind::Unsupported));
}

#[test]
fn contrary_evidence_dominates_silence_in_the_window_factor() {
    // Unknown start AND a recorded close the query is past. The record proves the
    // entity existed and ended; an unknown start must not downgrade that to a
    // mere "the record is silent". This pins the arm order of `window_factor`.
    let f = Filter::new(params());
    let mut records = chain_records();
    records.push(Record::Window {
        entity: e(4),
        recorded_at: t(0),
        via: ev(41),
        start: Start::Unknown,
        end: WindowEnd::KnownClosed(t(50)),
    });
    let corpus = SnapshotCorpus::from_records(records).unwrap();
    assert_eq!(
        kind_of(&f, &corpus, &chain_query(1, 4, 100)),
        Some(VerdictKind::Contradicted)
    );
}

#[test]
fn known_open_and_unknown_closure_are_arithmetically_identical() {
    // Both bound the end at the sentinel, so `t_q <= end` holds with no special
    // case; the distinction survives in the record, not in the comparison.
    let f = Filter::new(params());
    let build = |end: WindowEnd| {
        let mut r = chain_records();
        r.push(Record::Window {
            entity: e(3),
            recorded_at: t(1),
            via: ev(42),
            start: Start::Known(t(0)),
            end,
        });
        SnapshotCorpus::from_records(r).unwrap()
    };
    let q = chain_query(1, 3, 100);
    assert_eq!(
        kind_of(&f, &build(WindowEnd::KnownOpen), &q),
        kind_of(&f, &build(WindowEnd::UnknownClosure), &q)
    );
}

// ===========================================================================
// 5. Reflexive doubling — correctness and the raw-power regression
// ===========================================================================

/// Dense Boolean adjacency of `B(as_of)` over `order`, plus the reflexive term.
fn reflexive_adjacency(c: &SnapshotCorpus, order: &[EntityId], as_of: Tick) -> Vec<Vec<bool>> {
    let n = order.len();
    let mut m = vec![vec![false; n]; n];
    for (i, &row) in order.iter().enumerate() {
        m[i][i] = true; // the `I` of T_0 = I ∨ B
        for edge in c.neighbors(row, as_of).unwrap() {
            if let Some(j) = order.iter().position(|&x| x == edge.other) {
                m[i][j] = true;
            }
        }
    }
    m
}

/// Boolean OR-AND product.
fn bool_mul(a: &[Vec<bool>], b: &[Vec<bool>]) -> Vec<Vec<bool>> {
    let n = a.len();
    a.iter()
        .map(|row| {
            let mut out = vec![false; n];
            for (k, _) in row.iter().enumerate().filter(|(_, &set)| set) {
                for (j, o) in out.iter_mut().enumerate() {
                    *o |= b[k][j];
                }
            }
            out
        })
        .collect()
}

fn bool_or(a: &[Vec<bool>], b: &[Vec<bool>]) -> Vec<Vec<bool>> {
    a.iter()
        .zip(b)
        .map(|(ra, rb)| ra.iter().zip(rb).map(|(x, y)| *x | *y).collect())
        .collect()
}

/// `(I ∨ B)^k` — reachable in **at most** `k` edges. The linear reference the
/// doubling recurrence must agree with.
fn reachable_within(t0: &[Vec<bool>], k: u8) -> Vec<Vec<bool>> {
    let n = t0.len();
    let mut acc: Vec<Vec<bool>> = (0..n).map(|i| (0..n).map(|j| i == j).collect()).collect();
    for _ in 0..k {
        acc = bool_mul(&acc, t0);
    }
    acc
}

/// `T_{j+1} = T_j ∨ (T_j ∘ T_j)`, `j` times.
fn doubling(t0: &[Vec<bool>], j: u32) -> Vec<Vec<bool>> {
    let mut t = t0.to_vec();
    for _ in 0..j {
        let sq = bool_mul(&t, &t);
        t = bool_or(&t, &sq);
    }
    t
}

fn entity_order(c: &SnapshotCorpus) -> Vec<EntityId> {
    let mut set: BTreeSet<EntityId> = BTreeSet::new();
    for r in c.records() {
        match r {
            Record::CoOccurrence { a, b, .. } => {
                set.insert(a);
                set.insert(b);
            }
            Record::Window { entity, .. } => {
                set.insert(entity);
            }
            Record::Admissibility { .. } => {}
        }
    }
    for n in 1..=N_ENTITIES {
        set.insert(e(n));
    }
    set.into_iter().collect()
}

proptest! {
    /// The sparse bidirectional realization computes the same predicate as the
    /// dense `(I ∨ B)^k` reference on every generated graph.
    #[test]
    fn known_k_matches_dense_reference(records in any_records(), q in any_query()) {
        let c = SnapshotCorpus::from_records(records).unwrap();
        let order = entity_order(&c);
        let t0 = reflexive_adjacency(&c, &order, q.t_q);
        let reference = reachable_within(&t0, q.k.get());

        let i = order.iter().position(|&x| x == q.subjects.0).unwrap();
        let j = order.iter().position(|&x| x == q.subjects.1).unwrap();

        let got = matches!(
            known_k(&c, q.subjects.0, q.subjects.1, q.k, q.t_q).unwrap(),
            Reachability::Within(_)
        );
        prop_assert_eq!(got, reference[i][j]);
    }
}

proptest! {
    /// Reflexive doubling reaches exactly `<= 2^j`, in `j` multiplications.
    #[test]
    fn doubling_recurrence_equals_bounded_reachability(records in any_records(), as_of in any_tick()) {
        let c = SnapshotCorpus::from_records(records).unwrap();
        let order = entity_order(&c);
        let t0 = reflexive_adjacency(&c, &order, as_of);
        for j in 0..3u32 {
            prop_assert_eq!(doubling(&t0, j), reachable_within(&t0, 1u8 << j));
        }
    }
}

#[test]
fn raw_boolean_powers_are_a_bug_and_reflexive_doubling_is_not() {
    // `1 — 2 — 3 — 4`: exactly three hops, no shorter path, and no even-length
    // walk between 1 and 4. A raw `B^{∘4}` formulation reports UNREACHABLE;
    // reflexive doubling reaches `<= 4`. Pinned so the correction cannot regress.
    let mut records: Vec<Record> = (1..=4)
        .map(|n| Record::Window {
            entity: e(n),
            recorded_at: t(0),
            via: ev(n as u8),
            start: Start::Known(t(0)),
            end: WindowEnd::KnownOpen,
        })
        .collect();
    records.push(Record::CoOccurrence {
        a: e(1),
        b: e(2),
        at: t(1),
        via: ev(20),
    });
    records.push(Record::CoOccurrence {
        a: e(2),
        b: e(3),
        at: t(1),
        via: ev(21),
    });
    records.push(Record::CoOccurrence {
        a: e(3),
        b: e(4),
        at: t(1),
        via: ev(22),
    });
    let c = SnapshotCorpus::from_records(records).unwrap();
    let order = entity_order(&c);
    let as_of = t(100);

    // Reflexive doubling / the kernel: reachable within 4.
    assert!(matches!(
        known_k(&c, e(1), e(4), HopBound::new(4), as_of).unwrap(),
        Reachability::Within(_)
    ));

    // Raw powers, no reflexive term: B^{∘4} tests walks of length exactly 4.
    let mut b = reflexive_adjacency(&c, &order, as_of);
    for (i, row) in b.iter_mut().enumerate() {
        row[i] = false; // strip `I`
    }
    let b4 = bool_mul(&bool_mul(&b, &b), &bool_mul(&b, &b));
    let i = order.iter().position(|&x| x == e(1)).unwrap();
    let j = order.iter().position(|&x| x == e(4)).unwrap();
    assert!(
        !b4[i][j],
        "raw B^4 must miss the 3-hop pair — that is the bug"
    );
}

#[test]
fn supp_phi_witness_is_the_lexicographically_least_shortest_walk() {
    // Two parallel edges 1—2 (`ev(19)` and `ev(20)`): the witness must name the
    // least `(other, via)`, because that tie-break is what makes a sparse search
    // and a dense operator reconstruct the *same* supp(Φ), not merely the same
    // boolean.
    let mut records = chain_records();
    records.push(Record::CoOccurrence {
        a: e(1),
        b: e(2),
        at: t(10),
        via: ev(19),
    });
    let c = SnapshotCorpus::from_records(records).unwrap();
    let Reachability::Within(support) = known_k(&c, e(1), e(2), HopBound::new(2), t(100)).unwrap()
    else {
        panic!("1—2 is directly evidenced");
    };
    assert_eq!(support.hops().get(), 1);
    assert_eq!(support.witness().steps().len(), 1);
    assert_eq!(support.witness().steps()[0].via, ev(19));
}

#[test]
fn reflexive_pair_is_supported_at_zero_hops() {
    let f = Filter::new(params());
    let c = SnapshotCorpus::from_records(chain_records()).unwrap();
    let j = f.feasibility(&c, &chain_query(1, 1, 100)).unwrap();
    let Verdict::Supported { support } = j.verdict else {
        panic!("an entity reaches itself: that is the `I` term of T_0");
    };
    assert_eq!(support.hops().get(), 0);
    assert!(support.witness().steps().is_empty());
}

// ===========================================================================
// 6. feasibility() and certify() agree on the verdict kind
// ===========================================================================

proptest! {
    /// The short-circuit is a cost optimization and must never be a semantic one.
    /// The two paths may differ only in witness completeness.
    #[test]
    fn screen_and_certify_agree_on_verdict_kind(records in any_records(), q in any_query()) {
        let f = Filter::new(params());
        let c = SnapshotCorpus::from_records(records).unwrap();
        let screened = f.feasibility(&c, &q).map(|j| j.verdict.kind());
        let certified = f.certify(&c, &q).map(|cert| cert.judgment.verdict.kind());
        prop_assert_eq!(screened.ok(), certified.ok());
    }
}

proptest! {
    /// And they agree on `supp(Φ)` too when supported — the consensus-bearing
    /// half must be identical, not merely the discriminant.
    #[test]
    fn screen_and_certify_agree_on_support(records in any_records(), q in any_query()) {
        let f = Filter::new(params());
        let c = SnapshotCorpus::from_records(records).unwrap();
        let a = f.feasibility(&c, &q).ok().and_then(|j| j.verdict.support().cloned());
        let b = f.certify(&c, &q).ok().and_then(|cert| cert.judgment.verdict.support().cloned());
        prop_assert_eq!(a, b);
    }
}

proptest! {
    /// The certificate's consulted list is canonical: ascending and duplicate-free.
    #[test]
    fn certificate_consulted_list_is_canonical(records in any_records(), q in any_query()) {
        let f = Filter::new(params());
        let c = SnapshotCorpus::from_records(records).unwrap();
        let cert = f.certify(&c, &q).unwrap();
        let sorted: Vec<EventId> = {
            let s: BTreeSet<EventId> = cert.consulted.iter().copied().collect();
            s.into_iter().collect()
        };
        prop_assert_eq!(cert.consulted, sorted);
    }
}

// ===========================================================================
// 7. An error is not a reject
// ===========================================================================

/// Which factor's read should fail.
#[derive(Clone, Copy)]
enum FailAt {
    Neighbors,
    Window,
    Admissibility,
}

/// A view that fails at one factor and delegates the rest.
///
/// This fakes no service: it exercises the `CorpusView` error channel, which is
/// part of the trait's contract and has no other way to be reached.
struct FailingView<'a> {
    inner: &'a SnapshotCorpus,
    at: FailAt,
}

impl CorpusView for FailingView<'_> {
    fn neighbors(&self, entity: EntityId, as_of: Tick) -> Result<Vec<Edge>, ViewError> {
        match self.at {
            FailAt::Neighbors => Err(ViewError::Backend("injected".into())),
            _ => self.inner.neighbors(entity, as_of),
        }
    }
    fn window(&self, entity: EntityId, as_of: Tick) -> Result<cc_filter::Windowed, ViewError> {
        match self.at {
            FailAt::Window => Err(ViewError::Backend("injected".into())),
            _ => self.inner.window(entity, as_of),
        }
    }
    fn admissibility(&self, c: ClaimType, as_of: Tick) -> Result<cc_filter::Admitted, ViewError> {
        match self.at {
            FailAt::Admissibility => Err(ViewError::Backend("injected".into())),
            _ => self.inner.admissibility(c, as_of),
        }
    }
    fn corpus_digest(&self) -> CorpusDigest {
        self.inner.corpus_digest()
    }
}

#[test]
fn a_view_error_is_never_a_verdict() {
    let f = Filter::new(params());
    let inner = SnapshotCorpus::from_records(chain_records()).unwrap();
    let q = chain_query(1, 3, 100);
    for at in [FailAt::Window, FailAt::Admissibility, FailAt::Neighbors] {
        let v = FailingView { inner: &inner, at };
        assert!(
            matches!(f.feasibility(&v, &q), Err(FilterError::View(_))),
            "a filter that could not read the record must not report Unsupported"
        );
        assert!(matches!(f.certify(&v, &q), Err(FilterError::View(_))));
    }
}

#[test]
fn a_malformed_query_is_not_a_verdict_either() {
    let f = Filter::new(params());
    let c = SnapshotCorpus::from_records(chain_records()).unwrap();

    let too_deep = FeasibilityQuery {
        k: HopBound::new(K_MAX + 1),
        ..chain_query(1, 3, 100)
    };
    assert!(matches!(
        f.feasibility(&c, &too_deep),
        Err(FilterError::Malformed(
            cc_filter::QueryError::HopBoundExceedsGoverned { .. }
        ))
    ));

    let sentinel = FeasibilityQuery {
        t_q: Tick::SENTINEL,
        ..chain_query(1, 3, 100)
    };
    assert!(matches!(
        f.feasibility(&c, &sentinel),
        Err(FilterError::Malformed(
            cc_filter::QueryError::QueryTimeIsSentinel
        ))
    ));
}

// ===========================================================================
// 8. Filter-version separation: rule identity is not input identity
// ===========================================================================

#[test]
fn same_params_same_version_different_params_different_version() {
    let base = Filter::new(params());
    assert_eq!(base.version(), Filter::new(params()).version());

    let mut k_bumped = params();
    k_bumped.k_max = HopBound::new(K_MAX + 1);
    assert_ne!(base.version(), Filter::new(k_bumped).version());

    let mut smoothing_bumped = params();
    smoothing_bumped.smoothing = SmoothingId::from_bytes([0x99; 32]);
    assert_ne!(base.version(), Filter::new(smoothing_bumped).version());

    let mut vocab_bumped = params();
    vocab_bumped.vocabulary = VocabularyVersion::from_bytes([0x99; 32]);
    assert_ne!(base.version(), Filter::new(vocab_bumped).version());

    let mut scale_bumped = params();
    scale_bumped.b256.clock_zero_scale = TimeScaleId::TT;
    assert_ne!(base.version(), Filter::new(scale_bumped).version());

    let mut split_bumped = params();
    split_bumped.b256.split = FractionalBits(32);
    assert_ne!(base.version(), Filter::new(split_bumped).version());

    let mut tag_bumped = params();
    tag_bumped.logic_tag = cc_filter::LogicTag::from_bytes([0x77; 32]);
    assert_ne!(base.version(), Filter::new(tag_bumped).version());
}

proptest! {
    /// Changing the corpus must NOT change the filter version. Rule identity and
    /// input identity are the two things a disagreeing node uses to tell a gossip
    /// gap from a governance event; folding one into the other destroys that.
    #[test]
    fn corpus_does_not_influence_the_rule_identity(records in any_records(), q in any_query()) {
        let f = Filter::new(params());
        let c = SnapshotCorpus::from_records(records).unwrap();
        if let Ok(j) = f.feasibility(&c, &q) {
            prop_assert_eq!(j.filter_version, f.version());
        }
    }
}

// ===========================================================================
// Φ magnitude may rank, never threshold
// ===========================================================================

#[test]
fn magnitude_ranks_shorter_walks_above_longer_ones() {
    let f = Filter::new(params());
    let c = SnapshotCorpus::from_records(chain_records()).unwrap();
    let one_hop = f.feasibility(&c, &chain_query(1, 2, 100)).unwrap();
    let two_hop = f.feasibility(&c, &chain_query(1, 3, 100)).unwrap();
    let m1 = f.magnitude(one_hop.verdict.support().unwrap());
    let m2 = f.magnitude(two_hop.verdict.support().unwrap());
    // Ordering between two magnitudes that exist is the sanctioned use; there is
    // deliberately no way to write `m1 > 0.7`.
    assert!(m1.rank_key() > m2.rank_key());
}

// ===========================================================================
// WL colouring kernel determinism
// ===========================================================================

proptest! {
    /// The kernel is a pure function of the record set, not of insertion order —
    /// which is the property a later convergence test will depend on.
    #[test]
    fn wl_colouring_is_order_independent(records in any_records(), as_of in any_tick()) {
        let forward = SnapshotCorpus::from_records(records.clone()).unwrap();
        let reversed: Vec<Record> = records.iter().rev().copied().collect();
        let backward = SnapshotCorpus::from_records(reversed).unwrap();

        let seeds = [e(1), e(2)];
        let rounds = cc_filter::WlRounds::new(2);
        let sa = cc_filter::ball(&forward, seeds, as_of, 2).unwrap();
        let sb = cc_filter::ball(&backward, seeds, as_of, 2).unwrap();
        prop_assert_eq!(&sa, &sb);
        prop_assert_eq!(
            cc_filter::refine(&forward, &sa, as_of, rounds).unwrap(),
            cc_filter::refine(&backward, &sb, as_of, rounds).unwrap()
        );
    }
}

/// A corpus that disagrees with itself is refused, and refused the same way
/// whichever order it arrives in.
///
/// This is the invariant that keeping the last-written record quietly broke: the
/// digest became a function of insertion order, so two nodes holding identical
/// evidence could publish different digests and conclude they had diverged.
#[test]
fn contradictory_records_are_refused_in_either_order() {
    let via = EventId::from_bytes([7u8; 32]);
    let at = t(10);
    let records = vec![
        Record::Admissibility {
            claim: ClaimType::from_u32(1),
            recorded_at: at,
            via,
            ruling: Ruling::Valid,
        },
        Record::Admissibility {
            claim: ClaimType::from_u32(1),
            recorded_at: at,
            via,
            ruling: Ruling::OutsideValidity { band_end: t(5) },
        },
    ];
    let forward = SnapshotCorpus::from_records(records.clone());
    let reversed: Vec<Record> = records.into_iter().rev().collect();
    let backward = SnapshotCorpus::from_records(reversed);
    assert!(forward.is_err(), "contradictory input must be refused");
    assert!(backward.is_err(), "and refused in the other order too");
    assert_eq!(
        format!("{}", forward.unwrap_err()),
        format!("{}", backward.unwrap_err()),
        "the refusal must not depend on arrival order"
    );
}

/// The same record twice is not a contradiction — it is the same fact, and a
/// union of two nodes' evidence will contain it.
#[test]
fn an_identical_duplicate_is_accepted() {
    let via = EventId::from_bytes([9u8; 32]);
    let r = Record::Admissibility {
        claim: ClaimType::from_u32(1),
        recorded_at: t(10),
        via,
        ruling: Ruling::Valid,
    };
    assert!(SnapshotCorpus::from_records(vec![r, r]).is_ok());
}
