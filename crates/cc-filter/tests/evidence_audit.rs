//! Existing golden corpus supplies independently authored missing/closed windows.
use cc_core::Tick;
use cc_filter::{
    golden::{golden_corpus, golden_params},
    ClaimType, EntityId, FeasibilityQuery, Filter, HopBound, VerdictKind,
};

#[test]
fn mixed_evidence_survives_both_subject_orders_without_changing_governance() {
    let filter = Filter::new(golden_params());
    let corpus = golden_corpus();
    for (a, b, expected) in [
        (6, 7, VerdictKind::Unsupported),
        (7, 6, VerdictKind::Contradicted),
    ] {
        let q = FeasibilityQuery {
            subjects: (EntityId::from_i64(a), EntityId::from_i64(b)),
            t_q: Tick::from_i64(100),
            claim: ClaimType::from_u32(1),
            k: HopBound::new(4),
        };
        let c = filter.certify(&corpus, &q).unwrap();
        assert_eq!(c.judgment.verdict.kind(), expected);
        assert_eq!(c.contradictions.len(), 1);
        assert!(!c.absences.is_empty());
        assert_eq!(
            c.judgment.consensus_projection(),
            filter
                .feasibility(&corpus, &q)
                .unwrap()
                .consensus_projection()
        );
    }
}

#[test]
fn missing_window_does_not_hide_expired_type_from_audit() {
    let filter = Filter::new(golden_params());
    let q = FeasibilityQuery {
        subjects: (EntityId::from_i64(8), EntityId::from_i64(1)),
        t_q: Tick::from_i64(100),
        claim: ClaimType::from_u32(3),
        k: HopBound::new(4),
    };
    let c = filter.certify(&golden_corpus(), &q).unwrap();
    assert_eq!(c.judgment.verdict.kind(), VerdictKind::Unsupported);
    assert_eq!(c.contradictions.len(), 1);
    assert!(!c.absences.is_empty());
}
