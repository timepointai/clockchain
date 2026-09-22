//! The golden fixtures, pinned.
//!
//! Two things are nailed down here and they fail for different reasons, on
//! purpose. The **per-query table** fails when a factor's semantics change, and
//! names which query and which verdict — a diagnosable failure. The **digest**
//! fails when *any* consensus-bearing bit changes anywhere, including bits the
//! table does not spell out (witness contents, hop counts, the version itself) —
//! an alarm, not a diagnosis. The digest is also the value the `wasm32` build
//! recomputes, which is how "the same crate compiled to two targets returns
//! identical verdicts" becomes a checkable property of the artifacts rather than
//! a claim about the source.
//!
//! A change to either pin is a `logic_tag` question: if a diff moves these bytes,
//! it moved a `supp(Φ)` bit, and the tag must move with it.

use cc_filter::{
    golden::{golden_corpus, golden_digest, golden_params, golden_queries},
    CorpusView, Filter, VerdictKind,
};

/// The version hash of the golden parameter set.
///
/// Pinned because the filter version is what makes disagreement legible: if two
/// builds of the same source produced different bytes here, every downstream
/// "governance event vs gossip gap" classification would be noise.
const GOLDEN_FILTER_VERSION: &str =
    "8492ed08837f70d48253c482fffa10dc5d7940f3e0281506637a18c44966268c";

/// The fold of every golden judgment's consensus projection.
const GOLDEN_DIGEST: &str = "5ff8e208d7886d269de5fd484bfa50cf52cd37c55b2f047e61be9320cd9d4e97";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn filter_version_is_stable() {
    let f = Filter::new(golden_params());
    assert_eq!(hex(f.version().as_bytes()), GOLDEN_FILTER_VERSION);
}

#[test]
fn golden_digest_is_stable() {
    assert_eq!(hex(&golden_digest()), GOLDEN_DIGEST);
}

/// The expected verdict for each golden query, in order, with the measured hop
/// count where the verdict is `Supported`.
///
/// Spelled out rather than derived so that a regression names itself.
const EXPECTED: &[(VerdictKind, Option<u16>)] = &[
    // 0: reflexive — the `I` term of T_0.
    (VerdictKind::Supported, Some(0)),
    // 1: one hop, two candidate evidencing events.
    (VerdictKind::Supported, Some(1)),
    // 2: two hops.
    (VerdictKind::Supported, Some(2)),
    // 3: exactly three hops under k=4 — the raw-power regression.
    (VerdictKind::Supported, Some(3)),
    // 4: same pair under k=2 — out of bounds is silence, not contradiction.
    (VerdictKind::Unsupported, None),
    // 5: t_q precedes an evidenced start.
    (VerdictKind::Unsupported, None),
    // 6: no evidenced start at all.
    (VerdictKind::Unsupported, None),
    // 7: past a recorded cessation — contrary evidence.
    (VerdictKind::Contradicted, None),
    // 8: an entity with no record whatsoever.
    (VerdictKind::Unsupported, None),
    // 9: vocabulary silent about the claim type.
    (VerdictKind::Unsupported, None),
    // 10: vocabulary contradicts the claim type at t_q.
    (VerdictKind::Contradicted, None),
    // 11: before the co-occurrence exists — the time slice bites.
    (VerdictKind::Unsupported, None),
    // 12: after the direct 1—4 edge is recorded — one hop where it was three.
    (VerdictKind::Supported, Some(1)),
];

#[test]
fn golden_verdicts_match_the_pinned_table() {
    let f = Filter::new(golden_params());
    let c = golden_corpus();
    let queries = golden_queries();
    assert_eq!(
        queries.len(),
        EXPECTED.len(),
        "fixture table is out of step"
    );

    for (i, (q, &(kind, hops))) in queries.iter().zip(EXPECTED).enumerate() {
        let j = f
            .feasibility(&c, q)
            .unwrap_or_else(|e| panic!("golden query {i} must be answerable: {e}"));
        assert_eq!(
            j.verdict.kind(),
            kind,
            "golden query {i}: wrong verdict kind"
        );
        assert_eq!(
            j.verdict.support().map(|s| s.hops().get()),
            hops,
            "golden query {i}: wrong supp(Φ) hop count"
        );
    }
}

#[test]
fn golden_certify_agrees_with_the_screen_and_names_its_evidence() {
    let f = Filter::new(golden_params());
    let c = golden_corpus();
    for (i, q) in golden_queries().iter().enumerate() {
        let screened = f.feasibility(&c, q).unwrap();
        let cert = f.certify(&c, q).unwrap();
        assert_eq!(
            screened.verdict.kind(),
            cert.judgment.verdict.kind(),
            "golden query {i}: the short-circuit changed the verdict"
        );
        assert_eq!(screened.verdict.support(), cert.judgment.verdict.support());
        assert_eq!(screened.filter_version, cert.judgment.filter_version);
        assert_eq!(screened.corpus_digest, cert.judgment.corpus_digest);
    }
}

#[test]
fn every_judgment_carries_the_rule_and_the_inputs() {
    let f = Filter::new(golden_params());
    let c = golden_corpus();
    for q in golden_queries().iter() {
        let j = f.feasibility(&c, q).unwrap();
        assert_eq!(j.filter_version, f.version());
        assert_eq!(j.corpus_digest, c.corpus_digest());
    }
}
