//! Stage (e) conformance: the canonical projection rows of a fixed synthetic
//! projection are pinned byte for byte, and the stdlib reference independently
//! recomputes the corpus digest and view commitment from those bytes. Any
//! serialization or framing change fails here instead of silently changing
//! roots under the same fold_version.
use cc_ledger::v1::{canonical_rows, project, Snapshot};
use cc_testkit::v1::{filter, view_fixture};

#[test]
fn canonical_rows_and_view_commitment_are_pinned() {
    let set = view_fixture().into_iter().map(|e| (e.id(), e)).collect();
    let rows = canonical_rows(&project(&set));
    assert!(
        rows == include_bytes!("vectors/v1-view-rows.json"),
        "canonical rows changed"
    );
    let vectors: std::collections::BTreeMap<_, _> = include_str!("vectors/v1-view.txt")
        .lines()
        .map(|l| l.split_once(' ').unwrap())
        .collect();
    let s = Snapshot::of(&filter(), &set);
    assert_eq!(vectors.len(), 4);
    assert_eq!(
        vectors["rows_sha256"],
        hex::encode(cc_core::v1::hash(&rows))
    );
    assert_eq!(
        vectors["filter_version"],
        hex::encode(s.rule.filter_version)
    );
    assert_eq!(vectors["corpus_digest"], hex::encode(s.corpus_digest));
    assert_eq!(vectors["view_commitment"], hex::encode(s.commitment));
}
