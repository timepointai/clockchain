//! Recomputes every Stage (e) rule vector with the shipped cc-core/cc-filter
//! code. The same function runs natively (Cargo test) and in wasm32 (Node).
use cc_core::v1::rule::{cache_key, corpus_digest, fold_v1, view_commitment};
use cc_filter::v1::FilterIdentity;

const VECTORS: &str = include_str!("../../cc-core/tests/vectors/v1-rule.txt");

/// Bit i is set when vector line i matches; 0 means the file failed to parse.
pub fn matches() -> u32 {
    let mut curators = [1u8, 2].map(|s| cc_core::SecretKey::from_seed([s; 32]).author().to_bytes());
    curators.sort();
    let Ok(filter) = FilterIdentity::governed(curators.to_vec(), 4) else {
        return 0;
    };
    let corpus = corpus_digest(&[[1; 32], [2; 32], [3; 32]].into());
    let fold = fold_v1();
    let computed: [(&str, Vec<u8>); 8] = [
        ("fold_manifest", fold.manifest.to_vec()),
        ("ontology", filter.ontology.to_vec()),
        ("filter_canonical", filter.canonical()),
        ("filter_version", filter.version().to_vec()),
        ("corpus_digest", corpus.to_vec()),
        (
            "corpus_digest_empty",
            corpus_digest(&Default::default()).to_vec(),
        ),
        (
            "view_commitment",
            view_commitment(&fold, filter.version(), corpus, b"synthetic rows").to_vec(),
        ),
        (
            "cache_key",
            cache_key(filter.version(), corpus, b"synthetic query").to_vec(),
        ),
    ];
    let mut bits = 0;
    for (i, line) in VECTORS.lines().enumerate() {
        let Some((name, value)) = line.split_once(' ') else {
            return 0;
        };
        if computed
            .get(i)
            .is_some_and(|(n, v)| *n == name && hex::encode(v) == value)
        {
            bits |= 1 << i;
        }
    }
    bits
}
/// Wasm export: the full mask is `0xff` for all eight vectors.
#[no_mangle]
pub extern "C" fn cc_rule_vectors() -> u32 {
    matches()
}
