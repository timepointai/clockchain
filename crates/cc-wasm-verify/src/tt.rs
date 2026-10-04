//! The TT kind path of a subject key, read from the taxonomy tables `cc-filter`
//! bakes in at build time (`vendor/tt/taxonomy-v2.1.json`).
use cc_filter::version::{
    ancestors_of, is_valid_tt_id, lens_of, resolve_tt_id, TT_TAXONOMY_SHA256,
};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KindPath {
    pub kind: String,
    /// A node id of the pinned taxonomy.
    pub valid: bool,
    /// The successor when `kind` is retired; otherwise `kind`.
    pub current: String,
    pub lens: Option<&'static str>,
    /// Branch first, ending at `kind`. Empty when `kind` is not a node id.
    pub path: Vec<String>,
    /// sha256 of the taxonomy the path was read from.
    pub taxonomy: String,
}

pub fn kind_path(kind: &str) -> KindPath {
    let valid = is_valid_tt_id(kind);
    let mut path: Vec<String> = Vec::new();
    if valid {
        path = ancestors_of(kind)
            .into_iter()
            .rev()
            .map(String::from)
            .collect();
        path.push(kind.into());
    }
    KindPath {
        kind: kind.into(),
        valid,
        current: resolve_tt_id(kind).into(),
        lens: lens_of(kind),
        path,
        taxonomy: hex::encode(TT_TAXONOMY_SHA256),
    }
}

/// True when `bytes` are exactly the pinned taxonomy, so labels read from a
/// served copy of it describe the same ids the verifier uses.
pub fn is_pinned_taxonomy(bytes: &[u8]) -> bool {
    cc_core::v1::hash(bytes) == TT_TAXONOMY_SHA256
}
