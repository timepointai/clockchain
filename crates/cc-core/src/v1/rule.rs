//! Stage (e) rule identity and commitments. Pure functions; no I/O or clock.
//! `fold_version = (1, SHA256(canonical_fold_manifest))`. Any semantic change
//! must bump the number and the manifest; an unknown pair is refused.
use super::receipt::FoldRef;
use super::*;
use std::collections::BTreeSet;

pub const FOLD_NUMBER: u16 = 1;
/// The governed manifest, including the owner-adopted Stage (d) defaults.
pub const FOLD_MANIFEST: &str = include_str!("fold-manifest-v1.txt");

pub fn fold_v1() -> FoldRef {
    FoldRef {
        version: FOLD_NUMBER,
        manifest: hash(FOLD_MANIFEST.as_bytes()),
    }
}
/// The only fold this build implements. Never serve it under another tag.
pub fn supported_fold(fold: &FoldRef) -> bool {
    *fold == fold_v1()
}

fn framed(domain: &str) -> Vec<u8> {
    let mut out = (domain.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(domain.as_bytes());
    out
}
/// Digest of the retained candidate event set, including pending and invalid
/// candidates; rejection receipts and node receipts are not events.
pub fn corpus_digest(ids: &BTreeSet<Hash>) -> Hash {
    let mut out = framed("cc.corpus.v1");
    out.extend_from_slice(&(ids.len() as u32).to_be_bytes());
    for id in ids {
        out.extend_from_slice(id);
    }
    hash(&out)
}
/// `SHA256(frame("cc.view.v1") || canon_version || fold_version ||
/// filter_version || corpus_digest || canonical_projection_rows)`.
pub fn view_commitment(fold: &FoldRef, filter_version: Hash, corpus: Hash, rows: &[u8]) -> Hash {
    let mut out = framed("cc.view.v1");
    out.extend_from_slice(&CANON_VERSION.to_be_bytes());
    out.extend_from_slice(&fold.version.to_be_bytes());
    out.extend_from_slice(&fold.manifest);
    out.extend_from_slice(&filter_version);
    out.extend_from_slice(&corpus);
    out.extend_from_slice(&(rows.len() as u64).to_be_bytes());
    out.extend_from_slice(rows);
    hash(&out)
}
/// Cache keys name the rule identity, corpus snapshot and exact query bytes.
pub fn cache_key(filter_version: Hash, corpus: Hash, query: &[u8]) -> Hash {
    let mut out = framed("cc.cache.v1");
    out.extend_from_slice(&filter_version);
    out.extend_from_slice(&corpus);
    out.extend_from_slice(&(query.len() as u64).to_be_bytes());
    out.extend_from_slice(query);
    hash(&out)
}
