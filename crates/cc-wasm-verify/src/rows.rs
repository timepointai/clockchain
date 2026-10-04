//! The served v1 snapshot document and the canonical projection rows it
//! commits to.
//!
//! The node serves `GET /v1/snapshot` (and the gateway `GET /public/v1/snapshot`)
//! as a JSON object whose projection content keeps its canonical serde form,
//! but whose object keys are not in declaration order. The view commitment is
//! over `cc.view-rows.json.v1`: the same readings, serialized by serde_json in
//! declaration order, in one fixed top-level order. These types mirror the
//! projection readings field for field so that re-serializing what was served
//! reproduces those bytes.
//!
//! Every collection is a `Vec`, never a set or map, so the served order is kept
//! exactly: a reordered, deduplicated or padded collection re-encodes to
//! different bytes and fails the commitment instead of being silently repaired.
//! States, reasons and kinds are kept as strings for the same reason.
//!
//! Drift between these mirrors and `cc-ledger` is caught natively by the
//! pinned `cc-ledger` row vector and by the recorded fixture test, both of
//! which must reproduce the ledger's own bytes.
use cc_core::v1::{AssertedTime, Envelope, Hash, Pins};
use serde::{Deserialize, Serialize};

/// The fixed schema tag of the canonical rows.
pub const ROWS_SCHEMA: &str = "cc.view-rows.json.v1";

/// One candidate's reading: `cc_ledger::v1::EventReading`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub event: Hash,
    pub envelope: Envelope,
    pub state: String,
    pub reason: String,
    pub missing: Vec<Hash>,
    pub frontier: bool,
    pub revision: Option<Hash>,
    pub controlling_revokes: Vec<Hash>,
}
/// `cc_ledger::v1::Revision`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub id: Hash,
    pub subject: Hash,
    pub creating_event: Hash,
    pub body: Hash,
    pub asserted_time: Option<AssertedTime>,
}
/// `cc_ledger::v1::SubjectReading`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub subject: Hash,
    pub frontier: Vec<Hash>,
    pub state: String,
    pub frozen: bool,
}
/// `cc_ledger::v1::Grant`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub issued_by_event: Hash,
    pub issuer: Option<Hash>,
    pub holder: Hash,
    pub subject: Hash,
}
/// `cc_ledger::v1::Effect`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    pub reason: String,
    pub controlling_revokes: Vec<Hash>,
}
/// `cc_ledger::v1::EdgeReading`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub edge: Hash,
    pub author: Hash,
    pub relation: String,
    pub evidence: Vec<Hash>,
    pub heads: Vec<Hash>,
    pub pins: Vec<Pins>,
    pub history: Vec<Hash>,
    pub status: String,
    pub reasons: Vec<String>,
}
/// `cc_ledger::v1::MediaReading`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Media {
    pub attestation: Hash,
    pub author: Hash,
    pub target_kind: String,
    pub target: Hash,
    pub revision: Option<Hash>,
    pub body: Option<Hash>,
    pub artifact_kind: String,
    pub artifact: Hash,
}
/// The `authority` object of a served snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub grants: Vec<(Hash, Grant)>,
    pub active: Vec<Hash>,
    pub tombstones: Vec<Hash>,
    pub effective_revokes: Vec<Hash>,
    pub canceled: Vec<Hash>,
    pub effects: Vec<(Hash, Effect)>,
}
/// The rule identity a read names, as served: hashes are lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleJson {
    pub fold_version: u16,
    pub fold_manifest: String,
    pub filter_version: String,
}
/// A served snapshot document, exactly the fields the node emits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub rule: RuleJson,
    pub corpus_digest: String,
    pub commitment: String,
    pub rows: Vec<Row>,
    pub subjects: Vec<Subject>,
    pub revisions: Vec<Revision>,
    pub edges: Vec<Edge>,
    pub media: Vec<Media>,
    pub authority: Authority,
}

/// The canonical rows document, in the field order `cc_ledger::v1::canonical_rows`
/// writes. Deserializable as well, so the pinned ledger vector can be read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRows {
    pub schema: String,
    pub rows: Vec<Row>,
    pub revisions: Vec<Revision>,
    pub subjects: Vec<Subject>,
    pub grants: Vec<(Hash, Grant)>,
    pub active: Vec<Hash>,
    pub tombstones: Vec<Hash>,
    pub effective_revokes: Vec<Hash>,
    pub canceled: Vec<Hash>,
    pub effects: Vec<(Hash, Effect)>,
    pub edges: Vec<Edge>,
    pub media: Vec<Media>,
}
impl CanonicalRows {
    /// Rearrange a served snapshot into the committed document.
    pub fn of(s: &Snapshot) -> Self {
        let a = &s.authority;
        Self {
            schema: ROWS_SCHEMA.into(),
            rows: s.rows.clone(),
            revisions: s.revisions.clone(),
            subjects: s.subjects.clone(),
            grants: a.grants.clone(),
            active: a.active.clone(),
            tombstones: a.tombstones.clone(),
            effective_revokes: a.effective_revokes.clone(),
            canceled: a.canceled.clone(),
            effects: a.effects.clone(),
            edges: s.edges.clone(),
            media: s.media.clone(),
        }
    }
    /// The exact bytes the view commitment hashes.
    pub fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("plain data serializes")
    }
}
