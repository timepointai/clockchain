//! Verifies what a v1 node or the public gateway serves, in the browser or
//! natively, using the same `cc-core` and `cc-filter` code the node runs.
//!
//! No I/O, clock or randomness: every input is a document the caller already
//! fetched, passed in as text.
//!
//! # What is recomputed
//!
//! - **Event ids.** Each served row's envelope is re-encoded as canonical
//!   `cc.event.v1` bytes and hashed; the result must equal the row's `event`.
//!   Rows must be strictly ascending by that id.
//! - **Signatures.** Only when signed envelope bytes are supplied, as an export
//!   manifest. Each must decode as canonical and correctly signed; the decoded
//!   set must be exactly the rows' set, envelope for envelope. The `/public/v1`
//!   reads serve envelopes without signatures, so without an export this check
//!   is reported as not checked, never as passed.
//! - **Corpus digest.** Recomputed from the recomputed ids of all served rows.
//! - **`filter_version`.** Recomputed from the served identity (curator keys
//!   and `max_hops`), this build's `fold_version` 1 and the pinned TT taxonomy
//!   hash, and compared with `/health` and with the snapshot's rule.
//! - **View commitment.** The served projection is rearranged into the
//!   canonical `cc.view-rows.json.v1` bytes, and the commitment is recomputed
//!   from those bytes, the recomputed `filter_version` and the recomputed corpus
//!   digest. The projection readings are parsed strictly (no unknown or
//!   repeated fields; cc-core's envelope types ignore unknown keys when
//!   parsing), and the whole document must equal its canonical re-encoding as
//!   JSON values, which catches any unknown key at any depth. No field outside
//!   the commitment can ride along. The comparison is over
//!   values, not bytes: whitespace, key order and string escapes in the served
//!   text are not committed and are not checked.
//! - **Reads.** Subject, prose and support reads must name the verified rule,
//!   corpus digest and commitment. A subject read's state, frontier, `as_of`
//!   visibility and revision are recomputed from the verified rows; served
//!   prose must hash to its revision's committed body.
//!
//! # What is NOT recomputed
//!
//! The fold. This crate does not re-run `fold_version` 1 over the envelopes.
//! Admission states and reasons, frontiers, revision selection, authority,
//! subject readings, edge and media readings, and support verdicts with their
//! `as_of` exclusions are checked only for consistency with the view
//! commitment: they
//! are the rows the node committed to, not rows this verifier derived. A node
//! that folded wrongly but committed to its wrong rows passes every check here.
//! Re-running the fold in the browser needs a wasm-clean projection crate,
//! which is a future owner decision; see [`NOT_RECOMPUTED`].
//!
//! # Trust anchor
//!
//! The verifier does not authenticate the server or the origin of the corpus.
//! `/health`, the rule, the curator keys, the corpus digest and the commitment
//! all come from the same server. Without a signed export the envelopes'
//! signatures are unchecked, so a hostile server can serve a fully
//! self-consistent forged corpus under curator keys it names and still reach
//! `partial`. Even `verified` (with an export) means internal consistency under
//! the keys the server names. Authorship needs an export obtained out of band
//! and the served curator keys compared with the owner's independently
//! published keys. Nor can the verifier know whether a node withheld
//! candidates it never served.
//!
//! An empty corpus is reported as `not_checked` ("nothing to verify"), never
//! as a pass; so is an export with no envelopes.
use cc_core::v1::receipt::FoldRef;
use cc_core::v1::rule::{corpus_digest, fold_v1, view_commitment};
use cc_core::v1::{hash, Hash, Signed};
use cc_filter::v1::FilterIdentity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub mod rows;
pub mod tt;
mod wasm;

/// What this verifier does not recompute, for the report and the UI.
pub const NOT_RECOMPUTED: &[&str] = &[
    "The fold itself. Admission states and reasons, frontiers, revision selection, authority, subject readings, edge and media readings are checked only for consistency with the view commitment; they are not re-derived from the envelopes. Re-running fold_version 1 in the browser needs a wasm-clean projection crate, which is a future owner decision.",
    "Support verdicts. A support read is checked only for naming the verified rule, corpus digest and commitment; its path search and as_of exclusions are not recomputed. (A subject read's as_of visibility is recomputed, from the verified rows.)",
    "Authenticity. The verifier does not authenticate the gateway or the origin of the corpus: health, rule, curator keys, corpus digest and commitment all come from the same server. Without a signed export the row envelopes' signatures are unchecked, so a hostile server can serve a fully self-consistent forged corpus under curator keys it names and still reach partial. Even verified, with an export, means internal consistency under the keys the server names, and nothing more. Authorship needs an export obtained out of band and the served curator keys (and max_hops) compared with the owner's independently published keys.",
    "Completeness. The corpus digest proves which candidates the commitment covers, not that the node served every candidate it holds.",
];

/// One check's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    NotChecked,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}
/// `verified`: every check passed. `partial`: none failed, some were not
/// checked (for example signatures, with no export supplied). `failed`: any
/// check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Verified,
    Partial,
    Failed,
}
/// Values this verifier computed itself, lowercase hex.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Recomputed {
    pub fold_manifest: String,
    pub ontology: String,
    pub filter_version: Option<String>,
    pub corpus_digest: Option<String>,
    pub commitment: Option<String>,
    pub events: usize,
    pub signatures: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub outcome: Outcome,
    pub checks: Vec<Check>,
    pub recomputed: Recomputed,
    pub not_recomputed: &'static [&'static str],
}
impl Report {
    /// The named check, if it ran.
    pub fn check(&self, name: &str) -> Option<&Check> {
        self.checks.iter().find(|c| c.name == name)
    }
    pub fn status(&self, name: &str) -> Option<Status> {
        self.check(name).map(|c| c.status)
    }
}

/// A read to cross-check against the verified snapshot. `kind` is `subject`,
/// `prose` or `support`; `body` is the response text.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Read {
    pub kind: String,
    pub body: String,
}
/// Everything the caller fetched, as response text.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    /// `GET /public/v1/health`.
    pub health: String,
    /// `GET /public/v1/snapshot`.
    pub snapshot: String,
    /// Optional export manifest: the node's `GET /v1/export` JSON, whose
    /// `envelopes` are the signed wire bytes in hex.
    #[serde(default)]
    pub export: Option<String>,
    #[serde(default)]
    pub reads: Vec<Read>,
}

/// The `/health` identity fields the verifier uses. Other fields (build,
/// posture, semantic, an `instance` if present) are not identity.
#[derive(Deserialize)]
struct Health {
    ledger: String,
    fold_version: FoldJson,
    filter_version: String,
    curators: Vec<String>,
    max_hops: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FoldJson {
    version: u16,
    manifest: String,
}
/// The node's export manifest with hex envelopes; hashes are byte arrays.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    encoding: u16,
    rule: ExportRule,
    corpus_digest: Hash,
    commitment: Hash,
    envelopes: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportRule {
    fold_version: u16,
    fold_manifest: Hash,
    filter_version: Hash,
}

/// Exactly 64 lowercase hex characters, as the node writes them.
pub fn hex32(s: &str) -> Option<Hash> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

struct Checks(Vec<Check>);
impl Checks {
    fn push(&mut self, name: &str, status: Status, detail: impl Into<String>) {
        self.0.push(Check {
            name: name.into(),
            status,
            detail: detail.into(),
        });
    }
    fn pass(&mut self, name: &str, detail: impl Into<String>) {
        self.push(name, Status::Pass, detail)
    }
    fn fail(&mut self, name: &str, detail: impl Into<String>) {
        self.push(name, Status::Fail, detail)
    }
    /// Record `ok` as pass or fail; returns `ok`.
    fn expect(&mut self, name: &str, ok: bool, pass: String, fail: String) -> bool {
        if ok {
            self.pass(name, pass)
        } else {
            self.fail(name, fail)
        }
        ok
    }
}

/// The identity a `/health` document names, recomputed under this build.
fn identity(c: &mut Checks, text: &str) -> Option<(FoldRef, Hash)> {
    let h: Health = match serde_json::from_str(text) {
        Ok(h) => h,
        Err(e) => {
            c.fail("health", format!("health is not a v1 health document: {e}"));
            return None;
        }
    };
    if !c.expect(
        "health",
        h.ledger == "v1",
        "health names ledger v1".into(),
        format!("health names ledger {:?}, not v1", h.ledger),
    ) {
        return None;
    }
    let fold = fold_v1();
    let served = hex32(&h.fold_version.manifest).map(|manifest| FoldRef {
        version: h.fold_version.version,
        manifest,
    });
    if !c.expect(
        "fold_version",
        served.as_ref() == Some(&fold),
        format!(
            "fold_version (1, {}) is the fold this verifier was built with",
            hex::encode(fold.manifest)
        ),
        format!(
            "health fold_version ({}, {}) is not this verifier's (1, {})",
            h.fold_version.version,
            h.fold_version.manifest,
            hex::encode(fold.manifest)
        ),
    ) {
        return None;
    }
    let curators: Option<Vec<Hash>> = h.curators.iter().map(|k| hex32(k)).collect();
    let filter = match curators.map(|k| FilterIdentity::governed(k, h.max_hops)) {
        Some(Ok(f)) => f,
        Some(Err(e)) => {
            c.fail(
                "filter_version",
                format!("served identity is not one fold_version 1 governs: {e}"),
            );
            return None;
        }
        None => {
            c.fail("filter_version", "a curator key is not 64 lowercase hex");
            return None;
        }
    };
    let version = filter.version();
    c.expect(
        "filter_version",
        hex32(&h.filter_version) == Some(version),
        format!(
            "recomputed {} from {} curator keys, max_hops {} and TT taxonomy {}",
            hex::encode(version),
            filter.curators.len(),
            filter.max_hops,
            hex::encode(filter.ontology)
        ),
        format!(
            "health serves {} but its curators, max_hops and the pinned TT taxonomy give {}",
            h.filter_version,
            hex::encode(version)
        ),
    )
    .then_some((fold, version))
}

/// Verify a snapshot and everything served alongside it.
pub fn verify(input: &Input) -> Report {
    let mut c = Checks(vec![]);
    let mut r = Recomputed {
        fold_manifest: hex::encode(fold_v1().manifest),
        ontology: hex::encode(cc_filter::version::TT_TAXONOMY_SHA256),
        ..Default::default()
    };
    run(&mut c, &mut r, input);
    let outcome = if c.0.iter().any(|x| x.status == Status::Fail) {
        Outcome::Failed
    } else if c.0.iter().any(|x| x.status == Status::NotChecked) {
        Outcome::Partial
    } else {
        Outcome::Verified
    };
    Report {
        outcome,
        checks: c.0,
        recomputed: r,
        not_recomputed: NOT_RECOMPUTED,
    }
}

fn run(c: &mut Checks, r: &mut Recomputed, input: &Input) {
    let Some((fold, filter_version)) = identity(c, &input.health) else {
        return;
    };
    r.filter_version = Some(hex::encode(filter_version));

    // Both parses must succeed. The value form bounds nesting and number range;
    // the typed form is read straight from the text, so a repeated field of a
    // reading is refused rather than collapsed to one of its values. Neither
    // failure can panic: a panic would trap the wasm instance.
    let served: serde_json::Value = match serde_json::from_str(&input.snapshot) {
        Ok(v) => v,
        Err(e) => return c.fail("snapshot", format!("snapshot is not JSON: {e}")),
    };
    let s: rows::Snapshot = match serde_json::from_str(&input.snapshot) {
        Ok(s) => s,
        Err(e) => return c.fail("snapshot", format!("snapshot is not a v1 snapshot: {e}")),
    };
    c.pass(
        "snapshot",
        format!(
            "{} rows, {} subjects, {} revisions, {} edges, {} media",
            s.rows.len(),
            s.subjects.len(),
            s.revisions.len(),
            s.edges.len(),
            s.media.len()
        ),
    );
    c.expect(
        "snapshot_rule",
        s.rule.fold_version == fold.version
            && hex32(&s.rule.fold_manifest) == Some(fold.manifest)
            && hex32(&s.rule.filter_version) == Some(filter_version),
        "snapshot names the recomputed fold_version and filter_version".into(),
        format!(
            "snapshot names ({}, {}, {}), not the recomputed identity",
            s.rule.fold_version, s.rule.fold_manifest, s.rule.filter_version
        ),
    );
    let canonical = serde_json::to_value(&s).expect("plain data serializes");
    c.expect(
        "canonical_form",
        canonical == served,
        "the served snapshot equals its canonical re-encoding as JSON values".into(),
        "the served snapshot carries values outside its canonical encoding".into(),
    );

    // Event ids, from the envelope bytes rather than the served `event` field.
    let mut ids = BTreeSet::new();
    let mut bad = vec![];
    let mut previous: Option<Hash> = None;
    for row in &s.rows {
        match row.envelope.preimage() {
            Ok(pre) if hash(&pre) == row.event => {}
            Ok(_) => bad.push(format!("{} id mismatch", hex::encode(row.event))),
            Err(e) => bad.push(format!("{} not encodable: {e}", hex::encode(row.event))),
        }
        if previous.is_some_and(|p| p >= row.event) {
            bad.push(format!("{} out of order", hex::encode(row.event)));
        }
        previous = Some(row.event);
        ids.insert(row.event);
    }
    r.events = s.rows.len();
    let ids_ok = if s.rows.is_empty() {
        // An empty corpus is consistent with its digest and commitment, but
        // nothing in it was verified; it never reads as a pass.
        c.push(
            "event_ids",
            Status::NotChecked,
            "0 events: nothing to verify",
        );
        true
    } else {
        c.expect(
            "event_ids",
            bad.is_empty(),
            format!(
                "{} envelopes re-encode to their canonical event ids, strictly ascending",
                s.rows.len()
            ),
            format!("{} of {} rows: {}", bad.len(), s.rows.len(), bad.join("; ")),
        )
    };

    let corpus = corpus_digest(&ids);
    r.corpus_digest = ids_ok.then(|| hex::encode(corpus));
    let corpus_ok = c.expect(
        "corpus_digest",
        ids_ok && hex32(&s.corpus_digest) == Some(corpus),
        format!(
            "recomputed {} over {} events",
            hex::encode(corpus),
            ids.len()
        ),
        if ids_ok {
            format!(
                "served {} but the served rows give {}",
                s.corpus_digest,
                hex::encode(corpus)
            )
        } else {
            "event ids did not verify".into()
        },
    );

    let bytes = rows::CanonicalRows::of(&s).bytes();
    let commitment = view_commitment(&fold, filter_version, corpus, &bytes);
    r.commitment = corpus_ok.then(|| hex::encode(commitment));
    let commitment_ok = c.expect(
        "view_commitment",
        corpus_ok && hex32(&s.commitment) == Some(commitment),
        format!(
            "recomputed {} over {} bytes of canonical rows",
            hex::encode(commitment),
            bytes.len()
        ),
        if corpus_ok {
            format!(
                "served {} but the served rows give {}",
                s.commitment,
                hex::encode(commitment)
            )
        } else {
            "corpus digest did not verify".into()
        },
    );

    signatures(c, r, input.export.as_deref(), &s, (&fold, filter_version));
    for read in &input.reads {
        check_read(c, read, &s, commitment_ok);
    }
}

fn signatures(
    c: &mut Checks,
    r: &mut Recomputed,
    export: Option<&str>,
    s: &rows::Snapshot,
    (fold, filter_version): (&FoldRef, Hash),
) {
    let Some(text) = export else {
        return c.push(
            "signatures",
            Status::NotChecked,
            "the public reads serve envelopes without signatures; supply an export manifest to check them",
        );
    };
    let m: Export = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            return c.fail(
                "signatures",
                format!("export is not an export manifest: {e}"),
            )
        }
    };
    let named = m.encoding == cc_core::CANON_VERSION
        && m.rule.fold_version == fold.version
        && m.rule.fold_manifest == fold.manifest
        && m.rule.filter_version == filter_version
        && hex32(&s.corpus_digest) == Some(m.corpus_digest)
        && hex32(&s.commitment) == Some(m.commitment);
    if !named {
        return c.fail(
            "signatures",
            "export names a different encoding, rule, corpus digest or commitment than the snapshot",
        );
    }
    let mut decoded = std::collections::BTreeMap::new();
    for (i, h) in m.envelopes.iter().enumerate() {
        let Ok(bytes) = hex::decode(h) else {
            return c.fail("signatures", format!("envelope {i} is not hex"));
        };
        match Signed::decode(&bytes) {
            Ok(e) => {
                decoded.insert(e.id(), e);
            }
            Err(e) => return c.fail("signatures", format!("envelope {i}: {e}")),
        }
    }
    let same = decoded.len() == m.envelopes.len()
        && decoded.len() == s.rows.len()
        && s.rows
            .iter()
            .all(|row| decoded.get(&row.event).map(|e| e.envelope()) == Some(&row.envelope));
    r.signatures = if same { decoded.len() } else { 0 };
    if same && decoded.is_empty() {
        return c.push(
            "signatures",
            Status::NotChecked,
            "0 signed envelopes: nothing to verify",
        );
    }
    c.expect(
        "signatures",
        same,
        format!(
            "{} signed envelopes decode canonically, verify under their author keys and are exactly the served rows",
            decoded.len()
        ),
        "the signed envelopes are not exactly the served rows".into(),
    );
}

/// The rule, corpus digest and commitment every read names.
#[derive(Deserialize)]
struct Named {
    rule: rows::RuleJson,
    corpus_digest: String,
    commitment: String,
}
#[derive(Deserialize)]
struct SubjectRead {
    as_of: Option<String>,
    subject: String,
    state: String,
    frontier: Vec<String>,
    revision: Option<rows::Revision>,
    visibility: String,
}
#[derive(Deserialize)]
struct ProseRead {
    revision: rows::Revision,
    availability: String,
    prose: Option<String>,
}

fn check_read(c: &mut Checks, read: &Read, s: &rows::Snapshot, snapshot_ok: bool) {
    let name = format!("read:{}", read.kind);
    let fail = |c: &mut Checks, why: String| c.fail(&name, why);
    if !snapshot_ok {
        return fail(c, "the snapshot did not verify".into());
    }
    let named: Named = match serde_json::from_str(&read.body) {
        Ok(n) => n,
        Err(e) => return fail(c, format!("not a v1 read: {e}")),
    };
    if named.rule != s.rule
        || named.corpus_digest != s.corpus_digest
        || named.commitment != s.commitment
    {
        return fail(c, "names a different rule, corpus or commitment".into());
    }
    let detail = match read.kind.as_str() {
        "subject" => subject_read(&read.body, s),
        "prose" => prose_read(&read.body, s),
        "support" => Ok(
            "names the verified commitment; the verdict itself is derived from the fold and not recomputed"
                .into(),
        ),
        other => Err(format!("unknown read kind {other:?}")),
    };
    match detail {
        Ok(d) => c.pass(&name, d),
        Err(d) => fail(c, d),
    }
}

/// The subject read the verified snapshot implies, recomputed: the reading's
/// state and frontier, and the `as_of` visibility rule (the current revision
/// is visible only when its asserted coordinate is at or before `as_of`; an
/// unknown asserted time is not visible). This follows the node's
/// `Snapshot::visibility` over the verified rows, except that a resolved head
/// with no selected revision, which an honest node never serves, fails here
/// instead of reading as a visibility without a revision.
fn subject_read(body: &str, s: &rows::Snapshot) -> Result<String, String> {
    let read: SubjectRead = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let id = hex32(&read.subject).ok_or("subject is not hex")?;
    let as_of = match &read.as_of {
        None => None,
        Some(h) => Some(hex32(h).ok_or("as_of is not hex")?),
    };
    let Some(reading) = s.subjects.iter().find(|x| x.subject == id) else {
        return if read.visibility == "subject_unknown"
            && read.state.is_empty()
            && read.frontier.is_empty()
            && read.revision.is_none()
        {
            Ok(format!(
                "{} is unknown to the verified snapshot",
                read.subject
            ))
        } else {
            Err(format!("{} is not in the verified snapshot", read.subject))
        };
    };
    let frontier: Vec<_> = reading.frontier.iter().map(hex::encode).collect();
    if read.state != reading.state || read.frontier != frontier {
        return Err("state or frontier differs from the verified snapshot".into());
    }
    let (visibility, revision) = if reading.state != "resolved" {
        (reading.state.clone(), None)
    } else {
        let current = s
            .rows
            .iter()
            .find(|r| Some(&r.event) == reading.frontier.first())
            .and_then(|r| r.revision)
            .and_then(|id| s.revisions.iter().find(|r| r.id == id))
            .ok_or("the verified snapshot has no revision for its head")?;
        let visibility = match (as_of, &current.asserted_time) {
            (None, _) => "visible",
            (Some(_), None) => "asserted_time_unknown",
            (Some(q), Some(t)) if t.coordinate > q => "after_as_of",
            _ => "visible",
        };
        (
            visibility.to_string(),
            (visibility == "visible").then_some(current),
        )
    };
    if read.visibility != visibility || read.revision.as_ref() != revision {
        return Err(format!(
            "visibility {} and its revision differ from the verified snapshot's ({visibility})",
            read.visibility
        ));
    }
    Ok(format!(
        "state {}, frontier, visibility {visibility} and revision recomputed from the verified snapshot",
        read.state
    ))
}

fn prose_read(body: &str, s: &rows::Snapshot) -> Result<String, String> {
    let read: ProseRead = serde_json::from_str(body).map_err(|e| e.to_string())?;
    if !s.revisions.contains(&read.revision) {
        return Err("revision is not in the verified snapshot".into());
    }
    match (read.availability.as_str(), &read.prose) {
        ("available", Some(p)) if hash(p.as_bytes()) == read.revision.body => {
            Ok("prose hashes to its revision's committed body".into())
        }
        ("available", _) => Err("prose does not hash to its revision's body".into()),
        (a, None) => Ok(format!("no prose served ({a}); nothing to hash")),
        (a, Some(_)) => Err(format!("prose served with availability {a}")),
    }
}
