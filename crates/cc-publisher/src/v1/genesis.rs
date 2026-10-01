//! Offline v1 Genesis: validation, signing, the reviewed output directory and
//! its reload. The envelope is `cc_core::v1::Signed`, the encoding the node
//! decodes, and is checked with `cc_ledger::v1::classify` before it is written.
use super::time;
use anyhow::{anyhow, bail, ensure, Context, Result};
use cc_core::v1::{
    hash, revision_id, root_grant, AssertedTime, Envelope, Hash, Payload, Set, Signed, SubjectKey,
    MAX_ENVELOPE, MAX_SET,
};
use cc_core::SecretKey;
use cc_ledger::v1::{classify, State};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

/// Largest body the node's `PUT /v1/bodies/{sha256}` accepts.
pub const MAX_BODY: usize = 1024 * 1024;
/// Subject-key fields are limited to this many bytes by the v1 encoding.
pub const MAX_KEY_FIELD: usize = 1024;
pub const ENVELOPE_FILE: &str = "envelope.bin";
pub const BODY_FILE: &str = "body.bin";
pub const PREVIEW_FILE: &str = "preview.json";
pub const PREVIEW_SCHEMA: &str = "cc.publisher.v1.preview";

/// Everything a Genesis signs, already parsed. Strings are checked by [`build`].
#[derive(Clone, Debug)]
pub struct GenesisInput {
    pub instance: Hash,
    pub kind: String,
    pub namespace: String,
    pub value: String,
    pub body: Vec<u8>,
    pub asserted_time: AssertedTime,
    pub evidence: Vec<Hash>,
    pub nonce: Hash,
}

/// A signed Genesis and the exact body bytes its payload hashes.
#[derive(Clone, Debug)]
pub struct Genesis {
    pub signed: Signed,
    pub body: Vec<u8>,
}

/// The kind must be a current node id of the pinned TT taxonomy
/// (`vendor/tt`, checked by hash in `cc-filter`); a retired id is refused
/// with its successor named.
pub fn validate_kind(kind: &str) -> Result<()> {
    use cc_filter::version::{is_valid_tt_id, resolve_tt_id, TT_VERSION_STRING};
    ensure!(
        is_valid_tt_id(kind),
        "kind {kind:?} is not a node id in the pinned TT taxonomy ({TT_VERSION_STRING})"
    );
    let current = resolve_tt_id(kind);
    ensure!(
        current == kind,
        "kind {kind:?} is retired in the pinned TT taxonomy; its successor is {current:?}"
    );
    Ok(())
}

/// Characters that render as nothing or reorder text: soft hyphen, zero-width
/// and joiner characters, bidirectional marks, embeddings, overrides and
/// isolates, invisible operators, fillers, variation selectors, the
/// byte-order mark, interlinear annotation and tag characters.
pub fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{AD}' | '\u{34F}' | '\u{61C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}'
        | '\u{FFA0}' | '\u{FFF9}'..='\u{FFFB}' | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}')
}

/// Namespace and value: nonempty UTF-8 of at most 1024 bytes, without
/// control, invisible or bidirectional characters or leading/trailing
/// whitespace, so the signed key is exactly what a reviewer sees.
pub fn validate_key_field(field: &str, s: &str) -> Result<()> {
    ensure!(!s.is_empty(), "{field} must not be empty");
    ensure!(
        s.len() <= MAX_KEY_FIELD,
        "{field} exceeds {MAX_KEY_FIELD} bytes"
    );
    ensure!(
        !s.chars().any(char::is_control),
        "{field} must not contain control characters"
    );
    if let Some(c) = s.chars().find(|c| is_invisible(*c)) {
        bail!(
            "{field} must not contain invisible or bidirectional characters (found U+{:04X})",
            u32::from(c)
        );
    }
    ensure!(
        s.trim() == s,
        "{field} must not start or end with whitespace"
    );
    Ok(())
}

/// The body must be nonempty UTF-8 of at most 1 MiB: the node serves prose as
/// a JSON string, and `submit` compares those bytes with this file.
pub fn validate_body(body: &[u8]) -> Result<()> {
    ensure!(!body.is_empty(), "body must not be empty");
    ensure!(body.len() <= MAX_BODY, "body exceeds {MAX_BODY} bytes");
    ensure!(std::str::from_utf8(body).is_ok(), "body must be UTF-8 text");
    Ok(())
}

/// Sort evidence hashes into the canonical set, refusing duplicates.
pub fn evidence_set(mut evidence: Vec<Hash>) -> Result<Set<Hash>> {
    evidence.sort();
    if let Some(w) = evidence.windows(2).find(|w| w[0] == w[1]) {
        bail!("duplicate evidence hash {}", hex::encode(w[0]));
    }
    ensure!(
        evidence.len() <= MAX_SET,
        "at most {MAX_SET} evidence hashes"
    );
    Ok(Set(evidence))
}

/// Validate, sign and self-check a Genesis.
pub fn build(key: &SecretKey, input: GenesisInput) -> Result<Genesis> {
    validate_kind(&input.kind)?;
    validate_key_field("namespace", &input.namespace)?;
    validate_key_field("value", &input.value)?;
    validate_body(&input.body)?;
    ensure!(
        !input.asserted_time.precision.is_empty(),
        "asserted time precision must not be empty"
    );
    let envelope = Envelope {
        instance: input.instance,
        author: key.author().to_bytes(),
        subject: None,
        subject_key: Some(SubjectKey {
            kind: input.kind,
            namespace: input.namespace,
            value: input.value,
        }),
        grant: None,
        parents: Set(vec![]),
        asserted_time: Some(input.asserted_time),
        payload: Payload::Genesis {
            nonce: input.nonce,
            body: hash(&input.body),
            evidence: evidence_set(input.evidence)?,
        },
    };
    let signed = Signed::sign(key, envelope).map_err(|e| anyhow!("v1 encoding: {e}"))?;
    let genesis = Genesis {
        signed,
        body: input.body,
    };
    admissible(&genesis.signed)?;
    Ok(genesis)
}

/// The node's own branch-local classification must call it valid.
fn admissible(signed: &Signed) -> Result<()> {
    let status = classify(&BTreeMap::from([(signed.id(), signed.clone())]))
        .remove(&signed.id())
        .context("classification lost the event")?;
    ensure!(
        status.state == State::Valid,
        "cc_ledger::v1 classifies this Genesis as {:?} ({})",
        status.state,
        status.reason
    );
    Ok(())
}

/// The Genesis fields, re-derived from a decoded envelope.
pub struct Fields<'a> {
    pub key: &'a SubjectKey,
    pub asserted_time: &'a AssertedTime,
    pub nonce: Hash,
    pub body: Hash,
    pub evidence: &'a [Hash],
}
impl Genesis {
    pub fn id(&self) -> Hash {
        self.signed.id()
    }
    pub fn subject(&self) -> Hash {
        self.signed.id()
    }
    pub fn revision(&self) -> Hash {
        revision_id(self.subject(), self.id())
    }
    pub fn author(&self) -> Hash {
        self.signed.envelope().author
    }
    pub fn instance(&self) -> Hash {
        self.signed.envelope().instance
    }
    pub fn fields(&self) -> Result<Fields<'_>> {
        let e = self.signed.envelope();
        let Payload::Genesis {
            nonce,
            body,
            evidence,
        } = &e.payload
        else {
            bail!("envelope is not a Genesis");
        };
        Ok(Fields {
            key: e
                .subject_key
                .as_ref()
                .context("Genesis lacks a subject key")?,
            asserted_time: e
                .asserted_time
                .as_ref()
                .context("Genesis lacks an asserted time")?,
            nonce: *nonce,
            body: *body,
            evidence: &evidence.0,
        })
    }

    /// `preview.json`: a pure function of the envelope and body bytes.
    pub fn preview(&self) -> Result<Value> {
        let f = self.fields()?;
        let bytes = self.signed.bytes();
        Ok(json!({
            "schema": PREVIEW_SCHEMA,
            "event_kind": "genesis",
            "encoding": "cc.event.v1",
            "canon_version": cc_core::CANON_VERSION,
            "constants_version": cc_core::CONSTANTS_VERSION,
            "instance": hex::encode(self.instance()),
            "event": hex::encode(self.id()),
            "subject": hex::encode(self.subject()),
            "revision": hex::encode(self.revision()),
            "root_grant": hex::encode(root_grant(self.id())),
            "author": hex::encode(self.author()),
            "nonce": hex::encode(f.nonce),
            "subject_key": {
                "kind": f.key.kind,
                "namespace": f.key.namespace,
                "value": f.key.value,
            },
            "asserted_time": {
                "calendar": time::render(f.asserted_time),
                "precision": f.asserted_time.precision,
                "coordinate": hex::encode(f.asserted_time.coordinate),
            },
            "body_sha256": hex::encode(f.body),
            "body_bytes": self.body.len(),
            "evidence": f.evidence.iter().map(hex::encode).collect::<Vec<_>>(),
            "envelope_sha256": hex::encode(hash(bytes)),
            "envelope_bytes": bytes.len(),
            "taxonomy": {
                "version": cc_filter::version::TT_VERSION_STRING,
                "sha256": cc_filter::version::TT_BUNDLE_SHA256,
            },
        }))
    }

    /// Human review summary printed by `genesis`.
    pub fn summary(&self) -> Result<String> {
        let f = self.fields()?;
        let at = f.asserted_time;
        let first = String::from_utf8_lossy(&self.body)
            .lines()
            .next()
            .unwrap_or_default()
            .chars()
            .take(100)
            .collect::<String>();
        let mut s = String::new();
        let mut line = |k: &str, v: String| s.push_str(&format!("  {k:<15}{v}\n"));
        line("instance", hex::encode(self.instance()));
        line("author", hex::encode(self.author()));
        line("kind", f.key.kind.clone());
        line("namespace", f.key.namespace.clone());
        line("value", f.key.value.clone());
        line(
            "asserted time",
            format!(
                "{} (precision {}, coordinate {})",
                time::render(at).unwrap_or_else(|| "<not calendar-aligned>".into()),
                at.precision,
                hex::encode(at.coordinate)
            ),
        );
        line(
            "body",
            format!("{} bytes, sha256 {}", self.body.len(), hex::encode(f.body)),
        );
        line("body line 1", format!("{first:?}"));
        line("evidence", format!("{} hash(es)", f.evidence.len()));
        for e in f.evidence {
            line("", hex::encode(e));
        }
        line("nonce", hex::encode(f.nonce));
        line("event", hex::encode(self.id()));
        line(
            "subject",
            format!("{} (the event id)", hex::encode(self.subject())),
        );
        line("revision", hex::encode(self.revision()));
        let bytes = self.signed.bytes();
        line(
            "envelope",
            format!("{} bytes, sha256 {}", bytes.len(), hex::encode(hash(bytes))),
        );
        Ok(s)
    }

    /// Write `envelope.bin`, `body.bin` and `preview.json` into `dir`, which
    /// must be absent or empty. No existing file is replaced.
    pub fn write_dir(&self, dir: &Path) -> Result<()> {
        if !check_out_dir(dir)? {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("create {}", dir.display()))?;
        }
        let preview = serde_json::to_string_pretty(&self.preview()?)? + "\n";
        write_new(&dir.join(BODY_FILE), &self.body)?;
        write_new(&dir.join(ENVELOPE_FILE), self.signed.bytes())?;
        write_new(&dir.join(PREVIEW_FILE), preview.as_bytes())?;
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Reload a `genesis` directory and re-run every check `build` ran: the
    /// envelope decodes and verifies, is a valid Genesis over `body.bin`, and
    /// `preview.json` equals the preview recomputed from those bytes.
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let signed = Signed::decode(&read_capped(&dir.join(ENVELOPE_FILE), MAX_ENVELOPE)?)
            .map_err(|e| anyhow!("{ENVELOPE_FILE}: {e}"))?;
        let genesis = Self {
            signed,
            body: read_capped(&dir.join(BODY_FILE), MAX_BODY)?,
        };
        let f = genesis.fields()?;
        validate_kind(&f.key.kind)?;
        validate_key_field("namespace", &f.key.namespace)?;
        validate_key_field("value", &f.key.value)?;
        validate_body(&genesis.body)?;
        ensure!(
            hash(&genesis.body) == f.body,
            "{BODY_FILE} does not hash to the body the envelope signs"
        );
        admissible(&genesis.signed)?;
        let preview: Value =
            serde_json::from_slice(&read_capped(&dir.join(PREVIEW_FILE), MAX_BODY)?)
                .with_context(|| format!("{PREVIEW_FILE} is not JSON"))?;
        ensure!(
            preview == genesis.preview()?,
            "{PREVIEW_FILE} does not match {ENVELOPE_FILE} and {BODY_FILE}"
        );
        Ok(genesis)
    }
}

/// An output directory must be absent or empty. Returns whether it exists.
pub fn check_out_dir(dir: &Path) -> Result<bool> {
    if fs::symlink_metadata(dir).is_err() {
        return Ok(false);
    }
    ensure!(
        dir.is_dir(),
        "{} exists and is not a directory",
        dir.display()
    );
    ensure!(
        fs::read_dir(dir)?.next().is_none(),
        "refusing to write into non-empty {}",
        dir.display()
    );
    Ok(true)
}

/// Create a new file; never replace one.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| {
            format!(
                "create {} (existing files are never replaced)",
                path.display()
            )
        })?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Read a regular file of at most `cap` bytes. Anything else (a FIFO or a
/// device included) is refused before it is opened, so a read cannot block.
pub(crate) fn read_capped(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let meta = fs::metadata(path).with_context(|| format!("open {}", path.display()))?;
    ensure!(meta.is_file(), "{} is not a regular file", path.display());
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    ensure!(
        f.metadata()?.is_file(),
        "{} is not a regular file",
        path.display()
    );
    let mut out = Vec::new();
    f.take(cap as u64 + 1).read_to_end(&mut out)?;
    ensure!(out.len() <= cap, "{} exceeds {cap} bytes", path.display());
    Ok(out)
}
