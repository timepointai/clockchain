//! A reviewed packet: the signed envelopes one content command builds, the
//! bodies they hash, and `packet.json`, a pure function of those bytes and
//! the context they were checked against. The packet digest, SHA-256 of
//! `packet.json`, is what the owner approves; `submit-packet` refuses any other.
use super::genesis::{self, check_out_dir, read_capped, write_new, MAX_BODY};
use super::{hex32, time};
use anyhow::{anyhow, bail, ensure, Context as _, Result};
use cc_core::v1::{
    hash, revision_id, root_grant, AssertedTime, Decision, Hash, Kind, Pin, Pins, Signed,
    TargetKind, Value as Old, MAX_ENVELOPE,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

pub const PACKET_FILE: &str = "packet.json";
pub const PACKET_SCHEMA: &str = "cc.publisher.v1.packet";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const EVENTS_DIR: &str = "events";
pub const BODIES_DIR: &str = "bodies";
/// Rationales and source locators: signed text a reviewer must read as is.
pub const MAX_TEXT: usize = 64 * 1024;

pub struct Packet {
    /// `correction`, `edge assert`, `edge reaffirm`, `attest` or `entry`.
    pub command: String,
    pub instance: Hash,
    pub author: Hash,
    /// Corpus digest and size of the context the events were checked against.
    pub context: Hash,
    pub context_events: usize,
    /// In submission order.
    pub events: Vec<Signed>,
    pub bodies: BTreeMap<Hash, Vec<u8>>,
    /// `entry` only: the exact manifest bytes.
    pub manifest: Option<Vec<u8>>,
}

pub fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Genesis => "genesis",
        Kind::Correction => "correction",
        Kind::Delegate => "delegate",
        Kind::Revoke => "revoke",
        Kind::Resolve => "resolve",
        Kind::EdgeAssert => "edge_assert",
        Kind::EdgeReaffirm => "edge_reaffirm",
        Kind::Attestation => "attestation",
    }
}

/// Signed free text (rationale, locator): nonempty, at most `MAX_TEXT` bytes,
/// no leading or trailing whitespace, no control character but a newline,
/// and none of the invisible or bidirectional characters `genesis` refuses.
pub fn validate_text(field: &str, s: &str) -> Result<()> {
    ensure!(!s.is_empty(), "{field} must not be empty");
    ensure!(s.len() <= MAX_TEXT, "{field} exceeds {MAX_TEXT} bytes");
    ensure!(
        !s.chars().any(|c| c.is_control() && c != '\n'),
        "{field} must not contain control characters other than newline"
    );
    if let Some(c) = s.chars().find(|c| genesis::is_invisible(*c)) {
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

/// Parse `--evidence` hex values into a nonempty canonical set: every v1
/// decision must cite evidence.
pub fn evidence(values: &[String]) -> Result<Vec<Hash>> {
    let out = values
        .iter()
        .map(|e| hex32(e).with_context(|| format!("--evidence {e:?} must be 64 hex characters")))
        .collect::<Result<Vec<_>>>()?;
    ensure!(!out.is_empty(), "at least one --evidence hash is required");
    genesis::evidence_set(out.clone())?;
    Ok(out)
}

fn h(x: &Hash) -> String {
    hex::encode(x)
}
fn hs(xs: &[Hash]) -> Value {
    xs.iter().map(h).collect::<Vec<_>>().into()
}
pub fn pin_json(p: &Pin) -> Value {
    json!({"subject": h(&p.subject), "basis": h(&p.basis), "revision": h(&p.revision), "body": h(&p.body)})
}
pub fn pins_json(p: &Pins) -> Value {
    json!({"source": pin_json(&p.source), "target": pin_json(&p.target)})
}
fn time_json(t: &Option<AssertedTime>) -> Value {
    match t {
        None => Value::Null,
        Some(t) => json!({
            "calendar": time::render(t),
            "precision": t.precision,
            "coordinate": h(&t.coordinate),
        }),
    }
}
fn old_json(v: &Old) -> Result<Value> {
    Ok(match v {
        Old::None => Value::Null,
        Old::Body(b) => json!({"body": h(b)}),
        Old::Pins(p) => json!({"pins": pins_json(p)}),
        Old::ParentPins(s) => json!({"parent_pins": s.0.iter()
            .map(|p| json!({"parent": h(&p.parent), "pins": pins_json(&p.pins)}))
            .collect::<Vec<_>>()}),
        _ => bail!("decision value outside the content commands"),
    })
}
fn decision_json(d: &Decision) -> Result<Value> {
    Ok(json!({
        "rationale": d.rationale,
        "evidence": hs(&d.evidence.0),
        "parents": hs(&d.parents.0),
        "old": old_json(&d.old)?,
        "new": old_json(&d.new)?,
    }))
}

/// Every signed field of one content event, with its derived identifiers.
pub fn describe(index: usize, s: &Signed) -> Result<Value> {
    use cc_core::v1::Payload::*;
    let e = s.envelope();
    let id = s.id();
    let mut v = json!({
        "index": index,
        "file": format!("{EVENTS_DIR}/{index:02}.bin"),
        "kind": kind_name(e.payload.kind()),
        "event": h(&id),
        "envelope_sha256": h(&hash(s.bytes())),
        "envelope_bytes": s.bytes().len(),
        "subject": e.subject.as_ref().map(h),
        "subject_key": e.subject_key.as_ref().map(|k| json!({"kind": k.kind, "namespace": k.namespace, "value": k.value})),
        "grant": e.grant.as_ref().map(h),
        "parents": hs(&e.parents.0),
        "asserted_time": time_json(&e.asserted_time),
    });
    let extra = match &e.payload {
        Genesis {
            nonce,
            body,
            evidence,
        } => json!({
            "subject": h(&id),
            "revision": h(&revision_id(id, id)),
            "root_grant": h(&root_grant(id)),
            "nonce": h(nonce),
            "body_sha256": h(body),
            "evidence": hs(&evidence.0),
        }),
        Correction { body, decision } => json!({
            "revision": h(&revision_id(e.subject.unwrap_or(id), id)),
            "body_sha256": h(body),
            "decision": decision_json(decision)?,
        }),
        EdgeAssert {
            relation,
            pins,
            decision,
        } => json!({
            "edge": h(&id),
            "relation": relation,
            "pins": pins_json(pins),
            "decision": decision_json(decision)?,
        }),
        EdgeReaffirm {
            edge,
            new,
            decision,
            ..
        } => json!({
            "edge": h(edge),
            "pins": pins_json(new),
            "decision": decision_json(decision)?,
        }),
        Attestation {
            target_kind,
            target,
            artifact_kind,
            artifact,
        } => json!({
            "target_kind": match target_kind { TargetKind::Event => "event", TargetKind::Revision => "revision" },
            "target": h(target),
            "artifact_kind": artifact_kind,
            "artifact_sha256": h(artifact),
        }),
        _ => bail!(
            "{} events are not content events",
            kind_name(e.payload.kind())
        ),
    };
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    Ok(v)
}

/// Bodies a packet must carry: those its Genesis and Correction events sign.
fn signed_bodies(events: &[Signed]) -> Vec<Hash> {
    use cc_core::v1::Payload::*;
    events
        .iter()
        .filter_map(|s| match s.envelope().payload {
            Genesis { body, .. } | Correction { body, .. } => Some(body),
            _ => None,
        })
        .collect()
}

impl Packet {
    pub fn new(
        command: &str,
        ctx: &super::entry_context::Context,
        events: Vec<Signed>,
        bodies: Vec<Vec<u8>>,
        manifest: Option<Vec<u8>>,
    ) -> Result<Self> {
        let first = events
            .first()
            .context("a packet holds at least one event")?;
        let p = Self {
            command: command.into(),
            instance: first.envelope().instance,
            author: first.envelope().author,
            context: ctx.corpus_digest,
            context_events: ctx.events.len(),
            events,
            bodies: bodies.into_iter().map(|b| (hash(&b), b)).collect(),
            manifest,
        };
        p.check()?;
        Ok(p)
    }
    /// One instance, one author, no repeated event, and exactly the bodies
    /// the events sign, each a valid body.
    fn check(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for s in &self.events {
            let e = s.envelope();
            ensure!(e.instance == self.instance, "packet events span instances");
            ensure!(
                e.author == self.author,
                "packet events have several authors"
            );
            ensure!(seen.insert(s.id()), "packet repeats an event");
            describe(0, s)?;
        }
        let mut signed = signed_bodies(&self.events);
        signed.sort();
        signed.dedup();
        ensure!(
            signed == self.bodies.keys().copied().collect::<Vec<_>>(),
            "packet bodies differ from the bodies its events sign"
        );
        for b in self.bodies.values() {
            genesis::validate_body(b)?;
        }
        Ok(())
    }
    pub fn ids(&self) -> Vec<Hash> {
        self.events.iter().map(Signed::id).collect()
    }

    /// `packet.json`: a pure function of the fields above.
    pub fn render(&self) -> Result<Vec<u8>> {
        let v = json!({
            "schema": PACKET_SCHEMA,
            "command": self.command,
            "instance": h(&self.instance),
            "author": h(&self.author),
            "context": {"corpus_digest": h(&self.context), "events": self.context_events},
            "manifest_sha256": self.manifest.as_ref().map(|m| h(&hash(m))),
            "events": self.events.iter().enumerate().map(|(i, s)| describe(i, s)).collect::<Result<Vec<_>>>()?,
            "bodies": self.bodies.iter().map(|(k, b)| json!({
                "file": format!("{BODIES_DIR}/{}.bin", h(k)),
                "sha256": h(k),
                "bytes": b.len(),
            })).collect::<Vec<_>>(),
            "submitted": false,
            "publication_authorized": false,
        });
        Ok((serde_json::to_string_pretty(&v)? + "\n").into_bytes())
    }
    /// SHA-256 of `packet.json`; what the owner approves.
    pub fn digest(&self) -> Result<Hash> {
        Ok(hash(&self.render()?))
    }

    /// Write into an absent or empty directory; no file is ever replaced.
    pub fn write_dir(&self, dir: &Path) -> Result<Hash> {
        if !check_out_dir(dir)? {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("create {}", dir.display()))?;
        }
        for sub in [EVENTS_DIR, BODIES_DIR] {
            DirBuilder::new()
                .mode(0o700)
                .create(dir.join(sub))
                .with_context(|| format!("create {}", dir.join(sub).display()))?;
        }
        for (i, s) in self.events.iter().enumerate() {
            write_new(&dir.join(format!("{EVENTS_DIR}/{i:02}.bin")), s.bytes())?;
        }
        for (k, b) in &self.bodies {
            write_new(&dir.join(format!("{BODIES_DIR}/{}.bin", h(k))), b)?;
        }
        if let Some(m) = &self.manifest {
            write_new(&dir.join(MANIFEST_FILE), m)?;
        }
        let rendered = self.render()?;
        write_new(&dir.join(PACKET_FILE), &rendered)?;
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(hash(&rendered))
    }

    /// Reload a packet directory: every envelope decodes and verifies, the
    /// bodies hash to their names, and `packet.json` is byte-identical to the
    /// one recomputed from those files.
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let raw = read_capped(&dir.join(PACKET_FILE), MAX_ENVELOPE)?;
        let v: Value =
            serde_json::from_slice(&raw).with_context(|| format!("{PACKET_FILE} is not JSON"))?;
        ensure!(
            v["schema"] == PACKET_SCHEMA,
            "{PACKET_FILE} is not a {PACKET_SCHEMA}"
        );
        let field = |k: &str| {
            v["context"][k]
                .as_str()
                .and_then(hex32)
                .with_context(|| format!("{PACKET_FILE} context.{k}"))
        };
        let count = v["events"].as_array().map_or(0, Vec::len);
        let mut events = vec![];
        for i in 0..count {
            let bytes = read_capped(&dir.join(format!("{EVENTS_DIR}/{i:02}.bin")), MAX_ENVELOPE)?;
            events
                .push(Signed::decode(&bytes).map_err(|e| anyhow!("{EVENTS_DIR}/{i:02}.bin: {e}"))?);
        }
        let mut bodies = vec![];
        for b in v["bodies"].as_array().into_iter().flatten() {
            let name = b["sha256"]
                .as_str()
                .and_then(hex32)
                .context("bodies[].sha256")?;
            let bytes = read_capped(
                &dir.join(format!("{BODIES_DIR}/{}.bin", h(&name))),
                MAX_BODY,
            )?;
            ensure!(
                hash(&bytes) == name,
                "{BODIES_DIR}/{}.bin does not hash to its name",
                h(&name)
            );
            bodies.push(bytes);
        }
        let manifest = match v["manifest_sha256"].as_str() {
            None => None,
            Some(m) => {
                let bytes = read_capped(&dir.join(MANIFEST_FILE), MAX_ENVELOPE)?;
                ensure!(
                    h(&hash(&bytes)) == m,
                    "{MANIFEST_FILE} does not match {PACKET_FILE}"
                );
                Some(bytes)
            }
        };
        let first = events.first().context("packet holds no event")?;
        let p = Self {
            command: v["command"].as_str().context("packet command")?.into(),
            instance: first.envelope().instance,
            author: first.envelope().author,
            context: field("corpus_digest")?,
            context_events: v["context"]["events"].as_u64().context("context.events")? as usize,
            bodies: bodies.into_iter().map(|b| (hash(&b), b)).collect(),
            events,
            manifest,
        };
        p.check()?;
        p.only_listed_files(dir)?;
        ensure!(
            p.render()? == raw,
            "{PACKET_FILE} does not match the packet's envelopes and bodies"
        );
        Ok(p)
    }

    /// A packet directory holds exactly the files `write_dir` writes, so
    /// nothing unreviewed rides along.
    fn only_listed_files(&self, dir: &Path) -> Result<()> {
        let names = |d: &Path| -> Result<Vec<String>> {
            let mut v = fs::read_dir(d)
                .with_context(|| format!("read {}", d.display()))?
                .map(|e| Ok(e?.file_name().to_string_lossy().into_owned()))
                .collect::<Result<Vec<_>>>()?;
            v.sort();
            Ok(v)
        };
        let mut top = vec![PACKET_FILE.to_owned(), EVENTS_DIR.into(), BODIES_DIR.into()];
        if self.manifest.is_some() {
            top.push(MANIFEST_FILE.into());
        }
        top.sort();
        let found = names(dir)?;
        let mut events: Vec<_> = (0..self.events.len())
            .map(|i| format!("{i:02}.bin"))
            .collect();
        events.sort();
        let bodies: Vec<_> = self
            .bodies
            .keys()
            .map(|k| format!("{}.bin", h(k)))
            .collect();
        ensure!(
            found == top
                && names(&dir.join(EVENTS_DIR))? == events
                && names(&dir.join(BODIES_DIR))? == bodies,
            "{} holds files the packet does not list",
            dir.display()
        );
        Ok(())
    }

    /// The review summary every build command prints.
    pub fn summary(&self, dir: &Path, digest: Hash) -> String {
        let mut s = format!(
            "v1 {} packet written to {} (offline; nothing was submitted)\n\n",
            self.command,
            dir.display()
        );
        s += &format!("  {:<15}{}\n", "author", h(&self.author));
        s += &format!(
            "  {:<15}{} ({} events)\n",
            "context",
            h(&self.context),
            self.context_events
        );
        for (i, e) in self.events.iter().enumerate() {
            s += &format!(
                "  {:<15}{} {}\n",
                format!("event {i:02}"),
                kind_name(e.envelope().payload.kind()),
                h(&e.id())
            );
        }
        for (k, b) in &self.bodies {
            s += &format!("  {:<15}{} ({} bytes)\n", "body", h(k), b.len());
        }
        s += &format!("  {:<15}{}\n\n", "packet digest", h(&digest));
        s += &format!(
            "Review {}/{PACKET_FILE} and every body, then the owner approves with\n\
             `cc-publisher v1 submit-packet --node URL --dir {} --approve {}`.\n",
            dir.display(),
            dir.display(),
            h(&digest)
        );
        s
    }
}
