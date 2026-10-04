//! `cc-publisher v1 entry`: every envelope of one reviewed packet, built
//! offline from a manifest: a new subject's Genesis (subject key, body,
//! asserted time, sources as evidence) and its edges to subjects in the
//! context. It never submits; `submit-packet` does, after owner approval.
//!
//! Ported from the salvage authoring flow, offline parts only: declared
//! sources carry the SHA-256 of a retained capture, and a capture present on
//! disk must hash to it; an edge may cite only declared sources (the
//! salvage "support references uncaptured source", here "undeclared
//! source"); an existing endpoint carries the revision
//! the reviewer read, refused as `source_subject_changed` /
//! `target_subject_changed` once it moves; and the result is a digest-bound
//! packet, ready for owner review, which is not approval. A reloaded entry
//! packet is checked against its manifest again ([`check_manifest`]).
use super::edge::{self, check_dispute, check_relation, endpoint_pin};
use super::entry_context::Context;
use super::entry_packet::{validate_text, Packet};
use super::genesis::{self, read_capped, GenesisInput, MAX_BODY};
use super::{hex32, key, time};
use anyhow::{anyhow, bail, ensure, Context as _, Result};
use cc_core::v1::{hash, revision_id, Hash, Payload, Pin, Pins, Signed};
use cc_core::SecretKey;
use clap::Args;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

pub const MANIFEST_SCHEMA: &str = "cc.publisher.v1.entry";
/// The endpoint name of the packet's own new subject.
pub const ENTRY: &str = "entry";

#[derive(Args, Debug)]
pub struct EntryArgs {
    #[arg(long)]
    pub key: PathBuf,
    /// Context file written by `cc-publisher v1 context`.
    #[arg(long)]
    pub context: PathBuf,
    /// Entry manifest (JSON); relative paths in it resolve against its directory.
    #[arg(long)]
    pub manifest: PathBuf,
    /// Output directory; must be absent or empty.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub instance: String,
    pub subject: SubjectIn,
    pub asserted_time: String,
    /// Genesis nonce, 64 hex; fixed in the manifest so a rebuild is identical.
    pub nonce: String,
    /// Body file, relative to the manifest.
    pub body: String,
    pub sources: Vec<Source>,
    #[serde(default)]
    pub edges: Vec<EdgeIn>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SubjectIn {
    pub kind: String,
    pub namespace: String,
    pub value: String,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    /// SHA-256 of the retained capture bytes, 64 hex.
    pub sha256: String,
    /// Where the capture came from and which part supports the claim.
    pub locator: String,
    /// Optional capture file, relative to the manifest; verified when given.
    pub capture: Option<String>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct EdgeIn {
    pub relation: String,
    /// `entry`, or an existing subject id.
    pub source: String,
    pub target: String,
    /// Required for an existing source: its current revision, as reviewed.
    pub source_revision: Option<String>,
    pub target_revision: Option<String>,
    pub rationale: String,
    /// Source ids from `sources`; their hashes become the edge's evidence.
    pub sources: Vec<String>,
}

/// A manifest path: relative, without `..`, resolved against the manifest.
fn resolve(base: &Path, field: &str, rel: &str) -> Result<PathBuf> {
    let p = Path::new(rel);
    ensure!(
        !rel.is_empty()
            && p.components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
        "{field} {rel:?} must be a relative path without '..'"
    );
    Ok(base.join(p))
}

/// Which captures were found on disk and verified.
pub struct Built {
    pub packet: Packet,
    pub verified_captures: Vec<String>,
    pub unverified_captures: Vec<String>,
}

fn parse(raw: &[u8]) -> Result<Manifest> {
    let m: Manifest = serde_json::from_slice(raw)?;
    ensure!(
        m.schema == MANIFEST_SCHEMA,
        "manifest schema must be {MANIFEST_SCHEMA:?}"
    );
    Ok(m)
}

fn sorted(mut v: Vec<Hash>) -> Vec<Hash> {
    v.sort();
    v
}

/// The manifest an entry packet carries must say exactly what its events
/// sign: the Genesis instance, subject key, asserted time, nonce and evidence
/// (every source hash), then one edge per manifest edge with its relation,
/// rationale, cited source hashes, endpoints and reviewed revisions. Returns
/// the sources, with locators, for `packet.json`.
pub fn check_manifest(raw: &[u8], events: &[Signed]) -> Result<Value> {
    let m = parse(raw).context("manifest.json")?;
    let mismatch = |what: &str| anyhow!("manifest.json {what} differs from the signed events");
    let shas = m
        .sources
        .iter()
        .map(|s| hex32(&s.sha256).with_context(|| format!("source {:?} sha256", s.id)))
        .collect::<Result<Vec<_>>>()?;
    let by_id: BTreeMap<&str, Hash> = m
        .sources
        .iter()
        .map(|s| s.id.as_str())
        .zip(shas.iter().copied())
        .collect();
    ensure!(
        by_id.len() == m.sources.len(),
        "manifest.json declares a source id twice"
    );
    ensure!(events.len() == 1 + m.edges.len(), mismatch("event count"));
    let g = &events[0];
    let e = g.envelope();
    let Payload::Genesis {
        nonce, evidence, ..
    } = &e.payload
    else {
        bail!(mismatch("first event kind"));
    };
    let key = e
        .subject_key
        .as_ref()
        .context("Genesis lacks a subject key")?;
    ensure!(hex32(&m.instance) == Some(e.instance), mismatch("instance"));
    ensure!(
        (
            key.kind.as_str(),
            key.namespace.as_str(),
            key.value.as_str()
        ) == (
            m.subject.kind.as_str(),
            m.subject.namespace.as_str(),
            m.subject.value.as_str()
        ),
        mismatch("subject key")
    );
    ensure!(
        e.asserted_time.as_ref() == Some(&time::parse(&m.asserted_time)?),
        mismatch("asserted time")
    );
    ensure!(hex32(&m.nonce) == Some(*nonce), mismatch("nonce"));
    ensure!(evidence.0 == sorted(shas.clone()), mismatch("source set"));
    let entry = g.id();
    for (n, (edge, signed)) in m.edges.iter().zip(&events[1..]).enumerate() {
        let what = |x: &str| mismatch(&format!("edges[{n}] {x}"));
        let Payload::EdgeAssert {
            relation,
            pins,
            decision,
        } = &signed.envelope().payload
        else {
            bail!(what("kind"));
        };
        ensure!(*relation == edge.relation, what("relation"));
        ensure!(decision.rationale == edge.rationale, what("rationale"));
        let cited = edge
            .sources
            .iter()
            .map(|id| {
                by_id
                    .get(id.as_str())
                    .copied()
                    .with_context(|| what("sources"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(decision.evidence.0 == sorted(cited), what("sources"));
        for (side, end, rev, pin) in [
            ("source", &edge.source, &edge.source_revision, &pins.source),
            ("target", &edge.target, &edge.target_revision, &pins.target),
        ] {
            let ok = if end == ENTRY {
                rev.is_none()
                    && pin.subject == entry
                    && pin.basis == entry
                    && pin.revision == revision_id(entry, entry)
            } else {
                hex32(end) == Some(pin.subject)
                    && rev.as_deref().and_then(hex32) == Some(pin.revision)
            };
            ensure!(ok, what(side));
        }
    }
    Ok(m.sources
        .iter()
        .map(|s| json!({"id": s.id, "sha256": s.sha256.to_lowercase(), "locator": s.locator, "capture": s.capture}))
        .collect::<Vec<_>>()
        .into())
}

pub fn build(signer: &SecretKey, ctx: &Context, manifest_path: &Path) -> Result<Built> {
    let raw = read_capped(manifest_path, cc_core::v1::MAX_ENVELOPE)?;
    let m = parse(&raw)
        .with_context(|| format!("{} is not an entry manifest", manifest_path.display()))?;
    let base = manifest_path.parent().unwrap_or(Path::new("."));
    let instance = hex32(&m.instance).context("manifest instance must be 64 hex characters")?;
    ensure!(
        instance == ctx.instance,
        "manifest instance differs from the context's"
    );
    let author = signer.author().to_bytes();

    ensure!(
        !m.sources.is_empty(),
        "an entry must declare at least one source"
    );
    let mut sources: BTreeMap<&str, Hash> = BTreeMap::new();
    let (mut verified, mut unverified) = (vec![], vec![]);
    for s in &m.sources {
        genesis::validate_key_field("source id", &s.id)?;
        validate_text("source locator", &s.locator)?;
        let sha = hex32(&s.sha256)
            .with_context(|| format!("source {:?} sha256 must be 64 hex characters", s.id))?;
        ensure!(
            sources.insert(&s.id, sha).is_none(),
            "source id {:?} is declared twice",
            s.id
        );
        match &s.capture {
            Some(c) => {
                let bytes = read_capped(&resolve(base, "capture", c)?, 256 * 1024 * 1024)?;
                ensure!(
                    hash(&bytes) == sha,
                    "capture hash mismatch: source {:?} capture does not hash to its sha256",
                    s.id
                );
                verified.push(s.id.clone());
            }
            None => unverified.push(s.id.clone()),
        }
    }
    let body = read_capped(&resolve(base, "body", &m.body)?, MAX_BODY)?;
    let g = genesis::build(
        signer,
        GenesisInput {
            instance,
            kind: m.subject.kind.clone(),
            namespace: m.subject.namespace.clone(),
            value: m.subject.value.clone(),
            body: body.clone(),
            asserted_time: time::parse(&m.asserted_time)?,
            evidence: sources.values().copied().collect(),
            nonce: hex32(&m.nonce).context("manifest nonce must be 64 hex characters")?,
        },
    )?;
    let new = Pin {
        subject: g.subject(),
        basis: g.id(),
        revision: revision_id(g.subject(), g.id()),
        body: hash(&body),
    };

    let mut events: Vec<Signed> = vec![g.signed.clone()];
    for (n, e) in m.edges.iter().enumerate() {
        let at = || format!("edges[{n}]");
        check_relation(&e.relation).with_context(at)?;
        ensure!(
            (e.source == ENTRY) != (e.target == ENTRY),
            "{}: exactly one endpoint must be {ENTRY:?}",
            at()
        );
        let end = |side: &str, s: &str, rev: &Option<String>| -> Result<(Pin, Hash)> {
            if s == ENTRY {
                ensure!(
                    rev.is_none(),
                    "{side}_revision must be absent for the entry endpoint"
                );
                return Ok((new.clone(), author));
            }
            let subject =
                hex32(s).with_context(|| format!("{side} must be {ENTRY:?} or 64 hex"))?;
            let reviewed = rev
                .as_deref()
                .with_context(|| format!("{side}_revision is required for an existing subject"))?;
            let reviewed =
                hex32(reviewed).with_context(|| format!("{side}_revision must be 64 hex"))?;
            let pin = endpoint_pin(ctx, side, subject, reviewed)?;
            Ok((pin, ctx.current(subject)?.creator))
        };
        let (source, source_creator) =
            end("source", &e.source, &e.source_revision).with_context(at)?;
        let (target, _) = end("target", &e.target, &e.target_revision).with_context(at)?;
        let pins = Pins { source, target };
        check_dispute(&e.relation, &pins, source_creator, author).with_context(at)?;
        ensure!(
            !e.sources.is_empty(),
            "{}: an edge must cite at least one source",
            at()
        );
        let mut evidence = vec![];
        for id in &e.sources {
            match sources.get(id.as_str()) {
                Some(h) if !evidence.contains(h) => evidence.push(*h),
                Some(_) => bail!("{}: source {id:?} is cited twice", at()),
                None => bail!("{}: support references undeclared source {id:?}", at()),
            }
        }
        let envelope = edge::assert_envelope(
            instance,
            author,
            &e.relation,
            pins,
            e.rationale.clone(),
            evidence,
        )
        .with_context(at)?;
        events.push(
            Signed::sign(signer, envelope).map_err(|x| anyhow!("{}: v1 encoding: {x}", at()))?,
        );
    }
    ctx.self_check(&events)?;
    Ok(Built {
        packet: Packet::new("entry", ctx, events, vec![body], Some(raw))?,
        verified_captures: verified,
        unverified_captures: unverified,
    })
}

pub fn run(a: EntryArgs) -> Result<()> {
    genesis::check_out_dir(&a.out)?;
    let ctx = Context::load(&a.context)?;
    let signer = key::load_key(&a.key)?;
    let built = build(&signer, &ctx, &a.manifest)?;
    let digest = built.packet.write_dir(&a.out)?;
    print!("{}", built.packet.summary(&a.out, digest));
    println!(
        "Captures verified on disk: {}; declared by hash only: {}.",
        list(&built.verified_captures),
        list(&built.unverified_captures)
    );
    Ok(())
}
fn list(v: &[String]) -> String {
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}
