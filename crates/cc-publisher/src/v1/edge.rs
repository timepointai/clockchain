//! `cc-publisher v1 edge assert` and `edge reaffirm`: both-endpoint pinned
//! edges over the five governed relations, built offline against a saved
//! context. Each endpoint is pinned to its subject's single current head, and
//! the reviewer must name the revision of both endpoints; a moved endpoint is
//! refused. A `disputes` edge is signed only by the source subject's creator.
use super::entry_context::Context;
use super::entry_packet::{self, validate_text, Packet};
use super::{genesis, hex32, key};
use anyhow::{anyhow, bail, ensure, Context as _, Result};
use cc_core::v1::{
    Decision, Envelope, Hash, Kind, ParentPins, Payload, Pin, Pins, Set, Signed, Value,
};
use cc_core::SecretKey;
use cc_ledger::v1::RELATIONS;
use clap::{ArgAction, Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum EdgeCommand {
    /// Sign a new edge between two resolved subjects.
    Assert(AssertArgs),
    /// Re-pin an existing edge (original author only) to both endpoints' current revisions.
    Reaffirm(ReaffirmArgs),
}

#[derive(Args, Debug)]
pub struct Common {
    /// Seed file of the signing key.
    #[arg(long)]
    pub key: PathBuf,
    /// Context file written by `cc-publisher v1 context`.
    #[arg(long)]
    pub context: PathBuf,
    /// Current revision of the source subject, as reviewed.
    #[arg(long)]
    pub source_revision: String,
    /// Current revision of the target subject, as reviewed.
    #[arg(long)]
    pub target_revision: String,
    /// Why the relation holds; signed as is.
    #[arg(long)]
    pub rationale: String,
    /// Evidence SHA-256 hashes, 64 hex each; at least one; repeatable.
    #[arg(long, num_args = 1.., action = ArgAction::Append, required = true)]
    pub evidence: Vec<String>,
    /// Output directory; must be absent or empty.
    #[arg(long)]
    pub out: PathBuf,
}
#[derive(Args, Debug)]
pub struct AssertArgs {
    /// causation, co_occurrence, disputes, influence or participation.
    #[arg(long)]
    pub relation: String,
    /// Source subject id, 64 hex characters.
    #[arg(long)]
    pub source: String,
    /// Target subject id, 64 hex characters.
    #[arg(long)]
    pub target: String,
    #[command(flatten)]
    pub common: Common,
}
#[derive(Args, Debug)]
pub struct ReaffirmArgs {
    /// The edge id: its EdgeAssert event id, 64 hex characters.
    #[arg(long)]
    pub edge: String,
    #[command(flatten)]
    pub common: Common,
}

/// The relation must be one of the five governed v1 relations.
pub fn check_relation(relation: &str) -> Result<()> {
    ensure!(
        RELATIONS.contains(&relation),
        "relation {relation:?} is not a governed v1 relation (one of {})",
        RELATIONS.join(", ")
    );
    Ok(())
}

/// A pin of `subject`'s single current head. The reviewed revision must be
/// that head's revision: `source_subject_changed` / `target_subject_changed`.
pub fn endpoint_pin(ctx: &Context, side: &str, subject: Hash, reviewed: Hash) -> Result<Pin> {
    let cur = ctx
        .current(subject)
        .with_context(|| format!("{side} endpoint"))?;
    ensure!(
        cur.revision == reviewed,
        "{side}_subject_changed: {side} subject {} is at revision {}, not the reviewed {}; \
         refresh the context and review again",
        hex::encode(subject),
        hex::encode(cur.revision),
        hex::encode(reviewed)
    );
    Ok(cur.pin())
}

/// A counterclaim is the disputing author's own subject: only the creator of
/// the source subject may sign a `disputes` edge from it, never to itself.
pub fn check_dispute(
    relation: &str,
    pins: &Pins,
    source_creator: Hash,
    author: Hash,
) -> Result<()> {
    if relation == "disputes" {
        ensure!(
            pins.source.subject != pins.target.subject,
            "a disputes edge must join two different subjects"
        );
        ensure!(
            source_creator == author,
            "a disputes edge may be signed only by the creator of its source subject \
             (the counterclaim), {}, not by {}",
            hex::encode(source_creator),
            hex::encode(author)
        );
    }
    Ok(())
}

/// The EdgeAssert envelope for `pins`; the caller checks admissibility.
pub fn assert_envelope(
    instance: Hash,
    author: Hash,
    relation: &str,
    pins: Pins,
    rationale: String,
    evidence: Vec<Hash>,
) -> Result<Envelope> {
    check_relation(relation)?;
    validate_text("rationale", &rationale)?;
    ensure!(!evidence.is_empty(), "an edge must cite evidence");
    Ok(Envelope {
        instance,
        author,
        subject: None,
        subject_key: None,
        grant: None,
        parents: Set(vec![]),
        asserted_time: None,
        payload: Payload::EdgeAssert {
            relation: relation.into(),
            pins: pins.clone(),
            decision: Decision {
                kind: Kind::EdgeAssert,
                rationale,
                evidence: genesis::evidence_set(evidence)?,
                parents: Set(vec![]),
                old: Value::None,
                new: Value::Pins(pins),
            },
        },
    })
}

pub struct AssertInput {
    pub relation: String,
    pub source: Hash,
    pub target: Hash,
    pub source_revision: Hash,
    pub target_revision: Hash,
    pub rationale: String,
    pub evidence: Vec<Hash>,
}
pub fn build_assert(signer: &SecretKey, ctx: &Context, i: AssertInput) -> Result<Packet> {
    check_relation(&i.relation)?;
    ensure!(
        i.source != i.target,
        "source and target are the same subject; a same-subject edge never supports anything"
    );
    let pins = Pins {
        source: endpoint_pin(ctx, "source", i.source, i.source_revision)?,
        target: endpoint_pin(ctx, "target", i.target, i.target_revision)?,
    };
    let author = signer.author().to_bytes();
    check_dispute(&i.relation, &pins, ctx.current(i.source)?.creator, author)?;
    let envelope = assert_envelope(
        ctx.instance,
        author,
        &i.relation,
        pins,
        i.rationale,
        i.evidence,
    )?;
    let signed = Signed::sign(signer, envelope).map_err(|e| anyhow!("v1 encoding: {e}"))?;
    ctx.self_check(std::slice::from_ref(&signed))?;
    Packet::new("edge assert", ctx, vec![signed], vec![], None)
}

pub struct ReaffirmInput {
    pub edge: Hash,
    pub source_revision: Hash,
    pub target_revision: Hash,
    pub rationale: String,
    pub evidence: Vec<Hash>,
}
pub fn build_reaffirm(signer: &SecretKey, ctx: &Context, i: ReaffirmInput) -> Result<Packet> {
    let reading = ctx.edge(i.edge)?;
    let author = signer.author().to_bytes();
    ensure!(
        reading.author == author,
        "only the edge's original author, {}, may reaffirm it",
        hex::encode(reading.author)
    );
    validate_text("rationale", &i.rationale)?;
    ensure!(!i.evidence.is_empty(), "a reaffirmation must cite evidence");
    // Endpoints are fixed by the assertion; every head carries the same ones.
    let Payload::EdgeAssert { pins: base, .. } = &ctx.events[&i.edge].envelope().payload else {
        bail!("edge {} is not an EdgeAssert", hex::encode(i.edge));
    };
    let new = Pins {
        source: endpoint_pin(ctx, "source", base.source.subject, i.source_revision)?,
        target: endpoint_pin(ctx, "target", base.target.subject, i.target_revision)?,
    };
    let heads: Vec<Hash> = reading.heads.iter().copied().collect();
    let old = Set(heads
        .iter()
        .zip(&reading.pins)
        .map(|(&parent, pins)| ParentPins {
            parent,
            pins: pins.clone(),
        })
        .collect());
    let parents = Set(heads);
    let envelope = Envelope {
        instance: ctx.instance,
        author,
        subject: None,
        subject_key: None,
        grant: None,
        parents: parents.clone(),
        asserted_time: None,
        payload: Payload::EdgeReaffirm {
            edge: i.edge,
            old: old.clone(),
            new: new.clone(),
            decision: Decision {
                kind: Kind::EdgeReaffirm,
                rationale: i.rationale,
                evidence: genesis::evidence_set(i.evidence)?,
                parents,
                old: Value::ParentPins(old),
                new: Value::Pins(new),
            },
        },
    };
    let signed = Signed::sign(signer, envelope).map_err(|e| anyhow!("v1 encoding: {e}"))?;
    ctx.self_check(std::slice::from_ref(&signed))?;
    Packet::new("edge reaffirm", ctx, vec![signed], vec![], None)
}

fn hex_arg(flag: &str, v: &str) -> Result<Hash> {
    hex32(v).with_context(|| format!("{flag} must be 64 hex characters"))
}

pub fn run(cmd: EdgeCommand) -> Result<()> {
    match cmd {
        EdgeCommand::Assert(a) => {
            check_relation(&a.relation)?;
            let input = AssertInput {
                relation: a.relation,
                source: hex_arg("--source", &a.source)?,
                target: hex_arg("--target", &a.target)?,
                source_revision: hex_arg("--source-revision", &a.common.source_revision)?,
                target_revision: hex_arg("--target-revision", &a.common.target_revision)?,
                rationale: a.common.rationale.clone(),
                evidence: entry_packet::evidence(&a.common.evidence)?,
            };
            finish(&a.common, |k, ctx| build_assert(k, ctx, input))
        }
        EdgeCommand::Reaffirm(r) => {
            let input = ReaffirmInput {
                edge: hex_arg("--edge", &r.edge)?,
                source_revision: hex_arg("--source-revision", &r.common.source_revision)?,
                target_revision: hex_arg("--target-revision", &r.common.target_revision)?,
                rationale: r.common.rationale.clone(),
                evidence: entry_packet::evidence(&r.common.evidence)?,
            };
            finish(&r.common, |k, ctx| build_reaffirm(k, ctx, input))
        }
    }
}
fn finish(c: &Common, build: impl FnOnce(&SecretKey, &Context) -> Result<Packet>) -> Result<()> {
    genesis::check_out_dir(&c.out)?;
    let ctx = Context::load(&c.context)?;
    let signer = key::load_key(&c.key)?;
    let packet = build(&signer, &ctx)?;
    let digest = packet.write_dir(&c.out)?;
    print!("{}", packet.summary(&c.out, digest));
    Ok(())
}
