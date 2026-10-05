//! `cc-publisher v1 attest`: an Attestation exactly as `cc.event.v1` encodes
//! it: a revision or an event as target, an artifact kind and the artifact's
//! SHA-256. The fold binds it to that revision (or to the revision the target
//! event created) and never moves it after a correction.
//!
//! v1 has no signed absence: an Attestation always names an artifact hash, and
//! the fold infers nothing from a missing one (`media.inference=none`). This
//! command therefore has no absence form; see `docs/AUTHORING-V1.md`.
use super::entry_context::Context;
use super::entry_packet::Packet;
use super::{genesis, hex32, key};
use anyhow::{anyhow, bail, ensure, Context as _, Result};
use cc_core::v1::{revision_id, Envelope, Hash, Kind, Payload, Set, Signed, TargetKind};
use cc_core::SecretKey;
use cc_ledger::v1::State;
use clap::{ArgGroup, Args};
use std::path::PathBuf;

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("target").required(true).args(["revision", "event"])))]
pub struct AttestArgs {
    #[arg(long)]
    pub key: PathBuf,
    /// Context file written by `cc-publisher v1 context`.
    #[arg(long)]
    pub context: PathBuf,
    /// Revision-scoped: the revision id the artifact is bound to.
    #[arg(long)]
    pub revision: Option<String>,
    /// Event-scoped: a valid subject or edge event id.
    #[arg(long)]
    pub event: Option<String>,
    /// What the artifact is, e.g. a media type; same rules as a subject-key value.
    #[arg(long)]
    pub artifact_kind: String,
    /// SHA-256 of the artifact bytes, 64 hex characters. The artifact is never read.
    #[arg(long)]
    pub artifact_sha256: String,
    /// Output directory; must be absent or empty.
    #[arg(long)]
    pub out: PathBuf,
}

pub struct AttestInput {
    pub target_kind: TargetKind,
    pub target: Hash,
    pub artifact_kind: String,
    pub artifact: Hash,
}

/// The revision an attestation is bound to under `ctx`: the target revision,
/// or the revision a target event created; `None` for other events.
pub fn bound_revision(ctx: &Context, kind: TargetKind, target: Hash) -> Option<Hash> {
    let revisions = &ctx.projection.revisions;
    match kind {
        TargetKind::Revision => Some(target),
        TargetKind::Event => {
            let e = ctx.events.get(&target)?.envelope();
            let r = revision_id(e.subject.unwrap_or(target), target);
            revisions.iter().any(|x| x.id == r).then_some(r)
        }
    }
}

pub fn build(signer: &SecretKey, ctx: &Context, i: AttestInput) -> Result<Packet> {
    genesis::validate_key_field("artifact kind", &i.artifact_kind)?;
    let t = hex::encode(i.target);
    match i.target_kind {
        TargetKind::Revision => ensure!(
            ctx.projection.revisions.iter().any(|r| r.id == i.target),
            "revision {t} is not a revision in the context"
        ),
        TargetKind::Event => {
            match ctx.kind(i.target) {
                None => bail!("event {t} is not in the context"),
                Some(Kind::Attestation) => bail!("an attestation cannot target an attestation"),
                Some(_) => {}
            }
            ensure!(
                ctx.state(i.target) == Some(State::Valid),
                "event {t} is not valid in the context"
            );
        }
    }
    let envelope = Envelope {
        instance: ctx.instance,
        author: signer.author().to_bytes(),
        subject: None,
        subject_key: None,
        grant: None,
        parents: Set(vec![]),
        asserted_time: None,
        payload: Payload::Attestation {
            target_kind: i.target_kind,
            target: i.target,
            artifact_kind: i.artifact_kind,
            artifact: i.artifact,
        },
    };
    let signed = Signed::sign(signer, envelope).map_err(|e| anyhow!("v1 encoding: {e}"))?;
    ctx.self_check(std::slice::from_ref(&signed))?;
    Packet::new("attest", ctx, vec![signed], vec![], None)
}

pub fn run(a: AttestArgs) -> Result<()> {
    genesis::check_out_dir(&a.out)?;
    let (target_kind, target) = match (&a.revision, &a.event) {
        (Some(r), None) => (
            TargetKind::Revision,
            hex32(r).context("--revision must be 64 hex characters")?,
        ),
        (None, Some(e)) => (
            TargetKind::Event,
            hex32(e).context("--event must be 64 hex characters")?,
        ),
        _ => bail!("pass exactly one of --revision and --event"),
    };
    let input = AttestInput {
        target_kind,
        target,
        artifact_kind: a.artifact_kind,
        artifact: hex32(&a.artifact_sha256)
            .context("--artifact-sha256 must be 64 hex characters")?,
    };
    let ctx = Context::load(&a.context)?;
    let signer = key::load_key(&a.key)?;
    let packet = build(&signer, &ctx, input)?;
    let digest = packet.write_dir(&a.out)?;
    print!("{}", packet.summary(&a.out, digest));
    match bound_revision(&ctx, target_kind, target) {
        Some(r) => println!(
            "Bound to revision {} only; a later correction does not move it.",
            hex::encode(r)
        ),
        None => println!("Event-scoped; the target event creates no revision."),
    }
    Ok(())
}
