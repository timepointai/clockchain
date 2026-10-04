//! `cc-publisher v1 correction`: a signed Correction of one resolved subject,
//! built offline against a saved context. Its parent is the subject's single
//! head, its old body that head's current body, and its grant an active grant
//! the signing key holds for the subject.
use super::entry_context::Context;
use super::entry_packet::{self, validate_text, Packet};
use super::genesis::{self, evidence_set, read_capped, MAX_BODY};
use super::{hex32, key, time};
use anyhow::{anyhow, ensure, Context as _, Result};
use cc_core::v1::{
    hash, AssertedTime, Decision, Envelope, Hash, Kind, Payload, Set, Signed, Value,
};
use cc_core::SecretKey;
use clap::{ArgAction, Args};
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct CorrectionArgs {
    /// Seed file of a key holding an active grant for the subject.
    #[arg(long)]
    pub key: PathBuf,
    /// Context file written by `cc-publisher v1 context`.
    #[arg(long)]
    pub context: PathBuf,
    /// Subject id (its Genesis event id), 64 hex characters.
    #[arg(long)]
    pub subject: String,
    /// The subject's current revision, as reviewed; refused if it has moved.
    #[arg(long)]
    pub revision: String,
    /// New body file: nonempty UTF-8, at most 1 MiB, different from the current body.
    #[arg(long)]
    pub body: PathBuf,
    /// Why the body changes; signed as is.
    #[arg(long)]
    pub rationale: String,
    /// Evidence SHA-256 hashes, 64 hex each; at least one; repeatable.
    #[arg(long, num_args = 1.., action = ArgAction::Append, required = true)]
    pub evidence: Vec<String>,
    /// YYYY, YYYY-MM or YYYY-MM-DD; the current revision's asserted time when omitted.
    #[arg(long, allow_hyphen_values = true)]
    pub asserted_time: Option<String>,
    /// Grant id, when the key holds more than one active grant for the subject.
    #[arg(long)]
    pub grant: Option<String>,
    /// Output directory; must be absent or empty.
    #[arg(long)]
    pub out: PathBuf,
}

pub struct CorrectionInput {
    pub subject: Hash,
    pub revision: Hash,
    pub body: Vec<u8>,
    pub rationale: String,
    pub evidence: Vec<Hash>,
    pub asserted_time: Option<AssertedTime>,
    pub grant: Option<Hash>,
}

/// Sign a Correction and check it as the node would against `ctx`.
pub fn build(signer: &SecretKey, ctx: &Context, input: CorrectionInput) -> Result<Packet> {
    let cur = ctx.current(input.subject)?;
    ensure!(
        cur.revision == input.revision,
        "subject {} has moved: its current revision is {}, not the reviewed {}; \
         refresh the context and review again",
        hex::encode(input.subject),
        hex::encode(cur.revision),
        hex::encode(input.revision)
    );
    genesis::validate_body(&input.body)?;
    validate_text("rationale", &input.rationale)?;
    let body = hash(&input.body);
    ensure!(
        body != cur.body,
        "the new body equals the current body; a correction must change it"
    );
    let author = signer.author().to_bytes();
    let grant = ctx.grant(input.subject, author, input.grant)?;
    ensure!(
        !input.evidence.is_empty(),
        "a correction must cite evidence"
    );
    let parents = Set(vec![cur.head]);
    let envelope = Envelope {
        instance: ctx.instance,
        author,
        subject: Some(input.subject),
        subject_key: Some(cur.key.clone()),
        grant: Some(grant),
        parents: parents.clone(),
        asserted_time: input.asserted_time.or(cur.asserted_time.clone()),
        payload: Payload::Correction {
            body,
            decision: Decision {
                kind: Kind::Correction,
                rationale: input.rationale,
                evidence: evidence_set(input.evidence)?,
                parents,
                old: Value::Body(cur.body),
                new: Value::Body(body),
            },
        },
    };
    let signed = Signed::sign(signer, envelope).map_err(|e| anyhow!("v1 encoding: {e}"))?;
    ctx.self_check(std::slice::from_ref(&signed))?;
    Packet::new("correction", ctx, vec![signed], vec![input.body], None)
}

pub fn run(args: CorrectionArgs) -> Result<()> {
    genesis::check_out_dir(&args.out)?;
    let input = CorrectionInput {
        subject: hex32(&args.subject).context("--subject must be 64 hex characters")?,
        revision: hex32(&args.revision).context("--revision must be 64 hex characters")?,
        body: read_capped(&args.body, MAX_BODY)?,
        rationale: args.rationale,
        evidence: entry_packet::evidence(&args.evidence)?,
        asserted_time: args.asserted_time.as_deref().map(time::parse).transpose()?,
        grant: args
            .grant
            .as_deref()
            .map(|g| hex32(g).context("--grant must be 64 hex characters"))
            .transpose()?,
    };
    let ctx = Context::load(&args.context)?;
    let signer = key::load_key(&args.key)?;
    let packet = build(&signer, &ctx, input)?;
    let digest = packet.write_dir(&args.out)?;
    print!("{}", packet.summary(&args.out, digest));
    Ok(())
}
