//! `cc-publisher v1 grants`, `v1 delegate` and `v1 revoke`. `grants` is the
//! only one that talks to a node, and it only reads; `delegate` and `revoke`
//! sign offline from the grants file it writes. Runbook: `docs/KEYS.md`.
use super::authority::{self, Context, RevokeChoice};
use super::cli::{token, READ_TOKEN_ENV, WRITE_TOKEN_ENV};
use super::genesis::write_new;
use super::node::Node;
use super::{authority_node, hex32, key};
use anyhow::{Context as _, Result};
use clap::{ArgAction, ArgGroup, Args};
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct GrantsArgs {
    #[arg(long)]
    pub node: String,
    /// Subject id (the Genesis event id), 64 hex characters.
    #[arg(long)]
    pub subject: String,
    /// Also write the grants file here (new file only), for `delegate` and
    /// `revoke` on an offline machine.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// Arguments every offline authority command takes.
#[derive(Args, Debug)]
pub struct Signing {
    /// Seed file of the signing key; it must hold an active grant on the subject.
    #[arg(long)]
    pub key: PathBuf,
    /// Grants file written by `grants --out`.
    #[arg(long)]
    pub grants: PathBuf,
    /// Why, as signed in the decision: one line, at most 1024 bytes.
    #[arg(long)]
    pub rationale: String,
    /// Evidence SHA-256 hashes, 64 hex characters each; at least one.
    #[arg(long, required = true, num_args = 1.., action = ArgAction::Append)]
    pub evidence: Vec<String>,
    /// Output directory; must be absent or empty.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct DelegateArgs {
    #[command(flatten)]
    pub signing: Signing,
    /// Public key of the new key (`v1 pubkey`), 64 hex characters.
    #[arg(long)]
    pub grantee: String,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("cascade_choice").required(true).args(["cascade", "no_cascade"])))]
pub struct RevokeArgs {
    #[command(flatten)]
    pub signing: Signing,
    /// Grant id to revoke (from `grants`), 64 hex characters.
    #[arg(long)]
    pub target: String,
    /// Also revoke every grant issued below the target, now or later.
    #[arg(long)]
    pub cascade: bool,
    /// Revoke only the target; grants it issued in this revoke's past survive.
    #[arg(long)]
    pub no_cascade: bool,
    /// Required, and only accepted, when the root key revokes the root grant.
    #[arg(long)]
    pub relinquish_root: bool,
    /// Extend this earlier subject event instead of the sole head, so that
    /// later acts of the revoked grants fall outside the revoke's past.
    #[arg(long)]
    pub parent: Option<String>,
}

impl Signing {
    /// Parse everything and check `--out` before the key is loaded.
    fn parse(&self) -> Result<(Context, Vec<cc_core::v1::Hash>)> {
        super::genesis::check_out_dir(&self.out)?;
        let ctx = Context::load(&self.grants)?;
        authority::validate_rationale(&self.rationale)?;
        let evidence = self
            .evidence
            .iter()
            .map(|e| {
                hex32(e).with_context(|| format!("--evidence {e:?} must be 64 hex characters"))
            })
            .collect::<Result<Vec<_>>>()?;
        super::genesis::evidence_set(evidence.clone())?;
        Ok((ctx, evidence))
    }
}

fn written(ev: &authority::AuthorityEvent, ctx: &Context, out: &std::path::Path) -> Result<()> {
    ev.write_dir(out)?;
    print!(
        "v1 {} written to {} (offline; nothing was submitted)\n\n{}\n\
         Review {} before `cc-publisher v1 submit`.\n",
        ev.kind_name(),
        out.display(),
        ev.summary(ctx),
        authority::PREVIEW_FILE
    );
    Ok(())
}

pub async fn grants(a: GrantsArgs) -> Result<()> {
    let subject = hex32(&a.subject).context("--subject must be 64 hex characters")?;
    if let Some(out) = &a.out {
        anyhow::ensure!(
            std::fs::symlink_metadata(out).is_err(),
            "refusing to overwrite existing {}",
            out.display()
        );
    }
    let token = token(READ_TOKEN_ENV, Some(WRITE_TOKEN_ENV))?;
    let node = Node::new(&a.node, Some(&token))?;
    let ctx = authority_node::grants(&node, subject).await?;
    let mut v = ctx.to_json();
    node.redact_json(&mut v);
    let text = serde_json::to_string_pretty(&v)? + "\n";
    if let Some(out) = &a.out {
        write_new(out, text.as_bytes())?;
        eprintln!("grants file written to {}", out.display());
    }
    print!("{text}");
    Ok(())
}

pub fn delegate(a: DelegateArgs) -> Result<()> {
    let (ctx, evidence) = a.signing.parse()?;
    let grantee = hex32(&a.grantee).context("--grantee must be 64 hex characters")?;
    let signer = key::load_key(&a.signing.key)?;
    let ev = authority::delegate(&signer, &ctx, grantee, &a.signing.rationale, evidence)?;
    written(&ev, &ctx, &a.signing.out)
}

pub fn revoke(a: RevokeArgs) -> Result<()> {
    let (ctx, evidence) = a.signing.parse()?;
    let choice = RevokeChoice {
        target: hex32(&a.target).context("--target must be 64 hex characters")?,
        // The group makes exactly one of the two flags present.
        cascade: a.cascade && !a.no_cascade,
        relinquish_root: a.relinquish_root,
        parent: a
            .parent
            .as_deref()
            .map(|p| hex32(p).context("--parent must be 64 hex characters"))
            .transpose()?,
    };
    let signer = key::load_key(&a.signing.key)?;
    let ev = authority::revoke(&signer, &ctx, choice, &a.signing.rationale, evidence)?;
    written(&ev, &ctx, &a.signing.out)
}
