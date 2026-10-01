//! The `cc-publisher v1` subcommands. Secrets come only from files (`--key`)
//! or the environment (`CC_NODE_API_KEY`, `CC_NODE_READ_KEY`), never argv.
use super::genesis::{self, Genesis, GenesisInput, MAX_BODY};
use super::node::{self, Node};
use super::{hex32, key, time};
use anyhow::{bail, ensure, Context, Result};
use clap::{ArgAction, Args, Subcommand};
use std::path::{Path, PathBuf};

/// Write token for `submit`.
pub const WRITE_TOKEN_ENV: &str = "CC_NODE_API_KEY";
/// Read token for `verify`; `CC_NODE_API_KEY` is used when it is unset.
pub const READ_TOKEN_ENV: &str = "CC_NODE_READ_KEY";

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Write a new random 32-byte seed (hex, mode 0600) and print its public key.
    Keygen {
        /// New key file; an existing file is never replaced.
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the Ed25519 public key of a seed file.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Read a node's v1 /health; exit non-zero unless its fold is this build's.
    NodeInfo {
        #[arg(long)]
        node: String,
    },
    /// Build and sign a v1 Genesis offline into an empty output directory.
    Genesis(GenesisArgs),
    /// Check a node, store the body, submit the envelope and read both back.
    Submit {
        #[arg(long)]
        node: String,
        /// A directory written by `genesis`.
        #[arg(long)]
        dir: PathBuf,
        /// Submit even when the instance, fold, curator or filter check fails.
        #[arg(long)]
        allow_untrusted: bool,
    },
    /// Read-only check that a node serves a subject's current revision intact.
    Verify {
        #[arg(long)]
        node: String,
        /// Subject id (the Genesis event id), 64 hex characters.
        #[arg(long)]
        subject: String,
        /// Also require exactly this `genesis` directory's revision and body.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
pub struct GenesisArgs {
    /// Seed file written by `keygen`; refused if its mode is wider than 0600.
    #[arg(long)]
    pub key: PathBuf,
    /// Instance id, 64 hex characters.
    #[arg(long)]
    pub instance: String,
    /// Subject-key kind: a current node id of the pinned TT taxonomy.
    #[arg(long)]
    pub kind: String,
    #[arg(long)]
    pub namespace: String,
    #[arg(long)]
    pub value: String,
    /// Body file: nonempty UTF-8, at most 1 MiB.
    #[arg(long)]
    pub body: PathBuf,
    /// YYYY, YYYY-MM or YYYY-MM-DD (leading '-' for years before 0000).
    #[arg(long, allow_hyphen_values = true)]
    pub asserted_time: String,
    /// Evidence SHA-256 hashes, 64 hex characters each; repeatable.
    #[arg(long, num_args = 1.., action = ArgAction::Append)]
    pub evidence: Vec<String>,
    /// Genesis nonce, 64 hex characters; random from the OS RNG when omitted.
    #[arg(long)]
    pub nonce: Option<String>,
    /// Output directory; must be absent or empty.
    #[arg(long)]
    pub out: PathBuf,
}

impl GenesisArgs {
    /// Parse and check every argument before anything is written.
    pub fn input(&self) -> Result<GenesisInput> {
        let instance = hex32(&self.instance).context("--instance must be 64 hex characters")?;
        genesis::validate_kind(&self.kind)?;
        genesis::validate_key_field("namespace", &self.namespace)?;
        genesis::validate_key_field("value", &self.value)?;
        let asserted_time = time::parse(&self.asserted_time)?;
        let evidence = self
            .evidence
            .iter()
            .map(|e| {
                hex32(e).with_context(|| format!("--evidence {e:?} must be 64 hex characters"))
            })
            .collect::<Result<Vec<_>>>()?;
        genesis::evidence_set(evidence.clone())?;
        let nonce = match &self.nonce {
            Some(n) => hex32(n).context("--nonce must be 64 hex characters")?,
            None => key::os_random()?,
        };
        let body = genesis::read_capped(&self.body, MAX_BODY)?;
        genesis::validate_body(&body)?;
        Ok(GenesisInput {
            instance,
            kind: self.kind.clone(),
            namespace: self.namespace.clone(),
            value: self.value.clone(),
            body,
            asserted_time,
            evidence,
            nonce,
        })
    }
}

fn token(primary: &str, fallback: Option<&str>) -> Result<String> {
    let names = [Some(primary), fallback];
    for name in names.into_iter().flatten() {
        if let Ok(v) = std::env::var(name) {
            ensure!(!v.trim().is_empty(), "{name} is set but empty");
            return Ok(v);
        }
    }
    bail!("{primary} must be set in the environment (tokens are never taken from argv)")
}
fn subject_arg(s: &str) -> Result<cc_core::v1::Hash> {
    hex32(s).context("--subject must be 64 hex characters")
}
fn print_json(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Keygen { out } => println!("{}", hex::encode(key::keygen(&out)?)),
        Command::Pubkey { key } => {
            println!("{}", hex::encode(key::load_key(&key)?.author().to_bytes()))
        }
        Command::NodeInfo { node } => {
            let node = Node::new(&node, None)?;
            let health = node.health().await?;
            print_json(&node::node_info(&node, &health))?;
            ensure!(
                health.fold_matches(),
                "node fold_version differs from this build's fold_v1()"
            );
        }
        Command::Genesis(args) => {
            let input = args.input()?;
            let signer = key::load_key(&args.key)?;
            let g = genesis::build(&signer, input)?;
            g.write_dir(&args.out)?;
            print!(
                "v1 Genesis written to {} (offline; nothing was submitted)\n\n{}\n\
                 Review {} and {} before `cc-publisher v1 submit`.\n",
                args.out.display(),
                g.summary()?,
                genesis::BODY_FILE,
                genesis::PREVIEW_FILE
            );
        }
        Command::Submit {
            node,
            dir,
            allow_untrusted,
        } => {
            let node = Node::new(&node, Some(&token(WRITE_TOKEN_ENV, None)?))?;
            let done = node::submit(&node, &dir, allow_untrusted).await?;
            for w in &done.warnings {
                eprintln!("warning (--allow-untrusted): {w}");
            }
            print_json(&done.receipt)?;
            let path = dir.join(node::RECEIPT_FILE);
            if done.receipt_written {
                eprintln!("receipt written to {}", path.display());
            } else {
                eprintln!("{} already exists; left unchanged", path.display());
            }
        }
        Command::Verify { node, subject, dir } => {
            let token = token(READ_TOKEN_ENV, Some(WRITE_TOKEN_ENV))?;
            let node = Node::new(&node, Some(&token))?;
            let (ok, report) =
                node::verify(&node, subject_arg(&subject)?, dir.as_deref().map(Path::new)).await?;
            print_json(&report)?;
            ensure!(ok, "verification failed");
        }
    }
    Ok(())
}

/// Load a `genesis` directory with every reload check (for scripts and tests).
pub fn load(dir: &Path) -> Result<Genesis> {
    Genesis::load_dir(dir)
}
