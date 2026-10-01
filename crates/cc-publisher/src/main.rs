use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use sqlx::Row;
mod generation;
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    /// Compute endpoint bindings only; does not admit or rewrite a candidate.
    EdgeBindings {
        #[arg(long)]
        path: String,
    },
    /// Print the exact candidate admit set without a database, credentials or writes.
    DryRun {
        #[arg(long)]
        path: String,
        #[arg(long)]
        brief: String,
        #[arg(long)]
        attempt: String,
        /// Inspect a claims-only set without editing the original candidate.
        #[arg(long)]
        exclude_media: bool,
    },
    /// Generate or extend a private candidate through the selected model; never publish.
    Generate(generation::Generate),
    /// Append a literal window from an already captured, rights-reviewed source.
    SourceWindow(generation::SourceWindow),
    /// Generate private image candidates from model-authored prompts; never sign or publish.
    ImageGenerate(generation::ImageGenerate),
    /// Compute the exact entity/body binding used by publication, without writing.
    ImageBindings {
        #[arg(long)]
        path: String,
    },
    /// Validate a private candidate without database access or publication.
    Validate {
        #[arg(long)]
        path: String,
        /// Also enforce the required-image gate from this private brief.
        #[arg(long)]
        brief: Option<String>,
        /// Reject any subject replacement inside a frozen base.
        #[arg(long)]
        base: Option<String>,
    },
    BriefStage {
        #[arg(long)]
        id: String,
        #[arg(long)]
        path: String,
    },
    BriefShow {
        #[arg(long)]
        id: String,
    },
    CandidateStage {
        #[arg(long)]
        id: String,
        #[arg(long)]
        brief: String,
        #[arg(long)]
        path: String,
    },
    ApproveBrief {
        #[arg(long)]
        id: String,
        #[arg(long)]
        digest: String,
        #[arg(long)]
        reviewer: String,
    },
    ApproveCandidate {
        #[arg(long)]
        id: String,
        #[arg(long)]
        digest: String,
        #[arg(long)]
        reviewer: String,
    },
    Publish {
        #[arg(long)]
        id: String,
        #[arg(long)]
        digest: String,
    },
    Receipt {
        #[arg(long)]
        id: String,
    },
    Pause {
        #[arg(long)]
        reason: String,
    },
    Resume {
        #[arg(long)]
        reason: String,
    },
    Status,
}
fn file(path: &str) -> Result<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::EdgeBindings { path } => return generation::edge_bindings(path),
        Cmd::DryRun {
            path,
            brief,
            attempt,
            exclude_media,
        } => {
            let mut candidate = file(path)?;
            let input_digest = hex::encode(cc_publisher::digest(
                cc_publisher::canonical(&candidate).as_bytes(),
            ));
            if *exclude_media {
                candidate["images"] = json!([]);
            }
            let receipt = file(attempt)?;
            let mut report = cc_publisher::review::dry_run(&candidate, &file(brief)?, &receipt)?;
            report["input_candidate_digest"] = json!(input_digest);
            report["media_excluded_for_inspection"] = json!(exclude_media);
            if receipt["status"] == "proposal"
                && receipt["proposal_sha256"]
                    != hex::encode(cc_publisher::digest(&std::fs::read(path)?))
            {
                report["status"] = json!("blocked");
                report["blockers"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"code":"attempt_candidate_mismatch"}));
            }
            println!("{report}");
            if report["status"] == "blocked" {
                bail!("dry_run_blocked");
            }
            return Ok(());
        }
        Cmd::Generate(args) => return generation::generate(args),
        Cmd::SourceWindow(args) => return generation::source_window(args),
        Cmd::ImageGenerate(args) => return generation::image_generate(args),
        Cmd::ImageBindings { path } => return generation::image_bindings(path),
        _ => {}
    }
    if let Cmd::Validate { path, brief, base } = &cli.cmd {
        let candidate = file(path)?;
        if let Some(base) = base {
            cc_publisher::review::validate_frozen_subjects(&file(base)?, &candidate)?;
        }
        cc_publisher::validate_candidate(&candidate)?;
        if let Some(brief) = brief {
            cc_publisher::require_images(&file(brief)?, &candidate)?;
        }
        println!(
            "{}",
            json!({"valid":true,"entries":candidate["entries"].as_array().unwrap().len(),"edges":candidate["edges"].as_array().unwrap().len()})
        );
        return Ok(());
    }
    let pool = cc_ledger::connect(&std::env::var("DATABASE_URL").context("DATABASE_URL required")?)
        .await?;
    let result = match cli.cmd {
        Cmd::Validate { .. }
        | Cmd::EdgeBindings { .. }
        | Cmd::DryRun { .. }
        | Cmd::Generate(_)
        | Cmd::SourceWindow(_)
        | Cmd::ImageGenerate(_)
        | Cmd::ImageBindings { .. } => {
            unreachable!("handled before database connection")
        }
        Cmd::BriefStage { id, path } => {
            cc_publisher::stage_brief(&pool, &id, &file(&path)?).await?
        }
        Cmd::BriefShow { id } => {
            let row = sqlx::query("SELECT digest,payload FROM generation_briefs WHERE id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await?;
            let digest: Vec<u8> = row.get("digest");
            let brief: Value = serde_json::from_str(&row.get::<String, _>("payload"))?;
            let approved = cc_publisher::approved(&pool, "brief", &id, &digest)
                .await
                .is_ok();
            json!({"id":id,"digest":hex::encode(digest),"approved":approved,"brief":brief})
        }
        Cmd::CandidateStage { id, brief, path } => {
            cc_publisher::stage_candidate(&pool, &id, &brief, &file(&path)?).await?
        }
        Cmd::ApproveBrief {
            id,
            digest,
            reviewer,
        } => cc_publisher::approve(&pool, "brief", &id, &hex::decode(digest)?, &reviewer).await?,
        Cmd::ApproveCandidate {
            id,
            digest,
            reviewer,
        } => {
            cc_publisher::approve(&pool, "candidate", &id, &hex::decode(digest)?, &reviewer).await?
        }
        Cmd::Publish { id, digest } => {
            let raw = hex::decode(
                std::env::var("MIGRATOR_SECRET_KEY")
                    .context("MIGRATOR_SECRET_KEY required only for publication")?
                    .trim(),
            )?;
            let seed: [u8; 32] = match raw.try_into() {
                Ok(s) => s,
                Err(_) => bail!("signing seed must be32 bytes"),
            };
            cc_publisher::publish(
                &pool,
                &id,
                &hex::decode(digest)?,
                &cc_core::SecretKey::from_seed(seed),
            )
            .await?
        }
        Cmd::Receipt { id } => cc_publisher::receipt(&pool, &id)
            .await?
            .context("receipt not found")?,
        Cmd::Pause { reason } => {
            sqlx::query("UPDATE publication_control SET paused=true,reason=$1,updated_at=now() WHERE singleton").bind(reason).execute(&pool).await?;
            json!({"paused":true})
        }
        Cmd::Resume { reason } => {
            sqlx::query("UPDATE publication_control SET paused=false,reason=$1,updated_at=now() WHERE singleton").bind(reason).execute(&pool).await?;
            json!({"paused":false})
        }
        Cmd::Status => {
            let row = sqlx::query("SELECT paused,reason FROM publication_control WHERE singleton")
                .fetch_one(&pool)
                .await?;
            json!({"paused":row.get::<bool,_>("paused"),"reason":row.get::<String,_>("reason")})
        }
    };
    println!("{}", result);
    Ok(())
}
