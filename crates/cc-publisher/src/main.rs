use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use sqlx::Row;
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
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
    let pool = cc_ledger::connect(&std::env::var("DATABASE_URL").context("DATABASE_URL required")?)
        .await?;
    let result = match cli.cmd {
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
