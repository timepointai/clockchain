//! Application-owned proposal generation. The Python adapter owns transport,
//! route qualification and shared budget reservations; Rust owns admission.
//! No branch in this module opens a database or signs a historical record.
use anyhow::{ensure, Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Args)]
pub struct Generate {
    /// Explicit new attempt after needs_evidence; requires changed source evidence.
    #[arg(long)]
    after: Option<PathBuf>,
    #[arg(long)]
    registry: PathBuf,
    #[arg(long)]
    brief: PathBuf,
    #[arg(long)]
    sources: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// Exact previous unpublished candidate to preserve and extend.
    #[arg(long)]
    base: Option<PathBuf>,
    /// Ask the selected text model for source-bound image prompts for every base entry.
    #[arg(long, requires = "base")]
    media_plan: bool,
    #[arg(long, default_value = "python3")]
    python: PathBuf,
}

#[derive(Args)]
pub struct SourceWindow {
    #[arg(long)]
    sources: PathBuf,
    #[arg(long)]
    source_id: String,
    /// Unique literal beginning of a passage (included).
    #[arg(long)]
    start: String,
    /// Unique literal end marker after the start (excluded).
    #[arg(long)]
    end: String,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub struct ImageGenerate {
    #[arg(long)]
    registry: PathBuf,
    #[arg(long)]
    route: PathBuf,
    #[arg(long)]
    candidate: PathBuf,
    /// Directory containing the unchanged model-authored media plan and receipts.
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value = "python3")]
    python: PathBuf,
}

pub fn image_bindings(path: &str) -> Result<()> {
    let candidate = read(Path::new(path))?;
    cc_publisher::validate_candidate(&candidate)?;
    let bindings: Vec<_> = candidate["entries"].as_array().unwrap().iter().map(|entry| {
        let (id, _) = cc_authoring::claim_identity(entry["title"].as_str().unwrap(), entry["year"].as_i64().unwrap());
        json!({"entity_id": id.to_string(), "body_hash": hex::encode(cc_authoring::body_hash("claim_v4", &entry.to_string()))})
    }).collect();
    println!("{}", json!(bindings));
    Ok(())
}

pub fn edge_bindings(path: &str) -> Result<()> {
    let candidate = read(Path::new(path))?;
    cc_publisher::validate_candidate_bindings(&candidate, true)?;
    let bindings = candidate["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(cc_publisher::review::entry_binding)
        .collect::<Result<Vec<_>>>()?;
    println!("{}", json!(bindings));
    Ok(())
}

pub fn image_generate(args: &ImageGenerate) -> Result<()> {
    private_parent(&args.output)?;
    ensure!(!args.output.exists(), "attempt output already exists");
    let original = fs::read(&args.candidate)?;
    let candidate: Value = serde_json::from_slice(&original)?;
    cc_publisher::validate_candidate(&candidate)?;
    let development = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/image_prepare.py");
    let runtime = if development.is_file() {
        development
    } else {
        PathBuf::from("/app/ops/image_prepare.py")
    };
    ensure!(runtime.is_file(), "bundled image runtime missing");
    let mut child = Command::new(&args.python);
    child.env_clear();
    for key in ["PATH", "HOME", "TMPDIR", "LANG", "HF_TOKEN"] {
        if let Some(value) = std::env::var_os(key) {
            child.env(key, value);
        }
    }
    child.env("CC_PUBLISHER_BIN", std::env::current_exe()?);
    child
        .arg(runtime)
        .arg("--registry")
        .arg(&args.registry)
        .arg("--route")
        .arg(&args.route)
        .arg("--candidate")
        .arg(&args.candidate)
        .arg("--plan")
        .arg(&args.plan)
        .arg("--output")
        .arg(&args.output);
    ensure!(
        child.status()?.success(),
        "image preparation failed; retained receipt is authoritative"
    );
    ensure!(
        fs::read(&args.candidate)? == original,
        "candidate changed during image preparation"
    );
    let prepared = read(&args.output.join("proposal.json"))?;
    cc_publisher::validate_candidate(&prepared)?;
    for key in ["entries", "edges"] {
        ensure!(
            prepared[key] == candidate[key],
            "image preparation rewrote {key}"
        );
    }
    let receipt = json!({"schema":"cc.application-image-preparation.v1","admission":"pass",
        "candidate_sha256":hex::encode(cc_publisher::digest(&original)),
        "proposal_sha256":hex::encode(cc_publisher::digest(&fs::read(args.output.join("proposal.json"))?)),
        "visual_review":"pending","published":false});
    save(&args.output.join("application-admission.json"), &receipt)?;
    println!("{receipt}");
    Ok(())
}

fn read(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn private_parent(path: &Path) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let parent = path
        .parent()
        .context("output needs parent directory")?
        .canonicalize()?;
    if let Ok(root) = root.canonicalize() {
        ensure!(
            !parent.starts_with(root),
            "operational files must stay outside checkout"
        );
    }
    ensure!(
        !parent.starts_with("/app"),
        "operational files must stay outside application directory"
    );
    Ok(())
}

fn save(path: &Path, value: &Value) -> Result<()> {
    private_parent(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub fn source_window(args: &SourceWindow) -> Result<()> {
    let mut manifest = read(&args.sources)?;
    let rows = manifest
        .as_array_mut()
        .context("source manifest must be an array")?;
    ensure!(
        rows.iter().filter(|s| s["id"] == args.source_id).count() == 1,
        "source id must be unique"
    );
    let source = rows.iter_mut().find(|s| s["id"] == args.source_id).unwrap();
    let capture = fs::read(
        source["capture_path"]
            .as_str()
            .context("capture path missing")?,
    )?;
    ensure!(
        source["content_sha256"] == hex::encode(cc_publisher::digest(&capture)),
        "capture hash mismatch"
    );
    let text = std::str::from_utf8(&capture)?;
    ensure!(
        !args.start.is_empty() && !args.end.is_empty(),
        "nonempty markers required"
    );
    ensure!(
        text.matches(&args.start).count() == 1,
        "start marker must be unique"
    );
    let start = text.find(&args.start).unwrap();
    let tail = &text[start..];
    ensure!(
        tail.matches(&args.end).count() == 1,
        "end marker must be unique after start"
    );
    let end = tail.find(&args.end).unwrap();
    ensure!(end > 0, "empty source window");
    source["passages"]
        .as_array_mut()
        .context("passages array missing")?
        .push(json!(&tail[..end]));
    let previous = source["locator"].as_str().context("locator missing")?;
    source["locator"] = json!(format!(
        "{previous}; retained UTF-8 capture bytes {start}..{}",
        start + end
    ));
    save(&args.output, &manifest)?;
    println!(
        "{}",
        json!({"sources":args.output,"authored_history":false,"operation":"literal_capture_window"})
    );
    Ok(())
}

pub fn generate(args: &Generate) -> Result<()> {
    private_parent(&args.output)?;
    // Idempotent terminal read precedes route/credential/base access. A retry
    // never invokes Python, touches the receipt or spends again.
    if args.output.exists() {
        let receipt = read(&args.output.join("result.json"))?;
        ensure!(
            receipt["schema"] == "cc.generation-result.v1",
            "invalid attempt receipt"
        );
        let status = cc_publisher::review::AttemptStatus::from_receipt(&receipt)?;
        if status.is_nonproposal() {
            if status != cc_publisher::review::AttemptStatus::Failed {
                ensure!(
                    !args.output.join("proposal.json").exists(),
                    "terminal attempt has a proposal"
                );
            }
            println!("{receipt}");
            return Ok(());
        }
    }
    ensure!(!args.output.exists(), "attempt output already exists");
    let base = args
        .base
        .as_ref()
        .map(|path| -> Result<_> {
            let bytes = fs::read(path)?;
            let candidate: Value = serde_json::from_slice(&bytes)?;
            cc_publisher::validate_candidate(&candidate)?;
            Ok((bytes, candidate))
        })
        .transpose()?;
    let development = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/model_runtime.py");
    let runtime = if development.is_file() {
        development
    } else {
        PathBuf::from("/app/ops/model_runtime.py")
    };
    ensure!(runtime.is_file(), "bundled model runtime missing");
    let mut child = Command::new(&args.python);
    child.env_clear();
    // Never pass database, signing, node, cloud or unrelated credentials.
    for key in ["PATH", "HOME", "TMPDIR", "LANG", "OPENROUTER_API_KEY"] {
        if let Some(value) = std::env::var_os(key) {
            child.env(key, value);
        }
    }
    child.env("CC_PUBLISHER_BIN", std::env::current_exe()?);
    child
        .arg(runtime)
        .arg("--registry")
        .arg(&args.registry)
        .arg("--brief")
        .arg(&args.brief)
        .arg("--sources")
        .arg(&args.sources)
        .arg("--output")
        .arg(&args.output);
    if let Some(path) = &args.base {
        child.arg("--base").arg(path);
    }
    if args.media_plan {
        child.arg("--media-plan");
    }
    if let Some(path) = &args.after {
        child.arg("--after").arg(path);
    }
    let status = child.status().context("start bundled model runtime")?;
    ensure!(
        status.success(),
        "generation failed; retained attempt receipt is authoritative"
    );
    let result = read(&args.output.join("result.json"))?;
    cc_publisher::review::AttemptStatus::from_receipt(&result)?;
    if result["status"] == "media_plan" {
        ensure!(args.media_plan, "unexpected media plan");
        let (original, candidate) = base.context("media plan requires base")?;
        ensure!(
            fs::read(args.base.as_ref().unwrap())? == original,
            "base changed during media preparation"
        );
        let bytes = fs::read(args.output.join("media-plan.json"))?;
        ensure!(
            result["media_plan_sha256"] == hex::encode(cc_publisher::digest(&bytes)),
            "media plan receipt hash mismatch"
        );
        let plan: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            plan["candidate_sha256"] == hex::encode(cc_publisher::digest(&original)),
            "media plan candidate mismatch"
        );
        let mut indices = plan["prompts"]
            .as_array()
            .context("prompts missing")?
            .iter()
            .map(|p| p["entry_index"].as_u64().context("entry index missing"))
            .collect::<Result<Vec<_>>>()?;
        indices.sort_unstable();
        ensure!(
            indices
                == (0..candidate["entries"].as_array().unwrap().len() as u64).collect::<Vec<_>>(),
            "media plan does not cover every entry exactly once"
        );
        let receipt = json!({"schema":"cc.application-media-plan.v1","admission":"pass",
            "media_plan_sha256":result["media_plan_sha256"],"candidate_sha256":plan["candidate_sha256"],
            "prompt_author":"selected text model","images_generated":0,"published":false});
        save(&args.output.join("application-admission.json"), &receipt)?;
        println!("{receipt}");
        return Ok(());
    }
    if result["status"] != "proposal" {
        println!(
            "{}",
            json!({"status":result["status"],"reason":result["reason"],"published":false})
        );
        return Ok(());
    }
    let bytes = fs::read(args.output.join("proposal.json"))?;
    ensure!(
        result["proposal_sha256"] == hex::encode(cc_publisher::digest(&bytes)),
        "candidate receipt hash mismatch"
    );
    let candidate: Value = serde_json::from_slice(&bytes)?;
    cc_publisher::validate_candidate(&candidate)?;
    if let Some((original, old)) = base {
        ensure!(
            fs::read(args.base.as_ref().unwrap())? == original,
            "base changed during generation"
        );
        cc_publisher::review::validate_frozen_subjects(&old, &candidate)?;
        for key in ["entries", "edges", "images"] {
            let preserved = old[key].as_array().context("base array missing")?;
            ensure!(
                candidate[key]
                    .as_array()
                    .context("candidate array missing")?
                    .starts_with(preserved),
                "extension rewrote existing {key}"
            );
        }
    }
    let receipt = json!({"schema":"cc.application-generation.v1","admission":"pass",
        "candidate_sha256":result["proposal_sha256"],"base_sha256":result.get("base_sha256"),
        "entries":candidate["entries"].as_array().unwrap().len(),"edges":candidate["edges"].as_array().unwrap().len(),
        "historical_author": "selected model; no authored-field repair", "published":false});
    save(&args.output.join("application-admission.json"), &receipt)?;
    println!("{receipt}");
    Ok(())
}
