use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cc-generation-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cc-publisher"))
}

#[test]
fn source_windows_bind_original_bytes_and_never_overwrite() {
    let f = Fixture::new();
    let raw = "Header\nStart: synthetic event.\nEnd: unrelated material.";
    let capture = f.0.join("capture.txt");
    fs::write(&capture, raw).unwrap();
    let manifest = f.0.join("sources.json");
    fs::write(
        &manifest,
        json!([{"id":"fixture","capture_path":capture,
        "content_sha256":hex::encode(cc_publisher::digest(raw.as_bytes())),
        "locator":"fixture", "passages":["Header"]}])
        .to_string(),
    )
    .unwrap();
    let output = f.0.join("expanded.json");
    let run = || {
        cli()
            .args(["source-window", "--sources"])
            .arg(&manifest)
            .args([
                "--source-id",
                "fixture",
                "--start",
                "Start:",
                "--end",
                "End:",
                "--output",
            ])
            .arg(&output)
            .output()
            .unwrap()
    };
    assert!(run().status.success());
    let expanded: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(expanded[0]["passages"][1], "Start: synthetic event.\n");
    let before = fs::read(&output).unwrap();
    assert!(!run().status.success());
    assert_eq!(fs::read(&output).unwrap(), before);
    fs::remove_file(&output).unwrap();
    fs::write(&capture, "changed source").unwrap();
    assert!(!run().status.success());
    assert!(!output.exists());
}

#[test]
#[cfg(unix)]
fn generation_child_cannot_inherit_database_or_signing_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let interpreter = f.0.join("probe.sh");
    fs::write(&interpreter, "#!/bin/sh\nif [ -n \"$DATABASE_URL$CC_NODE_READ_KEY$MIGRATOR_SECRET_KEY$AWS_SECRET_ACCESS_KEY\" ]; then exit 71; fi\nif [ \"$OPENROUTER_API_KEY\" != synthetic-key ]; then exit 72; fi\nif [ -z \"$CC_PUBLISHER_BIN\" ]; then exit 73; fi\necho credential-isolation-pass\nexit 23\n").unwrap();
    fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o700)).unwrap();
    let output = cli()
        .arg("generate")
        .arg("--registry")
        .arg(&f.0)
        .arg("--brief")
        .arg(f.0.join("brief.json"))
        .arg("--sources")
        .arg(f.0.join("sources.json"))
        .arg("--output")
        .arg(f.0.join("attempt"))
        .arg("--python")
        .arg(interpreter)
        .env("DATABASE_URL", "synthetic-do-not-connect")
        .env("MIGRATOR_SECRET_KEY", "synthetic-signing-secret")
        .env("CC_NODE_READ_KEY", "synthetic-node-secret")
        .env("AWS_SECRET_ACCESS_KEY", "synthetic-unrelated-secret")
        .env("OPENROUTER_API_KEY", "synthetic-key")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("credential-isolation-pass"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("generation failed"));
    assert!(!f.0.join("attempt").exists());
}

#[test]
fn terminal_evidence_retry_is_read_only_without_python_or_credentials() {
    let f = Fixture::new();
    let attempt = f.0.join("attempt");
    fs::create_dir(&attempt).unwrap();
    let receipt = json!({"schema":"cc.generation-result.v1","status":"needs_evidence",
        "reason":"Synthetic machine evidence does not support a document edge.","published":false});
    let path = attempt.join("result.json");
    fs::write(&path, receipt.to_string()).unwrap();
    fs::write(attempt.join("bindings.json"), b"frozen bindings").unwrap();
    fs::write(attempt.join("image.png"), b"frozen private image").unwrap();
    let before = fs::read(&path).unwrap();
    let run = || {
        cli()
            .args(["generate", "--registry"])
            .arg(f.0.join("missing-registry"))
            .arg("--brief")
            .arg(f.0.join("missing-brief"))
            .arg("--sources")
            .arg(f.0.join("missing-sources"))
            .arg("--output")
            .arg(&attempt)
            .arg("--python")
            .arg(f.0.join("must-not-execute"))
            .output()
            .unwrap()
    };
    for _ in 0..2 {
        let output = run();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            receipt
        );
    }
    assert_eq!(fs::read(path).unwrap(), before);
    assert_eq!(
        fs::read(attempt.join("bindings.json")).unwrap(),
        b"frozen bindings"
    );
    assert_eq!(
        fs::read(attempt.join("image.png")).unwrap(),
        b"frozen private image"
    );
    assert!(!attempt.join("proposal.json").exists());
    assert!(!f.0.join("missing-registry").exists());
}

#[test]
fn blocked_dry_run_prints_hashes_and_no_media_without_database_access() {
    let f = Fixture::new();
    // Invalid source support is intentional: a blocked report must still expose
    // the proposed set, never stage a partially valid candidate.
    let proposal = json!({"entries":[{"title":"Synthetic unresolved machine","year":2001}],"edges":[],"images":[]});
    let path = f.0.join("proposal.json");
    fs::write(&path, proposal.to_string()).unwrap();
    let brief = f.0.join("brief.json");
    fs::write(&brief, "{\"images_required\":false}").unwrap();
    let receipt = f.0.join("result.json");
    fs::write(&receipt,json!({"schema":"cc.generation-result.v1","status":"needs_evidence","reason":"Synthetic missing evidence","published":false}).to_string()).unwrap();
    let before = fs::read(&path).unwrap();
    let output = cli()
        .arg("dry-run")
        .arg("--path")
        .arg(&path)
        .arg("--brief")
        .arg(&brief)
        .arg("--attempt")
        .arg(&receipt)
        .arg("--exclude-media")
        .env("DATABASE_URL", "must-not-connect")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["blockers"][0]["code"], "needs_evidence");
    assert_eq!(report["media"], json!({"kind":"none","records":[]}));
    assert_eq!(
        report["entities"][0]["body_hash"].as_str().unwrap().len(),
        64
    );
    assert_eq!(report["writes_performed"], false);
    assert_eq!(fs::read(path).unwrap(), before);
}
