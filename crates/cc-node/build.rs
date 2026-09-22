//! Bake the build revision into the binary.
//!
//! `/health` publishes `build` because the deploy-truth check reads it: v1 used
//! an OpenAPI listing as its deploy signal and that listing lied once during an
//! incident, so the field a verifier compares has to be one the new code
//! actually changes. A revision resolved at *runtime* would not be that field —
//! it would describe the machine, not the artifact.
//!
//! Deliberately infallible. A build that cannot reach git (a Docker layer with
//! no `.git`, a vendored source tree) must still build; it publishes the honest
//! string `unknown` rather than failing or, worse, inventing a plausible sha.

use std::process::Command;

fn main() {
    // An explicit `CC_BUILD_REV` wins: the container build knows its revision
    // when the source tree no longer does.
    let rev = std::env::var("CC_BUILD_REV")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(git_describe)
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=CC_BUILD_REV={rev}");
    println!("cargo:rerun-if-env-changed=CC_BUILD_REV");
    // Re-run when HEAD moves, so a rebuild after a commit republishes the new
    // revision instead of serving a cached one that names the wrong code.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
}

/// `<short sha>` or `<short sha>-dirty`. `None` on any failure whatsoever.
fn git_describe() -> Option<String> {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let sha = String::from_utf8(sha.stdout).ok()?.trim().to_string();
    if sha.is_empty() {
        return None;
    }
    // A dirty tree is named as such: "the running code equals commit X" is a
    // claim, and it is false for an uncommitted build.
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false);
    Some(if dirty { format!("{sha}-dirty") } else { sha })
}
