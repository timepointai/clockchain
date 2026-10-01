//! Signing seed files. A seed is 32 bytes from the operating-system RNG,
//! stored as 64 lowercase hex characters and a newline, readable and writable
//! by its owner only. A seed is never taken from argv and never printed.
use anyhow::{anyhow, bail, ensure, Context, Result};
use cc_core::SecretKey;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// The mode `keygen` creates and the widest mode a key file may have.
pub const KEY_FILE_MODE: u32 = 0o600;
/// Bits that must be clear on a key file: setuid, setgid, sticky, owner
/// execute and every group and other bit.
const WIDER_THAN_0600: u32 = 0o7177;

/// `N` bytes from the operating-system RNG.
pub fn os_random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|e| anyhow!("operating-system RNG failed: {e}"))?;
    Ok(out)
}

/// Write a fresh random seed to `out` and return its Ed25519 public key.
///
/// The seed goes to a mode-0600 temporary file in the same directory, which
/// is synced and then hard-linked to `out`. `link(2)` fails when `out` exists
/// (a dangling symlink included), so an existing file is never replaced and
/// `out` never appears partially written.
pub fn keygen(out: &Path) -> Result<[u8; 32]> {
    let seed: [u8; 32] = os_random()?;
    let public = SecretKey::from_seed(seed).author().to_bytes();
    create_private(out, format!("{}\n", hex::encode(seed)).as_bytes())?;
    // Read back through the same path `genesis` uses.
    ensure!(
        load_key(out)?.author().to_bytes() == public,
        "key file {} did not read back",
        out.display()
    );
    Ok(public)
}

fn create_private(out: &Path, bytes: &[u8]) -> Result<()> {
    if fs::symlink_metadata(out).is_ok() {
        bail!("refusing to overwrite existing {}", out.display());
    }
    let name = out
        .file_name()
        .with_context(|| format!("{} does not name a file", out.display()))?;
    let dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let suffix: [u8; 8] = os_random()?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        hex::encode(suffix)
    ));
    let written = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(KEY_FILE_MODE)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        // The umask can only narrow the creation mode; fix it to exactly 0600.
        f.set_permissions(Permissions::from_mode(KEY_FILE_MODE))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        match fs::hard_link(&tmp, out) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                bail!("refusing to overwrite existing {}", out.display())
            }
            Err(e) => Err(e).with_context(|| format!("link {}", out.display())),
        }
    })();
    let _ = fs::remove_file(&tmp);
    written?;
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Read a seed file: exactly 64 hex characters and an optional final newline.
/// A file whose mode is wider than 0600 is refused before it is read.
pub fn load_key(path: &Path) -> Result<SecretKey> {
    // Refuse a FIFO or device before opening it, and open without blocking
    // in case one is swapped in meanwhile; the handle is checked again below.
    let named = fs::metadata(path).with_context(|| format!("open key file {}", path.display()))?;
    ensure!(
        named.is_file(),
        "key file {} is not a regular file",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open key file {}", path.display()))?;
    // Checked on the opened handle, so the file read is the file checked.
    let meta = f.metadata()?;
    ensure!(
        meta.is_file(),
        "key file {} is not a regular file",
        path.display()
    );
    let mode = meta.permissions().mode() & 0o7777;
    ensure!(
        mode & WIDER_THAN_0600 == 0,
        "refusing to read key file {}: mode {mode:04o} is wider than 0600 (chmod 600 it first)",
        path.display()
    );
    let mut raw = Vec::new();
    f.take(80).read_to_end(&mut raw)?;
    let text = raw.strip_suffix(b"\n").unwrap_or(&raw);
    // No decoder error is echoed: it would quote part of the seed.
    let seed: Option<[u8; 32]> = (text.len() == 64)
        .then(|| hex::decode(text).ok()?.try_into().ok())
        .flatten();
    let seed = seed.with_context(|| {
        format!(
            "key file {} must hold exactly 64 hex characters and an optional newline",
            path.display()
        )
    })?;
    Ok(SecretKey::from_seed(seed))
}
