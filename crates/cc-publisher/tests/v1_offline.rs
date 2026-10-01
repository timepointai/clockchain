//! Offline integration tests for `cc-publisher v1`: the signed Genesis vector,
//! the binary's key-file and output-directory handling, and the refusals the
//! offline path makes before anything is written.
//!
//! Synthetic data only: Ed25519 seed `0x01 * 32` (`cc_testkit::v1::key(0)`),
//! instance `0x09 * 32`, kind `scientific-discovery`, namespace
//! `synthetic.publisher`. `vectors/v1-genesis.txt` was derived outside Rust
//! (Python stdlib framing and SHA-256, Ed25519 from the `cryptography`
//! package), so its pinned values check this crate rather than restate it.
//! Only the admission check in the first test uses PostgreSQL
//! (`TEST_DATABASE_URL`, read by `cc_testkit`).
use cc_core::v1::{AssertedTime, Hash};
use cc_core::{B256Constants, SecretKey, Tick};
use cc_filter::v1::FilterIdentity;
use cc_ledger::v1::{classify, ProjectionState, State, Store};
use cc_publisher::v1::genesis::{
    self, Genesis, GenesisInput, BODY_FILE, ENVELOPE_FILE, MAX_BODY, MAX_KEY_FIELD, PREVIEW_FILE,
};
use cc_publisher::v1::{key, time};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions, Permissions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ---------------------------------------------------------------------------
// The synthetic vector
// ---------------------------------------------------------------------------

/// The `cc_testkit::v1::key(0)` seed.
const SEED: [u8; 32] = [1; 32];
/// Ed25519 public key of `SEED`, pinned independently in
/// `crates/cc-core/tests/vectors/v1_reference.py`.
const AUTHOR: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const INSTANCE: Hash = [9; 32];
const KIND: &str = "scientific-discovery";
const NAMESPACE: &str = "synthetic.publisher";
const VALUE: &str = "vector-1";
const ASSERTED: &str = "1901-02-03";
const NONCE: Hash = [0x5a; 32];
/// Deliberately unsorted: the envelope must carry them sorted.
const EVIDENCE: [Hash; 2] = [[0xbb; 32], [0xaa; 32]];
const BODY: &[u8] = b"Synthetic v1 Genesis body for publisher vector-1.\n";

/// `(date(1901, 2, 3) - date(1970, 1, 1)).days` in Python.
const DAYS_1901_02_03: i64 = -25_169;
/// Unix seconds of J2000.0, 2000-01-01T12:00:00 UTC: 10957 days and 12 hours.
const UNIX_J2000: i64 = 10_957 * 86_400 + 43_200;

// Pinned by vectors/v1-genesis.txt. Ed25519 is deterministic.
const BODY_SHA256: &str = "682da54d778dcf6b6c1c2ef94ff9b9a329d0cd6b68fc974ae769080a9d4ff8ed";
const COORDINATE: &str = "7fffffffffffffffffffffffffffffffffffffff45f44a400000000000000000";
const EVENT: &str = "be60959d658040b537c3d2f09de8650e49274beca5334d088918f6d931f2920d";
const REVISION: &str = "9575cfaf9be5a13b9520e8dab28269e29279444bcb5285ef44a4f5e83f2935cc";
const ROOT_GRANT: &str = "1e92eb04fba1ed476c21b6d961f968915e07fbd9953ecbde025075d2244c560e";
const ENVELOPE_SHA256: &str = "f5df8c79bb281c12f7d1091f57c6eb2af7c5719d0ead6fccd8036089e46254e2";
const ENVELOPE_BYTES: usize = 387;
/// The vendored taxonomy: `sha256sum vendor/tt/taxonomy-v2.1.json`.
const TT_VERSION: &str = "tt-ontology/1.0 v2.1.0";
const TT_SHA256: &str = "31ed385e26522a5b548f7404f7757ee370ed9783dbd550b05cd69e89e9462113";

fn vector_input() -> GenesisInput {
    GenesisInput {
        instance: INSTANCE,
        kind: KIND.into(),
        namespace: NAMESPACE.into(),
        value: VALUE.into(),
        body: BODY.to_vec(),
        asserted_time: AssertedTime {
            coordinate: midnight(DAYS_1901_02_03),
            precision: "day".into(),
        },
        evidence: EVIDENCE.to_vec(),
        nonce: NONCE,
    }
}

fn build(input: GenesisInput) -> anyhow::Result<Genesis> {
    genesis::build(&SecretKey::from_seed(SEED), input)
}

fn vector_genesis() -> Genesis {
    build(vector_input()).expect("the synthetic vector builds")
}

/// The vector's v1 preimage, framed field by field as `v1_reference.py` does,
/// without cc-core's writer.
fn manual_preimage() -> Vec<u8> {
    let mut p = frame("cc.event.v1");
    p.extend_from_slice(&1u16.to_be_bytes()); // canon version
    p.extend_from_slice(&0u16.to_be_bytes()); // constants version
    p.extend_from_slice(&INSTANCE);
    p.extend_from_slice(&1u16.to_be_bytes()); // kind: Genesis
    p.extend_from_slice(&unhex(AUTHOR));
    p.push(0); // subject: None
    p.push(1); // subject_key: Some
    for field in [KIND, NAMESPACE, VALUE] {
        p.extend(frame(field));
    }
    p.push(0); // grant: None
    p.extend_from_slice(&0u32.to_be_bytes()); // parents: the empty set
    p.push(1); // asserted_time: Some
    p.extend_from_slice(&midnight(DAYS_1901_02_03));
    p.extend(frame("day"));
    p.extend_from_slice(&NONCE); // payload: nonce, body hash, sorted evidence
    p.extend_from_slice(&sha256(BODY));
    p.extend_from_slice(&2u32.to_be_bytes());
    p.extend_from_slice(&[0xaa; 32]);
    p.extend_from_slice(&[0xbb; 32]);
    p
}

/// `vectors/v1-genesis.txt` as `name -> hex`.
fn vector_file() -> BTreeMap<&'static str, &'static str> {
    include_str!("vectors/v1-genesis.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_once(' ').expect("a `name hex` line"))
        .collect()
}

// ---------------------------------------------------------------------------
// Independent encodings and calendar arithmetic
// ---------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

fn unhex(s: &str) -> Hash {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// `frame` in `v1_reference.py`: u32 big-endian byte length, then the bytes.
fn frame(s: &str) -> Vec<u8> {
    let mut out = u32::try_from(s.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(s.as_bytes());
    out
}

/// A whole-second coordinate written out by hand rather than via `Tick`:
/// `seconds << 64` as 256-bit two's complement, big-endian, sign bit flipped.
fn canon_seconds(seconds: i64) -> Hash {
    let mut out = [if seconds < 0 { 0xff } else { 0x00 }; 32];
    out[0] ^= 0x80;
    out[16..24].copy_from_slice(&seconds.to_be_bytes());
    out[24..].fill(0);
    out
}

/// Inverse of [`canon_seconds`]; fails on any other coordinate.
#[track_caller]
fn seconds_of(coordinate: &Hash) -> i64 {
    let seconds = i64::from_be_bytes(coordinate[16..24].try_into().unwrap());
    assert_eq!(
        hex::encode(coordinate),
        hex::encode(canon_seconds(seconds)),
        "not a whole-second coordinate"
    );
    seconds
}

/// The coordinate of 00:00 UTC, `days` days after 1970-01-01.
fn midnight(days: i64) -> Hash {
    canon_seconds(days * 86_400 - UNIX_J2000)
}

fn leap(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

fn month_days(year: i64, month: usize) -> i64 {
    let february = if leap(year) { 29 } else { 28 };
    [31, february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
}

fn year_text(year: i64) -> String {
    if year < 0 {
        format!("-{:04}", -year)
    } else {
        format!("{year:04}")
    }
}

// ---------------------------------------------------------------------------
// Files and the binary
// ---------------------------------------------------------------------------

/// Create `path` holding `bytes`, then give it exactly `mode`.
fn write_file(path: &Path, bytes: &[u8], mode: u32) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    drop(f);
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    assert_eq!(
        mode_of(path),
        mode,
        "chmod {mode:04o} did not apply to {}",
        path.display()
    );
}

/// Read, edit and rewrite an existing file in place.
fn edit_file(path: &Path, edit: impl FnOnce(&mut Vec<u8>)) {
    let mut bytes = fs::read(path).unwrap();
    edit(&mut bytes);
    fs::write(path, bytes).unwrap();
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn names(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect()
}

fn set_of(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| n.to_string()).collect()
}

/// Every file directly in `dir`, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    names(dir)
        .into_iter()
        .map(|n| {
            let bytes = fs::read(dir.join(&n)).unwrap();
            (n, bytes)
        })
        .collect()
}

#[track_caller]
fn assert_absent(path: &Path) {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        other => panic!("{} exists after a refusal: {other:?}", path.display()),
    }
}

/// The `{:#}` chain of the error the call must return.
#[track_caller]
fn error_text<T>(result: anyhow::Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => format!("{e:#}"),
    }
}

/// No run of 12 characters of `content` (whitespace removed) is in `text`.
#[track_caller]
fn assert_no_echo(text: &str, content: &str) {
    let compact: Vec<u8> = content
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    for run in compact.windows(12) {
        let run = std::str::from_utf8(run).unwrap();
        assert!(
            !text.contains(run),
            "error text echoes key-file content {run:?}: {text}"
        );
    }
}

fn utf8(path: &Path) -> &str {
    path.to_str().expect("temporary paths are UTF-8")
}

/// Run the real binary with no node token in its environment.
fn publisher<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_cc-publisher"))
        .args(args)
        .env_remove(cc_publisher::v1::cli::WRITE_TOKEN_ENV)
        .env_remove(cc_publisher::v1::cli::READ_TOKEN_ENV)
        .output()
        .expect("run cc-publisher")
}

/// Run the real binary under umask 000, so the only mode restrictions left on
/// what it creates are the ones it sets itself.
fn publisher_umask_000<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new("sh")
        .arg("-c")
        .arg(r#"umask 000; exec "$0" "$@""#)
        .arg(env!("CARGO_BIN_EXE_cc-publisher"))
        .args(args)
        .env_remove(cc_publisher::v1::cli::WRITE_TOKEN_ENV)
        .env_remove(cc_publisher::v1::cli::READ_TOKEN_ENV)
        .output()
        .expect("run cc-publisher under umask 000")
}

#[track_caller]
fn succeeded(out: &Output) -> String {
    assert!(
        out.status.success(),
        "cc-publisher failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone()).expect("UTF-8 stdout")
}

/// A refusal: exit status 1 (clap's usage errors exit 2), one
/// `cc-publisher v1:` error containing `needle`, and nothing on stdout.
#[track_caller]
fn refused(out: &Output, needle: &str) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected a refusal, got {}; stderr: {stderr}",
        out.status
    );
    assert!(
        stderr.starts_with("cc-publisher v1: "),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stderr.contains(needle),
        "stderr {stderr:?} does not contain {needle:?}"
    );
    assert!(
        out.stdout.is_empty(),
        "a refusal printed to stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    stderr
}

type Flags = Vec<(&'static str, OsString)>;

/// `v1 genesis` flags that sign the vector into `out`.
fn vector_flags(key: &Path, body: &Path, out: &Path) -> Flags {
    vec![
        ("--key", key.into()),
        ("--instance", hex::encode(INSTANCE).into()),
        ("--kind", KIND.into()),
        ("--namespace", NAMESPACE.into()),
        ("--value", VALUE.into()),
        ("--body", body.into()),
        ("--asserted-time", ASSERTED.into()),
        ("--evidence", hex::encode(EVIDENCE[0]).into()),
        ("--evidence", hex::encode(EVIDENCE[1]).into()),
        ("--nonce", hex::encode(NONCE).into()),
        ("--out", out.into()),
    ]
}

/// Replace the value of every occurrence of `flag`.
#[track_caller]
fn with(mut flags: Flags, flag: &str, value: &str) -> Flags {
    let mut found = false;
    for (f, v) in &mut flags {
        if *f == flag {
            *v = value.into();
            found = true;
        }
    }
    assert!(found, "no {flag} flag");
    flags
}

fn run_genesis(flags: Flags) -> Output {
    let mut args: Vec<OsString> = vec!["v1".into(), "genesis".into()];
    for (flag, value) in flags {
        args.push(flag.into());
        args.push(value);
    }
    publisher_umask_000(args)
}

/// A temporary directory holding the vector's seed file (mode 0600) and body.
struct Fixture {
    tmp: tempfile::TempDir,
    key: PathBuf,
    body: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("seed.hex");
        write_file(&key, format!("{}\n", hex::encode(SEED)).as_bytes(), 0o600);
        let body = tmp.path().join("body.txt");
        write_file(&body, BODY, 0o600);
        Self { tmp, key, body }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    fn flags(&self, out: &Path) -> Flags {
        vector_flags(&self.key, &self.body, out)
    }
}

/// Run `f` on another thread; fail if it has not returned within `seconds`.
#[track_caller]
fn within_seconds<T: Send + 'static>(seconds: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_secs(seconds))
        .expect("call did not return in time")
}

/// Write the vector into `root/case`, apply `tamper`, and return the error
/// `load_dir` must then report. The reload must not change the directory.
#[track_caller]
fn load_error(root: &Path, case: &str, tamper: impl FnOnce(&Path)) -> String {
    let dir = root.join(case);
    vector_genesis().write_dir(&dir).unwrap();
    Genesis::load_dir(&dir).expect("the untampered directory loads");
    tamper(&dir);
    let before = snapshot(&dir);
    let err = error_text(Genesis::load_dir(&dir));
    assert_eq!(snapshot(&dir), before, "load_dir changed {}", dir.display());
    err
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn genesis_vector_is_deterministic_and_independently_framed() {
    let g = vector_genesis();
    let bytes = g.signed.bytes();
    let preimage = manual_preimage();

    // (a) cc-core's encoding is the hand-framed v1 layout, signed by SEED.
    assert_eq!(
        hex::encode(&bytes[..bytes.len() - 64]),
        hex::encode(&preimage)
    );
    assert_eq!(bytes.len(), preimage.len() + 64);
    let signer = SecretKey::from_seed(SEED);
    assert_eq!(hex::encode(signer.author().to_bytes()), AUTHOR);
    assert_eq!(
        bytes[preimage.len()..],
        signer.sign_message(&preimage).to_bytes()
    );
    assert_eq!(
        build(vector_input()).unwrap().signed.bytes(),
        bytes,
        "signing the same input twice must give the same bytes"
    );

    // (b) Identities, hashed here from the hand-framed bytes.
    let id = sha256(&preimage);
    assert_eq!(g.id(), id);
    assert_eq!(g.subject(), id, "a Genesis is its own subject");
    let revision = sha256(&[&14u32.to_be_bytes()[..], b"cc.revision.v1", &id, &id].concat());
    assert_eq!(g.revision(), revision);
    let root_grant = sha256(&[&16u32.to_be_bytes()[..], b"cc.root-grant.v1", &id].concat());

    // (c) The values pinned outside Rust.
    assert_eq!(hex::encode(id), EVENT);
    assert_eq!(hex::encode(revision), REVISION);
    assert_eq!(hex::encode(root_grant), ROOT_GRANT);
    assert_eq!(hex::encode(sha256(bytes)), ENVELOPE_SHA256);
    assert_eq!(bytes.len(), ENVELOPE_BYTES);
    assert_eq!(hex::encode(sha256(BODY)), BODY_SHA256);
    assert_eq!(hex::encode(midnight(DAYS_1901_02_03)), COORDINATE);
    let file = vector_file();
    assert_eq!(file["envelope"], hex::encode(bytes));
    let body_hex = hex::encode(BODY);
    for (name, pinned) in [
        ("body", body_hex.as_str()),
        ("body_sha256", BODY_SHA256),
        ("coordinate", COORDINATE),
        ("event", EVENT),
        ("revision", REVISION),
        ("root_grant", ROOT_GRANT),
        ("envelope_sha256", ENVELOPE_SHA256),
    ] {
        assert_eq!(file[name], pinned, "vectors/v1-genesis.txt {name}");
    }
    assert_eq!(
        file.len(),
        8,
        "unexpected entries in vectors/v1-genesis.txt"
    );

    // (d) preview.json, every field.
    assert_eq!(
        g.preview().unwrap(),
        json!({
            "schema": "cc.publisher.v1.preview",
            "event_kind": "genesis",
            "encoding": "cc.event.v1",
            "canon_version": 1,
            "constants_version": 0,
            "instance": "09".repeat(32),
            "event": EVENT,
            "subject": EVENT,
            "revision": REVISION,
            "root_grant": ROOT_GRANT,
            "author": AUTHOR,
            "nonce": "5a".repeat(32),
            "subject_key": {"kind": KIND, "namespace": NAMESPACE, "value": VALUE},
            "asserted_time": {
                "calendar": ASSERTED,
                "precision": "day",
                "coordinate": COORDINATE,
            },
            "body_sha256": BODY_SHA256,
            "body_bytes": 50,
            "evidence": ["aa".repeat(32), "bb".repeat(32)],
            "envelope_sha256": ENVELOPE_SHA256,
            "envelope_bytes": ENVELOPE_BYTES,
            "taxonomy": {"version": TT_VERSION, "sha256": TT_SHA256},
        })
    );

    // (e) The ledger's branch-local classification alone.
    let statuses = classify(&BTreeMap::from([(id, g.signed.clone())]));
    assert_eq!(statuses.len(), 1);
    assert_eq!(
        statuses[&id].state,
        State::Valid,
        "{}",
        statuses[&id].reason
    );
    assert!(statuses[&id].missing.is_empty());

    // (f) A fresh real store, bound to a governed filter identity, admits it
    // as Valid and serves its revision. Read through `snapshot`, the serving
    // path, not the review-only accessors.
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let filter = FilterIdentity::governed(vec![unhex(AUTHOR)], 4).unwrap();
    let store = Store::provision(pool, INSTANCE)
        .await
        .unwrap()
        .bind(filter)
        .await
        .unwrap();
    let outcome = store.admit(bytes).await.unwrap();
    assert_eq!(
        outcome.status.state,
        State::Valid,
        "{}",
        outcome.status.reason
    );
    assert_eq!(outcome.event, Some(id));
    assert_eq!(hex::encode(outcome.input_digest), ENVELOPE_SHA256);
    let view = store.snapshot(None).await.unwrap();
    let asserted = Some(AssertedTime {
        coordinate: unhex(COORDINATE),
        precision: "day".into(),
    });
    let [r] = view.projection.revisions.as_slice() else {
        panic!("expected one revision: {:?}", view.projection.revisions);
    };
    assert_eq!(hex::encode(r.id), REVISION);
    assert_eq!((r.subject, r.creating_event), (id, id));
    assert_eq!(hex::encode(r.body), BODY_SHA256);
    assert_eq!(r.asserted_time, asserted);
    let [row] = view.projection.rows.as_slice() else {
        panic!("expected one row: {:?}", view.projection.rows);
    };
    assert_eq!(row.event, id);
    assert_eq!(row.state, ProjectionState::Head, "{}", row.reason);
    assert_eq!(row.revision, Some(unhex(REVISION)));
    assert!(row.frontier);
    let entity = view.entity(id, None);
    assert_eq!(entity.state, "resolved");
    assert_eq!(entity.visibility, "visible");
    assert_eq!(entity.frontier, BTreeSet::from([id]));
    let served = entity.revision.expect("the current revision is served");
    assert_eq!(hex::encode(served.id), REVISION);
    assert_eq!(hex::encode(served.body), BODY_SHA256);
    assert_eq!(served.asserted_time, asserted);
    // `as_of` compares against the signed coordinate: visible from that
    // instant, hidden a day earlier.
    let at = view.entity(id, Some(unhex(COORDINATE)));
    assert_eq!(at.visibility, "visible");
    let day_before = canon_seconds(seconds_of(&unhex(COORDINATE)) - 86_400);
    let before = view.entity(id, Some(day_before));
    assert_eq!(before.visibility, "after_as_of");
    assert_eq!(before.revision, None);
    cleanup.cleanup().await;
}

#[test]
fn cli_genesis_matches_library_bytes() {
    let fx = Fixture::new();
    let cli_dir = fx.path("cli");
    let stdout = succeeded(&run_genesis(fx.flags(&cli_dir)));
    assert!(
        stdout.contains(EVENT),
        "stdout lacks the event id: {stdout}"
    );
    assert!(
        stdout.contains(REVISION),
        "stdout lacks the revision: {stdout}"
    );
    assert!(stdout.contains("nothing was submitted"), "{stdout}");
    assert_no_echo(&stdout, &hex::encode(SEED));

    let lib_dir = fx.path("lib");
    let library = vector_genesis();
    library.write_dir(&lib_dir).unwrap();
    let outputs = [ENVELOPE_FILE, BODY_FILE, PREVIEW_FILE];
    assert_eq!(names(&cli_dir), set_of(&outputs));
    for name in outputs {
        assert_eq!(
            fs::read(cli_dir.join(name)).unwrap(),
            fs::read(lib_dir.join(name)).unwrap(),
            "{name} differs between the binary and the library"
        );
    }
    assert_eq!(
        hex::encode(fs::read(cli_dir.join(ENVELOPE_FILE)).unwrap()),
        vector_file()["envelope"]
    );
    assert_eq!(fs::read(cli_dir.join(BODY_FILE)).unwrap(), BODY);
    let preview = fs::read_to_string(cli_dir.join(PREVIEW_FILE)).unwrap();
    assert!(preview.ends_with("}\n"), "{preview}");
    let preview: Value = serde_json::from_str(&preview).unwrap();
    assert_eq!(preview["event"], EVENT);
    assert_eq!(preview["envelope_sha256"], ENVELOPE_SHA256);
    assert_eq!(preview["asserted_time"]["calendar"], ASSERTED);
    // Written under umask 000: these are exactly the modes genesis sets.
    assert_eq!(mode_of(&cli_dir), 0o700);
    for path in [
        cli_dir.join(ENVELOPE_FILE),
        cli_dir.join(BODY_FILE),
        cli_dir.join(PREVIEW_FILE),
    ] {
        assert_eq!(mode_of(&path), 0o600, "{}", path.display());
    }

    let loaded = Genesis::load_dir(&cli_dir).unwrap();
    assert_eq!(hex::encode(loaded.id()), EVENT);
    assert_eq!(loaded.signed.bytes(), library.signed.bytes());
    assert_eq!(loaded.body, BODY);
    assert_eq!(
        names(fx.tmp.path()),
        set_of(&["body.txt", "cli", "lib", "seed.hex"])
    );
}

#[test]
fn kind_outside_pinned_taxonomy_is_refused() {
    for kind in [
        "not-a-tt-kind",
        "Scientific-Discovery",
        "",
        " scientific-discovery",
        "scientific_discovery",
    ] {
        let err = error_text(genesis::validate_kind(kind));
        let needle =
            format!("kind {kind:?} is not a node id in the pinned TT taxonomy ({TT_VERSION})");
        assert!(err.contains(&needle), "{err}");
    }
    let err = error_text(genesis::validate_kind("everyday-movement-and-commute"));
    assert!(
        err.contains(
            "kind \"everyday-movement-and-commute\" is retired in the pinned TT taxonomy; \
             its successor is \"journey-and-travel\""
        ),
        "{err}"
    );
    genesis::validate_kind(KIND).unwrap();
    genesis::validate_kind("journey-and-travel").unwrap();

    // `build` applies the same rule.
    let mut input = vector_input();
    input.kind = "everyday-movement-and-commute".into();
    let err = error_text(build(input));
    assert!(
        err.contains("its successor is \"journey-and-travel\""),
        "{err}"
    );

    // So does the binary, before anything is written.
    let fx = Fixture::new();
    for (i, (kind, needle)) in [
        (
            "not-a-tt-kind",
            "kind \"not-a-tt-kind\" is not a node id in the pinned TT taxonomy",
        ),
        (
            "Scientific-Discovery",
            "kind \"Scientific-Discovery\" is not a node id",
        ),
        (
            "everyday-movement-and-commute",
            "its successor is \"journey-and-travel\"",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let out = fx.path(&format!("out-{i}"));
        let stderr = refused(&run_genesis(with(fx.flags(&out), "--kind", kind)), needle);
        assert!(stderr.contains("pinned TT taxonomy"), "{stderr}");
        assert_absent(&out);
    }
    assert_eq!(names(fx.tmp.path()), set_of(&["body.txt", "seed.hex"]));
}

#[test]
fn keygen_creates_0600_once_and_never_overwrites() {
    let tmp = tempfile::tempdir().unwrap();
    let k = tmp.path().join("k");
    // Under umask 000, so 0600 is the mode keygen sets, not the ambient umask.
    let stdout = succeeded(&publisher_umask_000(["v1", "keygen", "--out", utf8(&k)]));

    let text = fs::read(&k).unwrap();
    assert_eq!(text.len(), 65, "64 hex digits and a newline");
    assert_eq!(text[64], b'\n');
    assert!(
        text[..64]
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "the seed is not 64 lowercase hex digits"
    );
    assert!(fs::symlink_metadata(&k).unwrap().file_type().is_file());
    assert_eq!(mode_of(&k), 0o600);
    let seed: [u8; 32] = hex::decode(&text[..64]).unwrap().try_into().unwrap();
    let public = hex::encode(SecretKey::from_seed(seed).author().to_bytes());
    assert_eq!(stdout, format!("{public}\n"));
    assert_no_echo(&stdout, &hex::encode(seed));
    assert_eq!(
        succeeded(&publisher(["v1", "pubkey", "--key", utf8(&k)])),
        stdout
    );

    // A second keygen to the same path is refused and changes nothing.
    refused(
        &publisher(["v1", "keygen", "--out", utf8(&k)]),
        &format!("refusing to overwrite existing {}", k.display()),
    );
    assert_eq!(fs::read(&k).unwrap(), text);
    assert_eq!(mode_of(&k), 0o600);

    // So is an unrelated existing file.
    let unrelated = tmp.path().join("unrelated");
    write_file(&unrelated, b"keep\n", 0o644);
    refused(
        &publisher(["v1", "keygen", "--out", utf8(&unrelated)]),
        "refusing to overwrite existing",
    );
    assert_eq!(fs::read(&unrelated).unwrap(), b"keep\n");
    assert_eq!(mode_of(&unrelated), 0o644);

    // And a dangling symlink, whose target must not be created through it.
    let dangling = tmp.path().join("dangling");
    let target = tmp.path().join("target");
    symlink(&target, &dangling).unwrap();
    refused(
        &publisher(["v1", "keygen", "--out", utf8(&dangling)]),
        "refusing to overwrite existing",
    );
    assert_absent(&target);
    assert!(fs::symlink_metadata(&dangling)
        .unwrap()
        .file_type()
        .is_symlink());

    // No temporary file is left behind by any of these.
    assert_eq!(names(tmp.path()), set_of(&["dangling", "k", "unrelated"]));

    // The library refuses the same way.
    let lib = tmp.path().join("lib-key");
    let first = key::keygen(&lib).unwrap();
    assert_eq!(key::load_key(&lib).unwrap().author().to_bytes(), first);
    assert_ne!(hex::encode(first), public, "two keygens gave one key");
    let written = fs::read(&lib).unwrap();
    let err = error_text(key::keygen(&lib));
    assert!(err.contains("refusing to overwrite existing"), "{err}");
    assert_eq!(fs::read(&lib).unwrap(), written);
    assert_eq!(mode_of(&lib), 0o600);
    assert_eq!(
        names(tmp.path()),
        set_of(&["dangling", "k", "lib-key", "unrelated"])
    );
}

#[test]
fn key_file_wider_than_0600_is_refused() {
    let fx = Fixture::new();
    let seed_file = format!("{}\n", hex::encode(SEED));
    let mut wide = vec![0o640, 0o604, 0o644, 0o660, 0o700, 0o610, 0o601];
    // Linux lets an owner set setuid, setgid and sticky on a regular file;
    // other systems may refuse (EFTYPE) or silently clear these bits.
    if cfg!(target_os = "linux") {
        wide.extend([0o4600, 0o2600, 0o1600]);
    }
    for mode in wide {
        let path = fx.path(&format!("key-{mode:04o}"));
        write_file(&path, seed_file.as_bytes(), mode);
        let needle = format!("mode {mode:04o} is wider than 0600");
        let err = error_text(key::load_key(&path));
        assert!(err.contains(&needle), "{err}");
        assert_no_echo(&err, &seed_file);
        let stderr = refused(&publisher(["v1", "pubkey", "--key", utf8(&path)]), &needle);
        assert_no_echo(&stderr, &seed_file);
    }
    for mode in [0o600, 0o400] {
        let path = fx.path(&format!("key-{mode:04o}"));
        write_file(&path, seed_file.as_bytes(), mode);
        let public = key::load_key(&path).unwrap().author().to_bytes();
        assert_eq!(hex::encode(public), AUTHOR);
        assert_eq!(
            succeeded(&publisher(["v1", "pubkey", "--key", utf8(&path)])),
            format!("{AUTHOR}\n")
        );
    }

    // `genesis` refuses a 0644 key before its output directory exists.
    let out = fx.path("out");
    let wide = fx.path("key-0644");
    refused(
        &run_genesis(with(fx.flags(&out), "--key", utf8(&wide))),
        "mode 0644 is wider than 0600",
    );
    assert_absent(&out);

    // Only a regular file that exists is a key file.
    let dir = fx.path("key-dir");
    fs::create_dir(&dir).unwrap();
    let err = error_text(key::load_key(&dir));
    assert!(err.contains("is not a regular file"), "{err}");
    let err = error_text(key::load_key(&fx.path("key-absent")));
    assert!(err.contains("open key file"), "{err}");

    // A FIFO as key or body is refused before it is opened: opening one
    // blocks until a writer appears, so a regression times out here.
    let fifo = fx.path("fifo");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let key_err = within_seconds(10, {
        let fifo = fifo.clone();
        move || error_text(key::load_key(&fifo))
    });
    assert!(key_err.contains("is not a regular file"), "{key_err}");
    let body_err = within_seconds(10, {
        let args = cc_publisher::v1::cli::GenesisArgs {
            key: fx.key.clone(),
            instance: hex::encode(INSTANCE),
            kind: KIND.into(),
            namespace: NAMESPACE.into(),
            value: VALUE.into(),
            body: fifo.clone(),
            asserted_time: ASSERTED.into(),
            evidence: vec![],
            nonce: None,
            out: fx.path("fifo-out"),
        };
        move || error_text(args.input())
    });
    assert!(body_err.contains("is not a regular file"), "{body_err}");

    // Contents: exactly 64 hex digits and at most one "\n", never echoed.
    let pattern_seed: [u8; 32] = std::array::from_fn(|i| 0x10 + i as u8);
    let pattern = hex::encode(pattern_seed);
    let malformed = [
        format!("{}\n", &pattern[..63]),
        format!("{pattern}0\n"),
        format!(" {pattern}\n"),
        format!("{pattern} \n"),
        format!("{} {}\n", &pattern[..31], &pattern[32..]),
        format!("{pattern}\r\n"),
        format!("{pattern}\n\n"),
        format!("0x{}\n", &pattern[2..]),
        format!("{}g\n", &pattern[..63]),
        format!("{pattern}{pattern}\n"),
        "\n".to_string(),
        String::new(),
    ];
    let needle = "must hold exactly 64 hex characters and an optional newline";
    for (i, content) in malformed.iter().enumerate() {
        let path = fx.path(&format!("malformed-{i}"));
        write_file(&path, content.as_bytes(), 0o600);
        let err = error_text(key::load_key(&path));
        assert!(err.contains(needle), "{content:?}: {err}");
        assert_no_echo(&err, content);
        let stderr = refused(&publisher(["v1", "pubkey", "--key", utf8(&path)]), needle);
        assert_no_echo(&stderr, content);
    }

    // Accepted spellings of one seed: without the newline, and in either hex
    // case (`hex::decode` is case-insensitive; keygen writes lowercase).
    let expected = hex::encode(SecretKey::from_seed(pattern_seed).author().to_bytes());
    let mixed: String = pattern
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    for (i, content) in [
        pattern.clone(),
        format!("{pattern}\n"),
        format!("{}\n", pattern.to_uppercase()),
        format!("{mixed}\n"),
    ]
    .iter()
    .enumerate()
    {
        let path = fx.path(&format!("accepted-{i}"));
        write_file(&path, content.as_bytes(), 0o600);
        let public = key::load_key(&path).unwrap().author().to_bytes();
        assert_eq!(hex::encode(public), expected, "{content:?}");
        assert_eq!(
            succeeded(&publisher(["v1", "pubkey", "--key", utf8(&path)])),
            format!("{expected}\n")
        );
    }
}

#[test]
fn asserted_time_syntax_and_coordinates() {
    let split = B256Constants::V0.split;

    // Instants as whole seconds from J2000.0, computed with Python's datetime
    // (years before 0001 shifted by whole 400-year cycles of 146097 days).
    let anchors: &[(&str, &str, i64)] = &[
        ("1901-02-03", "day", -3_121_329_600),
        ("1901-02", "month", -3_121_502_400),
        ("1901", "year", -3_124_180_800),
        ("1970-01-01", "day", -946_728_000),
        ("2000-01-01", "day", -43_200),
        ("2000-02-29", "day", 5_054_400),
        ("1600-02-29", "day", -12_617_726_400),
        ("0000", "year", -63_113_947_200),
        ("-0001-12-31", "day", -63_114_033_600),
        ("-0043-03-15", "day", -64_464_552_000),
        ("-9999", "year", -378_651_844_800),
        ("9999-12-31", "day", 252_455_486_400),
    ];
    for &(input, precision, seconds) in anchors {
        let t = time::parse(input).unwrap_or_else(|e| panic!("{input}: {e:#}"));
        assert_eq!(t.precision, precision, "{input}");
        assert_eq!(seconds_of(&t.coordinate), seconds, "{input}");
        assert_eq!(
            t.coordinate,
            Tick::from_whole_ticks(seconds, split).to_canon_bytes(),
            "{input}"
        );
        assert_eq!(time::render(&t).as_deref(), Some(input));
    }
    // 1901-02-03 is day -25169 of the Unix epoch, and J2000.0 is 946728000 s.
    let seconds = DAYS_1901_02_03 * 86_400 - 946_728_000;
    let t = time::parse(ASSERTED).unwrap();
    assert_eq!(
        t.coordinate,
        Tick::from_whole_ticks(seconds, split).to_canon_bytes()
    );
    assert_eq!(hex::encode(t.coordinate), COORDINATE);

    // Years: `cc_authoring::year_tick`, an independent implementation.
    let edge_years = [
        -9999, -401, -400, -101, -100, -5, -4, -1, 0, 1, 4, 99, 100, 400, 1582, 1600, 1700, 1899,
        1900, 1969, 1970, 1999, 2000, 2001, 2100, 9999,
    ];
    for y in (-500..=2100).step_by(37).chain(edge_years) {
        let text = year_text(y);
        let t = time::parse(&text).unwrap();
        assert_eq!(t.precision, "year", "{text}");
        let expected = cc_authoring::year_tick(y).to_canon_bytes();
        assert_eq!(t.coordinate, expected, "{text}");
        let jan1 = time::parse(&format!("{text}-01-01")).unwrap();
        assert_eq!(jan1.coordinate, expected, "{text}");
        assert_eq!(time::render(&t), Some(text));
    }

    // Days and months: the v0 publisher's `entry_coordinate` (years 1..=2100).
    let sample_years = (1..=2100)
        .step_by(13)
        .chain([4, 100, 400, 1600, 1700, 1800, 1900, 2000, 2024, 2096, 2100]);
    for y in sample_years {
        for m in 1..=12 {
            for d in [1, 15, month_days(y, m)] {
                let text = format!("{y:04}-{m:02}-{d:02}");
                let t = time::parse(&text).unwrap();
                assert_eq!(t.precision, "day", "{text}");
                let entry = json!({
                    "year": y,
                    "prov_asserted": {"event_date": text, "date_precision": "day"},
                });
                let v0 = cc_publisher::entry_coordinate(&entry).unwrap();
                assert_eq!(t.coordinate, v0.to_canon_bytes(), "{text}");
                assert_eq!(time::render(&t).as_deref(), Some(text.as_str()));
            }
            let month = format!("{y:04}-{m:02}");
            let t = time::parse(&month).unwrap();
            assert_eq!(t.precision, "month", "{month}");
            let first = time::parse(&format!("{month}-01")).unwrap();
            assert_eq!(t.coordinate, first.coordinate, "{month}");
            assert_eq!(time::render(&t), Some(month));
        }
        let february_29 = format!("{y:04}-02-29");
        assert_eq!(time::parse(&february_29).is_ok(), leap(y), "{february_29}");
    }

    // Every day of these years, one day apart, from 1 January (year_tick) to
    // the next 1 January. Covers the leap year 2024 and the year -0001.
    for y in [-9999, -401, -400, -100, -43, -4, -1, 0, 1600, 1900, 2024] {
        let jan1 = seconds_of(&cc_authoring::year_tick(y).to_canon_bytes());
        let mut day = 0;
        for m in 1..=12 {
            for d in 1..=month_days(y, m) {
                let text = format!("{}-{m:02}-{d:02}", year_text(y));
                let t = time::parse(&text).unwrap();
                assert_eq!(seconds_of(&t.coordinate), jan1 + day * 86_400, "{text}");
                assert_eq!(time::render(&t).as_deref(), Some(text.as_str()));
                day += 1;
            }
        }
        assert_eq!(day, if leap(y) { 366 } else { 365 }, "{y}");
        let next = seconds_of(&cc_authoring::year_tick(y + 1).to_canon_bytes());
        assert_eq!(next, jan1 + day * 86_400, "{y}");
    }

    // Refused, each naming the input.
    let syntax = "must be YYYY, YYYY-MM or YYYY-MM-DD";
    let no_day = "no such day in that month";
    for (input, needle) in [
        ("1901-2-03", syntax),
        ("01901", syntax),
        ("1901-13", "month must be 01-12"),
        ("1901-00", "month must be 01-12"),
        ("1901-02-30", no_day),
        ("1900-02-29", no_day),
        ("1901-04-31", no_day),
        ("1901-02-00", no_day),
        ("1901-02-03T00:00Z", syntax),
        (" 1901", syntax),
        ("1901 ", syntax),
        ("+1901", syntax),
        ("-0000", "write year 0000 without a sign"),
        ("", syntax),
        ("19o1", syntax),
        ("1901--02", syntax),
        ("--1901", syntax),
        ("1901-", syntax),
        ("1901-02-03-04", syntax),
        ("10000", syntax),
        ("-10000", syntax),
        ("\u{ff11}\u{ff19}\u{ff10}\u{ff11}", syntax),
    ] {
        let err = error_text(time::parse(input));
        assert!(err.contains(needle), "{input:?}: {err}");
        assert!(err.contains(&format!("{input:?}")), "{input:?}: {err}");
    }

    // `render` gives no calendar text for a coordinate its precision does not
    // name exactly.
    let day = time::parse(ASSERTED).unwrap();
    let mut fractional = day.clone();
    fractional.coordinate[31] = 1;
    let noon = canon_seconds(seconds_of(&day.coordinate) + 43_200);
    for (coordinate, precision) in [
        (fractional.coordinate, "day"),
        (noon, "day"),
        (day.coordinate, "month"),
        (day.coordinate, "year"),
        (day.coordinate, "week"),
        (day.coordinate, ""),
    ] {
        let t = AssertedTime {
            coordinate,
            precision: precision.into(),
        };
        assert_eq!(time::render(&t), None, "{precision}");
    }

    // `build` refuses an empty precision.
    let mut input = vector_input();
    input.asserted_time.precision = String::new();
    let err = error_text(build(input));
    assert!(
        err.contains("asserted time precision must not be empty"),
        "{err}"
    );

    // The binary takes a year before 0000 as a value, not as a flag.
    let fx = Fixture::new();
    let bce = fx.path("bce");
    succeeded(&run_genesis(with(
        fx.flags(&bce),
        "--asserted-time",
        "-0043-03-15",
    )));
    let preview = Genesis::load_dir(&bce).unwrap().preview().unwrap();
    assert_eq!(preview["asserted_time"]["calendar"], "-0043-03-15");
    assert_eq!(
        preview["asserted_time"]["coordinate"],
        hex::encode(canon_seconds(-64_464_552_000))
    );
    let signed_zero = fx.path("signed-zero");
    refused(
        &run_genesis(with(fx.flags(&signed_zero), "--asserted-time", "-0000")),
        "write year 0000 without a sign",
    );
    assert_absent(&signed_zero);
}

#[test]
fn evidence_body_and_key_field_rules() {
    let (aa, bb, cc) = ([0xaa; 32], [0xbb; 32], [0xcc; 32]);

    // Evidence: duplicates refused, in the set builder and in `build`.
    let err = error_text(genesis::evidence_set(vec![aa, bb, aa]));
    assert!(
        err.contains(&format!("duplicate evidence hash {}", hex::encode(aa))),
        "{err}"
    );
    let mut input = vector_input();
    input.evidence = vec![bb, aa, bb];
    let err = error_text(build(input));
    assert!(
        err.contains(&format!("duplicate evidence hash {}", hex::encode(bb))),
        "{err}"
    );
    // Sorted in the envelope whatever the input order.
    let mut input = vector_input();
    input.evidence = vec![cc, [0x01; 32], bb];
    let g = build(input).unwrap();
    assert_eq!(g.fields().unwrap().evidence, [[0x01; 32], bb, cc]);
    let bytes = g.signed.bytes();
    let wire = [&3u32.to_be_bytes()[..], &[0x01u8; 32], &bb, &cc].concat();
    assert!(bytes[..bytes.len() - 64].ends_with(&wire));
    // At most 1024.
    let many: Vec<Hash> = (0u16..1025)
        .rev()
        .map(|i| {
            let mut h = [0; 32];
            h[..2].copy_from_slice(&i.to_be_bytes());
            h
        })
        .collect();
    let err = error_text(genesis::evidence_set(many.clone()));
    assert!(err.contains("at most 1024 evidence hashes"), "{err}");
    let set = genesis::evidence_set(many[1..].to_vec()).unwrap();
    assert_eq!(set.0.len(), 1024);
    assert!(set.0.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(set.0[0], [0; 32]);

    // Body: nonempty UTF-8 of at most 1 MiB.
    assert_eq!(MAX_BODY, 1 << 20);
    for (body, needle) in [
        (Vec::new(), "body must not be empty"),
        (vec![0xff, 0xfe], "body must be UTF-8 text"),
        (vec![0xc3], "body must be UTF-8 text"),
        (vec![0xc0, 0x80], "body must be UTF-8 text"),
        (vec![b'a'; MAX_BODY + 1], "body exceeds 1048576 bytes"),
    ] {
        let err = error_text(genesis::validate_body(&body));
        assert!(err.contains(needle), "{err}");
        let mut input = vector_input();
        input.body = body;
        let err = error_text(build(input));
        assert!(err.contains(needle), "{err}");
    }
    let largest = vec![b'a'; MAX_BODY];
    genesis::validate_body(&largest).unwrap();
    let mut input = vector_input();
    input.body = largest;
    build(input).unwrap();

    // Namespace and value: nonempty, at most 1024 bytes (not characters), no
    // control characters, no leading or trailing whitespace.
    assert_eq!(MAX_KEY_FIELD, 1024);
    let control = "must not contain control characters";
    let edge = "must not start or end with whitespace";
    for field in ["namespace", "value"] {
        for (s, needle) in [
            (String::new(), "must not be empty"),
            ("synthetic\npublisher".to_string(), control),
            ("synthetic\tpublisher".to_string(), control),
            ("synthetic\u{7f}".to_string(), control),
            ("synthetic\u{85}publisher".to_string(), control),
            ("vector-1\n".to_string(), control),
            (" vector-1".to_string(), edge),
            ("vector-1 ".to_string(), edge),
            ("\u{a0}vector-1".to_string(), edge),
            ("a".repeat(1025), "exceeds 1024 bytes"),
            ("\u{e9}".repeat(512) + "a", "exceeds 1024 bytes"),
        ] {
            let err = error_text(genesis::validate_key_field(field, &s));
            assert!(err.contains(&format!("{field} {needle}")), "{s:?}: {err}");
        }
        // Characters a reviewer cannot see, or that reorder what they see.
        for (c, code) in [
            ('\u{202E}', "U+202E"),
            ('\u{2066}', "U+2066"),
            ('\u{200B}', "U+200B"),
            ('\u{200D}', "U+200D"),
            ('\u{FEFF}', "U+FEFF"),
            ('\u{AD}', "U+00AD"),
            ('\u{E0041}', "U+E0041"),
        ] {
            let s = format!("synthetic{c}value");
            let err = error_text(genesis::validate_key_field(field, &s));
            let needle = format!(
                "{field} must not contain invisible or bidirectional characters (found {code})"
            );
            assert!(err.contains(&needle), "{s:?}: {err}");
        }
        for s in [
            "a".repeat(1024),
            "\u{e9}".repeat(512),
            "synthetic value".into(),
        ] {
            genesis::validate_key_field(field, &s).unwrap();
        }
    }
    let mut input = vector_input();
    input.namespace = "synthetic\npublisher".into();
    let err = error_text(build(input));
    assert!(err.contains(&format!("namespace {control}")), "{err}");
    let mut input = vector_input();
    input.value = " vector-1".into();
    let err = error_text(build(input));
    assert!(err.contains(&format!("value {edge}")), "{err}");
    // Both fields at the byte limit still encode and reload.
    let mut input = vector_input();
    input.namespace = "n".repeat(MAX_KEY_FIELD);
    input.value = "\u{e9}".repeat(MAX_KEY_FIELD / 2);
    let g = build(input).unwrap();
    let subject_key = g.signed.envelope().subject_key.as_ref().unwrap();
    assert_eq!(
        (subject_key.namespace.len(), subject_key.value.len()),
        (1024, 1024)
    );

    // The binary refuses these before anything is written.
    let fx = Fixture::new();
    let duplicate = fx.path("duplicate");
    refused(
        &run_genesis(with(fx.flags(&duplicate), "--evidence", &hex::encode(aa))),
        "duplicate evidence hash",
    );
    assert_absent(&duplicate);
    let padded = fx.path("padded");
    refused(
        &run_genesis(with(fx.flags(&padded), "--value", " vector-1")),
        "value must not start or end with whitespace",
    );
    assert_absent(&padded);
    let big = fx.path("big.txt");
    write_file(&big, &vec![b'a'; MAX_BODY + 1], 0o600);
    let oversized = fx.path("oversized");
    refused(
        &run_genesis(with(fx.flags(&oversized), "--body", utf8(&big))),
        "exceeds 1048576 bytes",
    );
    assert_absent(&oversized);
}

#[test]
fn genesis_dir_refuses_overwrite_and_tamper() {
    let tmp = tempfile::tempdir().unwrap();
    let g = vector_genesis();
    let keep = BTreeMap::from([("notes.txt".to_string(), b"keep\n".to_vec())]);

    // A non-empty directory is refused and left exactly as it was.
    let busy = tmp.path().join("busy");
    fs::create_dir(&busy).unwrap();
    fs::write(busy.join("notes.txt"), b"keep\n").unwrap();
    let err = error_text(g.write_dir(&busy));
    assert!(err.contains("refusing to write into non-empty"), "{err}");
    assert_eq!(snapshot(&busy), keep);
    // Including one that holds an earlier output file.
    let partial = tmp.path().join("partial");
    fs::create_dir(&partial).unwrap();
    fs::write(partial.join(ENVELOPE_FILE), b"earlier").unwrap();
    let err = error_text(g.write_dir(&partial));
    assert!(err.contains("refusing to write into non-empty"), "{err}");
    assert_eq!(
        snapshot(&partial),
        BTreeMap::from([(ENVELOPE_FILE.to_string(), b"earlier".to_vec())])
    );
    // A file in the way is refused and kept.
    let file = tmp.path().join("file");
    fs::write(&file, b"keep\n").unwrap();
    let err = error_text(g.write_dir(&file));
    assert!(err.contains("exists and is not a directory"), "{err}");
    assert_eq!(fs::read(&file).unwrap(), b"keep\n");
    // An existing empty directory is used; writing again is then refused.
    let empty = tmp.path().join("empty");
    fs::create_dir(&empty).unwrap();
    g.write_dir(&empty).unwrap();
    let written = snapshot(&empty);
    let err = error_text(g.write_dir(&empty));
    assert!(err.contains("refusing to write into non-empty"), "{err}");
    assert_eq!(snapshot(&empty), written);
    Genesis::load_dir(&empty).unwrap();

    // The binary refuses a non-empty --out the same way.
    let fx = Fixture::new();
    let busy = fx.path("busy");
    fs::create_dir(&busy).unwrap();
    fs::write(busy.join("notes.txt"), b"keep\n").unwrap();
    refused(
        &run_genesis(fx.flags(&busy)),
        "refusing to write into non-empty",
    );
    assert_eq!(snapshot(&busy), keep);

    // Reload refuses every tampered directory, each for its own reason.
    let root = tmp.path().join("tamper");
    let err = load_error(&root, "preview-value", |dir| {
        let path = dir.join(PREVIEW_FILE);
        let mut preview: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        preview["subject_key"]["value"] = json!("vector-2");
        fs::write(
            &path,
            serde_json::to_string_pretty(&preview).unwrap() + "\n",
        )
        .unwrap();
    });
    assert!(
        err.contains("preview.json does not match envelope.bin and body.bin"),
        "{err}"
    );
    let err = load_error(&root, "body-byte", |dir| {
        edit_file(&dir.join(BODY_FILE), |b| b[0] ^= 0x01);
    });
    assert!(
        err.contains("body.bin does not hash to the body the envelope signs"),
        "{err}"
    );
    let err = load_error(&root, "envelope-value-byte", |dir| {
        edit_file(&dir.join(ENVELOPE_FILE), |b| {
            let at = b.windows(8).position(|w| w == b"vector-1").unwrap();
            b[at + 7] = b'2';
        });
    });
    assert!(err.contains("envelope.bin: bad_signature"), "{err}");
    let err = load_error(&root, "envelope-signature-byte", |dir| {
        edit_file(&dir.join(ENVELOPE_FILE), |b| *b.last_mut().unwrap() ^= 0x01);
    });
    assert!(err.contains("envelope.bin: bad_signature"), "{err}");
    let err = load_error(&root, "envelope-encoding-byte", |dir| {
        edit_file(&dir.join(ENVELOPE_FILE), |b| b[4] ^= 0x20);
    });
    assert!(err.contains("envelope.bin: unsupported_encoding"), "{err}");
    let err = load_error(&root, "preview-removed", |dir| {
        fs::remove_file(dir.join(PREVIEW_FILE)).unwrap();
    });
    let missing = root.join("preview-removed").join(PREVIEW_FILE);
    assert!(
        err.contains(&format!("open {}", missing.display())),
        "{err}"
    );
    let err = load_error(&root, "preview-not-json", |dir| {
        fs::write(dir.join(PREVIEW_FILE), b"not json\n").unwrap();
    });
    assert!(err.contains("preview.json is not JSON"), "{err}");
    let err = load_error(&root, "body-not-utf8", |dir| {
        edit_file(&dir.join(BODY_FILE), |b| b[0] = 0xff);
    });
    assert!(err.contains("body must be UTF-8 text"), "{err}");
    let err = load_error(&root, "envelope-removed", |dir| {
        fs::remove_file(dir.join(ENVELOPE_FILE)).unwrap();
    });
    let missing = root.join("envelope-removed").join(ENVELOPE_FILE);
    assert!(
        err.contains(&format!("open {}", missing.display())),
        "{err}"
    );
}
