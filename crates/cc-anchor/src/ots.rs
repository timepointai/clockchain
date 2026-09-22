//! OpenTimestamps: getting 32 bytes into Bitcoin without owning a Bitcoin wallet.
//!
//! **Why aggregated calendars and not our own transaction.** The initiation
//! plan's open question (§"Anchoring in M4") offers two paths: free public
//! OpenTimestamps calendars, or a self-funded direct inscription. The calendars
//! are the assumed default and the one taken here, for the reason §storage
//! gives — "pennies, not fees that scale with the corpus". A calendar batches
//! thousands of digests into one Bitcoin transaction, so our per-epoch cost is
//! zero and there is no funded wallet, no key custody, and no fee market in the
//! anchoring path. What we take on instead is a liveness dependency on a third
//! party (memo §8), and the design answer to that is that a calendar can only
//! ever *fail to timestamp* us — it cannot forge a Bitcoin block, so a lost
//! calendar costs us an epoch's anchor, never the integrity of one we hold.
//!
//! **What an anchor proves, and what it does not.** A root committed in block
//! `N` was recorded *before* block `N`, proven by proof-of-work with no
//! timestamp authority consulted (§4.1, Prop. trscope). It never asserts an
//! instant. That is the whole retirement of the RFC 3161 model, and it is why
//! `anchors` records a block height rather than a timestamp.
//!
//! **The network boundary is one function.** [`submit`] and [`fetch_upgrade`]
//! are the only things here that touch a socket; everything else — building the
//! `.ots` file, walking its operations, reading its attestations — is a pure
//! function of bytes and is covered by tests. That split is deliberate: the
//! calendar round-trip cannot be exercised in CI without making a public service
//! a test dependency, so the untestable part is kept to two calls whose whole
//! body is a request and a status check.

use sha2::{Digest, Sha256};
use std::time::Duration;

/// The public OpenTimestamps calendars. Several, because the liveness dependency
/// above is per-calendar: a stamp submitted to all of them survives any one of
/// them going away.
pub const PUBLIC_CALENDARS: [&str; 3] = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://alice.btc.calendar.opentimestamps.org",
];

/// The magic that opens every `.ots` file (python-opentimestamps
/// `DetachedTimestampFile.HEADER_MAGIC`). Present so the file is self-describing
/// and a truncated or mis-typed blob fails at byte 0 instead of somewhere deep in
/// the operation stream.
const HEADER_MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
/// Serialization major version this build writes and accepts.
const MAJOR_VERSION: u64 = 1;

/// Operation tags (python-opentimestamps `ops.py`).
const OP_APPEND: u8 = 0xf0;
const OP_PREPEND: u8 = 0xf1;
const OP_REVERSE: u8 = 0xf2;
const OP_HEXLIFY: u8 = 0xf3;
const OP_SHA1: u8 = 0x02;
const OP_RIPEMD160: u8 = 0x03;
const OP_SHA256: u8 = 0x08;
const OP_KECCAK256: u8 = 0x67;
/// Marks an attestation rather than an operation in the timestamp stream.
const ATTESTATION_TAG: u8 = 0x00;
/// Marks "another sibling follows this one".
const CONTINUATION_TAG: u8 = 0xff;

const PENDING_ATTESTATION: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const BITCOIN_ATTESTATION: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// A failure in the anchoring path. Every variant is a refusal to proceed: an
/// anchor that "sort of worked" is worse than none, because the corpus would then
/// record a settlement bound nothing backs (memo §3, fail closed).
#[derive(Debug, thiserror::Error)]
pub enum OtsError {
    /// The calendar was unreachable, slow, or answered with a non-200.
    #[error("calendar {calendar} did not complete the round-trip: {detail}")]
    Calendar {
        /// Which calendar failed, so a multi-calendar tick names the one that did.
        calendar: String,
        /// What went wrong, verbatim.
        detail: String,
    },
    /// The bytes we were handed are not an OpenTimestamps structure.
    #[error("malformed OpenTimestamps data: {0}")]
    Malformed(&'static str),
    /// A hash function or operation this build cannot execute. Loud, because
    /// silently skipping an operation would produce a commitment that verifies
    /// against nothing.
    #[error("unsupported OpenTimestamps operation 0x{0:02x}")]
    UnsupportedOp(u8),
    /// The proof does not commit to the digest we submitted — the one thing a
    /// returned proof absolutely must do.
    #[error("proof commits to {found}, not to the submitted root {expected}")]
    WrongDigest {
        /// The root the caller paired this proof with.
        expected: String,
        /// The digest the proof is actually about.
        found: String,
    },
}

/// What a calendar or a blockchain says about a commitment.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Attestation {
    /// A calendar has taken the commitment and will fold it into a Bitcoin
    /// transaction. This is a *promise*, not a timestamp: it is exactly the
    /// `pending` half of the anchor lifecycle and must never be recorded as
    /// confirmed.
    Pending {
        /// The calendar to ask later for the completed path.
        uri: String,
    },
    /// A Bitcoin block header at `height` commits to this message. This is the
    /// settlement fact: everything under the root was recorded before this block.
    Bitcoin {
        /// Block height the commitment landed in.
        height: u64,
    },
    /// An attestation type this build does not recognize. Carried rather than
    /// dropped, so an unknown notary shows up as unknown instead of as absent.
    Unknown {
        /// The 8-byte type tag.
        tag: [u8; 8],
        /// The opaque payload.
        payload: Vec<u8>,
    },
}

/// An attestation together with the message it actually attests to.
///
/// The pair matters: a `Pending` attestation's message is the commitment the
/// calendar knows us by, and it is what [`fetch_upgrade`] must ask for. Reporting
/// the attestation without the message it belongs to would leave the caller
/// guessing which of several intermediate digests to use.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commitment {
    /// The attesting party's claim.
    pub attestation: Attestation,
    /// The message the claim is about.
    pub message: Vec<u8>,
}

/// A complete `.ots` detached timestamp file for one root.
///
/// Held as bytes rather than as a parsed tree because the bytes are what a third
/// party's `ots verify` consumes — re-serializing a parsed structure risks a
/// byte-level drift that would make our stored proof and the reference client's
/// disagree about the same fact.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OtsProof {
    bytes: Vec<u8>,
}

impl OtsProof {
    /// Assemble the `.ots` file for `digest` from a calendar's reply.
    ///
    /// The calendar answers a submission with the serialized timestamp *for the
    /// digest we sent*; a detached timestamp file is that, behind a header naming
    /// the hash function and the digest. Building it here rather than storing the
    /// raw reply is what makes the blob independently checkable — the reply alone
    /// does not say what it is about.
    ///
    /// Parses what it builds before returning: a reply we cannot walk, or that
    /// carries no attestation at all, is rejected here rather than discovered
    /// years later by an auditor.
    ///
    /// `digest` must be the digest that was actually submitted. A calendar's
    /// reply is only meaningful for that one input — its operation chain applied
    /// to any other message yields a commitment no calendar ever saw — and
    /// nothing in the reply itself names the digest, so this is the one
    /// correspondence the type cannot enforce for you. [`OtsProof::commits_to`]
    /// is how every later reader re-checks it.
    pub fn from_calendar_reply(digest: &[u8; 32], reply: &[u8]) -> Result<OtsProof, OtsError> {
        let mut bytes = Vec::with_capacity(HEADER_MAGIC.len() + 40 + reply.len());
        bytes.extend_from_slice(HEADER_MAGIC);
        write_varuint(&mut bytes, MAJOR_VERSION);
        bytes.push(OP_SHA256);
        bytes.extend_from_slice(digest);
        bytes.extend_from_slice(reply);
        let proof = OtsProof { bytes };
        // Walking it proves the operation stream is intact and that at least one
        // party attested to something.
        if proof.commitments()?.is_empty() {
            return Err(OtsError::Malformed("no attestation in the calendar reply"));
        }
        Ok(proof)
    }

    /// Refuse a proof that is about some other root.
    ///
    /// A blob read back from storage is only evidence about the root it names,
    /// and rows can be swapped. Anything that pairs a stored proof with a root
    /// calls this first, so a mismatched pair fails loudly instead of quietly
    /// anchoring one epoch's root with another epoch's timestamp.
    pub fn commits_to(&self, digest: &[u8; 32]) -> Result<(), OtsError> {
        let found = self.digest()?;
        if &found == digest {
            return Ok(());
        }
        Err(OtsError::WrongDigest {
            expected: hex::encode(digest),
            found: hex::encode(found),
        })
    }

    /// Adopt bytes that were already assembled (a row read back, a file on disk).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<OtsProof, OtsError> {
        let proof = OtsProof { bytes };
        proof.digest()?;
        Ok(proof)
    }

    /// The `.ots` file bytes, exactly as a reference client would read them.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `SHA-256` over the proof bytes: the content address `anchors` stores.
    ///
    /// Proofs go into the ledger *by reference* (memo §3) — the row carries this
    /// hash and the bytes live in `anchor_proofs`, so a proof cannot grow into
    /// the base64-in-a-text-column failure v1 shipped.
    pub fn blob_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    /// The digest this proof is about — our Merkle root.
    pub fn digest(&self) -> Result<[u8; 32], OtsError> {
        let mut r = Reader::new(&self.bytes);
        r.expect(HEADER_MAGIC)?;
        let version = r.varuint()?;
        if version != MAJOR_VERSION {
            return Err(OtsError::Malformed("unsupported .ots major version"));
        }
        let hash_op = r.u8()?;
        if hash_op != OP_SHA256 {
            return Err(OtsError::Malformed("file digest is not SHA-256"));
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(r.take(32)?);
        Ok(d)
    }

    /// Every attestation in the proof, paired with the message it attests to.
    ///
    /// Executes the operation stream to get there, so the messages returned are
    /// derived from our digest rather than asserted by the file. A proof whose
    /// operations do not actually lead to its attestations is a proof of nothing,
    /// and this is where that is caught.
    pub fn commitments(&self) -> Result<Vec<Commitment>, OtsError> {
        let digest = self.digest()?;
        let header = HEADER_MAGIC.len() + varuint_len(MAJOR_VERSION) + 1 + 32;
        let mut r = Reader::new(&self.bytes[header..]);
        let mut out = Vec::new();
        walk(&mut r, digest.to_vec(), &mut out)?;
        if !r.done() {
            return Err(OtsError::Malformed("trailing bytes after the timestamp"));
        }
        Ok(out)
    }

    /// The Bitcoin block height, if some block header already commits to this
    /// proof. `None` means "not confirmed yet", which is a state, not a failure —
    /// a fresh stamp is legitimately pending for hours.
    pub fn bitcoin_height(&self) -> Result<Option<u64>, OtsError> {
        Ok(self
            .commitments()?
            .into_iter()
            .find_map(|c| match c.attestation {
                Attestation::Bitcoin { height } => Some(height),
                _ => None,
            }))
    }

    /// The calendars holding this commitment, each with the message to ask them
    /// about — the exact input [`fetch_upgrade`] needs.
    pub fn pending(&self) -> Result<Vec<(String, Vec<u8>)>, OtsError> {
        Ok(self
            .commitments()?
            .into_iter()
            .filter_map(|c| match c.attestation {
                Attestation::Pending { uri } => Some((uri, c.message)),
                _ => None,
            })
            .collect())
    }
}

// ===========================================================================
// The operation stream
// ===========================================================================

/// Walk a serialized timestamp, executing operations and collecting attestations.
///
/// The grammar (python-opentimestamps `Timestamp._serialize`): `0xff 0x00`
/// introduces an attestation with siblings still to come, `0x00` an attestation
/// that ends this node, `0xff <op>` an operation with siblings to come, and a
/// bare `<op>` the last operation, whose subtree continues inline.
fn walk(r: &mut Reader, msg: Vec<u8>, out: &mut Vec<Commitment>) -> Result<(), OtsError> {
    let mut msg = msg;
    loop {
        match r.u8()? {
            ATTESTATION_TAG => {
                out.push(read_attestation(r, &msg)?);
                return Ok(());
            }
            CONTINUATION_TAG => {
                let tag = r.u8()?;
                if tag == ATTESTATION_TAG {
                    out.push(read_attestation(r, &msg)?);
                } else {
                    let branch = apply(r, tag, &msg)?;
                    walk(r, branch, out)?;
                }
            }
            tag => {
                // The last operation of this node: its subtree is serialized
                // inline, so continue in this loop rather than recursing.
                msg = apply(r, tag, &msg)?;
            }
        }
    }
}

/// Execute one operation against the running message.
///
/// Unknown or unimplemented operations are an error, never a skip. Skipping one
/// would silently produce a different message and therefore a commitment that
/// belongs to a document nobody submitted.
fn apply(r: &mut Reader, tag: u8, msg: &[u8]) -> Result<Vec<u8>, OtsError> {
    match tag {
        OP_APPEND => {
            let arg = r.varbytes()?;
            let mut v = msg.to_vec();
            v.extend_from_slice(arg);
            Ok(v)
        }
        OP_PREPEND => {
            let arg = r.varbytes()?;
            let mut v = arg.to_vec();
            v.extend_from_slice(msg);
            Ok(v)
        }
        OP_SHA256 => Ok(Sha256::digest(msg).to_vec()),
        OP_REVERSE => {
            let mut v = msg.to_vec();
            v.reverse();
            Ok(v)
        }
        OP_HEXLIFY => Ok(hex::encode(msg).into_bytes()),
        // Present by name so the refusal is specific: these appear in the OTS
        // vocabulary but no path we submit uses them, and guessing at one would
        // mean shipping an untested hash implementation into the settlement path.
        OP_SHA1 | OP_RIPEMD160 | OP_KECCAK256 => Err(OtsError::UnsupportedOp(tag)),
        other => Err(OtsError::UnsupportedOp(other)),
    }
}

fn read_attestation(r: &mut Reader, msg: &[u8]) -> Result<Commitment, OtsError> {
    let mut tag = [0u8; 8];
    tag.copy_from_slice(r.take(8)?);
    let payload = r.varbytes()?;
    let attestation = match tag {
        PENDING_ATTESTATION => {
            let mut pr = Reader::new(payload);
            let uri = pr.varbytes()?;
            Attestation::Pending {
                uri: String::from_utf8(uri.to_vec())
                    .map_err(|_| OtsError::Malformed("calendar URI is not UTF-8"))?,
            }
        }
        BITCOIN_ATTESTATION => {
            let mut pr = Reader::new(payload);
            Attestation::Bitcoin {
                height: pr.varuint()?,
            }
        }
        other => Attestation::Unknown {
            tag: other,
            payload: payload.to_vec(),
        },
    };
    Ok(Commitment {
        attestation,
        message: msg.to_vec(),
    })
}

// ===========================================================================
// Varint primitives (python-opentimestamps `serialize.py`)
// ===========================================================================

fn write_varuint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn varuint_len(n: u64) -> usize {
    let mut v = Vec::new();
    write_varuint(&mut v, n);
    v.len()
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], OtsError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(OtsError::Malformed("length overflow"))?;
        if end > self.b.len() {
            return Err(OtsError::Malformed("truncated"));
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, OtsError> {
        Ok(self.take(1)?[0])
    }

    fn expect(&mut self, magic: &[u8]) -> Result<(), OtsError> {
        if self.take(magic.len())? != magic {
            return Err(OtsError::Malformed("not an OpenTimestamps file"));
        }
        Ok(())
    }

    fn varuint(&mut self) -> Result<u64, OtsError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            let chunk = u64::from(b & 0x7f);
            value |= chunk
                .checked_shl(shift)
                .ok_or(OtsError::Malformed("varuint too wide"))?;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn varbytes(&mut self) -> Result<&'a [u8], OtsError> {
        let len = self.varuint()? as usize;
        self.take(len)
    }

    fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

// ===========================================================================
// The network boundary — the only untested code in this crate
// ===========================================================================

/// How long we wait on a calendar before calling the epoch's anchor a failure.
/// Short on purpose: a hung anchor tick that never returns is the failure mode
/// §6 warns about, where the absence of success is what has to alarm.
const CALENDAR_TIMEOUT: Duration = Duration::from_secs(20);

/// **NETWORK.** Submit a digest to an OpenTimestamps calendar and return the
/// serialized timestamp it answers with.
///
/// This function and [`fetch_upgrade`] are the only code in `cc-anchor` that a
/// test cannot exercise without depending on a public third-party service, which
/// is why they contain no logic beyond the request and the status check —
/// everything that could be wrong about a proof is checked in
/// [`OtsProof::from_calendar_reply`], which is pure and tested.
pub async fn submit(calendar: &str, digest: &[u8; 32]) -> Result<Vec<u8>, OtsError> {
    let url = format!("{}/digest", calendar.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(CALENDAR_TIMEOUT)
        .build()
        .map_err(|e| OtsError::Calendar {
            calendar: calendar.to_string(),
            detail: e.to_string(),
        })?;
    let resp = client
        .post(&url)
        .header("Accept", "application/vnd.opentimestamps.v1")
        .header("User-Agent", "cc-anchor")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(digest.to_vec())
        .send()
        .await
        .map_err(|e| OtsError::Calendar {
            calendar: calendar.to_string(),
            detail: e.to_string(),
        })?;
    let status = resp.status();
    let body = resp.bytes().await.map_err(|e| OtsError::Calendar {
        calendar: calendar.to_string(),
        detail: e.to_string(),
    })?;
    if !status.is_success() {
        return Err(OtsError::Calendar {
            calendar: calendar.to_string(),
            detail: format!("HTTP {status}"),
        });
    }
    Ok(body.to_vec())
}

/// **NETWORK.** Ask a calendar for the completed path of a commitment it took
/// earlier.
///
/// `Ok(None)` is the calendar answering "I have that commitment, but Bitcoin has
/// not confirmed it yet" — a `404`, and the expected reply for hours after a
/// stamp. It is deliberately *not* folded into [`OtsError::Calendar`]: waiting for
/// a block and failing to reach a calendar demand opposite operational responses,
/// and a cron that alarmed on the first would alarm through every normal day
/// (memo §5 — no-evidence, empty, and error are three answers, not one).
pub async fn fetch_upgrade(calendar: &str, commitment: &[u8]) -> Result<Option<Vec<u8>>, OtsError> {
    let url = format!(
        "{}/timestamp/{}",
        calendar.trim_end_matches('/'),
        hex::encode(commitment)
    );
    let client = reqwest::Client::builder()
        .timeout(CALENDAR_TIMEOUT)
        .build()
        .map_err(|e| OtsError::Calendar {
            calendar: calendar.to_string(),
            detail: e.to_string(),
        })?;
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.opentimestamps.v1")
        .header("User-Agent", "cc-anchor")
        .send()
        .await
        .map_err(|e| OtsError::Calendar {
            calendar: calendar.to_string(),
            detail: e.to_string(),
        })?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body = resp.bytes().await.map_err(|e| OtsError::Calendar {
        calendar: calendar.to_string(),
        detail: e.to_string(),
    })?;
    if !status.is_success() {
        return Err(OtsError::Calendar {
            calendar: calendar.to_string(),
            detail: format!("HTTP {status}"),
        });
    }
    Ok(Some(body.to_vec()))
}

/// Read the attestations out of a bare timestamp stream — what
/// [`fetch_upgrade`] returns — given the message it starts from.
///
/// Kept separate from [`OtsProof`] because an upgrade reply is a *fragment*: it
/// is the path onward from the calendar's commitment, not a file about our root.
/// Splicing that fragment back onto the stored proof to produce one confirmed
/// `.ots` is a real tree merge and is deliberately not done here — the block
/// height is what the ledger records, and inventing a merged file we could not
/// test against a reference client would be worse than holding both halves.
pub fn attestations_in(timestamp: &[u8], from_message: &[u8]) -> Result<Vec<Commitment>, OtsError> {
    let mut r = Reader::new(timestamp);
    let mut out = Vec::new();
    walk(&mut r, from_message.to_vec(), &mut out)?;
    if !r.done() {
        return Err(OtsError::Malformed("trailing bytes after the timestamp"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real reply from `https://a.pool.opentimestamps.org/digest`, captured on
    /// 2026-08-12 for the digest below. Pinned as a fixture so the assembly and
    /// the walker are tested against bytes a calendar actually produced, not
    /// against bytes we invented to match our own parser.
    /// `SHA-256("clockchain-v2 cc-anchor M4 calendar fixture")`.
    const CAPTURED_DIGEST: [u8; 32] = [
        0xac, 0x63, 0xc3, 0x7e, 0x21, 0xbd, 0xf9, 0xc7, 0x2a, 0x4c, 0x1d, 0xdb, 0x24, 0x3f, 0x7d,
        0xce, 0xaa, 0x2b, 0x3c, 0xb3, 0xd4, 0x69, 0x5b, 0x0d, 0x7a, 0xb9, 0xed, 0xd9, 0x62, 0xc5,
        0xf8, 0xfc,
    ];
    const CAPTURED_REPLY: &[u8] = include_bytes!("../tests/fixtures/calendar_reply.ots");

    fn pending_reply(uri: &str) -> Vec<u8> {
        // sha256, then a pending attestation — the minimal shape of a calendar
        // reply, built by hand so the walker is tested on a path we control too.
        let mut v = vec![OP_SHA256, ATTESTATION_TAG];
        v.extend_from_slice(&PENDING_ATTESTATION);
        let mut payload = Vec::new();
        write_varuint(&mut payload, uri.len() as u64);
        payload.extend_from_slice(uri.as_bytes());
        write_varuint(&mut v, payload.len() as u64);
        v.extend_from_slice(&payload);
        v
    }

    #[test]
    fn varuint_round_trips_across_the_boundaries() {
        for n in [
            0u64,
            1,
            127,
            128,
            300,
            16383,
            16384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut v = Vec::new();
            write_varuint(&mut v, n);
            assert_eq!(v.len(), varuint_len(n));
            assert_eq!(Reader::new(&v).varuint().expect("round trip"), n);
        }
    }

    #[test]
    fn a_hand_built_pending_reply_walks_to_its_calendar() {
        let digest = [7u8; 32];
        let proof = OtsProof::from_calendar_reply(&digest, &pending_reply("https://example.test"))
            .expect("well-formed reply");
        assert_eq!(proof.digest().expect("digest"), digest);
        let pending = proof.pending().expect("walk");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, "https://example.test");
        // The message the calendar knows us by is SHA-256 of our root, not the
        // root itself — the sha256 operation in the reply.
        assert_eq!(pending[0].1, Sha256::digest(digest).to_vec());
        assert_eq!(proof.bitcoin_height().expect("walk"), None);
    }

    #[test]
    fn a_real_calendar_reply_parses_and_commits_to_the_root_it_answered_for() {
        let proof = OtsProof::from_calendar_reply(&CAPTURED_DIGEST, CAPTURED_REPLY)
            .expect("the captured reply is well formed");
        assert_eq!(proof.digest().expect("digest"), CAPTURED_DIGEST);
        let pending = proof.pending().expect("walk");
        assert!(
            !pending.is_empty(),
            "a fresh stamp must carry a pending calendar attestation"
        );
        assert!(pending[0].0.starts_with("https://"));
        assert_eq!(
            proof.bitcoin_height().expect("walk"),
            None,
            "a stamp minutes old cannot already be in a block"
        );
        // Round-trips through storage unchanged.
        let stored = OtsProof::from_bytes(proof.bytes().to_vec()).expect("re-adopt");
        assert_eq!(stored, proof);
        assert_eq!(stored.blob_hash(), proof.blob_hash());
    }

    #[test]
    fn a_proof_paired_with_the_wrong_root_is_refused() {
        let proof =
            OtsProof::from_calendar_reply(&CAPTURED_DIGEST, CAPTURED_REPLY).expect("well formed");
        proof.commits_to(&CAPTURED_DIGEST).expect("its own root");
        assert!(matches!(
            proof.commits_to(&[9u8; 32]),
            Err(OtsError::WrongDigest { .. })
        ));
    }

    #[test]
    fn truncated_and_foreign_bytes_fail_loudly() {
        assert!(matches!(
            OtsProof::from_bytes(b"not an ots file".to_vec()),
            Err(OtsError::Malformed(_))
        ));
        let mut short = Vec::from(HEADER_MAGIC);
        write_varuint(&mut short, MAJOR_VERSION);
        short.push(OP_SHA256);
        assert!(matches!(
            OtsProof::from_bytes(short),
            Err(OtsError::Malformed(_))
        ));
    }

    #[test]
    fn an_unsupported_operation_is_an_error_not_a_skip() {
        let mut reply = vec![OP_RIPEMD160, ATTESTATION_TAG];
        reply.extend_from_slice(&PENDING_ATTESTATION);
        write_varuint(&mut reply, 1);
        reply.push(0);
        assert!(matches!(
            OtsProof::from_calendar_reply(&[1u8; 32], &reply),
            Err(OtsError::UnsupportedOp(OP_RIPEMD160))
        ));
    }

    #[test]
    fn a_bitcoin_attestation_reads_as_a_block_height() {
        // append(0xab) -> sha256 -> bitcoin attestation at height 800_000.
        let mut reply = vec![OP_APPEND, 1, 0xab, OP_SHA256, ATTESTATION_TAG];
        reply.extend_from_slice(&BITCOIN_ATTESTATION);
        let mut payload = Vec::new();
        write_varuint(&mut payload, 800_000);
        write_varuint(&mut reply, payload.len() as u64);
        reply.extend_from_slice(&payload);
        let proof = OtsProof::from_calendar_reply(&[3u8; 32], &reply).expect("well formed");
        assert_eq!(proof.bitcoin_height().expect("walk"), Some(800_000));
        assert!(proof.pending().expect("walk").is_empty());
    }

    #[test]
    fn an_upgrade_fragment_is_read_from_the_message_it_continues() {
        let commitment = Sha256::digest([5u8; 32]).to_vec();
        let mut fragment = vec![ATTESTATION_TAG];
        fragment.extend_from_slice(&BITCOIN_ATTESTATION);
        let mut payload = Vec::new();
        write_varuint(&mut payload, 42);
        write_varuint(&mut fragment, payload.len() as u64);
        fragment.extend_from_slice(&payload);
        let found = attestations_in(&fragment, &commitment).expect("walk");
        assert_eq!(
            found,
            vec![Commitment {
                attestation: Attestation::Bitcoin { height: 42 },
                message: commitment,
            }]
        );
    }
}
