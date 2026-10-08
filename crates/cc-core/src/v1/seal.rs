//! Signed node seals: a stateless, signed statement of the corpus state one
//! node served at one moment. Never an event, never subject authority, and
//! never part of any commitment, corpus digest or export root.
//!
//! A seal follows the [`super::receipt`] pattern exactly: the same wire
//! encoding, the same domain framing (under its own domain, `cc.seal.v1`),
//! the same trailing 64-byte Ed25519 signature and the same node key. Where
//! a receipt attests that the node saw one event, a seal attests that the
//! node served one `(corpus_digest, commitment)` pair under one rule identity
//! at `sealed_at_us` on its own clock. The node keeps no seal log; whoever
//! fetches seals keeps them, and a chain of saved seals is what makes a later
//! rewrite detectable ([SEALING](../../../../docs/design/SEALING.md)).
use super::receipt::FoldRef;
use super::*;

/// The seal's own domain string, framed exactly as `cc.receipt.v1` is.
pub const SEAL_DOMAIN: &str = "cc.seal.v1";
/// `build` is a short build revision such as `/health` publishes.
pub const MAX_BUILD: usize = 64;

/// Row counts the node has at hand when it seals. Only `candidates` is
/// included: it is the size of the retained candidate set the corpus digest
/// is computed over, which the fold already holds. Bodies, receipts and
/// rejections would each need a new store query and are left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealCounts {
    pub candidates: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSealV1 {
    pub instance: Hash,
    /// Set by [`sign_seal`] to the signing key; a verifier compares it with
    /// the node key it expects out of band.
    pub node_key: Hash,
    pub fold_version: FoldRef,
    pub filter_version: Hash,
    pub corpus_digest: Hash,
    pub commitment: Hash,
    pub counts: SealCounts,
    /// The build revision the node publishes on `/health`.
    pub build: String,
    /// Unix microseconds on the node's clock, not claimed historical time.
    pub sealed_at_us: u64,
}
record!(SealCounts, candidates);
record!(
    NodeSealV1,
    instance,
    node_key,
    fold_version,
    filter_version,
    corpus_digest,
    commitment,
    counts,
    build,
    sealed_at_us
);
impl NodeSealV1 {
    /// The canonical bytes a seal signature covers: the framed domain, then
    /// every field in declaration order with the shared v1 wire encoding.
    pub fn preimage(&self) -> Result<Vec<u8>> {
        if self.build.is_empty()
            || self.build.len() > MAX_BUILD
            || !self.build.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(WireError("seal_build"));
        }
        let mut w = Writer(Vec::new());
        SEAL_DOMAIN.to_owned().put(&mut w)?;
        self.put(&mut w)?;
        Ok(w.0)
    }
}

/// A seal whose bytes decoded as canonical and verified under their own
/// `node_key`. Only [`sign_seal`] and [`SignedSeal::decode`] construct it.
#[derive(Clone, Debug)]
pub struct SignedSeal {
    seal: NodeSealV1,
    bytes: Vec<u8>,
}
impl SignedSeal {
    /// Preimage followed by the 64-byte signature, as `SignedReceipt` does.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE {
            return Err(WireError("envelope_too_large"));
        }
        let split = bytes.len().checked_sub(64).ok_or(WireError("truncated"))?;
        let (preimage, signature) = bytes.split_at(split);
        let mut r = Reader(preimage);
        if String::get(&mut r)? != SEAL_DOMAIN {
            return Err(WireError("seal_domain"));
        }
        let seal = NodeSealV1::get(&mut r)?;
        if !r.0.is_empty() || seal.preimage()? != preimage {
            return Err(WireError("noncanonical"));
        }
        verify_seal(&seal, signature.try_into().unwrap())?;
        Ok(Self {
            seal,
            bytes: bytes.to_vec(),
        })
    }
    pub fn seal(&self) -> &NodeSealV1 {
        &self.seal
    }
    /// Preimage and signature together.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// The trailing 64 signature bytes alone.
    pub fn signature(&self) -> [u8; 64] {
        self.bytes[self.bytes.len() - 64..].try_into().unwrap()
    }
}

/// Sign `seal` under `key`. `node_key` is overwritten with the signer's
/// public key, as a receipt's is.
pub fn sign_seal(key: &SecretKey, mut seal: NodeSealV1) -> Result<SignedSeal> {
    seal.node_key = key.author().to_bytes();
    let mut bytes = seal.preimage()?;
    bytes.extend_from_slice(&key.sign_message(&bytes).to_bytes());
    SignedSeal::decode(&bytes)
}

/// Check `signature` over the canonical bytes of `seal` under `seal.node_key`.
/// A verifier must still compare `node_key` with the key it expects: this
/// proves the seal was signed by the key it names, nothing about that key.
pub fn verify_seal(seal: &NodeSealV1, signature: &[u8; 64]) -> Result<()> {
    let preimage = seal.preimage()?;
    let key = AuthorKey::from_bytes(&seal.node_key).map_err(|_| WireError("bad_signature"))?;
    verify(&key, &preimage, &Signature::from_bytes(*signature))
        .map_err(|_| WireError("bad_signature"))
}
