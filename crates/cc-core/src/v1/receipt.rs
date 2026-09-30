//! Signed node observations, never events or subject authority.
//! Fold identity is supplied explicitly; stage (e) must govern/enable it.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldRef {
    pub version: u16,
    pub manifest: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Admission {
    Valid = 1,
    Pending = 2,
    Invalid = 3,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialResult {
    pub state: Admission,
    pub reason: String,
    pub missing: Set<Hash>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeReceiptV1 {
    pub instance: Hash,
    pub node_key: Hash,
    pub event: Hash,
    /// Unix microseconds observed by this node, not claimed historical time.
    pub received_at: u64,
    pub encoding_version: u16,
    pub fold_version: FoldRef,
    pub initial_admission_result: InitialResult,
}
number!(u64, 8);
tags!(Admission, Valid = 1, Pending = 2, Invalid = 3);
record!(FoldRef, version, manifest);
record!(InitialResult, state, reason, missing);
record!(
    NodeReceiptV1,
    instance,
    node_key,
    event,
    received_at,
    encoding_version,
    fold_version,
    initial_admission_result
);
impl NodeReceiptV1 {
    fn preimage(&self) -> Result<Vec<u8>> {
        if self.encoding_version != CANON_VERSION {
            return Err(WireError("unsupported_encoding"));
        }
        let result = &self.initial_admission_result;
        if (result.state == Admission::Valid
            && (!result.reason.is_empty() || !result.missing.0.is_empty()))
            || (result.state != Admission::Valid && result.reason.is_empty())
            || (result.state != Admission::Pending && !result.missing.0.is_empty())
        {
            return Err(WireError("receipt_result"));
        }
        let mut w = Writer(Vec::new());
        "cc.receipt.v1".to_owned().put(&mut w)?;
        self.put(&mut w)?;
        if w.0.len() + 64 > MAX_ENVELOPE {
            return Err(WireError("envelope_too_large"));
        }
        Ok(w.0)
    }
}
#[derive(Clone, Debug)]
pub struct SignedReceipt {
    receipt: NodeReceiptV1,
    bytes: Vec<u8>,
}
impl SignedReceipt {
    pub fn sign(key: &SecretKey, mut receipt: NodeReceiptV1) -> Result<Self> {
        receipt.node_key = key.author().to_bytes();
        let mut bytes = receipt.preimage()?;
        bytes.extend_from_slice(&key.sign_message(&bytes).to_bytes());
        Self::decode(&bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE {
            return Err(WireError("envelope_too_large"));
        }
        let split = bytes.len().checked_sub(64).ok_or(WireError("truncated"))?;
        let (preimage, signature) = bytes.split_at(split);
        let mut r = Reader(preimage);
        if String::get(&mut r)? != "cc.receipt.v1" {
            return Err(WireError("receipt_domain"));
        }
        let receipt = NodeReceiptV1::get(&mut r)?;
        if !r.0.is_empty() || receipt.preimage()? != preimage {
            return Err(WireError("noncanonical"));
        }
        let key =
            AuthorKey::from_bytes(&receipt.node_key).map_err(|_| WireError("bad_signature"))?;
        verify(
            &key,
            preimage,
            &Signature::from_bytes(signature.try_into().unwrap()),
        )
        .map_err(|_| WireError("bad_signature"))?;
        Ok(Self {
            receipt,
            bytes: bytes.to_vec(),
        })
    }
    pub fn receipt(&self) -> &NodeReceiptV1 {
        &self.receipt
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
