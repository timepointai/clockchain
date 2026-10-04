//! `cc-publisher v1`: offline key and Genesis tooling, and a client for the v1
//! node's write and readback routes. Nothing here touches a database; the
//! envelope is built with the cc-core v1 types the node itself decodes.
//! Usage and file formats: `docs/PUBLISHER-V1.md`.
use cc_core::v1::Hash;
use serde_json::Value;

pub mod authority;
pub mod authority_cli;
pub mod authority_node;
pub mod cli;
pub mod genesis;
pub mod key;
pub mod node;
pub mod time;

/// Exactly 64 hex characters (either case) as 32 bytes.
pub fn hex32(s: &str) -> Option<Hash> {
    if s.len() != 64 {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// A 32-byte value as a node may serialize it: 64 hex characters, or serde's
/// form of `[u8; 32]`, an array of 32 integers.
pub fn hash_json(v: &Value) -> Option<Hash> {
    match v {
        Value::String(s) => hex32(s),
        Value::Array(a) if a.len() == 32 => {
            let mut out = [0u8; 32];
            for (o, x) in out.iter_mut().zip(a) {
                *o = u8::try_from(x.as_u64()?).ok()?;
            }
            Some(out)
        }
        _ => None,
    }
}
