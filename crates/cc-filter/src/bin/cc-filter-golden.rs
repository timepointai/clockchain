//! The golden-fixture runner, compiled to whichever target you point it at.
//!
//! This exists so the cross-target claim is settled by comparing two *artifacts*
//! rather than by reasoning about one source tree. Built natively it prints the
//! digest; built for `wasm32-unknown-unknown` it exposes the same digest through
//! a C ABI a host can call, and `tools/wasm-parity.mjs` checks the two agree.
//!
//! It lives in its own crate root rather than inside the library because the
//! library is `#![forbid(unsafe_code)]` and `#[no_mangle]` is exactly the kind of
//! symbol-level footgun that forbid exists to keep out of the consensus path.
//! Nothing here computes anything: every bit comes from `cc_filter::golden`.

use cc_filter::golden::golden_digest;

/// The `i`-th big-endian 32-bit word of the golden digest, or `0` past the end.
///
/// Returned a word at a time so the module needs no linear-memory protocol and
/// therefore no host imports at all — which is the point. A wasm module that
/// imports nothing cannot secretly consult a clock, and "the filter cannot read
/// live time" stops being a code-review promise and becomes a checkable property
/// of the artifact.
#[no_mangle]
pub extern "C" fn cc_filter_golden_digest_word(i: u32) -> u32 {
    let digest = golden_digest();
    let start = (i as usize) * 4;
    match digest.get(start..start + 4) {
        Some(w) => u32::from_be_bytes([w[0], w[1], w[2], w[3]]),
        None => 0,
    }
}

fn main() {
    let digest = golden_digest();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
}
