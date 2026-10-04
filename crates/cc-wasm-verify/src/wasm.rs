//! A minimal C ABI for the browser: no bindings generator, no host imports.
//!
//! The caller allocates input with `cc_alloc`, writes UTF-8 into it, calls an
//! entry point with `(ptr, len)`, then reads `cc_output_len()` bytes of UTF-8
//! JSON at `cc_output_ptr()`. Input is freed by the entry point.
use std::cell::RefCell;

thread_local! {
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn set_output(out: String) -> usize {
    let n = out.len();
    OUTPUT.with(|o| *o.borrow_mut() = out.into_bytes());
    n
}

/// Take ownership of an input buffer from [`cc_alloc`].
///
/// # Safety
/// `ptr` must come from `cc_alloc(len)` and not have been passed here before.
unsafe fn take(ptr: *mut u8, len: usize) -> Box<[u8]> {
    Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len))
}

fn json(v: impl serde::Serialize) -> String {
    serde_json::to_string(&v).expect("plain data serializes")
}

fn error(e: impl std::fmt::Display) -> String {
    json(serde_json::json!({ "error": e.to_string() }))
}

/// Allocate `len` bytes for an input.
#[no_mangle]
pub extern "C" fn cc_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()).cast()
}

#[no_mangle]
pub extern "C" fn cc_output_ptr() -> *const u8 {
    OUTPUT.with(|o| o.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn cc_output_len() -> usize {
    OUTPUT.with(|o| o.borrow().len())
}

/// Input: an [`crate::Input`] as JSON. Output: a [`crate::Report`], or
/// `{"error"}` when the input is not an `Input`.
///
/// # Safety
/// `ptr`/`len` must come from [`cc_alloc`]; the buffer is consumed.
#[no_mangle]
pub unsafe extern "C" fn cc_verify(ptr: *mut u8, len: usize) -> usize {
    let input = take(ptr, len);
    set_output(match serde_json::from_slice::<crate::Input>(&input) {
        Ok(i) => json(crate::verify(&i)),
        Err(e) => error(e),
    })
}

/// Input: a TT kind id. Output: a [`crate::tt::KindPath`].
///
/// # Safety
/// `ptr`/`len` must come from [`cc_alloc`]; the buffer is consumed.
#[no_mangle]
pub unsafe extern "C" fn cc_tt_kind(ptr: *mut u8, len: usize) -> usize {
    let input = take(ptr, len);
    set_output(match std::str::from_utf8(&input) {
        Ok(kind) => json(crate::tt::kind_path(kind)),
        Err(e) => error(e),
    })
}

/// Input: taxonomy file bytes. Output: `{"pinned": bool}`.
///
/// # Safety
/// `ptr`/`len` must come from [`cc_alloc`]; the buffer is consumed.
#[no_mangle]
pub unsafe extern "C" fn cc_taxonomy(ptr: *mut u8, len: usize) -> usize {
    let input = take(ptr, len);
    set_output(json(
        serde_json::json!({ "pinned": crate::tt::is_pinned_taxonomy(&input) }),
    ))
}

/// Output: the verifier's own identity and its stated limits.
#[no_mangle]
pub extern "C" fn cc_about() -> usize {
    set_output(json(serde_json::json!({
        "fold_version": {
            "version": cc_core::v1::rule::FOLD_NUMBER,
            "manifest": hex::encode(cc_core::v1::rule::fold_v1().manifest),
        },
        "ontology": hex::encode(cc_filter::version::TT_TAXONOMY_SHA256),
        "not_recomputed": crate::NOT_RECOMPUTED,
    })))
}
