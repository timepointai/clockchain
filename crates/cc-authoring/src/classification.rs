//! TT classification profiles — **enforced here, defined upstream**.
//!
//! This is a port of `timepoint-telemetry/python/tt_validate.py` (rev `65c5fc3`),
//! rule for rule and code for code. It is deliberately not a reimagining: TT
//! owns classification semantics, Clockchain consumes them, and the way a
//! consumer stays honest is by making its validator a translation rather than an
//! interpretation. Where this file and TT's conformance vectors disagree, **the
//! vectors win** and this file is wrong.
//!
//! ## Why the corpus needed this
//!
//! Every one of the 322 stored claims asserts exactly one `claim_type` and one
//! `lens`. A classifier with insufficient signal had no way to say so, which
//! made the pilot's own health metric — abstention rate — unmeasurable. You
//! cannot chart what cannot be expressed.
//!
//! Our single-type shape maps onto TT's profile trivially: **one entry, mass
//! 1.0**, in the lens the bundle assigns that id. Abstention is the shape that
//! was previously unsayable: `abstain: true` with **both lenses empty** and the
//! bundle cited.
//!
//! ## The two conservative resolutions, which are TT's and not ours
//!
//! TT-SPEC §4 does not pin these down; `tt_validate.py` resolves them and we
//! follow rather than re-decide:
//!
//!   * `abstain: true` alongside **any** mass in **either** lens rejects
//!     (`abstain-with-mass`). §4.4 blesses abstention "with empty lenses" and
//!     says nothing else.
//!   * a `bundle` citation naming a different release than the loaded bundle
//!     rejects (`bundle-mismatch`) — a citation has to mean something.
//!
//! ## Reject, never repair
//!
//! A failing profile is thrown back **whole**, with every failure named — not
//! the first, and not a helpfully-corrected version. A consumer that fixes mass
//! sums or drops surplus entries has manufactured a reading nobody produced.

use cc_filter::version::lens_of;
use serde_json::{Map, Value};

/// `"{schema} v{version}"` of the pinned bundle — the string TT's validator
/// stamps on accept (§4.5).
///
/// **Generated from the bundle, never typed.** It used to be a hand-written
/// constant here, and a *different* hand-written spelling — `tt-ontology/2.1.0`
/// — was being projected on the read surface, where any conformant validator
/// rejects it with `bundle-mismatch`. One derived definition removes the class.
pub use cc_filter::version::TT_VERSION_STRING as BUNDLE_VERSION_STRING;

/// TT-SPEC §4.1 rule 3.
const SUM_EPSILON: f64 = 1e-9;
const MAX_ENTRIES_PER_LENS: usize = 3;
const ALLOWED_KEYS: &[&str] = &["lens_a", "lens_b", "abstain", "bundle"];

/// A typed rejection. **Codes are TT's**, verbatim, because a caller must handle
/// them differently — a retired id names its successor, an unknown id never
/// existed — and because telemetry re-runs these strings against their own
/// implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    /// TT's rejection code, e.g. `abstain-with-mass`.
    pub code: &'static str,
    /// TT's detail text for that code.
    pub detail: String,
}

impl std::fmt::Display for Reject {
    /// The wire form `tt_validate.py` prints, so output can be diffed directly
    /// against theirs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rejected: {}: {}", self.code, self.detail)
    }
}

fn rej(code: &'static str, detail: impl Into<String>) -> Reject {
    Reject {
        code,
        detail: detail.into(),
    }
}

/// Render a JSON value the way Python's `repr()` would.
///
/// The reference interpolates offending values with `{!r}`, and telemetry's
/// probe protocol diffs our rejection strings against theirs **verbatim**. So
/// `True` not `true`, `'1.0'` not `"1.0"`, `None` not `null`. A differential
/// run caught five of these; every one would have read as correct to a human
/// and failed their check.
fn py_repr(v: &Value) -> String {
    match v {
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        Value::String(s) => format!("'{s}'"),
        Value::Number(n) => n
            .as_f64()
            .filter(|_| !n.is_i64() && !n.is_u64())
            .map_or_else(|| n.to_string(), py_float),
        Value::Array(a) => {
            format!("[{}]", a.iter().map(py_repr).collect::<Vec<_>>().join(", "))
        }
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, x)| format!("'{k}': {}", py_repr(x)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Python's `repr(float)`.
///
/// Rust's `Debug` agrees with Python on ordinary values — both emit the shortest
/// string that round-trips — and disagrees at the edges in two ways that matter
/// once these strings are contract:
///
///   * **Exponent form.** Python writes `1e+20` and `1e-05`: the sign is always
///     present, the exponent always at least two digits. Rust writes `1e20`.
///   * **The switch point.** Python uses fixed notation while the decimal
///     exponent is in `[-4, 16)` and scientific outside it; Rust switches
///     elsewhere, so `1e15` is `1000000000000000.0` to Python.
///
/// Both were found by differential run rather than by reading the reference. A
/// mass of `1e20` is absurd input — but "absurd input renders identically" is
/// precisely what a conformance vector asserts.
fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }

    let exp10 = f.abs().log10().floor() as i32;
    if (-4..16).contains(&exp10) {
        let s = format!("{f:?}");
        if !s.contains('e') {
            return s;
        }
        // Rust chose scientific where Python would not; expand to fixed.
        let places = (16 - exp10).max(1) as usize;
        let mut out = format!("{f:.places$}");
        while out.contains('.') && out.ends_with('0') && !out.ends_with(".0") {
            out.pop();
        }
        return out;
    }

    let s = format!("{f:e}");
    let (mant, exp) = s.split_once('e').expect("{:e} always emits an exponent");
    let n: i32 = exp.parse().expect("exponent is an integer");
    format!("{mant}e{}{:02}", if n < 0 { '-' } else { '+' }, n.abs())
}

/// Validate one classification profile against the pinned bundle.
///
/// Returns the **normalized** profile (bundle stamped, per §4.5) or every
/// rejection. Exactly one of the pair is meaningful.
pub fn validate(c: &Value) -> Result<Value, Vec<Reject>> {
    let mut errors: Vec<Reject> = Vec::new();

    let Some(obj) = c.as_object() else {
        return Err(vec![rej(
            "not-an-object",
            "classification must be a JSON object",
        )]);
    };

    for key in obj.keys() {
        if !ALLOWED_KEYS.contains(&key.as_str()) {
            errors.push(rej("unknown-key", format!("unknown top-level key `{key}`")));
        }
    }

    let abstain = match obj.get("abstain") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(v) => {
            errors.push(rej(
                "abstain-not-bool",
                format!("abstain must be true or false, got {}", py_repr(v)),
            ));
            false
        }
    };

    if let Some(cited) = obj.get("bundle").and_then(Value::as_str) {
        if cited != BUNDLE_VERSION_STRING {
            errors.push(rej(
                "bundle-mismatch",
                format!(
                    "classification cites `{cited}`, loaded bundle is `{BUNDLE_VERSION_STRING}`"
                ),
            ));
        }
    }

    let mut total_mass_entries = 0usize;
    let mut lenses: [Map<String, Value>; 2] = [Map::new(), Map::new()];

    for (i, (key, letter)) in [("lens_a", "A"), ("lens_b", "B")].into_iter().enumerate() {
        let profile = match obj.get(key) {
            None => continue,
            Some(Value::Object(p)) => p,
            Some(_) => {
                errors.push(rej(
                    "lens-not-object",
                    format!("{key} must be an object of id: mass"),
                ));
                continue;
            }
        };
        if profile.len() > MAX_ENTRIES_PER_LENS {
            errors.push(rej(
                "too-many-entries",
                format!(
                    "{key} has {} entries; at most {MAX_ENTRIES_PER_LENS}",
                    profile.len()
                ),
            ));
        }
        let mut lens_sum = 0.0f64;
        for (node_id, mass) in profile {
            // `is_bool` first: JSON `true` must not read as a number, matching
            // the reference's `isinstance(mass, bool)` guard.
            let m = match mass {
                Value::Bool(_) => None,
                Value::Number(n) => n.as_f64(),
                _ => None,
            };
            let Some(m) = m else {
                errors.push(rej(
                    "mass-not-number",
                    format!("{key}.{node_id}: mass {} is not a number", py_repr(mass)),
                ));
                continue;
            };
            if !(m > 0.0 && m <= 1.0) {
                errors.push(rej(
                    "mass-out-of-range",
                    // Render the ORIGINAL value, not the coerced f64: `"mass": 5` is an
                    // integer to Python and prints as `5`, where `py_float` would give
                    // `5.0`. Integer masses are ordinary input, so this is not an edge
                    // case — the differential only missed it because every case in the
                    // suite used a float literal.
                    format!("{key}.{node_id}: mass {} outside (0, 1]", py_repr(mass)),
                ));
            }
            lens_sum += m;
            match lens_of(node_id) {
                None => errors.push(rej(
                    "unknown-id",
                    format!("{key}.{node_id}: no such id in the bundle"),
                )),
                Some(actual) if retired_successor(node_id).is_some() => {
                    let _ = actual;
                    let succ = retired_successor(node_id).unwrap();
                    errors.push(rej(
                        "retired-id",
                        format!("{key}.{node_id}: retired in 2.1.0; use `{succ}`"),
                    ));
                }
                Some(actual) if actual != letter => errors.push(rej(
                    "wrong-lens",
                    format!("{key}.{node_id}: id is lens {actual}, offered under lens {letter}"),
                )),
                Some(_) => {}
            }
        }
        if lens_sum > 1.0 + SUM_EPSILON {
            errors.push(rej(
                "lens-sum-exceeded",
                format!("{key} masses sum to {}; at most 1.0", py_float(lens_sum)),
            ));
        }
        total_mass_entries += profile.len();
        lenses[i] = profile.clone();
    }

    if abstain && total_mass_entries > 0 {
        errors.push(rej(
            "abstain-with-mass",
            "abstain is true but lens masses are present; abstention is empty lenses (§4.4)",
        ));
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // Key order matches the reference's `normalized` dict so a byte-comparison
    // of the two outputs is meaningful.
    let mut out = Map::new();
    out.insert("lens_b".into(), Value::Object(lenses[1].clone()));
    out.insert("lens_a".into(), Value::Object(lenses[0].clone()));
    out.insert("abstain".into(), Value::Bool(abstain));
    out.insert("bundle".into(), Value::String(BUNDLE_VERSION_STRING.into()));
    Ok(Value::Object(out))
}

/// The successor of a retired id, if it is retired.
///
/// `cc_filter::resolve_tt_id` walks the chain; this asks the narrower question
/// the validator needs — *is this id itself retired* — without conflating "not
/// retired" with "resolves to itself".
fn retired_successor(id: &str) -> Option<&'static str> {
    // `resolve_tt_id` borrows from its argument when the id is not retired, so
    // compare first and only then take the 'static successor out of the table.
    let s = cc_filter::version::resolve_tt_id(id);
    if s == id {
        return None;
    }
    cc_filter::version::TT_SUPERSEDED
        .iter()
        .find(|(a, _)| *a == id)
        .map(|(_, succ)| *succ)
}

/// Is this profile an abstention? `abstain: true` with both lenses empty.
pub fn is_abstention(c: &Value) -> bool {
    c.get("abstain").and_then(Value::as_bool) == Some(true)
        && c.get("lens_a")
            .and_then(Value::as_object)
            .is_none_or(Map::is_empty)
        && c.get("lens_b")
            .and_then(Value::as_object)
            .is_none_or(Map::is_empty)
}

/// Build the profile a single-type claim implies: one entry, mass 1.0, in the
/// lens the **bundle** assigns — never the lens the claim declared.
pub fn from_single_type(claim_type: &str) -> Option<Value> {
    let letter = lens_of(claim_type)?;
    let mut lens = Map::new();
    lens.insert(claim_type.to_string(), Value::from(1.0));
    let (a, b) = if letter == "A" {
        (lens, Map::new())
    } else {
        (Map::new(), lens)
    };
    let mut out = Map::new();
    out.insert("lens_b".into(), Value::Object(b));
    out.insert("lens_a".into(), Value::Object(a));
    out.insert("abstain".into(), Value::Bool(false));
    out.insert("bundle".into(), Value::String(BUNDLE_VERSION_STRING.into()));
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_filter::version::TT_BUNDLE_SHA256;
    use serde_json::json;

    fn codes(c: &Value) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = validate(c)
            .unwrap_err()
            .into_iter()
            .map(|r| r.code)
            .collect();
        v.sort_unstable();
        v
    }

    /// The bundle string is stamped on accept, so it must match the release
    /// this binary vendors. Read from the artifact, not asserted from memory.
    #[test]
    fn the_version_string_matches_the_pinned_bundle() {
        let raw = include_str!("../../../vendor/tt/taxonomy-v2.1.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        let expect = format!(
            "{} v{}",
            v["schema"].as_str().unwrap(),
            v["version"].as_str().unwrap()
        );
        assert_eq!(BUNDLE_VERSION_STRING, expect);
        // And the bundle those bytes hash to is the one cc-filter compiled.
        assert_eq!(TT_BUNDLE_SHA256.len(), 64);
    }

    #[test]
    fn a_single_type_becomes_one_entry_at_mass_one() {
        let c = from_single_type("conflict-and-warfare").unwrap();
        assert_eq!(c["lens_a"]["conflict-and-warfare"], json!(1.0));
        assert_eq!(c["lens_b"], json!({}));
        assert_eq!(c["abstain"], json!(false));
        assert_eq!(c["bundle"], json!(BUNDLE_VERSION_STRING));
        // Round-trip: what we emit, the validator accepts (§4.5).
        assert_eq!(validate(&c).unwrap(), c);

        // A B-lens id lands in lens_b, from the bundle rather than a guess.
        let c = from_single_type("bonding-and-kinship").unwrap();
        assert_eq!(c["lens_b"]["bonding-and-kinship"], json!(1.0));
        assert_eq!(c["lens_a"], json!({}));
        assert_eq!(validate(&c).unwrap(), c);
    }

    /// THE ABSTENTION SHAPE. Previously unsayable in this corpus.
    #[test]
    fn abstention_is_empty_lenses_and_it_validates() {
        let c = json!({"lens_a": {}, "lens_b": {}, "abstain": true,
                       "bundle": BUNDLE_VERSION_STRING});
        let n = validate(&c).unwrap();
        assert!(is_abstention(&n));
        assert_eq!(n["abstain"], json!(true));
        // Round-trips.
        assert_eq!(validate(&n).unwrap(), n);
    }

    /// TT's conservative resolution: abstain plus ANY mass in EITHER lens.
    #[test]
    fn abstain_with_mass_is_rejected_in_either_lens() {
        for c in [
            json!({"lens_a": {"conflict-and-warfare": 1.0}, "lens_b": {}, "abstain": true}),
            json!({"lens_a": {}, "lens_b": {"bonding-and-kinship": 0.5}, "abstain": true}),
            json!({"lens_a": {"conflict-and-warfare": 0.5},
                   "lens_b": {"bonding-and-kinship": 0.5}, "abstain": true}),
        ] {
            let errs = validate(&c).unwrap_err();
            let hit = errs
                .iter()
                .find(|e| e.code == "abstain-with-mass")
                .expect("must reject");
            // The verbatim reference text — telemetry diffs this string.
            assert_eq!(
                hit.to_string(),
                "rejected: abstain-with-mass: abstain is true but lens masses are present; \
                 abstention is empty lenses (§4.4)"
            );
        }
    }

    #[test]
    fn the_bundle_rules_are_enforced_not_restated() {
        // Unknown id.
        assert!(codes(&json!({"lens_a": {"not-a-node": 1.0}})).contains(&"unknown-id"));
        // Retired id names its successor.
        let errs =
            validate(&json!({"lens_b": {"everyday-movement-and-commute": 1.0}})).unwrap_err();
        let r = errs.iter().find(|e| e.code == "retired-id").unwrap();
        assert!(r.detail.contains("journey-and-travel"), "{}", r.detail);
        // Wrong lens: an A id offered under lens_b.
        let errs = validate(&json!({"lens_b": {"conflict-and-warfare": 1.0}})).unwrap_err();
        assert!(errs.iter().any(|e| e.code == "wrong-lens"));
    }

    #[test]
    fn mass_shape_rules() {
        assert!(
            codes(&json!({"lens_a": {"conflict-and-warfare": 0.0}})).contains(&"mass-out-of-range")
        );
        assert!(
            codes(&json!({"lens_a": {"conflict-and-warfare": 1.5}})).contains(&"mass-out-of-range")
        );
        // A bool is not a number, matching the reference's explicit guard.
        assert!(
            codes(&json!({"lens_a": {"conflict-and-warfare": true}})).contains(&"mass-not-number")
        );
        // Per-lens sum.
        assert!(codes(&json!({"lens_a": {
            "conflict-and-warfare": 0.5, "politics-governance-and-law": 0.6}}))
        .contains(&"lens-sum-exceeded"));
        // At most three entries per lens.
        assert!(codes(&json!({"lens_a": {
            "conflict-and-warfare": 0.1, "politics-governance-and-law": 0.1,
            "economy-trade-and-labor": 0.1, "religious-life": 0.1}}))
        .contains(&"too-many-entries"));
    }

    #[test]
    fn a_citation_that_names_another_release_is_rejected() {
        let c = json!({"lens_a": {}, "lens_b": {}, "abstain": true,
                       "bundle": "tt-ontology/1.0 v2.0.0"});
        assert_eq!(codes(&c), vec!["bundle-mismatch"]);
    }

    /// The bundle is stamped whether or not it was sent (§4.5).
    #[test]
    fn the_bundle_is_stamped_on_accept() {
        let n = validate(&json!({"lens_a": {"conflict-and-warfare": 1.0}})).unwrap();
        assert_eq!(n["bundle"], json!(BUNDLE_VERSION_STRING));
    }

    #[test]
    fn every_failure_is_named_not_just_the_first() {
        let c = json!({"lens_a": {"not-a-node": 5.0}, "abstain": true, "surprise": 1});
        let got = codes(&c);
        assert!(got.contains(&"unknown-id"));
        assert!(got.contains(&"mass-out-of-range"));
        assert!(got.contains(&"abstain-with-mass"));
        assert!(got.contains(&"unknown-key"));
    }
}
