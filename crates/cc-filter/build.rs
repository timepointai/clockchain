//! Bake the TT bundle's id set into the binary at build time.
//!
//! `cc-filter` depends on `cc-core`, `sha2` and `thiserror` and nothing else: it
//! does no I/O, reads no clock, and builds to wasm with an empty host-import
//! table. That is a property worth keeping, so the bundle is parsed HERE, at
//! build time, and emitted as plain `&'static str` tables. `serde_json` is a
//! build-dependency only and never reaches the artifact.
//!
//! Two things come out of it, and both close a measured gap:
//!
//!   TT_IDS         — every valid node id. Lets admissibility distinguish a
//!                    typo'd id (not a real question about the world) from a
//!                    valid-but-undeclared one (a real question this corpus
//!                    cannot answer). Identical silence for both is the
//!                    gap/finding collapse; telemetry's Policy 2.
//!   TT_SUPERSEDED  — retired id -> successor, for resolve-on-read. Trivial
//!                    while nothing we use is retired, which is only true now.
//!   TT_LENS        — id -> lens ("A" or "B"). A claim declaring a lens its own
//!                    type does not carry is not a judgement call: the bundle
//!                    settles it, so admission can refuse rather than guess.
//!   TT_BRIDGES     — B-lens action -> (relation, A-lens event). The derivation
//!                    a shadow walks. 26 of them against 70 B nodes, so MOST B
//!                    nodes have NO bridge — that absence is a fact to type,
//!                    never a zero to invent.

// `std::env::var` is disallowed crate-wide, because a verdict must depend on
// the events alone and not the environment. That rule is correct and stays.
// It does not reach here: a build script runs at BUILD time and no part of it
// is compiled into the artifact, so reading OUT_DIR cannot influence a verdict.
// Exempted narrowly, at the one call, rather than by relaxing the lint.
#![allow(clippy::disallowed_methods)]

use std::{env, fs, path::Path};

fn main() {
    let bundle = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/tt/taxonomy-v2.1.json"
    );
    println!("cargo:rerun-if-changed={bundle}");
    let raw = fs::read_to_string(bundle).expect("the vendored TT bundle must be readable");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("the bundle must be JSON");
    let nodes = v["nodes"]
        .as_array()
        .expect("the bundle must carry a nodes array");

    let mut ids: Vec<&str> = Vec::with_capacity(nodes.len());
    let mut superseded: Vec<(&str, &str)> = Vec::new();
    let mut lens: Vec<(&str, &str)> = Vec::with_capacity(nodes.len());
    let mut parent: Vec<(&str, &str)> = Vec::with_capacity(nodes.len());
    for n in nodes {
        let id = n["id"].as_str().expect("every node has an id");
        ids.push(id);
        if let Some(succ) = n.get("superseded_by").and_then(|s| s.as_str()) {
            superseded.push((id, succ));
        }
        lens.push((id, n["lens"].as_str().expect("every node declares a lens")));
        if let Some(p) = n.get("parent").and_then(|p| p.as_str()) {
            parent.push((id, p));
        }
    }

    // Bridges are the B -> A derivation. Keyed by the ACTION (the B node),
    // because that is the direction a shadow is walked: a claim classified as
    // human action asks "what recorded event is this, at scale?".
    // The event is OPTIONAL and its absence is load-bearing: three bridges carry
    // `relation: "unrecorded"` with a null event, which is the bundle asserting
    // that this action leaves no public-event trace. That is a RECORDED absence
    // and it is not the same fact as "no bridge is listed for this action".
    // Flattening the two would rebuild, inside the shadow derivation, exactly
    // the gap/finding collapse the id table exists to prevent.
    let mut bridges: Vec<(&str, &str, Option<&str>)> = v["bridges"]
        .as_array()
        .expect("the bundle must carry a bridges array")
        .iter()
        .map(|b| {
            (
                b["action"].as_str().expect("a bridge has an action"),
                b["relation"].as_str().expect("a bridge has a relation"),
                b["event"].as_str(),
            )
        })
        .collect();
    bridges.sort_unstable();
    // Sorted so the generated table can be binary-searched, and so a bundle
    // whose node order changes but whose content does not produces identical
    // output — the file is an input to a hash a verdict commits to.
    ids.sort_unstable();
    superseded.sort_unstable();
    lens.sort_unstable();
    parent.sort_unstable();

    // The sha of the bytes THIS binary was built against. A claim declares the
    // bundle it was validated under; without this the comparison would be
    // against a string someone typed, which is a config echo and not a check.
    let bundle_sha = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(raw.as_bytes()))
    };

    // The citation TT's own validator stamps and accepts: "{schema} v{version}".
    // GENERATED, never typed. A hand-written copy of this string was projected
    // on the read surface as "tt-ontology/2.1.0" — plausible, wrong, and
    // rejected by any conformant validator with `bundle-mismatch`.
    let version_string = format!(
        "{} v{}",
        v["schema"].as_str().expect("the bundle names its schema"),
        v["version"].as_str().expect("the bundle names its version"),
    );

    let mut out = String::new();
    out.push_str("// @generated by build.rs from vendor/tt/taxonomy-v2.1.json — do not edit.\n");
    out.push_str(&format!(
        "/// sha256 of the exact bundle bytes compiled into this binary.\n\
         pub const TT_BUNDLE_SHA256: &str = {bundle_sha:?};\n\n\
         /// The canonical TT citation — `\"{{schema}} v{{version}}\"` — as TT's own\n\
         /// validator stamps it on accept (§4.5). Derived from the bundle, so it\n\
         /// cannot drift from the release it names.\n\
         pub const TT_VERSION_STRING: &str = {version_string:?};\n\n"
    ));
    out.push_str(&format!(
        "/// Every valid TT node id, sorted. {} of them.\n\
         pub const TT_IDS: &[&str] = &[\n",
        ids.len()
    ));
    for id in &ids {
        out.push_str(&format!("    {id:?},\n"));
    }
    out.push_str("];\n\n");
    out.push_str(
        "/// Retired id -> its successor, sorted by the retired id.\n\
         pub const TT_SUPERSEDED: &[(&str, &str)] = &[\n",
    );
    for (a, b) in &superseded {
        out.push_str(&format!("    ({a:?}, {b:?}),\n"));
    }
    out.push_str("];\n\n");

    out.push_str(&format!(
        "/// Node id -> its lens, sorted by id. {} entries.\n\
         pub const TT_LENS: &[(&str, &str)] = &[\n",
        lens.len()
    ));
    for (id, l) in &lens {
        out.push_str(&format!("    ({id:?}, {l:?}),\n"));
    }
    out.push_str("];\n\n");

    out.push_str(&format!(
        "/// Node id -> its parent id, sorted by id. {} entries; branches have no parent.\n\
         pub const TT_PARENT: &[(&str, &str)] = &[\n",
        parent.len()
    ));
    for (id, p) in &parent {
        out.push_str(&format!("    ({id:?}, {p:?}),\n"));
    }
    out.push_str("];\n\n");

    out.push_str(&format!(
        "/// B-lens action -> (relation, optional A-lens event), sorted by action.\n\
         /// {} of them against {} B-lens nodes, so most B nodes are unlisted; and a\n\
         /// listed bridge may still carry no event (`relation: \"unrecorded\"`).\n\
         pub const TT_BRIDGES: &[(&str, &str, Option<&str>)] = &[\n",
        bridges.len(),
        lens.iter().filter(|(_, l)| *l == "B").count()
    ));
    for (a, r, e) in &bridges {
        let ev = match e {
            Some(x) => format!("Some({x:?})"),
            None => "None".to_string(),
        };
        out.push_str(&format!("    ({a:?}, {r:?}, {ev}),\n"));
    }
    out.push_str("];\n");

    let dest = Path::new(&env::var("OUT_DIR").unwrap()).join("tt_bundle.rs");
    fs::write(dest, out).expect("write the generated bundle table");
}
