//! TT kind paths come from the taxonomy `cc-filter` pins, and only the pinned
//! taxonomy bytes are accepted as the label source.
use cc_wasm_verify::tt::{is_pinned_taxonomy, kind_path};

const TAXONOMY: &[u8] = include_bytes!("../../../vendor/tt/taxonomy-v2.1.json");

#[test]
fn subspecies_path_runs_branch_species_subspecies() {
    let p = kind_path("printing-and-publishing");
    assert!(p.valid);
    assert_eq!(p.current, "printing-and-publishing");
    assert_eq!(p.lens, Some("A"));
    assert_eq!(p.path.len(), 3);
    assert_eq!(p.path[2], "printing-and-publishing");
    assert_eq!(p.path[1], "letters-print-and-media");
    // The path agrees with the vendored bundle's own parent links.
    let bundle: serde_json::Value = serde_json::from_slice(TAXONOMY).unwrap();
    let parent = |id: &str| {
        bundle["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == id)
            .unwrap()["parent"]
            .as_str()
            .map(String::from)
    };
    assert_eq!(parent(&p.path[2]).as_deref(), Some(p.path[1].as_str()));
    assert_eq!(parent(&p.path[1]).as_deref(), Some(p.path[0].as_str()));
    assert_eq!(parent(&p.path[0]), None);
}

#[test]
fn unknown_kind_has_no_path_and_retired_kind_names_its_successor() {
    let p = kind_path("test");
    assert!(!p.valid);
    assert!(p.path.is_empty());
    assert_eq!(p.lens, None);
    let r = kind_path("everyday-movement-and-commute");
    assert!(r.valid);
    assert_eq!(r.current, "journey-and-travel");
}

#[test]
fn only_the_pinned_taxonomy_bytes_are_accepted() {
    assert!(is_pinned_taxonomy(TAXONOMY));
    let mut altered = TAXONOMY.to_vec();
    altered.push(b'\n');
    assert!(!is_pinned_taxonomy(&altered));
}
