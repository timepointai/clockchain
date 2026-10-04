//! Verifier unit tests on the recorded synthetic fixture (signed by synthetic
//! `cc-testkit` keys). The untouched fixture verifies; every tampering below
//! must fail the named check. `tests/fixture.rs` proves the fixture is what the
//! real node serves.
use cc_core::v1::rule::{fold_v1, view_commitment};
use cc_core::v1::Signed;
use cc_wasm_verify::rows::CanonicalRows;
use cc_wasm_verify::{hex32, verify, Input, Outcome, Read, Report, Status};
use serde_json::{json, Value};

macro_rules! fixture {
    ($p:literal) => {
        include_str!(concat!("../../../web/explorer/fixtures/synthetic/", $p))
    };
}
const HEALTH: &str = fixture!("health.json");
const SNAPSHOT: &str = fixture!("snapshot.json");
const EXPORT: &str = fixture!("export.json");
const SUBJECT_A: &str =
    fixture!("subjects/3747936fc819642242de14b93f084f0e4f498cabb05ec218ac20653ff06d00d1.json");
const PROSE_CURRENT: &str = fixture!(
    "revisions/30bbb55f88a082d6304e437b621f990911e668bb541875229707611a7b1b2661/prose.json"
);
const SUPPORT: &str = fixture!("support/3747936fc819642242de14b93f084f0e4f498cabb05ec218ac20653ff06d00d1-5c0755bae674aad41b123247015d920f7ed4af25d9dd4fba7f824fe0a51e92fb.json");

fn input() -> Input {
    Input {
        health: HEALTH.into(),
        snapshot: SNAPSHOT.into(),
        export: Some(EXPORT.into()),
        reads: vec![
            read("subject", SUBJECT_A),
            read("prose", PROSE_CURRENT),
            read("support", SUPPORT),
        ],
    }
}
fn read(kind: &str, body: &str) -> Read {
    Read {
        kind: kind.into(),
        body: body.into(),
    }
}
fn parse(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}
/// Apply `f` to a fixture document.
fn edit(s: &str, f: impl FnOnce(&mut Value)) -> String {
    let mut v = parse(s);
    f(&mut v);
    v.to_string()
}
fn snapshot(f: impl FnOnce(&mut Value)) -> Report {
    verify(&Input {
        snapshot: edit(SNAPSHOT, f),
        ..input()
    })
}
fn health(f: impl FnOnce(&mut Value)) -> Report {
    verify(&Input {
        health: edit(HEALTH, f),
        ..input()
    })
}
fn export(f: impl FnOnce(&mut Value)) -> Report {
    verify(&Input {
        export: Some(edit(EXPORT, f)),
        ..input()
    })
}
/// `name` failed, and so did the whole report.
#[track_caller]
fn fails(r: &Report, name: &str) {
    assert_eq!(r.status(name), Some(Status::Fail), "{name}: {r:#?}");
    assert_eq!(r.outcome, Outcome::Failed);
}
fn row_index(state: &str) -> usize {
    parse(SNAPSHOT)["rows"]
        .as_array()
        .unwrap()
        .iter()
        .position(|r| r["state"] == state)
        .unwrap()
}

#[test]
fn untouched_fixture_verifies_every_check() {
    let r = verify(&input());
    assert_eq!(r.outcome, Outcome::Verified, "{r:#?}");
    let names: Vec<_> = r.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "health",
            "fold_version",
            "filter_version",
            "snapshot",
            "snapshot_rule",
            "canonical_form",
            "event_ids",
            "corpus_digest",
            "view_commitment",
            "signatures",
            "read:subject",
            "read:prose",
            "read:support",
        ]
    );
    assert_eq!(r.recomputed.events, 9);
    assert_eq!(r.recomputed.signatures, 9);
    let s = parse(SNAPSHOT);
    assert_eq!(r.recomputed.commitment.as_deref(), s["commitment"].as_str());
    assert_eq!(
        r.recomputed.corpus_digest.as_deref(),
        s["corpus_digest"].as_str()
    );
    assert!(r.not_recomputed[0].starts_with("The fold itself."));
}

#[test]
fn without_signed_bytes_signatures_are_not_checked_and_not_passed() {
    let r = verify(&Input {
        export: None,
        ..input()
    });
    assert_eq!(r.status("signatures"), Some(Status::NotChecked));
    assert_eq!(r.outcome, Outcome::Partial);
    assert_eq!(r.recomputed.signatures, 0);
}

#[test]
fn tampered_signature_fails() {
    let r = export(|m| {
        let e = m["envelopes"][3].as_str().unwrap();
        let last = u8::from_str_radix(&e[e.len() - 2..], 16).unwrap() ^ 1;
        m["envelopes"][3] = format!("{}{last:02x}", &e[..e.len() - 2]).into();
    });
    fails(&r, "signatures");
    assert!(r
        .check("signatures")
        .unwrap()
        .detail
        .contains("bad_signature"));
    assert_eq!(r.recomputed.signatures, 0);
}

#[test]
fn validly_signed_envelope_that_is_not_the_served_row_fails() {
    // Re-signed by a key outside the fixture: a valid signature, another event.
    let r = export(|m| {
        let bytes = hex::decode(m["envelopes"][0].as_str().unwrap()).unwrap();
        let e = Signed::decode(&bytes).unwrap().envelope().clone();
        let other = Signed::sign(&cc_core::SecretKey::from_seed([99; 32]), e).unwrap();
        m["envelopes"][0] = hex::encode(other.bytes()).into();
    });
    fails(&r, "signatures");
}

#[test]
fn export_missing_an_envelope_fails() {
    fails(
        &export(|m| {
            m["envelopes"].as_array_mut().unwrap().pop();
        }),
        "signatures",
    );
}

#[test]
fn export_naming_another_commitment_fails() {
    fails(&export(|m| m["commitment"][0] = json!(0)), "signatures");
}

#[test]
fn tampered_row_reading_fails_the_commitment_only() {
    // A projection reading the fold produced, not an envelope: ids and the
    // corpus still verify, the commitment does not.
    let i = row_index("pending");
    let r = snapshot(|s| s["rows"][i]["reason"] = "ancestor".into());
    assert_eq!(r.status("event_ids"), Some(Status::Pass));
    assert_eq!(r.status("corpus_digest"), Some(Status::Pass));
    fails(&r, "view_commitment");
    // A read cross-checked against a snapshot that did not verify fails too.
    fails(&r, "read:subject");
}

#[test]
fn tampered_row_state_fails_the_commitment() {
    let i = row_index("invalid");
    fails(
        &snapshot(|s| s["rows"][i]["state"] = "head".into()),
        "view_commitment",
    );
}

#[test]
fn tampered_envelope_fails_its_event_id() {
    let i = row_index("head");
    let r = snapshot(|s| s["rows"][i]["envelope"]["author"][0] = json!(0));
    fails(&r, "event_ids");
    fails(&r, "corpus_digest");
    fails(&r, "view_commitment");
}

#[test]
fn dropped_row_fails_the_corpus_digest() {
    let r = snapshot(|s| {
        s["rows"].as_array_mut().unwrap().remove(0);
    });
    assert_eq!(r.status("event_ids"), Some(Status::Pass));
    fails(&r, "corpus_digest");
}

#[test]
fn reordered_rows_fail_the_event_ids() {
    fails(
        &snapshot(|s| s["rows"].as_array_mut().unwrap().swap(0, 1)),
        "event_ids",
    );
}

#[test]
fn reordered_collection_is_not_repaired() {
    // Edges are committed in id order; a reordering re-encodes differently.
    fails(
        &snapshot(|s| s["edges"].as_array_mut().unwrap().swap(0, 1)),
        "view_commitment",
    );
}

#[test]
fn served_commitment_or_digest_that_differs_fails() {
    fails(
        &snapshot(|s| s["commitment"] = "00".repeat(32).into()),
        "view_commitment",
    );
    fails(
        &snapshot(|s| s["corpus_digest"] = "00".repeat(32).into()),
        "corpus_digest",
    );
}

#[test]
fn unknown_fields_fail() {
    fails(&snapshot(|s| s["rows"][0]["note"] = "x".into()), "snapshot");
    fails(&snapshot(|s| s["instance"] = "x".into()), "snapshot");
    // Inside an envelope the typed decoder ignores it; the re-encoding check does not.
    fails(
        &snapshot(|s| s["rows"][0]["envelope"]["note"] = "x".into()),
        "canonical_form",
    );
}

#[test]
fn snapshot_naming_another_rule_fails() {
    fails(
        &snapshot(|s| s["rule"]["filter_version"] = "00".repeat(32).into()),
        "snapshot_rule",
    );
}

#[test]
fn served_identity_must_recompute_to_filter_version() {
    fails(
        &health(|h| {
            h["curators"].as_array_mut().unwrap().pop();
        }),
        "filter_version",
    );
    fails(&health(|h| h["max_hops"] = 5.into()), "filter_version");
    fails(
        &health(|h| h["filter_version"] = "00".repeat(32).into()),
        "filter_version",
    );
    // Unsorted curators are not a governed identity.
    fails(
        &health(|h| h["curators"].as_array_mut().unwrap().swap(0, 1)),
        "filter_version",
    );
    fails(
        &health(|h| h["fold_version"]["manifest"] = "00".repeat(32).into()),
        "fold_version",
    );
    fails(&health(|h| h["ledger"] = "v0".into()), "health");
}

#[test]
fn reads_must_agree_with_the_verified_snapshot() {
    let with = |kind: &str, body: String| {
        verify(&Input {
            reads: vec![read(kind, &body)],
            ..input()
        })
    };
    fails(
        &with(
            "subject",
            edit(SUBJECT_A, |v| v["state"] = "contested".into()),
        ),
        "read:subject",
    );
    fails(
        &with(
            "subject",
            edit(SUBJECT_A, |v| v["revision"]["body"][0] = json!(0)),
        ),
        "read:subject",
    );
    fails(
        &with(
            "prose",
            edit(PROSE_CURRENT, |v| v["prose"] = "Altered.".into()),
        ),
        "read:prose",
    );
    fails(
        &with(
            "support",
            edit(SUPPORT, |v| v["commitment"] = "00".repeat(32).into()),
        ),
        "read:support",
    );
    fails(&with("unheard-of", SUPPORT.into()), "read:unheard-of");
}

/// The mirror types reproduce the ledger's pinned canonical rows byte for
/// byte, and the pinned commitment from them.
#[test]
fn mirror_reproduces_the_pinned_ledger_rows_vector() {
    let pinned = include_bytes!("../../cc-ledger/tests/vectors/v1-view-rows.json");
    let rows: CanonicalRows = serde_json::from_slice(pinned).unwrap();
    assert!(rows.bytes() == pinned, "mirror re-encoding differs");
    let v: std::collections::BTreeMap<_, _> =
        include_str!("../../cc-ledger/tests/vectors/v1-view.txt")
            .lines()
            .map(|l| l.split_once(' ').unwrap())
            .collect();
    let commitment = view_commitment(
        &fold_v1(),
        hex32(v["filter_version"]).unwrap(),
        hex32(v["corpus_digest"]).unwrap(),
        &rows.bytes(),
    );
    assert_eq!(hex::encode(commitment), v["view_commitment"]);
}
