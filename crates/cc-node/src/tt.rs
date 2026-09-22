//! The TT layer, **derived at read time from what the chain already stores**.
//!
//! Nothing here is minted. The envelope hash and the Lens-B shadow are pure
//! functions of fields that are already in `claim_bodies`, so closing TT
//! conformance gaps 3 and 4 required no re-mint and no change to any stored
//! body — which is why the corpus's identities are untouched by this file.
//!
//! Two upstream artifacts do the work and neither is reimplemented here:
//!
//!   * **`tt-core`** (pinned rev) computes `content_hash`. It canonicalises per
//!     RFC 8785 and digests exactly `{label, occurs_at, participants}`. We do
//!     not canonicalise anything ourselves — a second JCS implementation is a
//!     second chance to disagree about bytes a hash commits to.
//!   * **`cc-filter`'s baked bundle tables** answer the bridge question. Those
//!     come from the vendored artifact this binary byte-checks.
//!
//! ## Two words that both say "source", on different axes
//!
//! A reader meets `classification_source` twice and they are not the same field:
//!
//!   * **Stored, on the claim body** — `"independent"` or `"derived"`. This says
//!     **HOW the reading was produced**: a separate classifier call, or a copy of
//!     `claim_type`. The admission gate reads it, because a derived profile that
//!     disagrees with its own headline type is corruption while an independent
//!     one is two readers disagreeing.
//!   * **Projected, on the read surface** — `"stored"` or `"derived from
//!     claim_type at mass 1.0"`. This says **THAT the reading was recorded
//!     rather than computed at read time**, so a reader is never told a
//!     classification was on the claim when this process built it.
//!
//! Different questions, deliberately: *how was it made* and *was it kept*. A
//! claim can be `independent` in storage and `stored` at the surface — in fact
//! every pilot claim is, which is the pairing worth understanding before the
//! words look like drift.
//!
//! ## The frozen renderings
//!
//! Agreed with telemetry before either side built anything, and pre-registered
//! by them with expected digests:
//!
//! | field | from | rendering |
//! |---|---|---|
//! | `label` | the claim's `title` | verbatim |
//! | `occurs_at` | the claim's `year` | unpadded decimal string, leading `-` for BCE |
//! | `participants` | — | always `[]` |
//!
//! **`participants: []` is true of the record, not a placeholder.** Our entities
//! *are* the events — `canonical_name` holds "Battle of Kadesh" — so a claim
//! references no actors at all. `participants: [subject]` would assert that the
//! Battle of Kadesh attended itself. TT ships a conformance vector for exactly
//! this shape, grounded "no participants recorded".
//!
//! **If participants are ever backfilled, `content_hash` changes** — correctly,
//! since it would be a new payload — and that lands as a visible migration,
//! never an in-place rewrite.

use cc_filter::version::{lens_of, Bridge};
use serde_json::{json, Value};

/// The Lens-B shadow: what the record keeps of a human action.
///
/// **Three states, and the two absences are different facts.** Collapsing them
/// would rebuild the gap/finding collapse one level below where `is_valid_tt_id`
/// closes it, so they stay distinct all the way to the wire.
pub fn shadow_of(claim_type: &str) -> Value {
    match lens_of(claim_type) {
        // Only Lens B casts a shadow into Lens A. An A-lens claim is already
        // what the record kept.
        Some("A") => json!({"applicable": false, "reason": "claim is Lens A"}),
        None => json!({"applicable": false, "reason": "claim type not in the bundle"}),
        _ => match cc_filter::version::bridge_of(claim_type) {
            Bridge::To { relation, event } => json!({
                "applicable": true,
                "state": "derived",
                "relation": relation,
                "event": event,
                "event_lens": lens_of(event),
            }),
            // The bundle LISTS this action and states it leaves no public
            // trace. An asserted absence — a claim about the world.
            Bridge::Unrecorded => json!({
                "applicable": true,
                "state": "unrecorded",
                "relation": "unrecorded",
                "event": Value::Null,
                "meaning": "the bundle asserts this action leaves no trace in the public record",
            }),
            // The bundle says nothing about this action. A gap in the data, not
            // a claim about the world.
            Bridge::Unlisted => json!({
                "applicable": true,
                "state": "unlisted",
                "relation": Value::Null,
                "event": Value::Null,
                "meaning": "the bundle lists no bridge for this action; it does not say there is none",
            }),
        },
    }
}

/// The §4 classification profile a stored single-type reading implies:
/// **one entry at mass 1.0**, in the lens the *bundle* assigns, `abstain: false`,
/// bundle cited.
///
/// Projected when the stored body carries no `classification` of its own — which
/// is every claim minted before the field existed. The alternative was leaving
/// the field `null`, which telemetry caught: per the contract a stored reading
/// surfaces as its §4 form, or the field is absent with a documented meaning.
/// **`null` is neither** — it reads as "there is no reading", when in fact there
/// is one and it is a confident single type.
///
/// `None` only when the claim type is not a bundle node at all, which the
/// admission gate already refuses at the write path.
pub fn classification_from_claim_type(claim_type: &str) -> Option<Value> {
    let letter = lens_of(claim_type)?;
    let entry = json!({ claim_type: 1.0 });
    let (a, b) = if letter == "A" {
        (entry, json!({}))
    } else {
        (json!({}), entry)
    };
    Some(json!({
        "lens_b": b,
        "lens_a": a,
        "abstain": false,
        "bundle": cc_filter::version::TT_VERSION_STRING,
    }))
}

/// The TT envelope payload for a claim, under the frozen renderings.
pub fn payload(title: &str, year: i64) -> Value {
    json!({
        "label": title,
        "occurs_at": year.to_string(),
        "participants": [],
    })
}

/// `content_hash` for a claim: `"sha256:" + hex`, computed by **`tt-core`**.
pub fn content_hash(title: &str, year: i64) -> Result<String, String> {
    tt_core::content_hash(&payload(title, year)).map_err(|e| e.to_string())
}

/// The exact bytes the hash digests, so a reader can recompute without trusting
/// our rendering. Telemetry asked for the payload alongside the hash precisely
/// so verification does not depend on our description of it.
pub fn content_canonical(title: &str, year: i64) -> Result<String, String> {
    tt_core::content_canonical(&payload(title, year)).map_err(|e| e.to_string())
}

// ===========================================================================
// Edge TT context — DERIVED, never a new edge type
// ===========================================================================

/// The pinned bundle, parsed once. `tt-core` owns the parse and the metric.
fn bundle() -> &'static tt_core::Bundle {
    static B: std::sync::OnceLock<tt_core::Bundle> = std::sync::OnceLock::new();
    B.get_or_init(|| {
        tt_core::Bundle::load_from_str(include_str!("../../../vendor/tt/taxonomy-v2.1.json"))
            .expect("the vendored bundle parses; cc-filter byte-checks the same file")
    })
}

/// One id as the mass distribution `distance` expects.
fn point(id: &str) -> std::collections::BTreeMap<String, f64> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(id.to_string(), 1.0);
    m
}

/// What the bundle says about an edge, derived from its endpoints' claim types.
///
/// **This is an annotation, never a type.** TT labels *nodes*; it defines no
/// event-to-event vocabulary, so `Causation` and `Influence` stay ours and TT's
/// four bridge words — `constitutes`, `scales-up-to`, `recorded-as`,
/// `unrecorded` — are **barred as edge type names**. An instance edge called
/// "scales-up-to" would claim semantics TT never defined. Those words appear
/// below only *inside* `bridge` , naming a bundle fact about the endpoint pair.
///
/// Three things are derivable and all three are:
///
///   * **the endpoint type pair and its lenses**, with the lens crossing made
///     explicit — 22 of 174 edges join a recorded event to a human action and
///     nothing surfaced it;
///   * **`type_distance`** — named that, never bare "distance", because the
///     number is the distance between the endpoints' **kinds in the taxonomy**,
///     not a similarity between the events. A reader will misread
///     `distance: 1.6` as event-relatedness unless the name refuses the reading;
///   * **bridge-relatedness**, for cross-lens pairs: is `(action, event)`
///     literally a bundle bridge? With its direction, because a B→A edge runs
///     *with* the bridge grain and an A→B edge runs against it — a different
///     and interesting object, surfaced, claimed nothing about.
///
/// **Source note, carried in the output.** These types come from `claim_type`,
/// the headline axis — and for 29 claims that headline coexists with a *stored
/// abstention*, where a classifier declined to read the claim. Deriving edge
/// context from the headline is legitimate: it is bundle-valid and it is what
/// exists. But the projection names its source field so nobody reads a
/// `type_distance` as "the classifier read both endpoints" when one declined.
pub fn edge_context(src_type: Option<&str>, dst_type: Option<&str>) -> Value {
    let (Some(s), Some(d)) = (src_type, dst_type) else {
        return json!({
            "state": "untyped",
            "reason": "an endpoint has no claim_type; nothing is derivable and \
                       no default is substituted",
        });
    };
    let (Some(sl), Some(dl)) = (lens_of(s), lens_of(d)) else {
        return json!({
            "state": "untyped",
            "reason": "an endpoint's claim_type is not a node in the pinned bundle",
            "src_claim_type": s,
            "dst_claim_type": d,
        });
    };

    let crossing = sl != dl;
    // Across lenses the bundle graph is DISCONNECTED — A and B are disjoint
    // components — so the shortest path is genuinely infinite. That is a real
    // answer, not a failure, and it is exactly why a cross-lens edge's only
    // meaningful taxonomic label is the bridge.
    let dist = tt_core::distance(bundle(), &point(s), &point(d));
    let type_distance = match dist {
        Some(v) if v.is_finite() => json!({
            "value": v,
            "metric": "tt-metric v2.1.0, design-constant weights",
            "note": "distance between the endpoints' TYPES in the taxonomy — \
                     not a similarity between the events",
            "caveat": "the 1.0 hierarchy / 1.6 lateral weights are design \
                       choices, not values fitted to data (TT README)",
        }),
        _ => json!({
            "value": Value::Null,
            "state": "unreachable",
            "reason": "the two lenses are disjoint components of the bundle \
                       graph; no path exists between an A-lens and a B-lens \
                       type. A real answer, not a missing one.",
        }),
    };

    // Bridge-relatedness: is this endpoint pair literally a bundle bridge?
    // Only meaningful across lenses, and the direction is the interesting part.
    let bridge = if !crossing {
        json!({"applicable": false, "reason": "same lens; bridges cross lenses"})
    } else {
        let (action, event, with_grain) = if sl == "B" {
            (s, d, true)
        } else {
            (d, s, false)
        };
        match cc_filter::version::bridge_of(action) {
            Bridge::To {
                relation,
                event: target,
            } if target == event => json!({
                "applicable": true,
                "bridge_related": true,
                "relation": relation,
                "action": action,
                "event": event,
                "direction": if with_grain { "with the bridge grain (B -> A)" }
                             else { "against the bridge grain (A -> B)" },
            }),
            Bridge::To {
                relation,
                event: target,
            } => json!({
                "applicable": true, "bridge_related": false,
                "reason": "the action IS bridged, but to a different event",
                "action": action, "bridges_to": target, "relation": relation,
                "edge_endpoint": event,
            }),
            Bridge::Unrecorded => json!({
                "applicable": true, "bridge_related": false,
                "reason": "the bundle asserts this action leaves no public trace",
                "action": action,
            }),
            Bridge::Unlisted => json!({
                "applicable": true, "bridge_related": false,
                "reason": "the bundle lists no bridge for this action; it does \
                           not say there is none",
                "action": action,
            }),
        }
    };

    json!({
        "state": "derived",
        "src_claim_type": s, "src_lens": sl,
        "dst_claim_type": d, "dst_lens": dl,
        "lens_crossing": crossing,
        "type_distance": type_distance,
        "bridge": bridge,
        "derived_from": "claim_type (the headline axis). 29 claims carry a \
                         stored abstention alongside their headline type, so a \
                         type_distance does not imply a classifier read either \
                         endpoint.",
        "not_an_edge_type": "the edge's own relation is Causation/Influence, \
                             which is Clockchain's axis. TT labels nodes and \
                             defines no event-to-event vocabulary.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three digests telemetry pre-registered, before either side built.
    ///
    /// **This proves the hash FUNCTION is stable, not that the corpus still
    /// contains these claims.** It computes from the title and year literals
    /// below, so a hand-correction that changed an anchor's title or year would
    /// leave this passing while the pre-registration quietly stopped being about
    /// the corpus it was registered against — a correct digest describing a claim
    /// that no longer exists. Telemetry found the gap; the census made it
    /// non-hypothetical, since two of these three (End of Apartheid, Mani) are
    /// among the five entities corrected by hand, and four of nine
    /// hand-corrections left no record at all.
    ///
    /// The other half lives in `ops/check-anchors.py`, which **parses these
    /// tuples** rather than copying them and asserts the corpus still holds
    /// them. Neither check substitutes for the other:
    ///
    /// ```text
    /// this test            the hash function is stable given (title, year)
    /// check-anchors.py     the corpus still contains those (title, year)
    /// together             the pre-registered digest describes a live claim
    /// ```
    ///
    /// If you change a tuple here, `check-anchors.py` reads the new one — so do
    /// not reconcile a moved anchor by editing a literal to match the corpus.
    #[test]
    fn the_pre_registered_hashes_reproduce() {
        for (title, year, want) in [
            (
                "Fall of Constantinople",
                1453,
                "sha256:10449f0ec6e0266edb6c5e3fb97504617a0e31ff13eb7bc268f275d57730d2a1",
            ),
            (
                "End of Apartheid",
                1994,
                "sha256:bda672b1ba35b396c1830bcb030fa059cdcd031023315a8bf56054dde3714021",
            ),
            (
                "Mani Is Executed for Heresy",
                276,
                "sha256:087cdc1b0b948d1fc8acf6a94b4ba88dc04360faf220330fbcf84e12c58f7738",
            ),
        ] {
            assert_eq!(content_hash(title, year).unwrap(), want, "{title}");
        }
    }

    /// A BCE year renders with a leading minus and no padding.
    #[test]
    fn the_year_rendering_is_frozen() {
        assert_eq!(payload("x", -1274)["occurs_at"], json!("-1274"));
        assert_eq!(payload("x", 276)["occurs_at"], json!("276"));
        assert_eq!(payload("x", 0)["occurs_at"], json!("0"));
        assert_eq!(
            content_canonical("Fall of Constantinople", 1453).unwrap(),
            r#"{"label":"Fall of Constantinople","occurs_at":"1453","participants":[]}"#
        );
    }

    /// Telemetry's mutation check: one character changes the hash.
    #[test]
    fn a_one_character_change_changes_the_hash() {
        let a = content_hash("Fall of Constantinople", 1453).unwrap();
        let b = content_hash("Fall of Constantinopla", 1453).unwrap();
        assert_ne!(a, b, "derivation, not copying");
        // The year is covered too.
        assert_ne!(a, content_hash("Fall of Constantinople", 1454).unwrap());
    }

    /// Telemetry's twin check: classification lives OUTSIDE the hash, so the
    /// same payload under different readings has the same content_hash.
    #[test]
    fn classification_does_not_enter_the_hash() {
        // Same label and year; the claim_type is not a payload field at all.
        let a = content_hash("Fall of Constantinople", 1453).unwrap();
        let b = content_hash("Fall of Constantinople", 1453).unwrap();
        assert_eq!(a, b);
        // And the payload carries exactly three keys — nothing classification-shaped.
        let p = payload("Fall of Constantinople", 1453);
        let keys: Vec<&String> = p.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["label", "occurs_at", "participants"]);
    }

    /// The citation must be the one TT's validator accepts.
    ///
    /// A hand-written `"tt-ontology/2.1.0"` was projected on the read surface.
    /// It is plausible, it is wrong, and any conformant validator rejects it
    /// with `bundle-mismatch` — so a reader who trusted the projection and
    /// pasted it got refused. The string is now generated from the bundle.
    #[test]
    fn the_projected_citation_is_the_one_tt_accepts() {
        assert_eq!(
            cc_filter::version::TT_VERSION_STRING,
            "tt-ontology/1.0 v2.1.0"
        );
        // It is not the internal spelling that was being served.
        assert_ne!(cc_filter::version::TT_VERSION_STRING, "tt-ontology/2.1.0");
        // And it is derived, so a bundle bump moves it rather than stranding it.
        let raw = include_str!("../../../vendor/tt/taxonomy-v2.1.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(
            cc_filter::version::TT_VERSION_STRING,
            format!(
                "{} v{}",
                v["schema"].as_str().unwrap(),
                v["version"].as_str().unwrap()
            )
        );
    }

    /// A stored single-type reading surfaces as its §4 form, never as `null`.
    #[test]
    fn a_single_type_projects_as_a_real_profile() {
        let c = classification_from_claim_type("siege-and-sack").unwrap();
        assert_eq!(c["lens_a"]["siege-and-sack"], json!(1.0));
        assert_eq!(c["lens_b"], json!({}));
        assert_eq!(c["abstain"], json!(false));
        assert_eq!(c["bundle"], json!("tt-ontology/1.0 v2.1.0"));

        // B-lens lands in lens_b, from the bundle rather than a guess.
        let c = classification_from_claim_type("writing-and-composition").unwrap();
        assert_eq!(c["lens_b"]["writing-and-composition"], json!(1.0));
        assert_eq!(c["lens_a"], json!({}));

        // Not a bundle node: no profile, rather than an invented one.
        assert!(classification_from_claim_type("not-a-node").is_none());
    }

    /// Cross-lens type_distance must be a TYPED ABSENCE, never a number and
    /// never zero. The two lenses are disjoint components of the bundle graph,
    /// so no path exists — a real answer, and the reason a cross-lens edge's
    /// only meaningful taxonomic label is the bridge.
    #[test]
    fn cross_lens_distance_is_unreachable_not_zero() {
        let c = edge_context(Some("conflict-and-warfare"), Some("bonding-and-kinship"));
        assert_eq!(c["lens_crossing"], json!(true));
        assert_eq!(c["type_distance"]["state"], json!("unreachable"));
        assert!(
            c["type_distance"]["value"].is_null(),
            "never a number, never 0"
        );
        assert!(c["type_distance"]["reason"]
            .as_str()
            .unwrap()
            .contains("disjoint"));
    }

    /// Within a lens the distance is finite and carries its weights caveat.
    #[test]
    fn within_lens_distance_carries_its_caveat() {
        let c = edge_context(Some("conflict-and-warfare"), Some("siege-and-sack"));
        assert_eq!(c["lens_crossing"], json!(false));
        let d = &c["type_distance"];
        assert!(d["value"].as_f64().is_some_and(|v| v.is_finite()));
        assert!(
            d["caveat"].as_str().unwrap().contains("design"),
            "weights caveat must travel"
        );
        assert!(
            d["note"].as_str().unwrap().contains("not a similarity"),
            "the name must refuse the event-similarity reading"
        );
    }

    /// Bridge-relatedness, and the direction is the interesting half.
    #[test]
    fn a_bridge_related_pair_names_its_relation_and_direction() {
        // B -> A, with the grain.
        let c = edge_context(
            Some("aggression-and-violence"),
            Some("conflict-and-warfare"),
        );
        assert_eq!(c["bridge"]["bridge_related"], json!(true));
        assert_eq!(c["bridge"]["relation"], json!("scales-up-to"));
        assert!(c["bridge"]["direction"]
            .as_str()
            .unwrap()
            .contains("with the bridge grain"));

        // A -> B, the same pair against the grain — a different object.
        let c = edge_context(
            Some("conflict-and-warfare"),
            Some("aggression-and-violence"),
        );
        assert_eq!(c["bridge"]["bridge_related"], json!(true));
        assert!(c["bridge"]["direction"]
            .as_str()
            .unwrap()
            .contains("against"));

        // Cross-lens but NOT a bridge pair: bridged elsewhere, said so.
        let c = edge_context(Some("aggression-and-violence"), Some("religious-life"));
        assert_eq!(c["bridge"]["bridge_related"], json!(false));
        assert_eq!(c["bridge"]["bridges_to"], json!("conflict-and-warfare"));
    }

    /// Typed absence over defaults, everywhere.
    #[test]
    fn an_underivable_endpoint_is_untyped_with_a_reason() {
        let c = edge_context(None, Some("conflict-and-warfare"));
        assert_eq!(c["state"], json!("untyped"));
        assert!(c["reason"].as_str().unwrap().contains("no default"));

        let c = edge_context(Some("not-a-node"), Some("conflict-and-warfare"));
        assert_eq!(c["state"], json!("untyped"));
        assert!(c["reason"].as_str().unwrap().contains("not a node"));
    }

    /// The edge's own relation is never a TT word.
    #[test]
    fn tts_bridge_words_are_barred_as_edge_types() {
        let c = edge_context(
            Some("aggression-and-violence"),
            Some("conflict-and-warfare"),
        );
        let s = c["not_an_edge_type"].as_str().unwrap();
        assert!(s.contains("Causation/Influence"));
        // The relation word appears ONLY inside the bridge annotation.
        assert_eq!(c["bridge"]["relation"], json!("scales-up-to"));
        assert!(
            c.get("relation").is_none(),
            "edge_context must not name an edge relation"
        );
    }

    #[test]
    fn the_two_absences_stay_distinct_at_the_surface() {
        // A derivable bridge.
        let s = shadow_of("aggression-and-violence");
        assert_eq!(s["state"], json!("derived"));
        assert_eq!(s["event"], json!("conflict-and-warfare"));
        assert_eq!(s["event_lens"], json!("A"));

        // The bundle asserts silence.
        let s = shadow_of("courtship-and-falling-in-love");
        assert_eq!(s["state"], json!("unrecorded"));
        assert!(s["event"].is_null());

        // The bundle says nothing.
        let s = shadow_of("building-and-construction");
        assert_eq!(s["state"], json!("unlisted"));

        // The three are visibly different on the wire.
        assert_ne!(
            shadow_of("courtship-and-falling-in-love"),
            shadow_of("building-and-construction")
        );

        // Lens A casts no shadow; a non-node is a different non-answer again.
        assert_eq!(
            shadow_of("conflict-and-warfare")["applicable"],
            json!(false)
        );
        assert_eq!(
            shadow_of("not-a-node")["reason"],
            json!("claim type not in the bundle")
        );
    }
}
