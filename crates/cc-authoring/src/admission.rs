//! Strict admission: what is allowed to enter the chain.
//!
//! Sean's ruling, 2026-08-17 (Atlas `d-20260817-1097b7`), on finding 30 entities
//! that declared their date unknown while asserting a year:
//!
//! > drop them and set an always-strict rule for clockchain; every entry has to
//! > be perfect
//!
//! This module is the second half of that. The drop was one afternoon; the gate
//! is what stops the next thirty. Every rule below is one a real defect walked
//! through, and each is named so a rejection is greppable back to its cause.
//!
//! ## Three properties, chosen deliberately
//!
//! **Every failure is reported, not just the first.** A batch that fails one
//! rule at a time costs one generation round per defect. Fixing all of them in
//! one pass is the difference between a gate people use and a gate people route
//! around.
//!
//! **A failing batch mints nothing.** Not "the good ones go in and the rest are
//! logged" — *every entry has to be perfect* is a property of the batch. A
//! partial mint also splits a causal chain: the edges reference titles that were
//! rejected, so the survivors arrive as orphans and the graph quietly degrades.
//!
//! **A restatement is refused, never merged.** The previous dedup destroyed
//! *Arab Conquest of Ctesiphon* by merging it into *Arab Conquest of Egypt* on a
//! Jaccard score of exactly 0.5 — the only differing token was the place name,
//! which is the thing that distinguishes them. The asymmetry is permanent: a
//! missed duplicate is visible and cheap, an over-merge is invisible and final.
//! So this gate never merges. It reports the pair and stops, and a human decides.
//! See `ops/dedup.py`, which carries the same rule and the same regression.
//!
//! ## Which rules are TT's and which are ours
//!
//! **This file enforces; it does not define taxonomy semantics.** Validity,
//! lens, ancestry, retirement and bridge shape are read from the pinned bundle
//! via `cc-filter`'s build-time tables — never restated here.
//!
//! Three rules below are **Clockchain's own admission profile**, permitted by
//! TT but not required by it, and they must never be described as TT policy
//! (telemetry's audit, 2026-08-17; TT `docs/CONSUMERS.md`, "stricter is allowed,
//! looser is not"):
//!
//!   * `claim-type-alternative-is-ancestor` / `-is-descendant` — TT **permits**
//!     ancestor+descendant mass as specificity uncertainty; the metric's
//!     hierarchy weights price it. We refuse it, because our
//!     `claim_type_alternatives` records CLASSIFIER COMPETITION, and there a
//!     parent is not a competing reading. Both stand: the field and the mass
//!     semantics answer different questions (telemetry, 2026-08-17).
//!     **When full mass profiles land (gap 1 and beyond), ancestor+descendant
//!     becomes expressible again. Refusing it then must be a conscious
//!     re-decision, not this default inherited by accident.**
//!   * `temporal_kind ∈ {event, process}` — **ours, and TT has no opinion.**
//!     TT-SPEC §7: *"Extent. Moments are points. A process with duration,
//!     recurrence or spread is not expressible today."* Never attribute this
//!     axis to TT; if a spec release adds extent, this axis re-maps visibly.
//!   * "prefer the most specific defensible node" — **practice, not TT law.**
//!     Branch-level classification is legitimate in TT and is sometimes the
//!     honest answer.
//!   * batch semantics (`duplicate-identity`, `restatement-unresolved`, and
//!     refusing the whole batch) — TT is explicit that dedup, merge policy and
//!     batch behaviour are the consumer's.
//!
//! The one-way rule is the boundary: **a consumer may refuse what TT permits;
//! it may never accept what TT rejects.** Every rule here is a refusal.
//!
//! ## What this gate does NOT do
//!
//! It does not reject model-asserted history. Every claim in the chain is
//! generated, carries `prov_measured` for how it was produced and `prov_asserted`
//! for the historical claim itself, and says so on its face. Requiring sourced
//! history would empty the chain — that is a product decision, not a validation
//! rule, and it is not one this file gets to make. What is enforced here is that
//! the provenance is **complete and non-contradictory**: an entry must say what
//! it is, and must not claim two incompatible things at once.

use cc_filter::version::{
    is_ancestor_of, is_valid_tt_id, lens_of, resolve_tt_id, TT_BUNDLE_SHA256,
};
use serde_json::Value;

/// A rule an entry broke. `rule` is stable and greppable; `detail` names the
/// offending value, because "invalid claim_type" without the id is a bug report
/// with the evidence removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// Stable kebab-case rule id, e.g. `date-not-known`.
    pub rule: &'static str,
    /// What was wrong, naming the value.
    pub detail: String,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.rule, self.detail)
    }
}

fn reject(rule: &'static str, detail: impl Into<String>) -> Rejection {
    Rejection {
        rule,
        detail: detail.into(),
    }
}

/// Exactly the keys an entry may carry. An unexpected key is a rejection rather
/// than a shrug: `prov_measure` for `prov_measured` would otherwise mint a claim
/// with silently absent provenance, which is the failure mode this whole schema
/// exists to prevent.
const ALLOWED_FIELDS: &[&str] = &[
    "title",
    "year",
    "claim_type",
    // Optional. The classifier's runner-up types, when it had competing signal.
    // Found in 8 stored claims from `v4-pilot-2026-08-14` by the check that
    // reads the chain back — the pipeline had been emitting it and nothing read
    // it, so it was neither validated nor surfaced. Kept rather than rejected:
    // it is MORE information about how a claim was classified, and it is the
    // nearest thing the corpus has to a recorded classifier uncertainty. Now
    // validated, so it cannot rot into a junk drawer.
    "claim_type_alternatives",
    // Optional, derived rather than believed: true when at least one ALTERNATIVE
    // sits in the other lens from the primary. Validated against the bundle on
    // every mint, so it can never disagree with the types it describes — a
    // bundle-derivable field allowed to drift is a config echo one layer down.
    //
    // Named `alternatives_` on telemetry's recommendation (audit, 2026-08-17).
    // TT's native notion of crossing lenses is **mass present in both lens
    // objects**; ours is a lossy projection of that over a single primary plus
    // alternatives. There is no collision today because TT defines no such
    // field — the prefix is insurance against the day it does, and this flag
    // must never be described as a TT semantic.
    "alternatives_cross_lens",
    "lens",
    "summary",
    "date_is_known",
    "temporal_kind",
    "observed_count",
    "tt_release",
    "tt_bundle_sha256",
    "prov_measured",
    "prov_asserted",
    // How the classification was produced: "derived" (from claim_type, by us) or
    // "independent" (a separate classifier read the claim). Absent means
    // derived, which is the conservative default — it keeps the strict
    // corruption check for everything minted before this field existed.
    "classification_source",
    // Optional TT classification profile: {lens_a, lens_b, abstain, bundle}.
    // Validated by `crate::classification`, which is a port of telemetry's
    // `tt_validate.py` — TT owns these semantics, we enforce them. This is the
    // field that makes abstention sayable: `abstain: true` with both lenses
    // empty. Optional because 322 claims predate it.
    "classification",
];

/// `prov_measured` describes how the bytes were produced. Every one of these is
/// required: a run that cannot be reproduced from its own record is not measured.
const PROV_MEASURED_FIELDS: &[&str] = &["text_model", "provider", "method", "run", "generated_at"];

/// The corpus is history. A claim outside this band is a parse artifact, not an
/// event — the bound is deliberately loose because narrowing it is a curatorial
/// decision and this is a validator.
const YEAR_MIN: i64 = -50_000;
const YEAR_MAX: i64 = 2_100;

const MIN_SUMMARY_CHARS: usize = 20;

/// A title in a cased script must carry a capital.
///
/// Case-aware on purpose. The first version of this check was `[A-Z]`, which
/// rejected every title in Chinese, Arabic, Hebrew, Hindi and Japanese — six
/// false positives on the first real batch. A script with no case cannot fail a
/// capitalisation rule, so it is not asked to.
fn is_cased_script(t: &str) -> bool {
    t.chars().any(|c| c.is_lowercase() || c.is_uppercase())
}

/// The title checks, in one place so the mint path and any staging tool agree.
fn check_title(t: &str, out: &mut Vec<Rejection>) {
    let t = t.trim();
    if t.is_empty() {
        out.push(reject("title-missing", "empty after trimming"));
        return;
    }
    if is_cased_script(t) && !t.chars().any(char::is_uppercase) {
        out.push(reject(
            "title-not-capitalised",
            format!("{t:?} is in a cased script and carries no capital — usually a raw slug"),
        ));
    }
    // "Battle of Kadesh (-1274)" — the year belongs in the year field, and a
    // title carrying it produces a second identity for the same claim.
    let tail = t.rsplit(' ').next().unwrap_or("");
    if tail.starts_with('(')
        && tail.ends_with(')')
        && tail[1..tail.len() - 1]
            .trim_start_matches('-')
            .chars()
            .all(|c| c.is_ascii_digit())
        && tail.len() > 2
    {
        out.push(reject(
            "title-year-appended",
            format!("{t:?} ends with a parenthesised year"),
        ));
    }
    // "battle-of-kadesh, -1274" — the generator's own key, echoed back.
    if t.contains(", -") {
        out.push(reject(
            "title-year-appended",
            format!("{t:?} carries a comma-separated year"),
        ));
    }
    // "..., egypt, africa" — place slugs appended from the prompt partition.
    let parts: Vec<&str> = t.split(',').map(str::trim).collect();
    if parts.len() >= 3
        && parts[parts.len() - 2..]
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
    {
        out.push(reject(
            "title-place-slug",
            format!("{t:?} ends with lowercase place slugs"),
        ));
    }
}

fn check_str_field<'a>(
    e: &'a Value,
    key: &'static str,
    rule_missing: &'static str,
    out: &mut Vec<Rejection>,
) -> Option<&'a str> {
    match e.get(key).and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => Some(s),
        Some(_) => {
            out.push(reject(
                rule_missing,
                format!("`{key}` is present but empty"),
            ));
            None
        }
        None => {
            out.push(reject(
                rule_missing,
                format!("`{key}` is missing or not a string"),
            ));
            None
        }
    }
}

/// Judge one entry. An empty result is admission.
pub fn admit(e: &Value) -> Vec<Rejection> {
    let mut out = Vec::new();

    let Some(obj) = e.as_object() else {
        return vec![reject("entry-not-object", "an entry must be a JSON object")];
    };
    for k in obj.keys() {
        if !ALLOWED_FIELDS.contains(&k.as_str()) {
            out.push(reject(
                "field-unknown",
                format!("`{k}` is not an entry field — typo?"),
            ));
        }
    }

    if let Some(t) = check_str_field(e, "title", "title-missing", &mut out) {
        check_title(t, &mut out);
    }

    // ---- the date, which is what the 30 failed on ------------------------
    let year = match e.get("year") {
        Some(Value::Number(n)) if n.is_i64() => {
            let y = n.as_i64().unwrap();
            if !(YEAR_MIN..=YEAR_MAX).contains(&y) {
                out.push(reject(
                    "year-implausible",
                    format!("{y} is outside {YEAR_MIN}..={YEAR_MAX}"),
                ));
            }
            Some(y)
        }
        Some(v) => {
            out.push(reject(
                "year-not-integer",
                format!("`year` is {v}, not an integer"),
            ));
            None
        }
        None => {
            out.push(reject("year-missing", "`year` is required"));
            None
        }
    };

    // THE RULE THE 30 BROKE. Each of them carried a year — several precise
    // ones, -1274 for Kadesh, -1754 for Hammurabi — while declaring
    // `date_is_known: false`. The mint path honoured the flag and wrote
    // WindowStart::Unknown to the entity, then wrote the moment at
    // year_tick(year) anyway. So the entity disclaimed a date its own body and
    // its own coordinate asserted. Two surfaces, one of them wrong, and no way
    // for a reader to tell which.
    match e.get("date_is_known") {
        Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) => out.push(reject(
            "date-not-known",
            match year {
                Some(y) => format!(
                    "declares `date_is_known: false` while asserting year {y} — an entry may \
                     not both carry a date and disclaim it; give it a defensible date or \
                     leave it out"
                ),
                None => "declares `date_is_known: false`; every entry needs a defensible date"
                    .to_string(),
            },
        )),
        Some(v) => out.push(reject(
            "date-not-known",
            format!("`date_is_known` is {v}, not a bool"),
        )),
        None => out.push(reject(
            "date-not-known",
            "`date_is_known` is required and must be true — silence is not a date",
        )),
    }

    // ---- classification, checked against the bundle ----------------------
    if let Some(ct) = check_str_field(e, "claim_type", "claim-type-missing", &mut out) {
        if !is_valid_tt_id(ct) {
            out.push(reject(
                "claim-type-invalid",
                format!("{ct:?} is not a node in the pinned TT bundle"),
            ));
        } else {
            let live = resolve_tt_id(ct);
            if live != ct {
                out.push(reject(
                    "claim-type-retired",
                    format!("{ct:?} is retired; the bundle's successor is {live:?}"),
                ));
            }
            // The bundle settles the lens. A claim that declares its own is
            // checked against it rather than believed.
            match (e.get("lens").and_then(Value::as_str), lens_of(live)) {
                (Some(declared), Some(actual)) if declared != actual => out.push(reject(
                    "lens-mismatch",
                    format!("declares lens {declared:?}; the bundle puts {live:?} in {actual:?}"),
                )),
                (None, _) => out.push(reject("lens-missing", "`lens` is required")),
                _ => {}
            }
        }
    }

    // The TT profile, if the pipeline produced one. Rejections carry TT's own
    // codes verbatim so a failure here is diffable against their validator.
    if let Some(c) = e.get("classification") {
        match crate::classification::validate(c) {
            Err(errs) => {
                for r in errs {
                    out.push(reject("classification-invalid", r.to_string()));
                }
            }
            Ok(norm) => {
                // LOCAL PROFILE, not a TT rule: TT knows nothing about our
                // `claim_type` field.
                //
                // **SCOPED TO ITS JUSTIFICATION.** The rationale was "two copies
                // of one fact can only disagree by corruption" — TRUE while a
                // classification was always DERIVED from `claim_type`, and FALSE
                // the moment one is produced independently. In the abstention
                // pilot the generator read a double burial as
                // `bonding-and-kinship` and a separate classifier read it as
                // `religious-life` + `knowing-and-meaning`. Both are defensible.
                // **Two readers disagreeing is the epistemic content a chain of
                // recorded readings exists to keep**, and a corruption check
                // enforced past its justification would have silently deleted
                // the finding.
                //
                // So: `classification_source: "independent"` admits the
                // disagreement and stores it. Anything else — including the
                // field being absent, which covers every claim minted before it
                // existed — keeps the strict check. The protection is not lost;
                // it is aimed at the case it was written for.
                //
                // Same move, same reason, as the abstention exemption below:
                // a rule enforced beyond its justification turns signal into
                // defect. (Telemetry, routed design review, 2026-08-17.)
                let independent = e
                    .get("classification_source")
                    .and_then(Value::as_str)
                    .is_some_and(|v| v == "independent");
                if !independent && !crate::classification::is_abstention(&norm) {
                    if let Some(ct) = e.get("claim_type").and_then(Value::as_str) {
                        let present = ["lens_a", "lens_b"].iter().any(|k| {
                            norm.get(*k)
                                .and_then(Value::as_object)
                                .is_some_and(|m| m.contains_key(ct))
                        });
                        if !present {
                            out.push(reject(
                                "derived-classification-disagrees-with-claim-type",
                                format!(
                                    "`claim_type` is {ct:?} but the DERIVED profile carries no \
                                     mass on it. A derived classification is a copy of the \
                                     headline type, so disagreement is corruption. If a separate \
                                     classifier produced this reading, mark it \
                                     `classification_source: \"independent\"` and the \
                                     disagreement is kept as a finding."
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Runner-up classifications, if any. Held to the same standard as the
    // chosen one: an alternative that is not a real node would let an invalid id
    // ride into the chain through a field nobody looks at.
    match e.get("claim_type_alternatives") {
        None => {
            // `alternatives_cross_lens` describes the alternatives. With none recorded it
            // can only be false, and a true value would be a claim about a
            // field that is not there.
            if e.get("alternatives_cross_lens").and_then(Value::as_bool) == Some(true) {
                out.push(reject(
                    "alternatives-cross-lens-mismatch",
                    "declares `alternatives_cross_lens: true` with no `claim_type_alternatives` \
                     to be across a lens from",
                ));
            }
        }
        Some(Value::Array(alts)) => {
            let chosen = e.get("claim_type").and_then(Value::as_str).unwrap_or("");
            let mut seen: Vec<&str> = Vec::new();
            for a in alts {
                match a.as_str() {
                    Some(s) if !is_valid_tt_id(s) => out.push(reject(
                        "claim-type-alternative-invalid",
                        format!("{s:?} is not a node in the pinned TT bundle"),
                    )),
                    Some(s) if s == chosen => out.push(reject(
                        "claim-type-alternative-invalid",
                        format!("{s:?} is also the chosen type — an alternative to itself"),
                    )),
                    // ---- LOCAL ADMISSION PROFILE, NOT A TT RULE ------------
                    //
                    // **TT permits this and we refuse it.** Mass on an ancestor
                    // and a descendant in one classification is a legitimate
                    // expression of specificity uncertainty under TT-SPEC, and
                    // the metric's hierarchy weights price it. Telemetry ruled
                    // on this explicitly (2026-08-17) after auditing the rule.
                    //
                    // Refusing it is allowed by the one-way rule in TT's
                    // `docs/CONSUMERS.md`: *a consumer may refuse what TT
                    // permits; it may never accept what TT rejects.* The two
                    // positions answer different questions — TT defines what is
                    // sayable, an admission profile defines what THIS chain
                    // stores.
                    //
                    // So this binds nobody else, and must never be described as
                    // TT policy. Our reason is narrow: `claim_type_alternatives`
                    // exists here to record that the classifier had genuine
                    // competition, and "it also considered being vaguer" dilutes
                    // the only signal the field carries.
                    Some(s) if is_ancestor_of(s, chosen) => out.push(reject(
                        "claim-type-alternative-is-ancestor",
                        format!(
                            "{s:?} is an ancestor of {chosen:?} — coarser, not competing. \
                             Clockchain's local profile refuses this; TT permits it"
                        ),
                    )),
                    // The mirror case, same standing: local, not TT.
                    Some(s) if is_ancestor_of(chosen, s) => out.push(reject(
                        "claim-type-alternative-is-descendant",
                        format!(
                            "{s:?} sits under {chosen:?} — if it is the better fit it should be \
                             the primary. Clockchain's local profile; TT permits it"
                        ),
                    )),
                    Some(s) if seen.contains(&s) => out.push(reject(
                        "claim-type-alternative-invalid",
                        format!("{s:?} is listed twice"),
                    )),
                    Some(s) => seen.push(s),
                    None => out.push(reject(
                        "claim-type-alternative-invalid",
                        format!("{a} is not a string"),
                    )),
                }
            }

            // `alternatives_cross_lens` is derived from the bundle; a declared value is
            // checked against it rather than trusted.
            let declared_lens = lens_of(chosen);
            let derived = seen
                .iter()
                .any(|s| lens_of(s).is_some() && lens_of(s) != declared_lens);
            match e.get("alternatives_cross_lens") {
                None => {}
                Some(Value::Bool(b)) if *b == derived => {}
                Some(Value::Bool(b)) => out.push(reject(
                    "alternatives-cross-lens-mismatch",
                    format!(
                        "declares `alternatives_cross_lens: {b}`; the bundle puts the alternatives \
                         {} the primary's lens",
                        if derived { "outside" } else { "inside" }
                    ),
                )),
                Some(v) => out.push(reject(
                    "alternatives-cross-lens-mismatch",
                    format!("`alternatives_cross_lens` is {v}, not a bool"),
                )),
            }
        }
        Some(v) => out.push(reject(
            "claim-type-alternative-invalid",
            format!("`claim_type_alternatives` is {v}, not an array"),
        )),
    }

    // The claim names the bundle it was validated under. Compared against the
    // sha of the bytes THIS binary was compiled from — not a constant typed
    // into a config, which is the echo that published a stale exhibit hash.
    check_str_field(e, "tt_release", "tt-release-missing", &mut out);
    match e.get("tt_bundle_sha256").and_then(Value::as_str) {
        Some(s) if s == TT_BUNDLE_SHA256 => {}
        Some(s) => out.push(reject(
            "tt-bundle-mismatch",
            format!(
                "declares bundle {s:.16}…; this binary was built against {TT_BUNDLE_SHA256:.16}…"
            ),
        )),
        None => out.push(reject(
            "tt-bundle-mismatch",
            "`tt_bundle_sha256` is required",
        )),
    }

    // ---- the rest of the shape -------------------------------------------
    match e.get("summary").and_then(Value::as_str) {
        Some(s) if s.trim().chars().count() >= MIN_SUMMARY_CHARS => {}
        Some(s) => out.push(reject(
            "summary-too-short",
            format!(
                "{} chars; {MIN_SUMMARY_CHARS} is the floor",
                s.trim().chars().count()
            ),
        )),
        None => out.push(reject("summary-too-short", "`summary` is required")),
    }

    match e.get("temporal_kind").and_then(Value::as_str) {
        Some("event") | Some("process") => {}
        Some(k) => out.push(reject(
            "temporal-kind-invalid",
            format!("{k:?} is not one of \"event\", \"process\""),
        )),
        None => out.push(reject(
            "temporal-kind-invalid",
            "`temporal_kind` is required",
        )),
    }

    match e.get("observed_count").and_then(Value::as_i64) {
        Some(n) if n >= 1 => {}
        Some(n) => out.push(reject("observed-count-invalid", format!("{n} is below 1"))),
        None => out.push(reject(
            "observed-count-invalid",
            "`observed_count` is required",
        )),
    }

    // ---- provenance, complete or not at all ------------------------------
    match e.get("prov_measured") {
        Some(Value::Object(m)) => {
            for f in PROV_MEASURED_FIELDS {
                match m.get(*f).and_then(Value::as_str) {
                    Some(s) if !s.trim().is_empty() => {}
                    _ => out.push(reject(
                        "prov-measured-incomplete",
                        format!("`prov_measured.{f}` is missing or empty"),
                    )),
                }
            }
        }
        _ => out.push(reject(
            "prov-measured-incomplete",
            "`prov_measured` is required",
        )),
    }
    match e.get("prov_asserted") {
        Some(Value::Object(a)) => match a.get("historical_claim").and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => {}
            _ => out.push(reject(
                "prov-asserted-incomplete",
                "`prov_asserted.historical_claim` is missing or empty",
            )),
        },
        _ => out.push(reject(
            "prov-asserted-incomplete",
            "`prov_asserted` is required",
        )),
    }

    out
}

// ===========================================================================
// A rule that was here and is deliberately gone
// ===========================================================================
//
// `scale-mismatch-review` flagged a claim whose primary sat under an
// "interpersonal" branch while its summary described state-level events. It
// found two real cases. Telemetry ruled it DELETED, not patched, on 2026-08-17,
// and the reasoning is worth keeping so nobody rebuilds it:
//
//   * It could not be re-expressed from the bundle. `reconciliation-and-forgiveness`
//     carries NO bridge, so a bundle-derived version would have MISSED *End of
//     Apartheid* entirely — the case that motivated the rule. And
//     `death-and-dying`'s bridge is `recorded-as -> royal-death-and-succession`,
//     noted "royalty only", so it would have fired on *Mani* pointing at the
//     wrong target. Bridges encode what the record DOES with an action, not what
//     scale an event operates at.
//   * TT has no language-independent state-scale signal and will not grow one by
//     keyword. Our version was 14 English words and could not fire on a title in
//     any other language — the third appearance of the failure shape that first
//     showed up as an `[A-Z]` title check rejecting six non-Latin-script titles.
//   * Deepest: the mismatch it hunted is an artifact of the SINGLE-PRIMARY
//     projection. Under a full TT mass profile, *End of Apartheid* carries A mass
//     (governance) and B mass (reconciliation) at once. There is nothing to flag,
//     because the tension was never in the event — only in the forced choice.
//
// The honest interim control is a human-review queue for B-primary claims, or
// nothing. This is nothing, on purpose.

// ===========================================================================
// Batch rules — the ones that need to see the other entries
// ===========================================================================

/// Words that carry no distinguishing weight. Deliberately short: every word
/// added here is a word that can no longer tell two events apart, which is one
/// abstraction up from how the Ctesiphon over-merge happened.
const STOP: &[&str] = &[
    "the", "of", "a", "an", "in", "at", "on", "to", "and", "by", "for", "s", "its", "his", "her",
    "their",
];

/// Generic event-shape verbs and nouns. Removing these lets *Black Death Reaches
/// Europe* and *Black Death Peaks in Europe* collapse, which they should. A
/// PROPER NOUN is never in this set — that is the whole point.
const FILLER: &[&str] = &[
    "begins",
    "begin",
    "began",
    "starts",
    "start",
    "started",
    "reaches",
    "reached",
    "peaks",
    "peaked",
    "arrival",
    "arrives",
    "signing",
    "signed",
    "posting",
    "posted",
    "publication",
    "published",
    "construction",
    "constructed",
    "establishment",
    "established",
    "founding",
    "founded",
    "invention",
    "invented",
    "discovery",
    "discovered",
    "creation",
    "created",
    "adoption",
    "adopted",
    "formation",
    "formed",
];

const YEAR_TOLERANCE: i64 = 12;

fn content_words(title: &str) -> Vec<String> {
    let mut w: Vec<String> = title
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .filter(|t| !STOP.contains(t) && !FILLER.contains(t))
        .map(str::to_string)
        .collect();
    w.sort();
    w.dedup();
    w
}

/// Is one claim a restatement of the other?
///
/// True only when one title's distinguishing words are a **subset** of the
/// other's — a longer spelling of the same claim. False when each carries
/// something the other lacks, because a word present in one and absent in the
/// other is, by construction, the thing that tells them apart. That is the rule
/// *Arab Conquest of Ctesiphon* needed and did not get.
fn is_restatement(ta: &str, ya: i64, tb: &str, yb: i64) -> bool {
    if (ya - yb).abs() > YEAR_TOLERANCE {
        return false;
    }
    let (wa, wb) = (content_words(ta), content_words(tb));
    if wa.is_empty() || wb.is_empty() {
        return false;
    }
    wa.iter().all(|w| wb.contains(w)) || wb.iter().all(|w| wa.contains(w))
}

/// Judge a whole batch. Returns `(index, rejection)` pairs; empty is admission.
///
/// Batch-level rules run **after** per-entry ones and only over entries that
/// have a usable title and year, so a missing title reports as `title-missing`
/// once rather than also as a spurious restatement of everything else.
pub fn admit_batch(entries: &[Value]) -> Vec<(usize, Rejection)> {
    let mut out: Vec<(usize, Rejection)> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        out.extend(admit(e).into_iter().map(|r| (i, r)));
    }

    let keyed: Vec<(usize, &str, i64)> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            Some((
                i,
                e.get("title")?.as_str()?.trim(),
                e.get("year")?.as_i64()?,
            ))
        })
        .collect();

    for (a, &(ia, ta, ya)) in keyed.iter().enumerate() {
        for &(ib, tb, yb) in &keyed[a + 1..] {
            if ta.eq_ignore_ascii_case(tb) && ya == yb {
                out.push((
                    ib,
                    reject(
                        "duplicate-identity",
                        format!(
                            "entry {ia} asserts the same ({ta:?}, {ya}) — one identity, two rows"
                        ),
                    ),
                ));
            } else if is_restatement(ta, ya, tb, yb) {
                // Refused, never merged. Which of the two survives is a
                // judgement about history, and this is a validator.
                out.push((
                    ib,
                    reject(
                        "restatement-unresolved",
                        format!(
                            "reads as a restatement of entry {ia} ({ta:?}, {ya}); keep one and \
                             drop the other before minting — this gate will not choose"
                        ),
                    ),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A perfect entry, and the base every rejection test mutates from — so a
    /// test proves the rule it names rather than accidentally passing on an
    /// unrelated defect.
    fn good() -> Value {
        json!({
            "title": "Battle of Kadesh",
            "year": -1274,
            "claim_type": "conflict-and-warfare",
            "lens": "A",
            "summary": "Egyptian and Hittite forces fought to a standstill at Kadesh on the Orontes.",
            "date_is_known": true,
            "temporal_kind": "event",
            "observed_count": 1,
            "tt_release": "tt-ontology/2.1.0",
            "tt_bundle_sha256": TT_BUNDLE_SHA256,
            "prov_measured": {
                "text_model": "nvidia/nemotron-3-ultra-550b-a55b:free",
                "provider": "openrouter",
                "method": "chat/completions; causal-chain prompt",
                "run": "test",
                "generated_at": "2026-08-17"
            },
            "prov_asserted": { "historical_claim": "model-asserted; no source consulted" }
        })
    }

    fn rules(v: &Value) -> Vec<&'static str> {
        let mut r: Vec<&'static str> = admit(v).into_iter().map(|x| x.rule).collect();
        r.sort_unstable();
        r
    }

    /// **The protection is not lost — it is aimed.** A DERIVED classification is
    /// a copy of the headline type, so disagreement can only be corruption and
    /// still rejects. This is the direction that guards every claim minted
    /// before `classification_source` existed, since absent means derived.
    #[test]
    fn a_derived_profile_that_contradicts_the_headline_type_is_still_refused() {
        let mut e = good();
        e["classification"] = crate::classification::from_single_type("religious-life").unwrap();
        // No source field at all — the pre-existing corpus's shape.
        assert_eq!(
            rules(&e),
            vec!["derived-classification-disagrees-with-claim-type"]
        );

        // Explicitly derived: same answer.
        e["classification_source"] = json!("derived");
        assert_eq!(
            rules(&e),
            vec!["derived-classification-disagrees-with-claim-type"]
        );

        // Anything that is not exactly "independent" keeps the strict check, so
        // a typo cannot silently disable a corruption guard.
        e["classification_source"] = json!("Independent");
        assert_eq!(
            rules(&e),
            vec!["derived-classification-disagrees-with-claim-type"]
        );
    }

    /// **The other direction.** When a SEPARATE classifier produced the reading,
    /// disagreement is two readers disagreeing — the epistemic content a chain
    /// of recorded readings exists to keep — and it stores as it stands.
    ///
    /// The live case: a double burial at Shum Laka. The generator read
    /// `bonding-and-kinship`; an independent classifier read `religious-life`
    /// and `knowing-and-meaning`. Both defensible. Under the unscoped rule the
    /// corruption check would have deleted the finding.
    #[test]
    fn an_independent_profile_may_disagree_and_is_kept() {
        let mut e = good();
        e["title"] = json!("Double Burial of Adolescents at Shum Laka");
        e["year"] = json!(-3000);
        e["claim_type"] = json!("bonding-and-kinship");
        e["lens"] = json!("B");
        e["classification_source"] = json!("independent");
        e["classification"] = json!({
            "lens_a": {"religious-life": 0.8},
            "lens_b": {"knowing-and-meaning": 0.8},
            "abstain": false,
            "bundle": crate::classification::BUNDLE_VERSION_STRING,
        });
        assert_eq!(
            admit(&e),
            vec![],
            "an independent disagreement is a finding, not a defect"
        );

        // An independent profile is still held to TT's own rules — scoping the
        // agreement check does not scope the validator.
        e["classification"] = json!({"lens_a": {"not-a-node": 1.0}, "lens_b": {},
                                     "abstain": false});
        assert!(rules(&e).contains(&"classification-invalid"));
    }

    /// A claim carrying both a headline type and a TT profile must not have
    /// them disagree — and an abstention is exempt, or abstention would become
    /// unsayable the moment a claim also carried a `claim_type`.
    #[test]
    fn a_profile_that_contradicts_the_headline_type_is_refused() {
        let mut e = good();
        e["classification"] =
            crate::classification::from_single_type("conflict-and-warfare").unwrap();
        assert_eq!(
            admit(&e),
            vec![],
            "a profile agreeing with claim_type passes"
        );

        e["classification"] = crate::classification::from_single_type("religious-life").unwrap();
        assert_eq!(
            rules(&e),
            vec!["derived-classification-disagrees-with-claim-type"]
        );

        e["classification"] = json!({"lens_a": {}, "lens_b": {}, "abstain": true,
            "bundle": crate::classification::BUNDLE_VERSION_STRING});
        assert_eq!(
            admit(&e),
            vec![],
            "an abstention must not be forced to name a type"
        );
    }

    /// An invalid profile carries TT's own rejection text through verbatim.
    #[test]
    fn a_bad_profile_reports_tts_codes_not_ours() {
        let mut e = good();
        e["classification"] = json!({"lens_a": {"conflict-and-warfare": 1.0}, "abstain": true});
        let r = admit(&e);
        assert!(r.iter().any(|x| x.rule == "classification-invalid"));
        assert!(
            r.iter().any(|x| x.detail.contains("abstain-with-mass")
                && x.detail.contains("abstention is empty lenses (§4.4)")),
            "TT's verbatim text must survive: {r:?}"
        );
    }

    #[test]
    fn the_baseline_is_admitted() {
        assert_eq!(
            admit(&good()),
            vec![],
            "the fixture must pass or every other test lies"
        );
    }

    /// The regression this gate was built for. All 30 dropped entities had this
    /// exact shape: a real year, and a flag disclaiming it.
    #[test]
    fn a_year_with_the_date_disclaimed_is_refused() {
        let mut e = good();
        e["date_is_known"] = json!(false);
        assert_eq!(rules(&e), vec!["date-not-known"]);
        assert!(
            admit(&e)[0].detail.contains("-1274"),
            "the rejection must name the year"
        );
    }

    #[test]
    fn a_missing_date_flag_is_not_a_pass() {
        let mut e = good();
        e.as_object_mut().unwrap().remove("date_is_known");
        assert_eq!(rules(&e), vec!["date-not-known"]);
    }

    #[test]
    fn every_failure_is_reported_not_just_the_first() {
        let mut e = good();
        e["date_is_known"] = json!(false);
        e["temporal_kind"] = json!("vibe");
        e["observed_count"] = json!(0);
        let r = rules(&e);
        assert_eq!(
            r,
            vec![
                "date-not-known",
                "observed-count-invalid",
                "temporal-kind-invalid"
            ]
        );
    }

    #[test]
    fn classification_is_checked_against_the_bundle() {
        let mut e = good();
        e["claim_type"] = json!("conflict-and-war"); // plausible, not a node
        assert_eq!(rules(&e), vec!["claim-type-invalid"]);

        let mut e = good();
        e["claim_type"] = json!("everyday-movement-and-commute"); // real, retired
        e["lens"] = json!("B");
        assert_eq!(rules(&e), vec!["claim-type-retired"]);
    }

    #[test]
    fn a_declared_lens_is_checked_not_believed() {
        let mut e = good();
        e["lens"] = json!("B"); // conflict-and-warfare is an A node
        assert_eq!(rules(&e), vec!["lens-mismatch"]);
    }

    #[test]
    fn the_bundle_sha_must_match_the_binary() {
        let mut e = good();
        e["tt_bundle_sha256"] = json!("0".repeat(64));
        assert_eq!(rules(&e), vec!["tt-bundle-mismatch"]);
    }

    /// The 8 stored claims that carry runner-up types must be admissible as
    /// they stand — the field is signal, and this pins that a later tightening
    /// cannot quietly start rejecting them.
    #[test]
    fn recorded_runner_up_classifications_are_kept_and_checked() {
        let mut e = good();
        e["title"] = json!("Signing of the Magna Carta");
        e["year"] = json!(1215);
        e["claim_type"] = json!("constitutions-and-charters");
        e["claim_type_alternatives"] = json!(["legislation-edicts-and-decrees"]);
        assert_eq!(admit(&e), vec![]);

        // …but an alternative is held to the same standard as the chosen type.
        for bad in [
            json!(["not-a-real-node"]),
            json!(["constitutions-and-charters"]),
            json!([
                "legislation-edicts-and-decrees",
                "legislation-edicts-and-decrees"
            ]),
            json!("legislation-edicts-and-decrees"),
            json!([7]),
        ] {
            let mut e2 = e.clone();
            e2["claim_type_alternatives"] = bad.clone();
            assert_eq!(
                rules(&e2),
                vec!["claim-type-alternative-invalid"],
                "{bad} should trip"
            );
        }
    }

    /// The eight stored claims that carry runner-up types, as fixtures.
    /// `(title, year, primary, alternatives)` — exactly as minted on
    /// 2026-08-14, so these tests describe the corpus rather than a hypothetical.
    fn the_eight() -> Vec<(&'static str, i64, &'static str, Vec<&'static str>)> {
        vec![
            (
                "Meiji Restoration",
                1868,
                "rulership-and-succession",
                vec![
                    "conquest-and-state-formation",
                    "coup-and-usurpation",
                    "independence-and-state-founding",
                    "politics-governance-and-law",
                ],
            ),
            (
                "Signing of the Magna Carta",
                1215,
                "constitutions-and-charters",
                vec!["legislation-edicts-and-decrees"],
            ),
            (
                "Invention of the Printing Press",
                1440,
                "invention-and-technology",
                vec!["printing-and-publishing"],
            ),
            (
                "Establishment of the United Nations",
                1945,
                "deliberative-assembly-and-congress",
                vec!["governance-and-popular-politics"],
            ),
            (
                "Discovery of Penicillin",
                1928,
                "scientific-discovery",
                vec!["health-illness-and-healing"],
            ),
            (
                "End of Apartheid",
                1994,
                "reconciliation-and-forgiveness",
                vec!["politics-governance-and-law"],
            ),
            (
                "Fall of the Berlin Wall",
                1989,
                "protest-riot-and-civil-unrest",
                vec!["political-violence-and-upheaval"],
            ),
            (
                "Fall of Constantinople",
                1453,
                "siege-and-sack",
                vec!["conquest-annexation-and-occupation"],
            ),
        ]
    }

    fn as_stored(title: &str, year: i64, primary: &str, alts: &[&str]) -> Value {
        let mut e = good();
        e["title"] = json!(title);
        e["year"] = json!(year);
        e["claim_type"] = json!(primary);
        e["lens"] = json!(lens_of(primary).unwrap());
        e["claim_type_alternatives"] = json!(alts);
        e
    }

    /// An "alternative" that is the primary's own ancestor is the same reading
    /// at a coarser level. The United Nations entry is the live instance.
    #[test]
    fn an_alternative_that_is_just_the_parent_is_refused() {
        let e = as_stored(
            "Establishment of the United Nations",
            1945,
            "deliberative-assembly-and-congress",
            &["governance-and-popular-politics"],
        );
        assert_eq!(rules(&e), vec!["claim-type-alternative-is-ancestor"]);

        // The mirror: an alternative below the primary is also not competition.
        let e = as_stored(
            "Establishment of the United Nations",
            1945,
            "governance-and-popular-politics",
            &["deliberative-assembly-and-congress"],
        );
        assert_eq!(rules(&e), vec!["claim-type-alternative-is-descendant"]);
    }

    /// **Two of the eight carry ancestor noise, not one.**
    ///
    /// I hand-read these and reported the UN entry as the only granularity
    /// artifact, calling Meiji Restoration "genuinely four-aspect". The rule
    /// disagreed and the rule is right: Meiji's fourth alternative,
    /// `politics-governance-and-law`, is the branch its own primary
    /// `rulership-and-succession` hangs from. Three of its four alternatives
    /// are real competition; the fourth is the same reading, coarser.
    ///
    /// That is the argument for a systemic rule over case-by-case judgement in
    /// one line: I looked at eight entries carefully and missed one, because
    /// "restoration, coup, conquest, state-founding" reads like four aspects
    /// until you check which of them is a parent of which.
    #[test]
    fn exactly_two_of_the_eight_carry_ancestor_noise() {
        let mut noisy = Vec::new();
        for (t, y, p, alts) in the_eight() {
            let e = as_stored(t, y, p, &alts);
            let rs = rules(&e);
            if rs.is_empty() {
                continue;
            }
            assert_eq!(
                rs,
                vec!["claim-type-alternative-is-ancestor"],
                "{t}: unexpected {rs:?}"
            );
            noisy.push(t);
        }
        assert_eq!(
            noisy,
            vec!["Meiji Restoration", "Establishment of the United Nations"],
            "these two need an alternative dropped; the other six are genuine competition"
        );
    }

    /// The six whose alternatives are all real competition must keep passing —
    /// a rule that also rejected these would trade a real signal for a tidier
    /// corpus.
    #[test]
    fn the_six_genuine_ambiguities_still_pass() {
        let noisy = ["Meiji Restoration", "Establishment of the United Nations"];
        let mut passed = 0;
        for (t, y, p, alts) in the_eight() {
            if noisy.contains(&t) {
                continue;
            }
            assert_eq!(
                admit(&as_stored(t, y, p, &alts)),
                vec![],
                "{t} must still be admissible"
            );
            passed += 1;
        }
        assert_eq!(passed, 6);
    }

    /// Meiji minus the branch is admissible — the fix is to drop one
    /// alternative, not to reclassify or drop the entry.
    #[test]
    fn meiji_passes_once_the_branch_is_dropped() {
        let e = as_stored(
            "Meiji Restoration",
            1868,
            "rulership-and-succession",
            &[
                "conquest-and-state-formation",
                "coup-and-usurpation",
                "independence-and-state-founding",
            ],
        );
        assert_eq!(admit(&e), vec![]);
    }

    /// `alternatives_cross_lens` is derived from the bundle, never believed.
    #[test]
    fn alternatives_cross_lens_is_checked_against_the_bundle() {
        // Penicillin: scientific-discovery is A, health-illness-and-healing is B.
        let mut e = as_stored(
            "Discovery of Penicillin",
            1928,
            "scientific-discovery",
            &["health-illness-and-healing"],
        );
        e["alternatives_cross_lens"] = json!(true);
        assert_eq!(
            admit(&e),
            vec![],
            "a true declaration matching the bundle passes"
        );

        e["alternatives_cross_lens"] = json!(false);
        assert_eq!(
            rules(&e),
            vec!["alternatives-cross-lens-mismatch"],
            "a false declaration is caught"
        );

        // Magna Carta: both types are A, so the flag must be false.
        let mut e = as_stored(
            "Signing of the Magna Carta",
            1215,
            "constitutions-and-charters",
            &["legislation-edicts-and-decrees"],
        );
        e["alternatives_cross_lens"] = json!(true);
        assert_eq!(rules(&e), vec!["alternatives-cross-lens-mismatch"]);
        e["alternatives_cross_lens"] = json!(false);
        assert_eq!(admit(&e), vec![]);

        // Declared with nothing to be across a lens from.
        let mut e = good();
        e["alternatives_cross_lens"] = json!(true);
        assert_eq!(rules(&e), vec!["alternatives-cross-lens-mismatch"]);
    }

    /// Exactly the two cross-lens entries in the live corpus, and no others.
    #[test]
    fn the_two_lens_crossing_entries_are_the_ones_the_bundle_says_they_are() {
        let mut found = Vec::new();
        for (t, _, p, alts) in the_eight() {
            let pl = lens_of(p);
            if alts
                .iter()
                .any(|a| lens_of(a).is_some() && lens_of(a) != pl)
            {
                found.push(t);
            }
        }
        assert_eq!(found, vec!["Discovery of Penicillin", "End of Apartheid"]);
    }

    #[test]
    fn a_typo_in_a_field_name_is_not_silently_absent_provenance() {
        let mut e = good();
        let m = e["prov_measured"].clone();
        let o = e.as_object_mut().unwrap();
        o.remove("prov_measured");
        o.insert("prov_measure".into(), m);
        assert_eq!(rules(&e), vec!["field-unknown", "prov-measured-incomplete"]);
    }

    #[test]
    fn partial_provenance_is_not_provenance() {
        let mut e = good();
        e["prov_measured"].as_object_mut().unwrap().remove("run");
        e["prov_measured"]["provider"] = json!("  ");
        assert_eq!(
            rules(&e),
            vec!["prov-measured-incomplete", "prov-measured-incomplete"]
        );
    }

    #[test]
    fn titles_that_leaked_the_generator_are_refused() {
        for (t, want) in [
            ("battle-of-kadesh", "title-not-capitalised"),
            ("Battle of Kadesh (-1274)", "title-year-appended"),
            ("Battle of Kadesh, -1274", "title-year-appended"),
            ("Battle of Kadesh, orontes, syria", "title-place-slug"),
        ] {
            let mut e = good();
            e["title"] = json!(t);
            assert!(
                rules(&e).contains(&want),
                "{t:?} should trip {want}, got {:?}",
                rules(&e)
            );
        }
    }

    /// The case-aware rule, which exists because `[A-Z]` rejected six real
    /// titles on the first batch that carried a non-Latin script.
    #[test]
    fn a_caseless_script_cannot_fail_a_capitalisation_rule() {
        for t in ["安史之乱", "معركة القادسية", "पानीपत का युद्ध", "応仁の乱"]
        {
            let mut e = good();
            e["title"] = json!(t);
            assert_eq!(admit(&e), vec![], "{t:?} must be admitted");
        }
    }

    // ---- batch rules ------------------------------------------------------

    fn at(t: &str, y: i64) -> Value {
        let mut e = good();
        e["title"] = json!(t);
        e["year"] = json!(y);
        e
    }

    /// THE REGRESSION. Different conquests, different places, four years apart.
    /// The old rule merged these and the event was gone for good.
    #[test]
    fn a_differing_place_name_is_a_distinction_not_noise() {
        let b = vec![
            at("Arab Conquest of Ctesiphon", 637),
            at("Arab Conquest of Egypt", 641),
        ];
        assert_eq!(
            admit_batch(&b),
            vec![],
            "neither may be flagged against the other"
        );
    }

    #[test]
    fn other_place_pairs_survive_too() {
        let b = vec![
            at("Battle of Panipat", 1526),
            at("Battle of Plassey", 1757),
            at("Siege of Vienna", 1529),
            at("Siege of Malta", 1565),
            at("Fall of Constantinople", 1453),
            at("Fall of Granada", 1492),
        ];
        assert_eq!(admit_batch(&b), vec![]);
    }

    #[test]
    fn a_restatement_is_refused_rather_than_merged() {
        for (a, ya, b, yb) in [
            (
                "Fall of Constantinople",
                1453,
                "The Fall of Constantinople",
                1453,
            ),
            (
                "Construction of the Great Wall",
                -221,
                "Construction of the Great Wall of China",
                -221,
            ),
            (
                "Black Death Reaches Europe",
                1347,
                "Arrival of the Black Death in Europe",
                1347,
            ),
            (
                "First Powered Flight",
                1903,
                "Wright Brothers First Powered Flight",
                1903,
            ),
        ] {
            let got = admit_batch(&[at(a, ya), at(b, yb)]);
            assert_eq!(got.len(), 1, "{a:?} / {b:?} should raise exactly one");
            assert_eq!(got[0].1.rule, "restatement-unresolved");
            // Refused, not resolved: the gate must not have picked a survivor.
            assert!(got[0].1.detail.contains("this gate will not choose"));
        }
    }

    /// Conservative by design: each title carries a word the other lacks, so
    /// this pair is left to human judgement rather than guessed at.
    #[test]
    fn same_event_different_name_is_left_for_a_human() {
        let b = vec![
            at("First Moon Landing", 1969),
            at("Apollo 11 Moon Landing", 1969),
        ];
        assert_eq!(admit_batch(&b), vec![]);
    }

    #[test]
    fn the_same_name_far_apart_is_two_events() {
        assert_eq!(
            admit_batch(&[at("Battle of Panipat", 1526), at("Battle of Panipat", 1761)]),
            vec![]
        );
    }

    /// Case is not identity: these converge to one `entity_id` at mint, so
    /// admitting both would assert one claim twice.
    #[test]
    fn one_identity_asserted_twice_is_refused() {
        let got = admit_batch(&[at("Battle of Kadesh", -1274), at("Battle Of Kadesh", -1274)]);
        assert_eq!(got.len(), 1, "got {got:?}");
        assert_eq!(got[0].1.rule, "duplicate-identity");
    }

    /// The 30 that were dropped must not be re-admittable unchanged — the
    /// artifact in `reverts/2026-08-17-undated-30/entries.json` is preserved so
    /// they can come back WITH a date, and this pins that they cannot come back
    /// without one.
    #[test]
    fn the_dropped_thirty_are_refused_as_they_stand() {
        let mut e = good();
        e["title"] = json!("Code of Hammurabi");
        e["year"] = json!(-1754);
        e["date_is_known"] = json!(false);
        assert_eq!(rules(&e), vec!["date-not-known"]);
        // …and are admitted the moment the contradiction is resolved.
        e["date_is_known"] = json!(true);
        assert_eq!(admit(&e), vec![]);
    }
}
