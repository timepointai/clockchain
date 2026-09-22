//! The filter-version hash: what makes disagreement legible.
//!
//! Every verdict rides on a hash binding `(B(t), k, smoothing)`. Two nodes that
//! disagree therefore differ in exactly one of two legible ways — a different
//! `corpus_digest` (a gossip-horizon gap that closes on event exchange) or a
//! different `filter_version` (a governance event, itself recorded as a node-0
//! moment) — and never in an unexplained fork.
//!
//! These bytes are also the payload of the genesis `protocol_constants_v0`
//! moment: a filter version *is* a governed constant recorded in the ledger, so
//! a version bump is a settled event, not a silent redeploy.

use crate::ids::{framed, framed_tick, HopBound};
use cc_core::{FractionalBits, Tick};
use sha2::{Digest, Sha256};

/// Domain separation for the params preimage, so a filter-params hash can never
/// collide with an event `H0` computed over unrelated bytes.
const DST_FILTER_PARAMS: &[u8] = b"cc.filter.params.v0";

/// The identity of the rule that judged.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FilterVersion([u8; 32]);

impl FilterVersion {
    /// Adopt a version read back from a stored moment or a peer's judgment.
    pub const fn from_bytes(b: [u8; 32]) -> FilterVersion {
        FilterVersion(b)
    }

    /// The raw 32 version bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// How `B(t)` is built from moments, referenced by content hash.
///
/// A hash rather than an inline rule description because the co-occurrence rule
/// is a governed artifact that will outgrow any enum this crate could pin, and a
/// version hash must change when the rule does without this crate having to know
/// how the rule is spelled.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CooccurrenceRuleId([u8; 32]);

impl CooccurrenceRuleId {
    /// Adopt a governed rule id.
    pub const fn from_bytes(b: [u8; 32]) -> CooccurrenceRuleId {
        CooccurrenceRuleId(b)
    }
    /// The raw id bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The Φ magnitude specification, referenced by content hash.
///
/// Deliberately an id and never raw float coefficients: `canon(params)` must
/// serialize no float, or the version hash itself would stop being bit-identical
/// across targets — the one hash that absolutely cannot wobble.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SmoothingId([u8; 32]);

impl SmoothingId {
    /// Adopt a governed smoothing id.
    pub const fn from_bytes(b: [u8; 32]) -> SmoothingId {
        SmoothingId(b)
    }
    /// The raw id bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The governed taxonomy snapshot `Admiss` is evaluated against.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VocabularyVersion([u8; 32]);

impl VocabularyVersion {
    /// Adopt a governed vocabulary snapshot id.
    pub const fn from_bytes(b: [u8; 32]) -> VocabularyVersion {
        VocabularyVersion(b)
    }
    /// The raw id bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The IAU coordinate-time scale anchoring Clock Zero.
///
/// Carried as a governed code rather than a string so the choice lands in the
/// version hash as an exact integer. Which scale ships at genesis is an open
/// governance call; [`TimeScaleId::UNSET`] exists so a build that has not made
/// the call produces a *different* version hash from one that has, instead of
/// silently sharing a version with it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TimeScaleId(u16);

impl TimeScaleId {
    /// No scale blessed yet — genesis must not ship this value.
    pub const UNSET: TimeScaleId = TimeScaleId(0);
    /// Barycentric Coordinate Time.
    pub const TCB: TimeScaleId = TimeScaleId(1);
    /// Geocentric Coordinate Time.
    pub const TCG: TimeScaleId = TimeScaleId(2);
    /// Terrestrial Time.
    pub const TT: TimeScaleId = TimeScaleId(3);

    /// The governed code.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// The b256 coordinate constants `B(t)` is built over.
///
/// Every field is an exact integer. The tick duration is held in attoseconds
/// (`10^-18` s) rather than as a duration type or a float because the version
/// hash must be a pure function of integers — the whole point of the b256
/// encoding is that two writers never drift, and a float here would reintroduce
/// exactly the representation-dependent divergence the encoding exists to kill.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct B256Constants {
    /// The IAU scale anchoring Clock Zero.
    pub clock_zero_scale: TimeScaleId,
    /// Tick duration in attoseconds. One SI second is `1_000_000_000_000_000_000`.
    pub tick_attoseconds: u128,
    /// The governed integer/fraction split `S`.
    pub split: FractionalBits,
}

/// The in-crate tag covering the **support path** only.
///
/// A change to consensus-bearing logic — the reachability kernel, a window-factor
/// branch, the admissibility factor — MUST bump this. A change to magnitude or
/// smoothing need not, because magnitude is non-consensus. The failure this
/// exists to make impossible is two nodes on different code carrying the same
/// tag and diverging on a hard verdict silently.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LogicTag([u8; 32]);

impl LogicTag {
    /// Adopt a tag.
    pub const fn from_bytes(b: [u8; 32]) -> LogicTag {
        LogicTag(b)
    }
    /// The raw tag bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The support-path tag this build ships.
///
/// Bump the trailing version on any diff that can change a `supp(Φ)` bit. It is
/// spelled as readable bytes on purpose: a reviewer comparing two builds should
/// be able to see the tag differ without decoding a hash.
pub const SUPPORT_PATH_LOGIC_TAG: LogicTag = LogicTag(*b"cc-filter/support-path/v0\0\0\0\0\0\0\0");

/// The governed parameters that constitute the rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FilterParams {
    /// How `B(t)` is built from moments.
    pub cooccurrence_rule: CooccurrenceRuleId,
    /// The governed reachability bound. A query may ask for less, never more.
    pub k_max: HopBound,
    /// The Φ magnitude specification.
    pub smoothing: SmoothingId,
    /// The governed taxonomy snapshot for `Admiss`.
    pub vocabulary: VocabularyVersion,
    /// Clock Zero, tick duration, integer/fraction split.
    pub b256: B256Constants,
    /// The compiled support-path identity.
    pub logic_tag: LogicTag,
}

/// The pinned Timepoint Telemetry taxonomy this build judges against.
///
/// sha256 of `vendor/tt/taxonomy-v2.1.json` (TT ontology v2.1.0). **Blessed** — this is no longer
/// a placeholder: `Admiss(c, t_q)` is evaluated against TT's vocabulary, so a verdict commits to
/// which taxonomy produced it.
///
/// Clockchain is downstream of TT for vocabulary and only for vocabulary. Identity stays ours:
/// `H0` remains the ledger's key and `content_hash` remains an attribute, per the boundary
/// ratified with the tt-core agent on 2026-08-12.
pub const TT_TAXONOMY_SHA256: [u8; 32] = [
    0x31, 0xed, 0x38, 0x5e, 0x26, 0x52, 0x2a, 0x5b, 0x54, 0x8f, 0x74, 0x04, 0xf7, 0x75, 0x7e, 0xe3,
    0x70, 0xed, 0x97, 0x83, 0xdb, 0xd5, 0x50, 0xb0, 0x5c, 0xd6, 0x9e, 0x89, 0xe9, 0x46, 0x21, 0x13,
];

/// The parameters this build actually ships, and whose hash genesis records.
///
/// Three of these are governance artifacts that have **not been blessed**: the
/// co-occurrence rule, the smoothing spec, and the vocabulary snapshot. They are
/// spelled as readable byte strings rather than zeros for the same reason
/// [`SUPPORT_PATH_LOGIC_TAG`] is: an unblessed build must produce a *legibly
/// different* version hash from a blessed one, and a reviewer holding two
/// version hashes should be able to learn why they differ by reading the
/// preimage rather than by guessing. All-zero bytes would look like a value.
///
/// Blessing any of these is a governance event that changes the filter version,
/// and the new version is itself recorded as a node-0 moment — which is exactly
/// the property that keeps a rule change from being a silent redeploy.
pub fn v0_params() -> FilterParams {
    FilterParams {
        cooccurrence_rule: CooccurrenceRuleId::from_bytes(*b"cc.cooccurrence/UNBLESSED/v0\0\0\0\0"),
        k_max: HopBound::new(4),
        smoothing: SmoothingId::from_bytes(*b"cc.smoothing/UNBLESSED/v0\0\0\0\0\0\0\0"),
        vocabulary: VocabularyVersion::from_bytes(TT_TAXONOMY_SHA256),
        // These three ARE settled: they are `cc_core::B256Constants::V0` spelled
        // as the exact integers the version hash requires. `clock_zero
        // "J2000.0 (TCB)"` is `TimeScaleId::TCB`; `tick "1 SI second"` is 10^18
        // attoseconds; `split` is the pinned 64.
        b256: B256Constants {
            clock_zero_scale: TimeScaleId::TCB,
            tick_attoseconds: 1_000_000_000_000_000_000,
            split: FractionalBits(64),
        },
        logic_tag: SUPPORT_PATH_LOGIC_TAG,
    }
}

/// The version of the rule this build ships — the value recorded in the genesis
/// `protocol_constants_v0` moment and published on `/health`.
pub fn v0_version() -> FilterVersion {
    version_of(&v0_params())
}

/// Serialize the params into their hash preimage.
///
/// Hand-rolled, length-framed, big-endian, no `serde`, no floats — every byte is
/// a pure function of the fields in a fixed order, so the version hash is
/// bit-identical on a server and in a wasm mirror.
pub fn canon_params(p: &FilterParams) -> Vec<u8> {
    let mut out = Vec::new();
    framed(&mut out, DST_FILTER_PARAMS);
    framed(&mut out, p.cooccurrence_rule.as_bytes());
    framed(&mut out, &[p.k_max.get()]);
    framed(&mut out, p.smoothing.as_bytes());
    framed(&mut out, p.vocabulary.as_bytes());
    framed(&mut out, &p.b256.clock_zero_scale.get().to_be_bytes());
    framed(&mut out, &p.b256.tick_attoseconds.to_be_bytes());
    framed(&mut out, &p.b256.split.0.to_be_bytes());
    framed(&mut out, p.logic_tag.as_bytes());
    out
}

/// The version hash over the canonical params bytes.
pub fn version_of(p: &FilterParams) -> FilterVersion {
    FilterVersion(Sha256::digest(canon_params(p)).into())
}

/// Fold a coordinate into a digest preimage, exported so the snapshot view and
/// the golden fixtures hash coordinates the one canonical way.
pub(crate) fn put_tick(out: &mut Vec<u8>, t: Tick) {
    framed_tick(out, t);
}

#[cfg(test)]
mod v0_tests {
    use super::*;

    /// The vendored TT bundle must be byte-identical to the hash we judge under.
    ///
    /// This is the CI byte-check. `vocabulary` is the bundle's sha256, so an edited
    /// or swapped bundle would silently change what every verdict was judged
    /// against while the constant kept claiming otherwise. Reads the file at test
    /// time — the crate itself still does no I/O.
    #[test]
    fn tt_taxonomy_bundle_matches_the_pinned_hash() {
        use sha2::{Digest, Sha256};
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/tt/taxonomy-v2.1.json"
        );
        let bytes = std::fs::read(path).expect("vendored TT bundle is missing");
        let got: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(
            got, TT_TAXONOMY_SHA256,
            "vendor/tt/taxonomy-v2.1.json does not match the pinned hash — the taxonomy this \
             build judges against is not the one it claims"
        );
    }

    /// Every claim type in the ledger must exist in the pinned bundle.
    ///
    /// Guards the failure telemetry's review caught: treating our observed 61 as
    /// an allow-list rather than validating against the bundle's full node set.
    #[test]
    fn the_pinned_bundle_contains_a_recognisable_taxonomy() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/tt/taxonomy-v2.1.json"
        );
        let raw = std::fs::read_to_string(path).expect("vendored TT bundle is missing");
        assert!(
            raw.contains("\"tt-ontology/1.0\""),
            "not a TT ontology bundle"
        );
        assert!(raw.contains("\"2.1.0\""), "unexpected bundle version");
        for id in [
            "conflict-and-warfare",
            "accession-and-coronation",
            "politics-governance-and-law",
        ] {
            assert!(
                raw.contains(id),
                "bundle is missing a node the ledger uses: {id}"
            );
        }
    }

    /// The version this build ships is pinned, because it is recorded in the
    /// ledger's founding moment and cannot be renegotiated afterwards.
    ///
    /// If this fails, a governed parameter or the support-path logic tag moved.
    /// That is allowed — it is what a governance event *is* — but it means the
    /// recorded `protocol_constants_v0` moment now names a rule this build no
    /// longer implements, and genesis must be re-recorded before the node is
    /// allowed to serve.
    #[test]
    fn v0_version_is_pinned() {
        assert_eq!(
            hex::encode(v0_version().as_bytes()),
            "28d53eae5b3744780f72d54b1256d4c811bcc719040ea8de9d920df89be50408"
        );
    }

    /// `cc-core` publishes the coordinate constants as display prose while the
    /// version hash needs them as exact integers. Nothing in the type system
    /// links the two, so the correspondence is asserted here — once, in the one
    /// place that owns the translation.
    ///
    /// The failure this prevents: `cc-core` is edited to say `TCG` or a
    /// millisecond tick, every `/health` page dutifully reports the new prose,
    /// and the version hash does not move — so two nodes running genuinely
    /// different coordinate systems claim to be running the same rule.
    #[test]
    fn the_published_prose_matches_the_hashed_integers() {
        let p = v0_params();
        let core = cc_core::B256Constants::V0;

        assert_eq!(p.b256.split, core.split, "split must not be re-typed");

        let scale = match p.b256.clock_zero_scale {
            s if s.get() == TimeScaleId::TCB.get() => "TCB",
            s if s.get() == TimeScaleId::TCG.get() => "TCG",
            s if s.get() == TimeScaleId::TT.get() => "TT",
            _ => "UNSET",
        };
        assert!(
            core.clock_zero.contains(scale),
            "cc-core publishes clock_zero {:?} but the hash commits to {scale}",
            core.clock_zero
        );

        assert_eq!(
            core.tick, "1 SI second",
            "the tick prose changed; tick_attoseconds must change with it"
        );
        assert_eq!(
            p.b256.tick_attoseconds, 1_000_000_000_000_000_000,
            "1 SI second is 10^18 attoseconds"
        );
    }

    /// The shipped rule and the golden fixtures must not share a version.
    ///
    /// They differ in their governed ids, so if these ever collided it would
    /// mean `canon_params` had stopped covering a field — and every test that
    /// passes under the fixture params would be silently asserting nothing about
    /// the rule actually shipped.
    #[test]
    fn the_shipped_rule_is_not_the_test_fixture() {
        assert_ne!(v0_version(), version_of(&crate::golden::golden_params()));
    }
}

// ===========================================================================
// The bundle's own id set, generated at build time
// ===========================================================================

include!(concat!(env!("OUT_DIR"), "/tt_bundle.rs"));

/// Is this a real TT node id?
///
/// The distinction admissibility needs. A typo'd id is **not a question about
/// the world** and must fail differently from a valid id this corpus has simply
/// not declared — which is a real question the corpus cannot answer. Returning
/// identical silence for both is the gap/finding collapse that TT Policy 2
/// exists to prevent, and it is the collapse whether the shared outcome is
/// refusal or silence.
///
/// Checked against the **full bundle**, never against our declared vocabulary.
/// Coverage is honestly ours to assert; validity never is.
pub fn is_valid_tt_id(id: &str) -> bool {
    TT_IDS.binary_search(&id).is_ok()
}

/// Follow a retirement to its successor, transitively.
///
/// Wired while nothing we use is retired — which is the only moment it is
/// cheap. A Structure release that retires one of our types turns this from
/// dormant into load-bearing with no code change.
///
/// Bounded rather than trusting the bundle to be acyclic: a cycle in a released
/// artifact would otherwise hang a read, and a read that hangs is worse than
/// one that reports the input it could not resolve.
pub fn resolve_tt_id(id: &str) -> &str {
    let mut cur = id;
    for _ in 0..8 {
        match TT_SUPERSEDED.binary_search_by_key(&cur, |(a, _)| a) {
            Ok(i) => cur = TT_SUPERSEDED[i].1,
            Err(_) => return cur,
        }
    }
    cur
}

/// The governed claim-type code for a TT label.
///
/// Derived from the label rather than assigned, so two nodes that never spoke
/// agree on the code for a tag — the same argument that makes every other
/// identity here content-addressed. `0` is reserved (an unresolved label must
/// not land on a real type), so it is mapped away.
///
/// **This truncation is why the query boundary has to accept the label.** Four
/// bytes of SHA-256 carry no route back to the string, so a typo'd id and a
/// valid-but-undeclared id both arrive at a `u32` boundary as well-formed
/// numbers that are simply absent from the vocabulary. The information needed to
/// tell them apart is destroyed before the request lands, and no check placed
/// there can recover it — which is the whole of TT conformance gap 2.
pub fn claim_code(label: &str) -> u32 {
    let d = Sha256::digest(label.as_bytes());
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    if n == 0 {
        1
    } else {
        n
    }
}

/// The lens the **bundle** assigns this id, if the id is real.
///
/// `None` means "not a node", which is a different answer from "a node with no
/// lens" — the bundle has none of the latter, and if a release ever introduces
/// one this returns `None` for it rather than inventing a default.
///
/// Admission uses this to refuse a claim that declares a lens its own type does
/// not carry. That is not a judgement call the pipeline gets to make.
pub fn lens_of(id: &str) -> Option<&'static str> {
    TT_LENS
        .binary_search_by_key(&id, |(a, _)| a)
        .ok()
        .map(|i| TT_LENS[i].1)
}

/// The node's parent, if it has one. Branches sit at the root and have none.
pub fn parent_of(id: &str) -> Option<&'static str> {
    TT_PARENT
        .binary_search_by_key(&id, |(a, _)| a)
        .ok()
        .map(|i| TT_PARENT[i].1)
}

/// Every ancestor of `id`, nearest first. Empty for a branch.
///
/// Bounded for the same reason [`resolve_tt_id`] is: a cycle in a released
/// artifact must not hang a caller. The bundle is three levels deep
/// (branch → species → subspecies), so 8 is generous.
pub fn ancestors_of(id: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut cur = id;
    for _ in 0..8 {
        match parent_of(cur) {
            Some(p) => {
                out.push(p);
                cur = p;
            }
            None => break,
        }
    }
    out
}

/// Is `maybe_ancestor` at or above `id` in the hierarchy?
///
/// Used to catch an "alternative" classification that is simply the primary's
/// own ancestor. That is not a competing reading of the event — it is the same
/// reading, less specific — and recording it as an alternative dilutes a field
/// whose whole value is that it means "the classifier had genuine competition".
pub fn is_ancestor_of(maybe_ancestor: &str, id: &str) -> bool {
    maybe_ancestor == id || ancestors_of(id).contains(&maybe_ancestor)
}

/// What the bundle says about a B-lens action's shadow in the A lens.
///
/// **Three states, and the two absences are different facts.** Collapsing them
/// would rebuild the gap/finding collapse inside the shadow derivation, one
/// level down from where [`is_valid_tt_id`] closes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bridge {
    /// The bundle lists no bridge for this action. We do not know what the
    /// record would have kept, and the bundle does not say.
    Unlisted,
    /// The bundle lists this action and states that it leaves **no** trace in
    /// the public record — `relation: "unrecorded"`. An asserted absence, which
    /// is a claim about the world, not a hole in the data.
    Unrecorded,
    /// The derivation: this action, under `relation`, shows up as `event`.
    To {
        /// How the action becomes the event: `scales-up-to`, `recorded-as`, …
        relation: &'static str,
        /// The A-lens node the shadow lands on.
        event: &'static str,
    },
}

/// The bridge the bundle records for a B-lens action.
///
/// Never `0.0`, never an empty string, never a missing key: a shadow that
/// cannot be derived says which kind of cannot it is.
pub fn bridge_of(action: &str) -> Bridge {
    match TT_BRIDGES.binary_search_by_key(&action, |(a, _, _)| a) {
        Err(_) => Bridge::Unlisted,
        Ok(i) => match TT_BRIDGES[i] {
            (_, relation, Some(event)) => Bridge::To { relation, event },
            (_, _, None) => Bridge::Unrecorded,
        },
    }
}

#[cfg(test)]
mod tt_bundle_tests {
    use super::*;

    #[test]
    fn the_generated_table_is_the_whole_bundle() {
        // 149 nodes in v2.1.0. A table that silently shrank would make invalid
        // ids look valid-but-undeclared, which is the collapse this closes.
        assert_eq!(TT_IDS.len(), 149, "TT_IDS must cover every bundle node");
        assert!(
            TT_IDS.windows(2).all(|w| w[0] < w[1]),
            "must be sorted, unique"
        );
    }

    #[test]
    fn validity_and_declaration_are_different_questions() {
        assert!(is_valid_tt_id("politics-governance-and-law"));
        // Real bundle node, and one Clockchain has never declared.
        assert!(is_valid_tt_id("everyday-movement-and-commute"));
        // Not a node. Plausible-looking, which is the dangerous kind.
        assert!(!is_valid_tt_id("politics-governance-and-laws"));
        assert!(!is_valid_tt_id("conflict-and-war"));
        assert!(!is_valid_tt_id(""));
    }

    #[test]
    fn retirement_resolves_to_the_successor() {
        // v2.1.0 retires exactly one node.
        assert_eq!(TT_SUPERSEDED.len(), 1);
        assert_eq!(
            resolve_tt_id("everyday-movement-and-commute"),
            "journey-and-travel"
        );
        // A live id resolves to itself; an unknown one is returned unchanged
        // rather than mapped to something plausible.
        assert_eq!(resolve_tt_id("journey-and-travel"), "journey-and-travel");
        assert_eq!(resolve_tt_id("not-a-node"), "not-a-node");
    }

    #[test]
    fn the_bundle_settles_the_lens() {
        assert_eq!(TT_LENS.len(), 149);
        assert_eq!(lens_of("politics-governance-and-law"), Some("A"));
        assert_eq!(lens_of("bonding-and-kinship"), Some("B"));
        // Not a node: no lens, rather than a defaulted one.
        assert_eq!(lens_of("politics-governance-and-laws"), None);
        assert_eq!(lens_of(""), None);
        // The split the bundle actually declares.
        assert_eq!(TT_LENS.iter().filter(|(_, l)| *l == "A").count(), 79);
        assert_eq!(TT_LENS.iter().filter(|(_, l)| *l == "B").count(), 70);
    }

    #[test]
    fn ancestry_comes_from_the_bundle() {
        assert_eq!(
            parent_of("politics-governance-and-law"),
            None,
            "a branch has no parent"
        );
        assert_eq!(
            parent_of("deliberative-assembly-and-congress"),
            Some("governance-and-popular-politics")
        );
        // The real case this exists for: the UN entry's "alternative" is its
        // primary's own parent.
        assert!(is_ancestor_of(
            "governance-and-popular-politics",
            "deliberative-assembly-and-congress"
        ));
        // …and a genuine sibling is not an ancestor, in either direction.
        assert!(!is_ancestor_of(
            "constitutions-and-charters",
            "legislation-edicts-and-decrees"
        ));
        assert!(!is_ancestor_of(
            "legislation-edicts-and-decrees",
            "constitutions-and-charters"
        ));
        // Every ancestry chain terminates at a branch, so the bounded walk
        // never truncates a real path.
        for (id, _) in TT_LENS {
            let a = ancestors_of(id);
            assert!(
                a.len() <= 3,
                "{id} has a chain of {} — deeper than the bundle's shape",
                a.len()
            );
            if let Some(top) = a.last() {
                assert_eq!(parent_of(top), None, "{id} chain must end at a branch");
            }
        }
    }

    #[test]
    fn the_two_kinds_of_missing_bridge_stay_distinct() {
        assert_eq!(TT_BRIDGES.len(), 26);
        assert_eq!(
            bridge_of("aggression-and-violence"),
            Bridge::To {
                relation: "scales-up-to",
                event: "conflict-and-warfare"
            }
        );
        // Listed, and the bundle asserts there is no public trace. This is a
        // claim about the world.
        assert_eq!(
            bridge_of("courtship-and-falling-in-love"),
            Bridge::Unrecorded
        );
        // Not listed at all. The bundle is silent, which is not the same claim.
        assert_eq!(bridge_of("politics-governance-and-law"), Bridge::Unlisted);
        assert_ne!(
            bridge_of("courtship-and-falling-in-love"),
            bridge_of("not-a-node")
        );
        // The bundle's own counts, so a release that changed the balance
        // surfaces here rather than inside a derived shadow.
        let derivable = TT_BRIDGES.iter().filter(|(_, _, e)| e.is_some()).count();
        assert_eq!(derivable, 23, "23 bridges derive; 3 assert unrecorded");
        let listed_b = TT_LENS
            .iter()
            .filter(|(id, l)| *l == "B" && bridge_of(id) != Bridge::Unlisted)
            .count();
        assert!(
            listed_b < 70,
            "bridges are partial by design; got {listed_b}/70"
        );
        // Every bridge must run B -> A. One pointing the other way would make a
        // shadow derive a human action from a recorded event, inverting the
        // whole construction.
        for (action, _, event) in TT_BRIDGES {
            assert_eq!(lens_of(action), Some("B"), "{action} must be a B node");
            if let Some(e) = event {
                assert_eq!(lens_of(e), Some("A"), "{e} must be an A node");
            }
        }
    }
}
