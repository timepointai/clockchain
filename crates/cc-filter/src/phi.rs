//! Φ's two halves, and the type-level wall between them.
//!
//! Φ's **support** is topology: provable, integer-exact, monotone under
//! accretion, and the only thing a hard decision may consume. Φ's **magnitude**
//! is model-dependent, ordinal, not monotone — "it may rank; it may never
//! threshold". Threshold a magnitude anywhere and the core distinction (certain
//! witness of absence vs. plausibility estimate) collapses at that call site, and
//! one inconsistent consumer poisons the guarantee globally.
//!
//! Enforcement is architectural. In Rust that means *un-writable*: [`Magnitude`]
//! implements neither `PartialOrd` nor `Ord`, has no public constructor from a
//! number, and offers no comparison against a scalar — so `magnitude > CUTOFF`
//! does not typecheck. Thresholding is not discouraged; it is a compile error.
//!
//! The split pays a second dividend. [`PhiSupport`] is integer, so it is the
//! only thing that has to be bit-identical across native and wasm; magnitude's
//! float smoothing is excused from cross-target reproducibility precisely
//! because it never gates. The epistemic hygiene rule and the cross-target
//! determinism guarantee turn out to be the same rule.

use crate::ids::{EntityId, WalkLen};
use cc_core::EventId;

/// One step of an evidenced walk: the entity stepped to and the co-occurrence
/// event that evidences the step.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WalkStep {
    /// The entity reached by this step.
    pub entity: EntityId,
    /// The event evidencing it.
    pub via: EventId,
}

/// The intermediary chain of a shortest evidenced walk.
///
/// Canonical, not merely *some* shortest walk: among all walks of the minimal
/// length it is the lexicographically least sequence of `(entity, via)` pairs.
/// That tie-break is what lets a sparse bidirectional search and a dense
/// doubling operator reconstruct the *identical* `supp(Φ)` rather than merely
/// agreeing on a boolean — which is what makes two realizations of the same
/// predicate safe to run on different nodes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct WalkWitness(Vec<WalkStep>);

impl WalkWitness {
    /// The empty witness — the reflexive case, where the walk is zero steps.
    pub fn reflexive() -> WalkWitness {
        WalkWitness(Vec::new())
    }

    /// The steps, in walk order.
    pub fn steps(&self) -> &[WalkStep] {
        &self.0
    }

    /// Build from an ordered step sequence. Crate-private: a witness that did not
    /// come out of the reachability kernel is not evidence of anything.
    pub(crate) fn from_steps(steps: Vec<WalkStep>) -> WalkWitness {
        WalkWitness(steps)
    }
}

/// Topological support of Φ: consensus-bearing, integer-exact, monotone under
/// accretion, and the only thing a hard decision may consume.
///
/// Fields are private so `supp(Φ)` can only be minted by the reachability
/// kernel — a settlement gate accepting a `PhiSupport` is accepting something
/// the filter actually computed, not a struct literal a call site assembled.
///
/// Not `Copy`, unlike the sketch in the plan: the witness is a variable-length
/// evidenced chain, and dropping it to gain `Copy` would drop the provenance
/// that makes the verdict certifiable.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PhiSupport {
    hops: WalkLen,
    witness: WalkWitness,
}

impl PhiSupport {
    /// The shortest evidenced walk length actually found — a *measurement*,
    /// distinct from the governed [`crate::HopBound`] it was searched under.
    pub fn hops(&self) -> WalkLen {
        self.hops
    }

    /// The canonical intermediary chain: provenance, never a score.
    pub fn witness(&self) -> &WalkWitness {
        &self.witness
    }

    /// The events this support was evidenced by, in walk order — the seam that
    /// later becomes the Merkle attribution path.
    pub fn consulted(&self) -> impl Iterator<Item = EventId> + '_ {
        self.witness.0.iter().map(|s| s.via)
    }

    /// Support for the reflexive case (`f_i == f_j`): zero hops, no evidence
    /// consulted. This is the `I` term of `T_0 = I ∨ B(t_q)` made a value.
    pub(crate) fn reflexive() -> PhiSupport {
        PhiSupport {
            hops: WalkLen::new(0),
            witness: WalkWitness::reflexive(),
        }
    }

    /// Mint support from a kernel result. Crate-private by design.
    pub(crate) fn from_walk(hops: WalkLen, witness: WalkWitness) -> PhiSupport {
        PhiSupport { hops, witness }
    }
}

/// Magnitude of Φ. Model-dependent, **not** monotone, **ordinal only**.
///
/// Implements neither `PartialOrd` nor `Ord`, exposes no constructor from a
/// number, and offers no comparison to a scalar. The load-bearing trick is that
/// thresholding requires a constant on one side of a comparison, and no type in
/// this crate can produce one: ranking needs only pairwise order among
/// magnitudes that actually exist, which [`RankKey`] provides; thresholding needs
/// a synthesized cutoff, which cannot be spoken.
///
/// Consequently no consumer *can* be the one inconsistent consumer that poisons
/// the guarantee — the global property is held by the type, not by reviewer
/// vigilance across every present and future call site.
///
/// ```compile_fail
/// # use cc_filter::Magnitude;
/// fn nope(a: Magnitude, b: Magnitude) -> bool {
///     a > b // ERROR: `Magnitude: PartialOrd` is not satisfied.
/// }
/// ```
///
/// ```compile_fail
/// # use cc_filter::Magnitude;
/// fn nope() -> Magnitude {
///     Magnitude::from(0.7) // ERROR: no `From<f64>` for `Magnitude`.
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Magnitude(f64);

impl Magnitude {
    /// Mint a magnitude. Crate-private: a magnitude that did not come out of the
    /// crate's own smoothing is not a Φ magnitude, it is a number someone chose.
    pub(crate) fn from_smoothed(value: f64) -> Magnitude {
        Magnitude(value)
    }

    /// Ranking is the sanctioned use ("what to corroborate first"). Yields an
    /// opaque key that is `Ord` only against other keys, so it can order a work
    /// queue and cannot be compared to a cutoff.
    pub fn rank_key(self) -> RankKey {
        RankKey(order_preserving_bits(self.0))
    }

    /// The only escape hatch for the raw number, named so its use is obvious in
    /// review: presentation and telemetry, never a decision.
    pub fn into_display_f64(self) -> f64 {
        self.0
    }
}

/// Total order over magnitudes, for ranking only.
///
/// No `From<u64>`, no public numeric constructor, private field: every `RankKey`
/// in existence came from a real [`Magnitude`], so `sort_by_key(|x|
/// x.mag.rank_key())` compiles and `key > RankKey::from(0.7)` names a constant
/// that does not exist.
///
/// ```compile_fail
/// # use cc_filter::RankKey;
/// fn nope() -> RankKey {
///     RankKey(0) // ERROR: field `0` is private.
/// }
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct RankKey(u64);

/// IEEE-754 total order as unsigned bits: flip the sign bit for non-negatives,
/// invert everything for negatives. Order-preserving, so sorting `RankKey`s
/// sorts the magnitudes behind them without ever exposing one.
fn order_preserving_bits(x: f64) -> u64 {
    let bits = x.to_bits();
    if bits & (1u64 << 63) != 0 {
        !bits
    } else {
        bits | (1u64 << 63)
    }
}
