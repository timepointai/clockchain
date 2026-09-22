//! The three-valued verdict, the two identities every verdict rides with, and
//! the fourth thing that is never folded into a verdict.
//!
//! `Filter(x) = 0` is "reject", but *absence of evidence*, *a query that returned
//! nothing*, and *an error consulting the store* must be distinguishable in the
//! response semantics themselves, because a fail-closed caller amplifies whatever
//! ambiguity is left behind. So the verdict is `Supported / Unsupported /
//! Contradicted` and [`FilterError`] is a fourth thing outside the enum.

use crate::ids::{ClaimType, CorpusDigest, EntityId, HopBound};
use crate::phi::PhiSupport;
use crate::version::FilterVersion;
use crate::view::ViewError;
use cc_core::{EventId, Tick};

/// The outcome of one feasibility evaluation.
///
/// The `Unsupported`/`Contradicted` split is the whole three-valued point and it
/// is *evidence-relative*: a defunct carrier queried in 2025 whose window is
/// `[1937, 1991]` is `Contradicted` (the record says it ended), while a real
/// interaction the record simply never captured is `Unsupported` (the record is
/// silent). Collapsing them — the naive `bool` filter — is the failure the whole
/// design exists to prevent.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Every factor held against the currently recorded evidence.
    ///
    /// Carries the topological support only, and is *not* a truth claim: it says
    /// what the graph supports, never what the world contains.
    Supported {
        /// `supp(Φ)` — the shortest evidenced walk and its canonical witness.
        support: PhiSupport,
    },

    /// A factor is zero because the record is **silent**: no window evidence, no
    /// vocabulary entry, no evidenced walk. Absence of evidence, never evidence
    /// of absence.
    ///
    /// A `Vec` because the audit path enumerates every vanished factor while the
    /// hot path short-circuits after the first; the list length is the only thing
    /// the two paths are allowed to differ in.
    Unsupported {
        /// Which factor(s) vanished, and how.
        because: Vec<AbsenceWitness>,
    },

    /// A factor is zero because the record **contradicts**: a recorded cessation
    /// puts `t_q` outside a known-closed window, or the vocabulary records the
    /// claim type as outside its validity band. This is revocation — the
    /// exoneration case, positive contrary evidence.
    Contradicted {
        /// The contrary evidence.
        by: ContraryWitness,
    },
}

impl Verdict {
    /// The consensus-bearing discriminant, stripped of witness detail.
    ///
    /// Exists because the equality two nodes must agree on is
    /// `(verdict-kind, supp(Φ))`, not the full value: witness completeness is
    /// deterministic enrichment and must never be a fork input.
    pub fn kind(&self) -> VerdictKind {
        match self {
            Verdict::Supported { .. } => VerdictKind::Supported,
            Verdict::Unsupported { .. } => VerdictKind::Unsupported,
            Verdict::Contradicted { .. } => VerdictKind::Contradicted,
        }
    }

    /// `supp(Φ)`, present only on a `Supported` verdict.
    pub fn support(&self) -> Option<&PhiSupport> {
        match self {
            Verdict::Supported { support } => Some(support),
            _ => None,
        }
    }
}

/// The verdict discriminant alone — the half of the consensus projection that is
/// not `supp(Φ)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u8)]
pub enum VerdictKind {
    /// Every factor held.
    Supported = 0,
    /// A factor vanished into silence.
    Unsupported = 1,
    /// A factor was contradicted by positive contrary evidence.
    Contradicted = 2,
}

/// Which factor vanished, and how — a certain witness of *missing* evidence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AbsenceWitness {
    /// The record has no evidenced start for this entity.
    NoRecordedStart {
        /// The entity the record is silent about.
        entity: EntityId,
    },
    /// `t_q` precedes the entity's evidenced start: the record does not place it
    /// in existence yet, which is silence about `t_q`, not a claim of absence.
    BeforeRecordedStart {
        /// The entity.
        entity: EntityId,
        /// Its evidenced start.
        start: Tick,
    },
    /// The governed vocabulary snapshot is silent about this claim type.
    ClaimTypeUnrecorded {
        /// The claim type the vocabulary does not carry at `t_q`.
        claim: ClaimType,
    },
    /// No evidenced walk of `<= k` hops between the subjects in `B(t_q)`.
    ///
    /// The bound is carried because "unreachable" is only meaningful relative to
    /// the `k` it was searched under, and `k` is governed.
    NoEvidencedWalk {
        /// One subject.
        from: EntityId,
        /// The other.
        to: EntityId,
        /// The governed bound the search ran under.
        within: HopBound,
    },
}

/// Positive contrary evidence — the record says no, rather than saying nothing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ContraryWitness {
    /// `t_q` is past a recorded cessation. A known close proves the entity
    /// existed, so this can never be downgraded to mere silence.
    AfterRecordedCessation {
        /// The entity.
        entity: EntityId,
        /// Its recorded cessation coordinate.
        ceased: Tick,
        /// The events the closed window was derived from.
        derived_from: Vec<EventId>,
    },
    /// The claim type's governed validity band ended before `t_q`.
    ClaimTypeOutsideValidity {
        /// The claim type.
        claim: ClaimType,
        /// The recorded end of its validity band.
        band_end: Tick,
        /// The vocabulary events the ruling was derived from.
        derived_from: Vec<EventId>,
    },
}

/// A verdict never escapes the crate bare.
///
/// Two identities ride on every judgment: the **rule** that judged
/// (`filter_version`) and the **inputs** it judged over (`corpus_digest`).
/// Carrying them on the returned value — rather than assembling them at the call
/// site, where they can be forgotten — is what lets a downstream node classify
/// any disagreement (different digest = gossip-horizon gap; different version =
/// governance event) instead of seeing an unexplained fork.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Judgment {
    /// The three-valued outcome.
    pub verdict: Verdict,
    /// The rule that judged.
    pub filter_version: FilterVersion,
    /// The inputs it judged over. A legibility tag, deliberately *not* part of
    /// the consensus equality.
    pub corpus_digest: CorpusDigest,
}

impl Judgment {
    /// The projection two nodes must agree on to be said to agree.
    ///
    /// `corpus_digest` is excluded because two nodes with different gossip
    /// horizons legitimately hold different inputs; Φ's magnitude is excluded
    /// because it is non-consensus by construction. What remains is exactly the
    /// set of bits a hard decision can depend on.
    pub fn consensus_projection(&self) -> ConsensusProjection {
        ConsensusProjection {
            kind: self.verdict.kind(),
            support: self.verdict.support().cloned(),
            filter_version: self.filter_version,
        }
    }
}

/// `(verdict-kind, supp(Φ), filter_version)` — the consensus-bearing bits.
///
/// A separate type rather than a tuple so that "what two nodes compare" is a
/// thing with a name that a later reader cannot widen by accident.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConsensusProjection {
    /// The verdict discriminant.
    pub kind: VerdictKind,
    /// `supp(Φ)` when supported.
    pub support: Option<PhiSupport>,
    /// The rule that produced it.
    pub filter_version: FilterVersion,
}

/// The audit-path result: a judgment plus every event it consulted.
///
/// The hot path returns the first (cheapest) witness, which is right for a
/// per-call read; a portable, evidence-relative certificate wants *every* zeroed
/// factor and the full consulted list. Both come out of the same factor
/// implementations, so the cost optimization can never change semantics.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Certificate {
    /// Verdict + the two identities.
    pub judgment: Judgment,
    /// The moments touched, deduplicated and in ascending id order so the list is
    /// canonical. This is the attribution seam a Merkle multiproof later replaces.
    pub consulted: Vec<EventId>,
    /// All absent factors, independent of the governed first-zero verdict.
    pub absences: Vec<AbsenceWitness>,
    /// All contrary factors, including those masked by an earlier absence.
    /// Diagnostic evidence only; does not change the consensus projection.
    pub contradictions: Vec<ContraryWitness>,
}

/// Distinct from any verdict: a view failure is not "unsupported".
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum FilterError {
    /// The corpus could not be consulted — fail closed above this crate.
    #[error("corpus could not be consulted: {0}")]
    View(#[from] ViewError),
    /// The query itself is not well-formed, so there is nothing to judge.
    #[error("malformed feasibility query: {0}")]
    Malformed(#[from] QueryError),
}

/// Ways a query fails to be a question this rule can answer.
///
/// Both arms exist because answering them anyway would silently break something
/// the rest of the design depends on, and returning `Unsupported` for either
/// would report a verdict for a question that was never asked.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum QueryError {
    /// The caller asked for a hop bound the governed rule does not sanction.
    ///
    /// Answering under a `k` the filter version does not bind would make the
    /// version hash a lie: two nodes could carry the same version and have
    /// searched different neighbourhoods.
    #[error("hop bound {requested:?} exceeds the governed bound {governed:?}")]
    HopBoundExceedsGoverned {
        /// What the caller asked for.
        requested: HopBound,
        /// What the filter version binds.
        governed: HopBound,
    },
    /// `t_q` is the window sentinel.
    ///
    /// The sentinel is the reserved maximal bound that makes `t_q <= end(f)` hold
    /// with no special case; admitting it as a *query* coordinate would make
    /// every open window trivially satisfied at the one coordinate where the
    /// arithmetic carries no information.
    #[error("t_q is the reserved existence-window sentinel, not a coordinate")]
    QueryTimeIsSentinel,
}

/// The hot-path result type.
pub type FilterResult = Result<Judgment, FilterError>;
