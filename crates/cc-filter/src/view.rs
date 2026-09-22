//! `CorpusView` — the time-sliced seam the filter reads the graph through.
//!
//! This trait is the entire reason `cc-filter` is a crate rather than four
//! indicator checks inlined against Postgres in `cc-node`. The filter is the
//! swarm's consensus rule, and "same Φ everywhere" has to be a *build property*:
//! the same compiled logic must run on the server, in a batch backfill, and
//! inside an embedded wasm mirror. One trait now buys that; retrofitting it
//! after a direct SQL feasibility path exists is a rewrite plus a swarm epoch
//! that cannot prove convergence.

use crate::ids::{ClaimType, CorpusDigest, EntityId};
use std::collections::BTreeMap;

use cc_core::{EventId, ExistenceWindow, Tick, WindowEnd};

/// Read-only, time-sliced projection of the evidence ledger.
///
/// **Every method is pinned to `as_of` (= `t_q`).** An implementation MUST
/// return only evidence whose event-time is `<= as_of`. That bound is not a
/// convenience filter; it is what makes monotonicity hold — a 2017 moment cannot
/// touch a 2016-pinned verdict because the view never yields it. There is
/// deliberately no method that returns the live graph, and `as_of` is never an
/// `Option`: an unbounded read would let a later moment leak into a pinned
/// verdict silently, which is the worst kind of failure because nothing alarms.
pub trait CorpusView {
    /// Co-occurrence neighbours of `entity` in `B(as_of)`: every entity sharing
    /// a moment with `entity` at event-time `<= as_of`, each with the
    /// [`EventId`] that evidences the co-occurrence.
    ///
    /// The provenance is not decoration. Every verdict must be able to enumerate
    /// the moments it consulted, because a certificate that names its evidence is
    /// what later routes per-call attribution — and which events a *past* verdict
    /// touched cannot be reconstructed after the fact.
    ///
    /// Implementations should return the list ascending by `(other, via)`. The
    /// filter re-sorts defensively (see [`crate::reach`]) so that a view bug can
    /// never change a consensus verdict, but the contract is stated here because
    /// a view that honours it lets the filter's sort be a no-op.
    fn neighbors(&self, entity: EntityId, as_of: Tick) -> Result<Vec<Edge>, ViewError>;

    /// The same question for many entities at once.
    ///
    /// `Known_k` expands a whole BFS level before it needs any of the answers,
    /// and on a corpus with mean degree near 48 a four-hop walk asks this
    /// thousands of times. Against a local store that is free; against a store
    /// one network hop away it is the entire cost of a verdict — measured at
    /// ~36s for a `Supported` answer, versus ~4s for the identical code and data
    /// with the store on localhost. The work was never the lookups; it was the
    /// round trips.
    ///
    /// The default implementation is exactly the loop it replaces, so every
    /// existing view keeps working untouched and an in-memory view has no reason
    /// to override it. A backed view overrides it with one query.
    ///
    /// **This must return precisely what `neighbors` would**, entity by entity.
    /// It is not a place to widen or narrow the relation: a batched read that
    /// disagreed with the single read would make a verdict depend on how many
    /// entities happened to be in a frontier together.
    fn neighbors_many(
        &self,
        entities: &[EntityId],
        as_of: Tick,
    ) -> Result<BTreeMap<EntityId, Vec<Edge>>, ViewError> {
        let mut out = BTreeMap::new();
        for &e in entities {
            out.insert(e, self.neighbors(e, as_of)?);
        }
        Ok(out)
    }

    /// The entity's existence window as recorded in this view at `as_of`.
    ///
    /// Three-state on both ends. An entity the view has never heard of is not an
    /// error and not an empty success — it is [`Windowed::unrecorded`], a real
    /// evidenced silence.
    fn window(&self, entity: EntityId, as_of: Tick) -> Result<Windowed, ViewError>;

    /// Type admissibility of claim-type `c` at `as_of`: taxonomic validity plus
    /// temporal coherence against the governed vocabulary snapshot. A sparse
    /// lookup, never a scan — this factor sits in front of the expensive
    /// reachability branch precisely because it is cheap.
    fn admissibility(&self, c: ClaimType, as_of: Tick) -> Result<Admitted, ViewError>;

    /// Identity of the event set this view projects, bound onto every judgment so
    /// a disagreement is legible rather than an unexplained fork.
    fn corpus_digest(&self) -> CorpusDigest;
}

/// One evidenced co-occurrence step: the neighbour reached and the event that
/// evidences reaching it.
///
/// Ordered by `(other, via)` — `Ord` is derived in that field order on purpose,
/// because that ordering *is* the canonical tie-break that makes `supp(Φ)`'s
/// witness a single well-defined walk rather than an arbitrary shortest one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Edge {
    /// The neighbouring entity.
    pub other: EntityId,
    /// The event evidencing the co-occurrence.
    pub via: EventId,
}

/// The start of an existence window, two-state like its end is three-state.
///
/// This was briefly a `cc-filter`-local type, because `cc-core`'s
/// [`ExistenceWindow`] carried a bare `Tick` start and the filter needed a
/// distinction the stored row could not express: "we have no evidenced start"
/// and "the evidenced start is after `t_q`" are different sentences about the
/// record, and both must stay *absence*, never contradiction.
///
/// It is now `cc-core`'s [`WindowStart`], re-exported under the name the filter
/// already used. Keeping it local would have left the gap one layer down — the
/// projection row had nowhere to carry the distinction, so a decoder crossing
/// the seam would have had to invent `Known` for every row.
pub use cc_core::WindowStart as Start;

/// An entity's recorded existence window, with the events it was derived from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Windowed {
    /// Evidenced start, or silence.
    pub start: Start,
    /// Evidenced end. Reuses `cc-core`'s three-state end so the "confirmed
    /// active" / "no recorded cessation" distinction crosses the seam intact —
    /// the arithmetic collapses both to the sentinel, the tag does not.
    pub end: WindowEnd,
    /// The events this window was derived from, so the certificate can name them.
    pub derived_from: Vec<EventId>,
}

impl Windowed {
    /// The window of an entity the view has never recorded.
    ///
    /// Silent on both ends and evidenced by nothing — which is exactly right:
    /// an unknown entity yields `Unsupported`, never `Contradicted`, because
    /// absence of a record is not a record of absence.
    pub fn unrecorded() -> Windowed {
        Windowed {
            start: Start::Unknown,
            end: WindowEnd::UnknownClosure,
            derived_from: Vec::new(),
        }
    }

    /// Lift a stored `cc-core` window.
    ///
    /// Now a straight carry on both axes: since `cc-core` models the start's
    /// two states itself, there is nothing left for a `cc-ledger` row decoder to
    /// get wrong here — it cannot invent an `Unknown` start or flatten a real
    /// one, because it never constructs the discriminant by hand.
    pub fn from_core(w: ExistenceWindow, derived_from: Vec<EventId>) -> Windowed {
        Windowed {
            start: w.start,
            end: w.end,
            derived_from,
        }
    }
}

/// The governed vocabulary's answer about a claim type at `as_of`.
///
/// Three-valued for the same reason the window is: the vocabulary being silent
/// about a claim type and the vocabulary recording that type as outside its
/// validity band are different facts, and collapsing them would turn an
/// exoneration into a shrug.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Admitted {
    /// In the vocabulary and temporally coherent at `as_of`.
    Valid {
        /// The vocabulary events this ruling was derived from.
        derived_from: Vec<EventId>,
    },
    /// The vocabulary snapshot is silent about this claim type at `as_of`.
    Unrecorded,
    /// The vocabulary records this claim type's validity band as ended before
    /// `as_of` — positive contrary evidence, not silence.
    OutsideValidity {
        /// The recorded end of the validity band.
        band_end: Tick,
        /// The vocabulary events this ruling was derived from.
        derived_from: Vec<EventId>,
    },
}

/// The corpus could not be consulted.
///
/// Deliberately *not* a verdict. A filter handed a view that errors returns
/// `Err`, so a downstream gate can tell "the record does not support this" from
/// "I could not read the record"; a handler that returned `Unsupported` on a
/// view error would bill the caller a real verdict for a void. Fail-closed lives
/// above the filter: `cc-filter` has no I/O and therefore nothing to degrade to,
/// so a missing store is a view *construction* failure in `cc-node`, which fails
/// before the filter is ever called.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ViewError {
    /// The backing store could not be reached, or the query failed.
    #[error("corpus view backend failed: {0}")]
    Backend(String),
    /// The store answered, but the answer could not be decoded into a typed
    /// value — a corrupt projection, which must be as loud as an outage.
    #[error("corpus view returned an undecodable row: {0}")]
    Decode(String),
}
