//! The Weisfeiler-Leman colour-refinement kernel.
//!
//! Two different things sit on top of this kernel and they belong on opposite
//! sides of the architecture's central cost asymmetry: a cheap **conformity**
//! screen ("could this shape occur") that runs per-submission on the write path,
//! and an expensive **convergence** test ("do independent accounts agree") that
//! runs only on the feasible survivors settlement adjudicates. Convergence is out
//! of scope for the initiation phase — there is one migrator and no independent
//! second rendering to converge yet — but the kernel is exposed here now so that
//! when convergence is built it reuses the *exact same refinement* and the two can
//! never drift. That is the same single-source discipline the filter itself
//! embodies, and it is why building the kernel once, in the pure crate, is what
//! lets both consumers sit on the right side of the asymmetry.
//!
//! WL is isomorphism-*invariant*, not -complete: equal colours are evidence of
//! conformity, never proof of correctness. Nothing here may be read as the latter.

use crate::ids::{framed, EntityId};
use crate::view::{CorpusView, ViewError};
use cc_core::Tick;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Domain separation for colour hashing.
const DST_WL: &[u8] = b"cc.filter.wl.v0";

/// A refinement colour.
///
/// A 32-byte hash rather than an interned integer because interning assigns
/// numbers in *discovery* order, which would make a colour depend on traversal
/// order and therefore on the view's row order — the exact class of leak the
/// determinism boundary exists to close. A content hash of the colour's own
/// derivation is order-free by construction.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Color([u8; 32]);

impl Color {
    /// The uniform colour every vertex starts at.
    ///
    /// Uniform rather than degree-seeded because round one already separates by
    /// degree; seeding with degree would only move information earlier while
    /// making the initial colour depend on the `as_of` slice twice.
    pub const SEED: Color = Color([0u8; 32]);

    /// The raw colour bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Number of refinement rounds — governed, because how far a colour sees is part
/// of what a screen means, and a screen whose depth varied per call site would
/// not be one rule.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WlRounds(u8);

impl WlRounds {
    /// A governed round count.
    pub const fn new(rounds: u8) -> WlRounds {
        WlRounds(rounds)
    }

    /// The round count.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// The `radius`-ball around `seeds` in `B(as_of)`.
///
/// The sparse scope a screen is meant to touch: refinement over the whole graph
/// would put the cheap gate on the expensive side of the asymmetry it exists to
/// exploit.
pub fn ball<V, I>(v: &V, seeds: I, as_of: Tick, radius: u8) -> Result<BTreeSet<EntityId>, ViewError>
where
    V: CorpusView,
    I: IntoIterator<Item = EntityId>,
{
    let mut scope: BTreeSet<EntityId> = seeds.into_iter().collect();
    let mut frontier: BTreeSet<EntityId> = scope.clone();
    for _ in 0..radius {
        let mut next = BTreeSet::new();
        for &e in &frontier {
            for edge in v.neighbors(e, as_of)? {
                if scope.insert(edge.other) {
                    next.insert(edge.other);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    Ok(scope)
}

/// Bounded-round colour refinement over the subgraph of `B(as_of)` induced by
/// `scope`.
///
/// **Exactness caveat, and it is load-bearing:** a vertex's colour is the colour
/// it would have in the full graph only if its entire `rounds`-hop neighbourhood
/// lies inside `scope`, because neighbours outside `scope` are invisible to the
/// refinement. Build `scope` with [`ball`] at radius `>= rounds` around the
/// vertices whose colours you intend to use, and use only those. Stated here
/// rather than left implicit because a truncated colour compared against an
/// untruncated one is a wrong answer that looks like a right one.
pub fn refine<V: CorpusView>(
    v: &V,
    scope: &BTreeSet<EntityId>,
    as_of: Tick,
    rounds: WlRounds,
) -> Result<BTreeMap<EntityId, Color>, ViewError> {
    let mut colors: BTreeMap<EntityId, Color> = scope.iter().map(|&e| (e, Color::SEED)).collect();

    for _ in 0..rounds.get() {
        let mut next = BTreeMap::new();
        for &e in scope {
            let mut neighbor_colors: Vec<[u8; 32]> = Vec::new();
            for edge in v.neighbors(e, as_of)? {
                if let Some(c) = colors.get(&edge.other) {
                    neighbor_colors.push(c.0);
                }
            }
            // Sorted: the refinement is over the neighbour colour *multiset*, so
            // the order the view happened to yield neighbours in must not survive
            // into the hash.
            neighbor_colors.sort_unstable();

            let own = colors.get(&e).copied().unwrap_or(Color::SEED);
            let mut buf = Vec::new();
            framed(&mut buf, DST_WL);
            framed(&mut buf, &own.0);
            for c in &neighbor_colors {
                framed(&mut buf, c);
            }
            next.insert(e, Color(Sha256::digest(&buf).into()));
        }
        colors = next;
    }
    Ok(colors)
}
