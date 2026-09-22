//! `Known_k`: bounded-hop reachability over `B(t_q)`, the time-sliced
//! co-occurrence graph built only from moments with event-time `<= t_q`.
//!
//! The normative definition is the reflexive-doubling recurrence
//! `T_0 = I ∨ B(t_q)`, `T_{j+1} = T_j ∨ (T_j ∘ T_j)`, under which
//! `T_j[f, f'] = 1` iff `f'` is reachable from `f` in **at most** `2^j` edges.
//! The reflexive term `I` is load-bearing: raw Boolean powers `B^{∘2^m}` test
//! walks of *exactly* that length and are a bug, because they miss a pair
//! reachable only at an odd or non-power-of-two hop distance. That correction is
//! pinned by a regression test, not by this comment.
//!
//! At initiation-phase scale a single query is realized as bounded bidirectional
//! frontier expansion meeting in the middle, which computes the identical
//! predicate. This is deliberately *not* claimed to achieve the headline
//! `O(log k)` matrix-multiplication cost — that cost belongs to the batch
//! operator over many pairs, which is a later-epoch seam. Both realizations
//! compute the same predicate and reconstruct the same canonical `supp(Φ)`.

use crate::ids::{EntityId, HopBound, WalkLen};
use crate::phi::{PhiSupport, WalkStep, WalkWitness};
use crate::verdict::AbsenceWitness;
use crate::view::{CorpusView, ViewError};
use cc_core::Tick;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

/// Whether the pair is within the governed bound, and the evidence if so.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Reachability {
    /// Reachable within `k`, with the canonical shortest evidenced walk.
    Within(PhiSupport),
    /// No evidenced walk of `<= k` hops exists in `B(as_of)`.
    None(AbsenceWitness),
}

/// Neighbours of `entity` in `B(as_of)`, canonicalized.
///
/// The trait contract says a view returns `(other, via)` ascending, and this
/// sorts anyway. That is not distrust for its own sake: the neighbour order *is*
/// the tie-break that selects `supp(Φ)`'s witness, so a view that returned rows
/// in an incidental order would change a consensus-bearing bit. Sorting here
/// makes the filter's output a function of the neighbour *set*, which is the
/// property the order-independence test actually needs to hold.
fn canonical_neighbors<V: CorpusView>(
    v: &V,
    entity: EntityId,
    as_of: Tick,
) -> Result<Vec<crate::view::Edge>, ViewError> {
    let mut edges = v.neighbors(entity, as_of)?;
    edges.sort_unstable();
    edges.dedup();
    Ok(edges)
}

/// Bounded bidirectional reachability over `B(as_of)`.
///
/// Two phases, because a rejection and an acceptance have different costs and
/// only the acceptance needs a witness:
///
/// 1. **Decision.** Alternating level-by-level expansion from both endpoints,
///    stopping as soon as the visited sets intersect or the combined depth would
///    exceed `k`. A rejection pays only this, and meets in the middle rather
///    than expanding a full `k` levels from one side — which is what puts the
///    expensive geometric factor behind the cheap ones in cost as well as order.
/// 2. **Witness.** Only on success: backward distance labels to depth `d`, then a
///    greedy forward walk taking the least `(other, via)` step that stays on a
///    shortest path. Greedy is exactly lexicographic-minimal here, because any
///    step whose backward distance is `remaining - 1` extends to *some* shortest
///    walk, so the least such step at each position is the least overall.
pub fn known_k<V: CorpusView>(
    v: &V,
    from: EntityId,
    to: EntityId,
    k: HopBound,
    as_of: Tick,
) -> Result<Reachability, ViewError> {
    // The reflexive term `I` of `T_0`, as a value: an entity reaches itself in
    // zero hops having consulted no evidence.
    if from == to {
        return Ok(Reachability::Within(PhiSupport::reflexive()));
    }

    let k_hops = u16::from(k.get());
    let unreachable = || {
        Reachability::None(AbsenceWitness::NoEvidencedWalk {
            from,
            to,
            within: k,
        })
    };
    if k_hops == 0 {
        return Ok(unreachable());
    }

    let Some(d) = shortest_distance(v, from, to, k_hops, as_of)? else {
        return Ok(unreachable());
    };

    let back = backward_labels(v, to, d, as_of)?;
    let witness = greedy_lex_min_walk(v, from, d, &back, as_of)?;
    Ok(Reachability::Within(PhiSupport::from_walk(
        WalkLen::new(d),
        witness,
    )))
}

/// Phase 1: the exact shortest distance if it is `<= k`, else `None`.
///
/// Correctness of stopping at first intersection: both sides always hold *whole*
/// levels, so when the visited sets first intersect at depths `(df, db)` we have
/// `D <= df + db`, and since `df + db >= D` there is a split `i <= df`,
/// `D - i <= db` — meaning the true midpoint is already in the intersection.
/// Hence the minimum of `dist_f + dist_b` over the intersection is exactly `D`.
fn shortest_distance<V: CorpusView>(
    v: &V,
    from: EntityId,
    to: EntityId,
    k_hops: u16,
    as_of: Tick,
) -> Result<Option<u16>, ViewError> {
    let mut dist_f: BTreeMap<EntityId, u16> = BTreeMap::from([(from, 0)]);
    let mut dist_b: BTreeMap<EntityId, u16> = BTreeMap::from([(to, 0)]);
    let mut frontier_f: BTreeSet<EntityId> = BTreeSet::from([from]);
    let mut frontier_b: BTreeSet<EntityId> = BTreeSet::from([to]);
    let (mut depth_f, mut depth_b) = (0u16, 0u16);

    while depth_f + depth_b < k_hops && !frontier_f.is_empty() && !frontier_b.is_empty() {
        // Expand whichever side is cheaper to expand. This only changes cost,
        // never the answer: the stopping rule above is symmetric in the two
        // depths, so the computed `D` is independent of the expansion schedule.
        let expand_forward = frontier_f.len() <= frontier_b.len();
        if expand_forward {
            depth_f += 1;
            frontier_f = expand(v, &frontier_f, &mut dist_f, depth_f, as_of)?;
        } else {
            depth_b += 1;
            frontier_b = expand(v, &frontier_b, &mut dist_b, depth_b, as_of)?;
        }

        let met = dist_f
            .iter()
            .filter_map(|(e, df)| dist_b.get(e).map(|db| df + db))
            .min();
        if let Some(d) = met {
            return Ok(if d <= k_hops { Some(d) } else { None });
        }
    }
    Ok(None)
}

/// One BFS level: label every unlabelled neighbour of the frontier with `depth`
/// and return the new frontier.
fn expand<V: CorpusView>(
    v: &V,
    frontier: &BTreeSet<EntityId>,
    dist: &mut BTreeMap<EntityId, u16>,
    depth: u16,
    as_of: Tick,
) -> Result<BTreeSet<EntityId>, ViewError> {
    let mut next = BTreeSet::new();
    // One read for the whole level. The frontier is a `BTreeSet`, so the entity
    // order handed down is sorted and the labelling below runs in exactly the
    // order the per-entity loop used to — the vacant-only rule is order
    // sensitive, so that equivalence is the thing to preserve, not just the
    // neighbour sets.
    let level: Vec<EntityId> = frontier.iter().copied().collect();
    let fetched = v.neighbors_many(&level, as_of)?;
    for e in &level {
        // Canonicalized identically to `canonical_neighbors`: the `(other, via)`
        // order IS the tie-break that selects the witness walk, so a batched
        // read must not inherit whatever order the store returned.
        let mut edges = fetched.get(e).cloned().unwrap_or_default();
        edges.sort_unstable();
        edges.dedup();
        for edge in edges {
            // Vacant-only: a plain `insert` would overwrite an earlier, shorter
            // label with this level's, which silently turns exact BFS distances
            // into whatever the traversal happened to visit last.
            if let Entry::Vacant(slot) = dist.entry(edge.other) {
                slot.insert(depth);
                next.insert(edge.other);
            }
        }
    }
    Ok(next)
}

/// Phase 2a: exact distances *to* `target` for every entity within `depth` hops.
///
/// The graph is undirected (co-occurrence is symmetric), so a BFS from the target
/// yields the backward labels the forward walk needs.
fn backward_labels<V: CorpusView>(
    v: &V,
    target: EntityId,
    depth: u16,
    as_of: Tick,
) -> Result<BTreeMap<EntityId, u16>, ViewError> {
    let mut dist: BTreeMap<EntityId, u16> = BTreeMap::from([(target, 0)]);
    let mut frontier: BTreeSet<EntityId> = BTreeSet::from([target]);
    for level in 1..=depth {
        if frontier.is_empty() {
            break;
        }
        frontier = expand(v, &frontier, &mut dist, level, as_of)?;
    }
    Ok(dist)
}

/// Phase 2b: the lexicographically least shortest walk under the `(other, via)`
/// neighbour order.
fn greedy_lex_min_walk<V: CorpusView>(
    v: &V,
    from: EntityId,
    d: u16,
    back: &BTreeMap<EntityId, u16>,
    as_of: Tick,
) -> Result<WalkWitness, ViewError> {
    let mut steps = Vec::with_capacity(usize::from(d));
    let mut cur = from;
    for remaining in (1..=d).rev() {
        let next = canonical_neighbors(v, cur, as_of)?
            .into_iter()
            .find(|e| back.get(&e.other) == Some(&(remaining - 1)));
        // Unreachable by construction: `back[cur] == remaining` holds on entry
        // (it holds for `from` because `d` came out of phase 1, and each step
        // re-establishes it), so some neighbour is labelled `remaining - 1`.
        // Returning a decode error rather than panicking keeps a corrupted view
        // loud but non-fatal — a filter that aborts a process is a worse failure
        // than one that reports it could not read the record.
        let Some(step) = next else {
            return Err(ViewError::Decode(
                "backward distance labels are inconsistent with the neighbour relation".into(),
            ));
        };
        steps.push(WalkStep {
            entity: step.other,
            via: step.via,
        });
        cur = step.other;
    }
    Ok(WalkWitness::from_steps(steps))
}
