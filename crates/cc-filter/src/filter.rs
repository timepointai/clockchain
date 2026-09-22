//! The filter product, evaluated cheapest-first.
//!
//! `Filter(x) = Known_k · 1[t_q ∈ I(f_i)] · 1[t_q ∈ I(f_j)] · Admiss(c, t_q)`.
//! As written the reachability factor is first; the implementation evaluates the
//! opposite order and short-circuits on the first zero. That is sound because the
//! filter is a tautological indicator *product* and AND is commutative, so
//! evaluation order is free to optimize — and "a zero from any factor rejects
//! before any expensive step" is a licence to reorder for cost. The two window
//! checks and `Admiss` are `O(1)`/sparse lookups; `Known_k` is the expensive
//! geometric factor, so it is gated behind the three cheap ones.

use crate::ids::{ClaimType, EntityId, HopBound};
use crate::phi::{Magnitude, PhiSupport};
use crate::reach::{known_k, Reachability};
use crate::verdict::{
    AbsenceWitness, Certificate, ContraryWitness, FilterError, FilterResult, Judgment, QueryError,
    Verdict,
};
use crate::version::{version_of, FilterParams, FilterVersion};
use crate::view::{Admitted, CorpusView, Start, Windowed};
use cc_core::{EventId, Tick, WindowEnd};
use std::collections::BTreeSet;

/// One feasibility question: did `f_i` and `f_j` interact at `t_q` in manner `c`?
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FeasibilityQuery {
    /// `(f_i, f_j)` — the two subjects.
    pub subjects: (EntityId, EntityId),
    /// `t_q` — the coordinate the claim is pinned to, and the `as_of` bound every
    /// view read is taken under.
    pub t_q: Tick,
    /// `c` — the claimed manner of interaction.
    pub claim: ClaimType,
    /// The hop bound to search under. May not exceed the governed
    /// [`FilterParams::k_max`]; asking for more is a malformed query, not a
    /// slower one, because a verdict searched under an unsanctioned bound would
    /// carry a version hash that does not describe it.
    pub k: HopBound,
}

/// The value of one indicator, plus the witness of why it vanished.
///
/// A three-armed outcome rather than a `bool` because "the indicator is zero" is
/// the point at which silence and contradiction must already be distinguished —
/// downstream of here the information is gone.
enum FactorOutcome {
    /// Indicator = 1.
    Holds,
    /// Indicator = 0, the record is silent.
    Absent(AbsenceWitness),
    /// Indicator = 0, the record is contrary.
    Contrary(ContraryWitness),
}

/// The compiled consensus rule: governed parameters plus the version hash that
/// names them.
///
/// The version is computed once at construction rather than on demand so that
/// every judgment carries a hash of the params this instance actually holds —
/// there is no path by which a verdict is stamped with a version derived from
/// different bytes than the ones that judged it.
#[derive(Clone, Debug)]
pub struct Filter {
    params: FilterParams,
    version: FilterVersion,
}

impl Filter {
    /// Compile the rule from its governed parameters.
    ///
    /// The params' canonical bytes are also the payload of the genesis
    /// `protocol_constants_v0` moment, so a version bump is a settled node-0
    /// event rather than a silent redeploy: the constitution is a subgraph.
    pub fn new(params: FilterParams) -> Filter {
        let version = version_of(&params);
        Filter { params, version }
    }

    /// The governed parameters this rule was compiled from.
    pub fn params(&self) -> &FilterParams {
        &self.params
    }

    /// The rule's identity, as surfaced on `/health` and on every judgment.
    pub fn version(&self) -> FilterVersion {
        self.version
    }

    /// Hot path. Short-circuits on the first zero: one witness, fastest reject.
    pub fn feasibility<V: CorpusView>(&self, v: &V, q: &FeasibilityQuery) -> FilterResult {
        self.check_query(q)?;

        // 1. Cheapest: two existence-window lookups.
        for f in [q.subjects.0, q.subjects.1] {
            match window_factor(v.window(f, q.t_q)?, q.t_q, f) {
                FactorOutcome::Holds => {}
                FactorOutcome::Absent(w) => {
                    return Ok(self.judge(v, Verdict::Unsupported { because: vec![w] }))
                }
                FactorOutcome::Contrary(w) => {
                    return Ok(self.judge(v, Verdict::Contradicted { by: w }))
                }
            }
        }

        // 2. Sparse: type admissibility.
        match admiss_factor(v.admissibility(q.claim, q.t_q)?, q.claim) {
            FactorOutcome::Holds => {}
            FactorOutcome::Absent(w) => {
                return Ok(self.judge(v, Verdict::Unsupported { because: vec![w] }))
            }
            FactorOutcome::Contrary(w) => return Ok(self.judge(v, Verdict::Contradicted { by: w })),
        }

        // 3. Expensive branch, reached only because the three cheap factors held.
        match known_k(v, q.subjects.0, q.subjects.1, q.k, q.t_q)? {
            Reachability::Within(support) => Ok(self.judge(v, Verdict::Supported { support })),
            Reachability::None(w) => Ok(self.judge(v, Verdict::Unsupported { because: vec![w] })),
        }
    }

    /// Audit path. Evaluates **all** factors and enumerates the consulted events,
    /// so the certificate is complete and portable.
    ///
    /// The verdict *kind* is taken from the first zero in the same canonical
    /// factor order the hot path uses — that is what makes the short-circuit
    /// semantics-preserving. The two paths differ only in witness completeness,
    /// and a property test pins that they never differ in anything else.
    pub fn certify<V: CorpusView>(
        &self,
        v: &V,
        q: &FeasibilityQuery,
    ) -> Result<Certificate, FilterError> {
        self.check_query(q)?;
        let mut consulted: BTreeSet<EventId> = BTreeSet::new();
        let mut outcomes: Vec<FactorOutcome> = Vec::with_capacity(4);

        for f in [q.subjects.0, q.subjects.1] {
            let w = v.window(f, q.t_q)?;
            consulted.extend(w.derived_from.iter().copied());
            outcomes.push(window_factor(w, q.t_q, f));
        }

        let a = v.admissibility(q.claim, q.t_q)?;
        consulted.extend(admitted_provenance(&a).iter().copied());
        outcomes.push(admiss_factor(a, q.claim));

        // Evaluated even when a cheap factor already vanished: the certificate
        // must report every zeroed factor, and the reachability evidence is what
        // a later attribution path is drawn over.
        let reach = known_k(v, q.subjects.0, q.subjects.1, q.k, q.t_q)?;
        let support = match reach {
            Reachability::Within(s) => {
                consulted.extend(s.consulted());
                outcomes.push(FactorOutcome::Holds);
                Some(s)
            }
            Reachability::None(w) => {
                outcomes.push(FactorOutcome::Absent(w));
                None
            }
        };

        let absences = outcomes
            .iter()
            .filter_map(|o| match o {
                FactorOutcome::Absent(w) => Some(w.clone()),
                _ => None,
            })
            .collect();
        let contradictions = outcomes
            .iter()
            .filter_map(|o| match o {
                FactorOutcome::Contrary(w) => Some(w.clone()),
                _ => None,
            })
            .collect();
        let verdict = combine(outcomes, support);
        Ok(Certificate {
            judgment: self.judge(v, verdict),
            consulted: consulted.into_iter().collect(),
            absences,
            contradictions,
        })
    }

    /// Φ's magnitude for a computed support.
    ///
    /// **Non-consensus.** It exists so the crate is the single place a magnitude
    /// can be born — a magnitude handed in from outside would be a number someone
    /// chose, and the type-level ban on thresholding only holds if nothing
    /// outside can mint one. The v0 smoothing is deliberately trivial
    /// (`1 / (1 + hops)`, so an evidenced two-hop path contributes small positive
    /// value rather than a hard zero); its float wobble across targets is
    /// harmless by construction because magnitude never gates and never enters
    /// the consensus projection.
    pub fn magnitude(&self, support: &PhiSupport) -> Magnitude {
        Magnitude::from_smoothed(1.0 / (1.0 + f64::from(support.hops().get())))
    }

    /// Bind the two identities every verdict carries: the rule that judged and
    /// the inputs it judged over.
    fn judge<V: CorpusView>(&self, v: &V, verdict: Verdict) -> Judgment {
        Judgment {
            verdict,
            filter_version: self.version,
            corpus_digest: v.corpus_digest(),
        }
    }

    /// Reject questions this rule cannot answer, before consulting anything.
    fn check_query(&self, q: &FeasibilityQuery) -> Result<(), QueryError> {
        if q.k > self.params.k_max {
            return Err(QueryError::HopBoundExceedsGoverned {
                requested: q.k,
                governed: self.params.k_max,
            });
        }
        if q.t_q == Tick::SENTINEL {
            return Err(QueryError::QueryTimeIsSentinel);
        }
        Ok(())
    }
}

/// Where three-valued logic is born out of the three-state window.
///
/// **Contrary evidence must dominate silence**, so the recorded-cessation arm is
/// evaluated first: a known close proves the entity existed, and an unknown start
/// can never downgrade a genuine "the record says it ended" to a mere "the record
/// is silent".
///
/// `KnownOpen` and `UnknownClosure` produce identical arithmetic — both bound the
/// end at the sentinel, so `t_q <= end` holds with no special case — but the
/// distinction is not lost by collapsing them to `Holds`: it survives in the
/// three-state window value and re-surfaces among the certificate's consulted
/// events, so "confirmed active" and "we have no cessation record" never get
/// conflated in what the judgment reports.
fn window_factor(w: Windowed, t_q: Tick, f: EntityId) -> FactorOutcome {
    match (w.start, w.end) {
        (_, WindowEnd::KnownClosed(e)) if t_q > e => {
            FactorOutcome::Contrary(ContraryWitness::AfterRecordedCessation {
                entity: f,
                ceased: e,
                derived_from: w.derived_from,
            })
        }
        (Start::Unknown, _) => FactorOutcome::Absent(AbsenceWitness::NoRecordedStart { entity: f }),
        (Start::Known(s), _) if t_q < s => {
            FactorOutcome::Absent(AbsenceWitness::BeforeRecordedStart {
                entity: f,
                start: s,
            })
        }
        _ => FactorOutcome::Holds,
    }
}

/// `Admiss(c, t_q)`.
///
/// Takes the claim type rather than `t_q` because the view has already resolved
/// the temporal question at `as_of`; what this factor still needs is the identity
/// to name in the witness.
fn admiss_factor(a: Admitted, c: ClaimType) -> FactorOutcome {
    match a {
        Admitted::Valid { .. } => FactorOutcome::Holds,
        Admitted::Unrecorded => {
            FactorOutcome::Absent(AbsenceWitness::ClaimTypeUnrecorded { claim: c })
        }
        Admitted::OutsideValidity {
            band_end,
            derived_from,
        } => FactorOutcome::Contrary(ContraryWitness::ClaimTypeOutsideValidity {
            claim: c,
            band_end,
            derived_from,
        }),
    }
}

/// The events an admissibility ruling was derived from.
fn admitted_provenance(a: &Admitted) -> &[EventId] {
    match a {
        Admitted::Valid { derived_from } => derived_from,
        Admitted::Unrecorded => &[],
        Admitted::OutsideValidity { derived_from, .. } => derived_from,
    }
}

/// Fold the full factor evaluation into one verdict.
///
/// The kind is decided by the *first* non-holding factor in the canonical order,
/// which is exactly what the short-circuiting hot path returns; the audit path
/// only adds the absence witnesses the hot path never reached.
fn combine(outcomes: Vec<FactorOutcome>, support: Option<PhiSupport>) -> Verdict {
    let mut absences = Vec::new();
    let mut first_zero_is_contrary: Option<ContraryWitness> = None;
    let mut any_zero = false;

    for o in outcomes {
        match o {
            FactorOutcome::Holds => {}
            FactorOutcome::Absent(w) => {
                any_zero = true;
                absences.push(w);
            }
            FactorOutcome::Contrary(w) => {
                if !any_zero {
                    first_zero_is_contrary = Some(w);
                }
                any_zero = true;
            }
        }
    }

    match (first_zero_is_contrary, any_zero) {
        (Some(by), _) => Verdict::Contradicted { by },
        (None, true) => Verdict::Unsupported { because: absences },
        (None, false) => Verdict::Supported {
            // Every factor held, so the reachability factor held, so support is
            // present. Expressed as an `expect` rather than an unreachable branch
            // because it is a real invariant of `certify`'s own construction.
            support: support.expect("all factors held, so Known_k produced support"),
        },
    }
}
