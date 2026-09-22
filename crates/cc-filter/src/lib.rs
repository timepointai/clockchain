//! `cc-filter` — the feasibility filter, built as the swarm's single-source
//! consensus rule.
//!
//! `Filter(x) = Known_k · 1[t_q ∈ I(f_i)] · 1[t_q ∈ I(f_j)] · Admiss(c, t_q)`.
//! A zero from any factor rejects before any expensive step, and a zero product
//! is a *certain* witness of missing evidence rather than a probabilistic one.
//!
//! # Why this is a crate and not four SQL predicates in the node
//!
//! In the initiation phase there is one node, one migrator, one materialized
//! view, so the four indicator checks could be inlined against Postgres and be
//! done. They are not, for one reason: the filter is the swarm's consensus rule,
//! and "same Φ everywhere" has to be a **build property, not a policy**. The
//! logic that computes a verdict on the server, in a batch backfill, and inside
//! an embedded wasm mirror must be the same compiled logic replaying the same
//! events to the same verdict — that is what replaces fork-choice and BFT with
//! union merge plus deterministic replay. The cost of the seam now is one trait
//! ([`CorpusView`]); the cost of retrofitting it after the node has grown a
//! direct SQL feasibility path is a rewrite plus a swarm epoch that cannot prove
//! convergence.
//!
//! # What is banned at the crate boundary
//!
//! A consensus rule that is only *usually* reproducible is not a consensus rule,
//! so the sources of nondeterminism are denied rather than avoided by habit:
//! `unsafe` is forbidden; `HashMap`/`HashSet` (SipHash-seeded iteration),
//! `SystemTime::now`, `Instant::now` and `env::var` are denied by the crate's own
//! `clippy.toml`. Every set, map, frontier and witness ordering is a `BTree*` or
//! an explicitly sorted `Vec`, so replay order is total and platform-independent.
//!
//! The most consequential determinism decision falls out of Φ's support/magnitude
//! split: **the entire consensus-bearing path is integer and boolean only.**
//! `supp(Φ)`, the window indicators and `Admiss` never touch a float. The only
//! `f64` in the crate is Φ's [`Magnitude`], which is architecturally forbidden
//! from gating anything — so its cross-target wobble is harmless by construction,
//! and cross-target determinism becomes tractable rather than aspirational.
//!
//! # The fourth thing, which is not a verdict
//!
//! [`Verdict`] is three-valued (`Supported` / `Unsupported` / `Contradicted`) and
//! [`FilterError`] is a **fourth** thing that is never folded into a verdict:
//! "the record does not support this" and "I could not read the record" must stay
//! distinguishable, because a fail-closed caller amplifies whatever ambiguity is
//! left behind. Every verdict rides inside a [`Judgment`] carrying the rule that
//! judged ([`FilterVersion`]) and the inputs it judged over ([`CorpusDigest`]), so
//! two nodes that disagree differ in exactly one legible way — a gossip-horizon
//! gap or a governance event — and never in an unexplained fork.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod filter;
pub mod golden;
pub mod ids;
pub mod phi;
pub mod reach;
pub mod snapshot;
pub mod verdict;
pub mod version;
pub mod view;
pub mod wl;

pub use filter::{FeasibilityQuery, Filter};
pub use ids::{ClaimType, CorpusDigest, EntityId, HopBound, WalkLen};
pub use phi::{Magnitude, PhiSupport, RankKey, WalkStep, WalkWitness};
pub use reach::{known_k, Reachability};
pub use snapshot::{Record, Ruling, SnapshotCorpus, SnapshotError};
pub use verdict::{
    AbsenceWitness, Certificate, ConsensusProjection, ContraryWitness, FilterError, FilterResult,
    Judgment, QueryError, Verdict, VerdictKind,
};
pub use version::{
    canon_params, v0_params, v0_version, version_of, B256Constants, CooccurrenceRuleId,
    FilterParams, FilterVersion, LogicTag, SmoothingId, TimeScaleId, VocabularyVersion,
    SUPPORT_PATH_LOGIC_TAG,
};
pub use view::{Admitted, CorpusView, Edge, Start, ViewError, Windowed};
pub use wl::{ball, refine, Color, WlRounds};
