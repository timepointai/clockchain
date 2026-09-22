//! The golden fixtures: one fixed corpus, one fixed query list, one digest.
//!
//! This module exists so the cross-target claim is *checkable* rather than
//! argued. The same crate compiled to native and to `wasm32` must return
//! identical verdicts; the only way to compare two builds that cannot share a
//! process is to have both fold the same evaluation into the same 32 bytes.
//! [`golden_digest`] is that fold, and it covers exactly the consensus-bearing
//! projection — verdict kind, `supp(Φ)`, and the filter version — because those
//! are the bits a hard decision may depend on. Φ's magnitude is deliberately
//! excluded: its float smoothing is not guaranteed bit-identical between an x86
//! libm and wasm, and that wobble is harmless precisely because magnitude never
//! gates.
//!
//! The fixture is deliberately small and hand-readable, and it covers every
//! verdict kind and every witness arm, so a digest change is diagnosable rather
//! than merely alarming.

use crate::filter::{FeasibilityQuery, Filter};
use crate::ids::{ClaimType, EntityId, HopBound};
use crate::snapshot::{Record, Ruling, SnapshotCorpus};
use crate::version::{
    B256Constants, CooccurrenceRuleId, FilterParams, SmoothingId, TimeScaleId, VocabularyVersion,
    SUPPORT_PATH_LOGIC_TAG,
};
use crate::view::{CorpusView, Start};
use cc_core::{EventId, FractionalBits, Tick, WindowEnd};
use sha2::{Digest, Sha256};

/// Domain separation for the golden fold.
const DST_GOLDEN: &[u8] = b"cc.filter.golden.v0";

/// A readable event id for the fixture: `n` repeated 32 times, so a witness in a
/// failure message names its event by a number a human can find below.
const fn ev(n: u8) -> EventId {
    EventId::from_bytes([n; 32])
}

/// A fixture coordinate.
fn t(n: i64) -> Tick {
    Tick::from_i64(n)
}

/// A fixture entity.
const fn e(n: i64) -> EntityId {
    EntityId::from_i64(n)
}

/// The governed parameters the fixtures are judged under.
///
/// Concrete ids rather than zeros so that a params field accidentally dropped
/// from the canon preimage changes the version hash and fails the pinned test,
/// instead of hashing to the same all-zero bytes either way.
pub fn golden_params() -> FilterParams {
    FilterParams {
        cooccurrence_rule: CooccurrenceRuleId::from_bytes([0x11; 32]),
        k_max: HopBound::new(4),
        smoothing: SmoothingId::from_bytes([0x22; 32]),
        vocabulary: VocabularyVersion::from_bytes([0x33; 32]),
        b256: B256Constants {
            clock_zero_scale: TimeScaleId::TCB,
            tick_attoseconds: 1_000_000_000_000_000_000,
            split: FractionalBits(64),
        },
        logic_tag: SUPPORT_PATH_LOGIC_TAG,
    }
}

/// The fixture corpus.
///
/// Shape, at `t_q = 100`:
/// - `1 — 2 — 3 — 4` is a co-occurrence chain established at `t = 10`, so
///   `1..4` is exactly three hops and cannot be reached by any even-length walk.
/// - `1 — 2` is doubly evidenced (`ev(19)` and `ev(20)`), so the `(other, via)`
///   tie-break has something to choose between.
/// - `1 — 4` exists directly but only from `t = 900`, so it is invisible at
///   `t_q = 100` and visible at `t_q = 1000` — the time slice, and the
///   accretion case, in one edge.
/// - entity 5 starts at `t = 500`; entity 6 has no evidenced start; entity 7
///   closed at `t = 50`; entity 8 has no record at all.
/// - claim 1 is valid, claim 2 is unrecorded, claim 3's validity band ended at
///   `t = 50`.
pub fn golden_corpus() -> SnapshotCorpus {
    let records = vec![
        // Windows.
        Record::Window {
            entity: e(1),
            recorded_at: t(0),
            via: ev(1),
            start: Start::Known(t(0)),
            end: WindowEnd::KnownOpen,
        },
        Record::Window {
            entity: e(2),
            recorded_at: t(0),
            via: ev(2),
            start: Start::Known(t(0)),
            end: WindowEnd::KnownOpen,
        },
        Record::Window {
            entity: e(3),
            recorded_at: t(0),
            via: ev(3),
            start: Start::Known(t(0)),
            // Not "confirmed active" — merely no recorded cessation. The
            // arithmetic is identical to KnownOpen; the distinction survives in
            // the record and in what the certificate reports.
            end: WindowEnd::UnknownClosure,
        },
        Record::Window {
            entity: e(4),
            recorded_at: t(0),
            via: ev(4),
            start: Start::Known(t(0)),
            end: WindowEnd::KnownOpen,
        },
        Record::Window {
            entity: e(5),
            recorded_at: t(0),
            via: ev(5),
            start: Start::Known(t(500)),
            end: WindowEnd::KnownOpen,
        },
        Record::Window {
            entity: e(6),
            recorded_at: t(0),
            via: ev(6),
            start: Start::Unknown,
            end: WindowEnd::UnknownClosure,
        },
        Record::Window {
            entity: e(7),
            recorded_at: t(0),
            via: ev(7),
            start: Start::Known(t(0)),
            end: WindowEnd::KnownClosed(t(50)),
        },
        // Co-occurrence.
        Record::CoOccurrence {
            a: e(1),
            b: e(2),
            at: t(10),
            via: ev(19),
        },
        Record::CoOccurrence {
            a: e(1),
            b: e(2),
            at: t(10),
            via: ev(20),
        },
        Record::CoOccurrence {
            a: e(2),
            b: e(3),
            at: t(10),
            via: ev(21),
        },
        Record::CoOccurrence {
            a: e(3),
            b: e(4),
            at: t(10),
            via: ev(22),
        },
        Record::CoOccurrence {
            a: e(1),
            b: e(4),
            at: t(900),
            via: ev(23),
        },
        Record::CoOccurrence {
            a: e(1),
            b: e(7),
            at: t(10),
            via: ev(24),
        },
        // Vocabulary.
        Record::Admissibility {
            claim: ClaimType::from_u32(1),
            recorded_at: t(0),
            via: ev(30),
            ruling: Ruling::Valid,
        },
        Record::Admissibility {
            claim: ClaimType::from_u32(3),
            recorded_at: t(0),
            via: ev(31),
            ruling: Ruling::OutsideValidity { band_end: t(50) },
        },
    ];
    SnapshotCorpus::from_records(records).expect("golden corpus is well-formed")
}

/// The fixture queries, covering every verdict kind and every witness arm.
pub fn golden_queries() -> Vec<FeasibilityQuery> {
    let c1 = ClaimType::from_u32(1);
    let q = |a: i64, b: i64, tq: i64, claim: ClaimType, k: u8| FeasibilityQuery {
        subjects: (e(a), e(b)),
        t_q: t(tq),
        claim,
        k: HopBound::new(k),
    };
    vec![
        // Reflexive: the `I` term of T_0, zero hops.
        q(1, 1, 100, c1, 4),
        // One hop, with two candidate evidencing events — pins the tie-break.
        q(1, 2, 100, c1, 4),
        // Two hops.
        q(1, 3, 100, c1, 4),
        // Exactly three hops under k=4: the raw-Boolean-power regression.
        q(1, 4, 100, c1, 4),
        // Same pair, k=2: out of bounds, so silence rather than contradiction.
        q(1, 4, 100, c1, 2),
        // t_q precedes an evidenced start.
        q(1, 5, 100, c1, 4),
        // No evidenced start at all.
        q(1, 6, 100, c1, 4),
        // Past a recorded cessation: contradiction, not silence.
        q(1, 7, 100, c1, 4),
        // Entity with no record whatsoever.
        q(1, 8, 100, c1, 4),
        // Vocabulary silent about the claim type.
        q(1, 2, 100, ClaimType::from_u32(2), 4),
        // Vocabulary contradicts the claim type at t_q.
        q(1, 2, 100, ClaimType::from_u32(3), 4),
        // Before the co-occurrence exists: the time slice bites.
        q(1, 2, 5, c1, 4),
        // After the direct 1—4 edge is recorded: one hop where it was three.
        q(1, 4, 1000, c1, 2),
    ]
}

/// Fold every golden judgment's consensus projection into 32 bytes.
///
/// Native and `wasm32` must agree on these bytes. The corpus digest is folded in
/// once at the head — not because it is consensus-bearing (it is a legibility
/// tag, and two nodes with different gossip horizons legitimately differ on it)
/// but because the fixture's corpus is fixed, so the two targets computing
/// different bytes for it would be a real cross-target defect in the view.
pub fn golden_digest() -> [u8; 32] {
    let filter = Filter::new(golden_params());
    let corpus = golden_corpus();
    let mut buf = Vec::new();
    crate::ids::framed(&mut buf, DST_GOLDEN);
    crate::ids::framed(&mut buf, corpus.corpus_digest().as_bytes());

    for (i, q) in golden_queries().iter().enumerate() {
        crate::ids::framed(&mut buf, &(i as u32).to_be_bytes());
        match filter.feasibility(&corpus, q) {
            Ok(j) => {
                let p = j.consensus_projection();
                crate::ids::framed(&mut buf, &[p.kind as u8]);
                crate::ids::framed(&mut buf, p.filter_version.as_bytes());
                match p.support {
                    None => crate::ids::framed(&mut buf, &[0u8]),
                    Some(s) => {
                        crate::ids::framed(&mut buf, &[1u8]);
                        crate::ids::framed(&mut buf, &s.hops().get().to_be_bytes());
                        for step in s.witness().steps() {
                            crate::ids::framed(&mut buf, &step.entity.to_i64().to_be_bytes());
                            crate::ids::framed(&mut buf, step.via.as_bytes());
                        }
                    }
                }
            }
            // An error is not a verdict, and the fold says so distinctly: a
            // target that errored where the other judged must not hash the same.
            Err(_) => crate::ids::framed(&mut buf, b"error"),
        }
    }
    Sha256::digest(&buf).into()
}
