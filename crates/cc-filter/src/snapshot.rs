//! `SnapshotCorpus` — an in-memory, time-sliced [`CorpusView`] over a set of
//! records.
//!
//! This is the *embedded* side of the seam, not a test fixture that happens to
//! live in the library: an embedded wasm mirror is `cc-filter` compiled to
//! `wasm32` against a snapshot view, and the cross-target determinism claim is
//! only checkable if native and wasm can be handed the same corpus. The
//! Postgres-backed view is `cc-ledger`'s and reads the maintained `cooccurrence`
//! projection; both must answer identically, which is what makes "same Φ
//! everywhere" a build property rather than two implementations that drift.
//!
//! It also happens to be the right input space for property testing the filter's
//! algebra, which is not a mock of a service — there is no service here to fake,
//! only a pure function over its domain.

use crate::ids::{framed, ClaimType, CorpusDigest, EntityId};
use crate::version::put_tick;
use crate::view::{Admitted, CorpusView, Edge, Start, ViewError, Windowed};
use cc_core::{EventId, Tick, WindowEnd};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Domain separation for the corpus digest preimage.
const DST_CORPUS: &[u8] = b"cc.filter.snapshot.v0";

/// The vocabulary's ruling about a claim type, as a record asserts it.
///
/// There is no `Unrecorded` arm: silence is the *absence* of a record, and
/// making it representable as a record would let a corpus assert "I am silent",
/// which is a different and un-evidenced thing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Ruling {
    /// Taxonomically and temporally coherent.
    Valid,
    /// The validity band is recorded as ended at `band_end`.
    OutsideValidity {
        /// The recorded end of the band.
        band_end: Tick,
    },
}

/// One projected fact, as the ledger's events would have produced it.
///
/// Every arm carries the event that evidences it and the coordinate it takes
/// effect at, because those are exactly the two things the `as_of` bound and the
/// certificate need — a record without provenance could not be certified, and a
/// record without a coordinate could not be time-sliced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Record {
    /// Two distinct entities share a moment at `at`.
    CoOccurrence {
        /// One entity.
        a: EntityId,
        /// The other; must differ from `a`.
        b: EntityId,
        /// The moment's event-time.
        at: Tick,
        /// The event evidencing the co-occurrence.
        via: EventId,
    },
    /// An entity's existence window as of `recorded_at`.
    Window {
        /// The entity.
        entity: EntityId,
        /// The event-time at which this window becomes the recorded one.
        recorded_at: Tick,
        /// The event evidencing it.
        via: EventId,
        /// Evidenced start, or silence.
        start: Start,
        /// Evidenced end, three-state.
        end: WindowEnd,
    },
    /// The governed vocabulary's ruling on a claim type as of `recorded_at`.
    Admissibility {
        /// The claim type.
        claim: ClaimType,
        /// The event-time at which this ruling becomes the recorded one.
        recorded_at: Tick,
        /// The event evidencing it.
        via: EventId,
        /// The ruling.
        ruling: Ruling,
    },
}

/// A record set that cannot be projected into a coherent view.
///
/// Loud rather than dropped: the write path rejects a self-co-occurrence, so a
/// snapshot containing one did not come from a ledger, and silently discarding it
/// would make the snapshot view and the Postgres view disagree on the same input.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SnapshotError {
    /// `lo == hi`: co-occurrence is a relation between two *distinct* entities.
    #[error("co-occurrence of an entity with itself is not representable: {0:?}")]
    SelfCoOccurrence(EntityId),
    /// Two records claim the same evidence event and disagree about what it says.
    ///
    /// Rejected rather than resolved. `(recorded_at, via)` identifies one piece
    /// of evidence, so two different rulings for it is a contradiction in the
    /// input, not a version history — and any tie-break would have to prefer one
    /// arbitrarily. Keeping the last one silently made the corpus digest a
    /// function of *insertion order*, so two nodes holding identical evidence
    /// could publish different digests and conclude they had diverged.
    #[error("two records disagree about evidence event {via:?} at {recorded_at:?}")]
    ContradictoryRecord {
        /// The coordinate the disagreeing records share.
        recorded_at: Tick,
        /// The evidence event they disagree about.
        via: EventId,
    },
}

/// Adjacency keyed for the `(other, via)` order the neighbour contract requires,
/// with the co-occurrence coordinate carried last so it can be filtered by
/// `as_of` without disturbing that order.
type Adjacency = BTreeMap<EntityId, BTreeSet<(EntityId, EventId, Tick)>>;

/// Window records, nested `entity -> (recorded_at, via) -> window`, so "the
/// latest record at or before `as_of`" is one bounded range query per entity
/// rather than a scan — the same shape the maintained Postgres projection is
/// indexed for, because the two views must not differ in what they can answer
/// cheaply.
type WindowIndex = BTreeMap<EntityId, BTreeMap<(Tick, EventId), (Start, WindowEnd)>>;

/// Vocabulary records, nested `claim -> (recorded_at, via) -> ruling`.
type AdmissIndex = BTreeMap<ClaimType, BTreeMap<(Tick, EventId), Ruling>>;

/// The maximal [`EventId`], used only as an inclusive upper range bound so
/// "latest record at or before `as_of`" needs no lower bound at all.
const MAX_EVENT_ID: EventId = EventId::from_bytes([0xffu8; 32]);

/// An immutable, time-sliced projection of a record set.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SnapshotCorpus {
    /// Canonical record set — the thing the digest is taken over, kept alongside
    /// the indexes so the digest names the *inputs* and not an index layout that
    /// could change without the corpus changing.
    cooccurrence: BTreeSet<(EntityId, EntityId, Tick, EventId)>,
    adjacency: Adjacency,
    windows: WindowIndex,
    admissibility: AdmissIndex,
    digest: CorpusDigest,
}

impl SnapshotCorpus {
    /// Project a record set into a view.
    ///
    /// Order-independent by construction: every collection is a `BTree*` keyed by
    /// canonical content, so shuffling the input cannot change the view, the
    /// digest, or any verdict taken over it. That is convergence (a grow-only set
    /// under union) made structural rather than tested for.
    pub fn from_records<I>(records: I) -> Result<SnapshotCorpus, SnapshotError>
    where
        I: IntoIterator<Item = Record>,
    {
        let mut cooccurrence = BTreeSet::new();
        let mut adjacency: Adjacency = BTreeMap::new();
        let mut windows: WindowIndex = BTreeMap::new();
        let mut admissibility: AdmissIndex = BTreeMap::new();

        for r in records {
            match r {
                Record::CoOccurrence { a, b, at, via } => {
                    if a == b {
                        return Err(SnapshotError::SelfCoOccurrence(a));
                    }
                    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
                    cooccurrence.insert((lo, hi, at, via));
                    adjacency.entry(lo).or_default().insert((hi, via, at));
                    adjacency.entry(hi).or_default().insert((lo, via, at));
                }
                Record::Window {
                    entity,
                    recorded_at,
                    via,
                    start,
                    end,
                } => {
                    // Reject, never repair: an insert that overwrites makes the
                    // result depend on which record arrived last.
                    if let Some(prev) = windows
                        .entry(entity)
                        .or_default()
                        .insert((recorded_at, via), (start, end))
                    {
                        if prev != (start, end) {
                            return Err(SnapshotError::ContradictoryRecord { recorded_at, via });
                        }
                    }
                }
                Record::Admissibility {
                    claim,
                    recorded_at,
                    via,
                    ruling,
                } => {
                    if let Some(prev) = admissibility
                        .entry(claim)
                        .or_default()
                        .insert((recorded_at, via), ruling)
                    {
                        if prev != ruling {
                            return Err(SnapshotError::ContradictoryRecord { recorded_at, via });
                        }
                    }
                }
            }
        }

        let digest = digest_of(&cooccurrence, &windows, &admissibility);
        Ok(SnapshotCorpus {
            cooccurrence,
            adjacency,
            windows,
            admissibility,
            digest,
        })
    }

    /// The record set, so a caller can accrete onto an existing corpus without
    /// having kept the original `Vec` — which is what accretion-monotonicity
    /// testing and a gossip merge both need.
    pub fn records(&self) -> Vec<Record> {
        let mut out: Vec<Record> = Vec::new();
        for &(lo, hi, at, via) in &self.cooccurrence {
            out.push(Record::CoOccurrence {
                a: lo,
                b: hi,
                at,
                via,
            });
        }
        for (&entity, per_entity) in &self.windows {
            for (&(recorded_at, via), &(start, end)) in per_entity {
                out.push(Record::Window {
                    entity,
                    recorded_at,
                    via,
                    start,
                    end,
                });
            }
        }
        for (&claim, per_claim) in &self.admissibility {
            for (&(recorded_at, via), &ruling) in per_claim {
                out.push(Record::Admissibility {
                    claim,
                    recorded_at,
                    via,
                    ruling,
                });
            }
        }
        out
    }
}

impl CorpusView for SnapshotCorpus {
    fn neighbors(&self, entity: EntityId, as_of: Tick) -> Result<Vec<Edge>, ViewError> {
        let Some(adj) = self.adjacency.get(&entity) else {
            // A real, evidenced absence: this entity co-occurs with nothing at or
            // before `as_of`. Never confused with an inability to read.
            return Ok(Vec::new());
        };
        let mut out: Vec<Edge> = Vec::new();
        for &(other, via, at) in adj {
            // The `at <= as_of` bound IS the monotonicity guarantee. It is not
            // optional and it is not an optimization.
            if at <= as_of {
                let e = Edge { other, via };
                if out.last() != Some(&e) {
                    out.push(e);
                }
            }
        }
        Ok(out)
    }

    fn window(&self, entity: EntityId, as_of: Tick) -> Result<Windowed, ViewError> {
        // Latest-wins at or before `as_of`, ties broken by event id. A record
        // whose coordinate is after `as_of` is invisible here, which is what
        // keeps a later-discovered cessation from touching an earlier-pinned
        // verdict.
        let latest = self
            .windows
            .get(&entity)
            .and_then(|per_entity| per_entity.range(..=(as_of, MAX_EVENT_ID)).next_back());
        Ok(match latest {
            Some((&(_, via), &(start, end))) => Windowed {
                start,
                end,
                derived_from: vec![via],
            },
            None => Windowed::unrecorded(),
        })
    }

    fn admissibility(&self, c: ClaimType, as_of: Tick) -> Result<Admitted, ViewError> {
        let latest = self
            .admissibility
            .get(&c)
            .and_then(|per_claim| per_claim.range(..=(as_of, MAX_EVENT_ID)).next_back());
        Ok(match latest {
            Some((&(_, via), Ruling::Valid)) => Admitted::Valid {
                derived_from: vec![via],
            },
            Some((&(_, via), &Ruling::OutsideValidity { band_end })) => Admitted::OutsideValidity {
                band_end,
                derived_from: vec![via],
            },
            None => Admitted::Unrecorded,
        })
    }

    fn corpus_digest(&self) -> CorpusDigest {
        self.digest
    }
}

/// Digest the record set, in canonical `BTree` order with length framing, so the
/// identity of the inputs is a pure function of the *set* and not of how it was
/// assembled.
fn digest_of(
    cooccurrence: &BTreeSet<(EntityId, EntityId, Tick, EventId)>,
    windows: &WindowIndex,
    admissibility: &AdmissIndex,
) -> CorpusDigest {
    let mut buf = Vec::new();
    framed(&mut buf, DST_CORPUS);

    framed(&mut buf, b"cooccurrence");
    for (lo, hi, at, via) in cooccurrence {
        framed(&mut buf, &lo.to_canon_bytes());
        framed(&mut buf, &hi.to_canon_bytes());
        put_tick(&mut buf, *at);
        framed(&mut buf, via.as_bytes());
    }

    framed(&mut buf, b"windows");
    for (entity, per_entity) in windows {
        for ((recorded_at, via), (start, end)) in per_entity {
            framed(&mut buf, &entity.to_canon_bytes());
            put_tick(&mut buf, *recorded_at);
            framed(&mut buf, via.as_bytes());
            match start {
                Start::Unknown => framed(&mut buf, &[0u8]),
                Start::Known(t) => {
                    framed(&mut buf, &[1u8]);
                    put_tick(&mut buf, *t);
                }
            }
            match end {
                WindowEnd::KnownOpen => framed(&mut buf, &[0u8]),
                WindowEnd::UnknownClosure => framed(&mut buf, &[1u8]),
                WindowEnd::KnownClosed(t) => {
                    framed(&mut buf, &[2u8]);
                    put_tick(&mut buf, *t);
                }
            }
        }
    }

    framed(&mut buf, b"admissibility");
    for (claim, per_claim) in admissibility {
        for ((recorded_at, via), ruling) in per_claim {
            framed(&mut buf, &claim.to_canon_bytes());
            put_tick(&mut buf, *recorded_at);
            framed(&mut buf, via.as_bytes());
            match ruling {
                Ruling::Valid => framed(&mut buf, &[0u8]),
                Ruling::OutsideValidity { band_end } => {
                    framed(&mut buf, &[1u8]);
                    put_tick(&mut buf, *band_end);
                }
            }
        }
    }

    CorpusDigest::from_bytes(Sha256::digest(&buf).into())
}
