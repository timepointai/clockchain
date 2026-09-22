//! `cc-core` — the determinism boundary of the whole build.
//!
//! It owns the value types every other crate agrees on — [`Tick`],
//! [`canon_event`], [`EventId`]/[`event_id`], [`AuthorKey`]/[`Signature`], the
//! typed [`EventBody`] kinds, [`ExistenceWindow`], [`ProtocolConstants`] — and
//! does **no I/O**, no wall-clock reads, no allocation hooks it does not control.
//! Every function is a pure function of its arguments so that native and
//! `wasm32` targets compute byte-identical `H0`s and verdicts (the convergence
//! guarantee, whitepaper Prop. *converge*).

use bnum::types::I256;
use bnum::BUint;
use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Number of `u64` limbs backing [`I256`] (256 / 64).
const LIMBS: usize = 4;

/// Canon encoding regime version, bound into every preimage so two encoding
/// regimes can never collide.
pub const CANON_VERSION: u16 = 0;
/// Governed-constants version, bound into every preimage so a coordinate integer
/// is only ever hashed under a stated constants version.
pub const CONSTANTS_VERSION: u16 = 0;

// ===========================================================================
// Tick — the b256 coordinate
// ===========================================================================

/// A frame-independent coordinate: a signed count of *sub-ticks* from Clock
/// Zero, held in one 256-bit word.
///
/// The governed split `S` ([`ProtocolConstants::split`]) says how many low bits
/// are fractional: `whole_ticks = value >> S`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Tick(I256);

impl Tick {
    /// The maximal representable coordinate, `2^255 - 1`. Unreachable by any
    /// real event-time, so a "known-open" window can never be silently closed
    /// by a real coordinate landing on it.
    pub const SENTINEL: Tick = Tick(I256::MAX);
    /// Clock Zero.
    pub const ORIGIN: Tick = Tick(I256::ZERO);

    /// Construct a `Tick` from a raw signed 256-bit integer.
    pub const fn from_i256(v: I256) -> Tick {
        Tick(v)
    }

    /// Construct a `Tick` from a signed 64-bit count of **sub-ticks** — the raw
    /// stored value. The full range is reachable via [`Tick::from_i256`].
    ///
    /// Mind the unit: this is sub-ticks, not whole ticks. To build a coordinate
    /// from a whole-tick count, use [`Tick::from_whole_ticks`].
    pub fn from_i64(v: i64) -> Tick {
        Tick(I256::from(v))
    }

    /// Construct a coordinate from a count of **whole ticks** since Clock Zero,
    /// applying the governed split.
    ///
    /// The shift happens in `I256`. Doing it in `i64` overflows for any split at
    /// or above 64 — and the pinned v0 split is exactly 64 — so a caller writing
    /// `Tick::from_i64(secs << split)` panics in debug and silently produces a
    /// wrong coordinate in release. This constructor exists so that mistake is
    /// unreachable from outside this module.
    pub fn from_whole_ticks(whole: i64, split: FractionalBits) -> Tick {
        Tick(I256::from(whole) << split.0)
    }

    /// The underlying signed 256-bit integer.
    pub const fn to_i256(self) -> I256 {
        self.0
    }

    /// Canon / storage bytes: offset-binary (sign-bit-flipped) big-endian, so
    /// bytewise (`memcmp`) order equals numeric order across the sign boundary.
    /// This is the ONLY serialized form of a `Tick` anywhere: hash preimage and
    /// DB key are the same 32 bytes.
    pub fn to_canon_bytes(self) -> [u8; 32] {
        // Reinterpret the two's-complement value as unsigned, then read its
        // limbs (little-endian) into big-endian bytes. Avoids any dependence on
        // arithmetic shift sign-extension.
        let digits: [u64; LIMBS] = *self.0.to_bits().digits();
        let mut out = [0u8; 32];
        for (i, &limb) in digits.iter().enumerate() {
            let start = (LIMBS - 1 - i) * 8; // limb 0 is least significant
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out[0] ^= 0x80; // flip the sign bit => offset-binary ordering
        out
    }

    /// Inverse of [`Tick::to_canon_bytes`].
    pub fn from_canon_bytes(mut b: [u8; 32]) -> Tick {
        b[0] ^= 0x80;
        let mut digits = [0u64; LIMBS];
        for (i, d) in digits.iter_mut().enumerate() {
            let start = (LIMBS - 1 - i) * 8;
            let mut limb = [0u8; 8];
            limb.copy_from_slice(&b[start..start + 8]);
            *d = u64::from_be_bytes(limb);
        }
        Tick(I256::from_bits(BUint::<LIMBS>::from_digits(digits)))
    }

    /// Whole-tick count: `value >> split`.
    pub fn whole_ticks(self, split: FractionalBits) -> I256 {
        self.0 >> split.0
    }

    /// Settlement posture relative to a record-time: `sign(event_time -
    /// record_time)` — `-1` mined-past, `0` witnessed-present, `+1`
    /// staked-future (whitepaper §postures). Computed once at the write path and
    /// frozen onto the row.
    pub fn posture(self, record_time: Tick) -> i16 {
        match self.0.cmp(&record_time.0) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }
}

/// The governed sub-tick split `S`: how many low bits of a [`Tick`] are
/// fractional.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
pub struct FractionalBits(pub u32);

// ===========================================================================
// Identity: EventId / H0
// ===========================================================================

/// A content-addressed event identity: `H0 = SHA-256(canon(...))`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EventId([u8; 32]);

impl EventId {
    /// Wrap raw identity bytes (for reading a stored `event_id` back).
    pub const fn from_bytes(b: [u8; 32]) -> EventId {
        EventId(b)
    }

    /// The raw 32 identity bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex rendering (presentation only; never a key).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// `H0` over an already-serialized canon preimage.
pub fn h0(canon_bytes: &[u8]) -> EventId {
    EventId(Sha256::digest(canon_bytes).into())
}

// ===========================================================================
// Canon primitives (hand-rolled, length-framed, big-endian, no floats)
// ===========================================================================

/// Length-framed append: `u32_be(len(x)) || x`. Makes the concatenation
/// injective (no field-boundary ambiguity). A field at/past 2^32 bytes fails
/// loud rather than wrapping the length prefix into a colliding preimage.
fn framed(out: &mut Vec<u8>, x: &[u8]) {
    let len = u32::try_from(x.len()).expect("canon field exceeds 4 GiB frame bound");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
}

/// Append a coordinate as its 32 canonical (offset-binary) bytes.
fn put_tick(out: &mut Vec<u8>, t: Tick) {
    out.extend_from_slice(&t.to_canon_bytes());
}

// ===========================================================================
// Typed event kinds and bodies
// ===========================================================================

/// The typed event kinds the initiation-phase projector folds. A discriminant,
/// never a string (memo §10). Stored as the `smallint kind` column.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i16)]
pub enum EventKind {
    /// Birth of a first-class entity with a three-state existence window.
    EntityCreate = 1,
    /// A moment about a subject entity at a coordinate.
    Moment = 2,
    /// A typed, attributed, evidence-classed relation between two entities.
    Edge = 3,
    /// An independent attestation of a target event (distinct per attester).
    Attestation = 4,
    /// A governed vocabulary declaration: a claim type and the band of
    /// coordinates over which it is admissible.
    VocabularyDeclare = 5,
}

impl EventKind {
    /// The stored discriminant.
    pub fn to_i16(self) -> i16 {
        self as i16
    }

    /// Parse the stored discriminant.
    pub fn from_i16(v: i16) -> Option<EventKind> {
        match v {
            1 => Some(EventKind::EntityCreate),
            2 => Some(EventKind::Moment),
            3 => Some(EventKind::Edge),
            4 => Some(EventKind::Attestation),
            5 => Some(EventKind::VocabularyDeclare),
            _ => None,
        }
    }
}

/// The governed edge-relation vocabulary, versioned like the filter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EdgeRelation {
    CoOccurrence = 0,
    Influence = 1,
    Causation = 2,
    Participation = 3,
    Attestation = 4,
    Supersession = 5,
}

/// The evidence class an edge carries from birth, so a challenge has a target.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EvidenceClass {
    PrimaryDocument = 0,
    SecondarySource = 1,
    Inference = 2,
    Assertion = 3,
}

/// The three-state existence-window closure discriminant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i16)]
pub enum ClosureState {
    /// Confirmed still active.
    KnownOpen = 0,
    /// A real, recorded cessation coordinate.
    KnownClosed = 1,
    /// No recorded cessation, but activity is not confirmed.
    UnknownClosure = 2,
}

/// The existence-window *start* discriminant, carrying what the stored start
/// coordinate cannot.
///
/// Symmetric with [`ClosureState`] and load-bearing for the same reason: the
/// filter's window factor must distinguish "the record is silent about when this
/// began" from "the evidenced start is `Tick::ORIGIN`". Both are absences of a
/// useful bound, but only the second is a claim. Collapsing them would let a
/// migrated row whose source date was unparseable masquerade as an entity
/// evidenced to exist since Clock Zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i16)]
pub enum StartState {
    /// An evidenced start coordinate.
    Known = 0,
    /// The record is silent about when the subject began.
    Unknown = 1,
}

/// A governed vocabulary declaration.
///
/// `Admiss(c, t_q)` asks whether a claim type is admissible *at the queried
/// coordinate*, so a claim type carries a band of coordinates rather than a
/// simple in/out flag: "pitched battle" and "spaceflight" are both real
/// classifications, and the second one cannot apply to the year 1200.
///
/// The band reuses [`ExistenceWindow`] deliberately. A claim type's validity has
/// exactly the states an entity's existence has — an evidenced beginning or
/// silence about one, and a recorded retirement, a confirmed-still-current
/// status, or silence — and giving it a second, parallel three-state type would
/// be two vocabularies for one idea.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VocabularyEntry {
    /// The governed code. `0` is reserved and must never be declared: a query
    /// that failed to resolve a label must not accidentally name a real type.
    pub claim_type: u32,
    /// The human-readable label the code stands for. In canon, so two
    /// declarations that agree on the code but disagree on what it means are
    /// different events rather than one.
    pub label: String,
    /// The coordinates over which this claim type is admissible.
    pub band: ExistenceWindow,
}

/// The birth of an entity: a first-class row with a three-state window, not JSON
/// inside a moment (memo §10). `entity_id` is an author-chosen content field, so
/// the birth is content-addressed and re-birth is an idempotent union no-op.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EntityBirth {
    pub entity_id: i64,
    pub resolution_key: String,
    pub canonical_name: String,
    pub window: ExistenceWindow,
}

/// A moment about a subject entity. Content-addressed (H0 excludes envelope), so
/// two writers asserting the same moment converge to one event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MomentBody {
    pub subject: i64,
    pub body_hash: [u8; 32],
}

/// A typed relation between two entities, attributed to its asserter (the
/// envelope author) and evidence-classed from birth.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EdgeBody {
    pub src: i64,
    pub dst: i64,
    pub relation: EdgeRelation,
    pub evidence_class: EvidenceClass,
}

/// An independent attestation of a target event. Its identity hashes the target,
/// the attester's key, and the record-time, so distinct acts of corroboration
/// accumulate as separate rows and heal `P(G)` forward rather than collapsing
/// into the moment they attest (whitepaper §coattest).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttestationBody {
    pub target: EventId,
}

/// The typed content of an event. The variant selects the domain-separation tag
/// and the canonical field order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EventBody {
    EntityCreate(EntityBirth),
    Moment(MomentBody),
    Edge(EdgeBody),
    Attestation(AttestationBody),
    VocabularyDeclare(VocabularyEntry),
}

impl EventBody {
    /// The kind discriminant of this body.
    pub fn kind(&self) -> EventKind {
        match self {
            EventBody::VocabularyDeclare(_) => EventKind::VocabularyDeclare,
            EventBody::EntityCreate(_) => EventKind::EntityCreate,
            EventBody::Moment(_) => EventKind::Moment,
            EventBody::Edge(_) => EventKind::Edge,
            EventBody::Attestation(_) => EventKind::Attestation,
        }
    }
}

/// Everything a canonical event carries. The identity `H0` is a function of a
/// *kind-specific subset* of this: content-addressed kinds hash `event_time` +
/// `supersedes` + body (never `author`/`record_time`), so two writers converge;
/// an attestation hashes `target` + `author` + `record_time`, so attesters stay
/// distinct. The full struct is what the `events` row stores.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EventContent {
    /// The coordinate the assertion is about (the subject dictates it).
    pub event_time: Tick,
    /// When we recorded it — our clock, floored to the governed tick. Never
    /// backfillable; the sign of `event_time - record_time` is the posture.
    pub record_time: Tick,
    /// The proposer's key. Envelope for content-addressed kinds (not in `H0`);
    /// identity-bearing for attestations.
    pub author: AuthorKey,
    /// Correction/challenge lineage. Included in `H0` for content kinds so a
    /// correction is a genuinely distinct event.
    pub supersedes: Option<EventId>,
    /// The typed content.
    pub body: EventBody,
}

const DST_ENTITY: &[u8] = b"cc.entity.v0";
const DST_MOMENT: &[u8] = b"cc.moment.v0";
const DST_EDGE: &[u8] = b"cc.edge.v0";
const DST_ATTEST: &[u8] = b"cc.attestation.v0";
const DST_VOCAB: &[u8] = b"cc.vocabulary.v0";

/// Serialize an event's canonical fields deterministically into its `H0`
/// preimage. Hand-rolled, length-framed, big-endian, no floats, no `serde` —
/// every byte is a pure function of the identity-bearing fields in FIXED order.
pub fn canon_event(c: &EventContent) -> Vec<u8> {
    let mut out = Vec::new();
    let dst = match &c.body {
        EventBody::EntityCreate(_) => DST_ENTITY,
        EventBody::Moment(_) => DST_MOMENT,
        EventBody::Edge(_) => DST_EDGE,
        EventBody::Attestation(_) => DST_ATTEST,
        EventBody::VocabularyDeclare(_) => DST_VOCAB,
    };
    framed(&mut out, dst);
    out.extend_from_slice(&CANON_VERSION.to_be_bytes());
    out.extend_from_slice(&CONSTANTS_VERSION.to_be_bytes());

    match &c.body {
        EventBody::Attestation(a) => {
            // Identity = target || author || record_time. Distinct per attester
            // and per record-time; NOT content-addressed (an attestation is a
            // separate act of authorship, whitepaper §coattest).
            out.extend_from_slice(a.target.as_bytes());
            out.extend_from_slice(&c.author.to_bytes());
            put_tick(&mut out, c.record_time);
        }
        _ => {
            // Content-addressed: event_time + supersedes + body. NEVER author or
            // record_time, so two writers asserting identical content produce
            // the identical H0 (cross-writer convergence, Prop. converge).
            put_tick(&mut out, c.event_time);
            match c.supersedes {
                Some(p) => {
                    out.push(1);
                    out.extend_from_slice(p.as_bytes());
                }
                None => out.push(0),
            }
            match &c.body {
                EventBody::EntityCreate(e) => {
                    out.extend_from_slice(&e.entity_id.to_be_bytes());
                    framed(&mut out, e.resolution_key.as_bytes());
                    framed(&mut out, e.canonical_name.as_bytes());
                    // Both discriminants ride in canon, because both ends of the
                    // window collapse distinct states onto the same stored
                    // coordinate. Without the closure tag, canon would collide
                    // KnownOpen with UnknownClosure; without the start tag it
                    // would collide "silent about the start" with "evidenced to
                    // begin at the sentinel". Two different claims must never
                    // share an H0.
                    out.push(e.window.closure_state() as u8);
                    out.push(e.window.start_state() as u8);
                    put_tick(&mut out, e.window.stored_start());
                    put_tick(&mut out, e.window.stored_end());
                }
                EventBody::Moment(m) => {
                    out.extend_from_slice(&m.subject.to_be_bytes());
                    out.extend_from_slice(&m.body_hash);
                }
                EventBody::Edge(ed) => {
                    out.extend_from_slice(&ed.src.to_be_bytes());
                    out.extend_from_slice(&ed.dst.to_be_bytes());
                    out.push(ed.relation as u8);
                    out.push(ed.evidence_class as u8);
                }
                EventBody::VocabularyDeclare(v) => {
                    out.extend_from_slice(&v.claim_type.to_be_bytes());
                    framed(&mut out, v.label.as_bytes());
                    // The validity band carries both discriminants for the same
                    // reason an existence window does: "admissible from an
                    // unrecorded coordinate" and "admissible from Clock Zero"
                    // are different declarations and must not share an H0.
                    out.push(v.band.closure_state() as u8);
                    out.push(v.band.start_state() as u8);
                    put_tick(&mut out, v.band.stored_start());
                    put_tick(&mut out, v.band.stored_end());
                }
                EventBody::Attestation(_) => unreachable!("handled above"),
            }
        }
    }
    out
}

/// `H0` of an event: `SHA-256(canon_event(content))`.
pub fn event_id(c: &EventContent) -> EventId {
    h0(&canon_event(c))
}

/// A forward reader over a canon preimage. Bounds-checked; any short read or
/// trailing garbage is a [`CoreError::MalformedPayload`].
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CoreError> {
        let end = self.pos.checked_add(n).ok_or(CoreError::MalformedPayload)?;
        if end > self.b.len() {
            return Err(CoreError::MalformedPayload);
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CoreError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, CoreError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, CoreError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn i64(&mut self) -> Result<i64, CoreError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(i64::from_be_bytes(a))
    }
    fn arr32(&mut self) -> Result<[u8; 32], CoreError> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn tick(&mut self) -> Result<Tick, CoreError> {
        Ok(Tick::from_canon_bytes(self.arr32()?))
    }
    fn framed(&mut self) -> Result<&'a [u8], CoreError> {
        let s = self.take(4)?;
        let len = u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as usize;
        self.take(len)
    }
    fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

/// Inverse of [`canon_event`]: reconstruct the typed [`EventContent`] from a
/// stored payload plus the envelope columns the payload does not itself carry.
///
/// For content-addressed kinds the payload carries `event_time`, `supersedes`,
/// and the body; `record_time` and `author` come from the envelope. For an
/// attestation the payload carries `target`, `author`, and `record_time`;
/// `event_time` comes from the envelope. `parse_event(canon_event(x), ..) == x`
/// (a round-trip property test guards against drift with the writer).
pub fn parse_event(
    payload: &[u8],
    env_event_time: Tick,
    env_record_time: Tick,
    env_author: AuthorKey,
) -> Result<EventContent, CoreError> {
    let mut r = Reader::new(payload);
    let dst = r.framed()?;
    let _canon_version = r.u16()?;
    let _constants_version = r.u16()?;

    let content = if dst == DST_ATTEST {
        let target = EventId(r.arr32()?);
        let author = AuthorKey::from_bytes(&r.arr32()?)?;
        let record_time = r.tick()?;
        EventContent {
            event_time: env_event_time,
            record_time,
            author,
            supersedes: None,
            body: EventBody::Attestation(AttestationBody { target }),
        }
    } else {
        let event_time = r.tick()?;
        let supersedes = match r.u8()? {
            0 => None,
            1 => Some(EventId(r.arr32()?)),
            _ => return Err(CoreError::MalformedPayload),
        };
        let body = if dst == DST_ENTITY {
            let entity_id = r.i64()?;
            let resolution_key =
                String::from_utf8(r.framed()?.to_vec()).map_err(|_| CoreError::MalformedPayload)?;
            let canonical_name =
                String::from_utf8(r.framed()?.to_vec()).map_err(|_| CoreError::MalformedPayload)?;
            let closure = match r.u8()? {
                0 => ClosureState::KnownOpen,
                1 => ClosureState::KnownClosed,
                2 => ClosureState::UnknownClosure,
                _ => return Err(CoreError::MalformedPayload),
            };
            let start_state = match r.u8()? {
                0 => StartState::Known,
                1 => StartState::Unknown,
                _ => return Err(CoreError::MalformedPayload),
            };
            let window_start = r.tick()?;
            let window_end = r.tick()?;
            EventBody::EntityCreate(EntityBirth {
                entity_id,
                resolution_key,
                canonical_name,
                window: ExistenceWindow::from_stored(
                    start_state,
                    window_start,
                    closure,
                    window_end,
                ),
            })
        } else if dst == DST_MOMENT {
            let subject = r.i64()?;
            let body_hash = r.arr32()?;
            EventBody::Moment(MomentBody { subject, body_hash })
        } else if dst == DST_EDGE {
            let src = r.i64()?;
            let dst_entity = r.i64()?;
            let relation = match r.u8()? {
                0 => EdgeRelation::CoOccurrence,
                1 => EdgeRelation::Influence,
                2 => EdgeRelation::Causation,
                3 => EdgeRelation::Participation,
                4 => EdgeRelation::Attestation,
                5 => EdgeRelation::Supersession,
                _ => return Err(CoreError::MalformedPayload),
            };
            let evidence_class = match r.u8()? {
                0 => EvidenceClass::PrimaryDocument,
                1 => EvidenceClass::SecondarySource,
                2 => EvidenceClass::Inference,
                3 => EvidenceClass::Assertion,
                _ => return Err(CoreError::MalformedPayload),
            };
            EventBody::Edge(EdgeBody {
                src,
                dst: dst_entity,
                relation,
                evidence_class,
            })
        } else if dst == DST_VOCAB {
            let claim_type = r.u32()?;
            let label =
                String::from_utf8(r.framed()?.to_vec()).map_err(|_| CoreError::MalformedPayload)?;
            let closure = match r.u8()? {
                0 => ClosureState::KnownOpen,
                1 => ClosureState::KnownClosed,
                2 => ClosureState::UnknownClosure,
                _ => return Err(CoreError::MalformedPayload),
            };
            let start_state = match r.u8()? {
                0 => StartState::Known,
                1 => StartState::Unknown,
                _ => return Err(CoreError::MalformedPayload),
            };
            let band_start = r.tick()?;
            let band_end = r.tick()?;
            EventBody::VocabularyDeclare(VocabularyEntry {
                claim_type,
                label,
                band: ExistenceWindow::from_stored(start_state, band_start, closure, band_end),
            })
        } else {
            return Err(CoreError::MalformedPayload);
        };
        EventContent {
            event_time,
            record_time: env_record_time,
            author: env_author,
            supersedes,
            body,
        }
    };

    if !r.done() {
        return Err(CoreError::MalformedPayload);
    }
    Ok(content)
}

// ===========================================================================
// Ed25519 identity
// ===========================================================================

/// An author's Ed25519 verifying (public) key. Signatures prove key possession,
/// not real-world identity — identity assurance is a layer above the ledger.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthorKey(pub VerifyingKey);

impl AuthorKey {
    /// Parse an author key from its 32 public-key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<AuthorKey, CoreError> {
        VerifyingKey::from_bytes(bytes)
            .map(AuthorKey)
            .map_err(|_| CoreError::BadKey)
    }

    /// The 32 public-key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// An Ed25519 signature over a message (in practice, over an [`EventId`]).
#[derive(Clone, Copy)]
pub struct Signature(pub DalekSig);

impl Signature {
    /// Wrap raw signature bytes.
    pub fn from_bytes(b: [u8; 64]) -> Signature {
        Signature(DalekSig::from_bytes(&b))
    }

    /// The 64 signature bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

/// Sign a message with a signing key (RFC-8032 deterministic).
pub fn sign(sk: &SigningKey, msg: &[u8]) -> Signature {
    Signature(sk.sign(msg))
}

/// Sign an event: produce the `(EventId, Signature)` for its content, signing
/// over the id bytes.
pub fn seal(sk: &SigningKey, c: &EventContent) -> (EventId, Signature) {
    let id = event_id(c);
    let sig = sign(sk, id.as_bytes());
    (id, sig)
}

/// Verify a signature with `verify_strict` (rejects non-canonical `S` and
/// small-order points — no signature malleability under a consensus verify).
pub fn verify(key: &AuthorKey, msg: &[u8], sig: &Signature) -> Result<(), CoreError> {
    key.0
        .verify_strict(msg, &sig.0)
        .map_err(|_| CoreError::BadSignature)
}

/// A signing identity. The ergonomic public wrapper over the Ed25519 secret, so
/// downstream crates and tests never depend on `ed25519-dalek` directly. A
/// real deployment loads the secret from a platform reference (memo §7); the
/// seed constructor here is for genesis key derivation and tests.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// Derive a signing identity from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> SecretKey {
        SecretKey(SigningKey::from_bytes(&seed))
    }

    /// This identity's public author key.
    pub fn author(&self) -> AuthorKey {
        AuthorKey(self.0.verifying_key())
    }

    /// Sign a domain-separated attachment commitment without exposing the seed.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        sign(&self.0, message)
    }

    /// Compute `(H0, signature)` for an event's content, signing over the id.
    pub fn seal(&self, content: &EventContent) -> (EventId, Signature) {
        seal(&self.0, content)
    }
}

// ===========================================================================
// Existence windows
// ===========================================================================

/// A three-state existence window over the coordinate axis.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExistenceWindow {
    pub start: WindowStart,
    pub end: WindowEnd,
}

/// The start of an existence window. `Unknown` stores as the sentinel; the
/// semantic distinction ("evidenced start" vs "the record is silent") rides in
/// this tag, not in the arithmetic — exactly as [`WindowEnd`] does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WindowStart {
    /// A real, evidenced start coordinate.
    Known(Tick),
    /// No evidenced start. NOT `Known(Tick::ORIGIN)`: Clock Zero is a claim
    /// about when something began, and silence is not.
    Unknown,
}

/// The end of an existence window. `KnownOpen` and `UnknownClosure` both store
/// as the sentinel; the *semantic* distinction ("confirmed still active" vs "no
/// recorded cessation") rides in this tag, not in the arithmetic — the stored
/// [`Tick`] cannot carry it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WindowEnd {
    /// Confirmed still active; no cessation exists.
    KnownOpen,
    /// A real, recorded cessation coordinate.
    KnownClosed(Tick),
    /// No recorded cessation, but activity is not confirmed.
    UnknownClosure,
}

impl ExistenceWindow {
    /// Map the window end to the stored coordinate. `KnownOpen` and
    /// `UnknownClosure` both collapse to [`Tick::SENTINEL`]; the distinction
    /// between them is preserved in [`ExistenceWindow::closure_state`], never
    /// here.
    pub fn stored_end(&self) -> Tick {
        match self.end {
            WindowEnd::KnownClosed(t) => t,
            WindowEnd::KnownOpen | WindowEnd::UnknownClosure => Tick::SENTINEL,
        }
    }

    /// Map the window start to the stored coordinate. `Unknown` collapses to
    /// [`Tick::SENTINEL`]; the distinction is preserved in
    /// [`ExistenceWindow::start_state`], never here.
    pub fn stored_start(&self) -> Tick {
        match self.start {
            WindowStart::Known(t) => t,
            WindowStart::Unknown => Tick::SENTINEL,
        }
    }

    /// The closure discriminant carrying the semantics the arithmetic bound
    /// cannot.
    pub fn closure_state(&self) -> ClosureState {
        match self.end {
            WindowEnd::KnownOpen => ClosureState::KnownOpen,
            WindowEnd::KnownClosed(_) => ClosureState::KnownClosed,
            WindowEnd::UnknownClosure => ClosureState::UnknownClosure,
        }
    }

    /// The start discriminant carrying the semantics the stored coordinate
    /// cannot.
    pub fn start_state(&self) -> StartState {
        match self.start {
            WindowStart::Known(_) => StartState::Known,
            WindowStart::Unknown => StartState::Unknown,
        }
    }

    /// Reconstruct a window from its stored parts (used by the projector reading
    /// a row back).
    pub fn from_stored(
        start_state: StartState,
        stored_start: Tick,
        closure: ClosureState,
        stored_end: Tick,
    ) -> ExistenceWindow {
        let start = match start_state {
            StartState::Known => WindowStart::Known(stored_start),
            StartState::Unknown => WindowStart::Unknown,
        };
        let end = match closure {
            ClosureState::KnownOpen => WindowEnd::KnownOpen,
            ClosureState::KnownClosed => WindowEnd::KnownClosed(stored_end),
            ClosureState::UnknownClosure => WindowEnd::UnknownClosure,
        };
        ExistenceWindow { start, end }
    }
}

// ===========================================================================
// Governed protocol constants
// ===========================================================================

/// The identity of the filter rule a node is running, as recorded in the ledger.
///
/// A 32-byte hash, not an ordinal. `cc-filter` computes it — `cc-core` only
/// holds it, because the crate that defines an event's canon must not depend on
/// the crate that judges events. This type is the seam: `cc-filter` produces the
/// bytes, `cc-core` carries them into the genesis moment, and nothing in between
/// can quietly substitute a counter for a commitment.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FilterVersionId(pub [u8; 32]);

impl FilterVersionId {
    /// The raw 32 version bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, the form recorded in the genesis moment and published on
    /// `/health`.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl serde::Serialize for FilterVersionId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

/// The b256 coordinate constants — the subset a coordinate is interpreted
/// against, and the subset the filter version hashes.
///
/// Split out from [`ProtocolConstants`] to break a circularity: the filter
/// version is a hash *over* the coordinate constants, so it cannot also be an
/// input to itself. These are knowable at compile time; the filter version is
/// not, because it commits to compiled logic.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct B256Constants {
    pub clock_zero: &'static str,
    pub tick: &'static str,
    pub split: FractionalBits,
    pub anchor_chain: &'static str,
}

impl B256Constants {
    /// The pinned v0 coordinate constants. NOTE: the concrete IAU scale, tick
    /// duration, and split are Sean/Leo governance calls that must be blessed
    /// before M3 genesis (see docs/INITIATION-PLAN.md "Open questions"); these
    /// compile-time defaults are inert until then.
    pub const V0: B256Constants = B256Constants {
        clock_zero: "J2000.0 (TCB)",
        tick: "1 SI second",
        split: FractionalBits(64),
        anchor_chain: "bitcoin",
    };
}

/// Published, versioned protocol constants: the coordinate constants plus the
/// identity of the rule that judges against them. Emitted as the ledger's
/// genesis node-0 `protocol_constants_v0` moment.
///
/// There is deliberately **no `const V0`**. The full set is not knowable at
/// `cc-core` compile time, because half of it is a hash of the filter's compiled
/// support path — so it is constructed, at genesis, from the real filter's real
/// version. A constant here would have to lie about a value it cannot compute,
/// and that lie would be permanently recorded in the one event that can never be
/// rewritten.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct ProtocolConstants {
    pub b256: B256Constants,
    pub filter_version: FilterVersionId,
}

impl ProtocolConstants {
    /// The v0 set, completed by the filter version this build actually runs.
    pub const fn v0(filter_version: FilterVersionId) -> ProtocolConstants {
        ProtocolConstants {
            b256: B256Constants::V0,
            filter_version,
        }
    }
}

// ===========================================================================
// The founding exhibit (whitepaper §bootstrap)
// ===========================================================================

/// Commitment to a pre-signing-regime corpus, over its **frozen bytes**.
///
/// Deliberately NOT an [`EventId`], and produced by a function that shares no
/// code path with [`canon_event`]. The whitepaper is explicit that the exhibit's
/// "committed hash is over its own frozen bytes and is independent of the
/// ledger's coordinate encoding: the b256 canonicalization governs ledger
/// entries born under the signing regime, not the exhibit's committed bytes,
/// which are never recanonicalized" (§bootstrap).
///
/// The type is the enforcement. `canon_event` takes an [`EventContent`], not
/// bytes, and this is not an `EventId`, so canonicalizing an exhibit is not a
/// mistake you can make — it is a program that does not compile.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ExhibitId(pub [u8; 32]);

impl ExhibitId {
    /// The raw 32 commitment bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex (presentation and manifests; also what SHA256SUMS records).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Commit a frozen corpus: plain `SHA-256` over the bytes exactly as they are.
///
/// No canonicalization, no framing, no domain-separation tag — a manifest
/// written by `shasum -a 256` must reproduce this exactly, because the corpus
/// predates the signing regime and its provenance is an external checksum, not
/// something this system generated. Cleaning or re-encoding the input before
/// hashing would "destroy the object under measurement" (§bootstrap).
pub fn exhibit_commit(frozen_bytes: &[u8]) -> ExhibitId {
    ExhibitId(Sha256::digest(frozen_bytes).into())
}

/// A migrated entry's pointer back into the committed exhibit, so lineage is
/// checkable: which corpus, and where in it.
///
/// Envelope, not identity. It is stored on the event row and deliberately kept
/// OUT of [`canon_event`] — two writers asserting the same moment must converge
/// on one `H0` whether or not they learned it from the same archive, exactly as
/// `author` and `record_time` are excluded for the same reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExhibitRef {
    pub exhibit: ExhibitId,
    /// Byte offset of the source record within the frozen corpus.
    pub offset: u64,
}

// ===========================================================================
// Errors
// ===========================================================================

/// Errors from the pure core. There is no I/O here, so these are all
/// value-level failures.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid ed25519 verifying key")]
    BadKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed canon payload")]
    MalformedPayload,
}

// ===========================================================================
// Tests (real, must pass)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_author() -> (SigningKey, AuthorKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let ak = AuthorKey(sk.verifying_key());
        (sk, ak)
    }

    fn sample_moment(subject: i64, tag: u8) -> EventContent {
        let (_, author) = test_author();
        EventContent {
            event_time: Tick::from_i64(42),
            record_time: Tick::from_i64(43),
            author,
            supersedes: None,
            body: EventBody::Moment(MomentBody {
                subject,
                body_hash: [tag; 32],
            }),
        }
    }

    #[test]
    fn canon_is_deterministic_and_field_sensitive() {
        let m = sample_moment(1, 9);
        assert_eq!(event_id(&m), event_id(&m));
        assert_eq!(canon_event(&m), canon_event(&m));

        // Altering any canonical field produces a different id.
        let m2 = sample_moment(1, 10);
        assert_ne!(event_id(&m), event_id(&m2));
        let m3 = sample_moment(2, 9);
        assert_ne!(event_id(&m), event_id(&m3));
    }

    #[test]
    fn moment_h0_excludes_envelope_cross_writer_convergence() {
        // Two writers, different record_time, same moment content => same H0.
        let (_, author_a) = test_author();
        let skb = SigningKey::from_bytes(&[11u8; 32]);
        let author_b = AuthorKey(skb.verifying_key());

        let a = EventContent {
            event_time: Tick::from_i64(100),
            record_time: Tick::from_i64(200),
            author: author_a,
            supersedes: None,
            body: EventBody::Moment(MomentBody {
                subject: 5,
                body_hash: [1u8; 32],
            }),
        };
        let b = EventContent {
            event_time: Tick::from_i64(100),
            record_time: Tick::from_i64(999), // different envelope
            author: author_b,                 // different author
            supersedes: None,
            body: EventBody::Moment(MomentBody {
                subject: 5,
                body_hash: [1u8; 32],
            }),
        };
        assert_eq!(
            event_id(&a),
            event_id(&b),
            "moment H0 must exclude envelope"
        );
    }

    #[test]
    fn attestation_h0_includes_author_and_record_time() {
        let (_, author_a) = test_author();
        let skb = SigningKey::from_bytes(&[11u8; 32]);
        let author_b = AuthorKey(skb.verifying_key());
        let target = event_id(&sample_moment(1, 1));

        let mk = |author: AuthorKey, rt: i64| EventContent {
            event_time: Tick::from_i64(0),
            record_time: Tick::from_i64(rt),
            author,
            supersedes: None,
            body: EventBody::Attestation(AttestationBody { target }),
        };
        // Distinct attesters => distinct H0.
        assert_ne!(event_id(&mk(author_a, 5)), event_id(&mk(author_b, 5)));
        // Distinct record_time by the same attester => distinct H0.
        assert_ne!(event_id(&mk(author_a, 5)), event_id(&mk(author_a, 6)));
    }

    #[test]
    fn entity_canon_distinguishes_open_from_unknown_closure() {
        let (_, author) = test_author();
        let mk = |end: WindowEnd| EventContent {
            event_time: Tick::ORIGIN,
            record_time: Tick::ORIGIN,
            author,
            supersedes: None,
            body: EventBody::EntityCreate(EntityBirth {
                entity_id: 7,
                resolution_key: "res-7".into(),
                canonical_name: "Seven".into(),
                window: ExistenceWindow {
                    start: WindowStart::Known(Tick::ORIGIN),
                    end,
                },
            }),
        };
        // KnownOpen and UnknownClosure both store the sentinel bound, but the
        // closure tag keeps their canon (hence identity) distinct.
        assert_ne!(
            event_id(&mk(WindowEnd::KnownOpen)),
            event_id(&mk(WindowEnd::UnknownClosure)),
        );
    }

    #[test]
    fn offset_binary_orders_across_sign_boundary() {
        let vals = [
            I256::from(-1000i64),
            I256::from(-1i64),
            I256::ZERO,
            I256::from(1i64),
            I256::from(1000i64),
        ];
        for w in vals.windows(2) {
            let a = Tick::from_i256(w[0]);
            let b = Tick::from_i256(w[1]);
            assert!(a.to_i256() < b.to_i256());
            assert!(
                a.to_canon_bytes() < b.to_canon_bytes(),
                "offset-binary order broke for {a:?} < {b:?}",
            );
        }
    }

    #[test]
    fn canon_bytes_roundtrip() {
        for v in [
            I256::MIN,
            I256::from(-1i64),
            I256::ZERO,
            I256::from(1i64),
            I256::MAX,
        ] {
            let t = Tick::from_i256(v);
            assert_eq!(Tick::from_canon_bytes(t.to_canon_bytes()), t);
        }
    }

    #[test]
    fn sentinel_is_all_ff_and_origin_is_offset_zero() {
        assert_eq!(Tick::SENTINEL.to_canon_bytes(), [0xffu8; 32]);
        let mut expected = [0u8; 32];
        expected[0] = 0x80;
        assert_eq!(Tick::ORIGIN.to_canon_bytes(), expected);
    }

    #[test]
    fn posture_is_sign_of_event_minus_record() {
        assert_eq!(Tick::from_i64(10).posture(Tick::from_i64(20)), -1); // mined-past
        assert_eq!(Tick::from_i64(20).posture(Tick::from_i64(20)), 0); // present
        assert_eq!(Tick::from_i64(30).posture(Tick::from_i64(20)), 1); // staked-future
    }

    #[test]
    fn whole_ticks_shifts_by_split() {
        let t = Tick::from_i256(I256::from(1i64) << 64);
        assert_eq!(t.whole_ticks(FractionalBits(64)), I256::from(1i64));
    }

    #[test]
    fn sign_seal_verify_roundtrips() {
        let (sk, author) = test_author();
        let m = sample_moment(1, 3);
        let (id, sig) = seal(&sk, &m);
        assert_eq!(id, event_id(&m));
        assert!(verify(&author, id.as_bytes(), &sig).is_ok());
        // A tampered id must fail.
        let other = event_id(&sample_moment(2, 3));
        assert!(verify(&author, other.as_bytes(), &sig).is_err());
    }

    #[test]
    fn parse_event_round_trips_every_kind() {
        let (_, author) = test_author();
        let samples = [
            EventContent {
                event_time: Tick::from_i64(-1969),
                record_time: Tick::from_i64(2026),
                author,
                supersedes: None,
                body: EventBody::EntityCreate(EntityBirth {
                    entity_id: 42,
                    resolution_key: "apollo-11".into(),
                    canonical_name: "Apollo 11".into(),
                    window: ExistenceWindow {
                        start: WindowStart::Known(Tick::from_i64(-1969)),
                        end: WindowEnd::KnownClosed(Tick::from_i64(-1968)),
                    },
                }),
            },
            EventContent {
                event_time: Tick::from_i64(100),
                record_time: Tick::from_i64(200),
                author,
                supersedes: Some(event_id(&sample_moment(1, 1))),
                body: EventBody::Moment(MomentBody {
                    subject: 42,
                    body_hash: [7u8; 32],
                }),
            },
            EventContent {
                event_time: Tick::from_i64(5),
                record_time: Tick::from_i64(6),
                author,
                supersedes: None,
                body: EventBody::Edge(EdgeBody {
                    src: 1,
                    dst: 2,
                    relation: EdgeRelation::Causation,
                    evidence_class: EvidenceClass::PrimaryDocument,
                }),
            },
            EventContent {
                event_time: Tick::from_i64(9),
                record_time: Tick::from_i64(9),
                author,
                supersedes: None,
                body: EventBody::Attestation(AttestationBody {
                    target: event_id(&sample_moment(3, 3)),
                }),
            },
        ];
        for c in samples {
            let payload = canon_event(&c);
            let parsed =
                parse_event(&payload, c.event_time, c.record_time, c.author).expect("round-trip");
            assert_eq!(parsed, c, "parse(canon(x)) must equal x");
            assert_eq!(event_id(&parsed), event_id(&c));
        }
    }

    #[test]
    fn parse_event_rejects_trailing_and_short() {
        let c = sample_moment(1, 1);
        let mut payload = canon_event(&c);
        payload.push(0); // trailing garbage
        assert!(parse_event(&payload, c.event_time, c.record_time, c.author).is_err());

        let short = &canon_event(&c)[..4];
        let (_, author) = test_author();
        assert!(parse_event(short, Tick::ORIGIN, Tick::ORIGIN, author).is_err());
    }

    #[test]
    fn secret_key_seal_matches_event_id_and_verifies() {
        let sk = SecretKey::from_seed([3u8; 32]);
        let c = EventContent {
            event_time: Tick::from_i64(1),
            record_time: Tick::from_i64(1),
            author: sk.author(),
            supersedes: None,
            body: EventBody::Moment(MomentBody {
                subject: 1,
                body_hash: [0u8; 32],
            }),
        };
        let (id, sig) = sk.seal(&c);
        assert_eq!(id, event_id(&c));
        assert!(verify(&sk.author(), id.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn existence_window_open_and_unknown_store_sentinel() {
        let k = WindowStart::Known(Tick::ORIGIN);
        let w_open = ExistenceWindow {
            start: k,
            end: WindowEnd::KnownOpen,
        };
        let w_unknown = ExistenceWindow {
            start: k,
            end: WindowEnd::UnknownClosure,
        };
        let w_closed = ExistenceWindow {
            start: k,
            end: WindowEnd::KnownClosed(Tick::from_i64(5)),
        };
        let w_silent = ExistenceWindow {
            start: WindowStart::Unknown,
            end: WindowEnd::UnknownClosure,
        };
        assert_eq!(w_open.stored_end(), Tick::SENTINEL);
        assert_eq!(w_unknown.stored_end(), Tick::SENTINEL);
        assert_eq!(w_closed.stored_end(), Tick::from_i64(5));
        assert_eq!(w_silent.stored_start(), Tick::SENTINEL);
        // Round-trip through stored parts, on both axes.
        for w in [w_open, w_unknown, w_closed, w_silent] {
            let r = ExistenceWindow::from_stored(
                w.start_state(),
                w.stored_start(),
                w.closure_state(),
                w.stored_end(),
            );
            assert_eq!(r, w);
        }
    }

    /// The failure this exists to prevent: a migrated row whose source date was
    /// unparseable claiming to have existed since Clock Zero. Silence about a
    /// start and an evidenced start of `ORIGIN` are different sentences about
    /// the record, so they must be different events with different `H0`s — not
    /// two spellings of one.
    #[test]
    fn unknown_start_is_not_the_same_claim_as_a_start_at_clock_zero() {
        let birth = |start: WindowStart| EventContent {
            event_time: Tick::from_i64(1),
            record_time: Tick::from_i64(1),
            author: SecretKey::from_seed([9u8; 32]).author(),
            supersedes: None,
            body: EventBody::EntityCreate(EntityBirth {
                entity_id: 1,
                resolution_key: "res-1".into(),
                canonical_name: "One".into(),
                window: ExistenceWindow {
                    start,
                    end: WindowEnd::UnknownClosure,
                },
            }),
        };
        let silent = birth(WindowStart::Unknown);
        let at_zero = birth(WindowStart::Known(Tick::ORIGIN));
        assert_ne!(canon_event(&silent), canon_event(&at_zero));
        assert_ne!(event_id(&silent), event_id(&at_zero));
        // And each survives the round trip as itself.
        for c in [silent, at_zero] {
            let back =
                parse_event(&canon_event(&c), c.event_time, c.record_time, c.author).unwrap();
            assert_eq!(back.body, c.body);
        }
    }

    // ── the founding exhibit ────────────────────────────────────────────────

    #[test]
    fn exhibit_commit_is_plain_sha256_reproducible_by_shasum() {
        // The whole point of the exhibit commitment is that a checksum written
        // OUTSIDE this system — by `shasum -a 256`, before the signing regime
        // existed — reproduces it. Any framing, domain tag or canonicalization
        // would break that, so these are the published SHA-256 vectors.
        assert_eq!(
            exhibit_commit(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            exhibit_commit(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn exhibit_commit_does_not_canonicalize_its_input() {
        // The separation between exhibit and ledger is enforced by TYPE, not by
        // digest: both are SHA-256, so over identical bytes they necessarily
        // agree, and asserting otherwise would be asserting SHA-256 is not a
        // function. What must hold is that exhibit_commit adds NOTHING — no
        // framing, no domain tag, no version binding — so an external checksum
        // reproduces it.
        let raw = b"a corpus, dirty, exactly as captured";
        assert_eq!(exhibit_commit(raw).as_bytes(), &Sha256::digest(raw)[..]);

        // canon_event, by contrast, always adds framing and the two version
        // words, so a moment's preimage is never its own raw bytes.
        let m = sample_moment(1, 9);
        let canon = canon_event(&m);
        assert!(
            canon.len() > 32,
            "canon must frame and version-bind, never pass bytes through"
        );
        assert!(
            canon.starts_with(&(DST_MOMENT.len() as u32).to_be_bytes()),
            "canon must open with a length-framed domain-separation tag"
        );

        // And the types do not interconvert: an ExhibitId is not an EventId, so
        // an exhibit cannot be stored where an event identity is required.
        let e: ExhibitId = exhibit_commit(raw);
        let _: &[u8; 32] = e.as_bytes();
    }

    #[test]
    fn exhibit_ref_is_envelope_not_identity() {
        // Provenance is where a writer learned a claim, not what the claim is.
        // Two writers migrating the same moment from different offsets — or one
        // from an archive and one from nowhere — must converge on one H0.
        let a = sample_moment(1, 9);
        let b = sample_moment(1, 9);
        assert_eq!(
            event_id(&a),
            event_id(&b),
            "H0 must not depend on provenance; cross-writer convergence"
        );
        let r = ExhibitRef {
            exhibit: exhibit_commit(b"corpus"),
            offset: 42,
        };
        assert_eq!(r.offset, 42);
        assert_eq!(r.exhibit, exhibit_commit(b"corpus"));
        assert_ne!(r.exhibit, exhibit_commit(b"corpus "));
    }

    #[test]
    fn from_whole_ticks_survives_the_v0_split() {
        // Regression: building a coordinate as `from_i64(secs << split)` panics
        // in debug and silently truncates in release, because the pinned v0
        // split is 64 and the shift was happening in i64. This is the exact
        // arithmetic the migrator does for every genesis event.
        let split = B256Constants::V0.split;
        assert_eq!(split.0, 64, "v0 split is the case that overflows i64");

        let secs: i64 = 839_678_400; // a real coordinate: 2026-08-12
        let t = Tick::from_whole_ticks(secs, split);
        assert_eq!(
            t.whole_ticks(split),
            I256::from(secs),
            "round-trips through the split"
        );

        // Negative coordinates are the common case for a historical corpus.
        let bce: i64 = -64_496_088_000; // 44 BCE
        let tb = Tick::from_whole_ticks(bce, split);
        assert_eq!(tb.whole_ticks(split), I256::from(bce));
        assert!(
            tb < t,
            "ordering survives the split across the sign boundary"
        );
    }
}
