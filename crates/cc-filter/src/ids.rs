//! The newtypes the filter's arguments are spoken in.
//!
//! `cc-core` carries entity identity, claim codes and hop bounds as bare
//! integers because at the storage layer they are just columns. Inside the
//! filter they are four different things that all happen to be integers, and
//! every one of them appears in the same call signature — so passing them bare
//! makes "subject and claim transposed at the call site" a silent wrong verdict
//! rather than a compile error. Newtypes are discipline #8 spent exactly where
//! the arity of `feasibility` makes it cheap.

use cc_core::Tick;

/// An entity as the ledger identifies it (`EntityBirth::entity_id`).
///
/// Wraps the `i64` `cc-core` stores so the geometric argument — *which* integers
/// are the vertices of `B(t)` — is carried by the type instead of by convention.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EntityId(i64);

impl EntityId {
    /// Adopt a stored entity id. Named `from_i64` rather than `new` so a reader
    /// of a `cc-ledger` row-decoding site can see the representation crossing.
    pub const fn from_i64(v: i64) -> EntityId {
        EntityId(v)
    }

    /// The stored representation, for writing the id back to a projection row.
    pub const fn to_i64(self) -> i64 {
        self.0
    }

    /// Canonical bytes: big-endian two's complement. Fixed width and
    /// order-irrelevant, so an id folded into a digest cannot collide with an
    /// adjacent field the way a variable-width decimal rendering could.
    pub(crate) fn to_canon_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// A claim type `c` from the governed vocabulary: the "manner" of the asserted
/// interaction, whose taxonomic and temporal coherence `Admiss(c, t_q)` judges.
///
/// A code, never a string: a stringly-typed claim type would put the vocabulary
/// snapshot's spelling inside a consensus-bearing comparison, so two nodes could
/// disagree over case-folding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ClaimType(u32);

impl ClaimType {
    /// Adopt a governed vocabulary code.
    pub const fn from_u32(v: u32) -> ClaimType {
        ClaimType(v)
    }

    /// The governed vocabulary code.
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// Canonical bytes, big-endian and fixed width, for the same reason
    /// [`EntityId::to_canon_bytes`] is.
    pub(crate) fn to_canon_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// The governed hop bound `k` for `Known_k`.
///
/// A newtype because `k` is a *governed constant recorded in the ledger*, not a
/// tuning knob: it is bound into the filter-version hash, so a query asking for
/// a bound the rule does not sanction is a malformed query rather than a slower
/// one. `u8` because a bound past 255 hops is not a feasibility question.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HopBound(u8);

impl HopBound {
    /// Adopt a governed bound.
    pub const fn new(k: u8) -> HopBound {
        HopBound(k)
    }

    /// The bound as a hop count.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// A *measured* shortest evidenced walk length — the integer the filter found,
/// deliberately a different type from the governed bound [`HopBound`] it is
/// compared against. Conflating "the rule allows 3 hops" with "the evidence
/// needed 3 hops" is how a bound silently becomes a measurement in a later
/// refactor; here it does not typecheck.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WalkLen(u16);

impl WalkLen {
    /// A measured walk length.
    pub const fn new(hops: u16) -> WalkLen {
        WalkLen(hops)
    }

    /// The measured hop count.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Identity of the *event set* a [`crate::CorpusView`] projects.
///
/// Kept rigorously separate from the filter version: the version names **the
/// rule**, this names **the inputs**. Two nodes that disagree therefore differ
/// in exactly one legible way — a different digest is a gossip-horizon gap that
/// closes on exchange, a different version is a governance event — and never in
/// an unexplained fork. Folding one into the other would destroy that.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CorpusDigest([u8; 32]);

impl CorpusDigest {
    /// Adopt a computed digest.
    pub const fn from_bytes(b: [u8; 32]) -> CorpusDigest {
        CorpusDigest(b)
    }

    /// The raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Length-framed append: `u32_be(len(x)) || x`.
///
/// Mirrors `cc-core`'s canon framing rather than reusing it because that
/// function is private to `cc-core` and this crate must not grow a dependency on
/// `cc-core` internals to hash its own parameters. Framing is what makes a
/// concatenation injective: without it, moving a byte from the end of one field
/// to the start of the next produces the same preimage.
pub(crate) fn framed(out: &mut Vec<u8>, x: &[u8]) {
    let len = u32::try_from(x.len()).expect("canon field exceeds 4 GiB frame bound");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
}

/// Append a coordinate as its 32 canonical (offset-binary) bytes — the single
/// serialized form of a `Tick` anywhere in the system, so a coordinate hashed
/// here and a coordinate keyed in Postgres are the same bytes.
pub(crate) fn framed_tick(out: &mut Vec<u8>, t: Tick) {
    framed(out, &t.to_canon_bytes());
}
