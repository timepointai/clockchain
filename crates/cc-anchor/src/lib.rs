//! `cc-anchor` — the commitment layer: a Merkle accumulator over the event log,
//! proofs about it, and thirty-two bytes of it inscribed into Bitcoin.
//!
//! **The design axiom, from which everything here follows** (§storage, §4.1):
//! *anchor the smallest thing that needs external trust; replicate promiscuously
//! everything that verifies itself.* Content is self-verifying against a root, so
//! content needs copies, not consensus. Roots are the one place an operator could
//! quietly rewrite the history of commitments, so roots — and only roots — go
//! into an external proof-of-work chain. Thirty-two bytes need consensus;
//! gigabytes need copies.
//!
//! **Three claims this crate makes checkable by a stranger:**
//!
//! 1. *This event is in the log.* [`prove_event`] returns an `O(log n)` audit
//!    path against a published root ([`merkle`], RFC 6962 semantics).
//! 2. *The log only ever grew.* [`consistency_between`] returns a proof that a
//!    later root extends an earlier one, so a mirror can tell "the operator
//!    appended" from "the operator rewrote and re-signed" while holding nothing
//!    but two 32-byte roots.
//! 3. *This all happened before block N.* [`anchor_root`] puts a root into
//!    Bitcoin through an OpenTimestamps calendar ([`ots`]), which yields a
//!    recorded-*before* bound proven by proof-of-work with no timestamp authority
//!    consulted — the retirement of the RFC 3161 model (Prop. trscope).
//!
//! **The Merkle path is also the payment path.** §mining: "every verdict already
//! enumerates the moments it consulted — the Merkle path is the attribution ...
//! the trust path and the payment path are one path." Nothing in the initiation
//! phase routes a royalty, but the proofs a later metered economy would route
//! over are the ones built here, because they cannot be reconstructed after the
//! fact for verdicts already given.
//!
//! **What is not built, named rather than hidden.** Verifying an upgraded OTS
//! proof against Bitcoin block headers needs a header source (a node or an
//! oracle) this build does not have: [`ots::attestations_in`] reads the block
//! height a calendar reports and [`confirm_anchor`] records it, but no code here
//! checks that height against the chain itself. The plan flags that dependency
//! rather than hiding it (§5.5), and so does this.

// This crate's whole product is evidence a stranger evaluates without asking us
// anything, so an undocumented public item here is a real defect: it is a proof
// obligation with no stated meaning. The lint makes that a build failure instead
// of a review note.
#![deny(missing_docs)]

pub mod merkle;
pub mod ots;
pub mod store;

pub use merkle::{
    leaf_hash, merkle_root, prove_consistency, prove_inclusion, ConsistencyProof, InclusionProof,
    LeafHash, MerkleRoot, ProofError,
};
pub use ots::{Attestation, Commitment, OtsError, OtsProof, PUBLIC_CALENDARS};
pub use store::{
    anchor_for, anchor_root, committed_leaf_count, confirm_anchor, consistency_between,
    latest_anchor, latest_root, load_proof, prove_event, publish_root, record_root_moment,
    record_stamp, root_at, upgrade_anchor, verify_root_chain, AnchorError, AnchorRecord,
    AnchorStatus, ChainAudit, EventInclusion, RootOutcome, RootPublication, UpgradeOutcome,
    NODE_ZERO,
};
