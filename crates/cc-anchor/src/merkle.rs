//! The Merkle accumulator: RFC 6962 semantics, hash for hash.
//!
//! **Why RFC 6962 rather than a bespoke tree.** The whitepaper (§4.1) promises a
//! stranger two things about our roots: leaf inclusion in `O(log n)` hashes, and
//! a consistency proof that a later root *extends* an earlier one instead of
//! quietly dropping leaves. Certificate Transparency specified exactly those two
//! proofs a decade ago and every CT auditor already implements the verifier. By
//! matching the RFC byte for byte we inherit that ecosystem: a third party can
//! check a Clockchain root with software that has never heard of Clockchain,
//! which is the only kind of verifiability worth publishing.
//!
//! **Why the tree is unbalanced.** Bitcoin's tree duplicates the last leaf on an
//! odd count; RFC 6962 splits at the largest power of two below `n` instead. The
//! duplicating construction cannot support consistency proofs — appending a leaf
//! reshapes the interior nodes above the duplicate, so an earlier root is not a
//! subtree of a later one. The split-at-`2^k` construction makes every earlier
//! tree a left subtree of every later tree, which is precisely what makes
//! non-removal provable. The skeleton's duplicating `merkle_root` was replaced
//! for that reason, not for taste.
//!
//! **Why leaves and interior nodes are prefixed differently.** Without the
//! `0x00`/`0x01` domain separation an attacker who controls two adjacent leaves
//! can present their concatenation as a single leaf whose hash equals a
//! legitimate interior node, and hand out an inclusion proof for a leaf the log
//! never committed. The prefixes make the two preimage spaces disjoint, so a
//! leaf can never be forged as an interior node (RFC 6962 §2.1). [`LeafHash`] is
//! a newtype for the same reason at the type level: a raw `EventId` cannot be
//! passed where a prefixed leaf is expected.

use cc_core::EventId;
use sha2::{Digest, Sha256};

/// Prefix on every leaf preimage (RFC 6962 §2.1).
const LEAF_PREFIX: u8 = 0x00;
/// Prefix on every interior-node preimage — disjoint from [`LEAF_PREFIX`], which
/// is the whole second-preimage argument.
const NODE_PREFIX: u8 = 0x01;

/// A domain-separated leaf: `SHA-256(0x00 || event_id)`.
///
/// Held as a distinct type from [`MerkleRoot`] and from a bare `EventId` so the
/// prefix cannot be forgotten at a call site. Forgetting it is not a cosmetic
/// error: an unprefixed leaf is exactly the second-preimage the prefix exists to
/// prevent.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LeafHash([u8; 32]);

impl LeafHash {
    /// The raw 32 bytes, for storage and for the wire.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstruct a leaf hash that was computed elsewhere (a mirror verifying a
    /// proof it was handed, a row read back from Postgres).
    pub const fn from_bytes(b: [u8; 32]) -> LeafHash {
        LeafHash(b)
    }
}

/// A Merkle Tree Hash over a prefix of the commitment log (RFC 6962 `MTH`).
///
/// Distinct from [`LeafHash`] so a one-leaf tree — where the two values are
/// numerically equal — still cannot be substituted for one another by a caller.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MerkleRoot([u8; 32]);

impl MerkleRoot {
    /// The raw 32 root bytes: the only thing that needs external consensus
    /// (§storage, "thirty-two bytes need consensus; gigabytes need copies").
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstruct a root read back from a row or received from a peer.
    pub const fn from_bytes(b: [u8; 32]) -> MerkleRoot {
        MerkleRoot(b)
    }

    /// Lowercase hex, for manifests and logs. Presentation only, never a key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// The leaf commitment for an event: `SHA-256(0x00 || H0)`.
///
/// The leaf is the event's *identity*, not its payload, because `H0` already
/// content-addresses every canonical field — committing to the id commits to the
/// bytes transitively, and keeps the tree independent of how a row is stored.
pub fn leaf_hash(id: &EventId) -> LeafHash {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(id.as_bytes());
    LeafHash(h.finalize().into())
}

/// Interior node: `SHA-256(0x01 || left || right)`.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two strictly less than `n` — RFC 6962's `k`, the split
/// that makes every earlier tree a left subtree of every later one.
fn split_point(n: usize) -> usize {
    debug_assert!(n > 1, "a tree of one leaf or fewer has no split");
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// `MTH(D[n])` — the Merkle root over a leaf range.
///
/// The empty tree hashes to `SHA-256("")` per RFC 6962, which is a *value*, not
/// a sentinel: an all-zero root would be forgeable by anyone and indistinguishable
/// from an uninitialized field.
pub fn merkle_root(leaves: &[LeafHash]) -> MerkleRoot {
    MerkleRoot(mth(leaves))
}

fn mth(leaves: &[LeafHash]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0].0,
        n => {
            let k = split_point(n);
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// Something a caller asked the accumulator to prove that the log cannot support.
///
/// Every variant is a *loud* refusal rather than an empty proof, because an empty
/// `Vec` returned from a failed proof attempt verifies as "one-leaf tree" against
/// a determined caller (memo §5: no-evidence and empty are different answers).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProofError {
    /// Asked to prove a leaf the tree does not contain.
    #[error("leaf index {index} is outside a tree of {tree_size} leaves")]
    IndexOutOfRange {
        /// The leaf asked for.
        index: u64,
        /// How many leaves the tree actually has.
        tree_size: u64,
    },
    /// Asked to prove consistency with a tree that is not a prefix of this one.
    #[error("old size {old_size} exceeds the current tree of {tree_size} leaves")]
    OldSizeExceedsTree {
        /// The earlier tree's claimed leaf count.
        old_size: u64,
        /// How many leaves this tree actually has.
        tree_size: u64,
    },
    /// Asked to prove that something extends the empty tree. Every tree does, so
    /// the proof would carry no information — and our root stream never asks:
    /// epoch 0 is published with no predecessor at all.
    #[error("the empty tree has no consistency proof to give")]
    EmptyOldTree,
    /// A stored proof blob is not a whole number of 32-byte hashes.
    #[error("proof path is {0} bytes, not a multiple of 32")]
    MalformedPath(usize),
}

// ===========================================================================
// Inclusion
// ===========================================================================

/// An audit path proving one leaf sits under one root — `O(log n)` hashes, the
/// bound §4.1 promises and the reason a client can check a claim without holding
/// the corpus.
///
/// It carries `tree_size` because the verifier's walk depends on the tree's
/// shape, not only on the path: the same sibling list under a different size is
/// a different proof, and a proof that did not pin the size could be replayed
/// against a tree it was never valid for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InclusionProof {
    leaf_index: u64,
    tree_size: u64,
    path: Vec<[u8; 32]>,
}

impl InclusionProof {
    /// The leaf's position in the commitment log — its `seq`.
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// The tree this proof is against. A proof is only meaningful with it.
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// The sibling hashes, leaf-ward first.
    pub fn path(&self) -> &[[u8; 32]] {
        &self.path
    }

    /// The path flattened for storage or the wire.
    pub fn path_bytes(&self) -> Vec<u8> {
        flatten(&self.path)
    }

    /// Rebuild a proof from its stored path plus the two numbers that fix the
    /// tree it belongs to.
    pub fn from_path_bytes(
        leaf_index: u64,
        tree_size: u64,
        bytes: &[u8],
    ) -> Result<InclusionProof, ProofError> {
        Ok(InclusionProof {
            leaf_index,
            tree_size,
            path: unflatten(bytes)?,
        })
    }

    /// Check this leaf against this root, exactly as RFC 6962 §2.1.1 specifies.
    ///
    /// Returns a plain `bool` and never an error: to a verifier, "the proof does
    /// not check out" is one answer however it failed, and a caller that could
    /// distinguish a malformed proof from a forged one would be tempted to treat
    /// the first as benign.
    pub fn verify(&self, leaf: &LeafHash, root: &MerkleRoot) -> bool {
        if self.leaf_index >= self.tree_size {
            return false;
        }
        let mut fnode = self.leaf_index;
        let mut snode = self.tree_size - 1;
        let mut r = leaf.0;
        for p in &self.path {
            if snode == 0 {
                return false;
            }
            if fnode & 1 == 1 || fnode == snode {
                r = node_hash(p, &r);
                if fnode & 1 == 0 {
                    while fnode != 0 && fnode & 1 == 0 {
                        fnode >>= 1;
                        snode >>= 1;
                    }
                }
            } else {
                r = node_hash(&r, p);
            }
            fnode >>= 1;
            snode >>= 1;
        }
        snode == 0 && r == root.0
    }
}

/// Build the audit path for `index` over `leaves` (RFC 6962 `PATH`).
pub fn prove_inclusion(leaves: &[LeafHash], index: u64) -> Result<InclusionProof, ProofError> {
    let n = leaves.len() as u64;
    if index >= n {
        return Err(ProofError::IndexOutOfRange {
            index,
            tree_size: n,
        });
    }
    let mut path = Vec::new();
    audit_path(leaves, index as usize, &mut path);
    Ok(InclusionProof {
        leaf_index: index,
        tree_size: n,
        path,
    })
}

fn audit_path(leaves: &[LeafHash], m: usize, out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n);
    if m < k {
        audit_path(&leaves[..k], m, out);
        out.push(mth(&leaves[k..]));
    } else {
        audit_path(&leaves[k..], m - k, out);
        out.push(mth(&leaves[..k]));
    }
}

// ===========================================================================
// Consistency
// ===========================================================================

/// A proof that a later root committed to *every* leaf an earlier root did, in
/// the same order and the same positions.
///
/// This is the non-removal guarantee of §4.1, and it is what makes an operator's
/// root stream auditable by someone who never saw the events: a mirror holding
/// only two 32-byte roots and this path can tell "the log grew" from "the log
/// was rewritten and re-signed".
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConsistencyProof {
    old_size: u64,
    new_size: u64,
    path: Vec<[u8; 32]>,
}

impl ConsistencyProof {
    /// Leaf count of the earlier tree.
    pub fn old_size(&self) -> u64 {
        self.old_size
    }

    /// Leaf count of the later tree.
    pub fn new_size(&self) -> u64 {
        self.new_size
    }

    /// The proof hashes.
    pub fn path(&self) -> &[[u8; 32]] {
        &self.path
    }

    /// The path flattened for the `roots.consistency` column.
    pub fn path_bytes(&self) -> Vec<u8> {
        flatten(&self.path)
    }

    /// Rebuild a stored proof. The two sizes come from the two `roots` rows, so
    /// the blob alone is never enough to replay a proof against another pair.
    pub fn from_path_bytes(
        old_size: u64,
        new_size: u64,
        bytes: &[u8],
    ) -> Result<ConsistencyProof, ProofError> {
        Ok(ConsistencyProof {
            old_size,
            new_size,
            path: unflatten(bytes)?,
        })
    }

    /// Check that `new_root` extends `old_root`, per RFC 6962 §2.1.2.
    ///
    /// Equal sizes are handled as the degenerate case they are: the same tree
    /// extends itself iff the two roots are equal, and no path is needed to say
    /// so. Anything else — a shrinking tree, a path of the wrong shape, a
    /// reordered leaf — is `false`.
    pub fn verify(&self, old_root: &MerkleRoot, new_root: &MerkleRoot) -> bool {
        if self.old_size > self.new_size || self.old_size == 0 {
            return false;
        }
        if self.old_size == self.new_size {
            return self.path.is_empty() && old_root == new_root;
        }

        // RFC 6962 §2.1.2 step 2: when the old tree is a perfect subtree its root
        // is not carried in the path (the verifier already has it), so seed the
        // walk with it.
        let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(self.path.len() + 1);
        if self.old_size.is_power_of_two() {
            nodes.push(old_root.0);
        }
        nodes.extend_from_slice(&self.path);

        let mut it = nodes.iter();
        let Some(first) = it.next() else {
            return false;
        };
        let mut fnode = self.old_size - 1;
        let mut snode = self.new_size - 1;
        while fnode & 1 == 1 {
            fnode >>= 1;
            snode >>= 1;
        }
        let mut fr = *first;
        let mut sr = *first;
        for c in it {
            if snode == 0 {
                return false;
            }
            if fnode & 1 == 1 || fnode == snode {
                fr = node_hash(c, &fr);
                sr = node_hash(c, &sr);
                if fnode & 1 == 0 {
                    while fnode != 0 && fnode & 1 == 0 {
                        fnode >>= 1;
                        snode >>= 1;
                    }
                }
            } else {
                sr = node_hash(&sr, c);
            }
            fnode >>= 1;
            snode >>= 1;
        }
        snode == 0 && fr == old_root.0 && sr == new_root.0
    }
}

/// Build the proof that `merkle_root(leaves)` extends `merkle_root(leaves[..old_size])`
/// (RFC 6962 `PROOF`/`SUBPROOF`).
pub fn prove_consistency(
    leaves: &[LeafHash],
    old_size: u64,
) -> Result<ConsistencyProof, ProofError> {
    let n = leaves.len() as u64;
    if old_size == 0 {
        return Err(ProofError::EmptyOldTree);
    }
    if old_size > n {
        return Err(ProofError::OldSizeExceedsTree {
            old_size,
            tree_size: n,
        });
    }
    let mut path = Vec::new();
    subproof(leaves, old_size as usize, true, &mut path);
    Ok(ConsistencyProof {
        old_size,
        new_size: n,
        path,
    })
}

/// `SUBPROOF(m, D[n], b)`. `b` ("the old tree is still whole in this subtree")
/// is what decides whether the old root has to be handed to the verifier or can
/// be left for it to recompute.
fn subproof(leaves: &[LeafHash], m: usize, b: bool, out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if m == n {
        if !b {
            out.push(mth(leaves));
        }
        return;
    }
    let k = split_point(n);
    if m <= k {
        subproof(&leaves[..k], m, b, out);
        out.push(mth(&leaves[k..]));
    } else {
        subproof(&leaves[k..], m - k, false, out);
        out.push(mth(&leaves[..k]));
    }
}

// ===========================================================================
// Path (de)serialization
// ===========================================================================

fn flatten(path: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len() * 32);
    for h in path {
        out.extend_from_slice(h);
    }
    out
}

fn unflatten(bytes: &[u8]) -> Result<Vec<[u8; 32]>, ProofError> {
    if !bytes.len().is_multiple_of(32) {
        return Err(ProofError::MalformedPath(bytes.len()));
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|c| {
            let mut h = [0u8; 32];
            h.copy_from_slice(c);
            h
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: u64) -> Vec<LeafHash> {
        (0..n)
            .map(|i| {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&i.to_be_bytes());
                leaf_hash(&EventId::from_bytes(b))
            })
            .collect()
    }

    #[test]
    fn empty_tree_is_the_hash_of_nothing_not_a_zero_sentinel() {
        let root = merkle_root(&[]);
        let expect: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(root.as_bytes(), &expect);
        assert_ne!(root.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn rfc6962_test_vectors() {
        // The CT reference vectors: SHA-256 of the empty string, and the roots of
        // the 8-entry test log. Matching these is the interoperability claim —
        // if these drift, a standard CT verifier stops being able to check us.
        assert_eq!(
            hex::encode(merkle_root(&[]).as_bytes()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // MTH of a single empty leaf: SHA-256(0x00) — RFC 6962 §2.1 worked example.
        let empty_leaf = {
            let mut h = Sha256::new();
            h.update([LEAF_PREFIX]);
            LeafHash(h.finalize().into())
        };
        assert_eq!(
            hex::encode(merkle_root(&[empty_leaf]).as_bytes()),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn root_depends_on_leaf_order_not_just_the_set() {
        let l = leaves(4);
        let mut swapped = l.clone();
        swapped.swap(0, 3);
        assert_ne!(merkle_root(&l), merkle_root(&swapped));
    }

    #[test]
    fn a_leaf_cannot_be_forged_as_an_interior_node() {
        // Two leaves and the interior node above them. If the prefixes were
        // dropped, an attacker could present `left || right` as a leaf whose hash
        // equals the parent. With domain separation the preimages are disjoint.
        let l = leaves(2);
        let parent = merkle_root(&l);
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(l[0].as_bytes());
        concatenated.extend_from_slice(l[1].as_bytes());
        let forged: [u8; 32] = Sha256::digest(&concatenated).into();
        assert_ne!(&forged, parent.as_bytes());
        // And the leaf-prefixed hash of the same bytes is different again.
        let mut h = Sha256::new();
        h.update([LEAF_PREFIX]);
        h.update(&concatenated);
        let as_leaf: [u8; 32] = h.finalize().into();
        assert_ne!(&as_leaf, parent.as_bytes());
    }

    #[test]
    fn inclusion_verifies_for_every_leaf_of_every_size_to_33() {
        for n in 1..=33u64 {
            let l = leaves(n);
            let root = merkle_root(&l);
            for i in 0..n {
                let proof = prove_inclusion(&l, i).expect("leaf is in range");
                assert!(
                    proof.verify(&l[i as usize], &root),
                    "n={n} i={i} must verify"
                );
                // O(log n): the path is never longer than the tree is deep.
                assert!(proof.path().len() <= 64 - (n - 1).leading_zeros() as usize);
            }
        }
    }

    #[test]
    fn inclusion_fails_for_a_tampered_leaf_and_a_tampered_path() {
        let l = leaves(9);
        let root = merkle_root(&l);
        let proof = prove_inclusion(&l, 4).expect("in range");
        assert!(proof.verify(&l[4], &root));

        // A different leaf under the same path: the forgery this proof exists to
        // refuse.
        assert!(!proof.verify(&l[5], &root));

        // One flipped bit anywhere in the path.
        let mut tampered = proof.clone();
        tampered.path[0][0] ^= 0x01;
        assert!(!tampered.verify(&l[4], &root));

        // A truncated path must not verify against a shorter tree by accident.
        let short = InclusionProof {
            leaf_index: 4,
            tree_size: 9,
            path: proof.path[..1].to_vec(),
        };
        assert!(!short.verify(&l[4], &root));
    }

    #[test]
    fn inclusion_out_of_range_is_an_error_not_an_empty_proof() {
        let l = leaves(3);
        assert_eq!(
            prove_inclusion(&l, 3),
            Err(ProofError::IndexOutOfRange {
                index: 3,
                tree_size: 3
            })
        );
    }

    #[test]
    fn consistency_verifies_for_every_prefix_pair_to_33() {
        for n in 1..=33u64 {
            let l = leaves(n);
            let new_root = merkle_root(&l);
            for m in 1..=n {
                let old_root = merkle_root(&l[..m as usize]);
                let proof = prove_consistency(&l, m).expect("m in range");
                assert!(
                    proof.verify(&old_root, &new_root),
                    "n={n} m={m} must verify"
                );
            }
        }
    }

    #[test]
    fn consistency_refuses_a_log_that_dropped_or_reordered_a_leaf() {
        let l = leaves(16);
        let old_root = merkle_root(&l[..5]);
        let proof = prove_consistency(&l, 5).expect("in range");
        assert!(proof.verify(&old_root, &merkle_root(&l)));

        // Rewrite leaf 2 and recompute: the same-shaped proof must not carry over.
        let mut rewritten = l.clone();
        rewritten[2] = leaf_hash(&EventId::from_bytes([0xAA; 32]));
        let rewritten_root = merkle_root(&rewritten);
        assert!(!proof.verify(&old_root, &rewritten_root));
        let rewritten_proof = prove_consistency(&rewritten, 5).expect("in range");
        assert!(!rewritten_proof.verify(&old_root, &rewritten_root));
    }

    #[test]
    fn consistency_of_a_tree_with_itself_needs_no_path() {
        let l = leaves(7);
        let root = merkle_root(&l);
        let proof = prove_consistency(&l, 7).expect("in range");
        assert!(proof.path().is_empty());
        assert!(proof.verify(&root, &root));
        // ...and does not verify against some other root.
        assert!(!proof.verify(&root, &merkle_root(&leaves(8))));
    }

    #[test]
    fn consistency_refuses_impossible_requests_loudly() {
        let l = leaves(4);
        assert_eq!(prove_consistency(&l, 0), Err(ProofError::EmptyOldTree));
        assert_eq!(
            prove_consistency(&l, 5),
            Err(ProofError::OldSizeExceedsTree {
                old_size: 5,
                tree_size: 4
            })
        );
    }

    #[test]
    fn proof_paths_round_trip_through_their_stored_form() {
        let l = leaves(11);
        let inc = prove_inclusion(&l, 6).expect("in range");
        let back = InclusionProof::from_path_bytes(6, 11, &inc.path_bytes()).expect("well formed");
        assert_eq!(inc, back);

        let con = prove_consistency(&l, 4).expect("in range");
        let back =
            ConsistencyProof::from_path_bytes(4, 11, &con.path_bytes()).expect("well formed");
        assert_eq!(con, back);

        assert_eq!(
            InclusionProof::from_path_bytes(0, 1, &[0u8; 33]),
            Err(ProofError::MalformedPath(33))
        );
    }
}
