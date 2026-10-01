//! Stage (e) v1 filter identity. The curator key set is boot-pinned
//! configuration, never a ledger event; changing any field changes identity.
use crate::version::TT_TAXONOMY_SHA256;
use cc_core::v1::{receipt::FoldRef, rule::fold_v1, Hash};
use sha2::{Digest, Sha256};

/// Positive support needs a curator edge author and curator Genesis creators.
pub const TRUST_POLICY: &str = "cc.trust.curator-genesis-creator.v1";

/// Everything a v1 support verdict commits to besides the corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterIdentity {
    /// `(1, SHA256(manifest))`.
    pub fold: FoldRef,
    /// Canonical event encoding version.
    pub encoding: u16,
    /// Coordinate constants version.
    pub constants: u16,
    /// sha256 of the pinned TT taxonomy.
    pub ontology: Hash,
    /// Exact, strictly sorted, nonempty Ed25519 curator keys.
    pub curators: Vec<Hash>,
    /// Named trust policy.
    pub trust_policy: String,
    /// Governed explicit hop bound for undirected support paths.
    pub max_hops: u16,
}
/// A filter identity this build will not construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// Empty, unsorted, duplicated or invalid curator keys.
    #[error("curator_set")]
    CuratorSet,
    /// A zero hop bound.
    #[error("max_hops")]
    MaxHops,
}
impl FilterIdentity {
    /// The identity this build governs, for an operator-supplied curator set.
    pub fn governed(curators: Vec<Hash>, max_hops: u16) -> Result<Self, IdentityError> {
        if curators.is_empty()
            || curators.windows(2).any(|p| p[0] >= p[1])
            || curators
                .iter()
                .any(|k| cc_core::AuthorKey::from_bytes(k).is_err())
        {
            return Err(IdentityError::CuratorSet);
        }
        if max_hops == 0 {
            return Err(IdentityError::MaxHops);
        }
        Ok(Self {
            fold: fold_v1(),
            encoding: cc_core::CANON_VERSION,
            constants: cc_core::CONSTANTS_VERSION,
            ontology: TT_TAXONOMY_SHA256,
            curators,
            trust_policy: TRUST_POLICY.into(),
            max_hops,
        })
    }
    /// True only for an identity this build would construct with
    /// [`FilterIdentity::governed`]: this fold, encoding, constants, ontology
    /// and trust policy, with a valid sorted curator set and nonzero hop bound.
    /// Fields stay public so verifiers can describe foreign identities; a store
    /// binds only governed ones.
    pub fn is_governed(&self) -> bool {
        Self::governed(self.curators.clone(), self.max_hops).as_ref() == Ok(self)
    }
    /// Domain-framed canonical bytes.
    pub fn canonical(&self) -> Vec<u8> {
        let domain = "cc.filter.v1";
        let mut out = (domain.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(domain.as_bytes());
        out.extend_from_slice(&self.fold.version.to_be_bytes());
        out.extend_from_slice(&self.fold.manifest);
        out.extend_from_slice(&self.encoding.to_be_bytes());
        out.extend_from_slice(&self.constants.to_be_bytes());
        out.extend_from_slice(&self.ontology);
        out.extend_from_slice(&(self.curators.len() as u32).to_be_bytes());
        for key in &self.curators {
            out.extend_from_slice(key);
        }
        out.extend_from_slice(&(self.trust_policy.len() as u32).to_be_bytes());
        out.extend_from_slice(self.trust_policy.as_bytes());
        out.extend_from_slice(&self.max_hops.to_be_bytes());
        out
    }
    /// `filter_version = SHA256(canonical)`.
    pub fn version(&self) -> Hash {
        Sha256::digest(self.canonical()).into()
    }
}
