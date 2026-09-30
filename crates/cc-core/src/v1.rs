//! Strict v1 wire format. No I/O or projection; legacy decoding is never tried.
use crate::{verify, AuthorKey, SecretKey, Signature, CANON_VERSION, CONSTANTS_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];
pub const MAX_ENVELOPE: usize = 1024 * 1024;
pub const MAX_SET: usize = 1024;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct WireError(pub &'static str);
type Result<T> = std::result::Result<T, WireError>;

/// Wire sets must already be strictly sorted. Encoding never silently repairs them.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Set<T>(pub Vec<T>);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubjectKey {
    pub kind: String,
    pub namespace: String,
    pub value: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertedTime {
    pub coordinate: Hash,
    pub precision: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Pin {
    pub subject: Hash,
    pub basis: Hash,
    pub revision: Hash,
    pub body: Hash,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Pins {
    pub source: Pin,
    pub target: Pin,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ParentPins {
    pub parent: Hash,
    pub pins: Pins,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Disposition {
    pub parent: Hash,
    pub action: DispositionKind,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u16)]
pub enum Kind {
    Genesis = 1,
    Correction = 2,
    Delegate = 3,
    Revoke = 4,
    Resolve = 5,
    EdgeAssert = 6,
    EdgeReaffirm = 7,
    Attestation = 8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u16)]
pub enum DispositionKind {
    Selected = 1,
    Merged = 2,
    NotSelected = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum TargetKind {
    Event = 1,
    Revision = 2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    None,
    Body(Hash),
    Grant { issuer: Hash, grantee: Hash },
    ActiveGrant(Hash),
    RevokedGrant { grant: Hash, cascade: bool },
    Heads(Set<Hash>),
    Revision(Hash),
    Pins(Pins),
    ParentPins(Set<ParentPins>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub kind: Kind,
    pub rationale: String,
    pub evidence: Set<Hash>,
    pub parents: Set<Hash>,
    pub old: Value,
    pub new: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Selection {
    Revision(Hash),
    MergedBody(Hash),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    Genesis {
        nonce: Hash,
        body: Hash,
        evidence: Set<Hash>,
    },
    Correction {
        body: Hash,
        decision: Decision,
    },
    Delegate {
        grantee: Hash,
        issuer: Hash,
        decision: Decision,
    },
    Revoke {
        target: Hash,
        cascade: bool,
        decision: Decision,
    },
    Resolve {
        selection: Selection,
        dispositions: Set<Disposition>,
        decision: Decision,
    },
    EdgeAssert {
        relation: String,
        pins: Pins,
        decision: Decision,
    },
    EdgeReaffirm {
        edge: Hash,
        old: Set<ParentPins>,
        new: Pins,
        decision: Decision,
    },
    Attestation {
        target_kind: TargetKind,
        target: Hash,
        artifact_kind: String,
        artifact: Hash,
    },
}
impl Payload {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Genesis { .. } => Kind::Genesis,
            Self::Correction { .. } => Kind::Correction,
            Self::Delegate { .. } => Kind::Delegate,
            Self::Revoke { .. } => Kind::Revoke,
            Self::Resolve { .. } => Kind::Resolve,
            Self::EdgeAssert { .. } => Kind::EdgeAssert,
            Self::EdgeReaffirm { .. } => Kind::EdgeReaffirm,
            Self::Attestation { .. } => Kind::Attestation,
        }
    }
    pub fn decision(&self) -> Option<&Decision> {
        match self {
            Self::Correction { decision, .. }
            | Self::Delegate { decision, .. }
            | Self::Revoke { decision, .. }
            | Self::Resolve { decision, .. }
            | Self::EdgeAssert { decision, .. }
            | Self::EdgeReaffirm { decision, .. } => Some(decision),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub instance: Hash,
    pub author: Hash,
    pub subject: Option<Hash>,
    pub subject_key: Option<SubjectKey>,
    pub grant: Option<Hash>,
    pub parents: Set<Hash>,
    pub asserted_time: Option<AssertedTime>,
    pub payload: Payload,
}

pub fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}
pub fn root_grant(genesis: Hash) -> Hash {
    domain_hash("cc.root-grant.v1", &[genesis])
}
pub fn revision_id(subject: Hash, creating_event: Hash) -> Hash {
    domain_hash("cc.revision.v1", &[subject, creating_event])
}
fn domain_hash(domain: &str, ids: &[Hash]) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    bytes.extend_from_slice(domain.as_bytes());
    for id in ids {
        bytes.extend_from_slice(id);
    }
    hash(&bytes)
}

impl Envelope {
    pub fn preimage(&self) -> Result<Vec<u8>> {
        if let Some(key) = &self.subject_key {
            if [&key.kind, &key.namespace, &key.value]
                .iter()
                .any(|s| s.is_empty() || s.len() > 1024)
            {
                return Err(WireError("subject_key_encoding"));
            }
        }
        let mut w = Writer(Vec::new());
        "cc.event.v1".to_owned().put(&mut w)?;
        CANON_VERSION.put(&mut w)?;
        CONSTANTS_VERSION.put(&mut w)?;
        self.instance.put(&mut w)?;
        self.payload.kind().put(&mut w)?;
        self.author.put(&mut w)?;
        self.subject.put(&mut w)?;
        self.subject_key.put(&mut w)?;
        self.grant.put(&mut w)?;
        self.parents.put(&mut w)?;
        self.asserted_time.put(&mut w)?;
        self.payload.put_payload(&mut w)?;
        if w.0.len() + 64 > MAX_ENVELOPE {
            return Err(WireError("envelope_too_large"));
        }
        Ok(w.0)
    }
}

/// Only verified, canonical wire bytes can construct this type.
#[derive(Clone, Debug)]
pub struct Signed {
    envelope: Envelope,
    id: Hash,
    bytes: Vec<u8>,
}
impl Signed {
    pub fn sign(key: &SecretKey, mut envelope: Envelope) -> Result<Self> {
        envelope.author = key.author().to_bytes();
        let mut bytes = envelope.preimage()?;
        let sig = key.sign_message(&bytes);
        bytes.extend_from_slice(&sig.to_bytes());
        Self::decode(&bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE {
            return Err(WireError("envelope_too_large"));
        }
        let split = bytes.len().checked_sub(64).ok_or(WireError("truncated"))?;
        let (preimage, signature) = bytes.split_at(split);
        let mut r = Reader(preimage);
        if String::get(&mut r)? != "cc.event.v1" {
            return Err(WireError("unsupported_encoding"));
        }
        if u16::get(&mut r)? != CANON_VERSION {
            return Err(WireError("unsupported_encoding"));
        }
        if u16::get(&mut r)? != CONSTANTS_VERSION {
            return Err(WireError("unsupported_constants"));
        }
        let instance = Hash::get(&mut r)?;
        let kind = Kind::get(&mut r)?;
        let envelope = Envelope {
            instance,
            author: Hash::get(&mut r)?,
            subject: Option::get(&mut r)?,
            subject_key: Option::get(&mut r)?,
            grant: Option::get(&mut r)?,
            parents: Set::get(&mut r)?,
            asserted_time: Option::get(&mut r)?,
            payload: Payload::get_payload(kind, &mut r)?,
        };
        if !r.0.is_empty() || envelope.preimage()? != preimage {
            return Err(WireError("noncanonical"));
        }
        let key =
            AuthorKey::from_bytes(&envelope.author).map_err(|_| WireError("bad_signature"))?;
        verify(
            &key,
            preimage,
            &Signature::from_bytes(signature.try_into().unwrap()),
        )
        .map_err(|_| WireError("bad_signature"))?;
        Ok(Self {
            envelope,
            id: hash(preimage),
            bytes: bytes.to_vec(),
        })
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

struct Writer(Vec<u8>);
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(WireError("truncated"));
        }
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(value)
    }
}
trait Wire: Sized {
    fn put(&self, w: &mut Writer) -> Result<()>;
    fn get(r: &mut Reader<'_>) -> Result<Self>;
}
macro_rules! number {
    ($t:ty,$n:expr) => {
        impl Wire for $t {
            fn put(&self, w: &mut Writer) -> Result<()> {
                w.0.extend_from_slice(&self.to_be_bytes());
                Ok(())
            }
            fn get(r: &mut Reader<'_>) -> Result<Self> {
                Ok(Self::from_be_bytes(r.take($n)?.try_into().unwrap()))
            }
        }
    };
}
number!(u16, 2);
number!(u32, 4);
impl<const N: usize> Wire for [u8; N] {
    fn put(&self, w: &mut Writer) -> Result<()> {
        w.0.extend_from_slice(self);
        Ok(())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self> {
        Ok(r.take(N)?.try_into().unwrap())
    }
}
impl Wire for bool {
    fn put(&self, w: &mut Writer) -> Result<()> {
        w.0.push(u8::from(*self));
        Ok(())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self> {
        match r.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError("noncanonical_bool")),
        }
    }
}
impl Wire for String {
    fn put(&self, w: &mut Writer) -> Result<()> {
        if self.len() > MAX_ENVELOPE {
            return Err(WireError("string_too_large"));
        }
        (self.len() as u32).put(w)?;
        w.0.extend_from_slice(self.as_bytes());
        Ok(())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self> {
        let n = u32::get(r)? as usize;
        String::from_utf8(r.take(n)?.to_vec()).map_err(|_| WireError("invalid_utf8"))
    }
}
impl<T: Wire> Wire for Option<T> {
    fn put(&self, w: &mut Writer) -> Result<()> {
        self.is_some().put(w)?;
        if let Some(v) = self {
            v.put(w)?;
        }
        Ok(())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self> {
        if bool::get(r)? {
            Ok(Some(T::get(r)?))
        } else {
            Ok(None)
        }
    }
}
trait Reference {
    fn reference(&self) -> &Hash;
}
impl Reference for Hash {
    fn reference(&self) -> &Hash {
        self
    }
}
impl Reference for ParentPins {
    fn reference(&self) -> &Hash {
        &self.parent
    }
}
impl Reference for Disposition {
    fn reference(&self) -> &Hash {
        &self.parent
    }
}
impl<T: Wire + Reference> Wire for Set<T> {
    fn put(&self, w: &mut Writer) -> Result<()> {
        if self.0.len() > MAX_SET
            || self
                .0
                .windows(2)
                .any(|p| p[0].reference() >= p[1].reference())
        {
            return Err(WireError("noncanonical_set"));
        }
        (self.0.len() as u32).put(w)?;
        for v in &self.0 {
            v.put(w)?;
        }
        Ok(())
    }
    fn get(r: &mut Reader<'_>) -> Result<Self> {
        let n = u32::get(r)? as usize;
        if n > MAX_SET {
            return Err(WireError("noncanonical_set"));
        }
        let mut values = Vec::new();
        for _ in 0..n {
            values.push(T::get(r)?);
        }
        if values
            .windows(2)
            .any(|p| p[0].reference() >= p[1].reference())
        {
            return Err(WireError("noncanonical_set"));
        }
        Ok(Set(values))
    }
}
macro_rules! record {($t:ident,$($field:ident),+)=>{impl Wire for $t {
    fn put(&self,w:&mut Writer)->Result<()>{$ (self.$field.put(w)?;)+Ok(())}
    fn get(r:&mut Reader<'_>)->Result<Self>{Ok(Self{$($field:Wire::get(r)?,)+})}
}};}
record!(SubjectKey, kind, namespace, value);
record!(AssertedTime, coordinate, precision);
record!(Pin, subject, basis, revision, body);
record!(Pins, source, target);
record!(ParentPins, parent, pins);
record!(Disposition, parent, action, rationale);
record!(Decision, kind, rationale, evidence, parents, old, new);
macro_rules! tags {($t:ident,$($v:ident=$tag:literal),+)=>{impl Wire for $t{
    fn put(&self,w:&mut Writer)->Result<()>{(*self as u16).put(w)}
    fn get(r:&mut Reader<'_>)->Result<Self>{match u16::get(r)?{$($tag=>Ok(Self::$v),)+_=>Err(WireError("unknown_tag"))}}
}};}
tags!(
    Kind,
    Genesis = 1,
    Correction = 2,
    Delegate = 3,
    Revoke = 4,
    Resolve = 5,
    EdgeAssert = 6,
    EdgeReaffirm = 7,
    Attestation = 8
);
tags!(DispositionKind, Selected = 1, Merged = 2, NotSelected = 3);
tags!(TargetKind, Event = 1, Revision = 2);
impl Wire for Value {
    fn put(&self, w: &mut Writer) -> Result<()> {
        match self {
            Self::None => 0u16.put(w),
            Self::Body(v) => {
                1u16.put(w)?;
                v.put(w)
            }
            Self::Grant { issuer, grantee } => {
                2u16.put(w)?;
                issuer.put(w)?;
                grantee.put(w)
            }
            Self::ActiveGrant(v) => {
                3u16.put(w)?;
                v.put(w)
            }
            Self::RevokedGrant { grant, cascade } => {
                4u16.put(w)?;
                grant.put(w)?;
                cascade.put(w)
            }
            Self::Heads(v) => {
                5u16.put(w)?;
                v.put(w)
            }
            Self::Revision(v) => {
                6u16.put(w)?;
                v.put(w)
            }
            Self::Pins(v) => {
                7u16.put(w)?;
                v.put(w)
            }
            Self::ParentPins(v) => {
                8u16.put(w)?;
                v.put(w)
            }
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self> {
        Ok(match u16::get(r)? {
            0 => Self::None,
            1 => Self::Body(Wire::get(r)?),
            2 => Self::Grant {
                issuer: Wire::get(r)?,
                grantee: Wire::get(r)?,
            },
            3 => Self::ActiveGrant(Wire::get(r)?),
            4 => Self::RevokedGrant {
                grant: Wire::get(r)?,
                cascade: Wire::get(r)?,
            },
            5 => Self::Heads(Wire::get(r)?),
            6 => Self::Revision(Wire::get(r)?),
            7 => Self::Pins(Wire::get(r)?),
            8 => Self::ParentPins(Wire::get(r)?),
            _ => return Err(WireError("unknown_value_tag")),
        })
    }
}
impl Wire for Selection {
    fn put(&self, w: &mut Writer) -> Result<()> {
        match self {
            Self::Revision(v) => {
                0u16.put(w)?;
                v.put(w)
            }
            Self::MergedBody(v) => {
                1u16.put(w)?;
                v.put(w)
            }
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self> {
        match u16::get(r)? {
            0 => Ok(Self::Revision(Wire::get(r)?)),
            1 => Ok(Self::MergedBody(Wire::get(r)?)),
            _ => Err(WireError("unknown_selection_tag")),
        }
    }
}
impl Payload {
    fn put_payload(&self, w: &mut Writer) -> Result<()> {
        macro_rules! fields {($($f:ident),+)=>{{$($f.put(w)?;)+}};}
        match self {
            Self::Genesis {
                nonce,
                body,
                evidence,
            } => fields!(nonce, body, evidence),
            Self::Correction { body, decision } => fields!(body, decision),
            Self::Delegate {
                grantee,
                issuer,
                decision,
            } => fields!(grantee, issuer, decision),
            Self::Revoke {
                target,
                cascade,
                decision,
            } => fields!(target, cascade, decision),
            Self::Resolve {
                selection,
                dispositions,
                decision,
            } => fields!(selection, dispositions, decision),
            Self::EdgeAssert {
                relation,
                pins,
                decision,
            } => fields!(relation, pins, decision),
            Self::EdgeReaffirm {
                edge,
                old,
                new,
                decision,
            } => fields!(edge, old, new, decision),
            Self::Attestation {
                target_kind,
                target,
                artifact_kind,
                artifact,
            } => fields!(target_kind, target, artifact_kind, artifact),
        }
        Ok(())
    }
    fn get_payload(k: Kind, r: &mut Reader<'_>) -> Result<Self> {
        Ok(match k {
            Kind::Genesis => Self::Genesis {
                nonce: Wire::get(r)?,
                body: Wire::get(r)?,
                evidence: Wire::get(r)?,
            },
            Kind::Correction => Self::Correction {
                body: Wire::get(r)?,
                decision: Wire::get(r)?,
            },
            Kind::Delegate => Self::Delegate {
                grantee: Wire::get(r)?,
                issuer: Wire::get(r)?,
                decision: Wire::get(r)?,
            },
            Kind::Revoke => Self::Revoke {
                target: Wire::get(r)?,
                cascade: Wire::get(r)?,
                decision: Wire::get(r)?,
            },
            Kind::Resolve => Self::Resolve {
                selection: Wire::get(r)?,
                dispositions: Wire::get(r)?,
                decision: Wire::get(r)?,
            },
            Kind::EdgeAssert => Self::EdgeAssert {
                relation: Wire::get(r)?,
                pins: Wire::get(r)?,
                decision: Wire::get(r)?,
            },
            Kind::EdgeReaffirm => Self::EdgeReaffirm {
                edge: Wire::get(r)?,
                old: Wire::get(r)?,
                new: Wire::get(r)?,
                decision: Wire::get(r)?,
            },
            Kind::Attestation => Self::Attestation {
                target_kind: Wire::get(r)?,
                target: Wire::get(r)?,
                artifact_kind: Wire::get(r)?,
                artifact: Wire::get(r)?,
            },
        })
    }
}

pub mod receipt;
