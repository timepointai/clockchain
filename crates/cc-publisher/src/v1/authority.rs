//! Offline v1 authority events: `Delegate` and `Revoke` (the Stage (b)
//! payloads), signed with a key that holds an active grant on the subject.
//!
//! What may be signed is decided from a grants file, the JSON `v1 grants`
//! reads from a node and writes with `--out`. The file is the only input from
//! the node; signing itself is offline. Before anything is signed:
//!
//! - the key must hold exactly one active grant on the subject (it never signs
//!   under a grant it does not hold, `authority.root_grant`/`delegate_key`);
//! - a Delegate's grantee must be a valid Ed25519 key that holds no grant on
//!   the subject, active or not (`authority.delegate_key=fresh_in_parent_cone`);
//! - a Revoke's target must be an active grant that is a strict issuer
//!   descendant of the signing grant, or the root grant itself when the root
//!   relinquishes explicitly (`authority.revoke_scope`), and its cascade flag
//!   is always an explicit choice (`authority.cascade=signed_bool_target_subtree`).
//!
//! `submit` re-checks all of this against the node before anything is written,
//! and the node's own admission is the final word. Usage: `docs/KEYS.md`.
use super::genesis::{evidence_set, read_capped, validate_key_field, write_new};
use super::hex32;
use super::node::Health;
use anyhow::{anyhow, bail, ensure, Context as _, Result};
use cc_core::v1::rule::fold_v1;
use cc_core::v1::{
    hash, root_grant, Decision, Envelope, Hash, Kind, Payload, Set, Signed, SubjectKey, Value,
    MAX_ENVELOPE,
};
use cc_core::SecretKey;
use serde_json::{json, Value as Json};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

pub const GRANTS_SCHEMA: &str = "cc.publisher.v1.grants";
pub const PREVIEW_SCHEMA: &str = "cc.publisher.v1.authority-preview";
/// Largest grants file read back.
pub const MAX_GRANTS_FILE: usize = 16 * 1024 * 1024;
pub use super::genesis::{ENVELOPE_FILE, PREVIEW_FILE};

/// A grant's state in the node's authority view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStatus {
    Active,
    /// Covered by an effective revoke.
    Tombstoned,
    /// Issued concurrently with an effective revoke of its issuer.
    Canceled,
}
impl GrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Tombstoned => "tombstoned",
            Self::Canceled => "canceled",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "active" => Self::Active,
            "tombstoned" => Self::Tombstoned,
            "canceled" => Self::Canceled,
            other => bail!("unknown grant status {other:?}"),
        })
    }
}

/// One grant on the subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRow {
    /// The grant id: the root grant hash, or the Delegate's event id.
    pub grant: Hash,
    pub status: GrantStatus,
    pub holder: Hash,
    /// `None` for the root grant.
    pub issuer: Option<Hash>,
    pub issued_by_event: Hash,
    /// Issuer chain from the root grant down to and including this grant.
    pub lineage: Vec<Hash>,
}

/// One retained event of the subject, as the node projects it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    pub event: Hash,
    /// `genesis`, `correction`, `delegate`, `revoke` or `resolve`.
    pub kind: String,
    pub author: Hash,
    pub grant: Option<Hash>,
    pub parents: Vec<Hash>,
    /// Projection state: head, superseded, branch, pending or invalid.
    pub state: String,
    /// Admission refusal or authority suppression reason; empty when eligible.
    pub reason: String,
}

/// A subject's authority as one node served it: the grants file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub node: String,
    pub health: Health,
    pub corpus_digest: Hash,
    pub commitment: Hash,
    pub subject: Hash,
    pub subject_key: SubjectKey,
    /// resolved, contested or no_current_body.
    pub state: String,
    /// No surviving authority on the subject.
    pub frozen: bool,
    pub frontier: Vec<Hash>,
    /// Holder of the root grant: the Genesis author.
    pub root_holder: Hash,
    /// Root first, then by depth and id.
    pub grants: Vec<GrantRow>,
    /// Sorted by event id (display order only).
    pub events: Vec<EventRow>,
}

pub fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Genesis => "genesis",
        Kind::Correction => "correction",
        Kind::Delegate => "delegate",
        Kind::Revoke => "revoke",
        Kind::Resolve => "resolve",
        Kind::EdgeAssert => "edge_assert",
        Kind::EdgeReaffirm => "edge_reaffirm",
        Kind::Attestation => "attestation",
    }
}

fn hexes(v: &[Hash]) -> Vec<String> {
    v.iter().map(hex::encode).collect()
}
fn field<'a>(v: &'a Json, k: &str) -> Result<&'a Json> {
    v.get(k).with_context(|| format!("missing field {k:?}"))
}
fn h32(v: &Json, k: &str) -> Result<Hash> {
    field(v, k)?
        .as_str()
        .and_then(hex32)
        .with_context(|| format!("field {k:?} must be 64 hex characters"))
}
fn opt_h32(v: &Json, k: &str) -> Result<Option<Hash>> {
    match field(v, k)? {
        Json::Null => Ok(None),
        _ => h32(v, k).map(Some),
    }
}
fn h32_list(v: &Json, k: &str) -> Result<Vec<Hash>> {
    field(v, k)?
        .as_array()
        .with_context(|| format!("field {k:?} must be a list"))?
        .iter()
        .map(|x| {
            x.as_str()
                .and_then(hex32)
                .with_context(|| format!("{k:?} entries must be 64 hex characters"))
        })
        .collect()
}
fn string(v: &Json, k: &str) -> Result<String> {
    field(v, k)?
        .as_str()
        .map(str::to_owned)
        .with_context(|| format!("field {k:?} must be a string"))
}

impl Context {
    pub fn grant(&self, id: Hash) -> Option<&GrantRow> {
        self.grants.iter().find(|g| g.grant == id)
    }
    pub fn event(&self, id: Hash) -> Option<&EventRow> {
        self.events.iter().find(|e| e.event == id)
    }
    pub fn root_grant(&self) -> Hash {
        root_grant(self.subject)
    }
    /// Active grants whose lineage strictly contains `grant`.
    pub fn descendants(&self, grant: Hash) -> Vec<&GrantRow> {
        self.grants
            .iter()
            .filter(|g| g.grant != grant && g.lineage.contains(&grant))
            .collect()
    }
    /// Reflexive causal past of `event` among this subject's events.
    pub fn past(&self, event: Hash) -> Vec<Hash> {
        let mut seen = Vec::new();
        let mut todo = vec![event];
        while let Some(id) = todo.pop() {
            if seen.contains(&id) {
                continue;
            }
            seen.push(id);
            if let Some(e) = self.event(id) {
                todo.extend(e.parents.iter().copied());
            }
        }
        seen.sort();
        seen
    }
    /// The sole current head, which a new Delegate or Revoke extends.
    pub fn sole_head(&self) -> Result<Hash> {
        ensure!(
            !self.frozen,
            "subject {} is frozen: no grant on it survives",
            hex::encode(self.subject)
        );
        match self.frontier.as_slice() {
            [head] => Ok(*head),
            [] => bail!("subject {} has no current head", hex::encode(self.subject)),
            heads => bail!(
                "subject {} has {} heads ({}); it needs a Resolve before an authority event",
                hex::encode(self.subject),
                heads.len(),
                hexes(heads).join(", ")
            ),
        }
    }
    /// The one active grant `author` holds on this subject.
    pub fn signing_grant(&self, author: Hash) -> Result<&GrantRow> {
        let held: Vec<_> = self.grants.iter().filter(|g| g.holder == author).collect();
        let active: Vec<_> = held
            .iter()
            .filter(|g| g.status == GrantStatus::Active)
            .collect();
        match active.as_slice() {
            [g] => Ok(g),
            [] => match held.first() {
                Some(g) => bail!(
                    "refusing to sign: key {} held grant {} on subject {}, but it is {}",
                    hex::encode(author),
                    hex::encode(g.grant),
                    hex::encode(self.subject),
                    g.status.as_str()
                ),
                None => bail!(
                    "refusing to sign: key {} holds no grant on subject {}",
                    hex::encode(author),
                    hex::encode(self.subject)
                ),
            },
            many => bail!(
                "refusing to sign: key {} holds {} active grants on subject {}",
                hex::encode(author),
                many.len(),
                hex::encode(self.subject)
            ),
        }
    }

    /// The grants file: JSON with lowercase hex throughout.
    pub fn to_json(&self) -> Json {
        json!({
            "schema": GRANTS_SCHEMA,
            "node": self.node,
            "node_health": self.health.to_json(),
            "corpus_digest": hex::encode(self.corpus_digest),
            "commitment": hex::encode(self.commitment),
            "subject": hex::encode(self.subject),
            "subject_key": {
                "kind": self.subject_key.kind,
                "namespace": self.subject_key.namespace,
                "value": self.subject_key.value,
            },
            "subject_state": self.state,
            "frozen": self.frozen,
            "frontier": hexes(&self.frontier),
            "root": {
                "grant": hex::encode(self.root_grant()),
                "holder": hex::encode(self.root_holder),
                "holder_is_curator": self.health.curators.contains(&self.root_holder),
            },
            "active": self.grants.iter()
                .filter(|g| g.status == GrantStatus::Active)
                .map(|g| hex::encode(g.grant))
                .collect::<Vec<_>>(),
            "grants": self.grants.iter().map(|g| json!({
                "grant": hex::encode(g.grant),
                "status": g.status.as_str(),
                "holder": hex::encode(g.holder),
                "issuer": g.issuer.map(hex::encode),
                "issued_by_event": hex::encode(g.issued_by_event),
                "depth": g.lineage.len() - 1,
                "lineage": hexes(&g.lineage),
            })).collect::<Vec<_>>(),
            "events": self.events.iter().map(|e| json!({
                "event": hex::encode(e.event),
                "kind": e.kind,
                "author": hex::encode(e.author),
                "grant": e.grant.map(hex::encode),
                "parents": hexes(&e.parents),
                "state": e.state,
                "reason": e.reason,
            })).collect::<Vec<_>>(),
        })
    }

    /// Parse a grants file and check that it is internally consistent and was
    /// read from a node running this build's fold.
    pub fn from_json(v: &Json) -> Result<Self> {
        ensure!(
            v.get("schema").and_then(Json::as_str) == Some(GRANTS_SCHEMA),
            "not a {GRANTS_SCHEMA} file"
        );
        let health = Health::parse(field(v, "node_health")?)?;
        ensure!(
            health.fold_matches(),
            "grants file was read from a node with fold_version {}/{}, not this build's {}/{}",
            health.fold.version,
            hex::encode(health.fold.manifest),
            fold_v1().version,
            hex::encode(fold_v1().manifest)
        );
        let key = field(v, "subject_key")?;
        let root = field(v, "root")?;
        let grants = field(v, "grants")?
            .as_array()
            .context("field \"grants\" must be a list")?
            .iter()
            .map(|g| {
                Ok(GrantRow {
                    grant: h32(g, "grant")?,
                    status: GrantStatus::parse(&string(g, "status")?)?,
                    holder: h32(g, "holder")?,
                    issuer: opt_h32(g, "issuer")?,
                    issued_by_event: h32(g, "issued_by_event")?,
                    lineage: h32_list(g, "lineage")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let events = field(v, "events")?
            .as_array()
            .context("field \"events\" must be a list")?
            .iter()
            .map(|e| {
                Ok(EventRow {
                    event: h32(e, "event")?,
                    kind: string(e, "kind")?,
                    author: h32(e, "author")?,
                    grant: opt_h32(e, "grant")?,
                    parents: h32_list(e, "parents")?,
                    state: string(e, "state")?,
                    reason: string(e, "reason")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let ctx = Self {
            node: string(v, "node")?,
            health,
            corpus_digest: h32(v, "corpus_digest")?,
            commitment: h32(v, "commitment")?,
            subject: h32(v, "subject")?,
            subject_key: SubjectKey {
                kind: string(key, "kind")?,
                namespace: string(key, "namespace")?,
                value: string(key, "value")?,
            },
            state: string(v, "subject_state")?,
            frozen: field(v, "frozen")?
                .as_bool()
                .context("field \"frozen\" must be a boolean")?,
            frontier: h32_list(v, "frontier")?,
            root_holder: h32(root, "holder")?,
            grants,
            events,
        };
        ensure!(
            h32(root, "grant")? == ctx.root_grant(),
            "root grant is not sha256(cc.root-grant.v1|subject)"
        );
        ensure!(
            h32_list(v, "active")?
                == ctx
                    .grants
                    .iter()
                    .filter(|g| g.status == GrantStatus::Active)
                    .map(|g| g.grant)
                    .collect::<Vec<_>>(),
            "\"active\" does not list exactly the grants whose status is active"
        );
        ctx.check()?;
        Ok(ctx)
    }

    /// Lineages follow issuer links down from the root grant, and every
    /// frontier member is a known event.
    pub fn check(&self) -> Result<()> {
        let root = self
            .grant(self.root_grant())
            .context("the subject's root grant is not listed")?;
        ensure!(
            root.issuer.is_none()
                && root.holder == self.root_holder
                && root.issued_by_event == self.subject
                && root.lineage == [root.grant],
            "root grant entry is inconsistent"
        );
        for g in &self.grants {
            let Some(issuer) = g.issuer else {
                ensure!(g.grant == root.grant, "a second root grant is listed");
                continue;
            };
            ensure!(
                g.grant == g.issued_by_event,
                "delegated grant {} is not its Delegate event id",
                hex::encode(g.grant)
            );
            let parent = self
                .grant(issuer)
                .with_context(|| format!("issuer {} is not listed", hex::encode(issuer)))?;
            let mut expect = parent.lineage.clone();
            expect.push(g.grant);
            ensure!(
                g.lineage == expect,
                "grant {} lineage does not follow its issuer",
                hex::encode(g.grant)
            );
        }
        for f in &self.frontier {
            ensure!(
                self.event(*f).is_some(),
                "frontier event {} is not listed",
                hex::encode(f)
            );
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = read_capped(path, MAX_GRANTS_FILE)?;
        let v: Json = serde_json::from_slice(&raw)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        Self::from_json(&v).with_context(|| format!("grants file {}", path.display()))
    }
}

/// A rationale: what `genesis` allows for a subject-key field (nonempty, at
/// most 1024 bytes, no control or invisible characters, no outer whitespace).
pub fn validate_rationale(s: &str) -> Result<()> {
    validate_key_field("rationale", s)
}

fn decision(kind: Kind, rationale: &str, evidence: Vec<Hash>, parent: Hash) -> Result<Decision> {
    validate_rationale(rationale)?;
    ensure!(
        !evidence.is_empty(),
        "at least one --evidence hash is required"
    );
    Ok(Decision {
        kind,
        rationale: rationale.to_owned(),
        evidence: evidence_set(evidence)?,
        parents: Set(vec![parent]),
        old: Value::None,
        new: Value::None,
    })
}

fn header(ctx: &Context, grant: Hash, parent: Hash, payload: Payload) -> Envelope {
    Envelope {
        instance: ctx.health.instance,
        author: [0; 32],
        subject: Some(ctx.subject),
        subject_key: Some(ctx.subject_key.clone()),
        grant: Some(grant),
        parents: Set(vec![parent]),
        // Authority events never edit asserted time.
        asserted_time: None,
        payload,
    }
}

fn sign(key: &SecretKey, envelope: Envelope) -> Result<AuthorityEvent> {
    let signed = Signed::sign(key, envelope).map_err(|e| anyhow!("v1 encoding: {e}"))?;
    AuthorityEvent::from_signed(signed)
}

/// Sign a Delegate from the key's grant to `grantee`, on the sole head.
pub fn delegate(
    key: &SecretKey,
    ctx: &Context,
    grantee: Hash,
    rationale: &str,
    evidence: Vec<Hash>,
) -> Result<AuthorityEvent> {
    let author = key.author().to_bytes();
    let issuer = ctx.signing_grant(author)?.grant;
    let parent = ctx.sole_head()?;
    ensure!(
        cc_core::AuthorKey::from_bytes(&grantee).is_ok(),
        "--grantee {} is not a valid Ed25519 public key",
        hex::encode(grantee)
    );
    if let Some(g) = ctx.grants.iter().find(|g| g.holder == grantee) {
        bail!(
            "--grantee {} already held grant {} ({}) on this subject; a delegate key must be fresh",
            hex::encode(grantee),
            hex::encode(g.grant),
            g.status.as_str()
        );
    }
    let mut d = decision(Kind::Delegate, rationale, evidence, parent)?;
    d.new = Value::Grant { issuer, grantee };
    sign(
        key,
        header(
            ctx,
            issuer,
            parent,
            Payload::Delegate {
                grantee,
                issuer,
                decision: d,
            },
        ),
    )
}

/// What a Revoke may target, decided before signing.
#[derive(Clone, Copy, Debug)]
pub struct RevokeChoice {
    pub target: Hash,
    /// Signed as-is; there is no default.
    pub cascade: bool,
    /// Required to revoke the root grant with the root key (irreversible).
    pub relinquish_root: bool,
    /// Defaults to the sole head. An earlier event of the subject leaves
    /// acts by covered grants after it outside the revoke's past.
    pub parent: Option<Hash>,
}

/// `authority.revoke_scope=strict_issuer_descendant_or_root_self`: `target`
/// is a strict issuer descendant of `signer`, or both are the root grant.
pub fn in_scope(ctx: &Context, signer: Hash, target: Hash) -> bool {
    match ctx.grant(target) {
        None => false,
        Some(t) if signer == target => t.issuer.is_none(),
        Some(t) => t.lineage[..t.lineage.len() - 1].contains(&signer),
    }
}

/// Sign a Revoke with the key's grant, after the scope and cascade checks.
pub fn revoke(
    key: &SecretKey,
    ctx: &Context,
    choice: RevokeChoice,
    rationale: &str,
    evidence: Vec<Hash>,
) -> Result<AuthorityEvent> {
    let author = key.author().to_bytes();
    let signer = ctx.signing_grant(author)?.grant;
    let target = ctx.grant(choice.target).with_context(|| {
        format!(
            "--target {} is not a grant on subject {}",
            hex::encode(choice.target),
            hex::encode(ctx.subject)
        )
    })?;
    ensure!(
        target.status == GrantStatus::Active,
        "--target {} is {}, not active",
        hex::encode(target.grant),
        target.status.as_str()
    );
    ensure!(
        in_scope(ctx, signer, target.grant),
        "refusing to sign: --target {} is not a strict issuer descendant of this key's grant {} \
         (authority.revoke_scope=strict_issuer_descendant_or_root_self)",
        hex::encode(target.grant),
        hex::encode(signer)
    );
    let relinquishing = target.grant == signer;
    ensure!(
        relinquishing == choice.relinquish_root,
        "{}",
        if relinquishing {
            "revoking the root grant with the root key relinquishes the subject for good; \
             pass --relinquish-root to sign it"
        } else {
            "--relinquish-root applies only when the root key revokes the root grant"
        }
    );
    let parent = match choice.parent {
        None => ctx.sole_head()?,
        Some(p) => {
            ensure!(!ctx.frozen, "subject is frozen: no grant on it survives");
            let e = ctx.event(p).with_context(|| {
                format!(
                    "--parent {} is not an event of this subject",
                    hex::encode(p)
                )
            })?;
            ensure!(
                matches!(e.state.as_str(), "head" | "superseded" | "branch"),
                "--parent {} is {} ({}), not a valid subject event",
                hex::encode(p),
                e.state,
                e.reason
            );
            p
        }
    };
    let mut d = decision(Kind::Revoke, rationale, evidence, parent)?;
    d.old = Value::ActiveGrant(target.grant);
    d.new = Value::RevokedGrant {
        grant: target.grant,
        cascade: choice.cascade,
    };
    sign(
        key,
        header(
            ctx,
            signer,
            parent,
            Payload::Revoke {
                target: target.grant,
                cascade: choice.cascade,
                decision: d,
            },
        ),
    )
}

/// The operation a signed authority event performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Delegate { grantee: Hash, issuer: Hash },
    Revoke { target: Hash, cascade: bool },
}

/// A signed Delegate or Revoke that passed the structural checks the node's
/// admission applies without the parent chain.
#[derive(Clone, Debug)]
pub struct AuthorityEvent {
    pub signed: Signed,
}
impl AuthorityEvent {
    /// Header and decision checks: a single parent, the subject header, no
    /// asserted time, and a decision that restates the payload exactly.
    pub fn from_signed(signed: Signed) -> Result<Self> {
        let ev = Self { signed };
        let e = ev.signed.envelope();
        ensure!(
            matches!(e.payload.kind(), Kind::Delegate | Kind::Revoke),
            "envelope is a {}, not a delegate or revoke",
            kind_name(e.payload.kind())
        );
        ensure!(
            e.subject.is_some() && e.subject_key.is_some() && e.grant.is_some(),
            "authority event lacks its subject, subject key or grant header"
        );
        ensure!(
            e.parents.0.len() == 1,
            "authority event needs exactly one parent"
        );
        ensure!(
            e.asserted_time.is_none(),
            "authority events never carry an asserted time"
        );
        let d = e
            .payload
            .decision()
            .context("authority event lacks its decision")?;
        ensure!(
            d.kind == e.payload.kind() && d.parents == e.parents && !d.evidence.0.is_empty(),
            "decision kind, parents or evidence do not match the envelope"
        );
        validate_rationale(&d.rationale)?;
        match ev.operation() {
            Operation::Delegate { grantee, issuer } => {
                ensure!(
                    Some(issuer) == e.grant,
                    "Delegate issuer is not the signing grant"
                );
                ensure!(
                    cc_core::AuthorKey::from_bytes(&grantee).is_ok(),
                    "Delegate grantee is not a valid Ed25519 public key"
                );
                ensure!(grantee != e.author, "a key cannot delegate to itself");
                ensure!(
                    d.old == Value::None && d.new == (Value::Grant { issuer, grantee }),
                    "Delegate decision does not restate the grant"
                );
            }
            Operation::Revoke { target, cascade } => ensure!(
                d.old == Value::ActiveGrant(target)
                    && d.new
                        == (Value::RevokedGrant {
                            grant: target,
                            cascade,
                        }),
                "Revoke decision does not restate the target and cascade flag"
            ),
        }
        Ok(ev)
    }
    pub fn id(&self) -> Hash {
        self.signed.id()
    }
    pub fn envelope(&self) -> &Envelope {
        self.signed.envelope()
    }
    pub fn subject(&self) -> Hash {
        self.envelope().subject.expect("checked in from_signed")
    }
    pub fn grant(&self) -> Hash {
        self.envelope().grant.expect("checked in from_signed")
    }
    pub fn parent(&self) -> Hash {
        self.envelope().parents.0[0]
    }
    pub fn author(&self) -> Hash {
        self.envelope().author
    }
    pub fn instance(&self) -> Hash {
        self.envelope().instance
    }
    pub fn operation(&self) -> Operation {
        match &self.envelope().payload {
            Payload::Delegate {
                grantee, issuer, ..
            } => Operation::Delegate {
                grantee: *grantee,
                issuer: *issuer,
            },
            Payload::Revoke {
                target, cascade, ..
            } => Operation::Revoke {
                target: *target,
                cascade: *cascade,
            },
            _ => unreachable!("checked in from_signed"),
        }
    }
    pub fn kind_name(&self) -> &'static str {
        kind_name(self.envelope().payload.kind())
    }

    /// `preview.json`: a pure function of the envelope bytes.
    pub fn preview(&self) -> Json {
        let e = self.envelope();
        let d = e.payload.decision().expect("checked in from_signed");
        let key = e.subject_key.as_ref().expect("checked in from_signed");
        let op = match self.operation() {
            Operation::Delegate { grantee, issuer } => json!({
                "grantee": hex::encode(grantee),
                "issuer": hex::encode(issuer),
                "new_grant": hex::encode(self.id()),
            }),
            Operation::Revoke { target, cascade } => json!({
                "target": hex::encode(target),
                "cascade": cascade,
                "relinquishes_root": target == self.grant() && target == root_grant(self.subject()),
            }),
        };
        let bytes = self.signed.bytes();
        json!({
            "schema": PREVIEW_SCHEMA,
            "event_kind": self.kind_name(),
            "encoding": "cc.event.v1",
            "canon_version": cc_core::CANON_VERSION,
            "constants_version": cc_core::CONSTANTS_VERSION,
            "instance": hex::encode(self.instance()),
            "event": hex::encode(self.id()),
            "subject": hex::encode(self.subject()),
            "subject_key": {"kind": key.kind, "namespace": key.namespace, "value": key.value},
            "author": hex::encode(self.author()),
            "grant": hex::encode(self.grant()),
            "parent": hex::encode(self.parent()),
            "rationale": d.rationale,
            "evidence": hexes(&d.evidence.0),
            self.kind_name(): op,
            "envelope_sha256": hex::encode(hash(bytes)),
            "envelope_bytes": bytes.len(),
        })
    }

    /// Human review summary printed by `delegate` and `revoke`.
    pub fn summary(&self, ctx: &Context) -> String {
        let mut s = String::new();
        let mut line = |k: &str, v: String| s.push_str(&format!("  {k:<15}{v}\n"));
        line("event kind", self.kind_name().into());
        line("instance", hex::encode(self.instance()));
        line("subject", hex::encode(self.subject()));
        line("signer", hex::encode(self.author()));
        line("signing grant", hex::encode(self.grant()));
        line("parent", hex::encode(self.parent()));
        match self.operation() {
            Operation::Delegate { grantee, .. } => {
                line("grantee", hex::encode(grantee));
                line(
                    "new grant",
                    format!("{} (the event id)", hex::encode(self.id())),
                );
            }
            Operation::Revoke { target, cascade } => {
                line("target", hex::encode(target));
                line("cascade", cascade.to_string());
                let below = ctx.descendants(target);
                let active = below
                    .iter()
                    .filter(|g| g.status == GrantStatus::Active)
                    .count();
                line(
                    "descendants",
                    if cascade {
                        format!("{active} active grant(s) below the target are revoked with it")
                    } else {
                        format!(
                            "{active} active grant(s) below the target in this revoke's past stay active"
                        )
                    },
                );
                if !ctx.frontier.contains(&self.parent()) {
                    let past = ctx.past(self.parent());
                    let outside: Vec<_> = ctx
                        .events
                        .iter()
                        .filter(|e| !past.contains(&e.event))
                        .map(|e| hex::encode(e.event))
                        .collect();
                    line(
                        "outside past",
                        format!(
                            "{} event(s) are not in this revoke's past: {}",
                            outside.len(),
                            outside.join(", ")
                        ),
                    );
                }
            }
        }
        line("event", hex::encode(self.id()));
        let bytes = self.signed.bytes();
        line(
            "envelope",
            format!("{} bytes, sha256 {}", bytes.len(), hex::encode(hash(bytes))),
        );
        line(
            "context",
            format!(
                "grants read from {} at corpus digest {}",
                ctx.node,
                hex::encode(ctx.corpus_digest)
            ),
        );
        s
    }

    /// Write `envelope.bin` and `preview.json` into `dir`, which must be
    /// absent or empty. No existing file is replaced.
    pub fn write_dir(&self, dir: &Path) -> Result<()> {
        if !super::genesis::check_out_dir(dir)? {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("create {}", dir.display()))?;
        }
        let preview = serde_json::to_string_pretty(&self.preview())? + "\n";
        write_new(&dir.join(ENVELOPE_FILE), self.signed.bytes())?;
        write_new(&dir.join(PREVIEW_FILE), preview.as_bytes())?;
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Reload a `delegate` or `revoke` directory: the envelope decodes,
    /// verifies and passes [`AuthorityEvent::from_signed`], and `preview.json`
    /// equals the preview recomputed from it.
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let signed = Signed::decode(&read_capped(&dir.join(ENVELOPE_FILE), MAX_ENVELOPE)?)
            .map_err(|e| anyhow!("{ENVELOPE_FILE}: {e}"))?;
        let ev = Self::from_signed(signed)?;
        let preview: Json =
            serde_json::from_slice(&read_capped(&dir.join(PREVIEW_FILE), MAX_ENVELOPE)?)
                .with_context(|| format!("{PREVIEW_FILE} is not JSON"))?;
        ensure!(
            preview == ev.preview(),
            "{PREVIEW_FILE} does not match {ENVELOPE_FILE}"
        );
        Ok(ev)
    }
}

/// Whether `dir/envelope.bin` decodes as a Delegate or Revoke, which `submit`
/// then handles here rather than as a Genesis.
pub fn is_authority_dir(dir: &Path) -> bool {
    read_capped(&dir.join(ENVELOPE_FILE), MAX_ENVELOPE)
        .ok()
        .and_then(|b| Signed::decode(&b).ok())
        .is_some_and(|s| matches!(s.envelope().payload.kind(), Kind::Delegate | Kind::Revoke))
}
