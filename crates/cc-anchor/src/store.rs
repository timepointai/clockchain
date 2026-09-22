//! The ledger side of anchoring: sealing epochs, publishing roots, recording
//! inscriptions.
//!
//! **Why there is a commitment log at all.** A consistency proof only means
//! "nothing was removed" if the leaf order is append-only. `events` is a
//! grow-only *set*, not a sequence: gossip can deliver an event whose `event_id`
//! sorts before every leaf already committed, and a frontier-mined past moment
//! lands in the middle of event-time order. Any order taken at read time
//! therefore renumbers earlier leaves, and every root published before that
//! renumbering becomes unverifiable — including the ones already inscribed into
//! Bitcoin. So the order is frozen once, at seal time, into `commitment_log`,
//! and never moves again (INITIATION-PLAN §5.5).
//!
//! **Why leaves are ordered by `event_id` inside a seal.** The plan assigns the
//! commitment `seq` at the write-path choke point, which makes it arrival order —
//! a local fact. Ordering each seal's new leaves by content address instead makes
//! the root a pure function of the event *set* and the epoch boundaries: two
//! nodes that have seen the same events and seal at the same boundary publish
//! byte-identical roots, with no gossip-order dependence at all. That is strictly
//! stronger than the plan requires for the single-node genesis epoch and costs
//! nothing, because the append-only property the proofs need comes from the log
//! being frozen at seal time, not from *how* a seal orders its own batch.
//! Divergent seal boundaries across replicas still produce divergent root
//! streams — that reconciliation is the Growth-epoch problem the plan defers.
//!
//! **Why a root publication is a signed event.** `roots` and `anchors` are
//! projections, not facts (memo §9). The facts are node-0 moments appended
//! through `cc-ledger`'s single choke point, exactly like any other writer's
//! (§nodezero: "the constitution is a subgraph"). Publishing a root by writing
//! only to the `roots` table would produce a settlement history that vanishes on
//! rebuild and that no replay could reproduce.

use crate::merkle::{
    leaf_hash, merkle_root, prove_consistency, prove_inclusion, ConsistencyProof, InclusionProof,
    LeafHash, MerkleRoot, ProofError,
};
use crate::ots::{self, OtsProof};
use cc_core::{EventBody, EventContent, EventId, MomentBody, SecretKey, Tick};
use cc_ledger::Signed;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};

/// The entity every constitutional moment is about (§nodezero). The ledger's own
/// operational history — root publications, anchor inscriptions — is ordinary
/// moments whose subject is this entity.
pub const NODE_ZERO: i64 = 0;

/// Serializes epoch sealing across processes. Two `anchor-tick` runs overlapping
/// would each seal "everything not yet sealed" and race to insert `seq` values;
/// the loser would abort on the primary key, but only after the winner had
/// already published a root over a leaf set the loser disagreed with. A
/// transaction-scoped advisory lock makes the overlap wait instead.
const SEAL_LOCK: i64 = 0x6363_5f61_6e63_686f; // "cc_ancho"

/// Domain tag for the body hash of a `root_epoch_n` moment.
const DST_ROOT: &[u8] = b"cc.anchor.root.v0";
/// Domain tag for the body hash of an `anchor_epoch_n_*` moment.
const DST_ANCHOR: &[u8] = b"cc.anchor.stamp.v0";

/// Every root row, plus the predecessor's leaf count.
///
/// The join is not decoration: a consistency proof is a claim about *two* tree
/// sizes, and the row only stores one of them. Reading the blob back without its
/// predecessor's size would silently reinterpret the proof as a different claim
/// than the one that was written.
const ROOT_COLUMNS: &str = "SELECT r.root_id, r.height, r.tree_size, r.prev_root, r.consistency, \
                            r.moment_id, p.tree_size AS prev_tree_size \
                            FROM roots r LEFT JOIN roots p ON p.root_id = r.prev_root";

/// Anything that stops the anchoring path.
///
/// There is no "degraded anchor" variant on purpose: an anchor that half-worked
/// would put a settlement bound in the corpus that nothing backs, which is worse
/// than the epoch simply not being anchored yet (memo §3, discipline #3).
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// Postgres said no.
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    /// The write path refused the node-0 moment.
    #[error("ledger: {0}")]
    Ledger(#[from] cc_ledger::LedgerError),
    /// The accumulator was asked for a proof it cannot honestly give.
    #[error("proof: {0}")]
    Proof(#[from] ProofError),
    /// The OpenTimestamps side failed.
    #[error("opentimestamps: {0}")]
    Ots(#[from] ots::OtsError),
    /// Leaves are committed but the root stream is gone — the state a
    /// `cc-ledger::rebuild` leaves behind, since it TRUNCATEs the `roots`
    /// projection while `commitment_log` (not a projection) survives. Publishing
    /// a fresh "genesis" root over an already-committed log would silently orphan
    /// every anchor ever made, so this refuses instead. Recovery is to re-derive
    /// `roots` from the node-0 root moments still in `events`.
    #[error("{leaves} leaves are committed but no root is published: re-derive the root stream from its node-0 moments before sealing another epoch")]
    RootStreamLost {
        /// How many leaves are already frozen in the commitment log.
        leaves: i64,
    },
    /// A root no `roots` row knows about.
    #[error("no published root {0}")]
    UnknownRoot(String),
    /// An event no epoch has sealed yet, so no root commits to it. Distinct from
    /// "the event does not exist" (memo §5: absent evidence is its own answer).
    #[error("event {0} is not in the commitment log: no root commits to it yet")]
    NotCommitted(String),
    /// The commitment log has a hole in it, which means something appended
    /// outside this module. Every root published since is suspect.
    #[error("commitment log is corrupt: position {expected} holds seq {found}")]
    LogCorrupt {
        /// The position walked to.
        expected: i64,
        /// The `seq` actually stored there.
        found: i64,
    },
    /// A stored hash is not 32 bytes. The width CHECKs make this unreachable
    /// from SQL, so reaching it means the column was written by something that
    /// bypassed them.
    #[error("stored hash is {0} bytes, not 32")]
    BadHashWidth(usize),
    /// A published root does not match what its own leaves hash to.
    #[error("root at height {height} is {recorded}, but its leaves hash to {recomputed}")]
    RootMismatch {
        /// Epoch of the root that failed.
        height: i64,
        /// What the row claims.
        recorded: String,
        /// What the log produces.
        recomputed: String,
    },
    /// A published root does not extend its predecessor — the one thing the whole
    /// consistency machinery exists to detect.
    #[error("the root at height {height} does not extend the root at height {}", height - 1)]
    ConsistencyBroken {
        /// Epoch of the root that failed to extend its predecessor.
        height: i64,
    },
    /// An anchor operation that the anchor's current state does not allow.
    #[error("anchor state for {root}: {detail}")]
    AnchorState {
        /// The root or blob the operation was about.
        root: String,
        /// Why it was refused.
        detail: &'static str,
    },
}

// ===========================================================================
// Root publication
// ===========================================================================

/// A published root and everything a mirror needs to check it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RootPublication {
    /// Epoch index in the root stream; 0 is the genesis root.
    pub height: u64,
    /// The Merkle Tree Hash over the first `tree_size` leaves.
    pub root: MerkleRoot,
    /// Number of leaves committed. This — not the mutable `ledger_stats` row —
    /// is what a restore is verified against (M6).
    pub tree_size: u64,
    /// The root this one extends. `None` only at height 0.
    pub prev_root: Option<MerkleRoot>,
    /// Proof that this root extends `prev_root`. `None` only at height 0.
    pub consistency: Option<ConsistencyProof>,
    /// The node-0 moment that recorded the publication. `None` means the row
    /// exists but its recording moment did not land — a state worth surfacing
    /// rather than hiding, because such a root is not yet settled history.
    pub moment: Option<EventId>,
}

/// What an anchor tick did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RootOutcome {
    /// New leaves were sealed and a new root published.
    Published(RootPublication),
    /// No event arrived since the last root, so the log did not grow.
    /// Republishing the same root would claim progress that did not happen, and
    /// it is not an error either — a quiet epoch is a normal state for a cron
    /// (memo §5: empty is not failure).
    Unchanged {
        /// The root that still stands.
        root: MerkleRoot,
        /// Its epoch.
        height: u64,
    },
}

/// Seal every event not yet committed, publish the root over the whole log, and
/// record the publication as a node-0 moment.
///
/// `now` is supplied by the caller rather than read from a clock here, for the
/// same reason `cc-core` reads no clock: a coordinate that lands in a signed
/// payload must come from the one place in the process that owns the mapping
/// from wall time to `Tick`, not from whichever library happened to need it.
///
/// The recording moment is appended *after* the seal, so it is committed by the
/// next epoch's root rather than by the one it describes — "the root of snapshot
/// n, recorded as a node-0 moment inside snapshot n+1" (§nodezero). A root that
/// had to include the moment announcing itself could not be computed at all.
///
/// One consequence, surprising on first reading and load-bearing on second: once
/// the stream is running, [`RootOutcome::Unchanged`] stops being reachable. Every
/// publication appends its own recording moment, so the next tick always has at
/// least that one leaf to seal. The root stream therefore beats at the cron's
/// cadence whether or not a user wrote anything — and that heartbeat *is* the
/// mechanism that turns the consistency chain into settled history instead of a
/// proof bolted on beside the ledger. `Unchanged` remains the honest answer for a
/// ledger where nothing has ever been written.
pub async fn publish_root(
    pool: &PgPool,
    key: &SecretKey,
    now: Tick,
) -> Result<RootOutcome, AnchorError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(SEAL_LOCK)
        .execute(&mut *tx)
        .await?;

    let prev = latest_root_tx(&mut tx).await?;
    let row = sqlx::query(
        "SELECT COALESCE(MAX(seq) + 1, 0) AS next_seq, count(*) AS n FROM commitment_log",
    )
    .fetch_one(&mut *tx)
    .await?;
    let next_seq: i64 = row.try_get("next_seq")?;
    let committed: i64 = row.try_get("n")?;
    if next_seq != committed {
        return Err(AnchorError::LogCorrupt {
            expected: committed,
            found: next_seq - 1,
        });
    }
    if prev.is_none() && committed > 0 {
        return Err(AnchorError::RootStreamLost { leaves: committed });
    }

    let height = prev.as_ref().map_or(0, |p| p.height + 1);
    let added = sqlx::query(
        "INSERT INTO commitment_log (seq, event_id, epoch) \
         SELECT $1::bigint + row_number() OVER (ORDER BY e.event_id) - 1, e.event_id, $2::bigint \
         FROM events e \
         WHERE NOT EXISTS (SELECT 1 FROM commitment_log c WHERE c.event_id = e.event_id)",
    )
    .bind(next_seq)
    .bind(height as i64)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if added == 0 {
        return Ok(match prev {
            Some(p) => RootOutcome::Unchanged {
                root: p.root,
                height: p.height,
            },
            // Nothing has ever been written. Not an error: the ledger is empty,
            // and the empty tree is not worth a root row.
            None => RootOutcome::Unchanged {
                root: merkle_root(&[]),
                height: 0,
            },
        });
    }

    let leaves = load_leaves_tx(&mut tx).await?;
    let root = merkle_root(&leaves);
    let consistency = match prev.as_ref() {
        Some(p) => Some(prove_consistency(&leaves, p.tree_size)?),
        None => None,
    };

    sqlx::query(
        "INSERT INTO roots (root_id, height, tree_size, prev_root, consistency) \
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(root.as_bytes().to_vec())
    .bind(height as i64)
    .bind(leaves.len() as i64)
    .bind(prev.as_ref().map(|p| p.root.as_bytes().to_vec()))
    .bind(consistency.as_ref().map(|c| c.path_bytes()))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let mut published = RootPublication {
        height,
        root,
        tree_size: leaves.len() as u64,
        prev_root: prev.as_ref().map(|p| p.root),
        consistency,
        moment: None,
    };
    published.moment = Some(record_root_moment(pool, key, &published, now).await?);
    Ok(RootOutcome::Published(published))
}

/// Append the node-0 moment that records a root publication, and point the
/// projection row at it.
///
/// Separate from [`publish_root`] so a tick that seals successfully but dies
/// before recording can be resumed without re-sealing — the leaf order is already
/// frozen, and re-running a seal is the one thing that must never happen.
pub async fn record_root_moment(
    pool: &PgPool,
    key: &SecretKey,
    published: &RootPublication,
    now: Tick,
) -> Result<EventId, AnchorError> {
    let content = EventContent {
        // A publication is an event about the present: the root is a fact as of
        // the moment it is taken, so event_time == record_time and the posture is
        // `present` rather than a mined past.
        event_time: now,
        record_time: now,
        author: key.author(),
        supersedes: None,
        body: EventBody::Moment(MomentBody {
            subject: NODE_ZERO,
            body_hash: root_body_hash(published),
        }),
    };
    let signed = Signed::sign(key, content);
    cc_ledger::commit(pool, &signed).await?;
    sqlx::query("UPDATE roots SET moment_id = $1 WHERE root_id = $2")
        .bind(signed.id().as_bytes().to_vec())
        .bind(published.root.as_bytes().to_vec())
        .execute(pool)
        .await?;
    Ok(signed.id())
}

/// The commitment a `root_epoch_n` moment carries.
///
/// Hand-rolled and length-framed in `cc-core`'s style — big-endian, no floats, no
/// `serde` — because this hash goes inside a signed payload: it must be a pure
/// function of the publication, with no derive-order or version drift, forever.
fn root_body_hash(p: &RootPublication) -> [u8; 32] {
    let mut h = Sha256::new();
    framed(&mut h, DST_ROOT);
    h.update(p.height.to_be_bytes());
    h.update(p.tree_size.to_be_bytes());
    h.update(p.root.as_bytes());
    match &p.prev_root {
        // A presence byte, so "no predecessor" and "a predecessor of 32 zero
        // bytes" cannot collide into the same preimage.
        None => h.update([0u8]),
        Some(prev) => {
            h.update([1u8]);
            h.update(prev.as_bytes());
        }
    }
    h.finalize().into()
}

fn framed(h: &mut Sha256, x: &[u8]) {
    let len = u32::try_from(x.len()).expect("framed field fits a u32 length prefix");
    h.update(len.to_be_bytes());
    h.update(x);
}

// ===========================================================================
// Reading the root stream
// ===========================================================================

/// The most recently published root, or `None` before the first epoch.
pub async fn latest_root(pool: &PgPool) -> Result<Option<RootPublication>, AnchorError> {
    let row = sqlx::query(&format!("{ROOT_COLUMNS} ORDER BY r.height DESC LIMIT 1"))
        .fetch_optional(pool)
        .await?;
    row.map(row_to_publication).transpose()
}

/// The root published at `height`.
pub async fn root_at(pool: &PgPool, height: u64) -> Result<Option<RootPublication>, AnchorError> {
    let row = sqlx::query(&format!("{ROOT_COLUMNS} WHERE r.height = $1"))
        .bind(height as i64)
        .fetch_optional(pool)
        .await?;
    row.map(row_to_publication).transpose()
}

async fn latest_root_tx(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Option<RootPublication>, AnchorError> {
    let row = sqlx::query(&format!("{ROOT_COLUMNS} ORDER BY r.height DESC LIMIT 1"))
        .fetch_optional(&mut **tx)
        .await?;
    row.map(row_to_publication).transpose()
}

fn row_to_publication(row: sqlx::postgres::PgRow) -> Result<RootPublication, AnchorError> {
    let root: Vec<u8> = row.try_get("root_id")?;
    let height: i64 = row.try_get("height")?;
    let tree_size: i64 = row.try_get("tree_size")?;
    let prev: Option<Vec<u8>> = row.try_get("prev_root")?;
    let prev_size: Option<i64> = row.try_get("prev_tree_size")?;
    let path: Option<Vec<u8>> = row.try_get("consistency")?;
    let moment: Option<Vec<u8>> = row.try_get("moment_id")?;

    let consistency = match (path, prev_size) {
        (Some(path), Some(prev_size)) => Some(ConsistencyProof::from_path_bytes(
            prev_size as u64,
            tree_size as u64,
            &path,
        )?),
        (None, _) => None,
        // A proof whose predecessor row is gone is not a proof of anything: the
        // sizes it needs to be checked against no longer exist.
        (Some(_), None) => {
            return Err(AnchorError::ConsistencyBroken { height });
        }
    };

    Ok(RootPublication {
        height: height as u64,
        root: MerkleRoot::from_bytes(to32(&root)?),
        tree_size: tree_size as u64,
        prev_root: prev
            .as_deref()
            .map(to32)
            .transpose()?
            .map(MerkleRoot::from_bytes),
        consistency,
        moment: moment
            .as_deref()
            .map(to32)
            .transpose()?
            .map(EventId::from_bytes),
    })
}

fn to32(b: &[u8]) -> Result<[u8; 32], AnchorError> {
    <[u8; 32]>::try_from(b).map_err(|_| AnchorError::BadHashWidth(b.len()))
}

/// Load the whole commitment log in leaf order, checking as it goes that the
/// sequence is gap-free.
///
/// The gap check is not paranoia about Postgres: it is the one invariant every
/// published proof rests on. A hole means something appended outside this module,
/// which changes the shape of the tree and invalidates every root since — better
/// to refuse than to serve proofs against a tree that quietly moved.
async fn load_leaves_tx(tx: &mut Transaction<'_, Postgres>) -> Result<Vec<LeafHash>, AnchorError> {
    let rows = sqlx::query("SELECT seq, event_id FROM commitment_log ORDER BY seq")
        .fetch_all(&mut **tx)
        .await?;
    rows_to_leaves(rows)
}

async fn load_leaves(pool: &PgPool) -> Result<Vec<LeafHash>, AnchorError> {
    let rows = sqlx::query("SELECT seq, event_id FROM commitment_log ORDER BY seq")
        .fetch_all(pool)
        .await?;
    rows_to_leaves(rows)
}

fn rows_to_leaves(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<LeafHash>, AnchorError> {
    let mut leaves = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let seq: i64 = row.try_get("seq")?;
        if seq != i as i64 {
            return Err(AnchorError::LogCorrupt {
                expected: i as i64,
                found: seq,
            });
        }
        let id: Vec<u8> = row.try_get("event_id")?;
        leaves.push(leaf_hash(&EventId::from_bytes(to32(&id)?)));
    }
    Ok(leaves)
}

/// How many leaves are committed. `restore-verify` (M6) compares a restored
/// `events` count against this rather than against the mutable `ledger_stats`
/// row, because only this number is backed by something inscribed in Bitcoin.
pub async fn committed_leaf_count(pool: &PgPool) -> Result<i64, AnchorError> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM commitment_log")
        .fetch_one(pool)
        .await?)
}

// ===========================================================================
// Inclusion proofs
// ===========================================================================

/// An event's place in the committed history: which root commits to it, and the
/// `O(log n)` hashes that show it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EventInclusion {
    /// The event proven.
    pub event: EventId,
    /// Its leaf commitment, `SHA-256(0x00 || event_id)`.
    pub leaf: LeafHash,
    /// The root the proof is against.
    pub root: MerkleRoot,
    /// That root's epoch.
    pub height: u64,
    /// The audit path.
    pub proof: InclusionProof,
}

impl EventInclusion {
    /// Re-check the proof exactly as an outside auditor would.
    ///
    /// Present so a caller that just received one of these from a route never has
    /// to trust the server that produced it — which is the entire reason to ship
    /// a proof instead of an assertion.
    pub fn verify(&self) -> bool {
        self.proof.verify(&self.leaf, &self.root)
    }
}

/// Prove that `event` is committed, against the *earliest* root that commits it.
///
/// Earliest rather than latest because the anchor under that root is what bounds
/// the event's record-time from above (Prop. trscope): a moment under a root
/// inscribed in block `N` was recorded before block `N`, and the first such root
/// gives the tightest bound the ledger can offer. Proving against the newest root
/// would be equally valid and strictly weaker as evidence.
pub async fn prove_event(pool: &PgPool, event: &EventId) -> Result<EventInclusion, AnchorError> {
    let seq: Option<i64> = sqlx::query_scalar("SELECT seq FROM commitment_log WHERE event_id = $1")
        .bind(event.as_bytes().to_vec())
        .fetch_optional(pool)
        .await?;
    let Some(seq) = seq else {
        return Err(AnchorError::NotCommitted(event.to_hex()));
    };

    let row = sqlx::query(&format!(
        "{ROOT_COLUMNS} WHERE r.tree_size > $1 ORDER BY r.height ASC LIMIT 1"
    ))
    .bind(seq)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Err(AnchorError::NotCommitted(event.to_hex()));
    };
    let published = row_to_publication(row)?;

    let leaves = load_leaves(pool).await?;
    let prefix = &leaves[..published.tree_size as usize];
    let proof = prove_inclusion(prefix, seq as u64)?;
    Ok(EventInclusion {
        event: *event,
        leaf: prefix[seq as usize],
        root: published.root,
        height: published.height,
        proof,
    })
}

// ===========================================================================
// Auditing the whole stream
// ===========================================================================

/// What a full re-derivation of the root stream found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChainAudit {
    /// Roots recomputed from the log and matched against their stored value.
    pub roots_checked: u64,
    /// Consistency proofs re-verified between successive roots.
    pub proofs_verified: u64,
    /// Leaves in the commitment log.
    pub leaves: u64,
    /// Roots whose recording node-0 moment is missing — published, but not yet
    /// settled history.
    pub unrecorded: u64,
}

/// Recompute every published root from the commitment log and re-verify every
/// consistency proof.
///
/// This is the mirror's job done locally: it is exactly what a third party with
/// our event export would run, so if it passes here and fails there, the
/// difference is the export and not the arithmetic. It is also the honest form of
/// "the database is a view" — the `roots` table is checked *against* the log
/// rather than believed.
pub async fn verify_root_chain(pool: &PgPool) -> Result<ChainAudit, AnchorError> {
    let leaves = load_leaves(pool).await?;
    let rows = sqlx::query(&format!("{ROOT_COLUMNS} ORDER BY r.height ASC"))
        .fetch_all(pool)
        .await?;

    let mut audit = ChainAudit {
        roots_checked: 0,
        proofs_verified: 0,
        leaves: leaves.len() as u64,
        unrecorded: 0,
    };
    let mut prev: Option<RootPublication> = None;
    for row in rows {
        let published = row_to_publication(row)?;
        let size = published.tree_size as usize;
        if size > leaves.len() {
            return Err(AnchorError::RootMismatch {
                height: published.height as i64,
                recorded: published.root.to_hex(),
                recomputed: format!("a log of only {} leaves", leaves.len()),
            });
        }
        let recomputed = merkle_root(&leaves[..size]);
        if recomputed != published.root {
            return Err(AnchorError::RootMismatch {
                height: published.height as i64,
                recorded: published.root.to_hex(),
                recomputed: recomputed.to_hex(),
            });
        }
        audit.roots_checked += 1;
        if published.moment.is_none() {
            audit.unrecorded += 1;
        }

        if let Some(prev) = prev.as_ref() {
            let ok = published
                .consistency
                .as_ref()
                .is_some_and(|proof| proof.verify(&prev.root, &published.root));
            if !ok {
                return Err(AnchorError::ConsistencyBroken {
                    height: published.height as i64,
                });
            }
            audit.proofs_verified += 1;
        }
        prev = Some(published);
    }
    Ok(audit)
}

/// The consistency proof between the roots at `height` and `height + 1`.
///
/// A mirror asks for this pair, checks it against the two roots it already holds,
/// and learns that the operator extended the log rather than rewriting it — with
/// no access to the events themselves.
pub async fn consistency_between(
    pool: &PgPool,
    height: u64,
) -> Result<(MerkleRoot, MerkleRoot, ConsistencyProof), AnchorError> {
    let Some(older) = root_at(pool, height).await? else {
        return Err(AnchorError::UnknownRoot(format!("height {height}")));
    };
    let Some(newer) = root_at(pool, height + 1).await? else {
        return Err(AnchorError::UnknownRoot(format!("height {}", height + 1)));
    };
    let Some(proof) = newer.consistency.clone() else {
        return Err(AnchorError::ConsistencyBroken {
            height: newer.height as i64,
        });
    };
    Ok((older.root, newer.root, proof))
}

// ===========================================================================
// Anchoring
// ===========================================================================

/// Where a root stands with the outside world.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnchorStatus {
    /// A calendar holds the commitment; no block confirms it yet. A promise.
    Pending,
    /// A Bitcoin block header commits to it. A settlement fact.
    Confirmed,
}

impl AnchorStatus {
    /// The stored discriminant — a smallint, never a string (memo §11).
    pub fn to_i16(self) -> i16 {
        match self {
            AnchorStatus::Pending => 0,
            AnchorStatus::Confirmed => 1,
        }
    }

    /// Read a stored discriminant back. An unknown value is refused rather than
    /// defaulted, because defaulting it to `Pending` would hide a schema drift in
    /// the settlement path.
    pub fn from_i16(v: i16) -> Option<AnchorStatus> {
        match v {
            0 => Some(AnchorStatus::Pending),
            1 => Some(AnchorStatus::Confirmed),
            _ => None,
        }
    }
}

/// The anchor record for one root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AnchorRecord {
    /// The root anchored.
    pub root: MerkleRoot,
    /// Pending or confirmed.
    pub status: AnchorStatus,
    /// Content address of the `.ots` proof; the bytes live in `anchor_proofs`.
    pub ots_blob_hash: [u8; 32],
    /// The calendar the commitment was submitted to.
    pub calendar_url: String,
    /// Bitcoin block height, once confirmed.
    pub block_height: Option<u64>,
    /// The node-0 moment recording the anchor's current state.
    pub moment: EventId,
    /// Seconds since the anchor row was written — what `/health/deep` alarms on,
    /// because a cancelled `anchor-tick` shows up as an anchor that stopped
    /// getting newer, never as an error anybody logged (§6).
    pub age_seconds: i64,
}

/// Record an OpenTimestamps stamp for a published root: store the proof by
/// reference, append the pending node-0 anchor moment, project the `anchors` row.
///
/// Takes the proof rather than fetching it, so everything that touches the ledger
/// is exercised against a real database while the calendar round-trip stays
/// isolated in [`anchor_root`].
pub async fn record_stamp(
    pool: &PgPool,
    key: &SecretKey,
    root: &MerkleRoot,
    proof: &OtsProof,
    calendar_url: &str,
    now: Tick,
) -> Result<AnchorRecord, AnchorError> {
    proof.commits_to(root.as_bytes())?;
    let published = root_by_id(pool, root).await?;
    if anchor_for(pool, root).await?.is_some() {
        return Err(AnchorError::AnchorState {
            root: root.to_hex(),
            detail: "already stamped; a second stamp would replace settled evidence",
        });
    }

    let blob = proof.blob_hash();
    sqlx::query(
        "INSERT INTO anchor_proofs (blob_hash, bytes) VALUES ($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(blob.to_vec())
    .bind(proof.bytes().to_vec())
    .execute(pool)
    .await?;

    let moment = anchor_moment(
        key,
        &published,
        AnchorStatus::Pending,
        &blob,
        calendar_url,
        None,
        None,
        None,
        now,
    );
    cc_ledger::commit(pool, &moment).await?;

    sqlx::query(
        "INSERT INTO anchors (root_id, status, ots_blob_hash, calendar_url, moment_id) \
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(root.as_bytes().to_vec())
    .bind(AnchorStatus::Pending.to_i16())
    .bind(blob.to_vec())
    .bind(calendar_url)
    .bind(moment.id().as_bytes().to_vec())
    .execute(pool)
    .await?;

    anchor_for(pool, root)
        .await?
        .ok_or_else(|| AnchorError::AnchorState {
            root: root.to_hex(),
            detail: "the anchor row vanished immediately after being written",
        })
}

/// Promote a pending anchor to confirmed once a Bitcoin block commits to it.
///
/// The confirmed state is a *new* signed moment superseding the pending one, not
/// an edit: `events` is never updated, and the `anchors` row is the collapsed view
/// of both (§ledger). `block_height` comes from the upgraded OTS proof; `txid` is
/// optional because a Bitcoin attestation names the block, not the transaction,
/// and recording a txid nothing verified would be a fabricated settlement detail.
pub async fn confirm_anchor(
    pool: &PgPool,
    key: &SecretKey,
    root: &MerkleRoot,
    block_height: u64,
    txid: Option<&[u8]>,
    now: Tick,
) -> Result<AnchorRecord, AnchorError> {
    let published = root_by_id(pool, root).await?;
    let Some(pending) = anchor_for(pool, root).await? else {
        return Err(AnchorError::AnchorState {
            root: root.to_hex(),
            detail: "no stamp to confirm",
        });
    };
    if pending.status == AnchorStatus::Confirmed {
        return Err(AnchorError::AnchorState {
            root: root.to_hex(),
            detail: "already confirmed; settlement is recorded once",
        });
    }

    let moment = anchor_moment(
        key,
        &published,
        AnchorStatus::Confirmed,
        &pending.ots_blob_hash,
        &pending.calendar_url,
        Some(block_height),
        txid,
        // The pending moment persists as signed history; the confirmed one
        // supersedes it in the view. Append-only lifecycle, never a status flip.
        Some(pending.moment),
        now,
    );
    cc_ledger::commit(pool, &moment).await?;

    sqlx::query(
        "UPDATE anchors SET status = $1, block_height = $2, txid = $3, moment_id = $4 \
         WHERE root_id = $5",
    )
    .bind(AnchorStatus::Confirmed.to_i16())
    .bind(block_height as i64)
    .bind(txid)
    .bind(moment.id().as_bytes().to_vec())
    .bind(root.as_bytes().to_vec())
    .execute(pool)
    .await?;

    anchor_for(pool, root)
        .await?
        .ok_or_else(|| AnchorError::AnchorState {
            root: root.to_hex(),
            detail: "the anchor row vanished immediately after being confirmed",
        })
}

/// **NETWORK.** The whole anchor tick for a root: submit to a calendar, then
/// record what came back.
///
/// One line of this function cannot be tested without making a public
/// third-party service a test dependency; everything before and after it runs
/// against a real database in the suite. If the calendar is unreachable the epoch
/// stays unanchored and the next tick retries — the failure mode that matters is
/// the silent one, which is why `/health/deep` alarms on anchor *age* rather than
/// on an error count (§6).
pub async fn anchor_root(
    pool: &PgPool,
    key: &SecretKey,
    root: &MerkleRoot,
    calendar_url: &str,
    now: Tick,
) -> Result<AnchorRecord, AnchorError> {
    let reply = ots::submit(calendar_url, root.as_bytes()).await?; // <-- the network hop
    let proof = OtsProof::from_calendar_reply(root.as_bytes(), &reply)?;
    record_stamp(pool, key, root, &proof, calendar_url, now).await
}

/// What asking the calendar for a confirmation produced.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UpgradeOutcome {
    /// Bitcoin now commits to the root, and the confirmation is recorded.
    Confirmed(AnchorRecord),
    /// The calendar still holds the commitment and no block carries it yet. The
    /// expected answer for hours after a stamp, and a state rather than a
    /// failure — the anchor stays pending and the next tick asks again.
    StillPending(AnchorRecord),
}

/// **NETWORK.** Ask the calendars whether a pending anchor has made it into a
/// Bitcoin block, and record the confirmation if it has.
///
/// This is the second half of the anchor lifecycle and the only place `pending`
/// becomes `confirmed`. Already-confirmed anchors are returned unchanged rather
/// than refused, so a cron can run this over every anchor every tick without
/// having to track which ones are done.
///
/// The block height comes from the OTS Bitcoin attestation. What this build does
/// *not* do is check that height against the chain: that needs a block-header
/// source (a node or an oracle) which the plan flags as a dependency (§5.5). Until
/// one exists, the confirmation records what the calendar's proof asserts, and
/// that limit is stated here rather than papered over.
pub async fn upgrade_anchor(
    pool: &PgPool,
    key: &SecretKey,
    root: &MerkleRoot,
    now: Tick,
) -> Result<UpgradeOutcome, AnchorError> {
    let Some(record) = anchor_for(pool, root).await? else {
        return Err(AnchorError::AnchorState {
            root: root.to_hex(),
            detail: "no stamp to upgrade",
        });
    };
    if record.status == AnchorStatus::Confirmed {
        return Ok(UpgradeOutcome::Confirmed(record));
    }

    let proof = load_proof(pool, &record.ots_blob_hash).await?;
    for (calendar, commitment) in proof.pending()? {
        let Some(upgraded) = ots::fetch_upgrade(&calendar, &commitment).await? else {
            continue; // that calendar has not put it in a block yet
        };
        let height = ots::attestations_in(&upgraded, &commitment)?
            .into_iter()
            .find_map(|c| match c.attestation {
                ots::Attestation::Bitcoin { height } => Some(height),
                _ => None,
            });
        if let Some(height) = height {
            let confirmed = confirm_anchor(pool, key, root, height, None, now).await?;
            return Ok(UpgradeOutcome::Confirmed(confirmed));
        }
    }
    Ok(UpgradeOutcome::StillPending(record))
}

/// The anchor record for a root, if it has one.
pub async fn anchor_for(
    pool: &PgPool,
    root: &MerkleRoot,
) -> Result<Option<AnchorRecord>, AnchorError> {
    let row = sqlx::query(
        "SELECT root_id, status, ots_blob_hash, calendar_url, block_height, moment_id, \
                EXTRACT(EPOCH FROM (now() - anchored_at))::bigint AS age_seconds \
         FROM anchors WHERE root_id = $1",
    )
    .bind(root.as_bytes().to_vec())
    .fetch_optional(pool)
    .await?;
    row.map(row_to_anchor).transpose()
}

/// The anchor of the highest anchored root — `/health/deep`'s "latest anchor age".
pub async fn latest_anchor(pool: &PgPool) -> Result<Option<AnchorRecord>, AnchorError> {
    let row = sqlx::query(
        "SELECT a.root_id, a.status, a.ots_blob_hash, a.calendar_url, a.block_height, a.moment_id, \
                EXTRACT(EPOCH FROM (now() - a.anchored_at))::bigint AS age_seconds \
         FROM anchors a JOIN roots r ON r.root_id = a.root_id \
         ORDER BY r.height DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    row.map(row_to_anchor).transpose()
}

/// The stored `.ots` bytes for an anchor, fetched by content address.
///
/// Verifies the blob against the hash it was stored under before returning it. A
/// proof that does not hash to its own key is corrupt, and handing that to an
/// auditor as evidence is worse than admitting it is gone.
pub async fn load_proof(pool: &PgPool, blob_hash: &[u8; 32]) -> Result<OtsProof, AnchorError> {
    let bytes: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT bytes FROM anchor_proofs WHERE blob_hash = $1")
            .bind(blob_hash.to_vec())
            .fetch_optional(pool)
            .await?;
    let Some(bytes) = bytes else {
        return Err(AnchorError::AnchorState {
            root: hex::encode(blob_hash),
            detail: "no stored proof under that content address",
        });
    };
    let proof = OtsProof::from_bytes(bytes)?;
    if &proof.blob_hash() != blob_hash {
        return Err(AnchorError::AnchorState {
            root: hex::encode(blob_hash),
            detail: "stored proof does not hash to its own key",
        });
    }
    Ok(proof)
}

fn row_to_anchor(row: sqlx::postgres::PgRow) -> Result<AnchorRecord, AnchorError> {
    let root: Vec<u8> = row.try_get("root_id")?;
    let status: i16 = row.try_get("status")?;
    let blob: Vec<u8> = row.try_get("ots_blob_hash")?;
    let calendar_url: Option<String> = row.try_get("calendar_url")?;
    let block_height: Option<i64> = row.try_get("block_height")?;
    let moment: Vec<u8> = row.try_get("moment_id")?;
    let age_seconds: i64 = row.try_get("age_seconds")?;
    Ok(AnchorRecord {
        root: MerkleRoot::from_bytes(to32(&root)?),
        status: AnchorStatus::from_i16(status).ok_or(AnchorError::AnchorState {
            root: hex::encode(&root),
            detail: "unknown anchor status discriminant",
        })?,
        ots_blob_hash: to32(&blob)?,
        calendar_url: calendar_url.unwrap_or_default(),
        block_height: block_height.map(|h| h as u64),
        moment: EventId::from_bytes(to32(&moment)?),
        age_seconds,
    })
}

async fn root_by_id(pool: &PgPool, root: &MerkleRoot) -> Result<RootPublication, AnchorError> {
    let row = sqlx::query(&format!("{ROOT_COLUMNS} WHERE r.root_id = $1"))
        .bind(root.as_bytes().to_vec())
        .fetch_optional(pool)
        .await?;
    match row {
        Some(row) => row_to_publication(row),
        None => Err(AnchorError::UnknownRoot(root.to_hex())),
    }
}

/// The signed node-0 moment for an anchor state transition.
///
/// Same framing discipline as [`root_body_hash`], and deliberately a *different*
/// domain tag, so a root moment and an anchor moment about the same root can
/// never share a body hash.
#[allow(clippy::too_many_arguments)]
fn anchor_moment(
    key: &SecretKey,
    published: &RootPublication,
    status: AnchorStatus,
    blob: &[u8; 32],
    calendar_url: &str,
    block_height: Option<u64>,
    txid: Option<&[u8]>,
    supersedes: Option<EventId>,
    now: Tick,
) -> Signed {
    let mut h = Sha256::new();
    framed(&mut h, DST_ANCHOR);
    h.update(published.root.as_bytes());
    h.update(published.height.to_be_bytes());
    h.update([status.to_i16() as u8]);
    h.update(blob);
    framed(&mut h, calendar_url.as_bytes());
    match block_height {
        None => h.update([0u8]),
        Some(n) => {
            h.update([1u8]);
            h.update(n.to_be_bytes());
        }
    }
    framed(&mut h, txid.unwrap_or_default());
    let body_hash: [u8; 32] = h.finalize().into();

    let content = EventContent {
        event_time: now,
        record_time: now,
        author: key.author(),
        supersedes,
        body: EventBody::Moment(MomentBody {
            subject: NODE_ZERO,
            body_hash,
        }),
    };
    Signed::sign(key, content)
}
