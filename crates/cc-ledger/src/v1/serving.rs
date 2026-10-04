//! Serving glue (Stage (g) G4): the committed-snapshot cache and node receipts.
//!
//! Neither changes what the fold computes. The cache only decides whether a
//! snapshot is recomputed or reused; a reused snapshot is the value the
//! uncached fold produced over byte-identical retained candidates. Receipts
//! are signed node observations kept in `cc_v1.receipts`, which no snapshot,
//! corpus digest, commitment or export reads.
use super::*;
use cc_core::v1::receipt::{Admission, InitialResult, NodeReceiptV1, SignedReceipt};
use cc_core::v1::rule::corpus_digest;
use cc_filter::v1::FilterIdentity;
use std::sync::{Arc, Mutex};

/// What a cached snapshot is keyed by: the rule identity and corpus digest it
/// was committed under, plus a digest of the exact retained bytes it was
/// folded from. The last part makes a retained row whose bytes changed out of
/// band a miss, so it is re-verified rather than served from memory.
///
/// Process-local and never serialized: distinct from the pinned `cc.cache.v1`
/// key ([`Snapshot::cache_key`]), which names query results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheKey {
    pub rule: RuleId,
    pub corpus_digest: Hash,
    content: Hash,
}

/// `(event_id, sha256(envelope))` pairs in event-id order. Both the database
/// probe and the fold that fills the cache derive the key from these.
fn key_of(filter: &FilterIdentity, rows: &[(Hash, Hash)]) -> CacheKey {
    let mut content = Vec::with_capacity(rows.len() * 64);
    for (id, digest) in rows {
        content.extend_from_slice(id);
        content.extend_from_slice(digest);
    }
    CacheKey {
        rule: RuleId::of(filter),
        corpus_digest: corpus_digest(&rows.iter().map(|(id, _)| *id).collect()),
        content: hash(&content),
    }
}

#[derive(Default)]
struct Inner {
    /// Bumped by every admission. A fold that started under an older
    /// generation is not stored. This only avoids filling the cache with a
    /// snapshot the next probe would miss anyway; correctness rests on the
    /// key, which is always derived from the rows the snapshot was folded from.
    generation: u64,
    /// Shared, so a hit holds the lock only to clone a pointer.
    entry: Option<(CacheKey, Arc<Snapshot>)>,
    hits: u64,
    misses: u64,
}

/// One entry, the latest committed snapshot. The corpus only grows, so an
/// older entry is never asked for again.
#[derive(Clone, Default)]
pub(crate) struct SnapshotCache(Arc<Mutex<Inner>>);

impl SnapshotCache {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only means another reader panicked mid-update; the
        // entry is replaced wholesale, so its state is still coherent.
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
    pub(crate) fn invalidate(&self) {
        let mut inner = self.lock();
        inner.generation += 1;
        inner.entry = None;
    }
}

impl Store {
    /// The cache probe: one query over ids and server-side byte digests,
    /// with no envelope transferred, decoded or verified. PostgreSQL still
    /// hashes every retained envelope, so its cost grows with corpus bytes;
    /// it skips the signature checks and the fold, which dominate a miss.
    async fn probe(&self, filter: &FilterIdentity) -> Result<CacheKey, Error> {
        let rows = sqlx::query(
            "SELECT event_id, sha256(envelope) AS digest FROM cc_v1.candidates ORDER BY event_id",
        )
        .fetch_all(&self.pool)
        .await?;
        let rows = rows
            .iter()
            .map(|row| {
                let id = row.get::<Vec<u8>, _>("event_id").try_into();
                let digest = row.get::<Vec<u8>, _>("digest").try_into();
                match (id, digest) {
                    (Ok(id), Ok(digest)) => Ok((id, digest)),
                    _ => Err(Error::Corrupt),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(key_of(filter, &rows))
    }

    /// The committed snapshot under `filter`: the cached one when its key
    /// equals the store's current key, otherwise a fresh fold from verified
    /// retained bytes, which then fills the cache.
    pub(crate) async fn committed(&self, filter: &FilterIdentity) -> Result<Snapshot, Error> {
        let Some(cache) = &self.cache else {
            return Ok(Snapshot::of(filter, &self.verified_candidates().await?));
        };
        let generation = cache.lock().generation;
        let key = self.probe(filter).await?;
        let hit = {
            let mut inner = cache.lock();
            let hit = match &inner.entry {
                Some((cached, s)) if *cached == key => Some(s.clone()),
                _ => None,
            };
            match hit {
                Some(_) => inner.hits += 1,
                None => inner.misses += 1,
            }
            hit
        };
        if let Some(s) = hit {
            return Ok(Snapshot::clone(&s));
        }
        let candidates = self.verified_candidates().await?;
        let s = Snapshot::of(filter, &candidates);
        let rows: Vec<_> = candidates
            .iter()
            .map(|(id, e)| (*id, hash(e.bytes())))
            .collect();
        let mut inner = cache.lock();
        if inner.generation == generation {
            inner.entry = Some((key_of(filter, &rows), Arc::new(s.clone())));
        }
        Ok(s)
    }

    /// The same store with the snapshot cache off: every read folds. The
    /// reference the cache-equivalence tests compare against.
    #[cfg(feature = "review")]
    pub fn uncached(mut self) -> Self {
        self.cache = None;
        self
    }

    /// The key of the cached snapshot, if one is held.
    #[cfg(feature = "review")]
    pub fn cached_key(&self) -> Option<CacheKey> {
        let cache = self.cache.as_ref()?;
        let inner = cache.lock();
        inner.entry.as_ref().map(|(k, _)| k.clone())
    }

    /// `(hits, misses)` since this store was opened.
    #[cfg(feature = "review")]
    pub fn cache_stats(&self) -> (u64, u64) {
        self.cache.as_ref().map_or((0, 0), |c| {
            let inner = c.lock();
            (inner.hits, inner.misses)
        })
    }

    /// Every receipt retained for `event`, verified (domain, canonical form,
    /// signature, instance, event and digest) before it is returned, in
    /// receipt-digest order. A row that fails verification is `Corrupt`.
    pub async fn receipts(&self, event: Hash) -> Result<Vec<SignedReceipt>, Error> {
        let rows = sqlx::query(
            "SELECT receipt_digest, envelope FROM cc_v1.receipts WHERE event_id=$1 ORDER BY receipt_digest",
        )
        .bind(event.to_vec())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let bytes: Vec<u8> = row.get("envelope");
                let r = SignedReceipt::decode(&bytes).map_err(|_| Error::Corrupt)?;
                if r.receipt().instance != self.instance
                    || r.receipt().event != event
                    || row.get::<Vec<u8>, _>("receipt_digest") != hash(&bytes)
                {
                    return Err(Error::Corrupt);
                }
                Ok(r)
            })
            .collect()
    }
}

/// The receipt this node signs for a candidate it has just retained for the
/// first time: the admission result exactly as `Outcome` reported it.
pub(crate) fn receipt_for(
    node: &cc_core::SecretKey,
    instance: Hash,
    filter: &FilterIdentity,
    event: Hash,
    status: &Status,
    received_at: u64,
) -> Result<SignedReceipt, Error> {
    let state = match status.state {
        State::Valid => Admission::Valid,
        State::Pending => Admission::Pending,
        State::Invalid => Admission::Invalid,
    };
    // A receipt's missing set is canonical: sorted and unique.
    let missing: BTreeSet<Hash> = status.missing.iter().copied().collect();
    SignedReceipt::sign(
        node,
        NodeReceiptV1 {
            instance,
            node_key: [0; 32],
            event,
            received_at,
            encoding_version: cc_core::CANON_VERSION,
            fold_version: filter.fold.clone(),
            initial_admission_result: InitialResult {
                state,
                reason: status.reason.clone(),
                missing: cc_core::v1::Set(missing.into_iter().collect()),
            },
        },
    )
    .map_err(|_| Error::Receipt)
}

/// Unix microseconds now. A clock before 1970 reads as 0 rather than failing
/// an admission; `received_at` is an observation, not a claimed time.
pub(crate) fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}
