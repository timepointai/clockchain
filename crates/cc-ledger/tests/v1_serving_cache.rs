//! Stage (g) G4 serving glue over real PostgreSQL: the committed-snapshot
//! cache answers exactly what the uncached fold answers across admissions,
//! every admission invalidates it, a changed retained byte is never served
//! from memory, and node receipts are signed on first admission only and
//! never enter a snapshot, corpus digest, commitment or export.
use cc_core::v1::receipt::{Admission, SignedReceipt};
use cc_core::v1::rule::fold_v1;
use cc_core::v1::*;
use cc_ledger::v1::{canonical_rows, Error, Outcome, State, Status, Store};
use cc_testkit::v1::*;
use sqlx::PgPool;

/// The node key used by these tests; not a curator (curators are keys 0..4).
fn node() -> cc_core::SecretKey {
    key(40)
}

async fn bound() -> (PgPool, cc_testkit::Cleanup, Store) {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    Store::provision(pool.clone(), INSTANCE)
        .await
        .unwrap()
        .bind(filter())
        .await
        .unwrap();
    let store = Store::open(pool.clone(), INSTANCE, filter()).await.unwrap();
    (pool, cleanup, store)
}

/// A deterministic generator; a failing seed is printed and replays exactly.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, (self.next() % (i as u64 + 1)) as usize);
        }
    }
}

/// Every admission input the property draws from: the pinned view fixture,
/// a competing correction, a delegation and a correction under it, a second
/// pinned edge, an invalid genesis, a wrong-instance envelope, undecodable bytes, and a repeat.
fn inputs() -> Vec<Vec<u8>> {
    let fixture = view_fixture();
    let g = &fixture[0];
    let c = &fixture[1];
    let b = &fixture[2];
    let rival = correction(g, g, 1, 7);
    let d = delegate(g, c, 0, root_grant(g.id()), 9);
    let mut wrong = genesis().envelope().clone();
    wrong.instance = [8; 32];
    let wrong = Signed::sign(&key(0), wrong).unwrap();
    // Retained but invalid: a genesis may not name a grant.
    let mut granted = genesis().envelope().clone();
    granted.grant = Some([6; 32]);
    let granted = Signed::sign(&key(0), granted).unwrap();
    let e2 = edge(
        1,
        "influence",
        Pins {
            source: pin(&[b], b),
            target: pin(&[g], g),
        },
    );
    let mut all: Vec<Vec<u8>> = fixture.iter().map(|e| e.bytes().to_vec()).collect();
    all.extend(
        [rival, d, e2, wrong, granted]
            .iter()
            .map(|e| e.bytes().to_vec()),
    );
    all.push(b"not an envelope".to_vec());
    all.push(fixture[0].bytes().to_vec());
    all
}

/// Snapshot equality plus the exact bytes a read derives from it.
fn assert_identical(cached: &cc_ledger::v1::Snapshot, folded: &cc_ledger::v1::Snapshot, at: &str) {
    assert_eq!(cached, folded, "{at}");
    assert_eq!(
        canonical_rows(&cached.projection),
        canonical_rows(&folded.projection),
        "{at}"
    );
    assert_eq!(cached.commitment, folded.commitment, "{at}");
    assert_eq!(cached.corpus_digest, folded.corpus_digest, "{at}");
}

/// The property: for every admission order drawn, after every admission, the
/// cached snapshot (on its miss and on its hit) equals a fresh uncached fold
/// over the same store, and the cache really served hits.
#[tokio::test]
async fn cached_snapshots_equal_the_uncached_fold_across_admits() {
    let mut compared = 0usize;
    for seed in [0x9e37_79b9_7f4a_7c15u64, 7, 1_000_003, 0xdead_beef] {
        let (pool, cleanup, store) = bound().await;
        let reference = store.clone().uncached();
        let mut order = inputs();
        Rng(seed).shuffle(&mut order);
        let before = store.cache_stats();
        for (n, bytes) in order.iter().enumerate() {
            store.admit(bytes).await.unwrap();
            let at = format!("seed {seed:#x}, after admission {n}");
            let miss = store.snapshot(None).await.unwrap();
            let hit = store.snapshot(None).await.unwrap();
            let folded = reference.snapshot(None).await.unwrap();
            assert_identical(&miss, &folded, &at);
            assert_identical(&hit, &folded, &at);
            compared += 2;
        }
        let (hits, misses) = store.cache_stats();
        let admissions = order.len() as u64;
        // One miss right after each admission, one hit right after that.
        assert_eq!(hits - before.0, admissions, "seed {seed:#x}");
        assert_eq!(misses - before.1, admissions, "seed {seed:#x}");
        // The reference never caches.
        assert_eq!(reference.cache_stats(), (0, 0));
        pool.close().await;
        cleanup.cleanup().await;
    }
    assert_eq!(compared, 4 * 2 * inputs().len());
}

/// Every admission empties the cache, whatever it admitted: a new candidate,
/// a repeat, a rejected input. The next read is then a miss.
#[tokio::test]
async fn every_admission_invalidates_the_cache() {
    let (pool, cleanup, store) = bound().await;
    let g = genesis();
    assert_eq!(store.cached_key(), None);
    for bytes in [
        g.bytes().to_vec(),
        g.bytes().to_vec(),
        b"rejected bytes".to_vec(),
    ] {
        let s = store.snapshot(None).await.unwrap();
        let key = store.cached_key().expect("a read fills the cache");
        assert_eq!(key.corpus_digest, s.corpus_digest);
        assert_eq!(key.rule, s.rule);
        let (hits, misses) = store.cache_stats();
        store.snapshot(None).await.unwrap();
        assert_eq!(store.cache_stats(), (hits + 1, misses));
        store.admit(&bytes).await.unwrap();
        assert_eq!(
            store.cached_key(),
            None,
            "an admission left the cache filled"
        );
        store.snapshot(None).await.unwrap();
        assert_eq!(store.cache_stats(), (hits + 1, misses + 1));
    }
    // Clones share one cache: an admission through one empties the other's.
    let other = store.clone();
    store.snapshot(None).await.unwrap();
    assert!(other.cached_key().is_some());
    other.admit(correction(&g, &g, 0, 5).bytes()).await.unwrap();
    assert_eq!(store.cached_key(), None);
    pool.close().await;
    cleanup.cleanup().await;
}

/// Two stores over one database hold separate caches, as two node processes
/// do during a rolling deploy. An admission through one never reaches the
/// other's invalidation, so only the key keeps the other from answering with
/// the corpus it cached before.
#[tokio::test]
async fn a_cache_never_answers_for_a_corpus_another_store_changed() {
    let (pool, cleanup, store) = bound().await;
    let other = Store::open(pool.clone(), INSTANCE, filter()).await.unwrap();
    let reference = store.clone().uncached();
    for e in view_fixture() {
        let before = store.snapshot(None).await.unwrap();
        assert!(store.cached_key().is_some());
        other.admit(e.bytes()).await.unwrap();
        // Still filled: the other store's admission did not invalidate it.
        assert!(store.cached_key().is_some());
        let after = store.snapshot(None).await.unwrap();
        assert_ne!(after.corpus_digest, before.corpus_digest);
        assert_identical(
            &after,
            &reference.snapshot(None).await.unwrap(),
            "cross-store",
        );
    }
    pool.close().await;
    cleanup.cleanup().await;
}

/// The key includes a digest of the retained bytes: a candidate row changed
/// behind the append-only trigger is re-verified and refused, never answered
/// from the cache.
#[tokio::test]
async fn a_changed_retained_byte_is_never_served_from_the_cache() {
    let (pool, cleanup, store) = bound().await;
    let g = genesis();
    store.admit(g.bytes()).await.unwrap();
    store.snapshot(None).await.unwrap();
    assert!(store.cached_key().is_some());
    sqlx::raw_sql(
        "ALTER TABLE cc_v1.candidates DISABLE TRIGGER immutable_candidates;
         UPDATE cc_v1.candidates SET envelope = envelope || '\\x00'::bytea;
         ALTER TABLE cc_v1.candidates ENABLE TRIGGER immutable_candidates;",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(store.snapshot(None).await, Err(Error::Corrupt)));
    pool.close().await;
    cleanup.cleanup().await;
}

fn observed(status: &Status) -> Admission {
    match status.state {
        State::Valid => Admission::Valid,
        State::Pending => Admission::Pending,
        State::Invalid => Admission::Invalid,
    }
}

async fn receipt_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cc_v1.receipts")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The same admissions into two stores, one receipting and one not: the
/// outcomes, snapshots, commitments and exports are identical; only the
/// receipting store holds receipts, one per first admission, each verifying
/// and naming exactly what its `Outcome` reported.
#[tokio::test]
async fn receipts_are_signed_on_first_admission_and_never_enter_commitments() {
    let (pool_on, cleanup_on, on) = bound().await;
    let (pool_off, cleanup_off, off) = bound().await;
    let mut order = inputs();
    Rng(42).shuffle(&mut order);
    let mut receipted = std::collections::BTreeSet::new();
    let mut states = Vec::new();
    for bytes in &order {
        let start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let (outcome, receipt) = on.admit_observed(bytes, Some(&node())).await.unwrap();
        let (plain, none) = off.admit_observed(bytes, None).await.unwrap();
        assert!(none.is_none());
        assert_eq!(outcome, plain);
        let Outcome { event, status, .. } = &outcome;
        match (event, receipt) {
            (None, receipt) => assert!(receipt.is_none(), "a rejected input was receipted"),
            (Some(id), Some(r)) => {
                assert!(receipted.insert(*id), "a repeat admission was receipted");
                let n = r.receipt();
                assert_eq!(n.instance, INSTANCE);
                assert_eq!(n.node_key, node().author().to_bytes());
                assert_eq!(n.event, *id);
                assert_eq!(n.encoding_version, 1);
                assert_eq!(n.fold_version, fold_v1());
                assert_eq!(n.initial_admission_result.state, observed(status));
                states.push(n.initial_admission_result.state);
                assert_eq!(n.initial_admission_result.reason, status.reason);
                assert_eq!(n.initial_admission_result.missing.0, status.missing);
                assert!(n.received_at >= start);
                // The retained receipt is the returned one, and verifies.
                let stored = on.receipts(*id).await.unwrap();
                assert_eq!(stored.len(), 1);
                assert_eq!(stored[0].bytes(), r.bytes());
                SignedReceipt::decode(stored[0].bytes()).unwrap();
            }
            (Some(id), None) => assert!(receipted.contains(id), "a first admission lacked one"),
        }
    }
    // The draw receipted every admission state, so each mapping was checked.
    for state in [Admission::Valid, Admission::Pending, Admission::Invalid] {
        assert!(states.contains(&state), "no {state:?} receipt in this draw");
    }
    assert_eq!(receipt_rows(&pool_on).await, receipted.len() as i64);
    assert_eq!(receipt_rows(&pool_off).await, 0);
    // A store with receipts commits exactly what one without them commits.
    let (a, b) = (
        on.clone().uncached().snapshot(None).await.unwrap(),
        off.clone().uncached().snapshot(None).await.unwrap(),
    );
    assert_identical(&a, &b, "receipts on vs off");
    assert_eq!(
        on.export(None).await.unwrap(),
        off.export(None).await.unwrap()
    );
    // A receipt never becomes a candidate: one candidate per receipted event.
    let candidates: i64 = sqlx::query_scalar("SELECT count(*) FROM cc_v1.candidates")
        .fetch_one(&pool_on)
        .await
        .unwrap();
    assert_eq!(candidates, receipted.len() as i64);
    for p in [pool_on, pool_off] {
        p.close().await;
    }
    cleanup_on.cleanup().await;
    cleanup_off.cleanup().await;
}

/// No fold, no receipt: an unbound store refuses to receipt before writing.
/// A stored receipt whose bytes changed is refused on read.
#[tokio::test]
async fn receipts_refuse_without_a_fold_and_verify_on_read() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let unbound = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    let g = genesis();
    assert!(matches!(
        unbound.admit_observed(g.bytes(), Some(&node())).await,
        Err(Error::Unbound)
    ));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM cc_v1.candidates")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    pool.close().await;
    cleanup.cleanup().await;

    let (pool, cleanup, store) = bound().await;
    store
        .admit_observed(g.bytes(), Some(&node()))
        .await
        .unwrap();
    assert_eq!(store.receipts(g.id()).await.unwrap().len(), 1);
    assert!(store.receipts([7; 32]).await.unwrap().is_empty());
    sqlx::raw_sql(
        "ALTER TABLE cc_v1.receipts DISABLE TRIGGER immutable_receipts;
         UPDATE cc_v1.receipts SET envelope = set_byte(envelope, 40, get_byte(envelope, 40) # 1);
         ALTER TABLE cc_v1.receipts ENABLE TRIGGER immutable_receipts;",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(store.receipts(g.id()).await, Err(Error::Corrupt)));
    pool.close().await;
    cleanup.cleanup().await;
}
