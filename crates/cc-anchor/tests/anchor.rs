//! M4 against a real Postgres — no mocks, per `CONTRIBUTING.md`. Every test here
//! provisions its own ephemeral database through `cc-testkit`, applies the real
//! migrations, and writes through `cc-ledger`'s real choke point.
//!
//! The one thing these tests do not exercise is the calendar round-trip, because
//! that would make a public third-party service a dependency of `cargo test`. It
//! is isolated to a single line inside `cc_anchor::anchor_root`, and the
//! `#[ignore]`d test at the bottom of this file drives it against the real
//! calendars on demand.

use cc_anchor::{
    anchor_for, committed_leaf_count, confirm_anchor, consistency_between, latest_anchor,
    latest_root, load_proof, merkle_root, prove_event, publish_root, root_at, verify_root_chain,
    AnchorError, AnchorStatus, OtsProof, RootOutcome,
};
use cc_core::{EventBody, EventContent, EventId, MomentBody, SecretKey, Tick};
use cc_ledger::{commit, Signed};
use sqlx::{PgPool, Row};

/// A real reply from a public OpenTimestamps calendar, captured on 2026-08-12.
///
/// Used here as the *operation stream* of a proof while the header is re-written
/// to name the root under test: an OTS operation chain is opaque to the digest it
/// starts from, so this exercises the storage and lifecycle path with bytes a
/// calendar actually produced rather than with bytes invented to please our own
/// parser. What it deliberately does not stand in for is the submission itself —
/// that is the `#[ignore]`d test.
const CALENDAR_REPLY: &[u8] = include_bytes!("fixtures/calendar_reply.ots");

/// The operator genesis key. In production this is loaded from a platform secret
/// reference and its absence is a refusal to boot (§5.2); a fixed seed is fine
/// for a test because the point under test is the signature, not the custody.
fn genesis_key() -> SecretKey {
    SecretKey::from_seed([42u8; 32])
}

fn now() -> Tick {
    Tick::from_i64(1_000_000)
}

/// A distinct signed moment. `n` varies the body hash, so every event has its own
/// `H0` and therefore its own leaf.
fn moment(sk: &SecretKey, n: u8) -> Signed {
    let content = EventContent {
        event_time: Tick::from_i64(i64::from(n)),
        record_time: Tick::from_i64(1_000),
        author: sk.author(),
        supersedes: None,
        body: EventBody::Moment(MomentBody {
            subject: 7,
            body_hash: [n; 32],
        }),
    };
    Signed::sign(sk, content)
}

async fn commit_all(pool: &PgPool, sk: &SecretKey, ns: &[u8]) -> Vec<EventId> {
    let mut ids = Vec::new();
    for n in ns {
        let signed = moment(sk, *n);
        commit(pool, &signed)
            .await
            .expect("commit through the gate");
        ids.push(signed.id());
    }
    ids
}

fn published(outcome: RootOutcome) -> cc_anchor::RootPublication {
    match outcome {
        RootOutcome::Published(p) => p,
        RootOutcome::Unchanged { root, height } => {
            panic!(
                "expected a new root, got the standing one at height {height}: {}",
                root.to_hex()
            )
        }
    }
}

// ===========================================================================
// Determinism: the whole point of a root
// ===========================================================================

/// Two nodes holding the same event set publish the same root, whatever order the
/// events arrived in.
///
/// This is the property the commitment layer exists for. If it did not hold, a
/// mirror could never confirm that it had converged with the node it replicates —
/// it would only ever be able to say "my root differs, and I cannot tell whether
/// that is because I am behind or because you rewrote history".
#[tokio::test]
async fn the_same_event_set_roots_identically_on_two_nodes() {
    let (node_a, cleanup_a) = cc_testkit::ephemeral_db().await;
    let (node_b, cleanup_b) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([1u8; 32]);

    // The same seven events, delivered in opposite orders — the gossip-order
    // difference that Prop. converge tolerates for the view and that a naive
    // insertion-ordered root would not tolerate at all.
    commit_all(&node_a, &sk, &[1, 2, 3, 4, 5, 6, 7]).await;
    commit_all(&node_b, &sk, &[7, 6, 5, 4, 3, 2, 1]).await;

    let a = published(
        publish_root(&node_a, &genesis_key(), now())
            .await
            .expect("publish on A"),
    );
    let b = published(
        publish_root(&node_b, &genesis_key(), now())
            .await
            .expect("publish on B"),
    );

    assert_eq!(a.root, b.root, "same event set must give the same root");
    assert_eq!(a.tree_size, 7);
    assert_eq!(b.tree_size, 7);
    assert_eq!(a.height, 0);
    assert!(a.prev_root.is_none(), "the genesis root extends nothing");
    assert!(a.consistency.is_none());

    node_a.close().await;
    node_b.close().await;
    cleanup_a.cleanup().await;
    cleanup_b.cleanup().await;
}

/// An empty ledger publishes nothing, and a tick with no user writes seals
/// exactly one leaf: the previous root's own recording moment.
///
/// That second half is the heartbeat the §nodezero construction implies and is
/// worth pinning, because it is surprising on first reading — once the stream is
/// running, `Unchanged` stops being reachable. Each tick commits the moment that
/// announced the previous root, which is precisely what turns the consistency
/// chain into settled history rather than a proof bolted on beside the ledger.
#[tokio::test]
async fn an_empty_ledger_publishes_nothing_and_a_quiet_tick_seals_one_leaf() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([2u8; 32]);

    // Before anything is written at all.
    match publish_root(&pool, &genesis_key(), now())
        .await
        .expect("empty tick")
    {
        RootOutcome::Unchanged { height, root } => {
            assert_eq!(height, 0);
            assert_eq!(
                root,
                merkle_root(&[]),
                "the empty tree is not a zero sentinel"
            );
        }
        RootOutcome::Published(p) => panic!("an empty ledger must not publish a root: {p:?}"),
    }
    let roots: i64 = sqlx::query_scalar("SELECT count(*) FROM roots")
        .fetch_one(&pool)
        .await
        .expect("count roots");
    assert_eq!(roots, 0, "no leaves, no root row");

    commit_all(&pool, &sk, &[1, 2]).await;
    let first = published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("first"),
    );
    assert_eq!(first.tree_size, 2);

    // No user writes between these ticks: each seals exactly the previous root's
    // recording moment, and nothing else.
    let second = published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("second"),
    );
    assert_eq!(second.tree_size, 3);
    let third = published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("third"),
    );
    assert_eq!(third.tree_size, 4);
    assert_eq!(
        latest_root(&pool)
            .await
            .expect("latest")
            .expect("some")
            .root,
        third.root
    );
    verify_root_chain(&pool)
        .await
        .expect("the heartbeat chain audits clean");

    pool.close().await;
    cleanup.cleanup().await;
}

// ===========================================================================
// Inclusion
// ===========================================================================

/// Every committed event has an `O(log n)` proof that verifies, and a leaf that
/// was tampered with does not.
#[tokio::test]
async fn inclusion_proofs_verify_and_a_tampered_leaf_does_not() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([3u8; 32]);
    let ids = commit_all(&pool, &sk, &(1..=21u8).collect::<Vec<_>>()).await;

    let root = published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("publish"),
    );
    assert_eq!(root.tree_size, 21);

    for id in &ids {
        let inclusion = prove_event(&pool, id)
            .await
            .expect("every committed event is provable");
        assert!(inclusion.verify(), "proof for {} must verify", id.to_hex());
        assert_eq!(inclusion.root, root.root);
        // O(log n): 21 leaves is a tree of depth 5.
        assert!(
            inclusion.proof.path().len() <= 5,
            "path of {} hashes for 21 leaves is not logarithmic",
            inclusion.proof.path().len()
        );
    }

    // A proof is about ONE leaf. Presenting it for another event's leaf — the
    // forgery the whole structure exists to refuse — must fail.
    let honest = prove_event(&pool, &ids[4]).await.expect("provable");
    let other = prove_event(&pool, &ids[9]).await.expect("provable");
    assert!(!honest.proof.verify(&other.leaf, &honest.root));

    // A flipped bit anywhere in the path breaks it too.
    let mut forged = honest.clone();
    let mut path = forged.proof.path_bytes();
    path[0] ^= 0x01;
    forged.proof = cc_anchor::InclusionProof::from_path_bytes(
        honest.proof.leaf_index(),
        honest.proof.tree_size(),
        &path,
    )
    .expect("well formed");
    assert!(!forged.verify(), "a tampered path must not verify");

    // An event nobody committed is "not committed", which is a different answer
    // from "the proof failed" (memo §5).
    let stranger = EventId::from_bytes([0xEE; 32]);
    assert!(matches!(
        prove_event(&pool, &stranger).await,
        Err(AnchorError::NotCommitted(_))
    ));

    pool.close().await;
    cleanup.cleanup().await;
}

// ===========================================================================
// Consistency
// ===========================================================================

/// Successive roots prove non-removal: root n+1 extends root n, and the whole
/// stream re-derives from the commitment log.
#[tokio::test]
async fn successive_roots_prove_the_log_only_grew() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([4u8; 32]);

    commit_all(&pool, &sk, &[1, 2, 3, 4, 5]).await;
    let first = published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("epoch 0"),
    );
    assert_eq!(first.tree_size, 5);

    commit_all(&pool, &sk, &[6, 7, 8]).await;
    let second = published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("epoch 1"),
    );

    // Three new moments plus the node-0 moment that recorded root 0: the root of
    // snapshot n is committed by snapshot n+1 (§nodezero), never by itself.
    assert_eq!(second.tree_size, 9);
    assert_eq!(second.height, 1);
    assert_eq!(second.prev_root, Some(first.root));

    let proof = second
        .consistency
        .clone()
        .expect("a non-genesis root carries its proof");
    assert!(
        proof.verify(&first.root, &second.root),
        "root 1 must prove that it extends root 0"
    );
    assert_eq!(proof.old_size(), 5);
    assert_eq!(proof.new_size(), 9);

    // The same proof must NOT verify against an unrelated pair of roots.
    assert!(
        !proof.verify(&second.root, &first.root),
        "consistency is directional"
    );
    assert!(!proof.verify(&first.root, &merkle_root(&[])));

    // Served straight from the projection, as a mirror would ask for it.
    let (older, newer, served) = consistency_between(&pool, 0).await.expect("serve the pair");
    assert_eq!((older, newer), (first.root, second.root));
    assert!(served.verify(&older, &newer));

    // And the whole stream re-derives from the log rather than being believed.
    let audit = verify_root_chain(&pool).await.expect("audit");
    assert_eq!(audit.roots_checked, 2);
    assert_eq!(audit.proofs_verified, 1);
    assert_eq!(audit.leaves, 9);
    assert_eq!(
        audit.unrecorded, 0,
        "every root must be recorded as a node-0 moment"
    );

    // A leaf committed under root 0 is still provable under root 0 after root 1
    // exists — the proof of non-removal made concrete.
    let leaves = committed_leaf_count(&pool).await.expect("count");
    assert_eq!(leaves, 9);

    pool.close().await;
    cleanup.cleanup().await;
}

/// A rewritten root is caught by re-derivation, even though `roots` is a mutable
/// projection that an operator can write to directly.
#[tokio::test]
async fn a_rewritten_root_row_fails_the_audit() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([5u8; 32]);
    commit_all(&pool, &sk, &[1, 2, 3]).await;
    let first = published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("epoch 0"),
    );
    verify_root_chain(&pool)
        .await
        .expect("honest chain audits clean");

    // `roots` is a view, so this is allowed by the schema — and must be caught by
    // arithmetic rather than by permissions.
    sqlx::query("UPDATE roots SET root_id = $1 WHERE root_id = $2")
        .bind(vec![0xABu8; 32])
        .bind(first.root.as_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("projections are mutable");

    match verify_root_chain(&pool).await {
        Err(AnchorError::RootMismatch { height, .. }) => assert_eq!(height, 0),
        other => panic!("a rewritten root must fail the audit loudly, got {other:?}"),
    }

    pool.close().await;
    cleanup.cleanup().await;
}

// ===========================================================================
// The commitment log itself
// ===========================================================================

/// The leaf order is append-only at the database level, not by convention.
/// Renumbering one leaf would invalidate every root published after it.
#[tokio::test]
async fn the_commitment_log_refuses_to_be_rewritten() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([6u8; 32]);
    commit_all(&pool, &sk, &[1, 2, 3]).await;
    published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("publish"),
    );

    let update = sqlx::query("UPDATE commitment_log SET seq = seq + 100")
        .execute(&pool)
        .await;
    assert!(update.is_err(), "renumbering a committed leaf must raise");

    let delete = sqlx::query("DELETE FROM commitment_log")
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "dropping a committed leaf must raise");

    let truncate = sqlx::query("TRUNCATE commitment_log").execute(&pool).await;
    assert!(
        truncate.is_err(),
        "truncating the commitment log must raise"
    );

    assert_eq!(committed_leaf_count(&pool).await.expect("count"), 3);

    pool.close().await;
    cleanup.cleanup().await;
}

/// If the `roots` stream is wiped by any means, sealing a new epoch must refuse
/// rather than publish a second "genesis" root over an already-committed log.
#[tokio::test]
async fn a_wiped_root_stream_refuses_to_seal_another_epoch() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([7u8; 32]);
    commit_all(&pool, &sk, &[1, 2, 3]).await;
    published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("publish"),
    );

    sqlx::query("DELETE FROM roots")
        .execute(&pool)
        .await
        .expect("delete roots");

    match publish_root(&pool, &genesis_key(), now()).await {
        Err(AnchorError::RootStreamLost { leaves }) => assert_eq!(leaves, 3),
        other => panic!("expected a loud refusal, got {other:?}"),
    }

    pool.close().await;
    cleanup.cleanup().await;
}

/// ...and `rebuild` must not be one of those means.
///
/// `cc-ledger::rebuild` TRUNCATEd `roots`/`anchors` along with the view tables,
/// on the stated theory that they are projections. They are not: a publication
/// is recorded as a node-0 moment carrying a `body_hash`, which commits to the
/// root without containing it, so no replay of `events` can put a wiped row
/// back. A discardability proof is supposed to show the database is
/// reconstructible — it must not itself make part of it unreconstructible.
#[tokio::test]
async fn rebuild_preserves_the_settlement_history_it_cannot_re_derive() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([21u8; 32]);
    commit_all(&pool, &sk, &[1, 2, 3]).await;
    let root = published(
        publish_root(&pool, &genesis_key(), now())
            .await
            .expect("publish"),
    );

    // The property rebuild exists to prove: the view is a pure fold of `events`.
    cc_ledger::rebuild(&pool).await.expect("rebuild agrees");

    let after = latest_root(&pool)
        .await
        .expect("read back")
        .expect("a root survived");
    assert_eq!(
        after.root, root.root,
        "the published root survived the rebuild"
    );
    assert_eq!(after.tree_size, root.tree_size);
    assert_eq!(after.height, root.height);
    assert_eq!(after.moment, root.moment, "and so did its recording moment");

    // And the ledger is still sealable, rather than parked in RootStreamLost.
    publish_root(&pool, &genesis_key(), now())
        .await
        .expect("sealing still works after a rebuild");

    pool.close().await;
    cleanup.cleanup().await;
}

// ===========================================================================
// The node-0 moments
// ===========================================================================

/// A root publication is a signed event in the ledger, not a table write.
#[tokio::test]
async fn a_root_publication_is_a_signed_node_zero_moment() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([8u8; 32]);
    let key = genesis_key();
    commit_all(&pool, &sk, &[1, 2]).await;

    let root = published(publish_root(&pool, &key, now()).await.expect("publish"));
    let moment = root.moment.expect("the publication must be recorded");

    // It is in the append-only log, signed by the genesis key.
    let row = sqlx::query("SELECT author_key, kind FROM events WHERE event_id = $1")
        .bind(moment.as_bytes().to_vec())
        .fetch_one(&pool)
        .await
        .expect("the recording moment is an ordinary event");
    let author: Vec<u8> = row.try_get("author_key").expect("author");
    assert_eq!(author, key.author().to_bytes().to_vec());

    // It projects as a moment about entity 0 — the constitution is a subgraph.
    let subject: i64 = sqlx::query_scalar("SELECT subject FROM moments WHERE root_event_id = $1")
        .bind(moment.as_bytes().to_vec())
        .fetch_one(&pool)
        .await
        .expect("projected");
    assert_eq!(subject, cc_anchor::NODE_ZERO);

    // And it is NOT a leaf of the tree it announces: it lands in the next epoch.
    let sealed: Option<i64> =
        sqlx::query_scalar("SELECT seq FROM commitment_log WHERE event_id = $1")
            .bind(moment.as_bytes().to_vec())
            .fetch_optional(&pool)
            .await
            .expect("query");
    assert!(
        sealed.is_none(),
        "a root cannot commit to the moment announcing it"
    );

    let second = published(publish_root(&pool, &key, now()).await.expect("epoch 1"));
    let sealed: Option<i64> =
        sqlx::query_scalar("SELECT seq FROM commitment_log WHERE event_id = $1")
            .bind(moment.as_bytes().to_vec())
            .fetch_optional(&pool)
            .await
            .expect("query");
    assert_eq!(
        sealed,
        Some(2),
        "epoch 1 commits epoch 0's recording moment"
    );
    assert_eq!(second.height, 1);

    pool.close().await;
    cleanup.cleanup().await;
}

// ===========================================================================
// The anchor lifecycle
// ===========================================================================

/// The pending -> confirmed lifecycle is two append-only moments and one
/// collapsed projection row.
#[tokio::test]
async fn an_anchor_goes_pending_then_confirmed_without_mutating_history() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([9u8; 32]);
    let key = genesis_key();
    commit_all(&pool, &sk, &[1, 2, 3, 4]).await;
    let root = published(publish_root(&pool, &key, now()).await.expect("publish"));

    let proof = OtsProof::from_calendar_reply(root.root.as_bytes(), CALENDAR_REPLY)
        .expect("a well-formed calendar reply");
    let calendar = "https://a.pool.opentimestamps.org";

    let pending = cc_anchor::record_stamp(&pool, &key, &root.root, &proof, calendar, now())
        .await
        .expect("record the stamp");
    assert_eq!(pending.status, AnchorStatus::Pending);
    assert_eq!(
        pending.block_height, None,
        "a pending anchor claims no block"
    );
    assert_eq!(pending.calendar_url, calendar);
    assert!(pending.age_seconds >= 0);

    // The proof bytes went in by reference and come back verified against their
    // own address.
    let stored = load_proof(&pool, &pending.ots_blob_hash)
        .await
        .expect("stored by reference");
    assert_eq!(stored, proof);

    // Stamping twice would replace evidence, so it is refused.
    assert!(matches!(
        cc_anchor::record_stamp(&pool, &key, &root.root, &proof, calendar, now()).await,
        Err(AnchorError::AnchorState { .. })
    ));

    let confirmed = confirm_anchor(&pool, &key, &root.root, 912_345, None, now())
        .await
        .expect("confirm");
    assert_eq!(confirmed.status, AnchorStatus::Confirmed);
    assert_eq!(confirmed.block_height, Some(912_345));
    assert_ne!(
        confirmed.moment, pending.moment,
        "confirmation is a new event"
    );

    // The pending moment survives as signed history, superseded rather than edited.
    let supersedes: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT supersedes FROM events WHERE event_id = $1")
            .bind(confirmed.moment.as_bytes().to_vec())
            .fetch_one(&pool)
            .await
            .expect("read lineage");
    assert_eq!(supersedes, Some(pending.moment.as_bytes().to_vec()));
    let pending_still_there: i64 =
        sqlx::query_scalar("SELECT count(*) FROM events WHERE event_id = $1")
            .bind(pending.moment.as_bytes().to_vec())
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(pending_still_there, 1);

    // Confirming twice is refused: settlement is recorded once.
    assert!(matches!(
        confirm_anchor(&pool, &key, &root.root, 912_345, None, now()).await,
        Err(AnchorError::AnchorState { .. })
    ));

    // `/health/deep`'s inputs.
    let latest = latest_anchor(&pool)
        .await
        .expect("query")
        .expect("one anchor");
    assert_eq!(latest.root, root.root);
    assert_eq!(latest.status, AnchorStatus::Confirmed);
    assert!(latest.age_seconds >= 0);
    assert_eq!(
        anchor_for(&pool, &root.root).await.expect("query"),
        Some(latest)
    );

    pool.close().await;
    cleanup.cleanup().await;
}

/// An anchor may only be recorded against the root its proof is about.
#[tokio::test]
async fn a_proof_about_another_root_is_refused() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([10u8; 32]);
    let key = genesis_key();
    commit_all(&pool, &sk, &[1, 2]).await;
    let first = published(publish_root(&pool, &key, now()).await.expect("epoch 0"));
    let second = published(publish_root(&pool, &key, now()).await.expect("epoch 1"));

    // A proof built for epoch 1's root, offered for epoch 0's.
    let proof =
        OtsProof::from_calendar_reply(second.root.as_bytes(), CALENDAR_REPLY).expect("well formed");
    assert!(matches!(
        cc_anchor::record_stamp(
            &pool,
            &key,
            &first.root,
            &proof,
            "https://example.test",
            now()
        )
        .await,
        Err(AnchorError::Ots(_))
    ));

    // ...and an unpublished root cannot be anchored at all.
    let never_published = merkle_root(&[]);
    let proof = OtsProof::from_calendar_reply(never_published.as_bytes(), CALENDAR_REPLY)
        .expect("well formed");
    assert!(matches!(
        cc_anchor::record_stamp(
            &pool,
            &key,
            &never_published,
            &proof,
            "https://example.test",
            now()
        )
        .await,
        Err(AnchorError::UnknownRoot(_))
    ));

    assert!(root_at(&pool, 7).await.expect("query").is_none());

    pool.close().await;
    cleanup.cleanup().await;
}

// ===========================================================================
// The network boundary
// ===========================================================================

/// **Requires network.** The one thing the suite above cannot cover: a real
/// submission to the real public calendars.
///
/// Ignored by default so `cargo test` never depends on a third party being up.
/// Run it deliberately:
///
/// ```sh
/// cargo test -p cc-anchor -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "requires network: submits to the public OpenTimestamps calendars"]
async fn a_real_calendar_round_trip_anchors_a_real_root() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let sk = SecretKey::from_seed([11u8; 32]);
    let key = genesis_key();
    commit_all(&pool, &sk, &[1, 2, 3]).await;
    let root = published(publish_root(&pool, &key, now()).await.expect("publish"));

    let calendar = cc_anchor::PUBLIC_CALENDARS[0];
    let record = cc_anchor::anchor_root(&pool, &key, &root.root, calendar, now())
        .await
        .expect("the calendar round-trip");
    assert_eq!(record.status, AnchorStatus::Pending);

    let proof = load_proof(&pool, &record.ots_blob_hash)
        .await
        .expect("stored");
    proof
        .commits_to(root.root.as_bytes())
        .expect("about our root");
    let pending = proof.pending().expect("walk the proof");
    assert!(!pending.is_empty(), "a fresh stamp must name a calendar");
    assert_eq!(
        proof.bitcoin_height().expect("walk"),
        None,
        "a stamp seconds old cannot already be in a block"
    );
    println!(
        "anchored root {} at {calendar}; {} bytes of proof, pending at {}",
        root.root.to_hex(),
        proof.bytes().len(),
        pending[0].0
    );

    // The other half of the network boundary: a commitment made seconds ago is
    // not in a block, and that must read as a state rather than as a failure.
    match cc_anchor::upgrade_anchor(&pool, &key, &root.root, now())
        .await
        .expect("asking the calendar must not error just because Bitcoin is slow")
    {
        cc_anchor::UpgradeOutcome::StillPending(r) => assert_eq!(r.status, AnchorStatus::Pending),
        cc_anchor::UpgradeOutcome::Confirmed(r) => {
            panic!("a stamp seconds old cannot be confirmed: {r:?}")
        }
    }

    pool.close().await;
    cleanup.cleanup().await;
}
