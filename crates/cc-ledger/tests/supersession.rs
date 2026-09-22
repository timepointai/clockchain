//! M1b — the supersession chain-fold, against real Postgres.
//!
//! Every test here would have passed against the M1 projector for the wrong
//! reason if it only asserted "a moment projects": M1 wrote a row per moment
//! event, so a chain of three produced three live rows and nothing marked which
//! one won. These assert the four properties that were the actual work —
//! **held-not-dropped arrival order, a canonical survivor among conflicting
//! corrections, a `moment_count` that counts chains, and a `rebuild` that
//! reproduces the fold** — and each one fails loudly against the old projector.

use cc_core::{
    AttestationBody, AuthorKey, EdgeBody, EdgeRelation, EntityBirth, EventBody, EventContent,
    EventId, EvidenceClass, ExistenceWindow, MomentBody, SecretKey, Signature, Tick,
    VocabularyEntry, WindowEnd, WindowStart,
};
use cc_ledger::{commit, rebuild, reproject, view_root, Signed};
use sqlx::{PgPool, Row};

fn key_a() -> SecretKey {
    SecretKey::from_seed([0xAA; 32])
}
fn key_b() -> SecretKey {
    SecretKey::from_seed([0xBB; 32])
}

fn entity(sk: &SecretKey, id: i64, name: &str) -> Signed {
    Signed::sign(
        sk,
        EventContent {
            event_time: Tick::from_i64(id),
            record_time: Tick::from_i64(id),
            author: sk.author(),
            supersedes: None,
            body: EventBody::EntityCreate(EntityBirth {
                entity_id: id,
                resolution_key: format!("res-{id}"),
                canonical_name: name.into(),
                window: ExistenceWindow {
                    start: WindowStart::Known(Tick::from_i64(0)),
                    end: WindowEnd::KnownOpen,
                },
            }),
        },
    )
}

/// A moment, optionally correcting an earlier one.
fn moment(sk: &SecretKey, subject: i64, t: i64, tag: u8, supersedes: Option<EventId>) -> Signed {
    Signed::sign(
        sk,
        EventContent {
            event_time: Tick::from_i64(t),
            record_time: Tick::from_i64(t + 1),
            author: sk.author(),
            supersedes,
            body: EventBody::Moment(MomentBody {
                subject,
                body_hash: [tag; 32],
            }),
        },
    )
}

async fn rows(pool: &PgPool) -> Vec<(Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>)> {
    sqlx::query(
        "SELECT root_event_id, head_event_id, subject, body_hash, author_key \
         FROM moments ORDER BY root_event_id",
    )
    .fetch_all(pool)
    .await
    .expect("read moments")
    .into_iter()
    .map(|r| {
        (
            r.get("root_event_id"),
            r.get("head_event_id"),
            r.get("subject"),
            r.get("body_hash"),
            r.get("author_key"),
        )
    })
    .collect()
}

async fn moment_count(pool: &PgPool) -> i64 {
    cc_ledger::read_stats(pool)
        .await
        .expect("read stats")
        .map(|s| s.moment_count)
        .unwrap_or(0)
}

async fn recount(pool: &PgPool) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM moments")
        .fetch_one(pool)
        .await
        .expect("recount")
}

// ===========================================================================
// The fold itself.
// ===========================================================================

/// A correction is ONE row: keyed by the root, carrying the head's reading.
/// Against the M1 projector this produced two live rows on one subject with
/// nothing saying which was current — the defect M1b exists to remove.
#[tokio::test]
async fn a_correction_folds_into_one_row() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let e = entity(&key_a(), 1, "Subject");
    let m1 = moment(&key_a(), 1, 10, 0x11, None);
    let m2 = moment(&key_a(), 1, 10, 0x22, Some(m1.id()));
    for s in [&e, &m1, &m2] {
        commit(&pool, s).await.expect("commit");
    }

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1, "a two-event chain must project one row");
    assert_eq!(
        r[0].0,
        m1.id().as_bytes().to_vec(),
        "root is the chain root"
    );
    assert_eq!(
        r[0].1,
        m2.id().as_bytes().to_vec(),
        "head is the correction"
    );
    assert_eq!(r[0].3, vec![0x22; 32], "the head's reading survives");
    assert_eq!(moment_count(&pool).await, 1);
    cleanup.cleanup().await;
}

/// The whole row follows the head, `author_key` included — and the reason is
/// not symmetry, it is that the published triple has to verify.
///
/// This test's first version asserted the opposite: `author_key` from the root,
/// "first-seen proposer" per the schema comment. It passed. What it could not
/// see is that `/v1/recents` joins `signature` from the event named by
/// `head_event_id` and publishes it beside `author_key` under the sentence *"the
/// holder of author_key signed this event id"*. Root attribution keeps that
/// sentence's shape and destroys its truth — every corrected moment would ship a
/// key that did not sign the id it is printed next to, and a consumer running
/// Ed25519 over the three published fields would get a failure.
///
/// So the assertion below is not `author_key == B`. It is **the verification a
/// consumer actually performs**, run against the bytes the row holds. A test
/// that compares the column to an expected key is a value check on the column;
/// only running the signature check tests the claim the API prints.
#[tokio::test]
async fn the_published_triple_verifies_for_a_corrected_moment() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let (a, b) = (key_a(), key_b());
    let e = entity(&a, 1, "Subject");
    let m1 = moment(&a, 1, 10, 0x11, None);
    let m2 = moment(&b, 1, 10, 0x22, Some(m1.id())); // corrected by the OTHER writer
    for s in [&e, &m1, &m2] {
        commit(&pool, s).await.expect("commit");
    }

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].3, vec![0x22; 32], "B's reading is the live one");

    // Exactly what /v1/recents assembles: head_event_id from `moments`,
    // signature from the event that id names, author_key from `moments`.
    let head = EventId::from_bytes(r[0].1.clone().try_into().expect("32 bytes"));
    let sig_bytes: Vec<u8> = sqlx::query_scalar("SELECT signature FROM events WHERE event_id = $1")
        .bind(head.as_bytes().to_vec())
        .fetch_one(&pool)
        .await
        .expect("the head event carries the signature the API publishes");
    let author = AuthorKey::from_bytes(&r[0].4.clone().try_into().expect("32 bytes"))
        .expect("author_key is a valid verifying key");
    let sig = Signature::from_bytes(sig_bytes.try_into().expect("64 bytes"));

    cc_core::verify(&author, head.as_bytes(), &sig)
        .expect("the published (head_event_id, author_key, signature) triple must verify");

    // ...and it is B's key, because B signed the surviving reading.
    assert_eq!(r[0].4, b.author().to_bytes().to_vec());
    // The first assertion stays reachable the symmetric way.
    let root_author: Vec<u8> =
        sqlx::query_scalar("SELECT author_key FROM events WHERE event_id = $1")
            .bind(r[0].0.clone())
            .fetch_one(&pool)
            .await
            .expect("root event");
    assert_eq!(
        root_author,
        a.author().to_bytes().to_vec(),
        "root_event_id recovers who asserted it first"
    );
    cleanup.cleanup().await;
}

/// Three deep. The head is the end of the chain, not the second link.
#[tokio::test]
async fn a_chain_folds_to_its_deepest_link() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let e = entity(&k, 1, "Subject");
    let m1 = moment(&k, 1, 10, 0x11, None);
    let m2 = moment(&k, 1, 10, 0x22, Some(m1.id()));
    let m3 = moment(&k, 1, 10, 0x33, Some(m2.id()));
    for s in [&e, &m1, &m2, &m3] {
        commit(&pool, s).await.expect("commit");
    }

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1, m3.id().as_bytes().to_vec());
    assert_eq!(r[0].3, vec![0x33; 32]);
    assert_eq!(moment_count(&pool).await, 1);
    cleanup.cleanup().await;
}

// ===========================================================================
// Hard part 1 — arrival order. Held, never dropped, never a root of its own.
// ===========================================================================

/// A correction whose target has not arrived is **held**: no row, no counter
/// movement — and durable in `events`, so the arrival that completes the chain
/// projects it. Projecting it as a root of its own instead would leave a second
/// live row that the target's arrival could never merge away.
#[tokio::test]
async fn a_correction_arriving_before_its_target_is_held_not_dropped() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let m1 = moment(&k, 1, 10, 0x11, None);
    let m2 = moment(&k, 1, 10, 0x22, Some(m1.id()));

    commit(&pool, &entity(&k, 1, "Subject")).await.expect("e");
    commit(&pool, &m2)
        .await
        .expect("commit the correction first");

    assert_eq!(rows(&pool).await.len(), 0, "held: no row");
    assert_eq!(moment_count(&pool).await, 0, "held: no count");
    let durable: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE event_id = $1")
        .bind(m2.id().as_bytes().to_vec())
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        durable, 1,
        "held is not dropped — the event is in the ledger"
    );

    commit(&pool, &m1).await.expect("the target arrives");
    let r = rows(&pool).await;
    assert_eq!(r.len(), 1, "the arrival picks the held correction up");
    assert_eq!(r[0].0, m1.id().as_bytes().to_vec());
    assert_eq!(r[0].1, m2.id().as_bytes().to_vec());
    assert_eq!(moment_count(&pool).await, 1, "counted exactly once, late");
    cleanup.cleanup().await;
}

/// Two held links, then the root: the forward walk must traverse the whole
/// buried chain, not just the link that names the arriving event.
#[tokio::test]
async fn a_chain_that_arrives_entirely_backwards_still_folds() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let m1 = moment(&k, 1, 10, 0x11, None);
    let m2 = moment(&k, 1, 10, 0x22, Some(m1.id()));
    let m3 = moment(&k, 1, 10, 0x33, Some(m2.id()));

    commit(&pool, &entity(&k, 1, "Subject")).await.expect("e");
    for s in [&m3, &m2] {
        commit(&pool, s).await.expect("commit");
        assert_eq!(rows(&pool).await.len(), 0, "still held");
    }
    commit(&pool, &m1).await.expect("root last");

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].1,
        m3.id().as_bytes().to_vec(),
        "head is the deepest link"
    );
    assert_eq!(moment_count(&pool).await, 1);
    cleanup.cleanup().await;
}

/// The property in its strongest form: every one of the 24 orderings of a
/// four-event world containing a three-long chain produces the byte-identical
/// view.
///
/// **Digest agreement alone is not enough**, and asserting only that was this
/// test's first version. The M1 projector passed it — it wrote a row per moment
/// event, consistently, in every order, so 24 identical *wrong* views agreed
/// perfectly. Agreement is a shape check; it takes the row count and the head
/// to make it a value check, and only the value check can tell a fold from a
/// pile.
#[tokio::test]
async fn every_arrival_order_of_a_chain_gives_the_same_view() {
    let k = key_a();
    let e = entity(&k, 1, "Subject");
    let m1 = moment(&k, 1, 10, 0x11, None);
    let m2 = moment(&k, 1, 10, 0x22, Some(m1.id()));
    let m3 = moment(&k, 1, 10, 0x33, Some(m2.id()));
    let world = [&e, &m1, &m2, &m3];

    let mut digests = Vec::new();
    let orders = permutations(4);
    assert_eq!(orders.len(), 24, "every ordering, not a sample");
    for p in orders {
        let (pool, cleanup) = cc_testkit::ephemeral_db().await;
        for i in p {
            commit(&pool, world[i]).await.expect("commit");
        }
        let r = rows(&pool).await;
        assert_eq!(r.len(), 1, "one chain is one row, in every arrival order");
        assert_eq!(r[0].0, m1.id().as_bytes().to_vec(), "root");
        assert_eq!(r[0].1, m3.id().as_bytes().to_vec(), "head");
        assert_eq!(moment_count(&pool).await, 1);
        digests.push(view_root(&pool).await.expect("root"));
        cleanup.cleanup().await;
    }
    assert!(
        digests.windows(2).all(|w| w[0] == w[1]),
        "the view must be a function of the event SET, not its arrival order"
    );
}

fn permutations(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![vec![]];
    }
    let mut out = Vec::new();
    for p in permutations(n - 1) {
        for i in 0..n {
            let mut q = p.clone();
            q.insert(i, n - 1);
            out.push(q);
        }
    }
    out
}

// ===========================================================================
// Hard part 2 — conflicting corrections resolve canonically.
// ===========================================================================

/// Two corrections of the same moment. The survivor is the canonically-earliest
/// `(event_time, event_id)` — the rule conflicting entity births already use,
/// and the order `rebuild` folds in, so incremental and batch cannot diverge.
/// The loser gets **no row of its own**: it is a rejected correction, not a
/// second moment.
#[tokio::test]
async fn conflicting_corrections_resolve_to_the_canonically_earliest() {
    let k = key_a();
    let e = entity(&k, 1, "Subject");
    let m1 = moment(&k, 1, 10, 0x11, None);
    let early = moment(&k, 1, 20, 0x22, Some(m1.id()));
    let late = moment(&k, 1, 30, 0x33, Some(m1.id()));

    // Commit them in both orders; the survivor must not depend on which landed.
    for order in [[&early, &late], [&late, &early]] {
        let (pool, cleanup) = cc_testkit::ephemeral_db().await;
        for s in [&e, &m1] {
            commit(&pool, s).await.expect("commit");
        }
        for s in order {
            commit(&pool, s).await.expect("commit");
        }
        let r = rows(&pool).await;
        assert_eq!(r.len(), 1, "a rejected correction is not a second moment");
        assert_eq!(r[0].1, early.id().as_bytes().to_vec(), "earliest survives");
        assert_eq!(moment_count(&pool).await, 1);
        cleanup.cleanup().await;
    }
}

/// The tiebreak that only fires when `event_time` cannot decide. Two
/// corrections at the identical coordinate: `event_id` breaks it, and Postgres'
/// `bytea` order is the byte order Rust compares, so the test names the winner
/// independently of the query that picks it.
#[tokio::test]
async fn a_tie_on_event_time_is_broken_by_event_id() {
    let k = key_a();
    let e = entity(&k, 1, "Subject");
    let m1 = moment(&k, 1, 10, 0x11, None);
    let a = moment(&k, 1, 20, 0xA1, Some(m1.id()));
    let b = moment(&k, 1, 20, 0xB2, Some(m1.id()));
    let expected = if a.id().as_bytes() < b.id().as_bytes() {
        a.id()
    } else {
        b.id()
    };

    for order in [[&a, &b], [&b, &a]] {
        let (pool, cleanup) = cc_testkit::ephemeral_db().await;
        for s in [&e, &m1] {
            commit(&pool, s).await.expect("commit");
        }
        for s in order {
            commit(&pool, s).await.expect("commit");
        }
        let r = rows(&pool).await;
        assert_eq!(r.len(), 1);
        assert_eq!(
            r[0].1,
            expected.as_bytes().to_vec(),
            "smaller event_id wins"
        );
        cleanup.cleanup().await;
    }
}

/// A correction of the *losing* branch stays off the canonical path — it does
/// not sneak in as a deeper head, and it does not become a root.
#[tokio::test]
async fn descendants_of_a_rejected_correction_stay_off_the_canonical_path() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let e = entity(&k, 1, "Subject");
    let m1 = moment(&k, 1, 10, 0x11, None);
    let winner = moment(&k, 1, 20, 0x22, Some(m1.id()));
    let loser = moment(&k, 1, 30, 0x33, Some(m1.id()));
    let loser_child = moment(&k, 1, 40, 0x44, Some(loser.id()));
    for s in [&e, &m1, &winner, &loser, &loser_child] {
        commit(&pool, s).await.expect("commit");
    }

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1, winner.id().as_bytes().to_vec());
    assert_eq!(moment_count(&pool).await, 1);
    cleanup.cleanup().await;
}

// ===========================================================================
// Hard part 3 — counting.
// ===========================================================================

/// `moment_count` counts CHAINS, so it equals `count(*) FROM moments`. That is
/// the invariant `/health/deep` publishes against, and the one that broke when
/// a counter with no decrement path served 351 over a table holding 321.
#[tokio::test]
async fn moment_count_counts_chains_and_equals_a_full_recount() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    commit(&pool, &entity(&k, 1, "One")).await.expect("e1");
    commit(&pool, &entity(&k, 2, "Two")).await.expect("e2");

    // Subject 1: a three-long chain. Subject 2: two independent moments.
    let a1 = moment(&k, 1, 10, 0x11, None);
    let a2 = moment(&k, 1, 10, 0x22, Some(a1.id()));
    let a3 = moment(&k, 1, 10, 0x33, Some(a2.id()));
    let b1 = moment(&k, 2, 50, 0x55, None);
    let b2 = moment(&k, 2, 60, 0x66, None);
    // ...plus a held correction of an event this node has never seen.
    let ghost = moment(&k, 2, 70, 0x77, None);
    let orphan = moment(&k, 2, 80, 0x88, Some(ghost.id()));

    for s in [&a1, &a2, &a3, &b1, &b2, &orphan] {
        commit(&pool, s).await.expect("commit");
    }

    assert_eq!(recount(&pool).await, 3, "one chain + two independents");
    assert_eq!(
        moment_count(&pool).await,
        3,
        "the counter agrees with the table"
    );

    // Six moment events; three chains. The gap is real and is exactly the
    // corrections plus the held orphan — not a drifted counter.
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE kind = 2")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(events, 6);
    cleanup.cleanup().await;
}

/// Re-applying any event of a chain moves no counter and changes no byte.
/// The row is a pure function of the event set, so every member projects it.
#[tokio::test]
async fn reprojecting_any_link_of_a_chain_is_a_noop() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let e = entity(&k, 1, "Subject");
    let m1 = moment(&k, 1, 10, 0x11, None);
    let m2 = moment(&k, 1, 20, 0x22, Some(m1.id()));
    let m3 = moment(&k, 1, 30, 0x33, Some(m2.id()));
    for s in [&e, &m1, &m2, &m3] {
        commit(&pool, s).await.expect("commit");
    }
    let before = view_root(&pool).await.expect("root");

    for s in [&m1, &m2, &m3, &m1] {
        reproject(&pool, s).await.expect("reproject");
        assert_eq!(
            view_root(&pool).await.expect("root"),
            before,
            "re-applying a link must not disturb the fold"
        );
    }
    assert_eq!(moment_count(&pool).await, 1);
    cleanup.cleanup().await;
}

// ===========================================================================
// Hard part 4 — rebuild reproduces the fold. The discardability proof.
// ===========================================================================

/// The proof that survives M1b: truncate every projection, re-fold `events` in
/// canonical order, and get the same 32 bytes — with chains, conflicts and a
/// held orphan in the world, in an arrival order that is not the fold order.
#[tokio::test]
async fn rebuild_equals_incremental_with_chains_conflicts_and_a_held_orphan() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let (a, b) = (key_a(), key_b());
    let e1 = entity(&a, 1, "One");
    let e2 = entity(&b, 2, "Two");
    let c1 = moment(&a, 1, 10, 0x11, None);
    let c2 = moment(&b, 1, 30, 0x22, Some(c1.id()));
    let c3 = moment(&a, 1, 40, 0x33, Some(c2.id()));
    let rival = moment(&b, 1, 50, 0x44, Some(c1.id())); // loses to c2
    let d1 = moment(&b, 2, 20, 0x55, None);
    let ghost = moment(&a, 2, 60, 0x66, None); // never committed
    let orphan = moment(&a, 2, 70, 0x77, Some(ghost.id()));

    // Deliberately not canonical order: corrections before targets, the rival
    // before the winner, the orphan before anything it could attach to.
    for s in [&orphan, &c3, &rival, &e2, &c2, &d1, &c1, &e1] {
        commit(&pool, s).await.expect("commit");
    }
    let incremental = view_root(&pool).await.expect("root");
    let r = rows(&pool).await;
    assert_eq!(
        r.len(),
        2,
        "one chain on subject 1, one moment on subject 2"
    );
    assert_eq!(
        r.iter().find(|x| x.2 == 1).expect("subject 1").1,
        c3.id().as_bytes().to_vec(),
        "head is the deepest canonical link"
    );

    let after = rebuild(&pool).await.expect("rebuild must not diverge");
    assert_eq!(
        after, incremental,
        "rebuild reproduces the fold byte-for-byte"
    );
    assert_eq!(moment_count(&pool).await, 2);
    assert_eq!(recount(&pool).await, 2);
    cleanup.cleanup().await;
}

// ===========================================================================
// Ill-formed lineage.
// ===========================================================================

/// A moment may only supersede a moment. A lineage pointing at an entity birth
/// is ill-formed, and ill-formed lineage is treated as NO lineage: the moment
/// becomes its own root rather than being discarded. Dropping it would make the
/// projection lossy in a way `rebuild` could not repair, and holding it forever
/// would hide a valid signed claim behind a malformed field.
#[tokio::test]
async fn a_moment_superseding_a_non_moment_becomes_its_own_root() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let e = entity(&k, 1, "Subject");
    let m = moment(&k, 1, 10, 0x11, Some(e.id()));
    for s in [&e, &m] {
        commit(&pool, s).await.expect("commit");
    }

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].0, m.id().as_bytes().to_vec(), "its own root");
    assert_eq!(r[0].1, m.id().as_bytes().to_vec(), "root == head");
    assert_eq!(moment_count(&pool).await, 1);

    let before = view_root(&pool).await.expect("root");
    assert_eq!(rebuild(&pool).await.expect("rebuild"), before);
    cleanup.cleanup().await;
}

/// The same, one link further down: the malformed link is the root, and the
/// correction below it still folds into it.
#[tokio::test]
async fn a_chain_rooted_at_a_malformed_link_still_folds_below_it() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let e = entity(&k, 1, "Subject");
    let bad = moment(&k, 1, 10, 0x11, Some(e.id()));
    let fix = moment(&k, 1, 20, 0x22, Some(bad.id()));
    for s in [&e, &bad, &fix] {
        commit(&pool, s).await.expect("commit");
    }

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].0, bad.id().as_bytes().to_vec());
    assert_eq!(r[0].1, fix.id().as_bytes().to_vec());
    assert_eq!(moment_count(&pool).await, 1);
    cleanup.cleanup().await;
}

// ===========================================================================
// The no-op guarantee for the live chain.
// ===========================================================================

/// Every moment on the live chain carries `supersedes = NULL` — 0 of 1176
/// events at the time M1b landed — so the fold must write byte-identical rows
/// to what M1 wrote. This pins that: a world with no supersession anywhere
/// projects root == head on every row, and the digest is stable across rebuild.
#[tokio::test]
async fn a_world_with_no_supersession_is_unchanged_by_the_fold() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let (a, b) = (key_a(), key_b());
    for s in [
        &entity(&a, 1, "One"),
        &entity(&b, 2, "Two"),
        &moment(&a, 1, 10, 0x11, None),
        &moment(&b, 2, 20, 0x22, None),
        &moment(&a, 1, 30, 0x33, None),
    ] {
        commit(&pool, s).await.expect("commit");
    }

    for r in rows(&pool).await {
        assert_eq!(r.0, r.1, "root == head where nothing supersedes anything");
    }
    assert_eq!(moment_count(&pool).await, 3);
    assert_eq!(recount(&pool).await, 3);
    let before = view_root(&pool).await.expect("root");
    assert_eq!(rebuild(&pool).await.expect("rebuild"), before);
    cleanup.cleanup().await;
}

// ===========================================================================
// A DECIDED policy question. Ruled by timepoint-telemetry.
// ===========================================================================

/// `subject` follows the head, so a correction naming a different entity moves
/// the row there. **Decided: permissive, with a recorded decision at mint
/// time.** This test's doc comment said "undecided" for about an hour; the
/// ruling is telemetry's and the reasoning is worth keeping:
///
/// 1. The fold's coherence depends on every column following the head. Carving
///    out `subject` produces a **chimera row** — the head's `body_hash`, whose
///    claim body may name entity B, filed under the root's subject A. That is
///    worse than either alternative originally weighed.
/// 2. Mis-attribution is a real error class and supersession is this ledger's
///    only correction mechanism. Refusing subject-moves re-introduces two live
///    rows for precisely the error corrections exist to fix.
/// 3. Enforcing sameness would put payload parsing inside `held-moments.py`'s
///    SQL walk — permanent mirror drift, which is the hazard class P1 exists to
///    check for.
///
/// **The condition: a subject-moving correction is a RECORDED DECISION**, an
/// artifact naming old subject, new subject and evidence, written at mint time.
/// Bind the writer, not the projector — we are the only writer. This is the
/// identity doctrine applied one level up: the projector stays automatic on
/// exact structure, and anything that moves MEANING gets a decision naming its
/// resolver and evidence. **Silent data movement is cured by making it
/// non-silent, not by making it impossible.** The same ruling governs the time
/// axis: `coord` and `posture` follow the head too, and a coordinate-moving
/// correction needs the same artifact — see
/// `a_correction_may_carry_an_earlier_coordinate_than_its_target` for why that
/// one moves a row across `as_of` windows.
///
/// TT has no supersession vocabulary (§7 excludes ordering and correction
/// semantics as consumer-local), so this is consumer-contract, not spec.
#[tokio::test]
async fn a_correction_may_move_its_subject_by_recorded_decision() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let m1 = moment(&k, 1, 10, 0x11, None);
    let m2 = moment(&k, 2, 20, 0x22, Some(m1.id())); // same chain, different subject
    for s in [&entity(&k, 1, "One"), &entity(&k, 2, "Two"), &m1, &m2] {
        commit(&pool, s).await.expect("commit");
    }

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1, "still one chain, one row");
    assert_eq!(r[0].0, m1.id().as_bytes().to_vec(), "keyed by the root");
    assert_eq!(r[0].2, 2, "and it now belongs to entity 2, not entity 1");
    assert_eq!(moment_count(&pool).await, 1);

    // Whatever the policy turns out to be, it has to survive a rebuild.
    let before = view_root(&pool).await.expect("root");
    assert_eq!(rebuild(&pool).await.expect("rebuild"), before);
    cleanup.cleanup().await;
}

// ===========================================================================
// The gaps timepoint-telemetry named in P2.
// ===========================================================================

fn window() -> ExistenceWindow {
    ExistenceWindow {
        start: WindowStart::Known(Tick::from_i64(0)),
        end: WindowEnd::KnownOpen,
    }
}

/// Every non-moment kind, so the ill-formed-lineage branch is kind-COMPLETE.
///
/// The two existing tests only ever superseded an entity birth. They exercise
/// the same single `kind != Moment` check, so this adds no new logic — which is
/// exactly why it is worth having: it costs one loop, and "we tested the branch
/// with one of five inputs" is how a later special-case for one kind gets added
/// without anyone noticing the others were never covered. Telemetry's call.
#[tokio::test]
async fn superseding_any_non_moment_kind_yields_its_own_root() {
    let k = key_a();
    let targets: Vec<(&str, EventBody)> = vec![
        (
            "entity birth",
            EventBody::EntityCreate(EntityBirth {
                entity_id: 7,
                resolution_key: "res-7".into(),
                canonical_name: "Seven".into(),
                window: window(),
            }),
        ),
        (
            "edge",
            EventBody::Edge(EdgeBody {
                src: 1,
                dst: 2,
                relation: EdgeRelation::CoOccurrence,
                evidence_class: EvidenceClass::Assertion,
            }),
        ),
        (
            "vocabulary declaration",
            EventBody::VocabularyDeclare(VocabularyEntry {
                claim_type: 4242,
                label: "a-test-type".into(),
                band: window(),
            }),
        ),
    ];

    for (what, body) in targets {
        let (pool, cleanup) = cc_testkit::ephemeral_db().await;
        for e in [&entity(&k, 1, "One"), &entity(&k, 2, "Two")] {
            commit(&pool, e).await.expect("commit");
        }
        let target = Signed::sign(
            &k,
            EventContent {
                event_time: Tick::from_i64(5),
                record_time: Tick::from_i64(5),
                author: k.author(),
                supersedes: None,
                body,
            },
        );
        commit(&pool, &target).await.expect("commit target");

        let m = moment(&k, 1, 10, 0x11, Some(target.id()));
        commit(&pool, &m).await.expect("commit moment");

        let r = rows(&pool).await;
        assert_eq!(r.len(), 1, "{what}: one row");
        assert_eq!(r[0].0, m.id().as_bytes().to_vec(), "{what}: its own root");
        assert_eq!(r[0].1, m.id().as_bytes().to_vec(), "{what}: root == head");
        assert_eq!(moment_count(&pool).await, 1, "{what}: counted once");
        cleanup.cleanup().await;
    }

    // ...and the fourth kind, an attestation, which needs a target to attest.
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let e = entity(&k, 1, "One");
    commit(&pool, &e).await.expect("commit");
    let att = Signed::sign(
        &k,
        EventContent {
            event_time: Tick::from_i64(5),
            record_time: Tick::from_i64(5),
            author: k.author(),
            supersedes: None,
            body: EventBody::Attestation(AttestationBody { target: e.id() }),
        },
    );
    commit(&pool, &att).await.expect("commit attestation");
    let m = moment(&k, 1, 10, 0x11, Some(att.id()));
    commit(&pool, &m).await.expect("commit moment");
    let r = rows(&pool).await;
    assert_eq!(r.len(), 1, "attestation: one row");
    assert_eq!(r[0].0, m.id().as_bytes().to_vec(), "attestation: own root");
    cleanup.cleanup().await;
}

/// Re-applying a HELD event stays a silent no-op. The path — `chain_root`
/// returns `None`, `project_moment` returns `Ok(())` — looks obviously correct,
/// which is the reason to pin it rather than the reason not to.
#[tokio::test]
async fn reprojecting_a_held_event_is_a_noop() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let ghost = moment(&k, 1, 10, 0x11, None); // never committed
    let orphan = moment(&k, 1, 20, 0x22, Some(ghost.id()));
    commit(&pool, &entity(&k, 1, "One")).await.expect("e");
    commit(&pool, &orphan).await.expect("commit the orphan");

    let before = view_root(&pool).await.expect("root");
    assert_eq!(rows(&pool).await.len(), 0, "held");
    for _ in 0..3 {
        reproject(&pool, &orphan).await.expect("reproject held");
        assert_eq!(view_root(&pool).await.expect("root"), before);
    }
    assert_eq!(moment_count(&pool).await, 0, "still uncounted");
    cleanup.cleanup().await;
}

/// A correction whose `event_time` is EARLIER than the moment it corrects.
///
/// Entirely legal: `event_time` is the historical coordinate, not the time the
/// correction was made, so fixing a claim's date from 1962 to 1955 produces
/// exactly this. Both walks are structural and neither compares a child's
/// coordinate to its parent's, so it folds — but every other test here uses
/// increasing coordinates, and time is where this fold is least intuitive.
///
/// It also demonstrates the consequence recorded in `api.rs`: `coord` follows
/// the head, so this correction MOVES THE ROW ACROSS `as_of` WINDOWS. A
/// consumer querying `coord <= 1960` sees the moment appear where it previously
/// was not, with no event inside that window to explain it.
#[tokio::test]
async fn a_correction_may_carry_an_earlier_coordinate_than_its_target() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let m1 = moment(&k, 1, 1962, 0x11, None);
    let m2 = moment(&k, 1, 1955, 0x22, Some(m1.id()));
    for s in [&entity(&k, 1, "One"), &m1, &m2] {
        commit(&pool, s).await.expect("commit");
    }

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].1,
        m2.id().as_bytes().to_vec(),
        "the earlier one is head"
    );

    // The window consequence, asserted rather than described.
    let in_1960: i64 = sqlx::query_scalar("SELECT count(*) FROM moments WHERE coord <= $1")
        .bind(Tick::from_i64(1960).to_canon_bytes().to_vec())
        .fetch_one(&pool)
        .await
        .expect("window query");
    assert_eq!(
        in_1960, 1,
        "the row moved INTO a window it was not in before"
    );

    let before = view_root(&pool).await.expect("root");
    assert_eq!(rebuild(&pool).await.expect("rebuild"), before);
    cleanup.cleanup().await;
}

/// **A correction must supersede the HEAD, not the root.** Correcting a moment
/// that has already been corrected, by naming the original event again,
/// produces a canonically-later sibling — and a later sibling loses.
///
/// This is the most operationally dangerous property of the fold and it is not
/// visible from the rule that produces it. The rejected correction is stored,
/// signed and durable, and it is invisible: no row, no error, no counter, and
/// nothing on any published surface saying a correction was refused. It is
/// found by telemetry's P2.
///
/// The test asserts both halves: naming the root loses, and naming the head
/// wins. The minting pipeline has to read the current `head_event_id`;
/// `ops/held-moments.py` prints the rejected count so the failure is at least
/// countable if it ever happens.
#[tokio::test]
async fn correcting_a_stale_target_loses_silently() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let m1 = moment(&k, 1, 10, 0x11, None);
    let first = moment(&k, 1, 20, 0x22, Some(m1.id()));
    let stale = moment(&k, 1, 30, 0x33, Some(m1.id())); // names the ROOT again
    for s in [&entity(&k, 1, "One"), &m1, &first, &stale] {
        commit(&pool, s).await.expect("commit");
    }

    let r = rows(&pool).await;
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].1,
        first.id().as_bytes().to_vec(),
        "the stale correction lost to the earlier sibling"
    );
    assert_eq!(
        r[0].3,
        vec![0x22; 32],
        "and its reading is not the live one"
    );

    // Stored, signed, durable — and invisible.
    let durable: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE event_id = $1")
        .bind(stale.id().as_bytes().to_vec())
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(durable, 1, "the rejected correction IS in the ledger");
    assert_eq!(moment_count(&pool).await, 1, "and moves no counter");

    // The way to actually win: supersede the head.
    let correct = moment(&k, 1, 40, 0x44, Some(first.id()));
    commit(&pool, &correct).await.expect("commit");
    let r = rows(&pool).await;
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].1,
        correct.id().as_bytes().to_vec(),
        "naming the head wins"
    );
    assert_eq!(r[0].3, vec![0x44; 32]);
    cleanup.cleanup().await;
}
