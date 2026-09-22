//! M1 projector property tests, all against real Postgres (no mocks).
//!
//! These are the executable form of the whitepaper's convergence claims: the
//! materialized view is a deterministic function of the event SET (never its
//! arrival order), a second node is `replay the other node's events` (union
//! merge), and the database is a discardable view (rebuild reproduces it
//! byte-for-byte). The P(G) transition counters are proven exact against a full
//! recount, and vacuous P(G) is NULL, never a protective-looking 0.0.

use cc_core::{
    AttestationBody, AuthorKey, EdgeBody, EdgeRelation, EntityBirth, EventBody, EventContent,
    EventId, EvidenceClass, ExistenceWindow, MomentBody, SecretKey, Tick, WindowEnd, WindowStart,
};
use cc_ledger::{commit, reproject, view_root, Appended, Signed};

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

fn moment(sk: &SecretKey, subject: i64, t: i64, tag: u8) -> Signed {
    Signed::sign(
        sk,
        EventContent {
            event_time: Tick::from_i64(t),
            record_time: Tick::from_i64(t + 1),
            author: sk.author(),
            supersedes: None,
            body: EventBody::Moment(MomentBody {
                subject,
                body_hash: [tag; 32],
            }),
        },
    )
}

fn edge(sk: &SecretKey, src: i64, dst: i64, t: i64) -> Signed {
    Signed::sign(
        sk,
        EventContent {
            event_time: Tick::from_i64(t),
            record_time: Tick::from_i64(t),
            author: sk.author(),
            supersedes: None,
            body: EventBody::Edge(EdgeBody {
                src,
                dst,
                relation: EdgeRelation::CoOccurrence,
                evidence_class: EvidenceClass::Assertion,
            }),
        },
    )
}

fn attest(sk: &SecretKey, target: EventId) -> Signed {
    Signed::sign(
        sk,
        EventContent {
            event_time: Tick::from_i64(0),
            record_time: Tick::from_i64(500),
            author: sk.author(),
            supersedes: None,
            body: EventBody::Attestation(AttestationBody { target }),
        },
    )
}

/// A fully-specified entity birth (explicit resolution_key, name, and coordinate)
/// for the collision/convergence regression tests.
fn entity_full(sk: &SecretKey, id: i64, reskey: &str, name: &str, t: i64) -> Signed {
    Signed::sign(
        sk,
        EventContent {
            event_time: Tick::from_i64(t),
            record_time: Tick::from_i64(t),
            author: sk.author(),
            supersedes: None,
            body: EventBody::EntityCreate(EntityBirth {
                entity_id: id,
                resolution_key: reskey.into(),
                canonical_name: name.into(),
                window: ExistenceWindow {
                    start: WindowStart::Known(Tick::from_i64(0)),
                    end: WindowEnd::KnownOpen,
                },
            }),
        },
    )
}

/// A small but complete world exercising every kind and the P(G) transition:
/// entities 1,2 authored by A; entity 3 authored by B; two moments; a
/// same-author edge (1->2, cross_writer=false) and a cross-writer edge (2->3,
/// endpoints A and B, cross_writer=true); an attestation of moment 1 by B.
fn world() -> Vec<Signed> {
    let a = key_a();
    let b = key_b();
    let m1 = moment(&a, 1, 100, 1);
    let target = m1.id();
    vec![
        entity(&a, 1, "One"),
        entity(&a, 2, "Two"),
        entity(&b, 3, "Three"),
        m1,
        moment(&a, 2, 200, 2),
        edge(&a, 1, 2, 10), // same-author endpoints  => cross_writer = false
        edge(&a, 2, 3, 20), // endpoints A and B       => cross_writer = true
        attest(&b, target),
    ]
}

async fn view_root_of_order(events: &[Signed]) -> [u8; 32] {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    for e in events {
        commit(&pool, e).await.expect("commit");
    }
    let root = view_root(&pool).await.expect("view_root");
    pool.close().await;
    cleanup.cleanup().await;
    root
}

#[tokio::test]
async fn projection_is_deterministic() {
    let w = world();
    assert_eq!(view_root_of_order(&w).await, view_root_of_order(&w).await);
}

#[tokio::test]
async fn arrival_order_is_irrelevant() {
    let w = world();
    let base = view_root_of_order(&w).await;
    let perms: Vec<Vec<usize>> = vec![
        (0..w.len()).rev().collect(), // reverse
        vec![5, 6, 0, 1, 2, 3, 4, 7], // both edges before their endpoint entities
        vec![7, 3, 5, 0, 6, 2, 1, 4], // attestation and an edge before their targets
        vec![6, 2, 5, 1, 7, 3, 0, 4], // interleaved
    ];
    for p in perms {
        let ordered: Vec<Signed> = p.iter().map(|&i| w[i].clone()).collect();
        assert_eq!(
            view_root_of_order(&ordered).await,
            base,
            "arrival permutation {p:?} produced a different view"
        );
    }
}

#[tokio::test]
async fn union_merge_converges() {
    // Two nodes see overlapping event sets in opposite orders; both, and a fresh
    // projection of the union, converge to one view (Prop. converge, executable).
    let w = world();
    let s1: Vec<Signed> = w[0..5].to_vec();
    let s2: Vec<Signed> = w[3..8].to_vec(); // overlap = {3,4}

    let mut a_order = s1.clone();
    a_order.extend(s2.clone());
    let mut b_order = s2;
    b_order.extend(s1);

    let ra = view_root_of_order(&a_order).await;
    let rb = view_root_of_order(&b_order).await;
    let whole = view_root_of_order(&w).await;
    assert_eq!(ra, rb, "opposite exchange orders must converge");
    assert_eq!(ra, whole, "union merge must equal projecting the whole set");
}

#[tokio::test]
async fn rebuild_equals_incremental() {
    let w = world();
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    for e in &w {
        commit(&pool, e).await.expect("commit");
    }
    let before = view_root(&pool).await.expect("view_root before");
    // rebuild drops the whole view, re-derives from `events`, and returns the
    // rebuilt root only if it matches the live one — the discardability proof.
    let after = cc_ledger::rebuild(&pool)
        .await
        .expect("rebuild must reproduce the view byte-for-byte");
    assert_eq!(before, after);
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn reapply_and_recommit_are_noops() {
    let w = world();
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    for e in &w {
        commit(&pool, e).await.expect("commit");
    }
    let before = view_root(&pool).await.expect("view_root");

    // Re-project several events directly (an entity that completes edges, an
    // edge, a moment) — every reducer is guarded, so this is a no-op.
    for &i in &[0usize, 2, 5, 6, 3] {
        reproject(&pool, &w[i]).await.expect("reproject");
    }
    // Re-committing through the append path unions with no change.
    for e in &w {
        assert_eq!(
            commit(&pool, e).await.expect("re-commit"),
            Appended::Unioned
        );
    }

    assert_eq!(before, view_root(&pool).await.expect("view_root after"));
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn ledger_stats_equals_full_recount() {
    let w = world();
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    for e in &w {
        commit(&pool, e).await.expect("commit");
    }

    let stats = cc_ledger::read_stats(&pool)
        .await
        .expect("read stats")
        .expect("stats row exists");
    // Maintained aggregates match the known world.
    assert_eq!(stats.entity_count, 3);
    assert_eq!(stats.moment_count, 2);
    assert_eq!(stats.edge_count, 2);
    assert_eq!(stats.attestation_count, 1);
    assert_eq!(stats.contested_edges, 2);
    assert_eq!(stats.cross_writer_contested, 1);
    assert_eq!(stats.protected_fraction, Some(0.5));

    // ...and equal a full recount over the projection tables (memo §9: the
    // maintained aggregate the choke point keeps is exact, never a COUNT drift).
    let recount = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(&pool)
                .await
                .expect("recount")
        }
    };
    assert_eq!(
        stats.entity_count,
        recount("SELECT count(*) FROM entities").await
    );
    assert_eq!(
        stats.moment_count,
        recount("SELECT count(*) FROM moments").await
    );
    assert_eq!(
        stats.edge_count,
        recount("SELECT count(*) FROM edges").await
    );
    assert_eq!(
        stats.attestation_count,
        recount("SELECT count(*) FROM attestations").await
    );
    assert_eq!(
        stats.contested_edges,
        recount("SELECT count(*) FROM edges WHERE in_g").await
    );
    assert_eq!(
        stats.cross_writer_contested,
        recount("SELECT count(*) FROM edges WHERE in_g AND cross_writer").await
    );

    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn protected_fraction_is_null_when_no_contested_edges() {
    let a = key_a();
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    // Only entities + a moment: there are no edges, so no contested edges.
    commit(&pool, &entity(&a, 1, "One")).await.expect("commit");
    commit(&pool, &moment(&a, 1, 10, 1)).await.expect("commit");

    let stats = cc_ledger::read_stats(&pool)
        .await
        .expect("read stats")
        .expect("stats row");
    assert_eq!(stats.contested_edges, 0);
    assert_eq!(
        stats.protected_fraction, None,
        "vacuous P(G) must be NULL (Prop. vacuity), never 0.0"
    );

    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn identical_content_from_two_writers_unions_to_one_event() {
    // Two writers assert the identical moment content; it excludes the envelope
    // from H0, so both hash to one event and the first-seen author stands.
    let a = key_a();
    let b = key_b();
    let content = |author: AuthorKey| EventContent {
        event_time: Tick::from_i64(100),
        record_time: Tick::from_i64(1),
        author,
        supersedes: None,
        body: EventBody::Moment(MomentBody {
            subject: 1,
            body_hash: [5u8; 32],
        }),
    };
    let sa = Signed::sign(&a, content(a.author()));
    let sb = Signed::sign(&b, content(b.author()));
    assert_eq!(sa.id(), sb.id(), "identical content => identical H0");

    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    assert_eq!(commit(&pool, &sa).await.expect("commit a"), Appended::New);
    assert_eq!(
        commit(&pool, &sb).await.expect("commit b"),
        Appended::Unioned
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1);
    let author: Vec<u8> = sqlx::query_scalar("SELECT author_key FROM events LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("author");
    assert_eq!(
        author,
        a.author().to_bytes().to_vec(),
        "first-seen proposer stands"
    );

    pool.close().await;
    cleanup.cleanup().await;
}

// --- Regression tests for the adversarial-review findings ------------------

#[tokio::test]
async fn conflicting_entity_births_resolve_to_a_canonical_survivor() {
    // Two DISTINCT signed births claim entity_id 5 (different resolution_key,
    // name, author, coordinate) -> two H0s, both in the event log. The projector
    // must keep the canonically-earliest (min event_time,id) = E1(author A),
    // regardless of arrival order, and repair cross_writer if a non-canonical
    // survivor was seen first. Under the old first-seen-wins reducer, ordering X
    // gave cross_writer_contested=1 and ordering Y gave 0 for the SAME event set.
    let a = key_a();
    let b = key_b();
    let e1 = entity_full(&a, 5, "r5a", "FiveA", 5); // canonical-min (event_time 5)
    let e2 = entity_full(&b, 5, "r5b", "FiveB", 7); // distinct content, same entity_id
    let eb = entity_full(&b, 6, "r6", "Six", 6);
    let ee = edge(&a, 5, 6, 10);

    let order_x = vec![e1.clone(), eb.clone(), ee.clone(), e2.clone()];
    let order_y = vec![e2, eb, ee, e1]; // the "hard" order: non-canonical survivor first
    assert_eq!(
        view_root_of_order(&order_x).await,
        view_root_of_order(&order_y).await,
        "conflicting entity births must converge to the canonical survivor"
    );

    // In the hard order, the canonical survivor is still E1 (author A), so
    // edge(5,6) is cross-writer (A vs B), the counter was repaired, and rebuild
    // reproduces the canonical view.
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    for e in &order_y {
        commit(&pool, e).await.expect("commit");
    }
    let asserter: Vec<u8> = sqlx::query_scalar("SELECT asserter FROM entities WHERE entity_id = 5")
        .fetch_one(&pool)
        .await
        .expect("asserter");
    assert_eq!(
        asserter,
        a.author().to_bytes().to_vec(),
        "canonical survivor = min(event_time,id) = E1(author A)"
    );
    let stats = cc_ledger::read_stats(&pool).await.unwrap().unwrap();
    assert_eq!(stats.entity_count, 2);
    assert_eq!(
        stats.cross_writer_contested, 1,
        "cross_writer repaired after survivor change"
    );
    cc_ledger::rebuild(&pool)
        .await
        .expect("rebuild reproduces the canonical view");
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn distinct_entities_sharing_a_resolution_key_both_project_convergently() {
    // Two DISTINCT entity_ids share a resolution_key. Uniqueness is the M2
    // resolve stage's job, not a DB constraint, so both project — order-
    // independently — rather than the second being silently dropped.
    let a = key_a();
    let b = key_b();
    let e1 = entity_full(&a, 10, "shared", "Ten", 1);
    let e2 = entity_full(&b, 11, "shared", "Eleven", 2);

    let fwd = vec![e1.clone(), e2.clone()];
    let rev = vec![e2, e1];
    assert_eq!(
        view_root_of_order(&fwd).await,
        view_root_of_order(&rev).await,
        "a resolution_key collision must not make the view arrival-order-dependent"
    );

    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    for e in &fwd {
        commit(&pool, e).await.expect("commit");
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM entities")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        n, 2,
        "both entities project; the DB does not enforce uniqueness"
    );
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn rebuild_on_empty_ledger_is_a_noop() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let root = cc_ledger::rebuild(&pool)
        .await
        .expect("rebuild on an empty ledger must not diverge (no seeded stats row)");
    assert_eq!(root, view_root(&pool).await.expect("view_root"));
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn sign_binds_attribution_to_the_actual_signer() {
    // Content claims author = B, but it is signed with A. sign() must overwrite
    // the author to A, so the stored event is attributed to the real signer and
    // passes the verifying gate (rebuild re-verifies every stored signature).
    let a = key_a();
    let b = key_b();
    let content = EventContent {
        event_time: Tick::from_i64(1),
        record_time: Tick::from_i64(1),
        author: b.author(), // a lie the gate must not honor
        supersedes: None,
        body: EventBody::Moment(MomentBody {
            subject: 1,
            body_hash: [0u8; 32],
        }),
    };
    let signed = Signed::sign(&a, content);

    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    commit(&pool, &signed).await.expect("commit");
    let author: Vec<u8> = sqlx::query_scalar("SELECT author_key FROM events LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("author");
    assert_eq!(
        author,
        a.author().to_bytes().to_vec(),
        "sign() must bind attribution to the actual signer, not the claimed author"
    );
    cc_ledger::rebuild(&pool)
        .await
        .expect("stored signature verifies under the stored author key");
    pool.close().await;
    cleanup.cleanup().await;
}

// ===========================================================================
// The maintained event-set digest (migration 0006)
// ===========================================================================

/// Read the trigger-maintained accumulator.
async fn digest_row(pool: &sqlx::PgPool) -> (i64, Vec<u8>) {
    let r: (i64, Vec<u8>) = sqlx::query_as("SELECT n, acc FROM event_digest WHERE id = true")
        .fetch_one(pool)
        .await
        .expect("event_digest row");
    r
}

/// The maintained digest must equal a fold recomputed from `events`.
///
/// This is the property the whole design rests on: the read path trusts one row
/// instead of scanning, so that row has to be the same answer the scan would
/// give. If the trigger ever misses an insert — or double-counts one, which XOR
/// would silently turn into a *deletion* — this is what catches it.
#[tokio::test]
async fn the_maintained_digest_equals_a_recomputed_fold() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let a = key_a();

    let (n0, acc0) = digest_row(&pool).await;
    assert_eq!(n0, 0, "a fresh ledger has folded nothing");
    assert_eq!(acc0, vec![0u8; 32], "and its accumulator is the identity");

    for i in 1..=25i64 {
        commit(&pool, &entity(&a, i, &format!("e{i}")))
            .await
            .expect("commit entity");
        commit(&pool, &moment(&a, i, i, i as u8))
            .await
            .expect("commit moment");
    }

    let (n, acc) = digest_row(&pool).await;
    let real: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, real, "count drifted from the event table");
    assert_ne!(
        acc,
        vec![0u8; 32],
        "50 events must not fold to the identity"
    );

    // Fold it again, independently, one row at a time.
    let ids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT sha256('cc.corpus.elem.v0'::bytea || event_id) FROM events ORDER BY random()",
    )
    .fetch_all(&pool)
    .await
    .expect("elements");
    let mut check = [0u8; 32];
    for e in &ids {
        for (c, b) in check.iter_mut().zip(e.iter()) {
            *c ^= b;
        }
    }
    assert_eq!(acc, check.to_vec(), "maintained accumulator != recomputed");

    pool.close().await;
    cleanup.cleanup().await;
}

/// Two nodes given the same events in opposite orders agree on the digest.
///
/// Order independence is the reason the accumulator is a XOR and not a running
/// hash chain: the digest names a SET, and two peers that gossiped the same
/// events in different orders must not conclude they are looking at different
/// corpora.
#[tokio::test]
async fn the_digest_is_a_function_of_the_event_set_not_its_order() {
    let (node_a, cleanup_a) = cc_testkit::ephemeral_db().await;
    let (node_b, cleanup_b) = cc_testkit::ephemeral_db().await;
    let k = key_a();

    let events: Vec<_> = (1..=12i64)
        .map(|i| entity(&k, i, &format!("e{i}")))
        .collect();
    for s in events.iter() {
        commit(&node_a, s).await.expect("A");
    }
    for s in events.iter().rev() {
        commit(&node_b, s).await.expect("B");
    }

    assert_eq!(
        digest_row(&node_a).await,
        digest_row(&node_b).await,
        "arrival order must not change the corpus digest"
    );

    node_a.close().await;
    node_b.close().await;
    cleanup_a.cleanup().await;
    cleanup_b.cleanup().await;
}

/// `reproject` must not disturb the digest.
///
/// This is the trap that kept the fold out of the projector: XOR is an
/// involution, so applying one event twice REMOVES it. `reproject` exists to
/// prove projector idempotence, and if the digest were maintained there, the
/// very act of proving idempotence would corrupt the corpus identity.
#[tokio::test]
async fn reprojecting_an_event_does_not_disturb_the_digest() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let e = entity(&k, 7, "seven");
    commit(&pool, &e).await.expect("commit");

    let before = digest_row(&pool).await;
    reproject(&pool, &e).await.expect("reproject");
    reproject(&pool, &e).await.expect("reproject twice");
    // And a duplicate commit, which unions rather than inserting.
    commit(&pool, &e).await.expect("re-commit");
    assert_eq!(
        before,
        digest_row(&pool).await,
        "digest moved on a re-apply"
    );

    pool.close().await;
    cleanup.cleanup().await;
}

/// `rebuild` must leave the digest alone: it is a function of `events`, and
/// `rebuild` never touches `events`.
#[tokio::test]
async fn rebuild_does_not_disturb_the_digest() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    for i in 1..=6i64 {
        commit(&pool, &entity(&k, i, &format!("e{i}")))
            .await
            .expect("commit");
    }
    let before = digest_row(&pool).await;
    cc_ledger::rebuild(&pool).await.expect("rebuild");
    assert_eq!(before, digest_row(&pool).await);

    pool.close().await;
    cleanup.cleanup().await;
}

/// A vocabulary declaration must land in the `vocabulary` projection.
#[tokio::test]
async fn a_vocabulary_declaration_projects() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let k = key_a();
    let content = EventContent {
        event_time: Tick::from_i64(1),
        record_time: Tick::from_i64(1),
        author: k.author(),
        supersedes: None,
        body: EventBody::VocabularyDeclare(cc_core::VocabularyEntry {
            claim_type: 7,
            label: "tax:co-located".into(),
            band: ExistenceWindow {
                start: WindowStart::Known(Tick::from_i64(0)),
                end: WindowEnd::KnownOpen,
            },
        }),
    };
    let signed = Signed::sign(&k, content);
    commit(&pool, &signed).await.expect("commit declaration");

    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM vocabulary")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1, "the declaration did not project");

    let (code, label): (i64, String) = sqlx::query_as("SELECT claim_type, label FROM vocabulary")
        .fetch_one(&pool)
        .await
        .expect("row");
    assert_eq!(code, 7);
    assert_eq!(label, "tax:co-located");

    pool.close().await;
    cleanup.cleanup().await;
}
