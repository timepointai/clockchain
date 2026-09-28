//! Characterization of direct-import rebinding, NOT a new fold validity rule.
//! All fixtures are synthetic; node HTTP admission is deliberately bypassed.
use cc_core::{
    EdgeBody, EdgeRelation, EntityBirth, EventBody, EventContent, EvidenceClass, ExistenceWindow,
    MomentBody, SecretKey, Tick, WindowEnd, WindowStart,
};
use cc_ledger::{commit, rebuild, view_root, Appended, Signed};

fn signed(key: &SecretKey, at: i64, body: EventBody) -> Signed {
    Signed::sign(
        key,
        EventContent {
            event_time: Tick::from_i64(at),
            record_time: Tick::from_i64(at),
            author: key.author(),
            supersedes: None,
            body,
        },
    )
}

fn permutations(indices: &mut [usize], at: usize, output: &mut Vec<Vec<usize>>) {
    if at == indices.len() {
        output.push(indices.to_vec());
        return;
    }
    for i in at..indices.len() {
        indices.swap(at, i);
        permutations(indices, at + 1, output);
        indices.swap(at, i);
    }
}

async fn characterize_rebinding(supersedes: bool) {
    let key = SecretKey::from_seed([81; 32]);
    let birth = |id| {
        signed(
            &key,
            0,
            EventBody::EntityCreate(EntityBirth {
                entity_id: id,
                resolution_key: format!("synthetic:{id}"),
                canonical_name: format!("Synthetic entity {id}"),
                window: ExistenceWindow {
                    start: WindowStart::Known(Tick::from_i64(0)),
                    end: WindowEnd::KnownOpen,
                },
            }),
        )
    };
    let h1 = signed(
        &key,
        1,
        EventBody::Moment(MomentBody {
            subject: 2,
            body_hash: [1; 32],
        }),
    );
    let edge = signed(
        &key,
        2,
        EventBody::Edge(EdgeBody {
            src: 1,
            dst: 2,
            relation: EdgeRelation::Influence,
            evidence_class: EvidenceClass::SecondarySource,
        }),
    );
    let mut replacement = EventContent {
        event_time: Tick::from_i64(3),
        record_time: Tick::from_i64(3),
        author: key.author(),
        supersedes: None,
        body: EventBody::Moment(MomentBody {
            subject: 2,
            body_hash: [2; 32],
        }),
    };
    if supersedes {
        replacement.supersedes = Some(h1.id());
    }
    let h2 = Signed::sign(&key, replacement);
    // Natural order is E/F births, H1, incident edge, then H2. Every permutation
    // also covers edges before births and a superseding child before its parent.
    let events = [birth(1), birth(2), h1.clone(), edge.clone(), h2.clone()];
    let mut orders = Vec::new();
    permutations(&mut [0, 1, 2, 3, 4], 0, &mut orders);
    assert_eq!(orders.len(), 120);
    let mut expected_root = None;
    for order in orders {
        let (pool, cleanup) = cc_testkit::ephemeral_db().await;
        for &i in &order {
            assert_eq!(commit(&pool, &events[i]).await.unwrap(), Appended::New);
        }
        let bodies: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT body_hash FROM moments WHERE subject=2 ORDER BY body_hash")
                .fetch_all(&pool)
                .await
                .unwrap();
        if supersedes {
            assert_eq!(bodies, vec![vec![2; 32]], "order {order:?}");
            let lineage: (Vec<u8>, Vec<u8>) =
                sqlx::query_as("SELECT root_event_id, head_event_id FROM moments WHERE subject=2")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(
                lineage,
                (h1.id().as_bytes().to_vec(), h2.id().as_bytes().to_vec())
            );
        } else {
            assert_eq!(bodies, vec![vec![1; 32], vec![2; 32]], "order {order:?}");
        }
        // The edge stays present, targets E, and is not marked as a rebinding
        // conflict. Status 0 means proposed, not conflict; in_g stays true.
        let projected_edge: (i64, i64, i16, i16, bool) = sqlx::query_as(
            "SELECT src_entity,dst_entity,relation,status,in_g FROM edges WHERE edge_id=$1",
        )
        .bind(edge.id().as_bytes().to_vec())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            projected_edge,
            (1, 2, EdgeRelation::Influence as i16, 0, true)
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM events")
                .fetch_one(&pool)
                .await
                .unwrap(),
            5
        );
        let root = view_root(&pool).await.unwrap();
        assert_eq!(
            *expected_root.get_or_insert(root),
            root,
            "arrival order {order:?}"
        );
        assert_eq!(
            rebuild(&pool).await.unwrap(),
            root,
            "rebuild for order {order:?}"
        );
        assert_eq!(commit(&pool, &h2).await.unwrap(), Appended::Unioned);
        assert_eq!(view_root(&pool).await.unwrap(), root);
        pool.close().await;
        cleanup.cleanup().await;
    }
}

#[tokio::test]
async fn direct_import_parallel_rebinding_keeps_both_bodies_and_edge_in_all_orders() {
    characterize_rebinding(false).await;
}

#[tokio::test]
async fn direct_import_superseding_rebinding_keeps_h2_and_edge_in_all_orders() {
    characterize_rebinding(true).await;
}

fn birth(key: &SecretKey, id: i64) -> Signed {
    signed(
        key,
        0,
        EventBody::EntityCreate(EntityBirth {
            entity_id: id,
            resolution_key: format!("synthetic:{id}"),
            canonical_name: format!("Synthetic entity {id}"),
            window: ExistenceWindow {
                start: WindowStart::Known(Tick::from_i64(0)),
                end: WindowEnd::KnownOpen,
            },
        }),
    )
}

fn correction(key: &SecretKey, parent: &Signed, subject: i64, tag: u8, at: i64) -> Signed {
    Signed::sign(
        key,
        EventContent {
            event_time: Tick::from_i64(at),
            record_time: Tick::from_i64(40),
            author: key.author(),
            supersedes: Some(parent.id()),
            body: EventBody::Moment(MomentBody {
                subject,
                body_hash: [tag; 32],
            }),
        },
    )
}

async fn projected_head(pool: &sqlx::PgPool) -> (Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    sqlx::query_as(
        "SELECT head_event_id,subject,body_hash,coord,record_coord,author_key FROM moments",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// This characterizes the absence of signer authorization in the fold. The
/// second key is a valid signer, not an actor authenticated as a subject owner.
/// known_gap characterization: current behavior, not a policy requirement.
/// A fix under issue #6 may intentionally change this expectation.
#[tokio::test]
async fn backdated_cross_author_sibling_wins_and_hides_the_other_in_all_720_orders() {
    let a = SecretKey::from_seed([83; 32]);
    let b = SecretKey::from_seed([84; 32]);
    let root = signed(
        &a,
        10,
        EventBody::Moment(MomentBody {
            subject: 2,
            body_hash: [1; 32],
        }),
    );
    let edge = signed(
        &a,
        11,
        EventBody::Edge(EdgeBody {
            src: 1,
            dst: 2,
            relation: EdgeRelation::Influence,
            evidence_class: EvidenceClass::SecondarySource,
        }),
    );
    let original_writer = correction(&a, &root, 2, 2, 30);
    let other_writer = correction(&b, &root, 2, 3, -5);
    let events = [
        birth(&a, 1),
        birth(&a, 2),
        root,
        edge,
        original_writer.clone(),
        other_writer.clone(),
    ];
    let mut orders = Vec::new();
    permutations(&mut [0, 1, 2, 3, 4, 5], 0, &mut orders);
    assert_eq!(orders.len(), 720);
    let mut expected_root = None;
    for order in orders {
        let (pool, cleanup) = cc_testkit::ephemeral_db().await;
        for &i in &order {
            assert_eq!(commit(&pool, &events[i]).await.unwrap(), Appended::New);
        }
        assert_eq!(
            projected_head(&pool).await,
            (
                other_writer.id().as_bytes().to_vec(),
                2,
                vec![3; 32],
                Tick::from_i64(-5).to_canon_bytes().to_vec(),
                Tick::from_i64(40).to_canon_bytes().to_vec(),
                b.author().to_bytes().to_vec()
            )
        );
        // Losing evidence remains stored but has no projected head or conflict.
        let loser: (bool, bool) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM events WHERE event_id=$1), EXISTS(SELECT 1 FROM moments WHERE head_event_id=$1)")
            .bind(original_writer.id().as_bytes().to_vec()).fetch_one(&pool).await.unwrap();
        assert_eq!(loser, (true, false));
        let incident: (i64, i16, bool) = sqlx::query_as("SELECT dst_entity,status,in_g FROM edges")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(incident, (2, 0, true));
        let digest = view_root(&pool).await.unwrap();
        assert_eq!(
            *expected_root.get_or_insert(digest),
            digest,
            "order {order:?}"
        );
        assert_eq!(rebuild(&pool).await.unwrap(), digest);
        assert_eq!(
            commit(&pool, &original_writer).await.unwrap(),
            Appended::Unioned
        );
        assert_eq!(
            commit(&pool, &other_writer).await.unwrap(),
            Appended::Unioned
        );
        assert_eq!(view_root(&pool).await.unwrap(), digest);
        pool.close().await;
        cleanup.cleanup().await;
    }
}

/// known_gap characterization: current behavior, not a policy requirement.
/// A fix under issue #6 may intentionally change this expectation.
#[tokio::test]
async fn subject_moving_correction_leaves_incident_edge_on_old_entity_in_all_720_orders() {
    let key = SecretKey::from_seed([85; 32]);
    let h1 = signed(
        &key,
        10,
        EventBody::Moment(MomentBody {
            subject: 2,
            body_hash: [1; 32],
        }),
    );
    let edge = signed(
        &key,
        11,
        EventBody::Edge(EdgeBody {
            src: 1,
            dst: 2,
            relation: EdgeRelation::Influence,
            evidence_class: EvidenceClass::SecondarySource,
        }),
    );
    let h2 = correction(&key, &h1, 3, 2, 30);
    // The recorded-decision doctrine is a writer obligation. No decision
    // artifact is supplied here: the current fold neither requires nor reads it.
    let events = [
        birth(&key, 1),
        birth(&key, 2),
        birth(&key, 3),
        h1,
        edge,
        h2.clone(),
    ];
    let mut orders = Vec::new();
    permutations(&mut [0, 1, 2, 3, 4, 5], 0, &mut orders);
    assert_eq!(orders.len(), 720);
    let mut expected_root = None;
    for order in orders {
        let (pool, cleanup) = cc_testkit::ephemeral_db().await;
        for &i in &order {
            assert_eq!(commit(&pool, &events[i]).await.unwrap(), Appended::New);
        }
        assert_eq!(
            projected_head(&pool).await,
            (
                h2.id().as_bytes().to_vec(),
                3,
                vec![2; 32],
                Tick::from_i64(30).to_canon_bytes().to_vec(),
                Tick::from_i64(40).to_canon_bytes().to_vec(),
                key.author().to_bytes().to_vec()
            )
        );
        let incident: (i64, i64, i16, bool) =
            sqlx::query_as("SELECT src_entity,dst_entity,status,in_g FROM edges")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(incident, (1, 2, 0, true));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM moments WHERE subject=2")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        let digest = view_root(&pool).await.unwrap();
        assert_eq!(
            *expected_root.get_or_insert(digest),
            digest,
            "order {order:?}"
        );
        assert_eq!(rebuild(&pool).await.unwrap(), digest);
        assert_eq!(commit(&pool, &h2).await.unwrap(), Appended::Unioned);
        assert_eq!(view_root(&pool).await.unwrap(), digest);
        pool.close().await;
        cleanup.cleanup().await;
    }
}

/// known_gap characterization: current behavior, not a policy requirement.
/// A fix under issue #6 may intentionally change this expectation.
#[tokio::test]
async fn original_writer_attestation_does_not_select_a_losing_correction() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let a = SecretKey::from_seed([86; 32]);
    let b = SecretKey::from_seed([87; 32]);
    let root = signed(
        &a,
        10,
        EventBody::Moment(MomentBody {
            subject: 2,
            body_hash: [1; 32],
        }),
    );
    let losing = correction(&a, &root, 2, 2, 30);
    let winning = correction(&b, &root, 2, 3, -5);
    for event in [&birth(&a, 2), &root, &losing, &winning] {
        commit(&pool, event).await.unwrap();
    }
    let before = projected_head(&pool).await;
    let attestation = signed(
        &a,
        50,
        EventBody::Attestation(cc_core::AttestationBody {
            target: losing.id(),
        }),
    );
    commit(&pool, &attestation).await.unwrap();
    assert_eq!(projected_head(&pool).await, before);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM attestations WHERE target=$1")
            .bind(losing.id().as_bytes().to_vec())
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    let digest = view_root(&pool).await.unwrap();
    assert_eq!(rebuild(&pool).await.unwrap(), digest);
    assert_eq!(projected_head(&pool).await, before);
    pool.close().await;
    cleanup.cleanup().await;
}
