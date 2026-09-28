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
