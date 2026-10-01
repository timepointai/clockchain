use cc_core::v1::{receipt::*, *};
use cc_ledger::v1::{analyze, State, Store};
use cc_testkit::v1::*;
use std::collections::BTreeMap;

fn set(events: &[Signed]) -> BTreeMap<Hash, Signed> {
    events.iter().map(|e| (e.id(), e.clone())).collect()
}
#[test]
fn exact_parent_grants_scope_decisions_and_inherited_body() {
    let g = genesis();
    let root = root_grant(g.id());
    let d = delegate(&g, &g, 0, root, 1);
    let child = delegate(&g, &d, 1, d.id(), 2);
    let r = revoke(&g, &child, 0, root, d.id(), false);
    let mut c = correction(&g, &g, 2, 9).envelope().clone();
    c.parents = Set(vec![r.id()]);
    c.grant = Some(child.id());
    if let Payload::Correction { decision, .. } = &mut c.payload {
        decision.parents = c.parents.clone();
    }
    let c = Signed::sign(&key(2), c).unwrap();
    let all = set(&[g.clone(), d.clone(), child.clone(), r.clone(), c.clone()]);
    let view = analyze(&all);
    assert_eq!(view.admission[&c.id()].state, State::Valid);
    assert!(view.authority.active.contains(&child.id()));
    assert!(!view.authority.active.contains(&d.id()));
    for (bad, reason) in [
        (
            revoke(&g, &child, 1, d.id(), root, false),
            "revocation_scope",
        ),
        (
            revoke(&g, &child, 2, child.id(), d.id(), false),
            "revocation_scope",
        ),
        (
            revoke(&g, &child, 2, d.id(), child.id(), false),
            "parent_authority",
        ),
        (delegate(&g, &child, 0, root, 1), "key_not_fresh"),
        (delegate(&g, &g, 1, d.id(), 2), "parent_authority"),
    ] {
        let mut candidates = all.clone();
        candidates.insert(bad.id(), bad.clone());
        assert_eq!(analyze(&candidates).admission[&bad.id()].reason, reason);
    }
    for mutation in 0..5 {
        let mut e = d.envelope().clone();
        if let Payload::Delegate {
            decision, issuer, ..
        } = &mut e.payload
        {
            match mutation {
                0 => *issuer = [88; 32],
                1 => decision.old = Value::ActiveGrant(root),
                2 => decision.new = Value::None,
                3 => decision.parents = Set(vec![]),
                _ => {
                    e.asserted_time = Some(AssertedTime {
                        coordinate: [0; 32],
                        precision: "synthetic".into(),
                    })
                }
            }
        }
        let bad = Signed::sign(&key(0), e).unwrap();
        let mut candidates = all.clone();
        candidates.insert(bad.id(), bad.clone());
        assert_eq!(
            analyze(&candidates).admission[&bad.id()].state,
            State::Invalid
        );
    }
    let mut e = r.envelope().clone();
    if let Payload::Revoke { cascade, .. } = &mut e.payload {
        *cascade = true;
    }
    let bad = Signed::sign(&key(0), e).unwrap();
    let mut candidates = all;
    candidates.insert(bad.id(), bad.clone());
    assert_eq!(
        analyze(&candidates).admission[&bad.id()].reason,
        "decision_mismatch"
    );
}

fn receipt(event: Hash, state: Admission, time: u64) -> SignedReceipt {
    SignedReceipt::sign(
        &key(5),
        NodeReceiptV1 {
            instance: INSTANCE,
            node_key: [0; 32],
            event,
            received_at: time,
            encoding_version: 1,
            // Synthetic test identity, not a production fold manifest/default.
            fold_version: FoldRef {
                version: 65535,
                manifest: [77; 32],
            },
            initial_admission_result: InitialResult {
                state,
                reason: if state == Admission::Valid {
                    ""
                } else {
                    "synthetic_observation"
                }
                .into(),
                missing: Set(vec![]),
            },
        },
    )
    .unwrap()
}
#[tokio::test]
async fn receipts_are_separate_untrusted_observations_and_cannot_install_authority() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let store = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    let g = genesis();
    let root = root_grant(g.id());
    let d = delegate(&g, &g, 0, root, 1);
    let wrong = correction(&g, &g, 1, 10);
    store
        .import(&[
            wrong.bytes().to_vec(),
            d.bytes().to_vec(),
            g.bytes().to_vec(),
        ])
        .await
        .unwrap();
    let before = store.review_authority().await.unwrap();
    // Even a signature claiming "valid" for an invalid event is only an observation.
    for time in [0, u64::MAX] {
        let r = receipt(wrong.id(), Admission::Valid, time);
        store.retain_receipt(r.bytes()).await.unwrap();
        store.retain_receipt(r.bytes()).await.unwrap();
        assert_eq!(before, store.review_authority().await.unwrap());
        // The event ingress cannot be used as a receipt ingress.
        assert!(store.admit(r.bytes()).await.unwrap().event.is_none());
    }
    assert_eq!(before.admission[&wrong.id()].state, State::Invalid);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cc_v1.receipts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let mut bad = receipt(g.id(), Admission::Valid, 1).bytes().to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert!(store.retain_receipt(&bad).await.is_err());
    assert!(store
        .retain_receipt(receipt([44; 32], Admission::Valid, 1).bytes())
        .await
        .is_err());
    let mut foreign = receipt(g.id(), Admission::Valid, 1).receipt().clone();
    foreign.instance = [99; 32];
    assert!(store
        .retain_receipt(SignedReceipt::sign(&key(5), foreign).unwrap().bytes())
        .await
        .is_err());
    for sql in [
        "DELETE FROM cc_v1.receipts",
        "TRUNCATE cc_v1.receipts",
        "UPDATE cc_v1.receipts SET envelope=envelope",
    ] {
        assert!(sqlx::query(sql).execute(&pool).await.is_err());
    }
    assert!(store.readiness().await.is_err());
    pool.close().await;
    cleanup.cleanup().await;
}
#[tokio::test]
async fn concurrent_arrival_recomputes_effective_tombstones_and_replay() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let store = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    let g = genesis();
    let root = root_grant(g.id());
    let d = delegate(&g, &g, 0, root, 1);
    let c = delegate(&g, &d, 1, d.id(), 2);
    let inner = revoke(&g, &c, 1, d.id(), c.id(), true);
    let outer = revoke(&g, &c, 0, root, d.id(), false);
    store
        .import(&[
            g.bytes().to_vec(),
            d.bytes().to_vec(),
            c.bytes().to_vec(),
            inner.bytes().to_vec(),
        ])
        .await
        .unwrap();
    assert!(store
        .review_authority()
        .await
        .unwrap()
        .authority
        .tombstones
        .contains(&c.id()));
    let (a, b) = tokio::join!(store.admit(outer.bytes()), store.admit(inner.bytes()));
    a.unwrap();
    b.unwrap();
    let view = store.review_authority().await.unwrap();
    assert!(view.authority.active.contains(&c.id()));
    assert_eq!(
        view.authority.effects[&inner.id()].reason,
        "revoked_concurrent"
    );
    assert_eq!(
        view.authority.effects[&inner.id()].controlling_revokes,
        std::collections::BTreeSet::from([outer.id()])
    );
    store
        .restore(&[
            outer.bytes().to_vec(),
            inner.bytes().to_vec(),
            c.bytes().to_vec(),
            d.bytes().to_vec(),
            g.bytes().to_vec(),
        ])
        .await
        .unwrap();
    assert_eq!(view, store.review_authority().await.unwrap());
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn stage_a_store_identity_requires_explicit_new_stage_provisioning() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    sqlx::raw_sql("CREATE SCHEMA cc_v1; CREATE TABLE cc_v1.identity(singleton boolean,instance bytea,encoding smallint,schema_hash bytea)")
        .execute(&pool).await.unwrap();
    // Actual Stage (a) bootstrap hash at merged main 3c86ee5.
    sqlx::query("INSERT INTO cc_v1.identity VALUES(true,$1,1,$2)")
        .bind(INSTANCE.to_vec())
        .bind(
            hex::decode("65ee83224cc28a8fcc4d59ce65450ba7462efc440c32d548b2a4c17eaaf5cfda")
                .unwrap(),
        )
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        Store::provision(pool.clone(), INSTANCE).await,
        Err(cc_ledger::v1::Error::Identity)
    ));
    pool.close().await;
    cleanup.cleanup().await;
}
