use cc_core::v1::*;
use cc_ledger::v1::{classify, State, Store};
use cc_testkit::v1::*;
use std::collections::BTreeMap;

#[test]
fn i4_subject_key_immutable_across_all_transitions() {
    let g = genesis();
    let c = correction(&g, &g, 0, 5);
    for part in 0..3 {
        for kind in [
            Kind::Correction,
            Kind::Delegate,
            Kind::Revoke,
            Kind::Resolve,
        ] {
            let mut e = c.envelope().clone();
            let k = e.subject_key.as_mut().unwrap();
            match part {
                0 => k.kind.push('x'),
                1 => k.namespace.push('x'),
                _ => k.value.push('x'),
            }
            let mut d = e.payload.decision().unwrap().clone();
            d.kind = kind;
            e.payload = match kind {
                Kind::Correction => Payload::Correction {
                    body: [5; 32],
                    decision: d,
                },
                Kind::Delegate => Payload::Delegate {
                    grantee: key(1).author().to_bytes(),
                    issuer: root_grant(g.id()),
                    decision: d,
                },
                Kind::Revoke => Payload::Revoke {
                    target: root_grant(g.id()),
                    cascade: true,
                    decision: d,
                },
                Kind::Resolve => {
                    e.parents = Set(vec![g.id(), c.id()]);
                    e.parents.0.sort();
                    Payload::Resolve {
                        selection: Selection::Revision(revision_id(g.id(), g.id())),
                        dispositions: Set(vec![]),
                        decision: d,
                    }
                }
                _ => unreachable!(),
            };
            let changed = Signed::sign(&key(0), e).unwrap();
            let set = BTreeMap::from([
                (g.id(), g.clone()),
                (c.id(), c.clone()),
                (changed.id(), changed.clone()),
            ]);
            assert_eq!(classify(&set)[&changed.id()].reason, "subject_key_changed");
        }
    }
    let mut other = g.envelope().clone();
    if let Payload::Genesis { nonce, .. } = &mut other.payload {
        *nonce = [99; 32];
    }
    let other = Signed::sign(&key(0), other).unwrap();
    let mut e = c.envelope().clone();
    e.subject = Some(other.id());
    let wrong = Signed::sign(&key(0), e).unwrap();
    assert_eq!(
        classify(&BTreeMap::from([
            (g.id(), g),
            (other.id(), other),
            (wrong.id(), wrong.clone())
        ]))[&wrong.id()]
            .reason,
        "wrong_subject"
    );
}

#[tokio::test]
async fn candidates_replay_pending_invalid_and_rejections_are_retained() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let store = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    assert!(store.readiness().is_err());
    let g = genesis();
    let c = correction(&g, &g, 0, 5);
    let wrong = correction(&g, &g, 1, 6);
    assert_eq!(
        store.admit(c.bytes()).await.unwrap().status.reason,
        "parent_missing"
    );
    store.admit(g.bytes()).await.unwrap();
    assert_eq!(store.review().await.unwrap()[&c.id()].state, State::Valid);
    let rejected = store.admit(wrong.bytes()).await.unwrap();
    assert_eq!(rejected.status.reason, "parent_authority");
    assert_eq!(rejected.event, Some(wrong.id()));
    let mut bad = c.bytes().to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        store.admit(&bad).await.unwrap().status.reason,
        "bad_signature"
    );
    assert_eq!(
        store.admit(c.bytes()).await.unwrap().status.state,
        State::Valid
    );
    let all = vec![
        g.bytes().to_vec(),
        c.bytes().to_vec(),
        wrong.bytes().to_vec(),
    ];
    let before = store.review().await.unwrap();
    store.restore(&all).await.unwrap();
    assert_eq!(before, store.review().await.unwrap());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cc_v1.candidates")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 3);
    let rejected: i64 = sqlx::query_scalar("SELECT count(*) FROM cc_v1.rejections")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejected, 1);
    for table in ["identity", "candidates", "rejections"] {
        assert!(sqlx::query(&format!("DELETE FROM cc_v1.{table}"))
            .execute(&pool)
            .await
            .is_err());
        assert!(sqlx::query(&format!("TRUNCATE cc_v1.{table}"))
            .execute(&pool)
            .await
            .is_err());
    }
    assert!(Store::provision(pool.clone(), [99; 32]).await.is_err());
    assert!(Store::provision(pool.clone(), INSTANCE).await.is_ok());
    // Database-owner tampering is outside signer authority, but replay must
    // detect a row key that disagrees with the signed event's content identity.
    sqlx::query("INSERT INTO cc_v1.candidates(event_id,envelope) VALUES($1,$2)")
        .bind(vec![88u8; 32])
        .bind(g.bytes())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store.review().await,
        Err(cc_ledger::v1::Error::Corrupt)
    ));
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn v1_fresh_store_refuses_even_empty_v0_projection() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    assert!(matches!(
        Store::provision(pool.clone(), INSTANCE).await,
        Err(cc_ledger::v1::Error::NotEmpty)
    ));
    pool.close().await;
    cleanup.cleanup().await;
}

#[tokio::test]
async fn resolve_is_checked_while_later_stages_cannot_grant_readiness() {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let store = Store::provision(pool.clone(), INSTANCE).await.unwrap();
    let g = genesis();
    store.admit(g.bytes()).await.unwrap();
    let mut e = correction(&g, &g, 0, 5).envelope().clone();
    let mut d = e.payload.decision().unwrap().clone();
    let c = correction(&g, &g, 0, 6);
    store.admit(c.bytes()).await.unwrap();
    e.parents = Set(vec![g.id(), c.id()]);
    e.parents.0.sort();
    d.parents = e.parents.clone();
    d.kind = Kind::Resolve;
    e.payload = Payload::Resolve {
        selection: Selection::MergedBody([5; 32]),
        dispositions: Set(vec![]),
        decision: d,
    };
    let event = Signed::sign(&key(0), e).unwrap();
    let result = store.admit(event.bytes()).await.unwrap();
    assert_eq!(result.status.state, State::Invalid);
    assert_eq!(result.status.reason, "comparable_parents");
    let mut attestation = g.envelope().clone();
    attestation.subject_key = None;
    attestation.payload = Payload::Attestation {
        target_kind: TargetKind::Event,
        target: g.id(),
        artifact_kind: "synthetic".into(),
        artifact: [44; 32],
    };
    let attestation = Signed::sign(&key(0), attestation).unwrap();
    let result = store.admit(attestation.bytes()).await.unwrap();
    assert_eq!(result.status.state, State::Pending);
    assert_eq!(result.status.reason, "stage_d_not_implemented");
    assert!(store.readiness().is_err());
    let media: bool = sqlx::query_scalar("SELECT to_regclass('public.media') IS NOT NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!media);
    pool.close().await;
    cleanup.cleanup().await;
}
