//! Stage (c): full model fold, including Resolve and every status/reason.
//! Stage (e): named I1/I2/I6 traces against the model and the real store.
use cc_core::v1::*;
use cc_ledger::v1::{classify, project, Projection, ProjectionState, Snapshot, Store};
use cc_testkit::v1::*;
use serde_json::{json, Value as Json};
use std::{collections::BTreeMap, process::Command};

static KEYS: std::sync::LazyLock<[Hash; 7]> =
    std::sync::LazyLock::new(|| std::array::from_fn(|i| key(i as u8).author().to_bytes()));

fn wire(
    events: &[Json],
    base: &Envelope,
    times: u8,
    cache: &mut BTreeMap<Vec<u8>, Signed>,
) -> Vec<Signed> {
    let mut signed: Vec<Signed> = vec![];
    let mut bodies = vec![];
    for (i, event) in events.iter().enumerate() {
        let author = event["key"].as_u64().unwrap() as u8;
        let kind = event["kind"].as_str().unwrap();
        let grant_ref = |n: usize| {
            if n == 0 {
                root_grant(signed[0].id())
            } else {
                signed[n].id()
            }
        };
        let mut e = base.clone();
        e.author = KEYS[author as usize];
        let body = if kind == "G" || kind == "C" || kind == "S" {
            [i as u8 + 3; 32]
        } else {
            bodies[event["parents"][0].as_u64().unwrap() as usize]
        };
        if kind != "G" {
            let p = event["parents"][0].as_u64().unwrap() as usize;
            e.subject = Some(signed[0].id());
            let grant = grant_ref(event["grant"].as_u64().unwrap() as usize);
            e.grant = Some(grant);
            e.parents = Set(event["parents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| signed[p.as_u64().unwrap() as usize].id())
                .collect());
            e.parents.0.sort();
            let mut d = Decision {
                kind: Kind::Correction,
                rationale: format!("Synthetic operation {i}"),
                evidence: Set(vec![[4; 32]]),
                parents: e.parents.clone(),
                old: Value::Body(bodies[p]),
                new: Value::Body(body),
            };
            let target = event["target"].as_i64().unwrap();
            e.payload = match kind {
                "C" => Payload::Correction { body, decision: d },
                "D" => {
                    let grantee = KEYS[target as usize];
                    d.kind = Kind::Delegate;
                    d.old = Value::None;
                    d.new = Value::Grant {
                        issuer: grant,
                        grantee,
                    };
                    Payload::Delegate {
                        grantee,
                        issuer: grant,
                        decision: d,
                    }
                }
                "R" => {
                    let target = grant_ref(target as usize);
                    let cascade = event["cascade"].as_bool().unwrap();
                    d.kind = Kind::Revoke;
                    d.old = Value::ActiveGrant(target);
                    d.new = Value::RevokedGrant {
                        grant: target,
                        cascade,
                    };
                    Payload::Revoke {
                        target,
                        cascade,
                        decision: d,
                    }
                }
                "S" => {
                    d.kind = Kind::Resolve;
                    d.old = Value::Heads(e.parents.clone());
                    let dispositions = Set(e
                        .parents
                        .0
                        .iter()
                        .map(|&parent| Disposition {
                            parent,
                            action: DispositionKind::Merged,
                            rationale: "Synthetic merge".into(),
                        })
                        .collect());
                    Payload::Resolve {
                        selection: Selection::MergedBody(body),
                        dispositions,
                        decision: d,
                    }
                }
                _ => unreachable!(),
            };
        }
        if kind == "G" || kind == "C" || kind == "S" {
            e.asserted_time = Some(AssertedTime {
                coordinate: [match times {
                    0 => i as u8,
                    1 => 255 - i as u8,
                    _ => 128,
                }; 32],
                precision: "synthetic".into(),
            });
        }
        let bytes = e.preimage().unwrap();
        let s = cache
            .entry(bytes)
            .or_insert_with(|| Signed::sign(&key(author), e).unwrap())
            .clone();
        signed.push(s);
        bodies.push(body);
    }
    signed
}
fn normalize(view: Projection, signed: &[Signed]) -> Json {
    let mut ids: BTreeMap<_, _> = signed
        .iter()
        .enumerate()
        .map(|(i, e)| (e.id(), i))
        .collect();
    ids.insert(root_grant(signed[0].id()), 0);
    let mut rows: Vec<_> = view
        .rows
        .iter()
        .map(|r| {
            let state = match r.state {
                ProjectionState::Head => "head",
                ProjectionState::Superseded => "superseded",
                ProjectionState::Branch => "branch",
                ProjectionState::Invalid => "invalid",
                ProjectionState::Pending => "pending",
            };
            json!([ids[&r.event], state, r.reason])
        })
        .collect();
    rows.sort_by_key(|r| r[0].as_u64());
    let resolve: Vec<_> = rows
        .iter()
        .filter(|r| {
            signed[r[0].as_u64().unwrap() as usize]
                .envelope()
                .payload
                .kind()
                == Kind::Resolve
        })
        .map(|r| {
            if r[1] == "invalid" || r[1] == "pending" {
                r.clone()
            } else {
                json!([r[0], "valid", ""])
            }
        })
        .collect();
    let mapped = |set: &std::collections::BTreeSet<Hash>| {
        let mut values: Vec<_> = set.iter().map(|id| ids[id]).collect();
        values.sort();
        values
    };
    let frontier = view
        .subjects
        .iter()
        .flat_map(|s| s.frontier.iter().copied())
        .collect();
    json!({"rows":rows,"frontier":mapped(&frontier),"resolve":resolve,
        "active":mapped(&view.authority.active),"tombstones":mapped(&view.authority.tombstones),
        "effective_revokes":mapped(&view.authority.effective_revokes),"canceled":mapped(&view.authority.canceled)})
}
fn permutations(order: &mut [usize], at: usize, visit: &mut impl FnMut(&[usize])) {
    if at == order.len() {
        visit(order);
        return;
    }
    for i in at..order.len() {
        order.swap(at, i);
        permutations(order, at + 1, visit);
        order.swap(at, i);
    }
}
#[test]
fn stage_c_full_rows_frontiers_resolve_and_time_match_model() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/stage0");
    let result =
        Command::new(std::env::var("CC_MODEL_PYTHON").unwrap_or_else(|_| "python3".into()))
            .arg(root.join("projection_oracle.py"))
            .output()
            .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let cases: Vec<Json> = serde_json::from_slice(&result.stdout).unwrap();
    let base = genesis().envelope().clone();
    let mut cache = BTreeMap::new();
    let mut comparisons = 0;
    let mut orderings = 0;
    let mut named = 0;
    let mut resolves = 0;
    for (case_index, case) in cases.iter().enumerate() {
        if case_index % 500 == 0 {
            eprintln!("Stage (c) differential DAG {case_index}/{}", cases.len());
        }
        resolves += case["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "S")
            .count();
        if case["permutations"] == true {
            named += 1;
        }
        for times in 0..3 {
            let signed = wire(case["events"].as_array().unwrap(), &base, times, &mut cache);
            if times == 0 && case["permutations"] == true {
                let expected = &case["checks"].as_array().unwrap().last().unwrap()["expected"];
                permutations(
                    &mut (0..signed.len()).collect::<Vec<_>>(),
                    0,
                    &mut |order| {
                        let mut delivered = BTreeMap::new();
                        for &i in order {
                            delivered.insert(signed[i].id(), signed[i].clone());
                        }
                        assert_eq!(
                            normalize(project(&delivered), &signed),
                            *expected,
                            "named delivery {}",
                            case["name"]
                        );
                        orderings += 1;
                    },
                );
            }
            for check in case["checks"].as_array().unwrap() {
                let mask = check["mask"].as_u64().unwrap();
                let left: BTreeMap<_, _> = signed
                    .iter()
                    .enumerate()
                    .rev()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, e)| (e.id(), e.clone()))
                    .collect();
                assert_eq!(
                    normalize(project(&left), &signed),
                    check["expected"],
                    "{} mask {mask} time {times}: {}",
                    case["name"],
                    case["events"]
                );
                // Construction varies both partition delivery and duplicate union.
                // The classifier consumes sets, so assert the exact union bytes;
                // its full-set result is compared once per DAG/time below.
                let mut union = left.clone();
                union.extend(signed.iter().map(|e| (e.id(), e.clone())));
                union.extend(left);
                assert_eq!(union.len(), signed.len());
                for e in &signed {
                    assert_eq!(union[&e.id()].bytes(), e.bytes());
                }
                comparisons += 1;
            }
        }
    }
    assert_eq!(named, 13);
    assert_eq!(orderings, 26568);
    assert_eq!(cases.len(), 3569);
    assert_eq!(comparisons, 196242);
    assert_eq!(resolves, 232);
    eprintln!("Stage (c): {} DAGs; {comparisons} full subset/time comparisons; {resolves} Resolve events; {named} named traces / {orderings} permutations",cases.len());
}

/// One symbolic event in the model grammar (target: Delegate key / Revoke grant).
fn ev(id: usize, kind: &str, key: u8, grant: usize, parents: &[usize], target: i64) -> Json {
    json!({"id":id,"kind":kind,"key":key,"grant":grant,"parents":parents,"target":target,"cascade":false})
}
/// Unchanged `model.fold` expectations for every subset of each trace.
fn model(traces: &[Vec<Json>]) -> Vec<Vec<Json>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/stage0");
    let mut child =
        Command::new(std::env::var("CC_MODEL_PYTHON").unwrap_or_else(|_| "python3".into()))
            .arg(root.join("trace_oracle.py"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(traces).unwrap())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    serde_json::from_slice(&out.stdout).unwrap()
}
static NAMED: std::sync::LazyLock<BTreeMap<String, Vec<Json>>> = std::sync::LazyLock::new(|| {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/stage0");
    let out = Command::new(std::env::var("CC_MODEL_PYTHON").unwrap_or_else(|_| "python3".into()))
        .arg(root.join("projection_oracle.py"))
        .output()
        .unwrap();
    let cases: Vec<Json> = serde_json::from_slice(&out.stdout).unwrap();
    cases
        .into_iter()
        .filter(|c| c["permutations"] == true)
        .map(|c| {
            let name = c["name"].as_str().unwrap().to_owned();
            (name, c["events"].as_array().unwrap().clone())
        })
        .collect()
});
fn orders(n: usize, seed: u64) -> Vec<Vec<usize>> {
    let mut all = vec![];
    if n <= 4 {
        permutations(&mut (0..n).collect::<Vec<_>>(), 0, &mut |o| {
            all.push(o.to_vec())
        });
        return all;
    }
    all.push((0..n).collect());
    all.push((0..n).rev().collect());
    let mut x = seed;
    for _ in 0..4 {
        let mut o: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            o.swap(i, (x % (i as u64 + 1)) as usize);
        }
        all.push(o);
    }
    all
}
async fn bound_store() -> (sqlx::PgPool, cc_testkit::Cleanup, Store) {
    let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
    let store = Store::provision(pool.clone(), INSTANCE)
        .await
        .unwrap()
        .bind(filter())
        .await
        .unwrap();
    (pool, cleanup, store)
}
/// Rust against the model on every subset under three asserted-time patterns,
/// then real `Store::admit` delivery orders (all of them through four events).
/// Returns (subset comparisons, store orders).
async fn named_trace(events: Vec<Json>) -> (usize, usize) {
    let expected = model(std::slice::from_ref(&events)).remove(0);
    let base = genesis().envelope().clone();
    let mut cache = BTreeMap::new();
    let mut subsets = 0;
    for times in 0..3 {
        let signed = wire(&events, &base, times, &mut cache);
        for check in &expected {
            let mask = check["mask"].as_u64().unwrap();
            let part = signed
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, e)| (e.id(), e.clone()))
                .collect();
            assert_eq!(
                normalize(project(&part), &signed),
                check["expected"],
                "mask {mask}"
            );
            subsets += 1;
        }
    }
    let signed = wire(&events, &base, 0, &mut cache);
    let full = &expected.last().unwrap()["expected"];
    let mut delivered_orders = 0;
    for order in orders(signed.len(), 20261001 + signed.len() as u64) {
        let (pool, cleanup, store) = bound_store().await;
        let mut delivered = BTreeMap::new();
        for &i in order.iter().chain(order.first()) {
            delivered.insert(signed[i].id(), signed[i].clone());
            let outcome = store.admit(signed[i].bytes()).await.unwrap();
            assert_eq!(outcome.status, classify(&delivered)[&signed[i].id()]);
        }
        assert_eq!(
            normalize(store.review_projection().await.unwrap(), &signed),
            *full
        );
        pool.close().await;
        cleanup.cleanup().await;
        delivered_orders += 1;
    }
    (subsets, delivered_orders)
}
async fn named_model_trace(name: &str) -> (usize, usize) {
    named_trace(NAMED[name].clone()).await
}

#[tokio::test]
async fn i2_parent_authority_and_surviving_join_grant() {
    // Branch-only delegate K resolving the fork that would establish it, a
    // resolver revoked in a joined parent, an unauthorized author and a wrong
    // grant. Missing parents are covered by every subset mask.
    let events = vec![
        ev(0, "G", 0, 0, &[], -1),
        ev(1, "D", 0, 0, &[0], 1),
        ev(2, "C", 0, 0, &[0], -1),
        ev(3, "S", 1, 1, &[1, 2], -1),
        ev(4, "R", 0, 0, &[1], 1),
        ev(5, "S", 1, 1, &[2, 4], -1),
        ev(6, "C", 2, 0, &[0], -1),
    ];
    let full = &model(std::slice::from_ref(&events))[0][127]["expected"];
    for id in [3, 5, 6] {
        assert!(full["rows"].as_array().unwrap().contains(&json!([
            id,
            "invalid",
            "parent_authority"
        ])));
    }
    let (subsets, orders) = named_trace(events).await;
    assert_eq!((subsets, orders), (3 * 128, 6));
    let mut wrong = vec![ev(0, "G", 0, 0, &[], -1), ev(1, "D", 0, 0, &[0], 1)];
    wrong.push(ev(2, "C", 1, 0, &[1], -1)); // K signs through the root grant.
    let full = &model(std::slice::from_ref(&wrong))[0][7]["expected"];
    assert!(full["rows"]
        .as_array()
        .unwrap()
        .contains(&json!([2, "invalid", "parent_authority"])));
    assert_eq!(named_trace(wrong).await, (3 * 8, 6));
}
#[tokio::test]
async fn i2_revoke_concurrent_correction_no_revoked_winner() {
    let events = vec![
        ev(0, "G", 0, 0, &[], -1),
        ev(1, "D", 0, 0, &[0], 1),
        ev(2, "C", 1, 1, &[1], -1),
        ev(3, "R", 0, 0, &[1], 1),
    ];
    let full = &model(std::slice::from_ref(&events))[0][15]["expected"];
    assert_eq!(full["frontier"], json!([3]));
    assert!(full["rows"]
        .as_array()
        .unwrap()
        .contains(&json!([2, "branch", "revoked_concurrent"])));
    assert_eq!(named_trace(events).await, (3 * 16, 24));
}
#[tokio::test]
async fn i2_revoke_concurrent_delegate_cancels_descendants() {
    let events = vec![
        ev(0, "G", 0, 0, &[], -1),
        ev(1, "D", 0, 0, &[0], 1),
        ev(2, "D", 1, 1, &[1], 2),
        ev(3, "R", 0, 0, &[1], 1),
    ];
    let full = &model(std::slice::from_ref(&events))[0][15]["expected"];
    assert_eq!(full["canceled"], json!([2]));
    assert_eq!(named_trace(events).await, (3 * 16, 24));
}
#[tokio::test]
async fn i2_prior_delegate_survives_later_revoke() {
    assert_eq!(
        named_model_trace("literal_monotone_tombstone_counterexample").await,
        (3 * 32, 6)
    );
}
#[tokio::test]
async fn i2_retroactive_revoke_from_old_parent_cannot_freeze() {
    assert_eq!(
        named_model_trace("i2_retroactive_revoke_from_old_parent_cannot_freeze").await,
        (3 * 16, 24)
    );
}
#[tokio::test]
async fn i2_revoke_parent_equal_delegate_preserves_grant() {
    assert_eq!(
        named_model_trace("i2_revoke_parent_equal_delegate_preserves_grant").await,
        (3 * 32, 6)
    );
}
#[tokio::test]
async fn i2_cascade_compromise_visible_attacker_delegates() {
    assert_eq!(
        named_model_trace("i2_cascade_compromise_visible_attacker_delegates").await,
        (3 * 32, 6)
    );
}
#[tokio::test]
async fn i2_non_cascade_honest_delegator_departure() {
    assert_eq!(
        named_model_trace("i2_non_cascade_honest_delegator_departure").await,
        (3 * 32, 6)
    );
}
#[tokio::test]
async fn i2_suppressed_cascade_has_no_descendant_effect() {
    assert_eq!(
        named_model_trace("i2_suppressed_cascade_has_no_descendant_effect").await,
        (3 * 64, 6)
    );
}

/// I1: two stores receive complementary partitions in different orders; each
/// must match the model for its subset. Their union (export/restore), rebuild
/// into a fresh store and duplicate replay must reproduce the full set's exact
/// view commitment, computed independently in memory.
#[tokio::test]
async fn i1_union_permutation_partition_convergence() {
    let crisscross = vec![
        ev(0, "G", 0, 0, &[], -1),
        ev(1, "D", 0, 0, &[0], 1),
        ev(2, "D", 0, 0, &[1], 2),
        ev(3, "C", 1, 1, &[2], -1),
        ev(4, "C", 2, 2, &[2], -1),
        ev(5, "S", 1, 1, &[3, 4], -1),
        ev(6, "S", 2, 2, &[3, 4], -1),
        ev(7, "S", 1, 1, &[5, 6], -1),
    ];
    let partial_late = vec![
        ev(0, "G", 0, 0, &[], -1),
        ev(1, "C", 0, 0, &[0], -1),
        ev(2, "C", 0, 0, &[0], -1),
        ev(3, "C", 0, 0, &[0], -1),
        ev(4, "S", 0, 0, &[1, 2], -1),
    ];
    let traces = vec![
        NAMED["i2_multiple_revokes_intersect_acknowledged_pasts"].clone(),
        NAMED["i2_concurrent_delegate_descendants_do_not_contend"].clone(),
        NAMED["i2_retroactive_revoke_from_old_parent_cannot_freeze"].clone(),
        NAMED["i1_competing_resolutions_and_join"].clone(),
        NAMED["i2_revoked_branch_cannot_launder_through_resolution"].clone(),
        crisscross,
        partial_late,
    ];
    let expected = model(&traces);
    let base = genesis().envelope().clone();
    let mut cache = BTreeMap::new();
    for (events, expected) in traces.iter().zip(&expected) {
        let signed = wire(events, &base, 0, &mut cache);
        let n = signed.len();
        let all: BTreeMap<_, _> = signed.iter().map(|e| (e.id(), e.clone())).collect();
        let root = Snapshot::of(&filter(), &all).commitment;
        for mask in [0b0101_0101u64 & ((1 << n) - 1), (1 << (n / 2)) - 1] {
            let (pa, ca, a) = bound_store().await;
            let (pb, cb, b) = bound_store().await;
            let (pc, cc, c) = bound_store().await;
            // Left half in reverse order, right half in listed order.
            for i in (0..n).rev().filter(|i| mask & (1 << i) != 0) {
                a.admit(signed[i].bytes()).await.unwrap();
            }
            for i in (0..n).filter(|i| mask & (1 << i) == 0) {
                b.admit(signed[i].bytes()).await.unwrap();
            }
            let rest = ((1u64 << n) - 1) ^ mask;
            for (store, m) in [(&a, mask), (&b, rest)] {
                let want = &expected[m as usize]["expected"];
                assert_eq!(
                    normalize(store.review_projection().await.unwrap(), &signed),
                    *want
                );
            }
            a.restore_export(&b.export(None).await.unwrap())
                .await
                .unwrap();
            let union = a.snapshot(None).await.unwrap();
            assert_eq!(union.commitment, root);
            assert_eq!(
                normalize(union.projection, &signed),
                expected[(1 << n) - 1]["expected"]
            );
            let export = a.export(None).await.unwrap();
            c.restore_export(&export).await.unwrap();
            assert_eq!(c.snapshot(None).await.unwrap().commitment, root);
            a.restore_export(&export).await.unwrap();
            assert_eq!(a.snapshot(None).await.unwrap().commitment, root);
            for (p, cl) in [(pa, ca), (pb, cb), (pc, cc)] {
                p.close().await;
                cl.cleanup().await;
            }
        }
    }
}

/// I6: isomorphic DAGs re-signed with increasing, reversed-extreme and equal
/// asserted times get different event IDs but identical authority, frontier
/// and status decisions under the symbol mapping. Node receipts claiming other
/// results, receipt times and body availability leave the committed root fixed.
#[tokio::test]
async fn i6_asserted_time_and_receipt_noninterference() {
    let base = genesis().envelope().clone();
    let mut cache = BTreeMap::new();
    let mut compared = 0;
    for events in NAMED.values() {
        let views: Vec<_> = (0..3)
            .map(|t| {
                let signed = wire(events, &base, t, &mut cache);
                let ids: Vec<_> = signed.iter().map(Signed::id).collect();
                let all = signed.iter().map(|e| (e.id(), e.clone())).collect();
                (ids, normalize(project(&all), &signed))
            })
            .collect();
        assert_ne!(views[0].0, views[1].0);
        assert_ne!(views[1].0, views[2].0);
        assert_eq!(views[0].1, views[1].1);
        assert_eq!(views[1].1, views[2].1);
        compared += 1;
    }
    assert_eq!(compared, 13);

    use cc_core::v1::receipt::*;
    let (pool, cleanup, store) = bound_store().await;
    let g = genesis();
    let c = correction(&g, &g, 0, 5);
    let bad = correction(&g, &g, 1, 6);
    store
        .import(&[g.bytes().to_vec(), c.bytes().to_vec(), bad.bytes().to_vec()])
        .await
        .unwrap();
    let before = store.snapshot(None).await.unwrap();
    for (event, state, time) in [
        (bad.id(), Admission::Valid, 1),
        (c.id(), Admission::Invalid, u64::MAX),
        (g.id(), Admission::Pending, 0),
    ] {
        let receipt = SignedReceipt::sign(
            &key(5),
            NodeReceiptV1 {
                instance: INSTANCE,
                node_key: [0; 32],
                event,
                received_at: time,
                encoding_version: 1,
                fold_version: fold_v1_for_receipts(),
                initial_admission_result: InitialResult {
                    state,
                    reason: if state == Admission::Valid {
                        ""
                    } else {
                        "synthetic"
                    }
                    .into(),
                    missing: Set(vec![]),
                },
            },
        )
        .unwrap();
        store.retain_receipt(receipt.bytes()).await.unwrap();
    }
    store.retain_body([5; 32], b"unrelated").await.unwrap_err();
    store
        .retain_body(hash(b"synthetic body"), b"synthetic body")
        .await
        .unwrap();
    assert_eq!(store.snapshot(None).await.unwrap(), before);
    pool.close().await;
    cleanup.cleanup().await;
}
fn fold_v1_for_receipts() -> cc_core::v1::receipt::FoldRef {
    cc_core::v1::rule::fold_v1()
}
