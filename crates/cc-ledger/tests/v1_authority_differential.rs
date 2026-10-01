//! Stage (b): compare admission/reasons and authority effects, not body frontiers.
use cc_core::v1::*;
use cc_ledger::v1::{analyze, Analysis, State};
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
        let body = if kind == "G" || kind == "C" {
            [i as u8 + 3; 32]
        } else {
            bodies[event["parents"][0].as_u64().unwrap() as usize]
        };
        if kind != "G" {
            let p = event["parents"][0].as_u64().unwrap() as usize;
            e.subject = Some(signed[0].id());
            let grant = grant_ref(event["grant"].as_u64().unwrap() as usize);
            e.grant = Some(grant);
            e.parents = Set(vec![signed[p].id()]);
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
                _ => panic!("Stage (c) must test Resolve separately"),
            };
        }
        if kind == "G" || kind == "C" {
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
fn normalize(view: Analysis, signed: &[Signed]) -> Json {
    let mut ids: BTreeMap<_, _> = signed
        .iter()
        .enumerate()
        .map(|(i, e)| (e.id(), i))
        .collect();
    ids.insert(root_grant(signed[0].id()), 0);
    let mut rows: Vec<_> = view
        .admission
        .iter()
        .map(|(id, s)| {
            let state = match s.state {
                State::Valid => "valid",
                State::Pending => "pending",
                State::Invalid => "invalid",
            };
            let reason = view
                .authority
                .effects
                .get(id)
                .map(|e| e.reason.as_str())
                .unwrap_or("");
            if let Some(effect) = view.authority.effects.get(id) {
                assert_eq!(
                    effect.reason.is_empty(),
                    effect.controlling_revokes.is_empty()
                );
                assert!(effect
                    .controlling_revokes
                    .is_subset(&view.authority.effective_revokes));
            }
            json!([ids[id], state, s.reason, reason])
        })
        .collect();
    rows.sort_by_key(|r| r[0].as_u64());
    let mapped = |set: &std::collections::BTreeSet<Hash>| {
        let mut values: Vec<_> = set.iter().map(|id| ids[id]).collect();
        values.sort();
        values
    };
    json!({"rows":rows,"active":mapped(&view.authority.active),"tombstones":mapped(&view.authority.tombstones),
        "effective_revokes":mapped(&view.authority.effective_revokes),"canceled":mapped(&view.authority.canceled)})
}
#[test]
fn stage_b_grants_revocations_suppression_acknowledgment_and_time_match_model() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/stage0");
    let result =
        Command::new(std::env::var("CC_MODEL_PYTHON").unwrap_or_else(|_| "python3".into()))
            .arg(root.join("authority_oracle.py"))
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
    for (case_index, case) in cases.iter().enumerate() {
        if case_index % 500 == 0 {
            eprintln!("Stage (b) differential DAG {case_index}/{}", cases.len());
        }
        for times in 0..3 {
            let signed = wire(case["events"].as_array().unwrap(), &base, times, &mut cache);
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
                    normalize(analyze(&left), &signed),
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
    assert_eq!(cases.len(), 3352);
    assert_eq!(comparisons, 162234);
    eprintln!("Stage (b): {} DAGs; {comparisons} subset/time comparisons plus duplicate unions; no frontier equivalence",cases.len());
}
