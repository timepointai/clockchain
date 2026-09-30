//! Stage (a) oracle domain: genesis + root-authorized correction DAGs, including
//! wrong signers, missing parents, duplicate delivery and every small ordering.
//! Extend this harness with Delegate/Revoke in (b), and full View rows in (c).
use cc_ledger::v1::{classify, State};
use cc_testkit::v1::*;
use serde_json::{json, Value as Json};
use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
};

fn permutations(items: &[usize]) -> Vec<Vec<usize>> {
    if items.is_empty() {
        return vec![vec![]];
    }
    let mut out = vec![];
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let first = rest.remove(i);
        for mut p in permutations(&rest) {
            p.insert(0, first);
            out.push(p);
        }
    }
    out
}
#[test]
fn stage_a_branch_local_admission_matches_reference_on_generated_dags() {
    let mut cases = vec![];
    let mut actual = vec![];
    // All one-parent correction DAGs through four total events, three signer
    // choices for the final act, and all delivery orders/prefixes/duplicate unions.
    for p2 in 0..2 {
        for p3 in 0..3 {
            for signer in 0..3 {
                let g = genesis();
                let c1 = correction(&g, &g, 0, 10);
                let c2 = correction(&g, &[g.clone(), c1.clone()][p2], 0, 11);
                let c3 = correction(&g, &[g.clone(), c1.clone(), c2.clone()][p3], signer, 12);
                let events = [g, c1, c2, c3];
                let symbolic = [
                    json!({"id":0,"kind":"G"}),
                    json!({"id":1,"kind":"C","parents":[0]}),
                    json!({"id":2,"kind":"C","parents":[p2]}),
                    json!({"id":3,"kind":"C","key":signer,"parents":[p3]}),
                ];
                for order in permutations(&[0, 1, 2, 3]) {
                    for size in 1..=4 {
                        let delivered = &order[..size];
                        let set: BTreeMap<_, _> = delivered
                            .iter()
                            .map(|i| (events[*i].id(), events[*i].clone()))
                            .collect();
                        let projection = classify(&set);
                        let rows: Vec<_> = delivered
                            .iter()
                            .map(|i| {
                                let s = &projection[&events[*i].id()];
                                let state = match s.state {
                                    State::Valid => "valid",
                                    State::Pending => "pending",
                                    State::Invalid => "invalid",
                                };
                                json!([i, state, s.reason])
                            })
                            .collect();
                        cases.push(Json::Array(
                            delivered
                                .iter()
                                .chain(delivered.iter())
                                .map(|i| symbolic[*i].clone())
                                .collect(),
                        ));
                        actual.push(rows);
                    }
                }
            }
        }
    }
    let python = std::env::var("CC_MODEL_PYTHON").unwrap_or_else(|_| "python3".into());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/stage0");
    let mut child = Command::new(python)
        .arg(root.join("admission_oracle.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Python reference oracle required");
    let input = serde_json::to_vec(&cases).unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        stdin.write_all(&input).unwrap();
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(output.status.success());
    let expected: Vec<Vec<Json>> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(expected.len(), actual.len());
    for (i, (expected, actual)) in expected.into_iter().zip(actual).enumerate() {
        let mut expected = expected;
        let mut actual = actual;
        expected.sort_by_key(|r| r[0].as_u64());
        actual.sort_by_key(|r| r[0].as_u64());
        assert_eq!(actual, expected, "case {}: {}", i, cases[i]);
    }
    assert_eq!(cases.len(), 1728);
}
