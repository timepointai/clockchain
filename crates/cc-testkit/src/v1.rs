//! Synthetic v1 test data; never historical fixture content or operator keys.
use cc_core::{v1::*, SecretKey};
pub const INSTANCE: Hash = [9; 32];
pub fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n + 1; 32])
}
pub fn genesis() -> Signed {
    Signed::sign(
        &key(0),
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: None,
            subject_key: Some(SubjectKey {
                kind: "test".into(),
                namespace: "synthetic".into(),
                value: "subject".into(),
            }),
            grant: None,
            parents: Set(vec![]),
            asserted_time: None,
            payload: Payload::Genesis {
                nonce: [2; 32],
                body: [3; 32],
                evidence: Set(vec![[4; 32]]),
            },
        },
    )
    .unwrap()
}
pub fn correction(g: &Signed, p: &Signed, signer: u8, body: u8) -> Signed {
    let old = match &p.envelope().payload {
        Payload::Genesis { body, .. } | Payload::Correction { body, .. } => *body,
        _ => panic!("synthetic parent must carry a body"),
    };
    let parents = Set(vec![p.id()]);
    Signed::sign(
        &key(signer),
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: Some(g.id()),
            subject_key: g.envelope().subject_key.clone(),
            grant: Some(root_grant(g.id())),
            parents: parents.clone(),
            asserted_time: None,
            payload: Payload::Correction {
                body: [body; 32],
                decision: Decision {
                    kind: Kind::Correction,
                    rationale: "Synthetic correction test".into(),
                    evidence: Set(vec![[4; 32]]),
                    parents,
                    old: Value::Body(old),
                    new: Value::Body([body; 32]),
                },
            },
        },
    )
    .unwrap()
}
