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

pub fn transition(g: &Signed, p: &Signed, signer: u8, grant: Hash, payload: Payload) -> Signed {
    Signed::sign(
        &key(signer),
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: Some(g.id()),
            subject_key: g.envelope().subject_key.clone(),
            grant: Some(grant),
            parents: Set(vec![p.id()]),
            asserted_time: None,
            payload,
        },
    )
    .unwrap()
}
pub fn delegate(g: &Signed, p: &Signed, signer: u8, issuer: Hash, grantee: u8) -> Signed {
    let grantee = key(grantee).author().to_bytes();
    let decision = Decision {
        kind: Kind::Delegate,
        rationale: "Synthetic delegation".into(),
        evidence: Set(vec![[4; 32]]),
        parents: Set(vec![p.id()]),
        old: Value::None,
        new: Value::Grant { issuer, grantee },
    };
    transition(
        g,
        p,
        signer,
        issuer,
        Payload::Delegate {
            grantee,
            issuer,
            decision,
        },
    )
}
pub fn revoke(
    g: &Signed,
    p: &Signed,
    signer: u8,
    grant: Hash,
    target: Hash,
    cascade: bool,
) -> Signed {
    let decision = Decision {
        kind: Kind::Revoke,
        rationale: "Synthetic revocation".into(),
        evidence: Set(vec![[4; 32]]),
        parents: Set(vec![p.id()]),
        old: Value::ActiveGrant(target),
        new: Value::RevokedGrant {
            grant: target,
            cascade,
        },
    };
    transition(
        g,
        p,
        signer,
        grant,
        Payload::Revoke {
            target,
            cascade,
            decision,
        },
    )
}

/// Explicit signed synthetic resolution, including every parent's disposition.
pub fn resolve(
    g: &Signed,
    parents: &[&Signed],
    signer: u8,
    grant: Hash,
    selection: Selection,
) -> Signed {
    let mut parents = Set(parents.iter().map(|p| p.id()).collect());
    parents.0.sort();
    let (new, action) = match selection {
        Selection::MergedBody(body) => (Value::Body(body), DispositionKind::Merged),
        Selection::Revision(revision) => (Value::Revision(revision), DispositionKind::Selected),
    };
    Signed::sign(
        &key(signer),
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: Some(g.id()),
            subject_key: g.envelope().subject_key.clone(),
            grant: Some(grant),
            parents: parents.clone(),
            asserted_time: None,
            payload: Payload::Resolve {
                selection,
                dispositions: Set(parents
                    .0
                    .iter()
                    .map(|&parent| Disposition {
                        parent,
                        action,
                        rationale: "Synthetic resolution disposition".into(),
                    })
                    .collect()),
                decision: Decision {
                    kind: Kind::Resolve,
                    rationale: "Synthetic resolution".into(),
                    evidence: Set(vec![[4; 32]]),
                    parents: parents.clone(),
                    old: Value::Heads(parents),
                    new,
                },
            },
        },
    )
    .unwrap()
}
