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

/// Independent synthetic subject, e.g. a counterclaim by another key.
pub fn subject(signer: u8, nonce: u8, body: u8) -> Signed {
    let mut e = genesis().envelope().clone();
    e.payload = Payload::Genesis {
        nonce: [nonce; 32],
        body: [body; 32],
        evidence: Set(vec![[4; 32]]),
    };
    Signed::sign(&key(signer), e).unwrap()
}
/// The exact pin a reviewer of `basis` signs, computed by the v1 projection.
pub fn pin(events: &[&Signed], basis: &Signed) -> Pin {
    let view = cc_ledger::v1::project(&events.iter().map(|e| (e.id(), (*e).clone())).collect());
    let row = view.rows.iter().find(|r| r.event == basis.id()).unwrap();
    let revision = row.revision.expect("basis must be a valid subject event");
    let r = view.revisions.iter().find(|r| r.id == revision).unwrap();
    Pin {
        subject: r.subject,
        basis: basis.id(),
        revision,
        body: r.body,
    }
}
fn unbound(parents: Set<Hash>, payload: Payload) -> Envelope {
    Envelope {
        instance: INSTANCE,
        author: [0; 32],
        subject: None,
        subject_key: None,
        grant: None,
        parents,
        asserted_time: None,
        payload,
    }
}
pub fn edge(signer: u8, relation: &str, pins: Pins) -> Signed {
    let decision = Decision {
        kind: Kind::EdgeAssert,
        rationale: "Synthetic edge assertion".into(),
        evidence: Set(vec![[4; 32]]),
        parents: Set(vec![]),
        old: Value::None,
        new: Value::Pins(pins.clone()),
    };
    let payload = Payload::EdgeAssert {
        relation: relation.into(),
        pins,
        decision,
    };
    Signed::sign(&key(signer), unbound(Set(vec![]), payload)).unwrap()
}
/// One exact old-pin pair per prior edge head; several heads resolve a conflict.
pub fn reaffirm(signer: u8, edge: &Signed, parents: &[&Signed], new: Pins) -> Signed {
    let mut old: Vec<_> = parents
        .iter()
        .map(|p| ParentPins {
            parent: p.id(),
            pins: match &p.envelope().payload {
                Payload::EdgeAssert { pins, .. } => pins.clone(),
                Payload::EdgeReaffirm { new, .. } => new.clone(),
                _ => panic!("synthetic reaffirmation parent must be an edge event"),
            },
        })
        .collect();
    old.sort();
    let old = Set(old);
    let parents = Set(old.0.iter().map(|o| o.parent).collect());
    let decision = Decision {
        kind: Kind::EdgeReaffirm,
        rationale: "Synthetic edge reaffirmation".into(),
        evidence: Set(vec![[4; 32]]),
        parents: parents.clone(),
        old: Value::ParentPins(old.clone()),
        new: Value::Pins(new.clone()),
    };
    let payload = Payload::EdgeReaffirm {
        edge: edge.id(),
        old,
        new,
        decision,
    };
    Signed::sign(&key(signer), unbound(parents, payload)).unwrap()
}
pub fn attest(
    signer: u8,
    target_kind: TargetKind,
    target: Hash,
    kind: &str,
    artifact: u8,
) -> Signed {
    let payload = Payload::Attestation {
        target_kind,
        target,
        artifact_kind: kind.into(),
        artifact: [artifact; 32],
    };
    Signed::sign(&key(signer), unbound(Set(vec![]), payload)).unwrap()
}

/// Synthetic boot-pinned curator set (keys 0..4) with a four-hop bound.
pub fn filter() -> cc_filter::v1::FilterIdentity {
    let mut curators: Vec<Hash> = (0..4).map(|k| key(k).author().to_bytes()).collect();
    curators.sort();
    cc_filter::v1::FilterIdentity::governed(curators, 4).unwrap()
}
