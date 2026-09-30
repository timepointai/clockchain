use cc_core::{v1::*, SecretKey};
fn key() -> SecretKey {
    SecretKey::from_seed([1; 32])
}
fn envelope(payload: Payload) -> Envelope {
    Envelope {
        instance: [9; 32],
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
        payload,
    }
}
fn decision(kind: Kind) -> Decision {
    Decision {
        kind,
        rationale: "synthetic".into(),
        evidence: Set(vec![[7; 32]]),
        parents: Set(vec![]),
        old: Value::None,
        new: Value::None,
    }
}
fn pin() -> Pin {
    Pin {
        subject: [1; 32],
        basis: [2; 32],
        revision: [3; 32],
        body: [4; 32],
    }
}
fn payloads() -> Vec<Payload> {
    vec![
        Payload::Genesis {
            nonce: [2; 32],
            body: [3; 32],
            evidence: Set(vec![[4; 32]]),
        },
        Payload::Correction {
            body: [5; 32],
            decision: decision(Kind::Correction),
        },
        Payload::Delegate {
            grantee: [5; 32],
            issuer: [6; 32],
            decision: decision(Kind::Delegate),
        },
        Payload::Revoke {
            target: [5; 32],
            cascade: true,
            decision: decision(Kind::Revoke),
        },
        Payload::Resolve {
            selection: Selection::MergedBody([5; 32]),
            dispositions: Set(vec![Disposition {
                parent: [6; 32],
                action: DispositionKind::Merged,
                rationale: "synthetic".into(),
            }]),
            decision: decision(Kind::Resolve),
        },
        Payload::EdgeAssert {
            relation: "disputes".into(),
            pins: Pins {
                source: pin(),
                target: pin(),
            },
            decision: decision(Kind::EdgeAssert),
        },
        Payload::EdgeReaffirm {
            edge: [5; 32],
            old: Set(vec![ParentPins {
                parent: [6; 32],
                pins: Pins {
                    source: pin(),
                    target: pin(),
                },
            }]),
            new: Pins {
                source: pin(),
                target: pin(),
            },
            decision: decision(Kind::EdgeReaffirm),
        },
        Payload::Attestation {
            target_kind: TargetKind::Revision,
            target: [5; 32],
            artifact_kind: "source".into(),
            artifact: [6; 32],
        },
    ]
}
#[test]
fn v1_canonical_author_bound_roundtrip() {
    for payload in payloads() {
        let a = Signed::sign(&key(), envelope(payload.clone())).unwrap();
        let b = Signed::sign(&SecretKey::from_seed([2; 32]), envelope(payload)).unwrap();
        assert_ne!(a.id(), b.id());
        assert_eq!(Signed::decode(a.bytes()).unwrap().envelope(), a.envelope());
        let mut bad = a.bytes().to_vec();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(Signed::decode(&bad).unwrap_err().0, "bad_signature");
        let mut trailing = a.bytes().to_vec();
        trailing.push(0);
        assert!(Signed::decode(&trailing).is_err());
        for n in [0, 1, 32, 64, a.bytes().len() - 1] {
            assert!(Signed::decode(&a.bytes()[..n]).is_err());
        }
    }
}
#[test]
fn v1_strict_versions_sets_utf8_and_bounds() {
    let signed = Signed::sign(&key(), envelope(payloads().remove(0))).unwrap();
    for (offset, expected) in [
        (15, "unsupported_encoding"),
        (17, "unsupported_constants"),
        (51, "unknown_tag"),
    ] {
        let mut b = signed.bytes().to_vec();
        b[offset] = 99;
        assert_eq!(Signed::decode(&b).unwrap_err().0, expected);
    }
    let mut e = signed.envelope().clone();
    e.parents = Set(vec![[2; 32], [1; 32]]);
    assert!(e.preimage().is_err());
    e.parents = Set(vec![[1; 32], [1; 32]]);
    assert!(e.preimage().is_err());
    e.parents = Set(vec![[1; 32]; 1025]);
    assert!(e.preimage().is_err());
    e.parents = Set(vec![]);
    e.subject_key.as_mut().unwrap().kind = "x".repeat(1025);
    assert!(e.preimage().is_err());
    let mut b = signed.bytes().to_vec();
    let at = b.windows(4).position(|w| w == b"test").unwrap();
    b[at] = 255;
    assert_eq!(Signed::decode(&b).unwrap_err().0, "invalid_utf8");
    assert_eq!(
        Signed::decode(&vec![0; MAX_ENVELOPE + 1]).unwrap_err().0,
        "envelope_too_large"
    );
}
#[test]
fn cascade_is_required_canonical_and_signed() {
    let mut e = envelope(Payload::Revoke {
        target: [5; 32],
        cascade: false,
        decision: decision(Kind::Revoke),
    });
    let a = Signed::sign(&key(), e.clone()).unwrap();
    if let Payload::Revoke { cascade, .. } = &mut e.payload {
        *cascade = true;
    }
    let b = Signed::sign(&key(), e).unwrap();
    assert_ne!(a.id(), b.id());
    let at = a
        .envelope()
        .preimage()
        .unwrap()
        .iter()
        .zip(b.envelope().preimage().unwrap())
        .position(|(a, b)| *a != b)
        .unwrap();
    let mut bad = a.bytes().to_vec();
    bad[at] = 2;
    assert_eq!(Signed::decode(&bad).unwrap_err().0, "noncanonical_bool");
    let mut omitted = a.bytes().to_vec();
    omitted.remove(at);
    assert!(Signed::decode(&omitted).is_err());
}

#[test]
fn duplicate_parent_dispositions_are_noncanonical_even_when_values_differ() {
    let mut e = envelope(payloads().remove(4));
    if let Payload::Resolve { dispositions, .. } = &mut e.payload {
        let mut duplicate = dispositions.0[0].clone();
        duplicate.action = DispositionKind::NotSelected;
        dispositions.0.push(duplicate);
    }
    assert_eq!(e.preimage().unwrap_err().0, "noncanonical_set");
}
#[test]
fn v1_no_legacy_ingress() {
    let mut old = vec![0; 200];
    old[..2].copy_from_slice(&0u16.to_be_bytes());
    assert!(Signed::decode(&old).is_err());
    assert_eq!(cc_core::CANON_VERSION, 1);
    assert_eq!(cc_core::LEGACY_CANON_VERSION, 0);
}
#[test]
fn v1_independent_wire_vectors() {
    let vectors: Vec<_> = include_str!("vectors/v1-preimages.txt").lines().collect();
    assert_eq!(vectors.len(), 8);
    for (payload, vector) in payloads().into_iter().zip(vectors) {
        let (preimage, digest) = vector.split_once(' ').unwrap();
        let signed = Signed::sign(&key(), envelope(payload)).unwrap();
        assert_eq!(hex::encode(signed.envelope().preimage().unwrap()), preimage);
        assert_eq!(hex::encode(signed.id()), digest);
    }
}
