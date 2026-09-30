use cc_core::{
    v1::{receipt::*, *},
    SecretKey,
};
#[test]
fn receipt_domain_signature_framing_and_metadata_are_independent_of_events() {
    let key = SecretKey::from_seed([7; 32]);
    let receipt = NodeReceiptV1 {
        instance: [1; 32],
        node_key: [0; 32],
        event: [2; 32],
        received_at: 0,
        encoding_version: 1,
        fold_version: FoldRef {
            version: 65535,
            manifest: [3; 32],
        },
        initial_admission_result: InitialResult {
            state: Admission::Pending,
            reason: "parent_missing".into(),
            missing: Set(vec![[4; 32]]),
        },
    };
    let signed = SignedReceipt::sign(&key, receipt).unwrap();
    assert_eq!(signed.receipt().node_key, key.author().to_bytes());
    assert_eq!(
        SignedReceipt::decode(signed.bytes()).unwrap().receipt(),
        signed.receipt()
    );
    assert!(Signed::decode(signed.bytes()).is_err());
    for i in 0..signed.bytes().len() {
        let mut bad = signed.bytes().to_vec();
        bad[i] ^= 1;
        assert!(SignedReceipt::decode(&bad).is_err(), "byte {i}");
    }
    let mut trailing = signed.bytes().to_vec();
    trailing.push(0);
    assert!(SignedReceipt::decode(&trailing).is_err());
    for n in [0, 32, 64, signed.bytes().len() - 1] {
        assert!(SignedReceipt::decode(&signed.bytes()[..n]).is_err());
    }
    let mut changed = signed.receipt().clone();
    changed.received_at = u64::MAX;
    let later = SignedReceipt::sign(&key, changed).unwrap();
    assert_ne!(signed.bytes(), later.bytes());
    assert_eq!(signed.receipt().event, later.receipt().event);
    let mut invalid = signed.receipt().clone();
    invalid.initial_admission_result.missing = Set(vec![[4; 32], [4; 32]]);
    assert!(SignedReceipt::sign(&key, invalid).is_err());
}
