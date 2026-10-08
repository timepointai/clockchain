//! Node seals: canonical bytes, domain framing, signing and verification,
//! following the receipt tests. The fixed vector below is also what
//! `ops/test_seal_v1.py` reproduces with the stdlib encoder, so the two
//! verifiers agree on the bytes a seal signature covers.
use cc_core::{
    v1::{receipt::FoldRef, seal::*, Signed, *},
    SecretKey,
};

/// A synthetic seed with visibly patterned bytes; never a real node seed.
const SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn seal() -> NodeSealV1 {
    NodeSealV1 {
        instance: [0x11; 32],
        node_key: [0; 32],
        fold_version: FoldRef {
            version: 1,
            manifest: [0x22; 32],
        },
        filter_version: [0x33; 32],
        corpus_digest: [0x44; 32],
        commitment: [0x55; 32],
        counts: SealCounts { candidates: 7 },
        build: "abc123def456".into(),
        sealed_at_us: 1_700_000_000_000_000,
    }
}

/// The canonical preimage of `seal()` once `node_key` is the public key of
/// `SEED`: framed domain, then every field in order. Fixed here so an
/// encoding change is a failing test, not a silent fork of the format.
const VECTOR: &str = concat!(
    "0000000a63632e7365616c2e7631", // frame("cc.seal.v1")
    "1111111111111111111111111111111111111111111111111111111111111111", // instance
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8", // node_key
    "0001",                         // fold version
    "2222222222222222222222222222222222222222222222222222222222222222", // fold manifest
    "3333333333333333333333333333333333333333333333333333333333333333", // filter_version
    "4444444444444444444444444444444444444444444444444444444444444444", // corpus_digest
    "5555555555555555555555555555555555555555555555555555555555555555", // commitment
    "0000000000000007",             // counts.candidates
    "0000000c616263313233646566343536", // build
    "00060a24181e4000",             // sealed_at_us
);

/// Ed25519 is deterministic: the signature of `SEED` over `VECTOR`, also
/// produced independently by the stdlib `ops/seal_v1.py` encoder and
/// `cryptography`, so the two verifiers agree on the bytes a seal covers.
const SIGNATURE: &str = "e219ff478eb38268b8f54be28d3acad26f51ceedc90a30554705d1a7c990dabb1f6814915780265bd2be4d468d4cfc298e0d7980d7ff4b35ada944b67a20710c";

#[test]
fn canonical_bytes_match_the_fixed_vector() {
    let key = SecretKey::from_seed(SEED);
    let signed = sign_seal(&key, seal()).unwrap();
    assert_eq!(signed.seal().node_key, key.author().to_bytes());
    assert_eq!(
        hex::encode(signed.seal().preimage().unwrap()),
        VECTOR,
        "the seal preimage changed"
    );
    assert_eq!(signed.bytes().len(), VECTOR.len() / 2 + 64);
    assert_eq!(
        &signed.bytes()[..VECTOR.len() / 2],
        hex::decode(VECTOR).unwrap()
    );
    assert_eq!(&signed.bytes()[VECTOR.len() / 2..], signed.signature());
    assert_eq!(hex::encode(signed.signature()), SIGNATURE);
    // Deterministic: the same seal under the same key is the same bytes.
    assert_eq!(sign_seal(&key, seal()).unwrap().bytes(), signed.bytes());
}

#[test]
fn sign_verify_round_trip_and_framing_are_independent_of_events_and_receipts() {
    let key = SecretKey::from_seed(SEED);
    let signed = sign_seal(&key, seal()).unwrap();
    verify_seal(signed.seal(), &signed.signature()).unwrap();
    assert_eq!(
        SignedSeal::decode(signed.bytes()).unwrap().seal(),
        signed.seal()
    );
    // Neither the event nor the receipt decoder accepts a seal, and the seal
    // decoder accepts neither of theirs.
    assert!(Signed::decode(signed.bytes()).is_err());
    assert!(cc_core::v1::receipt::SignedReceipt::decode(signed.bytes()).is_err());
    let receipt = cc_core::v1::receipt::SignedReceipt::sign(
        &key,
        cc_core::v1::receipt::NodeReceiptV1 {
            instance: [0x11; 32],
            node_key: [0; 32],
            event: [2; 32],
            received_at: 0,
            encoding_version: 1,
            fold_version: FoldRef {
                version: 1,
                manifest: [0x22; 32],
            },
            initial_admission_result: cc_core::v1::receipt::InitialResult {
                state: cc_core::v1::receipt::Admission::Valid,
                reason: String::new(),
                missing: Set(vec![]),
            },
        },
    )
    .unwrap();
    assert!(SignedSeal::decode(receipt.bytes()).is_err());
    // Every single-bit change to the signed bytes is refused.
    for i in 0..signed.bytes().len() {
        let mut bad = signed.bytes().to_vec();
        bad[i] ^= 1;
        assert!(SignedSeal::decode(&bad).is_err(), "byte {i}");
    }
    let mut trailing = signed.bytes().to_vec();
    trailing.push(0);
    assert!(SignedSeal::decode(&trailing).is_err());
    for n in [0, 32, 64, signed.bytes().len() - 1] {
        assert!(SignedSeal::decode(&signed.bytes()[..n]).is_err());
    }
}

#[test]
fn every_tampered_field_fails_verification() {
    let key = SecretKey::from_seed(SEED);
    let signed = sign_seal(&key, seal()).unwrap();
    let sig = signed.signature();
    let good = signed.seal().clone();
    let tampered: Vec<(&str, NodeSealV1)> = vec![
        ("instance", {
            let mut s = good.clone();
            s.instance[0] ^= 1;
            s
        }),
        ("node_key", {
            let mut s = good.clone();
            s.node_key = SecretKey::from_seed([9; 32]).author().to_bytes();
            s
        }),
        ("fold_version.version", {
            let mut s = good.clone();
            s.fold_version.version = 2;
            s
        }),
        ("fold_version.manifest", {
            let mut s = good.clone();
            s.fold_version.manifest[31] ^= 1;
            s
        }),
        ("filter_version", {
            let mut s = good.clone();
            s.filter_version[5] ^= 1;
            s
        }),
        ("corpus_digest", {
            let mut s = good.clone();
            s.corpus_digest[6] ^= 1;
            s
        }),
        ("commitment", {
            let mut s = good.clone();
            s.commitment[7] ^= 1;
            s
        }),
        ("counts.candidates", {
            let mut s = good.clone();
            s.counts.candidates += 1;
            s
        }),
        ("build", {
            let mut s = good.clone();
            s.build = "abc123def457".into();
            s
        }),
        ("sealed_at_us", {
            let mut s = good.clone();
            s.sealed_at_us += 1;
            s
        }),
    ];
    assert_eq!(tampered.len(), 10, "one case per field");
    for (name, s) in &tampered {
        assert_ne!(s, &good, "{name}: the case changes nothing");
        assert!(verify_seal(s, &sig).is_err(), "{name} verified");
        // A re-signed tampered seal differs in bytes, except that signing
        // overwrites `node_key` with the signer's key by design.
        let again = sign_seal(&key, s.clone()).unwrap();
        if *name == "node_key" {
            assert_eq!(again.bytes(), signed.bytes());
        } else {
            assert_ne!(again.bytes(), signed.bytes(), "{name}");
        }
    }
    verify_seal(&good, &sig).unwrap();
    // A wrong signature over the right seal, and a right signature under a
    // different key, are both refused.
    let mut wrong = sig;
    wrong[63] ^= 1;
    assert!(verify_seal(&good, &wrong).is_err());
    let other = sign_seal(&SecretKey::from_seed([9; 32]), seal()).unwrap();
    assert!(verify_seal(&good, &other.signature()).is_err());
    assert!(verify_seal(other.seal(), &sig).is_err());
}

#[test]
fn build_strings_are_bounded_and_printable() {
    let key = SecretKey::from_seed(SEED);
    for bad in [
        "",
        "with space",
        "tab\there",
        "ünïcode",
        &"x".repeat(MAX_BUILD + 1),
    ] {
        let mut s = seal();
        s.build = bad.into();
        assert!(sign_seal(&key, s).is_err(), "{bad:?}");
    }
    for good in ["unknown", "abc123def456-dirty", &"x".repeat(MAX_BUILD)] {
        let mut s = seal();
        s.build = good.into();
        sign_seal(&key, s).unwrap();
    }
}
