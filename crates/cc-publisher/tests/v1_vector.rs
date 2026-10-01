//! The publisher's Genesis equals the independent stdlib derivation in
//! `tests/vectors/v1_genesis_reference.py` (`v1-genesis-reference.txt`): the
//! canonical preimage, identifiers, body hash and asserted-time coordinate.
//! Ed25519 is deterministic, so the signed envelope is pinned as well.
//! Synthetic inputs only.
use cc_core::v1::{hash, Signed};
use cc_core::{AuthorKey, SecretKey, Signature};
use cc_publisher::v1::genesis::{build, Genesis, GenesisInput};
use cc_publisher::v1::{hex32, time};

const REFERENCE: &str = include_str!("vectors/v1-genesis-reference.txt");
/// SHA-256 of the full signed envelope (preimage and signature).
const ENVELOPE_SHA256: &str = "738da50db3515167ea1e717bf365c22356f4e4bdb9fa06a5d9c01f396082f835";
/// Public key of seed 0x01 * 32, as pinned by cc-core's v1_reference.py.
const AUTHOR: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

fn reference(key: &str) -> &'static str {
    REFERENCE
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("reference lacks {key}"))
}

fn vector() -> Genesis {
    build(
        &SecretKey::from_seed([1; 32]),
        GenesisInput {
            instance: [9; 32],
            kind: "scientific-discovery".into(),
            namespace: "synthetic.publisher".into(),
            value: "reference-1".into(),
            body: b"Synthetic publisher reference body.\nIt names no historical claim.\n".to_vec(),
            asserted_time: time::parse("1901-02-03").unwrap(),
            // Given unsorted; the signed set is canonical.
            evidence: vec![[0xbb; 32], [0xaa; 32]],
            nonce: [0x5a; 32],
        },
    )
    .unwrap()
}

#[test]
fn genesis_matches_the_independent_reference() {
    let g = vector();
    let bytes = g.signed.bytes();
    let (preimage, signature) = bytes.split_at(bytes.len() - 64);
    assert_eq!(hex::encode(preimage), reference("preimage"));
    assert_eq!(hex::encode(g.id()), reference("event"));
    assert_eq!(hex::encode(g.subject()), reference("subject"));
    assert_eq!(hex::encode(g.revision()), reference("revision"));
    assert_eq!(hex::encode(hash(&g.body)), reference("body_sha256"));
    assert_eq!(
        hex::encode(g.fields().unwrap().asserted_time.coordinate),
        reference("coordinate")
    );
    assert_eq!(hex::encode(hash(bytes)), ENVELOPE_SHA256);

    // The signature verifies under the independently pinned author key, and
    // the bytes decode as the node decodes them.
    let author = AuthorKey::from_bytes(&hex32(AUTHOR).unwrap()).unwrap();
    cc_core::verify(
        &author,
        preimage,
        &Signature::from_bytes(signature.try_into().unwrap()),
    )
    .unwrap();
    assert_eq!(Signed::decode(bytes).unwrap().id(), g.id());

    // The review preview names exactly these values.
    let p = g.preview().unwrap();
    for (field, key) in [
        ("event", "event"),
        ("subject", "subject"),
        ("revision", "revision"),
        ("root_grant", "root_grant"),
        ("body_sha256", "body_sha256"),
    ] {
        assert_eq!(p[field], reference(key), "{field}");
    }
    assert_eq!(p["author"], AUTHOR);
    assert_eq!(p["envelope_sha256"], ENVELOPE_SHA256);
    assert_eq!(p["asserted_time"]["coordinate"], reference("coordinate"));
    assert_eq!(p["asserted_time"]["calendar"], "1901-02-03");
    assert_eq!(
        p["evidence"],
        serde_json::json!([hex::encode([0xaa; 32]), hex::encode([0xbb; 32])])
    );
}
