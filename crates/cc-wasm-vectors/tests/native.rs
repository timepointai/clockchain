#[test]
fn native_rule_vectors_match_independent_reference() {
    assert_eq!(
        include_str!("../../cc-core/tests/vectors/v1-rule.txt")
            .lines()
            .count(),
        8
    );
    assert_eq!(cc_wasm_vectors::matches(), 0xff);
}
