/*
 * BindingHashCollapse.spec: whether the monolithic Safe v1.5.0 getTransactionHash value can depend on
 * its arguments at all in this model (defect A, report 6.2, L-BIND-9). Three variants that move which
 * arguments a policy folds into that hash pass R_COS_2, R_COS_2_hashBinding and R_IT_3, the rules
 * written to separate them.
 * Not a property spec: every assert is written to be refuted by a healthy model.
 */
methods {
    function safeTxHashOf(
        bytes32,address,uint256,bytes,BindingHarness.Operation,uint256,uint256,uint256,address,address,uint256
    ) external returns (bytes32) envfree;
    function structHashOf(
        address,uint256,bytes,BindingHarness.Operation,uint256,uint256,uint256,address,address,uint256
    ) external returns (bytes32) envfree;
    function eip712Of(bytes32, bytes32) external returns (bytes32) envfree;
}

// (a) Can the monolithic Safe tx hash see `value`?  SUCCESS here means it cannot.
rule p_txhash_blind_to_value(
    bytes32 d, address to, uint256 v1, uint256 v2, bytes data, BindingHarness.Operation op, uint256 n
) {
    assert safeTxHashOf(d, to, v1, data, op, 0, 0, 0, 0, 0, n)
        == safeTxHashOf(d, to, v2, data, op, 0, 0, 0, 0, 0, n),
        "PROBE: the monolithic Safe transaction hash is blind to `value`";
}

// (b) ... `nonce`?  (the field two of those variants move)
rule p_txhash_blind_to_nonce(
    bytes32 d, address to, uint256 v, bytes data, BindingHarness.Operation op, uint256 n1, uint256 n2
) {
    assert safeTxHashOf(d, to, v, data, op, 0, 0, 0, 0, 0, n1)
        == safeTxHashOf(d, to, v, data, op, 0, 0, 0, 0, 0, n2),
        "PROBE: the monolithic Safe transaction hash is blind to `nonce`";
}

// (c) ... the domain separator?
rule p_txhash_blind_to_domain(
    bytes32 d1, bytes32 d2, address to, uint256 v, bytes data, BindingHarness.Operation op, uint256 n
) {
    assert safeTxHashOf(d1, to, v, data, op, 0, 0, 0, 0, 0, n)
        == safeTxHashOf(d2, to, v, data, op, 0, 0, 0, 0, 0, n),
        "PROBE: the monolithic Safe transaction hash is blind to the domain separator";
}

// (d) Contrast 1: the word-aligned struct hash. A refutation here means the model *does* see `value`
//     one step earlier, so (a) is a property of the final offset-30 wrapper, not of hashing generally.
rule p_structhash_blind_to_value(
    address to, uint256 v1, uint256 v2, bytes data, BindingHarness.Operation op, uint256 n
) {
    assert structHashOf(to, v1, data, op, 0, 0, 0, 0, 0, n)
        == structHashOf(to, v2, data, op, 0, 0, 0, 0, 0, n),
        "PROBE: the SafeTx struct hash is blind to `value`";
}

// (e) Contrast 2: the assembly-free EIP-712 wrapper `keccak(0x1901 || d || s)`.
rule p_eip712_blind_to_inputs(bytes32 d1, bytes32 s1, bytes32 d2, bytes32 s2) {
    assert eip712Of(d1, s1) == eip712Of(d2, s2),
        "PROBE: the abi.encodePacked EIP-712 wrapper is blind to its inputs";
}
