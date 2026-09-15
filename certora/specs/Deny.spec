/* DenyPolicy: R-DENY-1, run by `conf/Deny.conf`.
 * Verified standalone with a free env, no scene and no summaries.
 * L-POL-6 splits each value claim in two: the `calldataarg` rules quantify over every raw byte string,
 * the typed-argument rules add the revert-iff's liveness half, which is false over raw calldata because
 * a rejected encoding reverts in solc's decoder; residual reverts become `PolicyReverted`. */

// Read from the ABI so the magic value is the compiler's, not the literal (PolicyEngine.sol:202).
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,DenyPolicy.Operation,address,bytes,AccessSelector.T).selector
);

// R-DENY-1, whose engine half is R-EC-4(c): `checkTransaction` reverts iff `msg.value != 0` and otherwise returns
// exactly bytes4(0), never MAGIC (DenyPolicy.sol:18-27); L-POL-6.
rule R_DENY_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    DenyPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    // Pinned to the engine's literal: MAGIC() reads this contract's ABI, so a changed policy signature cannot
    // drag the constant along.
    assert MAGIC() == to_bytes4(0xcbd11d55), "IPolicy.checkTransaction.selector";
    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;
    assert reverted <=> e.msg.value != 0, "DenyPolicy.checkTransaction reverts exactly on nonzero msg.value";
    assert !reverted => r == to_bytes4(0), "DenyPolicy.checkTransaction returns the zero magic value";
    assert !reverted => r != MAGIC(), "DenyPolicy.checkTransaction never returns the magic value";
}

// R-DENY-1 over `calldataarg`: no byte string makes DenyPolicy answer MAGIC, so the engine sees either
// PolicyReverted or AccessDenied (L-POL-6).
rule R_DENY_1_anyCalldata(env e, calldataarg args) {
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "DenyPolicy.checkTransaction is non-payable for every raw calldata";
    assert !reverted => r == to_bytes4(0),
        "DenyPolicy.checkTransaction returns the zero magic value, for every raw calldata";
    assert !reverted => r != MAGIC(),
        "DenyPolicy.checkTransaction never returns the magic value, for every raw calldata";
}

// W-DENY-1: a non-reverting `checkTransaction` returning zero on the shape W_ALLOW_1 fixes, so R-DENY-1's
// success branch is not vacuous.
rule W_DENY_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    DenyPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy r == to_bytes4(0) && value > 0 && data.length >= 4 && module != 0;
}
