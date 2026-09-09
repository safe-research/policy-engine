/* AllowPolicy: R-ALLOW-1, run by `conf/Allow.conf`.
 * Verified standalone with a free env, no scene and no summaries.
 * L-POL-6 splits each value claim in two: the `calldataarg` rules quantify over every raw byte string,
 * the typed-argument rules add the revert-iff's liveness half, which is false over raw calldata because
 * a rejected encoding reverts in solc's decoder with `msg.value == 0`. */

// Read from the ABI so the magic value is the compiler's, not the literal (PolicyEngine.sol:202).
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,AllowPolicy.Operation,address,bytes,AccessSelector.T).selector
);

// R-ALLOW-1: `checkTransaction` reverts iff `msg.value != 0` and otherwise returns MAGIC, for every argument vector and
// sender (AllowPolicy.sol:16-27); L-POL-6.
rule R_ALLOW_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    AllowPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    // Pinned to the engine's literal: MAGIC() reads this contract's ABI, so a changed policy signature cannot
    // drag the constant along.
    assert MAGIC() == to_bytes4(0xcbd11d55), "IPolicy.checkTransaction.selector";
    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;
    assert reverted <=> e.msg.value != 0, "AllowPolicy.checkTransaction reverts exactly on nonzero msg.value";
    assert !reverted => r == MAGIC(), "AllowPolicy.checkTransaction returns the magic value on success";
}

// R-ALLOW-1 over `calldataarg`, so no encoding can make the policy answer anything but MAGIC or a revert; the
// liveness half is left to R_ALLOW_1 (L-POL-6).
rule R_ALLOW_1_anyCalldata(env e, calldataarg args) {
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "AllowPolicy.checkTransaction is non-payable for every raw calldata";
    assert !reverted => r == MAGIC(),
        "AllowPolicy.checkTransaction answers MAGIC or reverts, for every raw calldata";
}

