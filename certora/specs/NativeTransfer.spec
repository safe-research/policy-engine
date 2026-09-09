/* NativeTransferPolicy: R-NATIVE-1, R-NATIVE-2 and W-NATIVE-1, run by `conf/NativeTransfer.conf` under exact
 * bitvector modelling (L-POL-3). Verified standalone with a free env, no scene and no summaries;
 * access-selector words are unpacked through LibHarness wrappers over the real AccessSelector library
 * rather than with CVL bitwise ops. L-POL-6 fixes the quantification domain: the typed rules own every
 * clause naming `value` or `access`. The op-mask companion is scoped by L-POL-2. Defect L-POL-CTX: R_NATIVE_1
 * takes two free CVL `bytes` (`data`, `context`) into a call under the conf's `precise_bitwise_ops: true`,
 * which is the shape L-POL-CTX describes, so its input pairs with exactly one empty buffer are dropped; no
 * companion rule ships here. */

using LibHarness as lib;

methods {
    function lib.getSelector(AccessSelector.T) external returns (bytes4) envfree;
    function lib.getOperation(AccessSelector.T) external returns (NativeTransferPolicy.Operation) envfree;
    // Operation.CALL and Operation.DELEGATECALL are reserved CVL tokens, so read the enum here.
    function lib.opCall() external returns (NativeTransferPolicy.Operation) envfree;
    function lib.opDelegateCall() external returns (NativeTransferPolicy.Operation) envfree;
}

// Read from the ABI so the magic value is the compiler's, not the literal (PolicyEngine.sol:202).
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,NativeTransferPolicy.Operation,address,bytes,AccessSelector.T).selector
);

// R-NATIVE-1: `checkTransaction` reverts iff `msg.value != 0` or `value == 0` and otherwise returns MAGIC, with every
// other argument free, which is the policy half of finding B-2 (NativeTransferPolicy.sol:29-30).
rule R_NATIVE_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    NativeTransferPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    // Pinned to the engine's literal: MAGIC() reads this contract's ABI, so a changed policy signature cannot
    // drag the constant along.
    assert MAGIC() == to_bytes4(0xcbd11d55), "IPolicy.checkTransaction.selector";
    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;
    assert reverted <=> (e.msg.value != 0 || value == 0),
        "NativeTransferPolicy.checkTransaction reverts exactly on nonzero msg.value or zero transfer value";
    assert !reverted => r == MAGIC(),
        "NativeTransferPolicy.checkTransaction returns the magic value on success";
}

// R-NATIVE-1 over `calldataarg`: no byte string makes the policy answer anything but MAGIC or a revert, which the
// engine turns into `PolicyReverted` (PolicyEngine.sol:203-204).
rule R_NATIVE_1_anyCalldata(env e, calldataarg args) {
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "NativeTransferPolicy.checkTransaction is non-payable for every raw calldata";
    assert !reverted => r == MAGIC(),
        "NativeTransferPolicy.checkTransaction answers MAGIC or reverts, for every raw calldata";
}

// R-NATIVE-2: `configure` reverts iff `msg.value != 0` and returns true iff `getSelector(access) == 0` and
// `getOperation(access) == CALL`, so within bits 160..223 only bit 216 decides and bits 160..215 and 217..223 are
// ignored, the selector bits 224..255 deciding separately (NativeTransferPolicy.sol:36-38, AccessSelector.sol:66).
rule R_NATIVE_2(env e, address safe, AccessSelector.T access, bytes data) {
    bool keyOk = lib.getSelector(access) == to_bytes4(0) && lib.getOperation(access) == lib.opCall();
    bool ok = configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;
    assert reverted <=> e.msg.value != 0, "NativeTransferPolicy.configure reverts exactly on nonzero msg.value";
    assert !reverted => (ok <=> keyOk),
        "NativeTransferPolicy.configure accepts exactly zero-selector CALL keys";
}

// R-NATIVE-2 over `calldataarg`: the non-payable half only, since the key verdict needs the decoded
// `access` word a calldataarg cannot supply.
rule R_NATIVE_2_anyCalldata(env e, calldataarg args) {
    configure@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "NativeTransferPolicy.configure is non-payable for every raw calldata";
}

// R-NATIVE-2 op-mask companion: concrete non-canonical instances of the R_NATIVE_2 iff, the same four words
// test/nativeTransferPolicy.spec.ts fixes in "Should read the operation from its own byte and ignore the padding around
// it" (AccessSelector.sol:66).
rule R_NATIVE_2_opMask(
    env e,
    address safe,
    bytes data,
    AccessSelector.T aBit217,
    AccessSelector.T aBit200,
    AccessSelector.T aBit216,
    AccessSelector.T aBit224
) {
    // CVL models `AccessSelector.T` as its underlying `uint256`, so each word is pinned directly.
    require aBit217 == 0x2000000000000000000000000000000000000000000000000000000;
    require aBit200 == 0x100000000000000000000000000000000000000000000000000;
    require aBit216 == 0x1000000000000000000000000000000000000000000000000000000;
    require aBit224 == 0x100000000000000000000000000000000000000000000000000000000;
    // One `env` for all four calls: `configure` is `external pure`, so the access word is the only
    // varying input (NativeTransferPolicy.sol:36).
    assert configure(e, safe, aBit217, data), "bit 217 is outside the operation mask: accepted";
    assert configure(e, safe, aBit200, data), "bits 160..215 are ignored: accepted";
    assert !configure(e, safe, aBit216, data), "bit 216 set = DELEGATECALL key: rejected";
    assert !configure(e, safe, aBit224, data), "nonzero selector byte: rejected";
}

// W-NATIVE-1 witness (W_NATIVE_1a): a check returning MAGIC with value > 0 and data.length >= 4, the side of finding
// B-2 where calldata-bearing value transfers pass.
rule W_NATIVE_1a(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    NativeTransferPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy r == MAGIC() && value > 0 && data.length >= 4;
}

// W-NATIVE-1 witness (W_NATIVE_1b): a check returning MAGIC with operation == DELEGATECALL,
// since only `configure` fixes the operation.
rule W_NATIVE_1b(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    NativeTransferPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy r == MAGIC() && op == lib.opDelegateCall();
}
