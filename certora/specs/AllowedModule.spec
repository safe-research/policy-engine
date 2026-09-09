/* AllowedModulePolicy: R-AMOD-1..3, INV-AMOD-1 and W-AMOD-1, run by `conf/AllowedModule.conf`.
 * Verified standalone with a free env, no scene and no summaries; `e.msg.sender` is the guard
 * namespace and stays free. `LibHarness` supplies the total raw reader `wordAt`, which R_AMOD_2's
 * effect clause asserts against the real `abi.decode(data, (address, bool))`.
 * File-wide: L-POL-9 fixes the quantification domain, L-POL-5 the raw-reader form of the decode clause,
 * L-POL-CTX the empty-`bytes` defect. */

using LibHarness as lib;

methods {
    function isModuleAllowed(address, address, address) external returns (bool) envfree;
    function lib.wordAt(bytes, uint256) external returns (uint256) envfree;
}

// Read from the ABI so the magic value is the compiler's; R_AMOD_1 also asserts it against the literal 0xcbd11d55, so a
// changed policy signature cannot drag the constant along (PolicyEngine.sol:202).
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,AllowedModulePolicy.Operation,address,bytes,AccessSelector.T).selector
);

// R-AMOD-1: `checkTransaction` reverts iff `msg.value != 0`, the engine-supplied `module` is zero, or that module is
// not allowlisted under (msg.sender, safe), and otherwise returns MAGIC (AllowedModulePolicy.sol:45-48).
rule R_AMOD_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    AllowedModulePolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    bool allowed = isModuleAllowed(e.msg.sender, safe, module);

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert MAGIC() == to_bytes4(0xcbd11d55), "IPolicy.checkTransaction.selector";
    assert reverted <=> (e.msg.value != 0 || module == 0 || !allowed),
        "AllowedModulePolicy.checkTransaction reverts exactly on nonzero msg.value, a zero module, or a module that is not allowlisted";
    assert !reverted => r == MAGIC(),
        "AllowedModulePolicy.checkTransaction returns the magic value on success";
}

// R-AMOD-1 over `calldataarg`: on every byte string the check is non-payable and any non-reverting call returns MAGIC,
// which rules out a `payable` re-declaration and any other `bytes4` returned at `AllowedModulePolicy.sol:48`.
rule R_AMOD_1_anyCalldata(env e, calldataarg args) {
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "AllowedModulePolicy.checkTransaction is non-payable for every raw calldata";
    assert !reverted => r == MAGIC(),
        "every non-reverting checkTransaction call, on any calldata, returns the magic value";
}

// R-AMOD-1 independence clause: the verdict is a function of (msg.sender, safe, module) alone, so two checks from the
// same pre-state agreeing on those three agree on revert status and post-storage (AllowedModulePolicy.sol:31-33).
rule R_AMOD_1_independent(
    env e,
    address safe,
    address module,
    address to1,
    uint256 value1,
    bytes data1,
    AllowedModulePolicy.Operation op1,
    bytes context1,
    AccessSelector.T access1,
    address to2,
    uint256 value2,
    bytes data2,
    AllowedModulePolicy.Operation op2,
    bytes context2,
    AccessSelector.T access2
) {
    storage init = lastStorage;

    checkTransaction@withrevert(e, safe, to1, value1, data1, op1, module, context1, access1);
    bool reverted1 = lastReverted;
    storage after1 = lastStorage;

    checkTransaction@withrevert(e, safe, to2, value2, data2, op2, module, context2, access2) at init;
    bool reverted2 = lastReverted;

    assert reverted1 == reverted2,
        "the verdict does not depend on context, to, value, data, operation or access";
    assert lastStorage == after1,
        "the state after the check does not depend on context, to, value, data, operation or access";
}

// R-AMOD-1 independence clause with `context1` empty (L-POL-CTX): the executable form of "never read the module from
// `context`, which any executor can choose" (AllowedModulePolicy.sol:33).
rule R_AMOD_1_independent_emptyContext(
    env e,
    address safe,
    address module,
    address to1,
    uint256 value1,
    bytes data1,
    AllowedModulePolicy.Operation op1,
    bytes context1,
    AccessSelector.T access1,
    address to2,
    uint256 value2,
    bytes data2,
    AllowedModulePolicy.Operation op2,
    bytes context2,
    AccessSelector.T access2
) {
    require context1.length == 0;

    storage init = lastStorage;

    checkTransaction@withrevert(e, safe, to1, value1, data1, op1, module, context1, access1);
    bool reverted1 = lastReverted;
    storage after1 = lastStorage;

    checkTransaction@withrevert(e, safe, to2, value2, data2, op2, module, context2, access2) at init;
    bool reverted2 = lastReverted;

    assert reverted1 == reverted2,
        "an arbitrary `context` gets the same verdict as no context at all";
    assert lastStorage == after1,
        "an arbitrary `context` leaves the same state as no context at all";
}

// INV-AMOD-1: the zero address is never allowlistable under any guard or Safe (AllowedModulePolicy.sol:62-63), so the
// owner path is denied twice over: by the check's own module != 0 require (R-AMOD-1) and, were that removed, by the
// empty allowlist entry.
invariant INV_AMOD_1(address g, address s)
    !isModuleAllowed(g, s, 0);

// R-AMOD-2: `configure` reverts iff `msg.value != 0`, `data` is short, its module word has dirty high bits, its flag
// word is not a canonical bool, or the decoded module is zero, and otherwise stores the decoded flag at
// [msg.sender][safe][module] (AllowedModulePolicy.sol:60-68); the missing `access` is finding B-6.
rule R_AMOD_2(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address gp,
    address sp,
    address mp
) {
    uint256 w0 = lib.wordAt(data, 0);
    uint256 w1 = lib.wordAt(data, 32);
    bool sameSlot = gp == e.msg.sender && sp == safe && assert_uint256(mp) == w0;
    bool otherBefore = isModuleAllowed(gp, sp, mp);

    bool ok = configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;

    assert reverted <=> (e.msg.value != 0 || data.length < 64 || w0 >= 2^160 || w1 > 1 || w0 == 0),
        "AllowedModulePolicy.configure reverts exactly on nonzero msg.value, data under 64 bytes, a dirty module word, a non-bool flag word, or a zero module";
    assert !reverted => ok,
        "AllowedModulePolicy.configure returns true on every accepted input";
    assert !reverted => isModuleAllowed(gp, sp, mp) == (sameSlot ? w1 == 1 : otherBefore),
        "configure stores the decoded flag at [msg.sender][safe][decoded module] and touches no other entry";
}

// R-AMOD-2 over `calldataarg`: `configure` is non-payable and never answers `false`, so every rejected shape is a
// revert the engine turns into PolicyConfigurationFailed (PolicyEngine.sol:292).
rule R_AMOD_2_anyCalldata(env e, calldataarg args) {
    bool ok = configure@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "AllowedModulePolicy.configure is non-payable for every raw calldata";
    assert !reverted => ok,
        "configure never returns false on any calldata: rejection is always a revert";
}

// R-AMOD-3: for every method and every (g', s', m'), a change to `isModuleAllowed(g', s', m')` implies the method was
// `configure` and g' == msg.sender (AllowedModulePolicy.sol:65).
rule R_AMOD_3(env e, method f, calldataarg args, address gp, address sp, address mp) {
    bool before = isModuleAllowed(gp, sp, mp);

    f(e, args);

    assert isModuleAllowed(gp, sp, mp) != before =>
        (f.selector == sig:configure(address,AccessSelector.T,bytes).selector && gp == e.msg.sender),
        "only configure writes the allowlist, and only in the caller's own guard namespace";
}

// R-AMOD-3, writer-specific half: `configure` moves only the entry named by its own (msg.sender, safe) and the module
// word it decoded (AllowedModulePolicy.sol:61-65).
rule R_AMOD_3_configureKeys(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address gp,
    address sp,
    address mp
) {
    bool before = isModuleAllowed(gp, sp, mp);

    configure@withrevert(e, safe, access, data);

    assert isModuleAllowed(gp, sp, mp) != before =>
        (gp == e.msg.sender && sp == safe && assert_uint256(mp) == lib.wordAt(data, 0)),
        "configure writes only the allowlist entry named by its own (msg.sender, safe) and the decoded module";
}

// W-AMOD-1 witness (W_AMOD_1a): a check that returns MAGIC, necessarily with a nonzero allowlisted module, so
// R_AMOD_1's success branch is not vacuous.
rule W_AMOD_1a(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    AllowedModulePolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy r == MAGIC() && module != 0;
}

// W-AMOD-1 witness (W_AMOD_1b): `configure` allowlists a module and a check by the same sender for it returns MAGIC,
// with the configured and checked keys forced apart, which witnesses finding B-6.
rule W_AMOD_1b(
    env e1,
    env e2,
    address safe,
    AccessSelector.T access1,
    bytes d,
    address to,
    uint256 value,
    bytes data,
    AllowedModulePolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access2
) {
    configure(e1, safe, access1, d);
    bytes4 r = checkTransaction(e2, safe, to, value, data, op, module, context, access2);
    satisfy r == MAGIC()
        && e2.msg.sender == e1.msg.sender
        && assert_uint256(module) == lib.wordAt(d, 0)
        && lib.wordAt(d, 32) == 1
        && access1 != access2;
}
