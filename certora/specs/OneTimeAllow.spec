/* OneTimeAllowPolicy: R-OTA-1..5 and W-OTA-1, run by `conf/OneTimeAllow.conf`. Verified standalone
 * with a free env, no scene and no summaries; `e.msg.sender` is the guard namespace and stays free.
 * `LibHarness` supplies the total raw reader `wordAt`, and R_OTA_4's effect clause
 * asserts `wordAt` against the real `abi.decode(data, (bool))`. File-wide: L-POL-9 fixes the quantification
 * domain, L-POL-5 the raw-reader form of the decode clause, L-POL-CTX the prover's empty-`bytes` pair defect. */

using LibHarness as lib;

methods {
    function isGranted(address, address, AccessSelector.T) external returns (bool) envfree;
    function lib.wordAt(bytes, uint256) external returns (uint256) envfree;
}

// Read from the ABI so the magic value is the compiler's; R_OTA_1 also asserts it against the literal 0xcbd11d55, so a
// changed policy signature cannot drag the constant along (PolicyEngine.sol:202).
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,OneTimeAllowPolicy.Operation,address,bytes,AccessSelector.T).selector
);

// Two access selectors are the same key iff their packed words are equal: CVL models `AccessSelector.T` as its
// underlying `uint256`, so `==` on the type is that comparison.
definition sameKey(AccessSelector.T x, AccessSelector.T y) returns bool = x == y;

// R-OTA-1: `checkTransaction` reverts iff `msg.value != 0` or no unspent grant exists for (msg.sender, safe, access)
// before the call, and otherwise returns MAGIC (OneTimeAllowPolicy.sol:49-52).
rule R_OTA_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    OneTimeAllowPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    bool granted = isGranted(e.msg.sender, safe, access);

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert MAGIC() == to_bytes4(0xcbd11d55), "IPolicy.checkTransaction.selector";
    assert reverted <=> (e.msg.value != 0 || !granted),
        "OneTimeAllowPolicy.checkTransaction reverts exactly on nonzero msg.value or a missing grant";
    assert !reverted => r == MAGIC(),
        "OneTimeAllowPolicy.checkTransaction returns the magic value on success";
}

// R-OTA-1 over `calldataarg`: on every byte string the check is non-payable and any non-reverting call returns MAGIC,
// which rules out a `payable` re-declaration and any other `bytes4` returned at `OneTimeAllowPolicy.sol:52`.
rule R_OTA_1_anyCalldata(env e, calldataarg args) {
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "OneTimeAllowPolicy.checkTransaction is non-payable for every raw calldata";
    assert !reverted => r == MAGIC(),
        "every non-reverting checkTransaction call, on any calldata, returns the magic value";
}

// R-OTA-2: a successful check clears exactly the grant it spent (OneTimeAllowPolicy.sol:50) and a reverting one changes
// nothing, so an identical repeat check under the same env always reverts.
rule R_OTA_2(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    OneTimeAllowPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    address gp,
    address sp,
    AccessSelector.T ap
) {
    bool sameSlot = gp == e.msg.sender && sp == safe && sameKey(ap, access);
    bool otherBefore = isGranted(gp, sp, ap);
    storage before = lastStorage;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted1 = lastReverted;

    assert !reverted1 => !isGranted(e.msg.sender, safe, access),
        "a successful check spends the grant it authorised on";
    assert (!reverted1 && !sameSlot) => isGranted(gp, sp, ap) == otherBefore,
        "a successful check leaves every other (guard, safe, access) grant unchanged";
    assert reverted1 => lastStorage == before,
        "a reverting check changes no state";

    // The corollary is unconditional: a first success spent the grant (:50) and a first revert left storage unchanged
    // by the assert above.
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    assert lastReverted,
        "an identical repeat check always reverts - the grant was just spent, or the first check already failed";
}

// R-OTA-3: two checks from the same pre-state, same sender and same (safe, access) but differing in to, value, data,
// operation, module or context, agree on revert status and post-storage.
rule R_OTA_3(
    env e,
    address safe,
    AccessSelector.T access,
    address to1,
    uint256 value1,
    bytes data1,
    OneTimeAllowPolicy.Operation op1,
    address module1,
    bytes context1,
    address to2,
    uint256 value2,
    bytes data2,
    OneTimeAllowPolicy.Operation op2,
    address module2,
    bytes context2
) {
    storage init = lastStorage;

    checkTransaction@withrevert(e, safe, to1, value1, data1, op1, module1, context1, access);
    bool reverted1 = lastReverted;
    storage after1 = lastStorage;

    checkTransaction@withrevert(e, safe, to2, value2, data2, op2, module2, context2, access) at init;
    bool reverted2 = lastReverted;

    assert reverted1 == reverted2,
        "the verdict does not depend on to, value, data, operation, module or context";
    assert lastStorage == after1,
        "the state written does not depend on to, value, data, operation, module or context";
}

// R-OTA-3 with `context1` empty (L-POL-CTX), so supplying any context gets the verdict
// and post-state that supplying none gets.
rule R_OTA_3_emptyContext(
    env e,
    address safe,
    AccessSelector.T access,
    address to1,
    uint256 value1,
    bytes data1,
    OneTimeAllowPolicy.Operation op1,
    address module1,
    bytes context1,
    address to2,
    uint256 value2,
    bytes data2,
    OneTimeAllowPolicy.Operation op2,
    address module2,
    bytes context2
) {
    require context1.length == 0;

    storage init = lastStorage;

    checkTransaction@withrevert(e, safe, to1, value1, data1, op1, module1, context1, access);
    bool reverted1 = lastReverted;
    storage after1 = lastStorage;

    checkTransaction@withrevert(e, safe, to2, value2, data2, op2, module2, context2, access) at init;
    bool reverted2 = lastReverted;

    assert reverted1 == reverted2,
        "an arbitrary `context` gets the same verdict as no context at all";
    assert lastStorage == after1,
        "an arbitrary `context` leaves the same state as no context at all";
}

// R-OTA-4: `configure` reverts iff `msg.value != 0`, `data` is under 32 bytes, or its first word is not a canonical
// bool, and otherwise stores that bool at [msg.sender][safe][access] alone (:63-66, boundary asserted on chain by
// test/oneTimeAllowPolicy.spec.ts, "Should reject a configuration word that is not a canonical boolean").
rule R_OTA_4(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address gp,
    address sp,
    AccessSelector.T ap
) {
    uint256 w0 = lib.wordAt(data, 0);
    bool sameSlot = gp == e.msg.sender && sp == safe && sameKey(ap, access);
    bool otherBefore = isGranted(gp, sp, ap);

    bool ok = configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;

    assert reverted <=> (e.msg.value != 0 || data.length < 32 || w0 > 1),
        "OneTimeAllowPolicy.configure reverts exactly on nonzero msg.value, data under 32 bytes, or a non-bool first word";
    assert !reverted => ok,
        "OneTimeAllowPolicy.configure returns true on every accepted input";
    assert !reverted => isGranted(gp, sp, ap) == (sameSlot ? w0 == 1 : otherBefore),
        "configure stores the decoded bool at [msg.sender][safe][access] and touches no other grant";
}

// R-OTA-4 over `calldataarg`: `configure` is non-payable and never answers `false`, so every rejected shape is a revert
// the engine turns into PolicyConfigurationFailed (PolicyEngine.sol:292).
rule R_OTA_4_anyCalldata(env e, calldataarg args) {
    bool ok = configure@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "OneTimeAllowPolicy.configure is non-payable for every raw calldata";
    assert !reverted => ok,
        "configure never returns false on any calldata: rejection is always a revert";
}

// R-OTA-5: for every method and every (g', s', a'), a change to `isGranted(g', s', a')` implies g' == msg.sender, so
// one deployment serves many guards and Safes without interference (:49-50, :64).
rule R_OTA_5(env e, method f, calldataarg args, address gp, address sp, AccessSelector.T ap) {
    bool before = isGranted(gp, sp, ap);

    f(e, args);

    assert isGranted(gp, sp, ap) != before => gp == e.msg.sender,
        "no method writes a grant outside the caller's own guard namespace";
}

// R-OTA-5, writer-specific half for `checkTransaction`: it moves only the grant at (msg.sender, safe, access), the key
// it was asked about (OneTimeAllowPolicy.sol:49-50).
rule R_OTA_5_checkKeys(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    OneTimeAllowPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    address gp,
    address sp,
    AccessSelector.T ap
) {
    bool before = isGranted(gp, sp, ap);

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert isGranted(gp, sp, ap) != before =>
        (gp == e.msg.sender && sp == safe && sameKey(ap, access)),
        "checkTransaction writes only the grant named by its own (msg.sender, safe, access)";
}

// R-OTA-5, writer-specific half for `configure`: a rogue caller's configure lands in its own namespace and
// nowhere else (OneTimeAllowPolicy.sol:64).
rule R_OTA_5_configureKeys(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address gp,
    address sp,
    AccessSelector.T ap
) {
    bool before = isGranted(gp, sp, ap);

    configure@withrevert(e, safe, access, data);

    assert isGranted(gp, sp, ap) != before =>
        (gp == e.msg.sender && sp == safe && sameKey(ap, access)),
        "configure writes only the grant named by its own (msg.sender, safe, access)";
}

// W-OTA-1 witness (W_OTA_1a): a check that returns MAGIC, so R_OTA_1's success branch is non-vacuous.
rule W_OTA_1a(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    OneTimeAllowPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy r == MAGIC();
}

// W-OTA-1 witness (W_OTA_1b): `configure` writes a `true` word and a check by the same sender on the same (safe,
// access) returns MAGIC, with neither call under @withrevert.
rule W_OTA_1b(
    env e1,
    env e2,
    address safe,
    AccessSelector.T access,
    bytes d,
    address to,
    uint256 value,
    bytes data,
    OneTimeAllowPolicy.Operation op,
    address module,
    bytes context
) {
    configure(e1, safe, access, d);
    bytes4 r = checkTransaction(e2, safe, to, value, data, op, module, context, access);
    satisfy r == MAGIC()
        && e2.msg.sender == e1.msg.sender
        && lib.wordAt(d, 0) == 1
        && d.length >= 32;
}
