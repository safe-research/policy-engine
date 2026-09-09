// Defect B reduced root cause on the unmutated contract (report 6.3, L-POL-CTX): an assert and a
// satisfy over the same input pair, in one build and one job. An assert SUCCESS beside a satisfy
// SUCCESS is the defect signature. CtxPair.conf runs it with precise_bitwise_ops on, CtxPairNoBitwise.conf
// with it off.
// Defect B: the pair (empty `context1`, non-empty `context2`) over two calls is claimed impossible.
rule V_pair_assert(
    env e, address safe, address to, uint256 value, bytes data,
    ERC20TransferPolicyHarness.Operation op, address module, AccessSelector.T access,
    bytes context1, bytes context2
) {
    storage init = lastStorage;
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context1, access);
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context2, access) at init;
    assert !(context1.length == 0 && context2.length > 0),
        "the prover reaches no model with an empty context1 beside a non-empty context2";
}

// The same pair asked for as a `satisfy`, in the same build and the same job as `V_pair_assert`.
rule V_pair_satisfy(
    env e, address safe, address to, uint256 value, bytes data,
    ERC20TransferPolicyHarness.Operation op, address module, AccessSelector.T access,
    bytes context1, bytes context2
) {
    storage init = lastStorage;
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context1, access);
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context2, access) at init;
    satisfy context1.length == 0 && context2.length > 0;
}

// The same pair when only ONE call is made -- is the two-call shape what matters?
rule V_pair_assert_onecall(
    env e, address safe, address to, uint256 value, bytes data,
    ERC20TransferPolicyHarness.Operation op, address module, AccessSelector.T access,
    bytes context1, bytes context2
) {
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context1, access);
    assert !(context1.length == 0 && context2.length > 0),
        "one call only; context2 is passed nowhere";
}

// And with no call at all.
rule V_pair_assert_nocall(bytes context1, bytes context2) {
    assert !(context1.length == 0 && context2.length > 0), "no call at all";
}

// Does it depend on which side is empty?
rule V_pair_assert_swapped(
    env e, address safe, address to, uint256 value, bytes data,
    ERC20TransferPolicyHarness.Operation op, address module, AccessSelector.T access,
    bytes context1, bytes context2
) {
    storage init = lastStorage;
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context1, access);
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context2, access) at init;
    assert !(context2.length == 0 && context1.length > 0),
        "the mirror pair: empty context2 beside a non-empty context1";
}

// The L-POL-CTX exclusion clause over two buffers that are both arguments of the one call. Measured SUCCESS,
// so the exclusion is false.
rule V_pair_assert_onecall_bothPassed(
    env e, address safe, address to, uint256 value, bytes data,
    ERC20TransferPolicyHarness.Operation op, address module, AccessSelector.T access,
    bytes context1, bytes context2
) {
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context1, access);
    assert !(data.length == 0 && context1.length > 0),
        "one call only; BOTH data and context1 are arguments of that call";
}

// The decisive shape: exactly two free `bytes`, both arguments of the single call, with the satisfy twin
// in the same job.
rule V_pair_assert_twoBytesBothPassed(
    env e, address safe, address to, uint256 value, bytes data,
    ERC20TransferPolicyHarness.Operation op, address module, AccessSelector.T access,
    bytes context1
) {
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context1, access);
    assert !(data.length == 0 && context1.length > 0),
        "exactly two free bytes, BOTH arguments of the one call";
}

// The pair (empty `data`, non-empty `context1`) asked for as a `satisfy`, both buffers on one call.
rule V_pair_satisfy_twoBytesBothPassed(
    env e, address safe, address to, uint256 value, bytes data,
    ERC20TransferPolicyHarness.Operation op, address module, AccessSelector.T access,
    bytes context1
) {
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context1, access);
    satisfy data.length == 0 && context1.length > 0;
}

// The mirror pair (empty `context1`, non-empty `data`) claimed impossible, both buffers on one call.
rule V_pair_assert_twoBytesBothPassed_swapped(
    env e, address safe, address to, uint256 value, bytes data,
    ERC20TransferPolicyHarness.Operation op, address module, AccessSelector.T access,
    bytes context1
) {
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context1, access);
    assert !(context1.length == 0 && data.length > 0),
        "the mirror pair, exactly two free bytes, both arguments of the one call";
}

// Result: every assert shape in which a call occurs is SUCCESS with the flag on and FAIL with it off;
// the no-call shape FAILs under both and both satisfy rules SUCCEED under both, so the discriminator is
// the flag, not the call shape (report 6.3).
