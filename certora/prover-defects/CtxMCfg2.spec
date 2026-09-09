/*
 * CtxMCfg2.spec: four instances of R_CFG_9_effects that separate two readings of the CtxMCfg vacuity
 * under precise_bitwise_ops: c.length == 2 is unreachable, or the empty-data requirement empties the model and
 * the flag erases empty struct-array buffers (L-POL-CTX, report 6.3). The flag-off companion conf,
 * CtxMCfg2NoBitwise.conf, says which reading is an artifact of the encoding.
 * Every rule body is R_CFG_9_effects's, verbatim, plus the `require`s the rule header names. The shared
 * ones are L-W0-SENDER (msg.sender != 0), L-CFG-LOOP (c.length <= 3), L-CFG-SCENE (allEntriesInScene)
 * and L-CFG-RECUR (configureMode != CALL_CONFIG); `i < c.length` keeps the decoders in range.
 */

import "../specs/EngineConfig.spec";

// R-CFG-9 effects at c.length <= 1: at most one free CVL `bytes`, out of the L-POL-CTX class.
rule R_CFG_9_effects_n1(env e, SafePolicyGuard.Configuration[] c, uint256 i, address sx, AccessSelector.T kx,
                     address s2, bytes32 r2, address x) {
    require c.length <= 1;

    require e.msg.sender != 0;
    require c.length <= 3;
    require allEntriesInScene(c);
    require mockPolicy.configureMode() != MockPolicyHarness.ConfigureMode.CALL_CONFIG;
    require i < c.length;
    resetFrame();

    address polOther0 = policyAt(sx, kx);
    uint256 root0 = rootConfigured(s2, r2);

    configureImmediately(e, c);

    assert policyAt(e.msg.sender, configKey(c, i)) == lastPolicyForKey(c, configKey(c, i)),
        "each named key holds the last entry's policy (last-write-wins)";
    assert (sx != e.msg.sender || !keyInArray(c, kx)) => policyAt(sx, kx) == polOther0,
        "no other (safe, key) entry of $policies changes";
    assert rootConfigured(s2, r2) == root0, "rootConfigured is untouched for every (safe, root)";
    assert gConfigureCalls == nonZeroPolicyCount(c) && gCalls == nonZeroPolicyCount(c),
        "configure is called exactly once per non-zero entry, and nothing else is called";
    assert gValueCalls == 0 && gDelegateCalls == 0, "no value-bearing call and no DELEGATECALL";
    assert gCalled[x] => calleesAreArrayPolicies(c, x), "every callee is one of the array's non-zero policies";
}

// R-CFG-9 effects at c.length == 2 with no `data` pinned: the control for the two probes below.
rule R_CFG_9_effects_n2(env e, SafePolicyGuard.Configuration[] c, uint256 i, address sx, AccessSelector.T kx,
                     address s2, bytes32 r2, address x) {
    require c.length == 2;

    require e.msg.sender != 0;
    require c.length <= 3;
    require allEntriesInScene(c);
    require mockPolicy.configureMode() != MockPolicyHarness.ConfigureMode.CALL_CONFIG;
    require i < c.length;
    resetFrame();

    address polOther0 = policyAt(sx, kx);
    uint256 root0 = rootConfigured(s2, r2);

    configureImmediately(e, c);

    assert policyAt(e.msg.sender, configKey(c, i)) == lastPolicyForKey(c, configKey(c, i)),
        "each named key holds the last entry's policy (last-write-wins)";
    assert (sx != e.msg.sender || !keyInArray(c, kx)) => policyAt(sx, kx) == polOther0,
        "no other (safe, key) entry of $policies changes";
    assert rootConfigured(s2, r2) == root0, "rootConfigured is untouched for every (safe, root)";
    assert gConfigureCalls == nonZeroPolicyCount(c) && gCalls == nonZeroPolicyCount(c),
        "configure is called exactly once per non-zero entry, and nothing else is called";
    assert gValueCalls == 0 && gDelegateCalls == 0, "no value-bearing call and no DELEGATECALL";
    assert gCalled[x] => calleesAreArrayPolicies(c, x), "every callee is one of the array's non-zero policies";
}

// R-CFG-9 effects at c.length == 2, first entry's buffer pinned empty: the L-POL-CTX shape.
rule R_CFG_9_effects_c0E(env e, SafePolicyGuard.Configuration[] c, uint256 i, address sx, AccessSelector.T kx,
                     address s2, bytes32 r2, address x) {
    require c.length == 2;
    require c[0].data.length == 0;

    require e.msg.sender != 0;
    require c.length <= 3;
    require allEntriesInScene(c);
    require mockPolicy.configureMode() != MockPolicyHarness.ConfigureMode.CALL_CONFIG;
    require i < c.length;
    resetFrame();

    address polOther0 = policyAt(sx, kx);
    uint256 root0 = rootConfigured(s2, r2);

    configureImmediately(e, c);

    assert policyAt(e.msg.sender, configKey(c, i)) == lastPolicyForKey(c, configKey(c, i)),
        "each named key holds the last entry's policy (last-write-wins)";
    assert (sx != e.msg.sender || !keyInArray(c, kx)) => policyAt(sx, kx) == polOther0,
        "no other (safe, key) entry of $policies changes";
    assert rootConfigured(s2, r2) == root0, "rootConfigured is untouched for every (safe, root)";
    assert gConfigureCalls == nonZeroPolicyCount(c) && gCalls == nonZeroPolicyCount(c),
        "configure is called exactly once per non-zero entry, and nothing else is called";
    assert gValueCalls == 0 && gDelegateCalls == 0, "no value-bearing call and no DELEGATECALL";
    assert gCalled[x] => calleesAreArrayPolicies(c, x), "every callee is one of the array's non-zero policies";
}

// R-CFG-9 effects at c.length == 2, second entry's buffer pinned empty: the mirror of `_c0E`.
rule R_CFG_9_effects_c1E(env e, SafePolicyGuard.Configuration[] c, uint256 i, address sx, AccessSelector.T kx,
                     address s2, bytes32 r2, address x) {
    require c.length == 2;
    require c[1].data.length == 0;

    require e.msg.sender != 0;
    require c.length <= 3;
    require allEntriesInScene(c);
    require mockPolicy.configureMode() != MockPolicyHarness.ConfigureMode.CALL_CONFIG;
    require i < c.length;
    resetFrame();

    address polOther0 = policyAt(sx, kx);
    uint256 root0 = rootConfigured(s2, r2);

    configureImmediately(e, c);

    assert policyAt(e.msg.sender, configKey(c, i)) == lastPolicyForKey(c, configKey(c, i)),
        "each named key holds the last entry's policy (last-write-wins)";
    assert (sx != e.msg.sender || !keyInArray(c, kx)) => policyAt(sx, kx) == polOther0,
        "no other (safe, key) entry of $policies changes";
    assert rootConfigured(s2, r2) == root0, "rootConfigured is untouched for every (safe, root)";
    assert gConfigureCalls == nonZeroPolicyCount(c) && gCalls == nonZeroPolicyCount(c),
        "configure is called exactly once per non-zero entry, and nothing else is called";
    assert gValueCalls == 0 && gDelegateCalls == 0, "no value-bearing call and no DELEGATECALL";
    assert gCalled[x] => calleesAreArrayPolicies(c, x), "every callee is one of the array's non-zero policies";
}
