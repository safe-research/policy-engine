// EngineCheckFrame.spec: EngineCheck properties that take the HAVOC_ECF default of L-EC-5, such as INV-EC-1, in the
// EngineCheck scene. Split from EngineCheck.spec
// because a methods entry is per spec; HAVOC_ECF is sound here because a callee reaches the guard's own storage only
// through the guard's external methods, which a parametric property here quantifies over. Confs: the
// conf/EngineCheck*.conf files that verify this spec, EngineCheckInv.conf alone running the use invariant.
// File-wide: L-EC-9, L-EC-FRAME, L-EC-LOOP, L-EC-LOOP-N1, L-W0-SENDER.

import "Common.spec";

methods {
    // L-EC-5: the engine-to-policy default is HAVOC_ECF for the frame rows, an adversarial callee with arbitrary return
    // data and arbitrary effect on every contract but this one.
    function _.checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,address,bytes,AccessSelector.T) external
        => DISPATCH [ AllowPolicy._, DenyPolicy._, OneTimeAllowPolicy._, MockPolicyHarness._ ] default HAVOC_ECF;
    function _.configure(address,AccessSelector.T,bytes) external
        => DISPATCH [ AllowPolicy._, DenyPolicy._, OneTimeAllowPolicy._, MockPolicyHarness._ ] default HAVOC_ECF;

    // Policy to guard re-entry (MockPolicyHarness calls `msg.sender`).
    function _.checkTransaction(address,uint256,bytes,SafePolicyGuardHarness.Operation,uint256,uint256,uint256,address,address,bytes,address) external
        => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;
    function _.checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,bytes) external
        => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;
    function _.checkModuleTransaction(address,uint256,bytes,SafePolicyGuardHarness.Operation,address) external
        => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;
    function _.requestConfiguration(bytes32) external => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;
    function _.applyConfiguration(SafePolicyGuard.Configuration[]) external => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;
    function _.invalidateRoot(bytes32) external => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;
    function _.configureImmediately(SafePolicyGuard.Configuration[]) external => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;
    function _.rootConfigured(address,bytes32) external => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;
}

// INV-EC-1: no check is in progress between external transactions; the engine entry is filtered out (L-W0-INVFILTER)
// because its induction step is vacuous, which R_EC_4a_notChecking proves.
use invariant sentinelsClear filtered {
    f -> f.selector != sig:checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,bytes).selector
}

// R-EC-1: from any state with S == s != 0 (reached by W_EC_1_g) and M == m, every non-reverting method of the guard
// leaves S and M unchanged; the Safe hooks are excluded (L-EC-INVFILTER).
rule R_EC_1(env e, method f, calldataarg args, SafePolicyGuard.Configuration[] c, address s, address m)
    filtered { f -> !f.isView && !f.isPure
        && f.selector != sig:checkTransaction(address,uint256,bytes,SafePolicyGuardHarness.Operation,uint256,uint256,uint256,address,address,bytes,address).selector
        && f.selector != sig:checkModuleTransaction(address,uint256,bytes,SafePolicyGuardHarness.Operation,address).selector
        && f.selector != sig:applyConfiguration(SafePolicyGuard.Configuration[]).selector }
{
    require e.msg.sender != 0;
    require checkingSafe() == s && s != 0 && checkingModule() == m;

    if (f.selector == sig:configureImmediately(SafePolicyGuard.Configuration[]).selector) {
        require c.length <= 3;
        configureImmediately(e, c);
    } else {
        f(e, args);
    }

    assert checkingSafe() == s, "$checkingSafe is immutable while a check is in progress";
    assert checkingModule() == m, "$checkingModule is immutable while a check is in progress";
}

// R-EC-1's applyConfiguration node at n <= 1, the n <= 3 form having come back UNKNOWN at contract_recursion_limit 1 /
// summary_recursion_limit 1 (L-W0-RECUR).
rule R_EC_1_apply1(env e, SafePolicyGuard.Configuration[] c, address s, address m) {
    require e.msg.sender != 0;
    require checkingSafe() == s && s != 0 && checkingModule() == m;
    require c.length <= 1;
    applyConfiguration(e, c);
    assert checkingSafe() == s, "$checkingSafe is immutable while a check is in progress (applyConfiguration, n <= 1)";
    assert checkingModule() == m, "$checkingModule is immutable while a check is in progress (applyConfiguration, n <= 1)";
}

// The check-path entry points: both Safe hooks, the engine entry, and the `tryCheck` scaffolding.
definition isCheckPath(method f) returns bool =
    f.selector == sig:checkTransaction(address,uint256,bytes,SafePolicyGuardHarness.Operation,uint256,uint256,uint256,address,address,bytes,address).selector
    || f.selector == sig:checkModuleTransaction(address,uint256,bytes,SafePolicyGuardHarness.Operation,address).selector
    || f.selector == sig:checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,bytes).selector
    || f.selector == sig:tryCheck(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,bytes).selector;

definition isImmediateSel(method f) returns bool =
    f.selector == sig:configureImmediately(SafePolicyGuard.Configuration[]).selector;
definition isRequestSel(method f) returns bool = f.selector == sig:requestConfiguration(bytes32).selector;
definition isInvalidateSel(method f) returns bool = f.selector == sig:invalidateRoot(bytes32).selector;

persistent ghost mapping(address => bool) gCalled;

// No Sstore/Sload hook: it would trigger a scene-wide storage analysis that SafeMockHarness.getStorageAt defeats, after
// which every rule of the conf errors.
hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (executingContract == currentContract) {
        gCalled[addr] = true;
    }
}

function resetFrame() {
    require forall address a. !gCalled[a];
}

// R-CFG-2 re-instantiated in the EngineCheck scene, a second leaf of that row beside the EngineConfigFrame* confs:
// every $policies or rootConfigured namespace f writes lies in {sender} u C_f, and on the check path the guard writes
// neither.
rule EC_ConfigFrame(env e, method f, calldataarg args, SafePolicyGuard.Configuration[] c,
                    address x, AccessSelector.T k, bytes32 r)
    filtered { f -> !f.isView && !f.isPure
        && f.selector != sig:applyConfiguration(SafePolicyGuard.Configuration[]).selector }
{
    require e.msg.sender != 0;
    resetFrame();
    address pol0 = policyAt(x, k);
    uint256 root0 = rootConfigured(x, r);

    if (isImmediateSel(f)) {
        require c.length <= 3;
        configureImmediately(e, c);
    } else {
        f(e, args);
    }

    bool wrotePolicy = policyAt(x, k) != pol0;
    bool wroteRoot = rootConfigured(x, r) != root0;

    assert wrotePolicy => (x == e.msg.sender || gCalled[x]),
        "a $policies namespace that changed is the sender's or a callee's";
    assert wroteRoot => (x == e.msg.sender || gCalled[x]),
        "a rootConfigured namespace that changed is the sender's or a callee's";
    // applyConfiguration is filtered out of this rule; the EngineConfigFrame* confs carry that node of R-CFG-2.
    assert (wrotePolicy && x == e.msg.sender) => (isImmediateSel(f) || gCalled[x]),
        "$policies[S][.] changes only via configureImmediately or a re-entrant callee";
    assert isCheckPath(f) => ((wrotePolicy || wroteRoot) => gCalled[x]),
        "on the check path the guard's own code writes neither mapping in any namespace";
    assert (isRequestSel(f) || isInvalidateSel(f)) => !gCalled[x],
        "requestConfiguration/invalidateRoot make no outgoing call (C_f is empty)";
}

// R-CFG-2 re-instantiated, the applyConfiguration node of EC_ConfigFrame at n <= 1; R_CFG_2_apply1 states that
// node's first two asserts in the EngineConfig scene at n <= 1, and R_CFG_2 filters that node out.
rule EC_ConfigFrame_apply1(env e, SafePolicyGuard.Configuration[] c,
                           address x, AccessSelector.T k, bytes32 r) {
    require e.msg.sender != 0;
    resetFrame();
    require c.length <= 1;
    address pol0 = policyAt(x, k);
    uint256 root0 = rootConfigured(x, r);
    applyConfiguration(e, c);
    bool wrotePolicy = policyAt(x, k) != pol0;
    bool wroteRoot = rootConfigured(x, r) != root0;
    assert wrotePolicy => (x == e.msg.sender || gCalled[x]),
        "a $policies namespace that changed is the sender's or a callee's (applyConfiguration, n <= 1)";
    assert wroteRoot => (x == e.msg.sender || gCalled[x]),
        "a rootConfigured namespace that changed is the sender's or a callee's (applyConfiguration, n <= 1)";
}
