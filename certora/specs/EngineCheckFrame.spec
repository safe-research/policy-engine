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

persistent ghost mapping(address => bool) gCalled;

// No Sstore/Sload hook: it would trigger a scene-wide storage analysis that SafeMockHarness.getStorageAt defeats, after
// which every rule of the conf errors.
hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (executingContract == currentContract) {
        gCalled[addr] = true;
    }
}

