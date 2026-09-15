// EngineConfig.spec: the configuration surface of SafePolicyGuard, its property rows (the composition headline
// has no rule of its own), on SafePolicyGuardHarness in
// the closed scene {AllowPolicy, DenyPolicy, OneTimeAllowPolicy, MockPolicyHarness} with
// SafeMockHarness, GuardProbeResponderMock, SafeSlotMock and LibHarness.
// Run by the conf/EngineConfig*.conf files that verify this spec.
// File-wide: L-CFG-SCENE, L-CFG-LOOP (n <= 3), L-CFG-LOOP-N1 (n <= 1 twins), L-CFG-RECUR, L-CFG-PROBE,
// L-CFG-GATE, L-CFG-SLOTMOCK, L-CFG-FRAME, L-ENV-TIME, L-POL-CTX-M, L-W0-SENDER.

import "Common.spec";

using AllowPolicy as allow;
using DenyPolicy as deny;
using OneTimeAllowPolicy as oneTimeAllow;
using GuardProbeResponderMock as responder;
using SafeSlotMock as slotMock;

methods {
    // Commented out with the rule that used it.
    // function responder.mode(uint256) external returns (GuardProbeResponderMock.Mode) envfree;
    // function responder.retLen(uint256) external returns (uint256) envfree;
    // function responder.word3Address(uint256) external returns (address) envfree;
    function slotMock.slotAddress(uint256) external returns (address) envfree;
    function oneTimeAllow.isGranted(address, address, AccessSelector.T) external returns (bool) envfree;
    function configDataWord0(SafePolicyGuard.Configuration[], uint256) external returns (uint256) envfree;
    // #101's window bound and its error; declared here rather than in Common.spec, which other specs share.
    function EXPIRY() external returns (uint256) envfree;

    // Scene dispatch, per signature (D-009): the closed scene stands in for arbitrary policy code (L-W0-2); an
    // out-of-scene address takes the D-008 HAVOC_ECF.
    function _.checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,address,bytes,AccessSelector.T) external
        => DISPATCH [ AllowPolicy._, DenyPolicy._, OneTimeAllowPolicy._, MockPolicyHarness._ ] default HAVOC_ECF;
    function _.configure(address,AccessSelector.T,bytes) external
        => DISPATCH [ AllowPolicy._, DenyPolicy._, OneTimeAllowPolicy._, MockPolicyHarness._ ] default HAVOC_ECF;

    // Policy re-entry into the guard: the guard itself resolves, any other callee is NONDET.
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

    // Guard-to-Safe probe, a raw STATICCALL: SafeMockHarness is excluded because the prover's storage analysis fails on
    // its verbatim Safe body; SafeSlotMock answers the same 96 bytes over storage the prover can follow
    // (L-CFG-SLOTMOCK) and the responder covers malformed, short and reverting answers (L-W0-3).
    function _.getStorageAt(uint256,uint256) external => DISPATCH [ GuardProbeResponderMock._, SafeSlotMock._ ] default NONDET;
}

// Frame observers, persistent because the guard's HAVOC_ECF branch havocs a plain ghost (D-007).

persistent ghost mapping(address => bool) gCalled;
persistent ghost mapping(address => bool) gStaticCalled;
persistent ghost mathint gCalls;
persistent ghost mathint gConfigureCalls;
persistent ghost mathint gOtherSelectorCalls;
persistent ghost mathint gValueCalls;
persistent ghost mathint gDelegateCalls;
persistent ghost mathint gStatics;
persistent ghost mathint gStaticsAfterCall;

// No Sstore/Sload hook: a storage hook triggers a scene-wide storage analysis that fails on
// SafeMockHarness.getStorageAt's raw sload over a symbolic slot (L-W0-1) and errors every rule, so the
// written-namespace frame uses direct pre/post reads. Opcode hooks do not trigger it.

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (executingContract == currentContract) {
        gCalled[addr] = true;
        gCalls = gCalls + 1;
        if (value != 0) {
            gValueCalls = gValueCalls + 1;
        }
        if (selector == sig:mockPolicy.configure(address,AccessSelector.T,bytes).selector) {
            gConfigureCalls = gConfigureCalls + 1;
        } else {
            gOtherSelectorCalls = gOtherSelectorCalls + 1;
        }
    }
}

hook DELEGATECALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (executingContract == currentContract) {
        gDelegateCalls = gDelegateCalls + 1;
    }
}

hook STATICCALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (executingContract == currentContract) {
        gStaticCalled[addr] = true;
        gStatics = gStatics + 1;
        if (gCalls > 0) {
            gStaticsAfterCall = gStaticsAfterCall + 1;
        }
    }
}

// #101's application window. `_expired(v)` is `block.timestamp >= v + EXPIRY` in checked arithmetic
// (SafePolicyGuard.sol:329-330), so the sum reverts with a Panic instead of answering when it overflows,
// and `expiredOrPanics` is the disjunction a revert-iff needs. EXPIRY stays symbolic throughout: the
// constructor's `expiry > 0` (ZeroExpiryNotAllowed, :152) is nowhere assumed, so EXPIRY == 0, which makes
// every matured root instantly expired, is one of the cases these rules cover.
definition windowOverflows(uint256 v) returns bool = to_mathint(v) + to_mathint(EXPIRY()) > max_uint256;
definition expired(uint256 t, uint256 v) returns bool = to_mathint(t) >= to_mathint(v) + to_mathint(EXPIRY());
definition expiredOrPanics(uint256 t, uint256 v) returns bool = expired(t, v) || windowOverflows(v);

// R-CFG-4: requestConfiguration(r) reverts iff paid, pending inside its window, or overflowing, and otherwise
// matures that entry alone at T + DELAY. Meaning changed by #101: a set entry no longer blocks the request
// unconditionally, only while the window is open (SafePolicyGuard.sol:365), and `_expired`'s own checked
// `validFrom + EXPIRY` is a second overflow that reverts with a Panic, reached only where v0 != 0.
rule R_CFG_4(env e, bytes32 r, address s2, bytes32 r2, address sp, AccessSelector.T k) {
    uint256 v0 = rootConfigured(e.msg.sender, r);
    uint256 other0 = rootConfigured(s2, r2);
    address pol0 = policyAt(sp, k);
    bool overflow = e.block.timestamp + DELAY() > max_uint256;   // mathint arithmetic; DELAY is unconstrained

    requestConfiguration@withrevert(e, r);
    bool reverted = lastReverted;

    // `v0 != 0 && !expired` also covers the Panic: where v0 + EXPIRY overflows, `expired` is false and the
    // checked sum reverts, so the two agree on the verdict and only differ in the error.
    assert reverted <=> (e.msg.value != 0 || (v0 != 0 && !expired(e.block.timestamp, v0)) || overflow),
        "reverts iff msg.value != 0, RootAlreadyConfigured inside the window, or block.timestamp + DELAY overflows";
    assert !reverted => to_mathint(rootConfigured(e.msg.sender, r)) == e.block.timestamp + DELAY(),
        "on success the root matures at block.timestamp + DELAY";
    assert !reverted => ((s2 != e.msg.sender || r2 != r) => rootConfigured(s2, r2) == other0),
        "no other (safe, root) entry changes";
    assert !reverted => policyAt(sp, k) == pol0, "$policies is untouched";
}

// R-CFG-5: invalidateRoot(r) reverts iff paid or not pending, otherwise clears that entry alone; a pending root
// stays invalidatable. Unmoved by #101, which gates neither: the liveness clause below therefore also says
// an expired root is still invalidatable, the claim test/safePolicyGuardDelayedConfiguration.spec.ts asserts on chain.
rule R_CFG_5(env e, bytes32 r, address s2, bytes32 r2, address sp, AccessSelector.T k) {
    uint256 v0 = rootConfigured(e.msg.sender, r);
    uint256 other0 = rootConfigured(s2, r2);
    address pol0 = policyAt(sp, k);

    invalidateRoot@withrevert(e, r);
    bool reverted = lastReverted;

    assert reverted <=> (e.msg.value != 0 || v0 == 0),
        "reverts iff msg.value != 0 or RootNotConfigured";
    assert !reverted => rootConfigured(e.msg.sender, r) == 0, "on success the root is cleared";
    assert !reverted => ((s2 != e.msg.sender || r2 != r) => rootConfigured(s2, r2) == other0),
        "no other (safe, root) entry changes";
    assert !reverted => policyAt(sp, k) == pol0, "$policies is untouched";
    assert (v0 != 0 && e.msg.value == 0) => !reverted,
        "liveness: a pending or matured root is always invalidatable by its Safe";
}

// Commented out: no SUCCESS verdict on certora-cli 8.19.1; the report's section 7 lists it.
/*
// R-CFG-6(a), unrestricted form: an unrequested, immature, expired or paid applyConfiguration always reverts, under
// no scene restriction. It runs in EngineConfig.conf and times out there, so the row's evidence is the n <= 1 twin
// R_CFG_6a_one in EngineConfigRootPin.conf. #101 adds the expired case to the same clause.
rule R_CFG_6a(env e, SafePolicyGuard.Configuration[] c) {
    require c.length <= 3;
    bytes32 root = configurationRoot(c);
    uint256 v0 = rootConfigured(e.msg.sender, root);

    applyConfiguration@withrevert(e, c);
    bool reverted = lastReverted;   // read before expiredOrPanics, which calls EXPIRY()

    assert (e.msg.value != 0 || v0 == 0 || e.block.timestamp < v0
            || expiredOrPanics(e.block.timestamp, v0)) => reverted,
        "an unrequested, immature or expired root never applies, and the entry point is not payable";
}
*/
// R-CFG-8: two configuration arrays with the same root have the same length.
rule R_CFG_8_length(SafePolicyGuard.Configuration[] c1, SafePolicyGuard.Configuration[] c2) {
    require c1.length <= 3 && c2.length <= 3;
    require configurationRoot(c1) == configurationRoot(c2);
    assert c1.length == c2.length, "equal roots => equal length";
}


// Commented out: no SUCCESS verdict on certora-cli 8.19.1; the report's section 7 lists it.
/*
// R-CFG-11, unrestricted form: a configuration applies only in [T + DELAY, T + DELAY + EXPIRY) after its request at
// T. It runs in EngineConfig.conf and times out there, so the row's evidence is the n <= 1 twin R_CFG_11_one in
// EngineConfigApply.conf. #101 adds the upper end, a second assert rather than a changed one.
rule R_CFG_11(env e1, env e2, bytes32 r, SafePolicyGuard.Configuration[] c) {
    require e1.msg.sender == e2.msg.sender;
    require c.length <= 3;
    require configurationRoot(c) == r;
    require mockPolicy.configureMode() != MockPolicyHarness.ConfigureMode.CALL_CONFIG;

    requestConfiguration(e1, r);
    applyConfiguration@withrevert(e2, c);
    bool reverted = lastReverted;   // read before DELAY() and EXPIRY()

    assert !reverted => e2.block.timestamp >= e1.block.timestamp + DELAY(),
        "a configuration applies only DELAY seconds after its request";
    assert !reverted => e2.block.timestamp < e1.block.timestamp + DELAY() + EXPIRY(),
        "and only while the EXPIRY window of that request is still open (#101)";
}
*/
// R-CFG-12, the second half: an expired root is spent, so the same root is requestable again with no invalidateRoot
// in between, and the fresh request restarts the delay. The overflow exclusion is the write's own checked
// `block.timestamp + DELAY`, the same arithmetic R-CFG-4 states as a revert cause; nothing about the
// window rests on it.
rule R_CFG_12_reRequest(env e, bytes32 r) {
    uint256 v0 = rootConfigured(e.msg.sender, r);
    require v0 != 0 && expired(e.block.timestamp, v0);
    require e.msg.value == 0;
    require e.block.timestamp + DELAY() <= max_uint256;

    requestConfiguration@withrevert(e, r);
    bool reverted = lastReverted;

    assert !reverted, "an expired root is requestable again, with no invalidateRoot in between";
    assert to_mathint(rootConfigured(e.msg.sender, r)) == e.block.timestamp + DELAY(),
        "and the fresh request restarts the delay from now, so it is not instantly applicable";
}

// W-CFG-1 witnesses, one rule per witness so a refutation names the missing path.

// W-CFG-1 witness (W_CFG_1_W1): request, then apply after the delay, and the AllowPolicy entry resolves through
// getPolicy.
rule W_CFG_1_W1(env e1, env e2, SafePolicyGuard.Configuration[] c, bytes data) {
    require e1.msg.sender == e2.msg.sender && e1.msg.sender != 0;
    require c.length == 1 && configPolicy(c, 0) == allow;
    require !badLen(data) && decodeSelector(data) == configSelector(c, 0);
    requestConfiguration(e1, configurationRoot(c));
    applyConfiguration(e2, c);
    AccessSelector.T a; address p;
    (a, p) = getPolicy(e2.msg.sender, configTarget(c, 0), data, configOperation(c, 0));
    satisfy e2.block.timestamp >= e1.block.timestamp + DELAY() && p == allow && a == configKey(c, 0);
}

// W-CFG-1 witness (W_CFG_1_W2): the same root is re-requestable once it has been applied.
rule W_CFG_1_W2(env e1, env e2, env e3, SafePolicyGuard.Configuration[] c) {
    require e1.msg.sender == e2.msg.sender && e2.msg.sender == e3.msg.sender && e1.msg.sender != 0;
    require c.length <= 1;
    bytes32 root = configurationRoot(c);
    requestConfiguration(e1, root);
    applyConfiguration(e2, c);
    requestConfiguration(e3, root);
    satisfy rootConfigured(e3.msg.sender, root) != 0;
}

// W-CFG-1 witness (W_CFG_1_W3): with DELAY == 0 a configuration is requested and applied in one block (WAIVED-ENV-3).
rule W_CFG_1_W3(env e1, env e2, SafePolicyGuard.Configuration[] c) {
    require e1.msg.sender == e2.msg.sender && e1.msg.sender != 0;
    require c.length <= 1;
    require DELAY() == 0 && e1.block.timestamp == e2.block.timestamp;
    requestConfiguration(e1, configurationRoot(c));
    applyConfiguration(e2, c);
    satisfy rootConfigured(e2.msg.sender, configurationRoot(c)) == 0;
}

// W-CFG-1 witness (W_CFG_1_W6): the empty array has a requestable root that applyConfiguration consumes.
rule W_CFG_1_W6(env e1, env e2, SafePolicyGuard.Configuration[] c) {
    require e1.msg.sender == e2.msg.sender && e1.msg.sender != 0;
    require c.length == 0;
    bytes32 root = configurationRoot(c);
    requestConfiguration(e1, root);
    uint256 pending = rootConfigured(e1.msg.sender, root);
    applyConfiguration(e2, c);
    satisfy pending != 0 && rootConfigured(e2.msg.sender, root) == 0;
}


// Reduced-scope twins at n <= 1 (L-CFG-LOOP-N1); the unrestricted forms are commented out above.

// R-CFG-6(a) at n <= 1: an unrequested, immature, expired or paid applyConfiguration always reverts; the expired case
// is #101's.
rule R_CFG_6a_one(env e, SafePolicyGuard.Configuration[] c) {
    require c.length <= 1;
    bytes32 root = configurationRoot(c);
    uint256 v0 = rootConfigured(e.msg.sender, root);

    applyConfiguration@withrevert(e, c);
    bool reverted = lastReverted;   // read before expiredOrPanics, which calls EXPIRY()

    assert (e.msg.value != 0 || v0 == 0 || e.block.timestamp < v0
            || expiredOrPanics(e.block.timestamp, v0)) => reverted,
        "an unrequested, immature or expired root never applies, and the entry point is not payable";
}

