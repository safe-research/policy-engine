// EngineCheck.spec: the check surface of SafePolicyGuard and PolicyEngine, property rows of the
// EngineCheck unit, on SafePolicyGuardHarness in the closed scene {Allow, Deny, OneTimeAllow, MockPolicyHarness} with
// LibHarness and SafeMockHarness. Run by the conf/EngineCheck*.conf files that verify this spec.
// File-wide: L-W0-2, L-W0-SENDER, L-W0-SENTINEL, L-EC-2, L-EC-3, L-EC-5, L-EC-7 (the precondition of the
// engine-outcome and hook rows), L-EC-9, L-EC-11, L-EC-12, L-EC-13, L-EC-FRAME, L-EC-LOOP, L-EC-LOOP-N1.

import "Common.spec";

using AllowPolicy as allow;
using DenyPolicy as deny;
using OneTimeAllowPolicy as oneTimeAllow;

// The guard-to-Safe probe keeps the AUTO STATICCALL NONDET default: no rule here reads its answer.
methods {
    function oneTimeAllow.isGranted(address, address, AccessSelector.T) external returns (bool) envfree;

    // L-EC-5: the engine-to-policy default is per spec and NONDET here, any other spec of the unit stating
    // its own in its own methods block; out of scene a policy answers with a free bytes4 (L-W0-2), which is
    // why every iff row requires inScene(p).
    function _.checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,address,bytes,AccessSelector.T) external
        => DISPATCH [ AllowPolicy._, DenyPolicy._, OneTimeAllowPolicy._, MockPolicyHarness._ ] default NONDET;
    function _.configure(address,AccessSelector.T,bytes) external
        => DISPATCH [ AllowPolicy._, DenyPolicy._, OneTimeAllowPolicy._, MockPolicyHarness._ ] default NONDET;

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
    // EngineConfig handoff: without this the mock's RECORD-mode read-back is an unresolved STATICCALL.
    function _.rootConfigured(address,bytes32) external => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;
}

// Frame observers, opcode hooks only, persistent so an unresolved call cannot havoc them (D-007) and so they survive
// the revert that the hooks' no-policy-on-revert clauses observe.

persistent ghost mapping(address => bool) gCalled;
persistent ghost mathint gCalls;
persistent ghost mathint gCheckCalls;
persistent ghost mathint gOtherSelectorCalls;
persistent ghost mathint gValueCalls;
persistent ghost mathint gDelegateCalls;
persistent ghost mathint gStatics;

// No Sstore/Sload hook: a storage hook triggers a scene-wide storage analysis that fails on
// SafeMockHarness.getStorageAt's verbatim sload and errors every rule; storage is read directly instead.
// In the CALL hook below `selector` is the first four calldata bytes at argsOffset, undefined when argsLength < 4; it
// is compared against a `sig:` expression, so a claim on gOtherSelectorCalls rests on that binding.

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (executingContract == currentContract) {
        gCalled[addr] = true;
        gCalls = gCalls + 1;
        if (value != 0) {
            gValueCalls = gValueCalls + 1;
        }
        if (selector == sig:mockPolicy.checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,address,bytes,AccessSelector.T).selector) {
            gCheckCalls = gCheckCalls + 1;
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
        gStatics = gStatics + 1;
    }
}

// L-EC-FRAME: zeroes the opcode-hook observers, which start at an arbitrary value.
function resetFrame() {
    require gCalls == 0 && gCheckCalls == 0 && gOtherSelectorCalls == 0 && gValueCalls == 0
        && gDelegateCalls == 0 && gStatics == 0;
    require forall address a. !gCalled[a];
}

// Policy addresses whose check verdict this scene fixes; 0 means no policy configured, which the engine rejects without
// calling.
definition inScene(address p) returns bool =
    p == 0 || p == allow || p == deny || p == oneTimeAllow || p == mockPolicy;

// The three non-re-entrant mock modes the engine and hook revert iffs run under (L-EC-11); the re-entrant modes stay
// free where the outgoing-call clauses count the guard's own CALLs, and the nested invocation and context rules and
// the witnesses of the nested and mid-check states require REENTER_ENGINE.
function pinNonReentrantMock() {
    require mockPolicy.checkMode() == MockPolicyHarness.CheckMode.ACCEPT
        || mockPolicy.checkMode() == MockPolicyHarness.CheckMode.WRONG_MAGIC
        || mockPolicy.checkMode() == MockPolicyHarness.CheckMode.REVERTS;
}

// verdict(p) == ACCEPT per scene member: Allow accepts; Deny returns bytes4(0); OneTimeAllow accepts iff an unspent
// grant exists for (guard, safe, access); the mock accepts only in ACCEPT mode. Used under pinNonReentrantMock.
function sceneAccepts(address p, address safe, AccessSelector.T access) returns bool {
    if (p == allow) {
        return true;
    }
    if (p == oneTimeAllow) {
        return oneTimeAllow.isGranted(currentContract, safe, access);
    }
    if (p == mockPolicy) {
        return mockPolicy.checkMode() == MockPolicyHarness.CheckMode.ACCEPT;
    }
    return false;
}

// _decodeContext does not revert: either there is no envelope, or it is long enough and its length word does not run
// past the front. Stated with the Lib unit's shared reader set, never with the guard's own decoder.
function wellFormedSig(bytes sg) returns bool {
    if (!lib.has(sg, CONTEXT_TYPE_HASH())) {
        return true;
    }
    if (sg.length < 64) {
        return false;
    }
    return to_mathint(lib.lengthWord(sg)) <= to_mathint(sg.length) - 64;
}

// The selector _decodeSelector yields where it does not revert, from the raw Lib reader selectorOf.
function expectedSelector(bytes data) returns bytes4 {
    if (data.length >= 4) {
        return lib.selectorOf(data);
    }
    return to_bytes4(0);
}

// R-EC-11: allowed(to,value,data,op) reverts iff badLen(data), and is true iff the call is a zero-value CALL to the
// guard carrying a hatch selector.
rule R_EC_11(address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op) {
    // The hatch selectors asserted against their literals, so a swap of two selectors fails here as well.
    assert SEL_REQUEST_CONFIGURATION() == to_bytes4(0xa809eb8e), "requestConfiguration(bytes32) selector";
    assert SEL_APPLY_CONFIGURATION() == to_bytes4(0xb9ba2798), "applyConfiguration(Configuration[]) selector";
    assert SEL_INVALIDATE_ROOT() == to_bytes4(0x3eefdcce), "invalidateRoot(bytes32) selector";
    assert SEL_CONFIGURE_IMMEDIATELY() == to_bytes4(0x8446dc43), "configureImmediately(Configuration[]) selector";

    bool a = allowedCalls@withrevert(to, value, data, op);
    bool rev = lastReverted;
    assert rev <=> badLen(data), "allowedCalls reverts iff data is 1-3 bytes (InvalidSelector)";

    bytes4 sel = expectedSelector(data);
    bool onHatch = to == currentContract && value == 0 && op == lib.opCall()
        && (sel == SEL_REQUEST_CONFIGURATION() || sel == SEL_APPLY_CONFIGURATION() || sel == SEL_INVALIDATE_ROOT());
    assert !rev => (a <=> onHatch), "the hatch is exactly (this, 0, CALL, one of the three selectors)";

    // The four named negatives of the row, each its own assert so a widening of the hatch names itself.
    assert !rev => (sel == SEL_CONFIGURE_IMMEDIATELY() => !a), "configureImmediately is never on the hatch";
    assert !rev => (data.length == 0 => !a), "empty calldata is never on the hatch";
    assert !rev => (value != 0 => !a), "a value-carrying self-call is never on the hatch";
    assert !rev => (op == lib.opDelegateCall() => !a), "a DELEGATECALL is never on the hatch";
    assert !rev => (to != currentContract => !a), "only this contract is on the hatch";
}

// R-EC-9: getPolicy(s,to,data,op) reverts iff badLen(data).
rule R_EC_9_revertIff(address s, address to, bytes data, SafePolicyGuardHarness.Operation op) {
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(s, to, data, op);
    assert lastReverted <=> badLen(data), "getPolicy reverts iff data is 1-3 bytes";
}

// R-EC-9: otherwise it returns the exact entry where one is set and the fallback entry otherwise, and the DELEGATECALL
// fallback never serves a CALL.
rule R_EC_9(address s, address to, bytes data, SafePolicyGuardHarness.Operation op) {
    // The expectation is built from the Lib reader set, so no single change moves both sides at once.
    bytes4 sel = expectedSelector(data);
    AccessSelector.T ek = lib.create(to, sel, op);
    AccessSelector.T fk = lib.createFallback(op);
    address pe = policyAt(s, ek);
    address pf = policyAt(s, fk);

    AccessSelector.T k; address p;
    k, p = getPolicy(s, to, data, op);

    assert pe != 0 => (k == ek && p == pe), "an existing exact entry is served, exact-first";
    assert pe == 0 => (k == fk && p == pf), "no exact entry falls back to the operation fallback";
    assert data.length == 0 => k == (pe != 0 ? lib.create(to, to_bytes4(0), op) : fk),
        "empty calldata resolves with selector 0";
    assert lib.createFallback(lib.opCall()) != lib.createFallback(lib.opDelegateCall()),
        "the CALL fallback key and the DELEGATECALL fallback key are distinct";
    assert lib.getOperation(fk) == op, "the fallback key carries the operation bit";
}

// R-EC-10: a payload of at least 4 bytes with a zero selector resolves exactly as the empty payload (finding B-2,
// intended).
rule R_EC_10(address s, address to, bytes data, bytes empty, SafePolicyGuardHarness.Operation op) {
    require data.length >= 4;
    require empty.length == 0;
    require lib.selectorOf(data) == to_bytes4(0);

    AccessSelector.T k1; address p1;
    AccessSelector.T k2; address p2;
    k1, p1 = getPolicy(s, to, data, op);
    k2, p2 = getPolicy(s, to, empty, op);
    assert k1 == k2 && p1 == p2, "a zero-selector payload shares the empty-calldata key";
}

// R-EC-10, second half: a non-zero selector never lands on the zero-selector exact key, stated over the exact key
// because create(0, 0, CALL) == createFallback(CALL) == 0 makes the resolved access ambiguous for to == 0.
rule R_EC_10_exactKey(address to, bytes data, SafePolicyGuardHarness.Operation op) {
    require data.length >= 4;
    assert lib.selectorOf(data) != to_bytes4(0)
        => lib.create(to, lib.selectorOf(data), op) != lib.create(to, to_bytes4(0), op),
        "a non-zero selector never lands on the zero-selector key";
}

// R-EC-16: supportsInterface(id) is true iff id is one of the four ids, and never reverts.
rule R_EC_16(env e, bytes4 id) {
    bool r = supportsInterface@withrevert(e, id);
    // The only revert source is solc's non-payable check; the row's claim is about the body.
    assert lastReverted => e.msg.value != 0, "supportsInterface never reverts on its own";
    assert !lastReverted => (r <=> (id == to_bytes4(0x04a9e3cd) || id == to_bytes4(0x58401ed8)
        || id == to_bytes4(0xe6d7a83a) || id == to_bytes4(0x01ffc9a7))),
        "true exactly for IPolicyEngine / ISafeModuleGuard / ISafeTransactionGuard / IERC165";
}

// R-EC-13: checkAfterExecution(hash, success) reverts iff !success or msg.value != 0, writes no storage and makes no
// call.
rule R_EC_13_owner(env e, bytes32 h, bool success) {
    resetFrame();
    storage init = lastStorage;
    checkAfterExecution@withrevert(e, h, success);
    bool rev = lastReverted;
    assert rev <=> (!success || e.msg.value != 0), "checkAfterExecution reverts iff !success (ExecutionFailed)";
    assert lastStorage == init, "the owner after-hook writes no storage";
    assert gCalls == 0 && gDelegateCalls == 0 && gStatics == 0,
        "the owner after-hook makes no outgoing call on any path";
}

// R-EC-13, the module twin: dropping that line burns a OneTimeAllow grant on a failed module transaction (WAIVED-S-4,
// asserted on chain by test/safePolicyGuardExecution.spec.ts, "Should restore a one-time grant when the module
// execution fails").
rule R_EC_13_module(env e, bytes32 h, bool success) {
    resetFrame();
    storage init = lastStorage;
    checkAfterModuleExecution@withrevert(e, h, success);
    bool rev = lastReverted;
    assert rev <=> (!success || e.msg.value != 0),
        "checkAfterModuleExecution reverts iff !success (ModuleExecutionFailed)";
    assert lastStorage == init, "the module after-hook writes no storage";
    assert gCalls == 0 && gDelegateCalls == 0 && gStatics == 0,
        "the module after-hook makes no outgoing call on any path";
}

// R-EC-2: a non-zero S makes both guard hooks revert for every argument vector and sender, before any policy call.
rule R_EC_2(env e, method f, calldataarg args) filtered {
    f -> f.selector == sig:checkTransaction(address,uint256,bytes,SafePolicyGuardHarness.Operation,uint256,uint256,uint256,address,address,bytes,address).selector
      || f.selector == sig:checkModuleTransaction(address,uint256,bytes,SafePolicyGuardHarness.Operation,address).selector
} {
    require checkingSafe() != 0;
    f@withrevert(e, args);
    assert lastReverted, "a guard hook entered mid-check reverts (Reentrancy, PolicyEngine.sol:222)";
}

// R-EC-4(a): with S == s != 0, checkTransaction reverts iff it is paid, the safe differs, badLen(data), the hatch
// is taken with m != 0, the target off the hatch is the guard itself, or the resolved policy is absent or does
// not accept. The guard-target case is #103's own disjunct and it precedes resolution, so a call aimed here
// reverts even where a policy is configured for it (PolicyEngine.sol:194).
rule R_EC_4a(env e, address safe, address to, uint256 value, bytes data,
             SafePolicyGuardHarness.Operation op, bytes ctx) {
    pinNonReentrantMock();
    require op == lib.opCall() || op == lib.opDelegateCall();
    address s = checkingSafe();
    address m = checkingModule();
    require s != 0;
    bool bad = badLen(data);

    bool allowedC = allowedCalls@withrevert(to, value, data, op);
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(safe, to, data, op);
    require inScene(p);
    // The scene verdict is computed only where getPolicy did not revert; on the badLen branch k is free.
    bool acc = false;
    if (!bad) {
        acc = sceneAccepts(p, safe, k);
    }

    bool expected = e.msg.value != 0 || safe != s || bad || (!bad && allowedC && m != 0)
        || (!bad && !allowedC && to == currentContract)
        || (!bad && !allowedC && (p == 0 || !acc));

    checkTransaction@withrevert(e, safe, to, value, data, op, ctx);
    assert lastReverted <=> expected, "engine revert iff (NotChecking is excluded by S != 0)";
}

// R-EC-4(a), the S == 0 limb, kept separate so it is asserted rather than assumed away; the filtered clause repeats the
// excluded induction node's selector expression, so both range over the same (method, calldata) pairs.
rule R_EC_4a_notChecking(env e, method f, calldataarg args) filtered {
    f -> f.selector == sig:checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,bytes).selector
} {
    require checkingSafe() == 0;
    f@withrevert(e, args);
    assert lastReverted, "the engine entry reverts NotChecking when no check is in progress";
}

// R-EC-4(b): on success it returns address(0) on the hatch and p otherwise, and the policy is called exactly once iff
// the hatch was missed.
rule R_EC_4b(env e, address safe, address to, uint256 value, bytes data,
             SafePolicyGuardHarness.Operation op, bytes ctx) {
    resetFrame();
    pinNonReentrantMock();
    address s = checkingSafe();
    require s != 0;
    bool allowedC = allowedCalls@withrevert(to, value, data, op);
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(safe, to, data, op);
    require inScene(p);

    address ret = checkTransaction(e, safe, to, value, data, op, ctx);
    assert allowedC => (ret == 0 && gCalls == 0), "the hatch returns address(0) and invokes no policy";
    assert !allowedC => (ret == p && p != 0 && gCalls == 1 && gCalled[p]),
        "a policy-served check returns and calls exactly the resolved policy, exactly once";
}


// R-EC-5: the owner hook reverts iff it is paid, gas-priced, mid-check, malformed in signatures or data, aimed at the
// guard off the hatch, or the resolved policy is absent or does not accept; on success S and M are 0. The
// guard-target disjunct is #103's; the hatch clause below returns before that denial.
rule R_EC_5(env e, address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op,
            uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
            address refundReceiver, bytes signatures, address msgSender) {
    require e.msg.sender != 0;
    pinNonReentrantMock();
    address s = e.msg.sender;
    address sPre = checkingSafe();
    require op == lib.opCall() || op == lib.opDelegateCall();
    bool bad = badLen(data);
    bool wf = wellFormedSig(signatures);

    bool allowedC = allowedCalls@withrevert(to, value, data, op);
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(s, to, data, op);
    require inScene(p);
    // The scene verdict is computed only where getPolicy did not revert; on the badLen branch k is free.
    bool acc = false;
    if (!bad) {
        acc = sceneAccepts(p, s, k);
    }

    bool expected = e.msg.value != 0 || gasPrice != 0 || safeTxGas != 0 || sPre != 0 || !wf || bad
        || (!bad && !allowedC && to == currentContract)
        || (!bad && !allowedC && (p == 0 || !acc));

    checkTransaction@withrevert(e, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken,
        refundReceiver, signatures, msgSender);
    bool rev = lastReverted;
    assert rev <=> expected, "owner-path hook revert iff";
    assert !rev => (checkingSafe() == 0 && checkingModule() == 0), "sentinels restored on success";
    // The hatch branch never reverts, asserted separately so a break of that branch names itself.
    assert (e.msg.value == 0 && gasPrice == 0 && safeTxGas == 0 && sPre == 0 && wf && !bad && allowedC)
        => !rev, "the escape hatch never reverts on the owner path";
}

// R-EC-5, the invocation-count clause on the success path: exactly one policy CALL iff the hatch was missed.
rule R_EC_5_callCount(env e, address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op,
                      uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
                      address refundReceiver, bytes signatures, address msgSender) {
    resetFrame();
    require e.msg.sender != 0;
    pinNonReentrantMock();
    bool allowedC = allowedCalls@withrevert(to, value, data, op);
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(e.msg.sender, to, data, op);
    require inScene(p);
    checkTransaction(e, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken,
        refundReceiver, signatures, msgSender);
    assert allowedC => gCalls == 0, "the hatch invokes no policy";
    assert !allowedC => (gCalls == 1 && gCalled[p]), "exactly one call, to the resolved policy";
}

// R-EC-6: the module hook reverts iff it is paid, mid-check, badLen(data), the hatch is taken with module != 0, the
// target off the hatch is the guard, or the resolved policy is absent or does not accept; on success it returns
// bytes32(0). The guard-target disjunct is #103's.
rule R_EC_6(env e, address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op, address module) {
    require e.msg.sender != 0;
    pinNonReentrantMock();
    require op == lib.opCall() || op == lib.opDelegateCall();
    address s = e.msg.sender;
    address sPre = checkingSafe();
    bool bad = badLen(data);

    bool allowedC = allowedCalls@withrevert(to, value, data, op);
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(s, to, data, op);
    require inScene(p);
    // The scene verdict is computed only where getPolicy did not revert; on the badLen branch k is free.
    bool acc = false;
    if (!bad) {
        acc = sceneAccepts(p, s, k);
    }

    bool expected = e.msg.value != 0 || sPre != 0 || bad || (!bad && allowedC && module != 0)
        || (!bad && !allowedC && to == currentContract)
        || (!bad && !allowedC && (p == 0 || !acc));

    bytes32 r = checkModuleTransaction@withrevert(e, to, value, data, op, module);
    bool rev = lastReverted;
    assert rev <=> expected, "module-path hook revert iff";
    assert !rev => r == to_bytes32(0), "the module hook returns bytes32(0)";
    assert !rev => (checkingSafe() == 0 && checkingModule() == 0), "sentinels restored on success";
}

// R-EC-6, the invocation clause: exactly one policy CALL iff the hatch was missed, carrying the hook's own module and
// an empty context; the empty-context half is R-EC-8's module limb, which shares this scene.
rule R_EC_6_invocation(env e, address to, uint256 value, bytes data,
                       SafePolicyGuardHarness.Operation op, address module) {
    resetFrame();
    require e.msg.sender != 0;
    pinNonReentrantMock();
    require mockPolicy.calls() == 0;
    bool allowedC = allowedCalls@withrevert(to, value, data, op);
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(e.msg.sender, to, data, op);
    require inScene(p);
    checkModuleTransaction(e, to, value, data, op, module);
    assert allowedC => gCalls == 0, "the hatch invokes no policy";
    assert !allowedC => (gCalls == 1 && gCalled[p]), "exactly one call, to the resolved policy";
    assert (!allowedC && p == mockPolicy) => (mockPolicy.calls() == 1 && mockPolicy.invModule(0) == module),
        "the policy receives the hook's own module argument";
    assert (!allowedC && p == mockPolicy) => mockPolicy.invContextLength(0) == 0,
        "the module path forwards an empty context (SafePolicyGuard.sol:256)";
}

// R-EC-17, the Safe transaction-guard hook: the denial reaches the owner path and no policy runs.
rule R_EC_17_owner(env e, uint256 value, bytes data, SafePolicyGuardHarness.Operation op,
                   uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
                   address refundReceiver, bytes signatures, address msgSender) {
    resetFrame();
    require e.msg.sender != 0;
    require !badLen(data);
    require !allowedCalls(currentContract, value, data, op);
    checkTransaction@withrevert(e, currentContract, value, data, op, safeTxGas, baseGas, gasPrice,
        gasToken, refundReceiver, signatures, msgSender);
    assert lastReverted, "the owner hook denies a transaction whose target is the guard, off the hatch";
    assert gCalls == 0, "and denies it before any policy is called, so no grant is spent";
}

// R-EC-17, the module hook, for every module the engine could attribute the call to.
rule R_EC_17_module(env e, uint256 value, bytes data, SafePolicyGuardHarness.Operation op, address module) {
    resetFrame();
    require e.msg.sender != 0;
    require !badLen(data);
    require !allowedCalls(currentContract, value, data, op);
    checkModuleTransaction@withrevert(e, currentContract, value, data, op, module);
    assert lastReverted, "the module hook denies a transaction whose target is the guard, off the hatch";
    assert gCalls == 0, "and denies it before any policy is called, so no module can be forged onto one";
}

