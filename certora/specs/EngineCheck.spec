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

// The resolved policy for (safe, to, data, op) is p, off the escape hatch: on the hatch the engine returns without
// calling any policy, which is what R-EC-4(b), R-EC-11 and the two hooks' iffs characterize.
function resolvesTo(address safe, address to, uint256 value, bytes data,
                    SafePolicyGuardHarness.Operation op, address p) returns AccessSelector.T {
    require !badLen(data);
    require !allowedCalls(to, value, data, op);
    AccessSelector.T a; address resolved;
    a, resolved = getPolicy(safe, to, data, op);
    require resolved == p;
    return a;
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

// R-EC-4(c): off the hatch with no policy configured, the revert class is exactly AccessDenied(0), except where the
// target is the guard, which #103 denies first with GuardTargetDenied; the two classes are asserted side by side, so
// the rule names a class for every input in its scope.
rule R_EC_4c_noPolicy(env e, address safe, address to, uint256 value, bytes data,
                      SafePolicyGuardHarness.Operation op, bytes ctx) {
    require safe != 0 && checkingSafe() == safe && checkingModule() == 0;
    require !badLen(data);
    bool allowedC = allowedCalls(to, value, data, op);
    require !allowedC;
    AccessSelector.T k; address p;
    k, p = getPolicy(safe, to, data, op);
    require p == 0;
    bool ok; bytes4 sel; address arg; uint256 len; address r;
    ok, sel, arg, len, r = tryCheck(e, safe, to, value, data, op, ctx);
    assert !ok, "an unserved target is denied";
    assert to != currentContract => (sel == errAccessDenied() && arg == 0 && len == 36),
        "AccessDenied(address(0))";
    assert to == currentContract => (sel == errGuardTargetDenied() && len == 4),
        "GuardTargetDenied, argument-free, for a call aimed at the guard off the hatch (#103)";
}

// R-EC-4(c): a clean bytes4 word that is not the magic value is AccessDenied(p), except where the target is the
// guard, which #103 denies before the policy is ever called; both classes are asserted.
rule R_EC_4c_wrongMagic(env e, address safe, address to, uint256 value, bytes data,
                        SafePolicyGuardHarness.Operation op, bytes ctx) {
    require safe != 0 && checkingSafe() == safe && checkingModule() == 0;
    require !badLen(data);
    bool allowedC = allowedCalls(to, value, data, op);
    require !allowedC;
    AccessSelector.T k; address p;
    k, p = getPolicy(safe, to, data, op);
    require p == deny || (p == mockPolicy && mockPolicy.checkMode() == MockPolicyHarness.CheckMode.WRONG_MAGIC);
    bool ok; bytes4 sel; address arg; uint256 len; address r;
    ok, sel, arg, len, r = tryCheck(e, safe, to, value, data, op, ctx);
    assert !ok, "a non-magic answer is denied";
    assert to != currentContract => (sel == errAccessDenied() && arg == p && len == 36),
        "AccessDenied(p) for a non-magic answer";
    assert to == currentContract => (sel == errGuardTargetDenied() && len == 4),
        "GuardTargetDenied instead, the policy never being reached (#103)";
}

// R-EC-4(c): a reverting policy denies the transaction. The PolicyReverted class and the forwarded revert data are
// in the commented-out rule below.
rule R_EC_4c_revert(env e, address safe, address to, uint256 value, bytes data,
                    SafePolicyGuardHarness.Operation op, bytes ctx) {
    require safe != 0 && checkingSafe() == safe && checkingModule() == 0;
    require !badLen(data);
    AccessSelector.T k = resolvesTo(safe, to, value, data, op, mockPolicy);
    address p = mockPolicy;
    require mockPolicy.checkMode() == MockPolicyHarness.CheckMode.REVERTS;
    bool ok; bytes4 sel; address arg; uint256 len; address r;
    ok, sel, arg, len, r = tryCheck(e, safe, to, value, data, op, ctx);
    // The conjunction is split: the provable half stands here; the class half is commented out below.
    assert !ok, "a reverting policy denies the transaction";
}

// Commented out: no SUCCESS verdict on certora-cli 8.19.1; the report's section 7 lists it.
/*
// R-EC-4(c), the classification half: the policy's own revert data is forwarded; blocked: the class is refuted while
// the denial itself holds. Under #103 the forwarding claim speaks only for a target that is not the guard, and
// the guard target gets its own class here rather than being dropped.
rule R_EC_4c_revertClass(env e, address safe, address to, uint256 value, bytes data,
                         SafePolicyGuardHarness.Operation op, bytes ctx) {
    require safe != 0 && checkingSafe() == safe && checkingModule() == 0;
    require !badLen(data);
    AccessSelector.T k = resolvesTo(safe, to, value, data, op, mockPolicy);
    address p = mockPolicy;
    require mockPolicy.checkMode() == MockPolicyHarness.CheckMode.REVERTS;
    bool ok; bytes4 sel; address arg; uint256 len; address r;
    ok, sel, arg, len, r = tryCheck(e, safe, to, value, data, op, ctx);
    assert (!ok && to != currentContract) => sel == errPolicyReverted(),
        "the class is PolicyReverted, not AccessDenied";
    assert (!ok && to != currentContract) => arg == p, "the reverting policy is named in the error";
    assert (!ok && to != currentContract) => len >= 100,
        "the policy's own revert data is forwarded, not swallowed";
    assert to == currentContract => (!ok && sel == errGuardTargetDenied() && len == 4),
        "a guard-targeted call is denied before the policy runs, so its revert data is not what is forwarded (#103)";
}
*/

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

// R-EC-5, the outgoing-call clause: no policy runs on any pre-check revert branch, which the persistent counter
// survives to observe.
rule R_EC_5_noPolicyOnRevert(env e, address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op,
                             uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
                             address refundReceiver, bytes signatures, address msgSender) {
    resetFrame();
    require e.msg.sender != 0;
    require op == lib.opCall() || op == lib.opDelegateCall();
    address sPre = checkingSafe();
    bool bad = badLen(data);
    bool wf = wellFormedSig(signatures);
    checkTransaction@withrevert(e, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken,
        refundReceiver, signatures, msgSender);
    assert (gasPrice != 0 || safeTxGas != 0 || sPre != 0 || !wf || bad) => gCalls == 0,
        "gas checks and the envelope parse happen before any policy call (AC-6)";
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

// R-EC-6, the outgoing-call clause: no policy runs on any revert branch, the hatch-with-module one and #103's
// guard-target one included.
rule R_EC_6_noPolicyOnRevert(env e, address to, uint256 value, bytes data,
                             SafePolicyGuardHarness.Operation op, address module) {
    resetFrame();
    require e.msg.sender != 0;
    require op == lib.opCall() || op == lib.opDelegateCall();
    address sPre = checkingSafe();
    bool bad = badLen(data);
    bool allowedC = allowedCalls@withrevert(to, value, data, op);
    checkModuleTransaction@withrevert(e, to, value, data, op, module);
    assert (sPre != 0 || bad || (!bad && allowedC && module != 0)
            || (!bad && !allowedC && to == currentContract)) => gCalls == 0,
        "the module hook's revert branches precede every policy call";
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

// R-EC-7: the top-level policy invocation of an owner-path check gets the hook's own (to, value, data, op), safe ==
// msg.sender, module == 0 and the resolved access and callee.
rule R_EC_7(env e, address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op,
            uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
            address refundReceiver, bytes signatures, address msgSender) {
    resetFrame();
    require e.msg.sender != 0;
    pinNonReentrantMock();
    require mockPolicy.calls() == 0;
    address s = e.msg.sender;
    AccessSelector.T k = resolvesTo(s, to, value, data, op, mockPolicy);
    address p = mockPolicy;
    checkTransaction(e, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken,
        refundReceiver, signatures, msgSender);
    assert mockPolicy.calls() == 1, "the policy is invoked exactly once";
    assert mockPolicy.invSender(0) == currentContract, "the engine is the caller";
    assert mockPolicy.invSafe(0) == s, "safe == the Safe that called the hook";
    assert mockPolicy.invModule(0) == 0, "an owner transaction has no authorizing module";
    assert mockPolicy.invTo(0) == to && mockPolicy.invValue(0) == value
        && mockPolicy.invOperation(0) == op, "(to, value, operation) are the hook's own";
    assert mockPolicy.invDataHash(0) == keccak(data) && mockPolicy.invDataLength(0) == data.length,
        "data is forwarded unaltered";
    assert mockPolicy.invAccess(0) == k, "access == resolve(...).access, exact or fallback as resolved";
    assert gCalls == 1 && gCalled[p], "the callee is the resolved policy";
}

// R-EC-7, the module-path twin: module comes from state, not from the caller.
rule R_EC_7_module(env e, address to, uint256 value, bytes data,
                   SafePolicyGuardHarness.Operation op, address module) {
    resetFrame();
    require e.msg.sender != 0;
    pinNonReentrantMock();
    require mockPolicy.calls() == 0;
    address s = e.msg.sender;
    AccessSelector.T k = resolvesTo(s, to, value, data, op, mockPolicy);
    checkModuleTransaction(e, to, value, data, op, module);
    assert mockPolicy.calls() == 1, "the policy is invoked exactly once";
    assert mockPolicy.invSafe(0) == s && mockPolicy.invModule(0) == module,
        "safe and module are the hook's own, taken from state";
    assert mockPolicy.invTo(0) == to && mockPolicy.invValue(0) == value
        && mockPolicy.invOperation(0) == op, "(to, value, operation) are the hook's own";
    assert mockPolicy.invDataHash(0) == keccak(data) && mockPolicy.invDataLength(0) == data.length,
        "data is forwarded unaltered";
    assert mockPolicy.invAccess(0) == k, "access == resolve(...).access";
}

// R-EC-7, the nested clause a batching policy's composition depends on: a nested engine call a policy issues reaches
// a policy with the top-level safe and module and its own resolved access.
// #103 splits the claim in two rather than shrinking it. A nested call whose own target is the guard is denied
// `GuardTargetDenied` at PolicyEngine.sol:194, before any policy is reached, so that branch asserts the denial and
// the invocation claims speak for the rest. `resolvesTo` already places the nested call off the escape hatch, so
// the guard as its target is exactly the denied case; no `require` was added, and the two branches partition the
// same input set the rule carried before.
rule R_EC_7_nested(env e, address to, uint256 value, bytes data,
                   SafePolicyGuardHarness.Operation op, address module) {
    resetFrame();
    require e.msg.sender != 0;
    address s = e.msg.sender;
    require mockPolicy.checkMode() == MockPolicyHarness.CheckMode.REENTER_ENGINE;
    require mockPolicy.depth() == 0 && mockPolicy.calls() == 0;
    require mockPolicy.reenterSafe() == s;
    require mockPolicy.reenterDataSkip() == 0;
    AccessSelector.T k = resolvesTo(s, to, value, data, op, mockPolicy);
    AccessSelector.T k1 = resolvesTo(s, mockPolicy.reenterTo(), mockPolicy.reenterValue(), data,
        mockPolicy.reenterOperation(), mockPolicy);
    address p1 = mockPolicy;
    bool guardTarget = mockPolicy.reenterTo() == currentContract;

    checkModuleTransaction(e, to, value, data, op, module);

    assert mockPolicy.innerCalled(), "the nested engine call is issued";
    assert guardTarget => (mockPolicy.innerReverted() && mockPolicy.innerErrorSelector() == errGuardTargetDenied()
        && mockPolicy.innerErrorLength() == 4),
        "a nested call aimed at the guard is denied GuardTargetDenied, argument-free (#103)";
    assert guardTarget => mockPolicy.calls() == 1, "the denied nested call reaches no policy at all (#103)";
    assert !guardTarget => !mockPolicy.innerReverted(), "the nested same-Safe check is served";
    assert !guardTarget => mockPolicy.calls() == 2, "the nested invocation is a second, distinct policy invocation";
    assert !guardTarget => mockPolicy.invSafe(1) == s,
        "the nested check runs for the Safe being checked, not one the policy names";
    assert !guardTarget => mockPolicy.invModule(1) == module,
        "the nested check carries the module from state - a policy cannot forge the authorization path";
    assert !guardTarget => (mockPolicy.invTo(1) == mockPolicy.reenterTo()
        && mockPolicy.invOperation(1) == mockPolicy.reenterOperation()),
        "the nested (to, operation) are that engine call's own arguments";
    assert !guardTarget => mockPolicy.invValue(1) == mockPolicy.reenterValue(),
        "the nested value is that engine call's own free value, not the top-level one";
    assert !guardTarget => mockPolicy.invAccess(1) == k1, "the nested access is resolved for the nested arguments";
    assert !guardTarget => mockPolicy.innerReturnedPolicy() == p1,
        "the nested callee is the policy resolved for the nested arguments";
    assert !guardTarget => (mockPolicy.invDataHash(1) == keccak(data)
        && mockPolicy.invDataLength(1) == data.length),
        "the nested data reaches the nested policy unaltered";
}

// R-EC-7, the nested data limb at free reenterDataSkip: the nested length is asserted as a function of the skip, with
// no access or callee claim, because CVL cannot name keccak(data[skip:]) for a symbolic skip (L-EC-12).
rule R_EC_7_nested_data(env e, address to, uint256 value, bytes data,
                        SafePolicyGuardHarness.Operation op, address module) {
    resetFrame();
    require e.msg.sender != 0;
    address s = e.msg.sender;
    require mockPolicy.checkMode() == MockPolicyHarness.CheckMode.REENTER_ENGINE;
    require mockPolicy.depth() == 0 && mockPolicy.calls() == 0;
    require mockPolicy.reenterSafe() == s;
    AccessSelector.T k = resolvesTo(s, to, value, data, op, mockPolicy);

    checkModuleTransaction(e, to, value, data, op, module);

    uint256 outer = mockPolicy.invDataLength(0);
    uint256 skip = mockPolicy.reenterDataSkip();
    assert mockPolicy.calls() == 2 => to_mathint(mockPolicy.invDataLength(1)) ==
        (skip >= outer ? 0 : to_mathint(outer) - to_mathint(skip)),
        "the nested data is the nested call's own argument, at every skip";
    assert (mockPolicy.calls() == 2 && skip > 0 && outer > 0) => mockPolicy.invDataLength(1) != outer,
        "a nested payload that differs from the top-level one really differs at the policy";
}

// W-EC-1(k): the antecedent of R_EC_7_nested_data is reachable at a non-zero skip over a non-empty payload.
rule W_EC_1_k_nestedTailData(env e, address to, uint256 value, bytes data,
                             SafePolicyGuardHarness.Operation op, address module) {
    resetFrame();
    require e.msg.sender != 0;
    address s = e.msg.sender;
    require mockPolicy.checkMode() == MockPolicyHarness.CheckMode.REENTER_ENGINE;
    require mockPolicy.depth() == 0 && mockPolicy.calls() == 0;
    require mockPolicy.reenterSafe() == s;
    AccessSelector.T k = resolvesTo(s, to, value, data, op, mockPolicy);

    checkModuleTransaction(e, to, value, data, op, module);

    satisfy mockPolicy.calls() == 2 && mockPolicy.reenterDataSkip() > 0
        && mockPolicy.invDataLength(0) > 0
        && mockPolicy.invDataLength(1) != mockPolicy.invDataLength(0);
}

// R-EC-8: on the owner path the top-level policy's context is payload(signatures) when the envelope is present and
// empty otherwise, read through the Lib reader set.
rule R_EC_8_owner(env e, address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op,
                  uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
                  address refundReceiver, bytes signatures, address msgSender) {
    require e.msg.sender != 0;
    pinNonReentrantMock();
    require mockPolicy.calls() == 0;
    address s = e.msg.sender;
    AccessSelector.T k = resolvesTo(s, to, value, data, op, mockPolicy);
    bool hasEnv = lib.has(signatures, CONTEXT_TYPE_HASH());
    checkTransaction(e, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken,
        refundReceiver, signatures, msgSender);
    assert hasEnv => (mockPolicy.invContextLength(0) == lib.payloadLength(signatures, CONTEXT_TYPE_HASH())
        && mockPolicy.invContextHash(0) == lib.payloadHash(signatures, CONTEXT_TYPE_HASH())),
        "context == payload(signatures) when the envelope is present";
    assert !hasEnv => mockPolicy.invContextLength(0) == 0,
        "context is empty when no envelope is present";
}

// R-EC-8: a nested engine call gives the nested policy that call's own context, not the top-level one.
// Split for #103 exactly as R_EC_7_nested is: a nested call aimed at the guard is denied `GuardTargetDenied` at
// PolicyEngine.sol:194 before any policy sees a context, so that branch asserts the denial and the context claims
// speak for the rest. No `require` was added; the branches partition the input set the rule already had.
rule R_EC_8_nested(env e, address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op,
                   uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
                   address refundReceiver, bytes signatures, address msgSender) {
    require e.msg.sender != 0;
    address s = e.msg.sender;
    require mockPolicy.checkMode() == MockPolicyHarness.CheckMode.REENTER_ENGINE;
    require mockPolicy.depth() == 0 && mockPolicy.calls() == 0;
    require mockPolicy.reenterSafe() == s && mockPolicy.reenterDataSkip() == 0;
    AccessSelector.T k = resolvesTo(s, to, value, data, op, mockPolicy);
    AccessSelector.T k1 = resolvesTo(s, mockPolicy.reenterTo(), mockPolicy.reenterValue(), data,
        mockPolicy.reenterOperation(), mockPolicy);
    bool guardTarget = mockPolicy.reenterTo() == currentContract;

    checkTransaction(e, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken,
        refundReceiver, signatures, msgSender);

    assert mockPolicy.innerCalled(), "the nested engine call is issued";
    assert guardTarget => (mockPolicy.innerReverted() && mockPolicy.innerErrorSelector() == errGuardTargetDenied()
        && mockPolicy.innerErrorLength() == 4),
        "a nested call aimed at the guard is denied before any policy sees a context (#103)";
    assert guardTarget => mockPolicy.calls() == 1, "the denied nested call reaches no policy at all (#103)";
    assert !guardTarget => !mockPolicy.innerReverted(), "the nested same-Safe check is served";
    uint256 outer = mockPolicy.invContextLength(0);
    uint256 skip = mockPolicy.reenterContextSkip();
    assert !guardTarget => to_mathint(mockPolicy.invContextLength(1)) ==
        (skip >= outer ? 0 : to_mathint(outer) - to_mathint(skip)),
        "the nested context is the nested call's own argument";
    assert (!guardTarget && skip > 0 && outer > 0) => mockPolicy.invContextLength(1) != outer,
        "a nested context that differs from the top-level one really differs at the policy";
}

// R-EC-14: the guard performs no DELEGATECALL anywhere.
rule R_EC_14_noDelegateCall(env e, method f, calldataarg args, SafePolicyGuard.Configuration[] c)
    filtered { f -> !f.isView && !f.isPure }
{
    resetFrame();
    if (f.selector == sig:applyConfiguration(SafePolicyGuard.Configuration[]).selector) {
        require c.length <= 3;
        applyConfiguration(e, c);
    } else if (f.selector == sig:configureImmediately(SafePolicyGuard.Configuration[]).selector) {
        require c.length <= 3;
        configureImmediately(e, c);
    } else {
        f(e, args);
    }
    assert gDelegateCalls == 0, "the guard never DELEGATECALLs";
}

// R-EC-14 at the applyConfiguration node with n <= 1 (L-EC-LOOP-N1): the n <= 3 node of R_EC_14_noDelegateCall, once
// a TIMEOUT on keccak over a symbolic array, is SUCCESS in EngineCheckDelegate.conf; the EngineConfig.spec rule that
// states the claim at n <= 3 is commented out.
rule R_EC_14_noDelegateCall_apply1(env e, SafePolicyGuard.Configuration[] c) {
    resetFrame();
    require c.length <= 1;
    applyConfiguration(e, c);
    assert gDelegateCalls == 0, "the guard never DELEGATECALLs (applyConfiguration at n <= 1)";
}

// R-EC-14: during a check every outgoing CALL the guard makes is IPolicy.checkTransaction with no value to the policy
// resolved for that invocation.
rule R_EC_14(env e, address to, uint256 value, bytes data,
             SafePolicyGuardHarness.Operation op, address module) {
    resetFrame();
    require e.msg.sender != 0;
    pinNonReentrantMock();
    bool allowedC = allowedCalls@withrevert(to, value, data, op);
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(e.msg.sender, to, data, op);
    require inScene(p);
    checkModuleTransaction(e, to, value, data, op, module);
    assert gDelegateCalls == 0, "no DELEGATECALL on the check path";
    assert gValueCalls == 0, "no value is forwarded to a policy";
    assert gOtherSelectorCalls == 0, "every outgoing CALL is IPolicy.checkTransaction (0xcbd11d55)";
    assert gCheckCalls == (allowedC ? 0 : 1), "exactly one policy call per non-hatch invocation, none on the hatch";
    assert forall address a. gCalled[a] => a == p, "the only callee is the resolved policy";
    assert gStatics == 0, "the check path reads no Safe storage";
}

// R-EC-15: two owner-path hook calls from the same storage differing only in baseGas, gasToken, refundReceiver and
// msgSender have the same outcome and leave the same storage; the fifth class of the row, the pre-envelope bytes of
// signatures, is un-attempted (R-EC-15).
rule R_EC_15(env e, address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op,
             uint256 safeTxGas, uint256 gasPrice, bytes signatures,
             uint256 baseGasA, address gasTokenA, address refundA, address senderA,
             uint256 baseGasB, address gasTokenB, address refundB, address senderB) {
    pinNonReentrantMock();
    require op == lib.opCall() || op == lib.opDelegateCall();
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(e.msg.sender, to, data, op);
    require inScene(p);
    // L-W0-2 is load-bearing here: under the NONDET default the two calls of this hyperproperty would answer with
    // independent free bytes4 values.
    storage init = lastStorage;
    checkTransaction@withrevert(e, to, value, data, op, safeTxGas, baseGasA, gasPrice, gasTokenA, refundA,
        signatures, senderA);
    bool revA = lastReverted;
    address sA = checkingSafe();
    address mA = checkingModule();
    checkTransaction@withrevert(e, to, value, data, op, safeTxGas, baseGasB, gasPrice, gasTokenB, refundB,
        signatures, senderB) at init;
    bool revB = lastReverted;
    assert revA == revB, "baseGas / gasToken / refundReceiver / msgSender never change the verdict";
    assert checkingSafe() == sA && checkingModule() == mA,
        "... nor either sentinel (msgSender is never authorised on; the root README's trust-of-check-inputs note, B-4)";
}

// R-EC-17: a checked transaction whose target is the guard itself is denied, at all three entries. Off the escape
// hatch the engine reverts before it resolves a policy, so a policy configured for the guard cannot serve the call
// and no policy state is spent on it (#103, PolicyEngine.sol:194); on the hatch the three configuration selectors
// still pass, which R-EC-11 states and this row does not touch.

// R-EC-17, the engine entry, which is the one that can name the class (L-EC-8).
rule R_EC_17_engine(env e, address safe, uint256 value, bytes data,
                    SafePolicyGuardHarness.Operation op, bytes ctx) {
    require safe != 0 && checkingSafe() == safe;
    require !badLen(data);
    require !allowedCalls(currentContract, value, data, op);
    bool ok; bytes4 sel; address arg; uint256 len; address r;
    ok, sel, arg, len, r = tryCheck(e, safe, currentContract, value, data, op, ctx);
    assert !ok && sel == errGuardTargetDenied() && len == 4,
        "the engine entry denies a guard-targeted call with GuardTargetDenied, whatever policy is configured";
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

// W-EC-1(g): the mid-check state is reached through the hook, which discharges the require S != 0 of R-EC-1/3/4
// (L-EC-9).
rule W_EC_1_g(env e, address to, uint256 value, bytes data,
              SafePolicyGuardHarness.Operation op, address module) {
    require e.msg.sender != 0;
    require checkingSafe() == 0;
    require mockPolicy.checkMode() == MockPolicyHarness.CheckMode.REENTER_ENGINE;
    require mockPolicy.depth() == 0 && mockPolicy.reenterSafe() == e.msg.sender;
    AccessSelector.T k; address p;
    k, p = getPolicy(e.msg.sender, to, data, op);
    require p == mockPolicy;
    checkModuleTransaction(e, to, value, data, op, module);
    satisfy mockPolicy.innerCalled() && !mockPolicy.innerReverted() && module != 0;
}

// W-EC-1(j): a nested engine call targeting the hatch is refused from state when the top-level check is
// module-authorised.
rule W_EC_1_j(env e, address to, uint256 value, bytes data,
              SafePolicyGuardHarness.Operation op, address module) {
    require e.msg.sender != 0;
    require module != 0;
    require mockPolicy.checkMode() == MockPolicyHarness.CheckMode.REENTER_ENGINE;
    require mockPolicy.depth() == 0 && mockPolicy.reenterSafe() == e.msg.sender;
    require mockPolicy.reenterTo() == currentContract && mockPolicy.reenterValue() == 0
        && mockPolicy.reenterOperation() == lib.opCall();
    AccessSelector.T k; address p;
    k, p = getPolicy(e.msg.sender, to, data, op);
    require p == mockPolicy;
    checkModuleTransaction(e, to, value, data, op, module);
    satisfy mockPolicy.innerCalled() && mockPolicy.innerReverted()
        && mockPolicy.innerErrorSelector() == errModuleConfigurationDenied();
}
