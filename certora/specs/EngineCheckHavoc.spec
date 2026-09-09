// EngineCheckHavoc.spec: the two EngineCheck rows stated against an arbitrary policy, R-EC-3 and R-EC-12,
// for which L-EC-5 prescribes HAVOC_ALL; a methods entry is per spec, so they live in their own file.
// HAVOC_ALL havocs the guard's own storage, so both rows are stated from pre-call state plus lastReverted
// and the persistent opcode-hook counter, with no DISPATCH list and no satisfy. Conf: EngineCheckHavoc.
// File-wide assumptions: L-EC-FRAME, L-W0-SENDER.

import "Common.spec";

methods {
    // The engine-to-policy call is fully adversarial: HAVOC_ALL is strictly more permissive than D-008's HAVOC_ECF, and
    // both rows are decided before it.
    function _.checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,address,bytes,AccessSelector.T) external
        => HAVOC_ALL;
    function _.configure(address,AccessSelector.T,bytes) external => HAVOC_ALL;
}

// Persistent so the counter survives both the unresolved call and the revert the rules provoke.
persistent ghost mathint gCalls;

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (executingContract == currentContract) {
        gCalls = gCalls + 1;
    }
}

function resetFrame() {
    require gCalls == 0;
}

// `_decodeContext` does not revert, stated with the Lib reader set rather than the guard's own decoder.
function wellFormedSig(bytes sg) returns bool {
    if (!lib.has(sg, CONTEXT_TYPE_HASH())) {
        return true;
    }
    if (sg.length < 64) {
        return false;
    }
    return to_mathint(lib.lengthWord(sg)) <= to_mathint(sg.length) - 64;
}

// R-EC-3: the engine entry reverts whenever S == 0, safe != S, badLen(data), the hatch is taken with M != 0, the target
// off the hatch is the guard itself, or no policy resolves, whatever msg.sender, ctx and the policies do. The
// guard-target clause is #103's, and it holds against an arbitrary policy because it precedes the policy call.
rule R_EC_3(env e, address safe, address to, uint256 value, bytes data,
            SafePolicyGuardHarness.Operation op, bytes ctx) {
    address s = checkingSafe();
    address m = checkingModule();
    bool bad = badLen(data);

    // Both readers are called `@withrevert` because both revert on `badLen(data)`; used only under `!bad`.
    bool allowedC = allowedCalls@withrevert(to, value, data, op);
    AccessSelector.T k; address p;
    k, p = getPolicy@withrevert(safe, to, data, op);

    checkTransaction@withrevert(e, safe, to, value, data, op, ctx);
    bool rev = lastReverted;

    assert s == 0 => rev, "no check in progress: NotChecking (PolicyEngine.sol:179)";
    assert safe != s => rev, "a check for another Safe: CrossSafeCheck (PolicyEngine.sol:180)";
    assert bad => rev, "1-3 byte calldata: InvalidSelector (PolicyEngine.sol:247-255)";
    assert (!bad && allowedC && m != 0) => rev,
        "a module transaction may not reach the configuration hatch: ModuleConfigurationDenied (PolicyEngine.sol:182-186)";
    assert (!bad && !allowedC && to == currentContract) => rev,
        "a checked transaction aimed at the guard itself: GuardTargetDenied (PolicyEngine.sol:194)";
    assert (!bad && !allowedC && p == 0) => rev,
        "no policy configured denies by default: AccessDenied(address(0)) (PolicyEngine.sol:197)";
}

// R-EC-12: from every P[.][.] state an unpaid, well-formed owner-path hook on the escape hatch succeeds and invokes no
// policy, so a Safe cannot lock itself out of its policies.
rule R_EC_12(env e, address to, uint256 value, bytes data, SafePolicyGuardHarness.Operation op,
             uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
             address refundReceiver, bytes signatures, address msgSender) {
    resetFrame();
    require e.msg.sender != 0;
    require e.msg.value == 0 && gasPrice == 0 && safeTxGas == 0;
    // the row's own preconditions; the hook rejects them at SafePolicyGuard.sol:218,224 (R-EC-5).
    require checkingSafe() == 0;   // the row is about a top-level owner transaction; R-EC-2 covers the mid-check case
    require wellFormedSig(signatures);
    bool allowedC = allowedCalls(to, value, data, op);
    require allowedC;

    checkTransaction@withrevert(e, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken,
        refundReceiver, signatures, msgSender);
    assert !lastReverted, "the escape hatch always succeeds, whatever P[.][.] holds";
    assert gCalls == 0, "the escape hatch invokes no policy, so no policy can veto it";
}
