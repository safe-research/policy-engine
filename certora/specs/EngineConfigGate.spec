// EngineConfigGate.spec: the gate half of R-CFG-9 and all of R-CFG-10, on SafePolicyGuardHarness in the
// scene specs/EngineConfig.spec uses, with the guard's raw returndata read replaced by the CVL summary
// L-CFG-DECODE. Run by conf/EngineConfigGate.conf.
//
// Why the summary: `_readGuardSlot` (`G:304-320`) reads word 3 of a `staticcall` return buffer with a raw
// `mload` that is never `abi.decode`d, so the prover's pointer analysis gives up on the caller ("Pointer
// analysis for optimization failed", at a `ByteLoad` node) and every gate leaf FAILs
// on a counterexample in which the probe answers with an unconstrained address.
//
// The cut: `_readGuardSlot(safe, slot)` is summarized by `readGuardSlotModel`, which returns
// `gSlotAnswer[safe][slot]`, an unconstrained ghost, and records the target and slot of every probe. Each
// rule then pins `gSlotAnswer` at the two guard slots to the decode of the caller's own storage,
// `(success && retLen >= 96) ? word3 & mask : 0`. Everything else stays real code: `_isGuardEnabled`'s
// `||` over the two slots and its `== address(this)`, and `configureImmediately`'s
// `require(!_isGuardEnabled(...))`.
//
// L-CFG-DECODE, the assumption this file adds: one probe of slot `s` at target `t` returns exactly
// `(success && returndata.length >= 96) ? word3(returndata) & 0xff..ff : address(0)`. Its decode half is
// proved by R_CFG_DECODE_pin (specs/GuardSlotDecode.spec, conf/GuardSlotDecode.conf) against a copy of
// the guard's assembly, which is the residual half: what the pin holds is a copy, so keeping it in step
// with the contract is a review obligation. The pin proves the decode for answers of at most 160 bytes
// (all three of its rules `require returnData.length <= 160`); the summary above states it for every
// length, which is sound because the guard reads word 3 and nothing else, whatever the total length.
// Its `staticcall` half, that the probe is a STATICCALL of the
// caller at the two guard-slot constants and that the buffer decoded is that call's returndata, stays
// with the already green R_CFG_9_probe (conf/EngineConfigLight.conf) and with L-W0-3;
// R_CFG_9_probeArgs below re-proves the target and the two slots through the summary.
//
// Which rules rest on L-CFG-DECODE: every rule of this file, that is R_CFG_9_gate, R_CFG_9_gate_live,
// R_CFG_10, R_CFG_10_notEnabled and R_CFG_9_probeArgs, and no other rule of the suite. A `methods` block
// entry is file-wide, so the summary is confined to this file rather than added to
// specs/EngineConfig.spec, where it would reach the 11 rules of that file that call
// `configureImmediately` across four confs, and would leave R_CFG_9_probe (which counts the probe
// STATICCALLs the summary removes) asserting three trivially true facts.
//
// The four gate rules are the ones specs/EngineConfig.spec states, assert messages included, with two
// added `require` lines each; the unsummarized originals, which reproduce the pointer-analysis defect
// L-CFG-DECODE cuts, are commented out in specs/EngineConfig.spec.
//
// File-wide, as in specs/EngineConfig.spec: L-CFG-SCENE, L-CFG-PROBE, L-CFG-GATE, L-CFG-SLOTMOCK, L-W0-3.

import "Common.spec";

using AllowPolicy as allow;
using DenyPolicy as deny;
using OneTimeAllowPolicy as oneTimeAllow;
using GuardProbeResponderMock as responder;
using SafeSlotMock as slotMock;

methods {
    function responder.mode(uint256) external returns (GuardProbeResponderMock.Mode) envfree;
    function responder.retLen(uint256) external returns (uint256) envfree;
    function responder.word3Address(uint256) external returns (address) envfree;
    function slotMock.slotAddress(uint256) external returns (address) envfree;

    // The one summary of this file (L-CFG-DECODE); `_readGuardSlot` is `private view` (`G:304`) and the
    // typechecker resolves it as an internal method entry, so a misspelt name is rejected rather than
    // silently unbound.
    function SafePolicyGuard._readGuardSlot(address safe, bytes32 slot) internal returns (address)
        => readGuardSlotModel(safe, slot);

    // Scene dispatch, per signature (D-009), as in specs/EngineConfig.spec: the closed scene stands in for
    // arbitrary policy code (L-W0-2); an out-of-scene address takes the D-008 HAVOC_ECF.
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

    // Kept in step with specs/EngineConfig.spec although the summary above leaves it unreachable from the
    // guard: the two mocks stay in scene as the storage a rule pins the probe answer against.
    function _.getStorageAt(uint256,uint256) external => DISPATCH [ GuardProbeResponderMock._, SafeSlotMock._ ] default NONDET;
}

// The probe answer the model hands back, unconstrained until a rule pins it, and the probe recorder.
persistent ghost mapping(address => mapping(bytes32 => address)) gSlotAnswer;
persistent ghost mathint gProbes;
persistent ghost mapping(mathint => address) gProbeTarget;
persistent ghost mapping(mathint => bytes32) gProbeSlot;

function readGuardSlotModel(address safe, bytes32 slot) returns address {
    gProbes = gProbes + 1;
    gProbeTarget[gProbes] = safe;
    gProbeSlot[gProbes] = slot;
    return gSlotAnswer[safe][slot];
}

function resetProbes() {
    require gProbes == 0;
}

// The decode of a SafeSlotMock answer: always a well-formed 96-byte payload, so word 3 masked is the slot
// word masked, which is what slotAddress returns (L-CFG-SLOTMOCK).
function pinSlotMock(uint256 gs, uint256 ms) {
    require gSlotAnswer[slotMock][to_bytes32(gs)] == slotMock.slotAddress(gs);
    require gSlotAnswer[slotMock][to_bytes32(ms)] == slotMock.slotAddress(ms);
}

// The decode of a GuardProbeResponderMock answer, per mode (L-W0-3): only RETURNS with at least 96 bytes
// yields word 3 masked; REVERT_EMPTY, REVERT_96 and a short return all yield address(0).
function responderDecodes(uint256 s) returns address {
    if (responder.mode(s) == GuardProbeResponderMock.Mode.RETURNS && responder.retLen(s) >= 96) {
        return responder.word3Address(s);
    }
    return 0;
}

function pinResponder(uint256 gs, uint256 ms) {
    require gSlotAnswer[responder][to_bytes32(gs)] == responderDecodes(gs);
    require gSlotAnswer[responder][to_bytes32(ms)] == responderDecodes(ms);
}

// R-CFG-9 (gate), under L-CFG-DECODE: configureImmediately reverts iff paid or a guard slot of the calling
// Safe holds this contract.
rule R_CFG_9_gate(env e, SafePolicyGuard.Configuration[] c, uint256 gs, uint256 ms) {
    require e.msg.sender == slotMock;
    require c.length == 0;
    require to_bytes32(gs) == GUARD_STORAGE_SLOT() && to_bytes32(ms) == MODULE_GUARD_STORAGE_SLOT();
    pinSlotMock(gs, ms);
    bool installed = slotMock.slotAddress(gs) == currentContract || slotMock.slotAddress(ms) == currentContract;

    configureImmediately@withrevert(e, c);

    assert (e.msg.value != 0 || installed) => lastReverted,
        "no bypass: once either guard slot of the calling Safe holds this contract, configureImmediately reverts";
}

// R-CFG-9 (gate, liveness half), under L-CFG-DECODE: an unguarded Safe can always configure itself
// immediately.
rule R_CFG_9_gate_live(env e, SafePolicyGuard.Configuration[] c, uint256 gs, uint256 ms) {
    require e.msg.sender == slotMock;
    require c.length == 0;
    require to_bytes32(gs) == GUARD_STORAGE_SLOT() && to_bytes32(ms) == MODULE_GUARD_STORAGE_SLOT();
    pinSlotMock(gs, ms);
    bool installed = slotMock.slotAddress(gs) == currentContract || slotMock.slotAddress(ms) == currentContract;

    configureImmediately@withrevert(e, c);

    assert (e.msg.value == 0 && !installed) => !lastReverted,
        "liveness: an unguarded Safe can always configure itself immediately";
}

// R-CFG-10, under L-CFG-DECODE: a slot answer of at least 96 bytes whose masked word 3 is this contract
// reads as installed.
rule R_CFG_10(env e, SafePolicyGuard.Configuration[] c, uint256 gs, uint256 ms) {
    require e.msg.sender == responder;
    require c.length == 0;
    require e.msg.value == 0;
    require to_bytes32(gs) == GUARD_STORAGE_SLOT() && to_bytes32(ms) == MODULE_GUARD_STORAGE_SLOT();
    require responder.retLen(gs) <= 160 && responder.retLen(ms) <= 160;
    pinResponder(gs, ms);

    bool viaGuardSlot = responder.mode(gs) == GuardProbeResponderMock.Mode.RETURNS
        && responder.retLen(gs) >= 96 && responder.word3Address(gs) == currentContract;
    bool viaModuleSlot = responder.mode(ms) == GuardProbeResponderMock.Mode.RETURNS
        && responder.retLen(ms) >= 96 && responder.word3Address(ms) == currentContract;

    configureImmediately@withrevert(e, c);

    assert (viaGuardSlot || viaModuleSlot) => lastReverted,
        "a successful answer of at least 96 bytes whose masked word 3 is this contract reads as enabled";
}

// R-CFG-10 (fail-closed half), under L-CFG-DECODE: reverting, short and dirty answers never read as
// installed.
rule R_CFG_10_notEnabled(env e, SafePolicyGuard.Configuration[] c, uint256 gs, uint256 ms) {
    require e.msg.sender == responder;
    require c.length == 0;
    require e.msg.value == 0;
    require to_bytes32(gs) == GUARD_STORAGE_SLOT() && to_bytes32(ms) == MODULE_GUARD_STORAGE_SLOT();
    require responder.retLen(gs) <= 160 && responder.retLen(ms) <= 160;
    pinResponder(gs, ms);

    bool viaGuardSlot = responder.mode(gs) == GuardProbeResponderMock.Mode.RETURNS
        && responder.retLen(gs) >= 96 && responder.word3Address(gs) == currentContract;
    bool viaModuleSlot = responder.mode(ms) == GuardProbeResponderMock.Mode.RETURNS
        && responder.retLen(ms) >= 96 && responder.word3Address(ms) == currentContract;

    configureImmediately@withrevert(e, c);

    assert (!viaGuardSlot && !viaModuleSlot) => !lastReverted,
        "reverting or short answers, and dirty words that do not mask to this contract, never read as enabled";
}

// R-CFG-9 (probe discipline, summary arguments): the audit trail of L-CFG-DECODE, that the two probes
// configureImmediately makes go to the caller, at the two guard-slot constants, and nowhere else. The
// opcode-level half of the same claim is R_CFG_9_probe in conf/EngineConfigLight.conf, which the summary
// does not reach.
rule R_CFG_9_probeArgs(env e, SafePolicyGuard.Configuration[] c) {
    require e.msg.sender == slotMock;
    require c.length == 0;
    resetProbes();

    configureImmediately(e, c);

    assert gProbes <= 2, "at most two guard-slot probes";
    assert gProbes >= 1 => (gProbeTarget[1] == e.msg.sender && gProbeSlot[1] == GUARD_STORAGE_SLOT()),
        "the first probe reads the caller's transaction-guard slot";
    assert gProbes >= 2 => (gProbeTarget[2] == e.msg.sender && gProbeSlot[2] == MODULE_GUARD_STORAGE_SLOT()),
        "the second probe reads the caller's module-guard slot";
}
