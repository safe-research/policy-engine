/* Discharge of the recording summary that `MultiSend.spec` rests on (L-MS-1); run by `conf/MultiSendPin.conf`.
 * Same subject and bounds; five rules re-prove R-MS-4..7's content with the engine callback resolved by a
 * DISPATCH list onto `EngineRecorderHarness`, a real contract that records what a real EVM CALL delivered
 * and reverts on a Solidity `require`. No twin for R-MS-1, R-MS-2, R-MS-3, R-MS-8 or the decoder rules; out
 * of scope are R-EC-7, R-EC-9, R-MS-9 and WAIVED-H-7. File-wide: L-MS-6, the bounds L-MS-2 and L-MS-4, and
 * defect L-POL-CTX: the four `assert` rules here each take two free CVL `bytes` (`data`, `context`) and make a
 * call, the shape that under the conf's `precise_bitwise_ops: true` silently drops every input pair with
 * exactly one empty buffer (L-POL-CTX). No companion rule ships here; the audit L-POL-CTX-M probed
 * these rules instead, R_MS_PIN_denial's empty-`data` probes being vacuous. */

import "Vocabulary.spec";

using EngineRecorderHarness as recorder;

methods {
    // The policy callback into the engine, resolved onto the real recorder by a per-signature DISPATCH list (D-009);
    // the `unresolved external in ...` form does not inline typed calls.
    function _.checkTransaction(
        address,
        address,
        uint256,
        bytes,
        MultiSendPolicyHarness.Operation,
        bytes
    ) external => DISPATCH [
        EngineRecorderHarness.checkTransaction(address,address,uint256,bytes,MultiSendPolicyHarness.Operation,bytes)
    ] default NONDET;

    function batchLength(bytes) external returns (uint256) envfree;
    function subTx(address, bytes, uint256) external
        returns (address, uint256, bytes, MultiSendPolicyHarness.Operation) envfree;
    function ctxItem(bytes, uint256) external returns (bytes) envfree;
    function ctxTail(bytes, uint256) external returns (bytes) envfree;

    function recorder.calls() external returns (uint256) envfree;
    function recorder.recCaller(uint256) external returns (address) envfree;
    function recorder.recSafe(uint256) external returns (address) envfree;
    function recorder.recTo(uint256) external returns (address) envfree;
    function recorder.recValue(uint256) external returns (uint256) envfree;
    function recorder.recDataHash(uint256) external returns (bytes32) envfree;
    function recorder.recDataLength(uint256) external returns (uint256) envfree;
    function recorder.recOperation(uint256) external returns (MultiSendPolicyHarness.Operation) envfree;
    function recorder.recContextHash(uint256) external returns (bytes32) envfree;
    function recorder.recContextLength(uint256) external returns (uint256) envfree;
    function recorder.verdict(uint256) external returns (bool) envfree;
}

// As in MultiSend.spec: the value the engine requires at PolicyEngine.sol:202.
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,MultiSendPolicyHarness.Operation,address,bytes,AccessSelector.T).selector
);

// The same batch bound as MultiSend.spec (L-MS-2).
// MS_MAX_BYTES is declared in Vocabulary.spec.

// Longest `context` envelope a rule running the batch loop admits (L-MS-4), equal to the conf's
// `hashing_length_bound`: with no summary the hashed terms are the recorder's own keccak of `data`
// and `context` plus the keccak this spec computes on the real decoder's output.
// MS_MAX_CTX is declared in Vocabulary.spec.

// R-MS-4 against a real callee: the policy performs exactly one real external call per decoded sub-transaction, which
// is what `R_MS_4` proves over the recording summary's ghost counter.
rule R_MS_PIN_count(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    MultiSendPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require e.msg.sender == recorder;
    require recorder.calls() == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    uint256 n = batchLength@withrevert(data);
    bool decodes = !lastReverted;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool cleared = !lastReverted;

    assert cleared => decodes,
        "a check that clears implies the whole batch decoded (real-callee instance of R-MS-4)";
    assert cleared => recorder.calls() == n,
        "the policy made exactly one real external call per decoded sub-transaction";
    assert cleared => recorder.calls() <= 3,
        "the ledgered batch bound L-MS-2 holds against a real callee too";
}

// R-MS-5 against a real callee: every field a real callee receives is item i of the batch, with a zero target resolved
// to the Safe, which is what `R_MS_5` proves over the summary's ghosts.
rule R_MS_PIN_fields(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    MultiSendPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require e.msg.sender == recorder;
    require recorder.calls() == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    // Raw decode of each item: `safe == 0` makes the :68-70 rewrite the identity.
    address rawTo0; uint256 val0; bytes sub0; MultiSendPolicyHarness.Operation sop0;
    address rawTo1; uint256 val1; bytes sub1; MultiSendPolicyHarness.Operation sop1;
    address rawTo2; uint256 val2; bytes sub2; MultiSendPolicyHarness.Operation sop2;
    // `@withrevert` throughout: a `@norevert` call would discard every batch with fewer than three items,
    // narrowing this rule to three-item batches.
    rawTo0, val0, sub0, sop0 = subTx@withrevert(0, data, 0);
    bool ok0 = !lastReverted;
    rawTo1, val1, sub1, sop1 = subTx@withrevert(0, data, 1);
    bool ok1 = !lastReverted;
    rawTo2, val2, sub2, sop2 = subTx@withrevert(0, data, 2);
    bool ok2 = !lastReverted;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool cleared = !lastReverted;
    uint256 n = recorder.calls();

    assert cleared => ((n > 0 => ok0) && (n > 1 => ok1) && (n > 2 => ok2)),
        "the harness walk decodes item i whenever the policy's own loop decoded it (the walker mirrors the loop, L-MS-5)";
    assert cleared && n > 0 =>
        recorder.recCaller(0) == currentContract && recorder.recSafe(0) == safe
        && recorder.recTo(0) == (rawTo0 == 0 ? safe : rawTo0)
        && recorder.recValue(0) == val0
        && recorder.recDataHash(0) == keccak256(sub0) && recorder.recDataLength(0) == sub0.length
        && recorder.recOperation(0) == sop0,
        "the real callee's first call carries item 0 verbatim, from this policy, with a zero target resolved to the Safe";
    assert cleared && n > 1 =>
        recorder.recCaller(1) == currentContract && recorder.recSafe(1) == safe
        && recorder.recTo(1) == (rawTo1 == 0 ? safe : rawTo1)
        && recorder.recValue(1) == val1
        && recorder.recDataHash(1) == keccak256(sub1) && recorder.recDataLength(1) == sub1.length
        && recorder.recOperation(1) == sop1,
        "the real callee's second call carries item 1 verbatim";
    assert cleared && n > 2 =>
        recorder.recCaller(2) == currentContract && recorder.recSafe(2) == safe
        && recorder.recTo(2) == (rawTo2 == 0 ? safe : rawTo2)
        && recorder.recValue(2) == val2
        && recorder.recDataHash(2) == keccak256(sub2) && recorder.recDataLength(2) == sub2.length
        && recorder.recOperation(2) == sop2,
        "the real callee's third call carries item 2 verbatim";
}

// R-MS-6 against a real callee: it receives context item i at position i, and the empty string once the envelope is
// exhausted, which is what `R_MS_6` proves over the ghosts.
rule R_MS_PIN_context(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    MultiSendPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require e.msg.sender == recorder;
    require recorder.calls() == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    bytes c0 = ctxItem@withrevert(context, 0);
    bool cok0 = !lastReverted;
    bytes c1 = ctxItem@withrevert(context, 1);
    bool cok1 = !lastReverted;
    bytes c2 = ctxItem@withrevert(context, 2);
    bool cok2 = !lastReverted;
    bytes tail1 = ctxTail@withrevert(context, 1);
    bool tok1 = !lastReverted;
    bytes tail2 = ctxTail@withrevert(context, 2);
    bool tok2 = !lastReverted;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool cleared = !lastReverted;
    uint256 n = recorder.calls();

    assert cleared && n > 0 =>
        cok0 && recorder.recContextHash(0) == keccak256(c0) && recorder.recContextLength(0) == c0.length,
        "the real callee's first call receives context item 0";
    assert cleared && n > 1 =>
        cok1 && recorder.recContextHash(1) == keccak256(c1) && recorder.recContextLength(1) == c1.length,
        "the real callee's second call receives context item 1, not item 0 again";
    assert cleared && n > 2 =>
        cok2 && recorder.recContextHash(2) == keccak256(c2) && recorder.recContextLength(2) == c2.length,
        "the real callee's third call receives context item 2";
    assert cleared && n > 1 && tok1 && tail1.length == 0 => recorder.recContextLength(1) == 0,
        "an envelope exhausted before position 1 hands the real callee the empty context";
    assert cleared && n > 2 && tok2 && tail2.length == 0 => recorder.recContextLength(2) == 0,
        "an envelope exhausted before position 2 hands the real callee the empty context";
}

// R-MS-7 against a real callee, which validates the reverting summary: a callee reverting through a Solidity `require`
// denies the whole batch, because MultiSendPolicy.sol:39 carries no `try/catch`.
rule R_MS_PIN_denial(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    MultiSendPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    uint256 j
) {
    require e.msg.sender == recorder;
    require recorder.calls() == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    uint256 n = batchLength@withrevert(data);
    require !lastReverted;                           // antecedent: the batch decodes
    require j < n;                                   // antecedent: position j is inside the batch
    require !recorder.verdict(j);                    // antecedent: the real callee denies at position j

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert lastReverted,
        "a real callee's revert at any reached position denies the whole batch";
}

// W-MS-1 against a real callee: a two-item batch reaches the real recorder twice with two distinct contexts and clears
// with the magic value, so the four rules above are not vacuous.
rule W_MS_PIN_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    MultiSendPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require e.msg.sender == recorder;
    require recorder.calls() == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool cleared = !lastReverted;

    satisfy cleared && r == MAGIC() && recorder.calls() == 2
        && recorder.recContextLength(0) != recorder.recContextLength(1),
        "a two-item batch really reaches the real callee twice, with two distinct contexts";
}
