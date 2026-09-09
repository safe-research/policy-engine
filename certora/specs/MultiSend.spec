/* MultiSendPolicy: R-MS-1, R-MS-2, R-MS-3 and R-MS-8, and completeness, fidelity, positional contexts and no
 * fall-through with their witnesses, run by `conf/MultiSend.conf`, on `MultiSendPolicyHarness`,
 * an additive subclass exposing the three real internal decoders. L-MS-1 summarizes the one external
 * call, `IPolicyEngine(msg.sender).checkTransaction` at MultiSendPolicy.sol:39, by a recording CVL
 * function with free per-call oracles; it drops the engine's own behaviour (R-EC-7, R-EC-9) and nested
 * batches (R-MS-9), and `specs/MultiSendPin.spec` re-proves R-MS-4..7 against a real contract.
 * File-wide: bounds L-MS-2 and L-MS-4; domain L-MS-7, an instance of L-POL-6 and L-POL-9; defect L-POL-CTX.
 * The L-POL-CTX exposure is this unit's largest: ten `assert` rules below take two free CVL `bytes` (`data`,
 * `context`) and make a call, namely R_MS_2, R_MS_3_malformed, R_MS_3_liveness, R_MS_3_ctxMalformed, R_MS_4,
 * R_MS_5, R_MS_6, R_MS_7_denial, R_MS_7_magic and R_MS_8_check. That is the shape which, under the conf's
 * `precise_bitwise_ops: true`, silently drops every input pair with exactly one empty buffer (L-POL-CTX).
 * No companion rule ships here; the audit L-POL-CTX-M probed these rules instead, and its six vacuous probes
 * are the empty-`data` cases of R_MS_3_liveness, R_MS_7_denial and its real-callee twin. */

import "Vocabulary.spec";

using LibHarness as lib;

// Recording summary of the engine callback (L-MS-1). The ghosts are `persistent` (D-007) so they survive an unresolved
// external call and a revert, which R-MS-2 and the no-fall-through rules state over.
persistent ghost mathint k;                                        // sub-checks observed so far
persistent ghost mapping(mathint => address) subCallee;            // the contract the policy called
persistent ghost mapping(mathint => address) subSafe;
persistent ghost mapping(mathint => address) subTarget;
persistent ghost mapping(mathint => uint256) subValue;
persistent ghost mapping(mathint => bytes32) subDataHash;
persistent ghost mapping(mathint => uint256) subDataLength;
persistent ghost mapping(mathint => MultiSendPolicyHarness.Operation) subOperation;
persistent ghost mapping(mathint => bytes32) subContextHash;
persistent ghost mapping(mathint => uint256) subContextLength;
persistent ghost mapping(mathint => bool) subVerdict;              // free oracle: accept or revert
persistent ghost mapping(mathint => address) subReturn;            // free oracle: returned policy

function recordSubCall(
    address callee,
    address safe,
    address to,
    uint256 value,
    bytes data,
    MultiSendPolicyHarness.Operation operation,
    bytes context
) returns address {
    mathint i = k;
    subCallee[i] = callee;
    subSafe[i] = safe;
    subTarget[i] = to;
    subValue[i] = value;
    subDataHash[i] = keccak256(data);
    subDataLength[i] = data.length;
    subOperation[i] = operation;
    subContextHash[i] = keccak256(context);
    subContextLength[i] = context.length;
    k = i + 1;
    if (!subVerdict[i]) {
        revert();
    }
    return subReturn[i];
}

methods {
    // The summarized engine callback. A wildcard entry leaves the policy UNRESOLVED, so `msg.sender` stays free and
    // no rule assumes the caller is the engine.
    function _.checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes data,
        MultiSendPolicyHarness.Operation operation,
        bytes context
    ) external => recordSubCall(calledContract, safe, to, value, data, operation, context) expect address;

    function batchBody(bytes) external returns (bytes) envfree;
    function batchLength(bytes) external returns (uint256) envfree;
    function subTx(address, bytes, uint256) external
        returns (address, uint256, bytes, MultiSendPolicyHarness.Operation) envfree;
    function ctxItem(bytes, uint256) external returns (bytes) envfree;
    function ctxTail(bytes, uint256) external returns (bytes) envfree;
    // One application of the real `_decodeNextTransaction`, no iteration, for R_MS_5_itemDecoder.
    function nextTx(address, bytes) external
        returns (address, uint256, bytes, MultiSendPolicyHarness.Operation, uint256) envfree;
    function selMultiSend() external returns (bytes4) envfree;
    // `CALL` and `DELEGATECALL` are reserved CVL tokens, so the enum members are read here.
    function opCall() external returns (MultiSendPolicyHarness.Operation) envfree;
    function opDelegateCall() external returns (MultiSendPolicyHarness.Operation) envfree;

    function lib.selectorOf(bytes) external returns (bytes4) envfree;
    // The two independent byte readers the decoder rules are written in: total functions of the bytes, zero past the
    // end, carrying no MultiSendPolicy code, pinned by Lib.spec R-LIB-6/7/8.
    function lib.byteAt(bytes, uint256) external returns (uint256) envfree;
    function lib.wordAt(bytes, uint256) external returns (uint256) envfree;
    function lib.getSelector(AccessSelector.T) external returns (bytes4) envfree;
    function lib.getOperation(AccessSelector.T) external returns (MultiSendPolicyHarness.Operation) envfree;
}

// Read from the ABI so the magic value is the compiler's; R_MS_1 also asserts it against the literal 0xcbd11d55
// (PolicyEngine.sol:202).
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,MultiSendPolicyHarness.Operation,address,bytes,AccessSelector.T).selector
);

// `IMultiSend.multiSend.selector` as a literal (IMultiSend.sol:23), asserted against the harness reader
// `selMultiSend()`, so neither the policy nor `IMultiSend` can move without failing a rule.
// SEL_MULTISEND is declared in Vocabulary.spec.

// Longest `bytes data` a rule running the batch loop admits (L-MS-2, the report's assumption row); the residual,
// batches of four or more sub-transactions, is WAIVED-H-7.
// MS_MAX_BYTES is declared in Vocabulary.spec.

// Longest `context` envelope a rule running the batch loop admits (L-MS-4), equal to the conf's
// `hashing_length_bound`: the summary hashes `ctx_i` on every sub-call and the default 3200-byte
// buffer put the keccak term beyond the bit-vector solver. 416 bytes covers three co-signature contexts.
// MS_MAX_CTX is declared in Vocabulary.spec.

// R-MS-1: `configure` returns true iff `getSelector(access)` is multiSend and `getOperation(access)` is DELEGATECALL,
// never reverts at zero callvalue and writes no storage (MultiSendPolicy.sol:94-96).
rule R_MS_1(env e, address safe, AccessSelector.T access, bytes data) {
    // `configure` is `external pure`, so the dispatcher rejects callvalue before the body runs; the payable half is
    // asserted over raw calldata by R_MS_1_anyCalldata.
    require e.msg.value == 0;

    bytes4 sel = lib.getSelector(access);
    MultiSendPolicyHarness.Operation op = lib.getOperation(access);
    bool keyOk = sel == SEL_MULTISEND() && op == opDelegateCall();

    storage before = lastStorage;
    bool ok = configure@withrevert(e, safe, access, data);

    assert !lastReverted,
        "configure never reverts at zero callvalue, for any safe/access/data (MultiSendPolicy.sol:94-96)";
    assert keyOk => ok,
        "configure accepts the multiSend DELEGATECALL key (the liveness half: the policy can be installed)";
    assert ok => keyOk,
        "configure accepts only the multiSend DELEGATECALL key (the safety half: no CALL key, no other selector)";
    assert lastStorage[currentContract] == before[currentContract],
        "configure writes no storage";
    assert selMultiSend() == SEL_MULTISEND() && MAGIC() == to_bytes4(0xcbd11d55),
        "the constants the policy compares against are IMultiSend.multiSend.selector and IPolicy.checkTransaction.selector";
}

// R-MS-1 over `calldataarg` (L-MS-7): `configure` is non-payable and writes no storage; the key iff is not restated,
// because a `calldataarg` cannot name `access`.
rule R_MS_1_anyCalldata(env e, calldataarg args) {
    storage before = lastStorage;
    configure@withrevert(e, args);

    assert e.msg.value != 0 => lastReverted,
        "configure is not payable, for every byte string";
    assert lastStorage[currentContract] == before[currentContract],
        "configure writes no storage, for every byte string";
}

// R-MS-2: `checkTransaction` reverts when `data.length < 4` or the selector is not multiSend,
// observing no sub-check and returning no magic value, and carries neither bound because the decode
// fails before the loop (MultiSendPolicy.sol:46).
rule R_MS_2(
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
    require k == 0;
    // The rule's own antecedent: `data` is not a MultiSend batch.
    require data.length < 4 || lib.selectorOf(data) != SEL_MULTISEND();

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert lastReverted,
        "calldata that is not a multiSend batch is rejected outright (MultiSendPolicy.sol:46), never answered with the magic value";
    assert k == 0,
        "and no sub-transaction is checked before that rejection";
}

// R-MS-3 (malformed batches): a batch the real decoder rejects always reverts and never returns the magic value; the
// rejected classes are an inconsistent ABI head (:49-54), a truncated sub-transaction or a `85 + dataLength` overflow
// (:73-75), and an `operation` byte above 1 (:66).
rule R_MS_3_malformed(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    // Everything the assertions mention is computed before the call, so `lastReverted` belongs to the call under test.
    bytes4 sel = lib.selectorOf(data);
    // "Malformed" is not a mirror predicate: it is the real decoders refusing the input.
    batchLength@withrevert(data);
    bool decodes = !lastReverted;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert !decodes => lastReverted,
        "a batch the real decoders reject never authorizes: the whole check reverts";
    assert (data.length >= 4 && sel == SEL_MULTISEND() && data.length < 36) => lastReverted,
        "a multiSend head with no room for the ABI offset and length words is rejected (MultiSendPolicy.sol:49-51)";
}

// R-MS-3, the liveness twin: a well-formed batch with well-formed contexts whose sub-checks all accept does not revert,
// returns the magic value, and performs exactly one sub-check per decoded sub-transaction (MultiSendPolicy.sol:36-42).
rule R_MS_3_liveness(
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
    require k == 0;
    // The rule's own antecedent; `checkTransaction` is non-payable, so callvalue reverts in the dispatcher.
    require e.msg.value == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    uint256 n = batchLength@withrevert(data);
    require !lastReverted;                           // the rule's antecedent: the batch is well formed

    // The envelope is well formed at every position the policy reaches. Each require is the rule's own antecedent,
    // guarded by `n < i + 1` so it says nothing about unreached positions, and the indices are literals so no walker
    // runs a symbolic number of iterations. The converse belongs to R_MS_3_ctxMalformed below.
    ctxItem@withrevert(context, 0);
    require n < 1 || !lastReverted;
    ctxItem@withrevert(context, 1);
    require n < 2 || !lastReverted;
    ctxItem@withrevert(context, 2);
    require n < 3 || !lastReverted;

    // ... and every sub-check accepts. `subVerdict` is a free ghost; this picks the accepting oracle.
    require subVerdict[0] && subVerdict[1] && subVerdict[2];

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert !lastReverted,
        "a well-formed batch with well-formed contexts and accepting sub-checks clears";
    assert r == MAGIC(),
        "and answers with IPolicy.checkTransaction.selector (MultiSendPolicy.sol:42)";
    assert k == to_mathint(n),
        "having performed exactly one sub-check per decoded sub-transaction";
}

// R-MS-3, the malformed-context disjunct `R_MS_3_malformed` misses: `batchLength` walks
// transactions only, so `ctxItem(context, i)` applies the real `_decodeNextContext` (:78-89) i + 1
// times, and `n <= 3` exhausts positions 0..2.
rule R_MS_3_ctxMalformed(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    // Both sides are computed before the call and neither is assumed: `decodes` and `n` come from the real transaction
    // walk, `cok_i` from the real context decoder.
    uint256 n = batchLength@withrevert(data);
    bool decodes = !lastReverted;

    ctxItem@withrevert(context, 0);
    bool cok0 = !lastReverted;
    ctxItem@withrevert(context, 1);
    bool cok1 = !lastReverted;
    ctxItem@withrevert(context, 2);
    bool cok2 = !lastReverted;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert (decodes && n > 0 && !cok0) => lastReverted,
        "a context envelope the real _decodeNextContext rejects at position 0 denies the whole batch (MultiSendPolicy.sol:38,85-88)";
    assert (decodes && n > 1 && !cok1) => lastReverted,
        "a context envelope malformed at or before position 1 denies the whole batch, whatever the sub-check verdicts";
    assert (decodes && n > 2 && !cok2) => lastReverted,
        "a context envelope malformed at or before position 2 denies the whole batch";
}

// Decoder rules (L-MS-9, the MultiSend instance of L-POL-11 and L-LIB-3). Elsewhere this file states the
// policy in the vocabulary of harness walkers that call the same inherited decoders, so a defect inside a
// decoder moves both sides at once; these three rules close that hole, compare like reads with like so
// L-LIB-4 costs them nothing, and carry neither L-MS-2 nor L-MS-4.

// R-MS-3 head decoder rule: `_decodeMultiSendTransactions` (MultiSendPolicy.sol:45-55) succeeds iff `data` is at least
// four bytes, carries the multiSend selector and has a consistent ABI head, `off + 36 + lenWord <= data.length`, and
// then the body is exactly `lenWord` bytes from byte `36 + off`.
rule R_MS_3_headDecoder(bytes data, uint256 lenOff, uint256 bodyOff, uint256 j, uint256 srcIdx) {
    bytes4 sel = lib.selectorOf(data);                 // bytes4(data), zero-padded
    uint256 off = lib.wordAt(data, 4);                 // the ABI offset word (:49)
    uint256 lenWord = lib.wordAt(data, lenOff);        // the length word (:51)

    bytes body = batchBody@withrevert(data);           // the real decoder, whole
    bool ok = !lastReverted;

    assert (data.length < 4 || sel != SEL_MULTISEND()) => !ok,
        "the head decoder rejects calldata shorter than four bytes, and calldata under a foreign selector (MultiSendPolicy.sol:46)";
    assert (data.length >= 4 && sel == SEL_MULTISEND()
            && to_mathint(off) + 36 > to_mathint(data.length)) => !ok,
        "an ABI offset leaving no room for the length word is rejected (MultiSendPolicy.sol:49-51)";
    assert (data.length >= 4 && sel == SEL_MULTISEND()
            && to_mathint(lenOff) == 4 + to_mathint(off)
            && to_mathint(off) + 36 + to_mathint(lenWord) > to_mathint(data.length)) => !ok,
        "a body length word reaching past the end of the calldata is rejected (MultiSendPolicy.sol:54)";
    assert (data.length >= 4 && sel == SEL_MULTISEND()
            && to_mathint(lenOff) == 4 + to_mathint(off)
            && to_mathint(off) + 36 + to_mathint(lenWord) <= to_mathint(data.length))
           => (ok && to_mathint(body.length) == to_mathint(lenWord)),
        "a consistent multiSend head always decodes, and the body is exactly as long as the length word says";
    assert (ok && to_mathint(bodyOff) == 36 + to_mathint(off)
            && to_mathint(srcIdx) == to_mathint(bodyOff) + to_mathint(j)
            && j < body.length)
           => lib.byteAt(body, j) == lib.byteAt(data, srcIdx),
        "the body is the slice of the calldata beginning at 36 + off: byte j of the body is byte 36 + off + j of data";
}

// R-MS-5 item decoder rule: `_decodeNextTransaction` (MultiSendPolicy.sol:62-76) applied once by
// `nextTx` to an arbitrary body, with its revert condition, four fields and step size stated
// against LibHarness readers of the same bytes.
rule R_MS_5_itemDecoder(bytes body, uint256 j, uint256 srcIdx) {
    uint256 opByte = lib.byteAt(body, 0);              // the operation byte (:66)
    uint256 toWord = lib.wordAt(body, 1);              // the target, top 20 bytes (:67)
    uint256 valWord = lib.wordAt(body, 21);            // the value (:71)
    uint256 dlWord = lib.wordAt(body, 53);             // the data length (:72)

    address rawTo; uint256 val; bytes sub; MultiSendPolicyHarness.Operation sop; uint256 restLen;
    // `safe == 0` makes the `:68-70` zero-target rewrite the identity, so `rawTo` is the raw field.
    rawTo, val, sub, sop, restLen = nextTx@withrevert(0, body);
    bool ok = !lastReverted;

    assert ok <=> (to_mathint(body.length) >= 85 && opByte <= 1
                   && 85 + to_mathint(dlWord) <= to_mathint(body.length)),
        "the item decoder succeeds exactly on an 85-byte item header whose operation byte is 0 or 1 and whose data length fits the body (MultiSendPolicy.sol:66-75)";
    assert ok => ((opByte == 0 && sop == opCall()) || (opByte == 1 && sop == opDelegateCall())),
        "the operation is byte 0 of the item, unmasked (MultiSendPolicy.sol:66)";
    assert ok => to_mathint(rawTo) == to_mathint(toWord) / 2^96,
        "the raw target is the twenty bytes at offset 1 (MultiSendPolicy.sol:67)";
    assert ok => to_mathint(val) == to_mathint(valWord),
        "the value is the word at offset 21 (MultiSendPolicy.sol:71)";
    assert ok => to_mathint(sub.length) == to_mathint(dlWord),
        "the sub-calldata is as long as the word at offset 53 says (MultiSendPolicy.sol:72-73)";
    assert (ok && to_mathint(srcIdx) == 85 + to_mathint(j) && j < sub.length)
           => lib.byteAt(sub, j) == lib.byteAt(body, srcIdx),
        "the sub-calldata is the slice beginning at offset 85: byte j of it is byte 85 + j of the body (MultiSendPolicy.sol:73)";
    assert ok => to_mathint(restLen) == to_mathint(body.length) - 85 - to_mathint(dlWord),
        "the step consumes exactly 85 + dataLength bytes, so the next item starts where this one ends (MultiSendPolicy.sol:75)";
}

// R-MS-6 context decoder rule: `_decodeNextContext` (MultiSendPolicy.sol:78-89) applied once to the head of an
// arbitrary envelope, in both branches, the empty envelope (:81-83) and the length-prefixed slice (:85-88).
rule R_MS_6_ctxDecoder(bytes context, uint256 j, uint256 srcIdx) {
    uint256 lenWord = lib.wordAt(context, 0);          // the item's length word (:85)

    bytes c = ctxItem@withrevert(context, 0);
    bool ok = !lastReverted;
    bytes tail = ctxTail@withrevert(context, 1);
    bool tok = !lastReverted;

    assert ok <=> (context.length == 0
                   || (context.length >= 32 && 32 + to_mathint(lenWord) <= to_mathint(context.length))),
        "the context decoder succeeds exactly on an empty envelope, or on one whose leading length word fits inside it (MultiSendPolicy.sol:81-88)";
    assert ok == tok,
        "the item and the remainder are decoded by the same step, so they succeed together (MultiSendPolicy.sol:87-88)";
    assert (ok && context.length == 0) => c.length == 0,
        "an exhausted envelope answers the empty context, without reverting (MultiSendPolicy.sol:81-83)";
    assert (ok && context.length != 0) => to_mathint(c.length) == to_mathint(lenWord),
        "a non-empty envelope yields exactly as many bytes as its leading length word says (MultiSendPolicy.sol:85-87)";
    assert (ok && to_mathint(srcIdx) == 32 + to_mathint(j) && j < c.length)
           => lib.byteAt(c, j) == lib.byteAt(context, srcIdx),
        "the context item is the slice beginning at offset 32: byte j of it is byte 32 + j of the envelope (MultiSendPolicy.sol:87)";
    assert (tok && context.length != 0) => to_mathint(tail.length) == to_mathint(context.length) - 32 - to_mathint(lenWord),
        "the step consumes exactly 32 + length bytes of the envelope (MultiSendPolicy.sol:86,88)";
}

// R-MS-4: on a non-reverting call `k == batchLength(data)` and `k <= 3`, so every decoded sub-transaction was checked
// exactly once with no extra sub-check; the batch-order half of the row belongs to R_MS_5 (MultiSendPolicy.sol:36-40).
rule R_MS_4(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    uint256 n = batchLength@withrevert(data);
    bool decodes = !lastReverted;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert !lastReverted => decodes,
        "a check that clears implies the whole batch decoded";
    assert !lastReverted => k == to_mathint(n),
        "every decoded sub-transaction was checked exactly once: no early break, no extra sub-check";
    assert !lastReverted => k <= 3,
        "the ledgered batch bound L-MS-2 is a proven consequence of the byte bound, not an assumption";
}

// R-MS-5: for every i < k the sub-check is invoked on the calling engine with (safe, to_i, value_i, data_i, op_i) equal
// to the real decoding of item i, a zero target resolving to the Safe (MultiSendPolicy.sol:37-39,66-73).
rule R_MS_5(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    // The expected items, decoded by the real `_decodeNextTransaction` with `safe == 0`, which makes the :68-70 rewrite
    // the identity, so `rawTo_i` is the raw field and the resolution is asserted below.
    address rawTo0; uint256 val0; bytes sub0; MultiSendPolicyHarness.Operation sop0;
    address rawTo1; uint256 val1; bytes sub1; MultiSendPolicyHarness.Operation sop1;
    address rawTo2; uint256 val2; bytes sub2; MultiSendPolicyHarness.Operation sop2;
    // L-MS-5: `@withrevert` on every walker call, because a `@norevert` call would discard every execution whose batch
    // has fewer than three items; the flags below are asserted, not assumed.
    rawTo0, val0, sub0, sop0 = subTx@withrevert(0, data, 0);
    bool ok0 = !lastReverted;
    rawTo1, val1, sub1, sop1 = subTx@withrevert(0, data, 1);
    bool ok1 = !lastReverted;
    rawTo2, val2, sub2, sop2 = subTx@withrevert(0, data, 2);
    bool ok2 = !lastReverted;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool cleared = !lastReverted;

    assert cleared => k <= 3, "the ledgered batch bound holds (L-MS-2)";
    assert cleared => ((k > 0 => ok0) && (k > 1 => ok1) && (k > 2 => ok2)),
        "the harness walk decodes item i whenever the policy's own loop decoded it (the walker mirrors the loop, L-MS-5)";

    assert cleared && k > 0 =>
        subCallee[0] == e.msg.sender && subSafe[0] == safe,
        "sub-check 0 is driven on the calling engine (msg.sender, never a hard-coded address) for the same Safe";
    assert cleared && k > 0 =>
        subTarget[0] == (rawTo0 == 0 ? safe : rawTo0),
        "sub-check 0 targets item 0's address, with a zero target resolved to the Safe as MultiSend itself resolves it";
    assert cleared && k > 0 =>
        subValue[0] == val0 && subDataHash[0] == keccak256(sub0) && subDataLength[0] == sub0.length && subOperation[0] == sop0,
        "sub-check 0 carries item 0's value, calldata and operation verbatim";

    assert cleared && k > 1 =>
        subCallee[1] == e.msg.sender && subSafe[1] == safe,
        "sub-check 1 is driven on the calling engine for the same Safe";
    assert cleared && k > 1 =>
        subTarget[1] == (rawTo1 == 0 ? safe : rawTo1),
        "sub-check 1 targets item 1's address, with a zero target resolved to the Safe";
    assert cleared && k > 1 =>
        subValue[1] == val1 && subDataHash[1] == keccak256(sub1) && subDataLength[1] == sub1.length && subOperation[1] == sop1,
        "sub-check 1 carries item 1's value, calldata and operation verbatim";

    assert cleared && k > 2 =>
        subCallee[2] == e.msg.sender && subSafe[2] == safe,
        "sub-check 2 is driven on the calling engine for the same Safe";
    assert cleared && k > 2 =>
        subTarget[2] == (rawTo2 == 0 ? safe : rawTo2),
        "sub-check 2 targets item 2's address, with a zero target resolved to the Safe";
    assert cleared && k > 2 =>
        subValue[2] == val2 && subDataHash[2] == keccak256(sub2) && subDataLength[2] == sub2.length && subOperation[2] == sop2,
        "sub-check 2 carries item 2's value, calldata and operation verbatim";
}

// R-MS-6: for every i < k the sub-check receives context item i of the envelope, and once the envelope is exhausted
// every further sub-check receives the empty string, surplus items ignored (MultiSendPolicy.sol:38,78-89).
rule R_MS_6(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    // The expected contexts and the envelope remaining before each position, from the real
    // `_decodeNextContext`, at literal indices only.
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

    // Positional pairing: item i to sub-check i.
    assert cleared && k > 0 =>
        cok0 && subContextHash[0] == keccak256(c0) && subContextLength[0] == c0.length,
        "sub-check 0 receives context item 0 of the envelope";
    assert cleared && k > 1 =>
        cok1 && subContextHash[1] == keccak256(c1) && subContextLength[1] == c1.length,
        "sub-check 1 receives context item 1, not item 0 again";
    assert cleared && k > 2 =>
        cok2 && subContextHash[2] == keccak256(c2) && subContextLength[2] == c2.length,
        "sub-check 2 receives context item 2";

    // Exhaustion: once the envelope has run out the remaining sub-checks get the empty string.
    assert cleared && k > 0 && context.length == 0 =>
        subContextLength[0] == 0,
        "an empty envelope hands every sub-check the empty context (MultiSendPolicy.sol:81-83)";
    assert cleared && k > 1 && tok1 && tail1.length == 0 =>
        subContextLength[1] == 0,
        "an envelope exhausted before position 1 hands sub-check 1 the empty context, not a repeat of item 0";
    assert cleared && k > 2 && tok2 && tail2.length == 0 =>
        subContextLength[2] == 0,
        "an envelope exhausted before position 2 hands sub-check 2 the empty context";
}

// R-MS-7 (denial): if any sub-check the policy reaches denies, the whole batch is denied, because the recursive call
// carries no `try/catch` (MultiSendPolicy.sol:39).
rule R_MS_7_denial(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    uint256 n = batchLength@withrevert(data);
    require !lastReverted;                           // antecedent: the batch decodes, so it has n items
    require j < n;                                   // antecedent: position j is inside the batch
    require !subVerdict[j];                          // antecedent: the sub-check at j denies

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert lastReverted,
        "one denied sub-transaction denies the whole batch: the recursive call is not wrapped in try/catch";
}

// R-MS-7 (magic): the batch clears only if every sub-check it performed accepted, and then it answers with the magic
// value (MultiSendPolicy.sol:39,42).
rule R_MS_7_magic(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert !lastReverted => r == MAGIC(),
        "the only non-reverting answer is IPolicy.checkTransaction.selector";
    assert !lastReverted => (k <= 3 && (k > 0 => subVerdict[0]) && (k > 1 => subVerdict[1]) && (k > 2 => subVerdict[2])),
        "a batch clears only if every sub-check it performed accepted";
}

// R-MS-8: no method of MultiSendPolicy changes its storage, parametric over raw calldata with the batch-walking entry
// points excluded because their loops are unbounded under `calldataarg`; R_MS_8_check re-covers `checkTransaction`
// under L-MS-2 and the other four are `external pure` accessors.
rule R_MS_8(method f, env e, calldataarg args) filtered {
    f -> f.selector != sig:checkTransaction(address,address,uint256,bytes,MultiSendPolicyHarness.Operation,address,bytes,AccessSelector.T).selector
      && f.selector != sig:batchLength(bytes).selector
      && f.selector != sig:subTx(address,bytes,uint256).selector
      && f.selector != sig:ctxItem(bytes,uint256).selector
      && f.selector != sig:ctxTail(bytes,uint256).selector
} {
    storage before = lastStorage;
    f@withrevert(e, args);
    assert lastStorage[currentContract] == before[currentContract],
        "no method of MultiSendPolicy writes its storage";
}

// R-MS-8 for the batch entry point itself, under L-MS-2 and with the free sub-check oracles.
rule R_MS_8_check(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    storage before = lastStorage;
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert lastStorage[currentContract] == before[currentContract],
        "checkTransaction writes no policy storage, whatever the batch and whatever the sub-check verdicts";
}

// W-MS-1 witness (W_MS_1a): a batch of two sub-transactions with two different contexts, both sub-checks
// accepting, clears with the magic value, so R-MS-4 to R-MS-7 are not vacuous and positional context
// pairing really happens.
rule W_MS_1a(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    satisfy !lastReverted && r == MAGIC() && k == 2 && subContextLength[0] != subContextLength[1],
        "a two-item batch with two distinct contexts clears";
}

// W-MS-1 witness (W_MS_1c), the minimal live batch: a one-item batch clears, so the `k > i` guards of R_MS_5 and R_MS_6
// are reachable rather than green for the wrong reason.
rule W_MS_1c(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    satisfy !lastReverted && r == MAGIC() && k == 1,
        "a one-item batch clears after exactly one sub-check";
}

// W-MS-1 witness (W_MS_1b): an empty batch, `multiSend` calldata whose body length is zero, succeeds with `k == 0` and
// returns the magic value, a no-op DELEGATECALL into the trusted MultiSend library rather than a finding.
rule W_MS_1b(
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
    require k == 0;
    require to_mathint(data.length) <= MS_MAX_BYTES();
    require to_mathint(context.length) <= MS_MAX_CTX();

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    satisfy !lastReverted && r == MAGIC() && k == 0,
        "an empty batch clears without checking anything";
}
