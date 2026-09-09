/* AccessSelector packing and the SignatureExtension envelope, proven on the
 * real library code through the pure wrappers of `LibHarness` (verify target) and, for R-LIB-7,
 * through `SafePolicyGuardHarness.decodeContext` over `SafePolicyGuard._decodeContext` (:278-284).
 * `conf/Lib.conf` runs R_LIB_6 and R_LIB_7 at the default encoding. File-wide: L-LIB-1, L-LIB-2, L-LIB-3, L-LIB-4. */

using SafePolicyGuardHarness as guard;

methods {
    function create(address, bytes4, LibHarness.Operation) external returns (AccessSelector.T) envfree;
    function createFallback(LibHarness.Operation) external returns (AccessSelector.T) envfree;
    function getTarget(AccessSelector.T) external returns (address) envfree;
    function getSelector(AccessSelector.T) external returns (bytes4) envfree;
    function getOperation(AccessSelector.T) external returns (LibHarness.Operation) envfree;
    function opCall() external returns (LibHarness.Operation) envfree;
    function opDelegateCall() external returns (LibHarness.Operation) envfree;
    function selUint(bytes4) external returns (uint256) envfree;
    function has(bytes, bytes32) external returns (bool) envfree;
    function payload(bytes, bytes32) external returns (bytes) envfree;
    function payloadLength(bytes, bytes32) external returns (uint256) envfree;
    function tailWord(bytes) external returns (bytes32) envfree;
    function lengthWord(bytes) external returns (uint256) envfree;
    function envelopeByteAt(bytes, uint256) external returns (uint256) envfree;
    function byteAt(bytes, uint256) external returns (uint256) envfree;
    function selectorOf(bytes) external returns (bytes4) envfree;
    function wordAt(bytes, uint256) external returns (uint256) envfree;

    function guard.CONTEXT_TYPE_HASH() external returns (bytes32) envfree;
    function guard.decodeContext(bytes) external returns (bytes) envfree;
}

// Canonical means bits 160..215 and 217..223 are zero, stated arithmetically because CVL bitwise ops are
// over-approximated.
definition canonical(uint256 x) returns bool =
    (x % 2^216) < 2^160 && ((x / 2^216) % 256) <= 1;

// R-LIB-1: the three getters invert `create` for every (to, sel, op), so `create` is injective.
rule R_LIB_1(address to, bytes4 sel, LibHarness.Operation op,
             address to2, bytes4 sel2, LibHarness.Operation op2) {
    AccessSelector.T k = create(to, sel, op);
    assert getTarget(k) == to, "getTarget inverts create";
    assert getSelector(k) == sel, "getSelector inverts create";
    assert getOperation(k) == op, "getOperation inverts create";
    AccessSelector.T k2 = create(to2, sel2, op2);
    assert k == k2 => (to == to2 && sel == sel2 && op == op2), "create is injective";
}

// R-LIB-2: `create(to,sel,op)` is `to + op*2^216 + sel*2^224` and canonical, `createFallback(CALL)` is 0 and
// `createFallback(DELEGATECALL)` is 2^216.
rule R_LIB_2(address to, bytes4 sel, LibHarness.Operation op) {
    uint256 k = assert_uint256(create(to, sel, op));
    // The three components are < 2^160, < 2 and < 2^32, so the sum cannot overflow and the equation fixes the exact bit
    // layout.
    assert k == to_mathint(to) + to_mathint(op) * 2^216 + selUint(sel) * 2^224,
        "packed word == target + op*2^216 + selector*2^224";
    assert canonical(k), "bits 160..215 and 217..223 of a create result are zero";
    assert createFallback(opCall()) == 0, "createFallback(CALL) == 0";
    assert to_mathint(createFallback(opDelegateCall())) == 2^216, "createFallback(DELEGATECALL) == 2^216";
}

// R-LIB-3: createFallback(op) == create(0, 0, op) for both operations. The collision is intended.
rule R_LIB_3() {
    assert createFallback(opCall()) == create(0, to_bytes4(0), opCall()),
        "createFallback(CALL) == create(address(0), bytes4(0), CALL)";
    assert createFallback(opDelegateCall()) == create(0, to_bytes4(0), opDelegateCall()),
        "createFallback(DELEGATECALL) == create(address(0), bytes4(0), DELEGATECALL)";
}

// R-LIB-4: for an arbitrary word the getters never revert and `getOperation` returns CALL or
// DELEGATECALL (the `& 1` at AccessSelector.sol:66).
rule R_LIB_4(uint256 raw) {
    AccessSelector.T x = raw;
    getTarget@withrevert(x);
    assert !lastReverted, "getTarget never reverts";
    getSelector@withrevert(x);
    assert !lastReverted, "getSelector never reverts";
    LibHarness.Operation o = getOperation@withrevert(x);
    assert !lastReverted, "getOperation never reverts";
    assert o == opCall() || o == opDelegateCall(), "getOperation is CALL or DELEGATECALL";
}

// R-LIB-5: recomposing a word through the getters is the identity exactly on canonical words, and is always canonical
// and getter-equivalent.
rule R_LIB_5(uint256 raw) {
    AccessSelector.T x = raw;
    AccessSelector.T y = create(getTarget(x), getSelector(x), getOperation(x));
    assert (y == x) <=> canonical(raw), "recompose is the identity iff bits 160..215 and 217..223 are zero";
    assert canonical(assert_uint256(y)), "the recomposed word is canonical";
    assert getTarget(y) == getTarget(x) && getSelector(y) == getSelector(x)
        && getOperation(y) == getOperation(x), "the recomposed word is getter-equivalent";
}

// W-LIB-1, selector half: (a) a non-canonical word with all getters defined, (b) a DELEGATECALL key with to != 0 and
// sel != 0 that round-trips.
rule W_LIB_1_selector(uint256 raw, address to, bytes4 sel) {
    AccessSelector.T x = raw;
    getTarget@withrevert(x);
    bool ok1 = !lastReverted;
    getSelector@withrevert(x);
    bool ok2 = !lastReverted;
    getOperation@withrevert(x);
    bool ok3 = !lastReverted;
    satisfy ok1 && ok2 && ok3 && !canonical(raw); // (a)
    AccessSelector.T k = create(to, sel, opDelegateCall());
    satisfy to != 0 && sel != to_bytes4(0)
        && getTarget(k) == to && getSelector(k) == sel && getOperation(k) == opDelegateCall(); // (b)
}

// R-LIB-6: `payload(blob, T)` reverts iff the blob is short, wrongly typed or over-long, and
// otherwise returns the designated envelope slice.
rule R_LIB_6(bytes blob, bytes32 th, uint256 off) {
    bool tooShort = blob.length < 64;
    bytes32 tw = tailWord(blob);
    uint256 lw = lengthWord(blob);
    bool malformed = tooShort || tw != th || lw > blob.length - 64;
    bytes p = payload@withrevert(blob, th);
    bool reverted = lastReverted;
    assert reverted <=> malformed,
        "payload reverts iff too short, wrong type hash, or length past the front";
    assert !reverted => p.length == lw, "the returned slice has length lengthWord(blob)";
    uint256 n = payloadLength@withrevert(blob, th);
    assert lastReverted == reverted, "payloadLength reverts exactly when payload does";
    assert !reverted => n == lw, "payloadLength agrees with the slice length";
    // `envelopeByteAt` is computed from `blob.length` and the length word alone, so a slice at any other offset
    // diverges; both readers return 0 past their ends.
    uint256 pb = byteAt(p, off);
    uint256 eb = envelopeByteAt(blob, off);
    assert !reverted => pb == eb, "the returned slice is the envelope payload region, byte for byte";
}

// R-LIB-7: `has` never reverts and holds iff the blob is >= 32 bytes and ends in the type hash; `decodeContext` reverts
// iff the blob claims H but is malformed, else yields the payload or empty.
rule R_LIB_7(bytes blob, bytes32 th, uint256 off) {
    bool h = has@withrevert(blob, th);
    assert !lastReverted, "has never reverts";
    assert h <=> (blob.length >= 32 && tailWord(blob) == th),
        "has holds iff the blob is >= 32 bytes and ends in the type hash";

    bytes32 H = guard.CONTEXT_TYPE_HASH();
    bool hasH = has(blob, H);
    uint256 lw = lengthWord(blob);
    bool malformed = hasH && (blob.length < 64 || lw > blob.length - 64);
    bytes ctx = guard.decodeContext@withrevert(blob);
    bool reverted = lastReverted;
    assert reverted <=> malformed,
        "decodeContext reverts iff the blob claims the context type but is malformed";
    assert !reverted && hasH => ctx.length == lw, "typed and well-formed: context is the payload";
    assert !reverted && !hasH => ctx.length == 0, "no envelope of the context type: context is empty";
    // Content of the typed branch, as in R_LIB_6; length 0 already settles the untyped branch.
    uint256 cb = byteAt(ctx, off);
    uint256 eb = envelopeByteAt(blob, off);
    assert !reverted && hasH => cb == eb,
        "typed and well-formed: the context is the envelope payload region, byte for byte";
}

// W-LIB-1, envelope half: (c) a well-formed envelope decodes to non-empty context, (d) a >= 32-byte blob not ending in
// H yields empty context; run under `precise_bitwise_ops` so no `satisfy` is met by an over-approximation.
rule W_LIB_1_envelope(bytes blobA, bytes blobB) {
    bytes32 H = guard.CONTEXT_TYPE_HASH();
    bytes ctxA = guard.decodeContext@withrevert(blobA);
    bool okA = !lastReverted;
    satisfy okA && has(blobA, H) && ctxA.length > 0; // (c)
    bytes ctxB = guard.decodeContext@withrevert(blobB);
    bool okB = !lastReverted;
    satisfy okB && blobB.length >= 32 && !has(blobB, H) && ctxB.length == 0; // (d)
}

// R-LIB-8: `selectorOf(d)` is `bytes4(d)` at every length, zero-padded past `d.length`, what the two ERC20
// readers compute (ERC20TransferPolicy.sol:93, ERC20ApprovePolicy.sol:96). `PolicyEngine._decodeSelector`
// (PolicyEngine.sol:247-255) agrees at length 0 and at length >= 4 and reverts InvalidSelector in between; the
// claim WAIVED-EC-2 stood in for; L-LIB-2, L-LIB-4.
rule R_LIB_8(bytes d) {
    uint256 sel = selUint(selectorOf(d));
    assert sel == wordAt(d, 0) / 2^224, "selectorOf(d) is the first four bytes of d";
    assert sel / 0x1000000 == byteAt(d, 0), "the leading byte of selectorOf(d) is byte 0 of d";
}
