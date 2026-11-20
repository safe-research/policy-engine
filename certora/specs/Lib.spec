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

