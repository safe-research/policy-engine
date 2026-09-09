// CoSignerArgs.spec: R-COS-2 and R-COS-3's hash dimension restated one step earlier so the claims
// discriminate (L-COS-13). Under L-BIND-9 the prover models Safe v1.5.0's offset-30 keccak as independent of
// its inputs, so CoSigner.spec's capHash == h is blind; here ISafe.getTransactionHash is capture-only and the
// rules assert that call's arguments plus that the policy consumed the Safe's answer. Conf: CoSignerArgs, an
// addition to CoSigner.conf, never a replacement. The Safe in scene is Safe v1.5.0 itself, inherited
// unchanged by RealSafeHarness. File-wide: L-COS-1, L-COS-3, L-COS-5, L-COS-6, D-007.

using RealSafeHarness as realSafe;

// Capture ghosts, persistent so they survive the ISafe STATICCALLs and stay readable across a summarized call;
// gthDataHash is a CVL-side keccak, used on both sides of every assert.
persistent ghost bool gthCalled;
persistent ghost mathint gthCount;
persistent ghost address gthTo;
persistent ghost uint256 gthValue;
persistent ghost bytes32 gthDataHash;
persistent ghost mathint gthDataLen;
persistent ghost CoSignerPolicy.Operation gthOp;
persistent ghost uint256 gthSafeTxGas;
persistent ghost uint256 gthBaseGas;
persistent ghost uint256 gthGasPrice;
persistent ghost address gthGasToken;
persistent ghost address gthRefundReceiver;
persistent ghost uint256 gthNonce;
// The Safe's answer, fresh per call, so a second call cannot be forced to return the first call's value.
persistent ghost mapping(mathint => bytes32) gthRetOf;

function captureTxHash(
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address refundReceiver,
    uint256 _nonce
) returns bytes32 {
    gthCalled = true;
    gthCount = gthCount + 1;
    gthTo = to;
    gthValue = value;
    gthDataHash = keccak256(data);
    gthDataLen = to_mathint(data.length);
    gthOp = operation;
    gthSafeTxGas = safeTxGas;
    gthBaseGas = baseGas;
    gthGasPrice = gasPrice;
    gthGasToken = gasToken;
    gthRefundReceiver = refundReceiver;
    gthNonce = _nonce;
    return gthRetOf[gthCount];
}

// The signature verdict, verbatim from CoSigner.spec (L-COS-1).
persistent ghost mapping(address => mapping(bytes32 => mapping(bytes => bool))) V;
persistent ghost bool capCalled;
persistent ghost address capSigner;
persistent ghost bytes32 capHash;
persistent ghost bytes32 capSigHash;
persistent ghost uint256 capSigLen;
persistent ghost bool capVerdict;

function sigVerdict(address signer, bytes32 hash, bytes signature) returns bool {
    capCalled = true;
    capSigner = signer;
    capHash = hash;
    capSigHash = keccak256(signature);
    capSigLen = signature.length;
    capVerdict = V[signer][hash][signature];
    return capVerdict;
}

methods {
    // The summarized signature verdict (L-COS-1); internal library call site, `:72`.
    function SignatureChecker.isValidSignatureNow(address signer, bytes32 hash, bytes memory signature) internal returns (bool)
        => sigVerdict(signer, hash, signature);

    // L-COS-13: the Safe's hash derivation is capture-only, so no claim below compares two Safe-style hashes.
    function _.getTransactionHash(
        address to, uint256 value, bytes data, CoSignerPolicy.Operation operation,
        uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
        address refundReceiver, uint256 _nonce
    ) external => captureTxHash(
        to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce
    ) expect bytes32;

    // The rest of the Safe environment (L-COS-3), unchanged from CoSigner.spec.
    function _.nonce() external => DISPATCH [ RealSafeHarness._ ] default NONDET;

    function realSafe.nonce() external returns (uint256) envfree;
}

// The two private mappings, read by direct storage access (D-007); $spent's getter is pinned by CoSigner.spec's
// R_COS_4_gettersAgree.
definition cosignerOf(address g, address s, AccessSelector.T a) returns address = currentContract.$cosigners[g][s][a];
definition spentOf(address g, address s, bytes32 h) returns bool = currentContract.$spent[g][s][h];

// R-COS-2 (argument form): an authorizing call asked the Safe exactly once for the transaction hash of (to, value,
// data, operation) with gas and refund zeroed at nonce() - 1, and verified that answer for the configured cosigner with
// context verbatim.
rule R_COS_2_args(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;
    require !gthCalled && gthCount == 0;

    uint256 n = realSafe.nonce();
    require n >= 1;

    address cs = cosignerOf(e.msg.sender, safe, access);

    // No `@withrevert`: the claim is about calls that authorize. W_COS_args witnesses that they exist.
    checkTransaction(e, safe, to, value, data, op, module, context, access);

    assert capCalled && gthCalled && gthCount == 1,
        "an authorizing check consulted the signature verdict after exactly one Safe transaction-hash derivation";
    assert gthTo == to && gthValue == value
        && gthDataHash == keccak256(data) && gthDataLen == to_mathint(data.length)
        && gthOp == op
        && gthSafeTxGas == 0 && gthBaseGas == 0 && gthGasPrice == 0
        && gthGasToken == 0 && gthRefundReceiver == 0
        && gthNonce == assert_uint256(n - 1),
        "the derivation is over (to, value, data, operation) with the five gas/refund fields zeroed, at nonce() - 1";
    assert capHash == gthRetOf[1],
        "the message the co-signature is verified over is exactly the hash the Safe answered with";
    assert capSigner == cs,
        "the verdict was asked about the cosigner configured for this guard, Safe and access selector";
    assert capSigHash == keccak256(context) && capSigLen == context.length,
        "the verified signature is exactly the caller-supplied context";
    assert capVerdict,
        "an authorizing check received an accepting verdict";
}

// R-COS-2 (spend-key argument form), the dimension R-COS-3 hands over: an authorizing check marks the spent flag of its
// own guard and Safe at exactly the hash the Safe answered, and touches no other slot; the key is that captured answer,
// not a recomputed hash (L-BIND-9).
rule R_COS_3_argsSpendKey(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    address g2,
    address s2,
    bytes32 h2
) {
    require safe == realSafe;
    require !gthCalled && gthCount == 0;

    uint256 n = realSafe.nonce();
    require n >= 1;

    bool otherBefore = spentOf(g2, s2, h2);

    checkTransaction(e, safe, to, value, data, op, module, context, access);

    assert gthCalled && gthCount == 1,
        "an authorizing check derived the Safe transaction hash exactly once";
    assert gthTo == to && gthValue == value
        && gthDataHash == keccak256(data) && gthDataLen == to_mathint(data.length)
        && gthOp == op
        && gthSafeTxGas == 0 && gthBaseGas == 0 && gthGasPrice == 0
        && gthGasToken == 0 && gthRefundReceiver == 0
        && gthNonce == assert_uint256(n - 1),
        "the spent key is derived from (to, value, data, operation), gas and refund fields zeroed, at nonce() - 1";
    assert spentOf(e.msg.sender, safe, gthRetOf[1]),
        "the flag spent is the one at the hash the Safe answered with, under this guard's and Safe's key";
    assert (g2 != e.msg.sender || s2 != safe || h2 != gthRetOf[1]) => spentOf(g2, s2, h2) == otherBefore,
        "no other guard's, Safe's or hash's spent flag is touched";
}

// Non-vacuity witness (W_COS_args) for R-COS-2 and R-COS-3 in argument form: the authorizing path both
// quantify over is reachable.
rule W_COS_args(
    env e, address safe, address to, uint256 value, bytes data, CoSignerPolicy.Operation op,
    address module, bytes context, AccessSelector.T access
) {
    require safe == realSafe;
    require !gthCalled && gthCount == 0;
    require realSafe.nonce() >= 1;
    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy r == to_bytes4(0xcbd11d55) && capCalled && gthCalled && spentOf(e.msg.sender, safe, capHash),
        "a co-signed owner transaction authorizes, derives the Safe hash and spends it";
}
