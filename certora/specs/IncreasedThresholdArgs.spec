// IncreasedThresholdArgs.spec: verdict binding and R-IT-5's hash dimension restated one step earlier so the claims
// discriminate (L-IT-10). Under L-BIND-9 the prover models Safe v1.5.0's offset-30 keccak as independent of its
// inputs, so IncreasedThreshold.spec's capHash == h is blind and a policy that zeroes the value passes it; here
// ISafe.getTransactionHash is capture-only and the rules assert that call's arguments plus that the policy consumed the
// answer. Conf: IncreasedThresholdArgs. File-wide: L-IT-1, L-IT-2, L-IT-3, L-IT-4, L-IT-5, L-IT-7, L-IT-8, L-SAFE-1,
// D-007.

import "Vocabulary.spec";

// Safe v1.5.0 itself, inherited unchanged, is the Safe every rule speaks about, as in IncreasedThreshold.spec.
using RealSafeHarness as realSafe;

// Capture ghosts for the ISafe.getTransactionHash call, its arguments and its answer, persistent for the same reasons
// as IncreasedThreshold.spec's.
persistent ghost bool gthCalled;
persistent ghost mathint gthCount;
persistent ghost address gthTo;
persistent ghost uint256 gthValue;
persistent ghost bytes32 gthDataHash;
persistent ghost mathint gthDataLen;
persistent ghost IncreasedThresholdPolicy.Operation gthOp;
persistent ghost uint256 gthSafeTxGas;
persistent ghost uint256 gthBaseGas;
persistent ghost uint256 gthGasPrice;
persistent ghost address gthGasToken;
persistent ghost address gthRefundReceiver;
persistent ghost uint256 gthNonce;
persistent ghost mapping(mathint => bytes32) gthRetOf;

function captureTxHash(
    address to,
    uint256 value,
    bytes data,
    IncreasedThresholdPolicy.Operation operation,
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

// The Safe's signature verdict, verbatim from IncreasedThreshold.spec (L-IT-1).
persistent ghost mapping(bytes32 => mapping(bytes => mapping(uint256 => bool))) NV;

persistent ghost bool capCalled;
persistent ghost address capExec;
persistent ghost bytes32 capHash;
persistent ghost bytes32 capSigsHash;
persistent ghost uint256 capSigsLen;
persistent ghost uint256 capReq;

function nsigModel(address executor, bytes32 dataHash, bytes signatures, uint256 required) {
    capCalled = true;
    capExec = executor;
    capHash = dataHash;
    capSigsHash = keccak256(signatures);
    capSigsLen = signatures.length;
    capReq = required;
    if (!NV[dataHash][signatures][required]) {
        revert();
    }
}

methods {
    // The summarized signature verdict: wildcard, so it holds for every `safe`.
    function _.checkNSignatures(address executor, bytes32 dataHash, bytes signatures, uint256 required) external
        => nsigModel(executor, dataHash, signatures, required) expect void;

    // L-IT-10: the Safe's hash derivation is capture-only, which is the point of this spec.
    function _.getTransactionHash(
        address to, uint256 value, bytes data, IncreasedThresholdPolicy.Operation operation,
        uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
        address refundReceiver, uint256 _nonce
    ) external => captureTxHash(
        to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce
    ) expect bytes32;

    // The rest of the Safe environment (L-IT-5), unchanged from IncreasedThreshold.spec.
    function _.nonce() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
    function _.getThreshold() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
    function _.getOwners() external => DISPATCH [ RealSafeHarness._ ] default NONDET;

    // Safe v1.5.0 reads, all views; `ownerCount` and the `owners` list are `internal`, so
    // they arrive through the harness.
    function realSafe.nonce() external returns (uint256) envfree;
    function realSafe.getThreshold() external returns (uint256) envfree;
    function realSafe.harnessOwnerCount() external returns (uint256) envfree;
    function realSafe.harnessOwnerAfter(address) external returns (address) envfree;

    // The policy's own view surface.
    function getRequiredSignatures(address, address, AccessSelector.T) external returns (uint256) envfree;
    function getMaxAbsentOwners(address, address, AccessSelector.T) external returns (uint256) envfree;
}

// The pessimistic owner bound (L-IT-4), required by every rule here; same value as IncreasedThreshold.spec. On the real
// Safe it also bounds the linked-list walk of OwnerManager.getOwners(), which loop_iter = 5 unrolls.
// MAX_OWNERS is declared in Vocabulary.spec.

// OwnerManager.SENTINEL_OWNERS (SAFE/base/OwnerManager.sol:17): `owners[SENTINEL]` is the first
// owner and the last owner points back at it.
// SENTINEL is declared in Vocabulary.spec.

// The Safe environment the mock used to supply by construction, stated over the real OwnerManager storage
// exactly as IncreasedThreshold.spec states it: `1 <= threshold <= ownerCount <= MAX_OWNERS` (L-IT-2,
// L-IT-4) plus a well-formed owner linked list of exactly `ownerCount` distinct non-zero owners (L-SAFE-1),
// without which `getOwners()` either walks past `loop_iter` or writes past the end of its
// `new address[](ownerCount)` array.
function setUpRealSafe() returns uint256 {
    uint256 oc; address o1; address o2; address o3; address o4;

    require oc == realSafe.harnessOwnerCount();
    require 1 <= oc && oc <= MAX_OWNERS();
    require 1 <= realSafe.getThreshold() && realSafe.getThreshold() <= oc;

    require o1 != 0 && o1 != SENTINEL();
    require realSafe.harnessOwnerAfter(SENTINEL()) == o1;
    require oc == 1 => realSafe.harnessOwnerAfter(o1) == SENTINEL();
    require oc >= 2 => (o2 != 0 && o2 != SENTINEL() && o2 != o1 && realSafe.harnessOwnerAfter(o1) == o2);
    require oc == 2 => realSafe.harnessOwnerAfter(o2) == SENTINEL();
    require oc >= 3 => (o3 != 0 && o3 != SENTINEL() && o3 != o1 && o3 != o2
        && realSafe.harnessOwnerAfter(o2) == o3);
    require oc == 3 => realSafe.harnessOwnerAfter(o3) == SENTINEL();
    require oc == 4 => (o4 != 0 && o4 != SENTINEL() && o4 != o1 && o4 != o2 && o4 != o3
        && realSafe.harnessOwnerAfter(o3) == o4 && realSafe.harnessOwnerAfter(o4) == SENTINEL());

    return oc;
}

// `$spent`, read by direct storage access (D-007), as in IncreasedThreshold.spec: the policy exposes no
// getter for it.
definition spentOf(address g, address s, bytes32 h) returns bool = currentContract.$spent[g][s][h];

// R-IT-3 (argument form): an authorizing call asked the Safe exactly once for the hash of (to, value, data, operation)
// with gas and refund zeroed at nonce() - 1, and checked that answer for executor = address(0), context verbatim and
// the required count.
rule R_IT_3_args(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    IncreasedThresholdPolicy.Operation op,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;
    setUpRealSafe();
    require !gthCalled && gthCount == 0;

    uint256 n = realSafe.nonce();
    require n >= 1;

    uint256 req = getRequiredSignatures(e.msg.sender, safe, access);

    // No `@withrevert`: the claim is about calls that authorize. W_IT_args witnesses that they exist.
    checkTransaction(e, safe, to, value, data, op, 0, context, access);

    assert capCalled && gthCalled && gthCount == 1,
        "an authorizing check reached the Safe's signature verification after exactly one hash derivation";
    assert gthTo == to && gthValue == value
        && gthDataHash == keccak256(data) && gthDataLen == to_mathint(data.length)
        && gthOp == op
        && gthSafeTxGas == 0 && gthBaseGas == 0 && gthGasPrice == 0
        && gthGasToken == 0 && gthRefundReceiver == 0
        && gthNonce == assert_uint256(n - 1),
        "the derivation is over (to, value, data, operation) with the five gas/refund fields zeroed, at nonce() - 1";
    assert capHash == gthRetOf[1],
        "the message the owner signatures are checked over is exactly the hash the Safe answered with";
    assert capExec == 0,
        "the executor passed to checkNSignatures is address(0), never a caller-chosen address";
    assert capSigsHash == keccak256(context) && capSigsLen == context.length,
        "the verified signatures are exactly the caller-supplied context";
    assert capReq == req,
        "the verified count is the clamped required-signature count for this guard, Safe and access";
    assert NV[capHash][context][capReq],
        "an authorizing check had an accepting signature verdict";
}

// R-IT-3 (spend-key argument form), the dimension R-IT-5 hands over: an authorizing check marks the spent flag of its
// own guard and Safe at exactly the hash the Safe answered, and touches no other slot; the key is that captured answer,
// not a recomputed hash (L-BIND-9).
rule R_IT_5_argsSpendKey(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    IncreasedThresholdPolicy.Operation op,
    bytes context,
    AccessSelector.T access,
    address g2,
    address s2,
    bytes32 h2
) {
    require safe == realSafe;
    setUpRealSafe();
    require !gthCalled && gthCount == 0;

    uint256 n = realSafe.nonce();
    require n >= 1;

    bool otherBefore = spentOf(g2, s2, h2);

    checkTransaction(e, safe, to, value, data, op, 0, context, access);

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

// Non-vacuity witness (W_IT_args) for R-IT-3 and R-IT-5 in argument form: the authorizing path both rules
// quantify over is reachable.
rule W_IT_args(
    env e, address safe, address to, uint256 value, bytes data,
    IncreasedThresholdPolicy.Operation op, bytes context, AccessSelector.T access
) {
    require safe == realSafe;
    setUpRealSafe();
    require !capCalled && !gthCalled && gthCount == 0;
    require realSafe.nonce() >= 1;
    bytes4 r = checkTransaction(e, safe, to, value, data, op, 0, context, access);
    satisfy r == to_bytes4(0xcbd11d55) && capCalled && gthCalled && spentOf(e.msg.sender, safe, capHash),
        "an owner-path check with enough owner signatures authorizes, derives the Safe hash and spends it";
}
