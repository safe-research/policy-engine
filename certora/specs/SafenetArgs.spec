// SafenetArgs.spec: R-SN-1's verdict-binding half restated one step earlier so the claim discriminates
// (L-SN-15). Under L-BIND-9 the prover models Safe v1.5.0's offset-30 keccak as independent of its inputs,
// so the fifth argument of Safenet.spec's capMsg == m is blind and a policy that zeroes the value passes it;
// here ISafe.getTransactionHash is capture-only and the rule asserts that call's arguments plus that the
// message folds in the Safe's answer. The Safe in scene is Safe v1.5.0 itself, inherited unchanged by
// RealSafeHarness. Conf: SafenetArgs. File-wide: L-SN-1, L-SN-2, L-SN-3, L-SN-4, L-SN-6, L-SN-7, L-SN-8,
// L-SN-9, L-SN-10, L-SN-14, L-SN-15, L-BIND-9, L-POL-CTX. R_SN_1_bindingArgs carries two free CVL `bytes`
// into a call, but the conf leaves `precise_bitwise_ops` unset, which is the sound side for an `assert`
// under L-POL-CTX: the defect drops the pair with exactly one empty buffer only with the flag on. What the
// unset flag costs is the `satisfy` witness W_SN_args, which runs on the coarse default model, unsound for
// `satisfy` (L-SN-10, L-POL-CTX).

using RealSafeHarness as realSafe;

// Capture ghosts for the ISafe.getTransactionHash call, its arguments and its answer; persistent and spec-local
// instrumentation, as in Safenet.spec (L-SN-7).
persistent ghost bool gthCalled;
persistent ghost mathint gthCount;
persistent ghost address gthTo;
persistent ghost uint256 gthValue;
persistent ghost bytes32 gthDataHash;
persistent ghost mathint gthDataLen;
persistent ghost SafenetHarness.Operation gthOp;
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
    SafenetHarness.Operation operation,
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

// The FROST verdict and the two message models, verbatim from Safenet.spec (L-SN-1, L-SN-3).
persistent ghost frostVerdict(uint256, uint256, uint256, uint256, uint256, bytes32) returns bool;

persistent ghost bool frostCalled;
persistent ghost uint256 capKeyX;
persistent ghost uint256 capKeyY;
persistent ghost uint256 capSigRX;
persistent ghost uint256 capSigRY;
persistent ghost uint256 capSigZ;
persistent ghost bytes32 capMsg;

persistent ghost proposalMsg(bytes32, uint64, address, bytes32, bytes32) returns bytes32;
persistent ghost rolloverMsg(bytes32, uint64, uint64, uint64, uint256, uint256) returns bytes32;

function frostVerifyModel(Secp256k1.Point y, FROST.Signature signature, bytes32 message) {
    frostCalled = true;
    capKeyX = y.x;
    capKeyY = y.y;
    capSigRX = signature.r.x;
    capSigRY = signature.r.y;
    capSigZ = signature.z;
    capMsg = message;
    if (!frostVerdict(y.x, y.y, signature.r.x, signature.r.y, signature.z, message)) {
        revert();
    }
}

function requireNonZeroModel(Secp256k1.Point p) {
    if (p.x == 0 && p.y == 0) {
        revert();
    }
}

function rolloverMsgOf(bytes32 ds, uint64 activeEpoch, uint64 proposedEpoch, uint64 rolloverBlock, Secp256k1.Point groupKey)
    returns bytes32
{
    return rolloverMsg(ds, activeEpoch, proposedEpoch, rolloverBlock, groupKey.x, groupKey.y);
}

function proposalMsgOf(bytes32 ds, uint64 epoch, address oracle, bytes32 oracleDataHash, bytes32 safeTxHash)
    returns bytes32
{
    return proposalMsg(ds, epoch, oracle, oracleDataHash, safeTxHash);
}

methods {
    // Production views (SafenetPolicy.sol:203-224).
    function isKnownEpoch(Secp256k1.Point groupKey, uint64 epoch) external returns (bool) envfree;
    function isAttestationSpent(address policyGuard, address safe, uint256 nonce) external returns (bool) envfree;
    function getConsensusDomainSeparator() external returns (bytes32) envfree;

    // The harness's one addition: the attestation decode of `:115-121` as its own function.
    function decodeAttestation(bytes context) external
        returns (uint64, address, bytes32, Secp256k1.Point, FROST.Signature) envfree;

    // Cryptography modelled symbolically, control flow left real (L-SN-1, L-SN-2).
    function FROST.verify(Secp256k1.Point memory y, FROST.Signature memory signature, bytes32 message) internal
        => frostVerifyModel(y, signature, message);
    function Secp256k1.requireNonZero(Secp256k1.Point memory p) internal => requireNonZeroModel(p);

    // EIP-712 message construction (L-SN-3, L-SN-14).
    function ConsensusMessages.domain(uint256 chainId, address verifyingContract) internal returns (bytes32)
        => NONDET;
    function ConsensusMessages.transactionProposal(
        bytes32 domainSeparator,
        uint64 epoch,
        address oracle,
        bytes32 oracleDataHash,
        bytes32 transactionHash
    ) internal returns (bytes32) => proposalMsgOf(domainSeparator, epoch, oracle, oracleDataHash, transactionHash);
    function ConsensusMessages.epochRollover(
        bytes32 domainSeparator,
        uint64 activeEpoch,
        uint64 proposedEpoch,
        uint64 rolloverBlock,
        Secp256k1.Point memory groupKey
    ) internal returns (bytes32) => rolloverMsgOf(domainSeparator, activeEpoch, proposedEpoch, rolloverBlock, groupKey);

    // L-SN-15: the Safe's hash derivation is capture-only, which is the point of this spec.
    function _.getTransactionHash(
        address to, uint256 value, bytes data, SafenetHarness.Operation operation,
        uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
        address refundReceiver, uint256 _nonce
    ) external => captureTxHash(
        to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce
    ) expect bytes32;

    // The rest of the Safe environment (L-SN-4), unchanged from Safenet.spec.
    function _.nonce() external => DISPATCH [ RealSafeHarness._ ] default NONDET;

    function realSafe.nonce() external returns (uint256) envfree;
}

// R-SN-1 (argument form): an authorizing call asked the verdict about the decoded key and signature and about
// transactionProposal(domainSeparator, epoch, oracle, oracleDataHash, H), H the Safe's own answer at nonce() - 1; the
// gthValue conjunct rejects a policy that zeroes the value.
rule R_SN_1_bindingArgs(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;
    require !gthCalled && gthCount == 0;

    uint256 n = realSafe.nonce();
    require n >= 1;

    // What the attestation commits to (the decode of `:115-121`, as its own function).
    uint64 ep;
    address orc;
    bytes32 odh;
    Secp256k1.Point gk;
    FROST.Signature sgn;
    ep, orc, odh, gk, sgn = decodeAttestation(context);

    // No `@withrevert`: the claim is about calls that authorize. W_SN_args witnesses that they exist.
    checkTransaction(e, safe, to, value, data, op, 0, context, access);

    assert frostCalled && gthCalled && gthCount == 1,
        "an authorizing check consulted the FROST verdict after exactly one Safe transaction-hash derivation";
    assert gthTo == to && gthValue == value
        && gthDataHash == keccak256(data) && gthDataLen == to_mathint(data.length)
        && gthOp == op
        && gthSafeTxGas == 0 && gthBaseGas == 0 && gthGasPrice == 0
        && gthGasToken == 0 && gthRefundReceiver == 0
        && gthNonce == assert_uint256(n - 1),
        "the derivation is over (to, value, data, operation) with the five gas/refund fields zeroed, at nonce() - 1";
    assert capKeyX == gk.x && capKeyY == gk.y,
        "the verdict was asked about the group key decoded from the attestation, never a stored or caller-named one";
    assert capSigRX == sgn.r.x && capSigRY == sgn.r.y && capSigZ == sgn.z,
        "the verdict was asked about the signature decoded from the attestation";
    assert capMsg == proposalMsgOf(getConsensusDomainSeparator(), ep, orc, odh, gthRetOf[1]),
        "the verified message is transactionProposal(consensus domain, decoded epoch, oracle, oracleData hash, the Safe's answer)";
}

// R-SN-1 non-vacuity witness (W_SN_args): the authorizing path is reachable in this scene, the same argument
// as Safenet.spec's W_SN_1a.
rule W_SN_args(
    env e, address safe, address to, uint256 value, bytes data, SafenetHarness.Operation op,
    bytes context, AccessSelector.T access
) {
    require safe == realSafe;
    require !frostCalled && !gthCalled && gthCount == 0;
    require realSafe.nonce() >= 1;
    bytes4 r = checkTransaction(e, safe, to, value, data, op, 0, context, access);
    satisfy r == to_bytes4(0xcbd11d55) && frostCalled && gthCalled,
        "an attested transaction authorizes, and does so after deriving the Safe transaction hash";
}
