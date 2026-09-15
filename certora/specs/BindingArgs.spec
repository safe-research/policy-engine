// BindingArgs.spec: the Binding unit's per-policy claims restated one step earlier so they discriminate. Binding.spec's
// R_BIND_1_cosigner, R_BIND_1_threshold, R_BIND_1_refundUnbound and R_BIND_2 compare two values that have each passed
// through Safe v1.5.0's offset-30 keccak, which the prover proves equal even when they differ (L-BIND-9); here
// ISafe.getTransactionHash is capture-only and the rules assert that call's arguments plus that the verdict received
// the answer. Conf: BindingArgs. File-wide: L-BIND-1, L-BIND-2, L-BIND-5, L-BIND-9, L-BIND-10, L-BIND-11,
// L-BIND-12, WAIVED-B-3.

import "Vocabulary.spec";

using BindingHarness as safeMock;
using CoSignerPolicy as cosigner;
using IncreasedThresholdPolicy as threshold;
using SafenetPolicy as safenet;

// Capture ghosts, persistent as in Binding.spec: they survive the ISafe STATICCALLs and stay readable on the executions
// the @withrevert rules end in.

// The ISafe.getTransactionHash call the policy makes: its arguments, and its answer.
persistent ghost bool gthCalled;
persistent ghost mathint gthCount;
persistent ghost address gthTo;
persistent ghost uint256 gthValue;
persistent ghost bytes32 gthDataHash;
persistent ghost mathint gthDataLen;
persistent ghost BindingHarness.Operation gthOp;
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
    BindingHarness.Operation operation,
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

// CoSignerPolicy: SignatureChecker.isValidSignatureNow, verbatim from Binding.spec.
persistent ghost mapping(address => mapping(bytes32 => mapping(bytes => bool))) V;
persistent ghost bool cosCalled;
persistent ghost bytes32 cosHash;

function sigVerdict(address signer, bytes32 hash, bytes signature) returns bool {
    cosCalled = true;
    cosHash = hash;
    return V[signer][hash][signature];
}

// IncreasedThresholdPolicy: ISafe.checkNSignatures, verbatim from Binding.spec.
persistent ghost bool nsigCalled;
persistent ghost bytes32 nsigHash;

function nsigCapture(address executor, bytes32 dataHash, bytes signatures, uint256 required) {
    nsigCalled = true;
    nsigHash = dataHash;
}

// SafenetPolicy: FROST.verify, verbatim from Binding.spec.
persistent ghost bool frostCalled;
persistent ghost uint256 frostKeyX;
persistent ghost uint256 frostKeyY;
persistent ghost uint256 frostSigRX;
persistent ghost uint256 frostSigRY;
persistent ghost uint256 frostSigZ;
persistent ghost bytes32 frostMsg;

function captureVerify(Secp256k1.Point y, FROST.Signature signature, bytes32 message) {
    frostCalled = true;
    frostKeyX = y.x;
    frostKeyY = y.y;
    frostSigRX = signature.r.x;
    frostSigRY = signature.r.y;
    frostSigZ = signature.z;
    frostMsg = message;
}

// Partial model of Secp256k1.requireNonZero (L-BIND-1), verbatim from Binding.spec.
function requireNonZeroModel(Secp256k1.Point p) {
    if (p.x == 0 && p.y == 0) {
        revert();
    }
}

methods {
    function safeMock.transactionProposalOf(bytes32, uint64, address, bytes32, bytes32) external
        returns (bytes32) envfree;
    function safeMock.decodeAttestation(bytes) external
        returns (uint64, address, bytes32, Secp256k1.Point, FROST.Signature) envfree;
    function safeMock.nonce() external returns (uint256) envfree;
    function safeMock.ownerCount() external returns (uint256) envfree;

    function safenet.getConsensusDomainSeparator() external returns (bytes32) envfree;

    // The three cryptographic verdicts, capture-only (L-BIND-1).
    function SignatureChecker.isValidSignatureNow(address signer, bytes32 hash, bytes memory signature)
        internal returns (bool) => sigVerdict(signer, hash, signature);
    function _.checkNSignatures(address executor, bytes32 dataHash, bytes signatures, uint256 required)
        external => nsigCapture(executor, dataHash, signatures, required) expect void;
    function FROST.verify(Secp256k1.Point memory y, FROST.Signature memory signature, bytes32 message)
        internal => captureVerify(y, signature, message);
    function Secp256k1.requireNonZero(Secp256k1.Point memory p) internal => requireNonZeroModel(p);

    // The Safe's hash derivation is capture-only too (L-BIND-12): every claim below is about the arguments of the call,
    // never about two Safe-style hash values.
    function _.getTransactionHash(
        address to, uint256 value, bytes data, BindingHarness.Operation operation,
        uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
        address refundReceiver, uint256 _nonce
    ) external => captureTxHash(
        to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce
    ) expect bytes32;

    // The rest of the Safe environment (L-BIND-2).
    function _.nonce() external => DISPATCH [ BindingHarness._ ] default NONDET;
    function _.getOwners() external => DISPATCH [ BindingHarness._ ] default NONDET;
    function _.getThreshold() external => DISPATCH [ BindingHarness._ ] default NONDET;
}

// MAX_OWNERS is declared in Vocabulary.spec; the owner-list bound as in Binding.spec.

// R-BIND-1 (CoSigner instance): whenever CoSignerPolicy consults the signature verdict, the Safe was asked exactly once
// for the hash of (to, value, data, operation) with gas and refund zeroed at nonce() - 1, and the verdict's message is
// that answer.
rule R_BINDA_1_cosigner(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    BindingHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require safe == safeMock;
    require !cosCalled;
    require !gthCalled && gthCount == 0;

    uint256 n = safeMock.nonce();
    require n >= 1;

    cosigner.checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert cosCalled => (gthCalled && gthCount == 1),
        "the co-signature verdict is preceded by exactly one Safe transaction-hash derivation";
    assert cosCalled => (
        gthTo == to && gthValue == value
        && gthDataHash == keccak256(data) && gthDataLen == to_mathint(data.length)
        && gthOp == op
        && gthSafeTxGas == 0 && gthBaseGas == 0 && gthGasPrice == 0
        && gthGasToken == 0 && gthRefundReceiver == 0
        && gthNonce == assert_uint256(n - 1)
    ),
        "the derivation is over (to, value, data, operation) with the five gas/refund fields zeroed, at nonce() - 1";
    assert cosCalled => cosHash == gthRetOf[1],
        "and the message the co-signature is verified over is exactly the hash the Safe answered with";
}

// R-BIND-1 (IncreasedThreshold instance): the same three claims for the owner-signature check, with context, module and
// access free, discriminating the same four cases, checkNSignatures on a hash taken from context included.
rule R_BINDA_1_threshold(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    BindingHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require safe == safeMock;
    require !nsigCalled;
    require !gthCalled && gthCount == 0;
    require safeMock.ownerCount() <= MAX_OWNERS();

    uint256 n = safeMock.nonce();
    require n >= 1;

    threshold.checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert nsigCalled => (gthCalled && gthCount == 1),
        "the owner-signature check is preceded by exactly one Safe transaction-hash derivation";
    assert nsigCalled => (
        gthTo == to && gthValue == value
        && gthDataHash == keccak256(data) && gthDataLen == to_mathint(data.length)
        && gthOp == op
        && gthSafeTxGas == 0 && gthBaseGas == 0 && gthGasPrice == 0
        && gthGasToken == 0 && gthRefundReceiver == 0
        && gthNonce == assert_uint256(n - 1)
    ),
        "the derivation is over (to, value, data, operation) with the five gas/refund fields zeroed, at nonce() - 1";
    assert nsigCalled => nsigHash == gthRetOf[1],
        "and the message the owner signatures are checked over is exactly the hash the Safe answered with";
}

// R-BIND-1 (B-4, positively and discriminating): baseGas, gasToken and refundReceiver of the executed transaction reach
// the policy through no argument at all, so the derivation the co-signature is checked against carries literal zeros
// there.
rule R_BINDA_1_refundUnbound(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    BindingHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    uint256 baseGas,
    address gasToken,
    address refundReceiver
) {
    require safe == safeMock;
    require !cosCalled;
    require !gthCalled && gthCount == 0;

    uint256 n = safeMock.nonce();
    require n >= 1;

    cosigner.checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert cosCalled => (
        gthBaseGas == 0 && gthGasToken == 0 && gthRefundReceiver == 0
        && gthNonce == assert_uint256(n - 1)
        && cosHash == gthRetOf[1]
    ),
        "the executed transaction's baseGas, gasToken and refundReceiver reach the derivation as zeros, whatever they are";
}

// R-BIND-2: on a non-reverting attestation path FROST.verify is called with the decoded key and signature and over
// transactionProposal(consensus domain, decoded epoch, oracle, oracleData hash, the Safe's answer at nonce() - 1 with
// gas and refund zeroed).
rule R_BINDA_2(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    BindingHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require safe == safeMock;
    require !gthCalled && gthCount == 0;

    uint256 n = safeMock.nonce();
    require n >= 1;

    // What the attestation commits to (the decode of `:115-121`, as its own function).
    uint64 epoch;
    address oracle;
    bytes32 oracleDataHash;
    Secp256k1.Point groupKey;
    FROST.Signature signature;
    epoch, oracle, oracleDataHash, groupKey, signature = safeMock.decodeAttestation(context);

    // No `@withrevert`: the claim is about calls that authorize. `W_BINDA_2` witnesses that they exist.
    safenet.checkTransaction(e, safe, to, value, data, op, module, context, access);

    assert frostCalled && gthCalled && gthCount == 1,
        "an authorizing attestation path consulted the FROST verdict after exactly one hash derivation";
    assert gthTo == to && gthValue == value
        && gthDataHash == keccak256(data) && gthDataLen == to_mathint(data.length)
        && gthOp == op
        && gthSafeTxGas == 0 && gthBaseGas == 0 && gthGasPrice == 0
        && gthGasToken == 0 && gthRefundReceiver == 0
        && gthNonce == assert_uint256(n - 1),
        "the Safe hash it commits to is the one of this transaction, gas and refund fields zeroed, at nonce() - 1";
    assert frostKeyX == groupKey.x && frostKeyY == groupKey.y,
        "FROST verification uses the group key committed in the attestation, not a caller-chosen one";
    assert frostSigRX == signature.r.x && frostSigRY == signature.r.y && frostSigZ == signature.z,
        "FROST verification uses the signature committed in the attestation";
    assert frostMsg == safeMock.transactionProposalOf(
            safenet.getConsensusDomainSeparator(), epoch, oracle, oracleDataHash, gthRetOf[1]),
        "the verified message is transactionProposal(consensus domain, decoded epoch, oracle, oracleData hash, the Safe's answer)";
}

// Non-vacuity witnesses: the capCalled antecedents are reachable in this scene, rule_not_vacuous checking the rule
// rather than the antecedent; a satisfy is existential, so repeating the parent rules' requires costs nothing.

// R-BIND-1 witness (W_BINDA_1a): R_BINDA_1_cosigner's cosCalled antecedent is reachable in this scene.
rule W_BINDA_1a(
    env e, address safe, address to, uint256 value, bytes data, BindingHarness.Operation op,
    address module, bytes context, AccessSelector.T access
) {
    require safe == safeMock;
    require !cosCalled && !gthCalled && gthCount == 0;
    require safeMock.nonce() >= 1;
    cosigner.checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy cosCalled;
}

// R-BIND-1 witness (W_BINDA_1b): R_BINDA_1_threshold's nsigCalled antecedent is reachable in this scene.
rule W_BINDA_1b(
    env e, address safe, address to, uint256 value, bytes data, BindingHarness.Operation op,
    address module, bytes context, AccessSelector.T access
) {
    require safe == safeMock;
    require !nsigCalled && !gthCalled && gthCount == 0;
    require safeMock.ownerCount() <= MAX_OWNERS();
    require safeMock.nonce() >= 1;
    threshold.checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy nsigCalled;
}

// R-BIND-2 witness (W_BINDA_2): the non-reverting attestation path R_BINDA_2 quantifies over is reachable.
rule W_BINDA_2(
    env e, address safe, address to, uint256 value, bytes data, BindingHarness.Operation op,
    address module, bytes context, AccessSelector.T access
) {
    require safe == safeMock;
    require !frostCalled && !gthCalled && gthCount == 0;
    require safeMock.nonce() >= 1;
    safenet.checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy frostCalled;
}
