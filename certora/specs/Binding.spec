// Binding.spec: the one spec in this suite that hashes for real, rows R-BIND-3 and R-BIND-4 and the verdict-hash and
// attestation binding rules. Every other unit summarizes the Safe transaction hash, so its binding asserts are
// model-internal; here ConsensusMessages and the Safe hash run
// for real, and the rules prove the reconstructed message binds each field it claims to and name the fields it does not
// (B-4, WAIVED-B-1). Conf: Binding. File-wide assumptions: L-BIND-1 (capture-only, never reverting verdicts), L-BIND-2,
// L-BIND-4, L-BIND-5, L-BIND-6, L-BIND-8, L-BIND-9, L-BIND-10, L-BIND-11, L-POL-CTX, WAIVED-B-3.

import "Vocabulary.spec";

using BindingHarness as safeMock;
using CoSignerPolicy as cosigner;
using IncreasedThresholdPolicy as threshold;
using SafenetPolicy as safenet;

// Capture ghosts (L-BIND-1), persistent so they survive the ISafe STATICCALLs the policies make around the verification
// and stay readable on the executions the @withrevert rules end in.

// CoSignerPolicy: SignatureChecker.isValidSignatureNow.
persistent ghost mapping(address => mapping(bytes32 => mapping(bytes => bool))) V;
persistent ghost bool cosCalled;
// No `signer` capture: which signer the verdict was asked about is R-COS-2's claim, not this unit's.
persistent ghost bytes32 cosHash;

function sigVerdict(address signer, bytes32 hash, bytes signature) returns bool {
    cosCalled = true;
    cosHash = hash;
    return V[signer][hash][signature];
}

// IncreasedThresholdPolicy: ISafe.checkNSignatures.
persistent ghost bool nsigCalled;
persistent ghost bytes32 nsigHash;

// `signatures` and `required` are named only because a CVL summary must match the summarized
// signature; they are R-IT-3's and R-IT-4's claims.
function nsigCapture(address executor, bytes32 dataHash, bytes signatures, uint256 required) {
    nsigCalled = true;
    nsigHash = dataHash;
}

// SafenetPolicy and EpochRollover: FROST.verify, the same capture shape as Safenet.spec.
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

// Partial model of Secp256k1.requireNonZero, ported from Safenet.spec: it rejects the zero point exactly as the real
// function does and leaves every other point free, a safety superset no rule here asserts into.
function requireNonZeroModel(Secp256k1.Point p) {
    if (p.x == 0 && p.y == 0) {
        revert();
    }
}

methods {
    // BindingHarness: the parameterized mirrors and the library wrappers. `domainSeparator`, `getTransactionHash` and
    // `domainMirrorAgrees` read chainid(), so they take an env; the rest are
    // pure and envfree.
    function safeMock.domainHashOf(uint256, address) external returns (bytes32) envfree;
    function safeMock.safeTxHashOf(
        bytes32,address,uint256,bytes,BindingHarness.Operation,uint256,uint256,uint256,address,address,uint256
    ) external returns (bytes32) envfree;
    function safeMock.structHashOf(
        address,uint256,bytes,BindingHarness.Operation,uint256,uint256,uint256,address,address,uint256
    ) external returns (bytes32) envfree;
    function safeMock.structHashAlignedOf(
        address,uint256,bytes,BindingHarness.Operation,uint256,uint256,uint256,address,address,uint256
    ) external returns (bytes32) envfree;
    function safeMock.eip712Of(bytes32, bytes32) external returns (bytes32) envfree;
    function safeMock.dataHashOf(bytes) external returns (bytes32) envfree;
    function safeMock.transactionProposalOf(bytes32, uint64, address, bytes32, bytes32) external
        returns (bytes32) envfree;
    function safeMock.epochRolloverOf(bytes32, uint64, uint64, uint64, Secp256k1.Point) external
        returns (bytes32) envfree;
    function safeMock.decodeAttestation(bytes) external
        returns (uint64, address, bytes32, Secp256k1.Point, FROST.Signature) envfree;
    function safeMock.nonce() external returns (uint256) envfree;
    function safeMock.ownerCount() external returns (uint256) envfree;

    // Production views.
    function safenet.getConsensusDomainSeparator() external returns (bytes32) envfree;

    // The three cryptographic verdicts, capture-only (L-BIND-1).
    function SignatureChecker.isValidSignatureNow(address signer, bytes32 hash, bytes memory signature)
        internal returns (bool) => sigVerdict(signer, hash, signature);
    function _.checkNSignatures(address executor, bytes32 dataHash, bytes signatures, uint256 required)
        external => nsigCapture(executor, dataHash, signatures, required) expect void;
    function FROST.verify(Secp256k1.Point memory y, FROST.Signature memory signature, bytes32 message)
        internal => captureVerify(y, signature, message);
    function Secp256k1.requireNonZero(Secp256k1.Point memory p) internal => requireNonZeroModel(p);

    // The Safe environment (L-BIND-2): every one of these is view, hence a STATICCALL.
    function _.nonce() external => DISPATCH [ BindingHarness._ ] default NONDET;
    function _.getTransactionHash(
        address,uint256,bytes,BindingHarness.Operation,uint256,uint256,uint256,address,address,uint256
    ) external => DISPATCH [ BindingHarness._ ] default NONDET;
    function _.getOwners() external => DISPATCH [ BindingHarness._ ] default NONDET;
    function _.getThreshold() external => DISPATCH [ BindingHarness._ ] default NONDET;
}

// The owner-list bound the IncreasedThreshold unit measured (L-IT-4, re-derived as L-BIND-5): the policy is loop-free,
// but solc's ABI coder walks the returned address[], so loop_iter 5 with optimistic_loop false asserts the bound.
// MAX_OWNERS is declared in Vocabulary.spec.

// R-BIND-1 (domain form): domainHashOf(chainId, verifyingContract) at this contract's own domain is exactly the
// verbatim Safe v1.5.0 domainSeparator(), which rejects a wrong typehash literal and a swap of the two inputs. The
// comparison is made inside the harness rather than in CVL so both sides read `chainid()` in one frame.
rule R_BIND_1_domainPin(env e) {
    assert safeMock.domainMirrorAgrees(e),
        "domainHashOf(block.chainid, address(this)) is the verbatim Safe v1.5.0 domain separator";
}

// R-BIND-1 (mirror form): safeTxHashOf(domainSeparator(), ...) is exactly the verbatim Safe v1.5.0
// getTransactionHash(...); under L-BIND-9 both sides pass through the offset-30 step, so it is green but blind
// (WAIVED-B-3).
rule R_BIND_1_mirrorPin(
    env e,
    address to,
    uint256 value,
    bytes data,
    BindingHarness.Operation op,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address refundReceiver,
    uint256 nonce
) {
    bytes32 d = safeMock.domainSeparator(e);
    assert safeMock.safeTxHashOf(d, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce)
        == safeMock.getTransactionHash(e, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce),
        "the parameterized mirror computes exactly the Safe transaction hash the modelled Safe computes";
}

// R-BIND-1 (the discriminating form): the mirror's 352-byte SafeTx pre-image is the EIP-712 one word for word, hashed
// word-aligned from offset 0, the shape the prover does decompose and the L-BIND-9 reproducer beside
// R_BIND_1_mirrorPin.
rule R_BIND_1_structPin(
    address to,
    uint256 value,
    bytes data,
    BindingHarness.Operation op,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address refundReceiver,
    uint256 nonce
) {
    assert safeMock.structHashOf(to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce)
        == safeMock.structHashAlignedOf(to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce),
        "the mirror's assembly builds exactly the EIP-712 SafeTx pre-image, word for word";
}

// R-BIND-1: the EIP-712 SafeTx struct hash is injective in each of the ten transaction fields, which is what makes a
// signature over one transaction unusable for another; data is compared as dataHashOf(data) with its length (L-BIND-4).
rule R_BIND_1(
    address to1, uint256 value1, bytes data1, BindingHarness.Operation op1,
    uint256 safeTxGas1, uint256 baseGas1, uint256 gasPrice1, address gasToken1, address refundReceiver1,
    uint256 nonce1,
    address to2, uint256 value2, bytes data2, BindingHarness.Operation op2,
    uint256 safeTxGas2, uint256 baseGas2, uint256 gasPrice2, address gasToken2, address refundReceiver2,
    uint256 nonce2
) {
    bytes32 s1 = safeMock.structHashOf(
        to1, value1, data1, op1, safeTxGas1, baseGas1, gasPrice1, gasToken1, refundReceiver1, nonce1);
    bytes32 s2 = safeMock.structHashOf(
        to2, value2, data2, op2, safeTxGas2, baseGas2, gasPrice2, gasToken2, refundReceiver2, nonce2);

    assert s1 == s2 => to1 == to2,
        "the SafeTx struct hash binds `to`";
    assert s1 == s2 => value1 == value2,
        "the SafeTx struct hash binds `value`";
    assert s1 == s2 => (safeMock.dataHashOf(data1) == safeMock.dataHashOf(data2) && data1.length == data2.length),
        "the SafeTx struct hash binds keccak(data) and data.length, i.e. `data` under an injective keccak";
    assert s1 == s2 => op1 == op2,
        "the SafeTx struct hash binds `operation`";
    assert s1 == s2 => nonce1 == nonce2,
        "the SafeTx struct hash binds `nonce`";
    assert s1 == s2 => safeTxGas1 == safeTxGas2,
        "the SafeTx struct hash binds `safeTxGas`";
    assert s1 == s2 => baseGas1 == baseGas2,
        "the SafeTx struct hash binds `baseGas`";
    assert s1 == s2 => gasPrice1 == gasPrice2,
        "the SafeTx struct hash binds `gasPrice`";
    assert s1 == s2 => gasToken1 == gasToken2,
        "the SafeTx struct hash binds `gasToken`";
    assert s1 == s2 => refundReceiver1 == refundReceiver2,
        "the SafeTx struct hash binds `refundReceiver`";
}

// R-BIND-1 with an empty data, a regression marker for L-POL-CTX; this conf leaves the defect's discriminator
// `precise_bitwise_ops` unset, which is the sound side for an `assert` (L-POL-CTX), and this is one of only
// two rules a change to the SafeTx pre-image reaches (L-BIND-9).
rule R_BIND_1_emptyData(
    address to1, uint256 value1, bytes data1, BindingHarness.Operation op1,
    uint256 safeTxGas1, uint256 baseGas1, uint256 gasPrice1, address gasToken1, address refundReceiver1,
    uint256 nonce1,
    address to2, uint256 value2, bytes data2, BindingHarness.Operation op2,
    uint256 safeTxGas2, uint256 baseGas2, uint256 gasPrice2, address gasToken2, address refundReceiver2,
    uint256 nonce2
) {
    require data1.length == 0;

    bytes32 s1 = safeMock.structHashOf(
        to1, value1, data1, op1, safeTxGas1, baseGas1, gasPrice1, gasToken1, refundReceiver1, nonce1);
    bytes32 s2 = safeMock.structHashOf(
        to2, value2, data2, op2, safeTxGas2, baseGas2, gasPrice2, gasToken2, refundReceiver2, nonce2);

    assert s1 == s2 => (to1 == to2 && value1 == value2 && op1 == op2 && nonce1 == nonce2),
        "the empty-data case binds `to`, `value`, `operation` and `nonce` too";
    assert s1 == s2 => (safeMock.dataHashOf(data1) == safeMock.dataHashOf(data2) && data1.length == data2.length),
        "an empty `data` is not confusable with any non-empty payload";
    assert s1 == s2 => (safeTxGas1 == safeTxGas2 && baseGas1 == baseGas2 && gasPrice1 == gasPrice2
        && gasToken1 == gasToken2 && refundReceiver1 == refundReceiver2),
        "the empty-data case binds the five gas and refund fields too";
}

// R-BIND-1 (wrapper half): the EIP-712 encode step is injective in (domainSeparator, structHash), which rules out a
// wrapper that drops the domain separator; with R_BIND_1 and R_BIND_1_domain it is the whole field-binding claim,
// modulo WAIVED-B-3.
rule R_BIND_1_eip712(bytes32 domain1, bytes32 struct1, bytes32 domain2, bytes32 struct2) {
    assert safeMock.eip712Of(domain1, struct1) == safeMock.eip712Of(domain2, struct2)
        => (domain1 == domain2 && struct1 == struct2),
        "the EIP-712 message hash binds the domain separator and the struct hash";
}

// R-BIND-1 (domain half): the domain separator is injective in (chainId, verifyingContract), which rules out a domain
// that omits either.
rule R_BIND_1_domain(uint256 chainId1, address verifying1, uint256 chainId2, address verifying2) {
    assert safeMock.domainHashOf(chainId1, verifying1) == safeMock.domainHashOf(chainId2, verifying2)
        => (chainId1 == chainId2 && verifying1 == verifying2),
        "the EIP-712 domain separator binds both the chain id and the verifying Safe";
}

// R-BIND-1 (CoSigner instance): whenever CoSignerPolicy consults the signature verdict, the message is the Safe's own
// hash of (to, value, data, operation) with gas and refund zeroed at nonce() - 1; under L-BIND-9 the assert
// discriminates nothing.
rule R_BIND_1_cosigner(
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

    uint256 n = safeMock.nonce();
    require n >= 1;

    bytes32 d = safeMock.domainSeparator(e);
    bytes32 expected = safeMock.safeTxHashOf(d, to, value, data, op, 0, 0, 0, 0, 0, assert_uint256(n - 1));

    cosigner.checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert cosCalled => cosHash == expected,
        "the co-signature is verified over the Safe transaction hash with the gas and refund fields zeroed at nonce() - 1";
}

// R-BIND-1 (IncreasedThreshold instance): the same claim for the owner-signature check, with context, module and access
// free; under L-BIND-9 the assert discriminates nothing.
rule R_BIND_1_threshold(
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
    require safeMock.ownerCount() <= MAX_OWNERS();

    uint256 n = safeMock.nonce();
    require n >= 1;

    bytes32 d = safeMock.domainSeparator(e);
    bytes32 expected = safeMock.safeTxHashOf(d, to, value, data, op, 0, 0, 0, 0, 0, assert_uint256(n - 1));

    threshold.checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert nsigCalled => nsigHash == expected,
        "the owner signatures are checked over the Safe transaction hash with the gas and refund fields zeroed at nonce() - 1";
}

// R-BIND-1 (the unbound half, B-4, as intended behaviour): the three refund fields the guard leaves unconstrained are
// not bound by the co-signature: the checked message is that transaction's own Safe hash when they are zero, and the
// struct differs otherwise.
rule R_BIND_1_refundUnbound(
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

    uint256 n = safeMock.nonce();
    require n >= 1;

    bytes32 d = safeMock.domainSeparator(e);
    uint256 signedNonce = assert_uint256(n - 1);

    bytes32 executedHash =
        safeMock.safeTxHashOf(d, to, value, data, op, 0, baseGas, 0, gasToken, refundReceiver, signedNonce);
    bytes32 executedStruct =
        safeMock.structHashOf(to, value, data, op, 0, baseGas, 0, gasToken, refundReceiver, signedNonce);
    bytes32 signedStruct = safeMock.structHashOf(to, value, data, op, 0, 0, 0, 0, 0, signedNonce);

    cosigner.checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert (cosCalled && baseGas == 0 && gasToken == 0 && refundReceiver == 0) => cosHash == executedHash,
        "with the three refund fields zero, the verified message is the executed transaction's own Safe hash";
    assert signedStruct == executedStruct <=> (baseGas == 0 && gasToken == 0 && refundReceiver == 0),
        "and only then: a non-zero baseGas, gasToken or refundReceiver is a different SafeTx struct, so the co-signature never approved it (B-4, intended)";
}

// R-BIND-2: on a non-reverting attestation path FROST.verify is called with the decoded key and signature and over
// transactionProposal(consensus domain, decoded epoch, oracle, oracleData hash, Safe tx hash at nonce() - 1); L-BIND-9
// blinds the fourth assert.
rule R_BIND_2(
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

    uint256 n = safeMock.nonce();
    require n >= 1;

    // What the attestation commits to (the decode of `:115-121`, as its own function).
    uint64 epoch;
    address oracle;
    bytes32 oracleDataHash;
    Secp256k1.Point groupKey;
    FROST.Signature signature;
    epoch, oracle, oracleDataHash, groupKey, signature = safeMock.decodeAttestation(context);

    bytes32 d = safeMock.domainSeparator(e);
    bytes32 safeTxHash = safeMock.safeTxHashOf(d, to, value, data, op, 0, 0, 0, 0, 0, assert_uint256(n - 1));
    bytes32 expected = safeMock.transactionProposalOf(
        safenet.getConsensusDomainSeparator(), epoch, oracle, oracleDataHash, safeTxHash);

    // No @withrevert: the claim is about calls that authorize, which W_BIND_2 witnesses. Deliberately proved without
    // the require !frostCalled its siblings carry: a havoced persistent ghost only makes the rule harder (L-BIND-10).
    safenet.checkTransaction(e, safe, to, value, data, op, module, context, access);

    assert frostCalled,
        "an authorizing attestation path consulted the FROST verdict";
    assert frostKeyX == groupKey.x && frostKeyY == groupKey.y,
        "FROST verification uses the group key committed in the attestation, not a caller-chosen one";
    assert frostSigRX == signature.r.x && frostSigRY == signature.r.y && frostSigZ == signature.z,
        "FROST verification uses the signature committed in the attestation";
    assert frostMsg == expected,
        "the verified message is transactionProposal(consensus domain, decoded epoch, oracle, oracleData hash, Safe tx hash at nonce() - 1)";
}

// R-BIND-3: ConsensusMessages.transactionProposal is injective in its five arguments, without which R_BIND_2 would say
// only that the verdict was asked about some function of them and a collision could serve two proposals.
rule R_BIND_3(
    bytes32 domain1, uint64 epoch1, address oracle1, bytes32 oracleDataHash1, bytes32 safeTxHash1,
    bytes32 domain2, uint64 epoch2, address oracle2, bytes32 oracleDataHash2, bytes32 safeTxHash2
) {
    assert safeMock.transactionProposalOf(domain1, epoch1, oracle1, oracleDataHash1, safeTxHash1)
        == safeMock.transactionProposalOf(domain2, epoch2, oracle2, oracleDataHash2, safeTxHash2)
        => (domain1 == domain2 && epoch1 == epoch2 && oracle1 == oracle2
            && oracleDataHash1 == oracleDataHash2 && safeTxHash1 == safeTxHash2),
        "the transaction-proposal message binds the consensus domain, epoch, oracle, oracleData hash and Safe tx hash";
}

// R-BIND-4: in updateEpoch, FROST.verify is called with the caller-supplied parentKey and signature and over
// epochRollover(consensus domain, parentEpoch, proposedEpoch, rolloverBlock, newGroupKey); R-SN-6 states that the
// parent pair is trusted already.
rule R_BIND_4(
    env e,
    Secp256k1.Point parentKey,
    uint64 parentEpoch,
    uint64 proposedEpoch,
    uint64 rolloverBlock,
    Secp256k1.Point newGroupKey,
    FROST.Signature signature
) {
    require !frostCalled;

    bytes32 expected = safeMock.epochRolloverOf(
        safenet.getConsensusDomainSeparator(), parentEpoch, proposedEpoch, rolloverBlock, newGroupKey);

    // No `@withrevert`: the claim is about rollovers that are accepted. `W_BIND_4` witnesses they exist.
    safenet.updateEpoch(e, parentKey, parentEpoch, proposedEpoch, rolloverBlock, newGroupKey, signature);

    assert frostCalled,
        "an accepted rollover consulted the FROST verdict";
    assert frostKeyX == parentKey.x && frostKeyY == parentKey.y,
        "the rollover signature is verified against the parent group key, not the new one";
    assert frostSigRX == signature.r.x && frostSigRY == signature.r.y && frostSigZ == signature.z,
        "the rollover verifies the caller-supplied signature";
    assert frostMsg == expected,
        "the verified message is epochRollover(consensus domain, parentEpoch, proposedEpoch, rolloverBlock, newGroupKey)";
}

// Non-vacuity witnesses: the rules above are capCalled implications or non-@withrevert claims about authorizing paths,
// and rule_not_vacuous checks the rule rather than the antecedent, so these satisfy rules show the antecedents are
// reachable; each repeats its parent's requires (L-BIND-2, L-BIND-5, L-BIND-10, L-BIND-11).

// R-BIND-1 witness (W_BIND_1a): a CoSignerPolicy check that reaches the signature verdict and returns, the antecedent
// of R_BIND_1_cosigner and R_BIND_1_refundUnbound.
rule W_BIND_1a(
    env e, address safe, address to, uint256 value, bytes data, BindingHarness.Operation op,
    address module, bytes context, AccessSelector.T access
) {
    require safe == safeMock;
    require !cosCalled;
    require safeMock.nonce() >= 1;
    cosigner.checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy cosCalled;
}

// R-BIND-1 witness (W_BIND_1b): an IncreasedThresholdPolicy check that reaches the Safe's signature check, the
// antecedent of R_BIND_1_threshold.
rule W_BIND_1b(
    env e, address safe, address to, uint256 value, bytes data, BindingHarness.Operation op,
    address module, bytes context, AccessSelector.T access
) {
    require safe == safeMock;
    require !nsigCalled;
    require safeMock.ownerCount() <= MAX_OWNERS();
    require safeMock.nonce() >= 1;
    threshold.checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy nsigCalled;
}

// R-BIND-2 witness (W_BIND_2): the non-reverting attestation path R_BIND_2 quantifies over is reachable, reaching
// FROST.verify and returning.
rule W_BIND_2(
    env e, address safe, address to, uint256 value, bytes data, BindingHarness.Operation op,
    address module, bytes context, AccessSelector.T access
) {
    require safe == safeMock;
    require !frostCalled;
    require safeMock.nonce() >= 1;
    safenet.checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy frostCalled;
}

// R-BIND-4 witness (W_BIND_4): an `updateEpoch` that reaches `FROST.verify`, the antecedent of `R_BIND_4`.
rule W_BIND_4(
    env e, Secp256k1.Point parentKey, uint64 parentEpoch, uint64 proposedEpoch, uint64 rolloverBlock,
    Secp256k1.Point newGroupKey, FROST.Signature signature
) {
    require !frostCalled;
    safenet.updateEpoch(e, parentKey, parentEpoch, proposedEpoch, rolloverBlock, newGroupKey, signature);
    satisfy frostCalled;
}
