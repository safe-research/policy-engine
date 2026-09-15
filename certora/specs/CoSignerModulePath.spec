// CoSignerModulePath.spec: R-COS-6, that through the guard a module transaction is never authorized by CoSignerPolicy:
// SafePolicyGuard.sol:256 passes _emptyContext() on the module path, so no co-signature reaches the policy (D-006).
// Scene: the guard harness, the real CoSignerPolicy and Safe v1.5.0 itself through RealSafeHarness, entering at
// checkModuleTransaction. Conf: CoSignerModulePath. File-wide assumptions: L-COS-1, L-COS-2 (with ERC-1271 cosigners
// the residual WAIVED-H-3), L-COS-3, L-COS-5, L-COS-6, L-COS-8, L-COS-9, L-COS-10.

import "Vocabulary.spec";

using CoSignerPolicy as coSigner;
using RealSafeHarness as realSafe;

// The signature verdict model, identical to CoSigner.spec's (L-COS-1); a `using` alias is file-scoped,
// so the preamble is repeated. No rule is.

persistent ghost mapping(address => mapping(bytes32 => mapping(bytes => bool))) V;

// Only capCalled and capSigLen are read here; the others keep this summary body identical to CoSigner.spec's.
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
    // The summarized signature verdict (L-COS-1); internal library call site, CoSignerPolicy.sol:72.
    function SignatureChecker.isValidSignatureNow(address signer, bytes32 hash, bytes memory signature) internal returns (bool)
        => sigVerdict(signer, hash, signature);

    // Engine to policy, per-signature DISPATCH (D-009); every rule requires the resolved policy to be CoSignerPolicy,
    // so no claim rests on the default branch.
    function _.checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,address,bytes,AccessSelector.T) external
        => DISPATCH [ CoSignerPolicy._ ] default NONDET;

    // Policy to Safe (CoSignerPolicy.sol:53-65), both view and hence STATICCALLs: Safe v1.5.0's own body when `safe` is
    // that Safe, a havoced return with no state effect otherwise (L-COS-3).
    function _.nonce() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
    function _.getTransactionHash(
        address,uint256,bytes,SafePolicyGuardHarness.Operation,uint256,uint256,uint256,address,address,uint256
    ) external => DISPATCH [ RealSafeHarness._ ] default NONDET;

    // Guard views this spec reads.
    function getPolicy(address, address, bytes, SafePolicyGuardHarness.Operation) external returns (AccessSelector.T, address) envfree;
    function allowedCalls(address, uint256, bytes, SafePolicyGuardHarness.Operation) external returns (bool) envfree;

    // Safe v1.5.0 reads.
    function realSafe.nonce() external returns (uint256) envfree;
}

// `_decodeSelector` reverts `InvalidSelector` for 1-3 bytes of `data` (contracts/core/PolicyEngine.sol:247-255).
// badLen is declared in Vocabulary.spec.

// The engine's sentinels, `private` in PolicyEngine.sol:35,46, read by direct storage access (D-007).
definition checkingSafe() returns address = currentContract.$checkingSafe;
definition checkingModule() returns address = currentContract.$checkingModule;

// The module hook reaches a policy only off the escape hatch and with a decodable selector, `p` being the policy the
// engine then resolves. This is the rule's scope, not an assumption: the excluded branches revert
// or return before PolicyEngine.sol:200, so no co-signature is consulted on them.
function moduleHookReaches(address safe, address to, bytes data, SafePolicyGuardHarness.Operation op, address p) {
    require !badLen(data);
    require !allowedCalls(to, 0, data, op);
    AccessSelector.T a; address resolved;
    a, resolved = getPolicy(safe, to, data, op);
    require resolved == p;
}

// R-COS-6 (unconditional half): for any checkModuleTransaction whose resolved policy is CoSignerPolicy, the signature
// the policy submits to SignatureChecker is empty.
rule R_COS_6(
    env e,
    address to,
    uint256 value,
    bytes data,
    SafePolicyGuardHarness.Operation op,
    address module
) {
    require !capCalled;

    moduleHookReaches(e.msg.sender, to, data, op, coSigner);

    checkModuleTransaction@withrevert(e, to, value, data, op, module);

    assert capCalled => capSigLen == 0,
        "on the module path CoSignerPolicy verifies the empty signature: the guard forwards an empty context";
}

// R-COS-6 (denial half, under the assumed axiom L-COS-2 that no code-less cosigner accepts the empty signature,
// countersigned at SignatureChecker.sol:23-27): the same call reverts, with ERC-1271 the residual WAIVED-H-3.
rule R_COS_6_denies(
    env e,
    address to,
    uint256 value,
    bytes data,
    SafePolicyGuardHarness.Operation op,
    address module,
    bytes emptySig
) {
    require emptySig.length == 0;
    require forall address s. forall bytes32 hh. !V[s][hh][emptySig];

    moduleHookReaches(e.msg.sender, to, data, op, coSigner);

    checkModuleTransaction@withrevert(e, to, value, data, op, module);

    assert lastReverted,
        "a module transaction whose policy is CoSignerPolicy is always denied: the empty co-signature is never valid";
}

// R-COS-6 non-vacuity witness (W_COS_6), for both halves above: the module hook really does reach CoSignerPolicy's
// signature check with an empty signature, which a scene whose DISPATCH never fires could not show.
rule W_COS_6(
    env e,
    address to,
    uint256 value,
    bytes data,
    SafePolicyGuardHarness.Operation op,
    address module
) {
    require checkingSafe() == 0 && checkingModule() == 0;
    require e.msg.sender == realSafe;
    require realSafe.nonce() >= 1;
    moduleHookReaches(e.msg.sender, to, data, op, coSigner);

    checkModuleTransaction@withrevert(e, to, value, data, op, module);

    satisfy capCalled && capSigLen == 0,
        "the module hook reaches CoSignerPolicy's signature check, with an empty signature";
}
