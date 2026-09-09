// IncreasedThresholdOpenSafe.spec: the IncreasedThreshold rows quantified over an arbitrary Safe, namely R-IT-6's
// parametric guard-dimension frame, the fail-closed half of R-IT-3, and the raw-calldata companions of R-IT-1 and
// R-IT-2; IncreasedThreshold.spec carries the other 13 rules. These three cannot run under that spec's DISPATCH for
// getOwners, whose default branch returns an unbounded symbolic array, so ownersModel answers it here. Conf:
// IncreasedThresholdOpenSafe. File-wide: L-IT-1, L-IT-4, L-IT-5, L-IT-6, L-IT-7, L-IT-9, L-IT-11, WAIVED-H-4.

import "Vocabulary.spec";

// No `using` alias: no rule here names the Safe in scene, its owner count or its threshold. Safe v1.5.0 through
// RealSafeHarness is the DISPATCH target below, as in the companion spec.

// Persistent: these ghosts must survive the summarized external call and stay readable on a reverting execution.
persistent ghost mapping(bytes32 => mapping(bytes => mapping(uint256 => bool))) NV;

// The capture set is identical to IncreasedThreshold.spec's; capExec, capSigsHash and capSigsLen are written here but
// read only there.
persistent ghost bool capCalled;
persistent ghost address capExec;
persistent ghost bytes32 capHash;
persistent ghost bytes32 capSigsHash;
persistent ghost uint256 capSigsLen;
persistent ghost uint256 capReq;

// Model of an unknown Safe's ISafe.getOwners() (L-IT-9): every production read of the returned array is .length, so a
// free array of free length loses nothing observable, and Safe v1.5.0's own getOwners() returns exactly ownerCount()
// entries by construction, walking the owner list it allocates for. The free length is bounded per rule.
persistent ghost uint256 modelOwners;

function ownersModel() returns address[] {
    address[] owners;
    require owners.length == modelOwners;
    return owners;
}

// Reverting verdict summary of ISafe.checkNSignatures, kept identical to the companion spec's; the captures run first.
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
    // The summarized signature verdict: wildcard, so it holds for every `safe`, the Safe in scene included.
    function _.checkNSignatures(address executor, bytes32 dataHash, bytes signatures, uint256 required) external
        => nsigModel(executor, dataHash, signatures, required) expect void;

    // Three of the four remaining ISafe calls, all view and so STATICCALLs: Safe v1.5.0's own code when `safe` is that
    // Safe, a havoced return with no state effect otherwise (L-IT-5).
    function _.nonce() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
    function _.getThreshold() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
    function _.getTransactionHash(
        address,uint256,bytes,IncreasedThresholdPolicy.Operation,uint256,uint256,uint256,address,address,uint256
    ) external => DISPATCH [ RealSafeHarness._ ] default NONDET;

    // The unknown Safe's owner list: the bounded model above, applied to every callee.
    function _.getOwners() external => ownersModel() expect address[];

    // The policy's own view surface (IncreasedThresholdPolicy.sol:130-136).
    function getMaxAbsentOwners(address, address, AccessSelector.T) external returns (uint256) envfree;
}

// The engine accepts a policy answer iff it equals IPolicy.checkTransaction.selector; the companion spec's R_IT_2
// asserts it against the source literal.
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,IncreasedThresholdPolicy.Operation,address,bytes,AccessSelector.T).selector
);

// Owner-count bound (L-IT-4): all three rules bound the model's free length directly, proving Safes of at most 4 owners
// (nothing here excludes an empty owner list; the 1 <= threshold <= ownerCount half is L-IT-2, which no rule here
// needs); optimistic_loop stays false, so a longer array fails the run instead of being assumed away.
// MAX_OWNERS is declared in Vocabulary.spec.

// The private $spent mapping read by direct storage access (D-007), so no harness getter has to be pinned.
function spentOf(address g, address s, bytes32 h) returns bool {
    return currentContract.$spent[g][s][h];
}

// R-IT-1 and R-IT-2 over raw calldata (L-IT-6): for every byte string the check is non-payable and any
// non-reverting call returns MAGIC, which rules out a payable checkTransaction and any change to the returned
// selector. One rule for both rows: the two claims are the same over `calldataarg`.
rule R_IT_1_anyCalldata(env e, calldataarg args) {
    require modelOwners <= MAX_OWNERS();
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "IncreasedThresholdPolicy.checkTransaction is non-payable for every raw calldata";
    assert !reverted => r == MAGIC(),
        "every non-reverting checkTransaction call, on any calldata, returns the magic value";
}

// R-IT-3 (fail-closed half): a failed or absent signature verification never authorizes, over an arbitrary safe with no
// scene or nonce assumption, since the wildcard summary covers every callee.
rule R_IT_3_failClosed(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    IncreasedThresholdPolicy.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require modelOwners <= MAX_OWNERS();

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert !reverted => capCalled,
        "an absent signature verification never authorizes: every authorizing call reached checkNSignatures";
    assert !reverted => NV[capHash][context][capReq],
        "a failed signature verification never authorizes";
}

// R-IT-6 (guard dimension, parametric over raw calldata): no method changes either mapping outside the caller's own
// namespace and $spent is monotone, the nonce-rewind defence; parametric_contracts keeps f on the subject (L-IT-11).
rule R_IT_6(env e, method f, calldataarg args, address g2, address s2, bytes32 h2, AccessSelector.T a2) {
    require modelOwners <= MAX_OWNERS();
    bool spentBefore = spentOf(g2, s2, h2);
    uint256 maBefore = getMaxAbsentOwners(g2, s2, a2);

    f(e, args);

    assert spentOf(g2, s2, h2) != spentBefore => g2 == e.msg.sender,
        "a spent flag changes only inside the calling guard's own namespace";
    assert spentOf(g2, s2, h2) != spentBefore => (!spentBefore && spentOf(g2, s2, h2)),
        "spent flags are monotone: nothing ever clears one";
    assert getMaxAbsentOwners(g2, s2, a2) != maBefore => g2 == e.msg.sender,
        "the owner-absence tolerance changes only inside the calling guard's own namespace";
}
