// IncreasedThreshold.spec: IncreasedThresholdPolicy, stated about the Safe in scene: rows R-IT-4, R-IT-5, R-IT-7 and
// W-IT-1, the module-path, revert-characterisation and verdict-binding rules, and the writer-key halves of write
// provenance. The subject is the real policy, with $spent read by direct storage access (D-007); the Safe is
// Safe v1.5.0 itself, inherited unchanged by RealSafeHarness.
// Conf: IncreasedThreshold. File-wide assumptions: L-HASHBLIND (no rule here may rest on comparing two Safe-style
// offset-30 hashes, the L-BIND-9 defect), L-IT-1, L-IT-2, L-IT-3, L-IT-4, L-IT-5, L-IT-6, L-IT-7, L-IT-8, L-IT-10,
// L-SAFE-1, L-BIND-9, WAIVED-H-4.

import "Vocabulary.spec";

using RealSafeHarness as realSafe;
using LibHarness as lib;

// Persistent: these ghosts must survive the summarized external call and stay readable on a reverting execution.
persistent ghost mapping(bytes32 => mapping(bytes => mapping(uint256 => bool))) NV;

persistent ghost bool capCalled;
persistent ghost address capExec;
persistent ghost bytes32 capHash;
persistent ghost bytes32 capSigsHash;
persistent ghost uint256 capSigsLen;
persistent ghost uint256 capReq;

// Reverting verdict summary of ISafe.checkNSignatures, kept identical to the companion spec's; the captures run first,
// so the binding asserts see the arguments even on the rejecting path.
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
    // The summarized signature verdict: wildcard, so it holds for every `safe`, the real Safe included.
    function _.checkNSignatures(address executor, bytes32 dataHash, bytes signatures, uint256 required) external
        => nsigModel(executor, dataHash, signatures, required) expect void;

    // Three of the four remaining ISafe calls, all view and so STATICCALLs: Safe v1.5.0's own code when `safe` is that
    // Safe, a havoced return with no state effect otherwise. `getOwners` is below.
    function _.nonce() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
    function _.getThreshold() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
    function _.getTransactionHash(
        address,uint256,bytes,IncreasedThresholdPolicy.Operation,uint256,uint256,uint256,address,address,uint256
    ) external => DISPATCH [ RealSafeHarness._ ] default NONDET;

    // The policy's own view surface (IncreasedThresholdPolicy.sol:115-136).
    function getRequiredSignatures(address, address, AccessSelector.T) external returns (uint256) envfree;
    function getMaxAbsentOwners(address, address, AccessSelector.T) external returns (uint256) envfree;

    // Safe v1.5.0 reads, all views; `ownerCount` and the `owners` list are `internal`, so
    // they arrive through the harness.
    function realSafe.nonce() external returns (uint256) envfree;
    function realSafe.getThreshold() external returns (uint256) envfree;
    function realSafe.harnessOwnerCount() external returns (uint256) envfree;
    function realSafe.harnessOwnerAfter(address) external returns (address) envfree;

    // LibHarness raw reader: `wordAt` is the 32-byte word of a `bytes` value.
    function lib.wordAt(bytes, uint256) external returns (uint256) envfree;
}
// The Safe environment's owner list, DISPATCHed so Safe v1.5.0's own linked-list walk runs for the Safe every rule
// speaks about; no rule reaches the default branch.
methods {
    function _.getOwners() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
}

// The engine accepts a policy answer iff it equals IPolicy.checkTransaction.selector; R_IT_2 also asserts it against
// the source literal, so a changed policy signature cannot drag the constant along.
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,IncreasedThresholdPolicy.Operation,address,bytes,AccessSelector.T).selector
);

// The required-signature formula transcribed in three steps: saturating subtraction, floor at threshold + 1, ceiling at
// the owner count. R_IT_4 asserts it equal to the shipped getRequiredSignatures.
definition reqRaw(mathint oc, mathint ma) returns mathint = ma >= oc ? 0 : oc - ma;                       // :150
definition reqFloor(mathint oc, mathint th, mathint ma) returns mathint =
    reqRaw(oc, ma) < th + 1 ? th + 1 : reqRaw(oc, ma);                                                    // :151-153
definition reqOf(mathint oc, mathint th, mathint ma) returns mathint =
    reqFloor(oc, th, ma) > oc ? oc : reqFloor(oc, th, ma);                                                // :154-156

// Two access selectors name the same key iff their packed words are equal: CVL models `AccessSelector.T` as its
// underlying `uint256`, so `==` on the type is that comparison.
definition sameKey(AccessSelector.T x, AccessSelector.T y) returns bool = x == y;

// Owner-count bound (L-IT-4) for the eight rules that reach ISafe(safe).getOwners() through setUpRealSafe(); the
// other five hold at every owner count. Safes of 1 to 4 owners, an under-approximation in the owner count alone:
// all three clamps of IncreasedThresholdPolicy.sol:147-157 already fire at three owners. On the real Safe it also
// bounds the linked-list walk of OwnerManager.getOwners(), which loop_iter = 5 unrolls.
// MAX_OWNERS is declared in Vocabulary.spec.

// OwnerManager.SENTINEL_OWNERS (SAFE/base/OwnerManager.sol:17): `owners[SENTINEL]` is the first
// owner and the last owner points back at it.
// SENTINEL is declared in Vocabulary.spec.

// The Safe environment the mock used to supply by construction, stated over the real OwnerManager storage:
// `1 <= threshold <= ownerCount <= MAX_OWNERS` (L-IT-2, L-IT-4) plus a well-formed owner linked list of
// exactly `ownerCount` distinct non-zero owners (L-SAFE-1), without which `getOwners()` either walks past
// `loop_iter` or writes past the end of its `new address[](ownerCount)` array.
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

// The private $spent mapping read by direct storage access (D-007), so no harness getter has to be pinned.
function spentOf(address g, address s, bytes32 h) returns bool {
    return currentContract.$spent[g][s][h];
}

// R-IT-1: every call with module != 0 reverts, and reverts before the Safe's signature check is reached, for any safe,
// context, nonce, verdict or spent state.
rule R_IT_1(
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
    require module != 0;
    require !capCalled;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert lastReverted,
        "IncreasedThresholdPolicy.checkTransaction reverts ModulePathUnsupported on every module-path call";
    assert !capCalled,
        "the module-path call reverts before the Safe's signature check is reached";
}

// R-IT-2: with the Safe set up and its nonce advanced, checkTransaction succeeds iff it is unpaid, module == 0, the
// verdict for (derived hash, context, required) accepts and that hash is unspent, and it then returns MAGIC; nonce == 0
// is R_IT_2_zeroNonce.
rule R_IT_2(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    IncreasedThresholdPolicy.Operation op,
    Enum.Operation opSafe,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;
    setUpRealSafe();

    uint256 n = realSafe.nonce();
    require n >= 1;

    // Safe v1.5.0 takes `Enum.Operation`, this repo declares its own top-level `Operation`: the same
    // uint8 and the same selector, but CVL will not pass a value of one type for the other, so the
    // spec carries both and requires them equal.
    require to_mathint(opSafe) == to_mathint(op);

    uint256 req = getRequiredSignatures(e.msg.sender, safe, access);
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));
    bool accepts = NV[h][context][req];
    bool spentBefore = spentOf(e.msg.sender, safe, h);

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert MAGIC() == to_bytes4(0xcbd11d55),
        "IPolicy.checkTransaction.selector is 0xcbd11d55";
    assert !reverted => (e.msg.value == 0 && module == 0 && accepts && !spentBefore),
        "a checkTransaction that authorizes had zero value, no module, an accepting verdict and an unspent hash";
    assert (e.msg.value == 0 && module == 0 && accepts && !spentBefore) => !reverted,
        "checkTransaction authorizes whenever value is zero, no module, the verdict accepts and the hash is unspent";
    assert !reverted => r == MAGIC(),
        "IncreasedThresholdPolicy.checkTransaction returns the magic value on success";
}

// R-IT-2 at nonce == 0: an un-advanced nonce denies before the signature check because nonce() - 1 panics, so a policy
// that rebuilt the hash at nonce() fails here.
rule R_IT_2_zeroNonce(
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
    require !capCalled;
    require realSafe.nonce() == 0;

    checkTransaction@withrevert(e, safe, to, value, data, op, 0, context, access);

    assert lastReverted,
        "a Safe whose nonce has not been advanced denies: nonce() - 1 panics";
    assert !capCalled,
        "the nonce underflow denies before the Safe's signature check is reached";
}

// R-IT-3: an authorizing call asked the signature check about executor = address(0), the hash with gas and refund
// zeroed at nonce() - 1, context verbatim and the clamped required count; L-BIND-9 leaves the hash unproven here.
rule R_IT_3(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    IncreasedThresholdPolicy.Operation op,
    Enum.Operation opSafe,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;
    setUpRealSafe();

    uint256 n = realSafe.nonce();
    require n >= 1;

    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_IT_2

    uint256 req = getRequiredSignatures(e.msg.sender, safe, access);
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));

    // No `@withrevert`: the claim is about calls that authorize. W_IT_1 witnesses that such calls exist.
    checkTransaction(e, safe, to, value, data, op, 0, context, access);

    assert capCalled,
        "an authorizing check consulted the Safe's signature verification";
    assert capExec == 0,
        "the executor passed to checkNSignatures is address(0), never a caller-chosen address";
    assert capHash == h,
        "the verified hash is the Safe transaction hash with the gas and refund fields zeroed at nonce() - 1";
    assert capSigsHash == keccak256(context) && capSigsLen == context.length,
        "the verified signatures are exactly the caller-supplied context";
    assert capReq == req,
        "the verified count is the clamped required-signature count for this guard, Safe and access";
    assert NV[capHash][context][capReq],
        "an authorizing check had an accepting signature verdict";
}

// R-IT-4: the required count is clamp(ownerCount - maxAbsent, threshold + 1, ownerCount): never zero, never above the
// owner count, above the threshold unless the Safe is N-of-N, and antitone in maxAbsent (finding B-1 asserted).
rule R_IT_4(address g, address safe, AccessSelector.T a1, AccessSelector.T a2) {
    require safe == realSafe;
    uint256 oc = setUpRealSafe();

    uint256 th = realSafe.getThreshold();
    uint256 ma1 = getMaxAbsentOwners(g, safe, a1);
    uint256 ma2 = getMaxAbsentOwners(g, safe, a2);
    uint256 r1 = getRequiredSignatures(g, safe, a1);
    uint256 r2 = getRequiredSignatures(g, safe, a2);

    assert to_mathint(r1) == reqOf(oc, th, ma1),
        "getRequiredSignatures is exactly clamp(owners - maxAbsent, threshold + 1, owners)";
    assert r1 >= 1,
        "the required count is never zero, so the Safe's vacuous zero-signature acceptance is unreachable";
    assert r1 <= oc,
        "the required count never exceeds the owner count, so it is always satisfiable";
    assert th < oc => r1 > th,
        "the required count is strictly above the Safe's own threshold whenever the Safe is not N-of-N";
    assert th == oc => r1 == oc,
        "on an N-of-N Safe the required count equals the threshold: the policy adds nothing (BUGS B-1)";
    assert ma1 == 0 => r1 == oc,
        "an unconfigured access selector reads maxAbsent as 0 and demands every owner";
    assert ma1 <= ma2 => r1 >= r2,
        "the required count is antitone in the configured owner-absence tolerance";
}

// R-IT-4 (saturation half): a maxAbsent at or above the owner count saturates to the floor instead of panicking; its
// own rule because only an explicit did-not-revert assert makes the deleted branch observable.
rule R_IT_4_saturates(address g, address safe, AccessSelector.T access) {
    require safe == realSafe;
    uint256 oc = setUpRealSafe();

    uint256 th = realSafe.getThreshold();
    require getMaxAbsentOwners(g, safe, access) >= oc;

    uint256 r = getRequiredSignatures@withrevert(g, safe, access);

    assert !lastReverted,
        "an over-large maxAbsent saturates instead of reverting: the access selector stays usable";
    assert to_mathint(r) == (th + 1 > to_mathint(oc) ? to_mathint(oc) : th + 1),
        "a saturated maxAbsent falls back to the floor threshold + 1, clamped to the owner count";
}

// R-IT-5: an authorizing check marks exactly $spent[msg.sender][safe][derived hash] and nothing else, and an identical
// repeat reverts; L-BIND-9 leaves the nonce dimension unproven here.
rule R_IT_5(
    env e,
    env e2,
    address safe,
    address to,
    uint256 value,
    bytes data,
    IncreasedThresholdPolicy.Operation op,
    Enum.Operation opSafe,
    bytes context,
    AccessSelector.T access,
    address g2,
    address s2,
    bytes32 h2,
    AccessSelector.T a2
) {
    require safe == realSafe;
    setUpRealSafe();

    uint256 n = realSafe.nonce();
    require n >= 1;
    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_IT_2
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));

    bool spentBefore = spentOf(e.msg.sender, safe, h);
    bool otherBefore = spentOf(g2, s2, h2);
    uint256 maBefore = getMaxAbsentOwners(g2, s2, a2);

    checkTransaction(e, safe, to, value, data, op, 0, context, access);

    assert !spentBefore && spentOf(e.msg.sender, safe, h),
        "an authorizing check spends exactly the hash it verified, and it was unspent before";
    assert (g2 != e.msg.sender || s2 != safe || h2 != h) => spentOf(g2, s2, h2) == otherBefore,
        "no other guard's, Safe's or hash's spent flag is touched";
    assert getMaxAbsentOwners(g2, s2, a2) == maBefore,
        "the check path never writes the configured owner-absence tolerance";

    require e2.msg.sender == e.msg.sender;
    checkTransaction@withrevert(e2, safe, to, value, data, op, 0, context, access);
    assert lastReverted,
        "the same signatures cannot authorize the same transaction twice: SignaturesAlreadySpent";
}

// R-IT-6 (writer key, check path): the only $spent slot checkTransaction may change is [msg.sender][safe][derived
// hash]; the typed-argument half (L-IT-6).
rule R_IT_6_checkKeys(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    IncreasedThresholdPolicy.Operation op,
    Enum.Operation opSafe,
    address module,
    bytes context,
    AccessSelector.T access,
    address g2,
    address s2,
    bytes32 h2
) {
    require safe == realSafe;
    setUpRealSafe();

    uint256 n = realSafe.nonce();
    require n >= 1;
    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_IT_2
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));

    bool otherBefore = spentOf(g2, s2, h2);

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert spentOf(g2, s2, h2) != otherBefore => (g2 == e.msg.sender && s2 == safe && h2 == h),
        "checkTransaction writes only the spent flag of its own guard, Safe and derived hash";
}

// R-IT-6 (writer key, configure path): the only $maxAbsent slot configure may change is [msg.sender][safe][access],
// taking the first word of data (L-IT-6).
rule R_IT_6_configureKeys(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address g2,
    address s2,
    AccessSelector.T a2
) {
    uint256 otherBefore = getMaxAbsentOwners(g2, s2, a2);

    configure@withrevert(e, safe, access, data);

    assert getMaxAbsentOwners(g2, s2, a2) != otherBefore
        => (g2 == e.msg.sender && s2 == safe && sameKey(a2, access)),
        "configure writes only the tolerance of its own guard, Safe and access selector";
}

// R-IT-7: configure(safe, access, data) reverts iff it is paid or data is shorter than 32 bytes, and otherwise returns
// true and stores the first word verbatim, with every uint256 accepted and safe and access never validated.
rule R_IT_7(env e, address safe, AccessSelector.T access, bytes data) {
    uint256 w = lib.wordAt(data, 0);

    bool ok = configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;

    assert reverted => (e.msg.value != 0 || data.length < 32),
        "configure reverts only on a payable call or a data payload shorter than one word";
    assert (e.msg.value != 0 || data.length < 32) => reverted,
        "configure reverts on every payable call and on every data payload shorter than one word";
    assert !reverted => ok,
        "configure returns true whenever it succeeds";
    assert !reverted => getMaxAbsentOwners(e.msg.sender, safe, access) == w,
        "configure stores the first word of data as the owner-absence tolerance, unvalidated";
}

// R-IT-7 over raw calldata (L-IT-6): non-payability, and configure never returns false, for every byte string.
rule R_IT_7_anyCalldata(env e, calldataarg args) {
    bool ok = configure@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "IncreasedThresholdPolicy.configure is non-payable for every raw calldata";
    assert !reverted => ok,
        "on any calldata, a non-reverting configure returns true";
}

// W-IT-1: an owner-path check with an advanced nonce, an accepting verdict for the clamped required count and an
// unspent hash returns MAGIC and marks the hash spent, the non-vacuity evidence for R_IT_2, R_IT_3 and R_IT_5.
rule W_IT_1(
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
    require !capCalled;
    require realSafe.nonce() >= 1;

    bytes4 r = checkTransaction(e, safe, to, value, data, op, 0, context, access);

    satisfy r == MAGIC() && capCalled && capExec == 0 && spentOf(e.msg.sender, safe, capHash),
        "an owner-path check with enough owner signatures authorizes and spends the hash";
}

// W-IT-1 witness (W_IT_1b): the required count really can exceed the Safe's own threshold, without which every accept
// rule above would be consistent with required == threshold.
rule W_IT_1b(address g, address safe, AccessSelector.T access) {
    require safe == realSafe;
    setUpRealSafe();

    uint256 th = realSafe.getThreshold();
    uint256 req = getRequiredSignatures(g, safe, access);

    satisfy req > th,
        "a configuration exists in which the policy demands strictly more signatures than the Safe's threshold";
}
