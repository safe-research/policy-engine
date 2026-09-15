// CoSigner.spec: CoSignerPolicy in isolation, rows R-COS-1, R-COS-3, R-COS-4, R-COS-5 and W-COS-1, and verdict
// binding. The subject is the real contract: both private mappings are read by direct storage access (D-007) and
// the two shipped getters are pinned by R_COS_4_gettersAgree.
// Conf: CoSigner. The Safe in scene is Safe v1.5.0 itself, inherited unchanged by RealSafeHarness, so
// `nonce` and `getTransactionHash` are the shipped package's own code. File-wide assumptions: L-HASHBLIND
// (no rule here may rest on comparing two Safe-style offset-30 hashes, the L-BIND-9 defect), L-COS-1 (the
// free signature-verdict oracle), L-COS-3, L-COS-4, L-COS-5, L-COS-6, L-COS-11, L-COS-12, L-COS-13,
// L-BIND-9, WAIVED-H-3, WAIVED-H-9.

using RealSafeHarness as realSafe;
using LibHarness as lib;

// Persistent: these ghosts must survive the external ISafe calls and stay readable on a reverting execution.
persistent ghost mapping(address => mapping(bytes32 => mapping(bytes => bool))) V;

persistent ghost bool capCalled;
persistent ghost address capSigner;
persistent ghost bytes32 capHash;
persistent ghost bytes32 capSigHash;
persistent ghost uint256 capSigLen;
persistent ghost bool capVerdict;

// Non-reverting verdict summary of SignatureChecker.isValidSignatureNow; the captures run first, so the binding asserts
// see the arguments even on the rejecting path, capSigHash with capSigLen standing for the bytes.
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
    // The summarized signature verdict (L-COS-1), at the internal library call site `:72`.
    function SignatureChecker.isValidSignatureNow(address signer, bytes32 hash, bytes memory signature) internal returns (bool)
        => sigVerdict(signer, hash, signature);

    // The two ISafe calls (`:53-65`) are view, hence STATICCALLs: Safe v1.5.0's own body when `safe` is that Safe, a
    // havoced return with no state effect otherwise.
    function _.nonce() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
    function _.getTransactionHash(
        address,uint256,bytes,CoSignerPolicy.Operation,uint256,uint256,uint256,address,address,uint256
    ) external => DISPATCH [ RealSafeHarness._ ] default NONDET;

    // The policy's own view surface; `getCoSigner` reads `msg.sender`, so it is not envfree.
    function isCoSignatureSpent(address, address, bytes32) external returns (bool) envfree;

    // Safe v1.5.0 reads; `getTransactionHash` and `domainSeparator` read `chainid()`, so they take an env.
    function realSafe.nonce() external returns (uint256) envfree;

    // LibHarness raw reader: `wordAt` is the 32-byte word of a `bytes` value.
    function lib.wordAt(bytes, uint256) external returns (uint256) envfree;
}

// The engine accepts a policy answer iff it equals `IPolicy.checkTransaction.selector`; `R_COS_1` also asserts it
// against the source literal, so a changed policy signature cannot drag the constant along.
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,CoSignerPolicy.Operation,address,bytes,AccessSelector.T).selector
);

// H'(k), used by the rule headers below, is the Safe transaction hash of (to, value, data, operation)
// with the five gas and refund fields zeroed, at nonce k (CoSignerPolicy.sol:53-65).

// The two private mappings, read by direct storage access (D-007); $spent's getter is itself pinned by
// R_COS_4_gettersAgree.
definition cosignerOf(address g, address s, AccessSelector.T a) returns address = currentContract.$cosigners[g][s][a];
definition spentOf(address g, address s, bytes32 h) returns bool = currentContract.$spent[g][s][h];

// Two access selectors name the same key iff their packed words are equal: CVL models `AccessSelector.T` as its
// underlying `uint256`, so `==` on the type is that comparison.
definition sameKey(AccessSelector.T x, AccessSelector.T y) returns bool = x == y;

// The address boundary solc's memory decoder enforces on `abi.decode(data, (address))` (`:85`).
definition TWO_160() returns mathint = 1461501637330902918203684832716283019655932542976;   // 2^160

// R-COS-1: with the nonce advanced, checkTransaction succeeds iff it is unpaid, a cosigner is configured, the verdict
// for (cosigner, H'(nonce-1), context) accepts and that hash is unspent, and it then returns MAGIC; module is free
// (D-006).
rule R_COS_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation op,
    Enum.Operation opSafe,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;

    uint256 n = realSafe.nonce();
    require n >= 1;

    address cs = cosignerOf(e.msg.sender, safe, access);
    // Safe v1.5.0 takes `Enum.Operation`, this repo declares its own top-level `Operation`: the same
    // uint8 and the same selector, but CVL will not pass a value of one type for the other, so the
    // spec carries both and requires them equal.
    require to_mathint(opSafe) == to_mathint(op);
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));
    bool v = V[cs][h][context];
    bool spentBefore = spentOf(e.msg.sender, safe, h);

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert MAGIC() == to_bytes4(0xcbd11d55),
        "IPolicy.checkTransaction.selector is 0xcbd11d55";
    assert !reverted => (e.msg.value == 0 && cs != 0 && v && !spentBefore),
        "a checkTransaction that authorizes had zero value, a configured cosigner, an accepting verdict and an unspent hash";
    assert (e.msg.value == 0 && cs != 0 && v && !spentBefore) => !reverted,
        "checkTransaction authorizes whenever value is zero, a cosigner is configured, the verdict accepts and the hash is unspent";
    assert !reverted => r == MAGIC(),
        "CoSignerPolicy.checkTransaction returns the magic value on success";
}

// R-COS-1 with context pinned empty (L-COS-11): no coverage R_COS_1 lacks, kept as a regression marker for the
// L-POL-CTX defect class; it runs in conf/CoSigner.conf with the rest of the file.
rule R_COS_1_emptyContext(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation op,
    Enum.Operation opSafe,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require context.length == 0;
    require safe == realSafe;

    uint256 n = realSafe.nonce();
    require n >= 1;

    address cs = cosignerOf(e.msg.sender, safe, access);
    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_COS_1
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));
    bool v = V[cs][h][context];
    bool spentBefore = spentOf(e.msg.sender, safe, h);

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert !reverted => (e.msg.value == 0 && cs != 0 && v && !spentBefore),
        "an empty context authorizes only if the verdict accepts the empty signature for the configured cosigner";
    assert (e.msg.value == 0 && cs != 0 && v && !spentBefore) => !reverted,
        "with an empty context the same four conditions are still sufficient";
    assert !reverted => r == MAGIC(),
        "CoSignerPolicy.checkTransaction returns the magic value on success with an empty context";
}

// R-COS-1 at nonce == 0: an un-advanced Safe nonce denies before any policy storage is read, so a policy that rebuilt
// the hash at nonce() fails here.
rule R_COS_1_zeroNonce(
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
    require !capCalled;
    require realSafe.nonce() == 0;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert lastReverted,
        "a Safe whose nonce has not been advanced denies: nonce() - 1 panics";
    assert !capCalled,
        "the nonce underflow denies before the signature verdict is consulted";
}

// R-COS-1 over raw calldata (L-COS-4): non-payability, and any non-reverting call returns MAGIC, for every byte string.
rule R_COS_1_anyCalldata(env e, calldataarg args) {
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "CoSignerPolicy.checkTransaction is non-payable for every raw calldata";
    assert !reverted => r == MAGIC(),
        "on any calldata, a non-reverting checkTransaction returns the magic value";
}

// R-COS-2: an authorizing call consulted the verdict about exactly the configured cosigner, the hash at nonce() - 1
// with the five gas and refund fields zeroed, and context verbatim. Under L-BIND-9 exactly one assert below is
// blind, `capHash == h`; the cosigner, signature and verdict asserts are unaffected.
rule R_COS_2(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation op,
    Enum.Operation opSafe,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;

    uint256 n = realSafe.nonce();
    require n >= 1;

    address cs = cosignerOf(e.msg.sender, safe, access);
    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_COS_1
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));

    // No `@withrevert`: the claim is about calls that authorize. W_COS_1 witnesses that such calls exist.
    checkTransaction(e, safe, to, value, data, op, module, context, access);

    assert capCalled,
        "an authorizing check consulted the signature verdict";
    assert capSigner == cs,
        "the verdict was asked about the cosigner configured for this guard, Safe and access selector";
    // Blind under L-BIND-9: both sides passed through Safe's offset-30 keccak, so the prover proves this even
    // when it is false.
    assert capHash == h,
        "the verified hash is the Safe's own transaction hash with the gas and refund fields zeroed at nonce() - 1";
    assert capSigHash == keccak256(context) && capSigLen == context.length,
        "the verified signature is exactly the caller-supplied context";
    assert capVerdict,
        "an authorizing check received an accepting verdict";
}

// R-COS-2 (fail-closed half): a failed or absent verification never authorizes, over an arbitrary safe and sender, and
// the accepting oracle entry must be the caller's own context.
rule R_COS_2_failClosed(
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
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert !reverted => capCalled,
        "no call authorizes without consulting the signature verdict";
    assert !reverted => capVerdict,
        "a failed verification never authorizes";
    assert !reverted => V[capSigner][capHash][context],
        "the accepting verdict was the one for the caller-supplied context bytes";
}

// R-COS-2 (hash and signer binding half): a verdict for one hash or one signer never authorizes another. The one
// assert rests on a `require` over the offset-30 hash `h`, so under L-BIND-9 the whole rule is blind; it is kept as
// a regression marker.
rule R_COS_2_hashBinding(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation op,
    Enum.Operation opSafe,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;

    uint256 n = realSafe.nonce();
    require n >= 1;

    address cs = cosignerOf(e.msg.sender, safe, access);
    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_COS_1
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));

    require !V[cs][h][context];

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert lastReverted,
        "no verdict for another hash, signer or signature can authorize this transaction";
}

// R-COS-3: an authorizing check marks exactly $spent[msg.sender][safe][H'(n-1)], touches no other slot, and an
// identical repeat reverts; L-BIND-9 leaves the nonce dimension unproven here.
rule R_COS_3(
    env e,
    env e2,
    address safe,
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation op,
    Enum.Operation opSafe,
    address module,
    bytes context,
    AccessSelector.T access,
    address g2,
    address s2,
    bytes32 h2,
    address g3,
    address s3,
    AccessSelector.T a3
) {
    require safe == realSafe;

    uint256 n = realSafe.nonce();
    require n >= 1;
    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_COS_1
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));

    bool spentBefore = spentOf(e.msg.sender, safe, h);
    bool otherBefore = spentOf(g2, s2, h2);
    address csBefore = cosignerOf(g3, s3, a3);

    checkTransaction(e, safe, to, value, data, op, module, context, access);

    assert !spentBefore && spentOf(e.msg.sender, safe, h),
        "an authorizing check spends exactly the hash it verified, and it was unspent before";
    assert (g2 != e.msg.sender || s2 != safe || h2 != h) => spentOf(g2, s2, h2) == otherBefore,
        "no other guard's, Safe's or hash's spent flag is touched";
    assert cosignerOf(g3, s3, a3) == csBefore,
        "the check path never writes a configured cosigner";

    require e2.msg.sender == e.msg.sender;
    checkTransaction@withrevert(e2, safe, to, value, data, op, module, context, access);
    assert lastReverted,
        "the same co-signature cannot authorize the same transaction twice: CoSignatureAlreadySpent";
}

// R-COS-4 (guard dimension, over raw calldata): no method writes a cosigner or a spent flag under another guard's key;
// $spent is written only by checkTransaction and only false to true, $cosigners only by configure, which is the
// nonce-rewind defence.
rule R_COS_4(env e, method f, calldataarg args, address g2, address s2, bytes32 h2, AccessSelector.T a2)
    // `!f.isView` removes only the two view getters, whose bytecode contains no SSTORE (L-COS-12).
    filtered { f -> !f.isView }
{
    bool spentBefore = spentOf(g2, s2, h2);
    address csBefore = cosignerOf(g2, s2, a2);

    f(e, args);

    assert spentOf(g2, s2, h2) != spentBefore
        => (g2 == e.msg.sender && f.selector == sig:checkTransaction(address,address,uint256,bytes,CoSignerPolicy.Operation,address,bytes,AccessSelector.T).selector),
        "only checkTransaction, and only under its own caller's key, changes a spent flag";
    assert spentBefore => spentOf(g2, s2, h2),
        "a spent flag is never cleared: the spend map is monotone, the nonce-rewind defence";
    assert cosignerOf(g2, s2, a2) != csBefore
        => (g2 == e.msg.sender && f.selector == sig:configure(address,AccessSelector.T,bytes).selector),
        "only configure, and only under its own caller's key, changes a configured cosigner";
}

// R-COS-4 (writer key, check path): the only $spent slot checkTransaction may change is [msg.sender][safe][H'(n-1)];
// the typed-argument half (L-COS-4), with R_COS_4 carrying the guard dimension raw.
rule R_COS_4_checkKeys(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation op,
    Enum.Operation opSafe,
    address module,
    bytes context,
    AccessSelector.T access,
    address g2,
    address s2,
    bytes32 h2
) {
    require safe == realSafe;

    uint256 n = realSafe.nonce();
    require n >= 1;
    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_COS_1
    bytes32 h = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, assert_uint256(n - 1));

    bool otherBefore = spentOf(g2, s2, h2);

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert spentOf(g2, s2, h2) != otherBefore => (g2 == e.msg.sender && s2 == safe && h2 == h),
        "checkTransaction writes only the spent flag of its own guard, Safe and derived hash";
}

// R-COS-4 (writer key, configure path): the only $cosigners slot configure may change is [msg.sender][safe][access],
// taking the address in the first word of data (L-COS-4).
rule R_COS_4_configureKeys(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address g2,
    address s2,
    AccessSelector.T a2
) {
    address otherBefore = cosignerOf(g2, s2, a2);

    configure@withrevert(e, safe, access, data);

    assert cosignerOf(g2, s2, a2) != otherBefore
        => (g2 == e.msg.sender && s2 == safe && sameKey(a2, access)),
        "configure writes only the cosigner of its own guard, Safe and access selector";
}

// R-COS-4 (reader agreement): the two shipped getters name the slots this spec reads by direct storage access (D-007),
// getCoSigner keyed on the caller rather than an explicit guard.
rule R_COS_4_gettersAgree(env e, address g, address safe, bytes32 h, AccessSelector.T access) {
    assert isCoSignatureSpent(g, safe, h) == spentOf(g, safe, h),
        "isCoSignatureSpent reads exactly $spent[policyGuard][safe][safeTxHash]";
    assert getCoSigner(e, safe, access) == cosignerOf(e.msg.sender, safe, access),
        "getCoSigner reads $cosigners[msg.sender][safe][access]: it is keyed on the caller";
}

// R-COS-5: configure(safe, access, data) reverts iff it is paid, data is shorter than 32 bytes or its first word is not
// a clean address, and otherwise returns true and stores that word; address(0) disables the selector.
rule R_COS_5(env e, address safe, AccessSelector.T access, bytes data) {
    uint256 w = lib.wordAt(data, 0);

    bool ok = configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;

    assert reverted => (e.msg.value != 0 || data.length < 32 || to_mathint(w) >= TWO_160()),
        "configure reverts only on a payable call, a data payload shorter than one word, or a dirty address word";
    assert (e.msg.value != 0 || data.length < 32 || to_mathint(w) >= TWO_160()) => reverted,
        "configure reverts on every payable call, every short data payload and every dirty address word";
    assert !reverted => ok,
        "configure returns true whenever it succeeds";
    assert !reverted => to_mathint(cosignerOf(e.msg.sender, safe, access)) == to_mathint(w),
        "configure stores the first word of data as the cosigner, address(0) included";
}

// R-COS-5 over raw calldata (L-COS-4): non-payability, and configure never returns false, for every byte string.
rule R_COS_5_anyCalldata(env e, calldataarg args) {
    bool ok = configure@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "CoSignerPolicy.configure is non-payable for every raw calldata";
    assert !reverted => ok,
        "on any calldata, a non-reverting configure returns true";
}

// W-COS-1: a configured cosigner, an advanced nonce, an accepting verdict and an unspent hash give MAGIC and mark the
// hash spent, the non-vacuity evidence for R_COS_1, R_COS_2 and R_COS_3.
rule W_COS_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    CoSignerPolicy.Operation op,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;
    require realSafe.nonce() >= 1;

    bytes4 r = checkTransaction(e, safe, to, value, data, op, 0, context, access);

    satisfy r == MAGIC() && capCalled && capVerdict && spentOf(e.msg.sender, safe, capHash),
        "a co-signed owner transaction authorizes and spends the hash";
}

// W-COS-1 witness (W_COS_1b), the formal statement of D-006's premise: in isolation this policy authorizes a call with
// module != 0, since it never reads module; the guard's empty context is what fails closed.
rule W_COS_1b(
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
    require module != 0;
    require realSafe.nonce() >= 1;

    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);

    satisfy r == MAGIC() && capCalled && capVerdict && capSigLen == 65,
        "in isolation CoSignerPolicy authorizes a module transaction carrying a 65-byte co-signature (D-006): the module path fails closed only through the guard";
}
