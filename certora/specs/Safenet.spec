// Safenet.spec: SafenetPolicy in isolation, rows R-SN-2 to R-SN-9, INV-SN-1, W-SN-1, the revert characterisation in
// isolation and the reader rule R_SN_5_gettersAgree, on the real policy through SafenetHarness with both private
// mappings read by direct storage access (D-007). FROST.verify is a free verdict over its argument tuple, the message
// constructions are free ghost functions, requireNonZero a zero-point check. The Safe in scene is Safe v1.5.0 itself,
// inherited unchanged by
// RealSafeHarness. Conf: Safenet. File-wide assumptions: L-HASHBLIND (no rule here may rest on comparing two Safe-style
// offset-30 hashes, the L-BIND-9 defect), L-SN-1, L-SN-2, L-SN-3, L-SN-4, L-SN-6, L-SN-7, L-SN-8, L-SN-9, L-SN-10,
// L-SN-12, L-SN-13, L-SN-14, L-SN-15, L-BIND-9, L-POL-CTX, WAIVED-H-1, WAIVED-H-2.

using RealSafeHarness as realSafe;

// Persistent: the capture ghosts must survive the dispatched external calls and stay readable on an execution that ends
// in a revert; they are spec-local instrumentation, not contract state (L-SN-7).
persistent ghost frostVerdict(uint256, uint256, uint256, uint256, uint256, bytes32) returns bool;

persistent ghost bool frostCalled;
persistent ghost uint256 capKeyX;
persistent ghost uint256 capKeyY;
persistent ghost uint256 capSigRX;
persistent ghost uint256 capSigRY;
persistent ghost uint256 capSigZ;
persistent ghost bytes32 capMsg;

// Free deterministic models of the two EIP-712 message constructions, ghost functions of their arguments rather than
// NONDET (L-SN-3).
persistent ghost proposalMsg(bytes32, uint64, address, bytes32, bytes32) returns bytes32;
persistent ghost rolloverMsg(bytes32, uint64, uint64, uint64, uint256, uint256) returns bytes32;

// Reverting verdict summary of FROST.verify; the captures run first, so the binding asserts see the arguments even on
// the rejecting path.
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

// Partial model of Secp256k1.requireNonZero (L-SN-2): it rejects the zero point exactly as the real function does and
// leaves every other point free, a safety superset; the omitted off-curve region is covered on chain by the curve
// checks of test/safenetPolicy.spec.ts.
function requireNonZeroModel(Secp256k1.Point p) {
    if (p.x == 0 && p.y == 0) {
        revert();
    }
}

// The rollover message as a function of the struct argument, unpacked because a ghost function cannot take a struct.
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
    // Production views.
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

    // EIP-712 message construction (L-SN-3). `domain` is called once, in the constructor, and read back through
    // getConsensusDomainSeparator(), so NONDET suffices; L-SN-14 records that no rule here constrains
    // the derivation, which test/safenetPolicy.spec.ts asserts on chain.
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

    // The Safe environment (L-SN-4): both calls are view, hence STATICCALLs with no state effect.
    function _.nonce() external => DISPATCH [ RealSafeHarness._ ] default NONDET;
    function _.getTransactionHash(
        address,uint256,bytes,SafenetHarness.Operation,uint256,uint256,uint256,address,address,uint256
    ) external => DISPATCH [ RealSafeHarness._ ] default NONDET;

    function realSafe.nonce() external returns (uint256) envfree;
}

// The engine accepts a policy answer iff it equals IPolicy.checkTransaction.selector; R_SN_1 also asserts it against
// the source literal 0xcbd11d55, rejecting a change to IPolicy.sol that an ABI-only comparison would follow.
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,SafenetHarness.Operation,address,bytes,AccessSelector.T).selector
);

// The trusted (group key, epoch) forest and the spent-nonce map, read by direct storage access (D-007);
// R_SN_5_gettersAgree asserts the two shipped getters against these reads.
function knownRaw(uint256 x, uint256 y, uint64 ep) returns bool {
    return currentContract.$epochs.entries[x][y][ep];
}

function spentOf(address g, address s, uint256 k) returns bool {
    return currentContract.$spent[g][s][k];
}

// R-SN-5 (reader agreement): the two production getters answer exactly what the direct storage access this spec uses
// reads, in both directions.
rule R_SN_5_gettersAgree(Secp256k1.Point gk, uint64 ep, address g, address s, uint256 k) {
    assert isKnownEpoch(gk, ep) == knownRaw(gk.x, gk.y, ep),
        "isKnownEpoch answers exactly the $epochs.entries[x][y][epoch] slot the rules read";
    assert isAttestationSpent(g, s, k) == spentOf(g, s, k),
        "isAttestationSpent answers exactly the $spent[guard][safe][nonce] slot the rules read";
}

// R-SN-1: with the nonce advanced, checkTransaction succeeds iff it is unpaid, module == 0, the context is 256 bytes
// and decodes, the decoded (group key, epoch) is trusted, nonce() - 1 is unspent and the verdict accepts; it then
// returns MAGIC.
rule R_SN_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    Enum.Operation opSafe,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;

    // Safe v1.5.0 takes `Enum.Operation`, this repo declares its own top-level `Operation`: the same uint8 and the
    // same selector, but CVL will not pass a value of one type for the other, so the spec carries both and requires
    // them equal.
    require to_mathint(opSafe) == to_mathint(op);

    uint256 n = realSafe.nonce();
    require n >= 1;
    uint256 k = assert_uint256(n - 1);

    // The decode runs twice on purpose (L-SN-12): the `@withrevert` call supplies the revert flag and its returns
    // are discarded, since reading a struct return of a reverting call trips an internal prover assert; its plain
    // twin runs only where the same pure call cannot revert, so nothing is pruned.
    decodeAttestation@withrevert(context);
    bool decodes = !lastReverted;

    bool ok = false;
    if (decodes) {
        uint64 ep;
        address orc;
        bytes32 odh;
        Secp256k1.Point gk;
        FROST.Signature sgn;
        ep, orc, odh, gk, sgn = decodeAttestation(context);

        bool knownKey = knownRaw(gk.x, gk.y, ep);
        bool spentBefore = spentOf(e.msg.sender, safe, k);
        bytes32 sth = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, k);
        bytes32 m = proposalMsgOf(getConsensusDomainSeparator(), ep, orc, odh, sth);
        bool accepts = frostVerdict(gk.x, gk.y, sgn.r.x, sgn.r.y, sgn.z, m);

        ok = e.msg.value == 0 && module == 0 && context.length == 256
            && knownKey && !spentBefore && accepts;
    }

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert MAGIC() == to_bytes4(0xcbd11d55),
        "IPolicy.checkTransaction.selector is 0xcbd11d55";
    assert !reverted => ok,
        "a check that authorizes had zero value, no module, a 256-byte decodable attestation for a trusted pair, an unspent nonce and an accepting FROST verdict";
    assert ok => !reverted,
        "a zero-value, module-free, well-formed attestation for a trusted pair at an unspent nonce with an accepting FROST verdict authorizes";
    assert !reverted => r == MAGIC(),
        "SafenetPolicy.checkTransaction returns the magic value on success";
}

// R-SN-1 at nonce == 0: an un-advanced Safe nonce denies before the FROST verdict is consulted, because nonce() - 1
// panics, so a policy that rebuilt the hash at nonce() fails here.
rule R_SN_1_zeroNonce(
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
    require !frostCalled;
    require realSafe.nonce() == 0;

    checkTransaction@withrevert(e, safe, to, value, data, op, 0, context, access);

    assert lastReverted,
        "a Safe whose nonce has not been advanced denies: nonce() - 1 panics";
    assert !frostCalled,
        "the nonce underflow denies before the FROST verdict is consulted";
}

// R-SN-1 (fail-closed): on every Safe, real or not, a call that authorizes consulted the FROST verdict and that verdict
// accepted, stated through the capture ghosts alone.
rule R_SN_1_failClosed(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require !frostCalled;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert !lastReverted => frostCalled,
        "no call authorizes without consulting the FROST verdict";
    assert !lastReverted => frostVerdict(capKeyX, capKeyY, capSigRX, capSigRY, capSigZ, capMsg),
        "a failed FROST verdict never authorizes";
}

// R-SN-1 (gates before the verdict): a module-path call, a context that is not exactly 256 bytes or does not decode,
// and an attestation naming an untrusted (group key, epoch) pair are all rejected without consulting the FROST verdict.
rule R_SN_1_gatesBeforeVerdict(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require !frostCalled;

    decodeAttestation@withrevert(context);
    bool decodes = !lastReverted;

    bool keyTrusted = false;
    if (decodes) {
        uint64 ep;
        address orc;
        bytes32 odh;
        Secp256k1.Point gk;
        FROST.Signature sgn;
        ep, orc, odh, gk, sgn = decodeAttestation(context);
        keyTrusted = knownRaw(gk.x, gk.y, ep);
    }

    require module != 0 || context.length != 256 || !decodes || !keyTrusted;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert lastReverted,
        "a module-path call, a malformed attestation or an untrusted attestation key is always denied";
    assert !frostCalled,
        "the module, length, decode and membership gates all deny before the FROST verdict is consulted";
}

// R-SN-1 (verdict binding): an authorizing call asked the verdict about the decoded key and signature and about
// transactionProposal(domainSeparator, epoch, oracle, oracleDataHash, H), H the Safe hash with gas and refund zeroed at
// nonce() - 1; L-BIND-9 leaves H unproven here.
rule R_SN_1_binding(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    Enum.Operation opSafe,
    bytes context,
    AccessSelector.T access
) {
    require safe == realSafe;

    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_SN_1

    uint256 n = realSafe.nonce();
    require n >= 1;
    uint256 k = assert_uint256(n - 1);

    uint64 ep;
    address orc;
    bytes32 odh;
    Secp256k1.Point gk;
    FROST.Signature sgn;
    ep, orc, odh, gk, sgn = decodeAttestation(context);

    bytes32 sth = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, k);
    bytes32 m = proposalMsgOf(getConsensusDomainSeparator(), ep, orc, odh, sth);

    // No `@withrevert`: the claim is about calls that authorize. W_SN_1a witnesses that such calls exist.
    checkTransaction(e, safe, to, value, data, op, 0, context, access);

    assert frostCalled,
        "an authorizing check consulted the FROST verdict";
    assert capKeyX == gk.x && capKeyY == gk.y,
        "the verdict was asked about the group key decoded from the attestation, never a stored or caller-named one";
    assert capSigRX == sgn.r.x && capSigRY == sgn.r.y && capSigZ == sgn.z,
        "the verdict was asked about the signature decoded from the attestation";
    assert capMsg == m,
        "the verified message is transactionProposal(domainSeparator, epoch, oracle, oracleDataHash, safeTxHash at nonce() - 1)";
}

// R-SN-1 (non-transferability): where the verdict for this transaction's message rejects, no accepting verdict for
// another message with the same key and signature lets the call through; L-BIND-9 leaves the safeTxHash dimension
// unproven here.
rule R_SN_1_verdictNotTransferable(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    Enum.Operation opSafe,
    bytes context,
    AccessSelector.T access,
    bytes32 m2
) {
    require safe == realSafe;

    require to_mathint(opSafe) == to_mathint(op);   // the Enum bridge of R_SN_1

    uint256 n = realSafe.nonce();
    require n >= 1;
    uint256 k = assert_uint256(n - 1);

    uint64 ep;
    address orc;
    bytes32 odh;
    Secp256k1.Point gk;
    FROST.Signature sgn;
    ep, orc, odh, gk, sgn = decodeAttestation(context);

    bytes32 sth = realSafe.getTransactionHash(e, to, value, data, opSafe, 0, 0, 0, 0, 0, k);
    bytes32 m = proposalMsgOf(getConsensusDomainSeparator(), ep, orc, odh, sth);

    require !frostVerdict(gk.x, gk.y, sgn.r.x, sgn.r.y, sgn.z, m);
    require m2 != m && frostVerdict(gk.x, gk.y, sgn.r.x, sgn.r.y, sgn.z, m2);

    checkTransaction@withrevert(e, safe, to, value, data, op, 0, context, access);

    assert lastReverted,
        "an attestation verified for a different message never authorizes this transaction";
}

// R-SN-1 over raw calldata (L-SN-8): non-payability, and any non-reverting call answers MAGIC, over every byte string.
rule R_SN_1_anyCalldata(env e, calldataarg args) {
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "SafenetPolicy.checkTransaction is non-payable for every raw calldata";
    assert !reverted => r == MAGIC(),
        "on any calldata, a non-reverting checkTransaction answers the magic value";
}

// R-SN-2: every call with module != 0 reverts, and reverts before the FROST verdict is consulted, whatever the safe,
// context, nonce, verdict or spent state.
rule R_SN_2(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    require module != 0;
    require !frostCalled;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert lastReverted,
        "SafenetPolicy.checkTransaction reverts ModulePathUnsupported on every module-path call";
    assert !frostCalled,
        "the module-path call reverts before the FROST verdict is consulted";
}

// R-SN-3: an authorizing check marks exactly $spent[msg.sender][safe][nonce() - 1], which was unset before, touches no
// other spent slot and never changes the trusted epoch forest; the configure half of this row is R_SN_9.
rule R_SN_3(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    bytes context,
    AccessSelector.T access,
    address g2,
    address s2,
    uint256 k2,
    uint256 x2,
    uint256 y2,
    uint64 ep2
) {
    require safe == realSafe;

    uint256 n = realSafe.nonce();
    require n >= 1;
    uint256 k = assert_uint256(n - 1);

    bool spentBefore = spentOf(e.msg.sender, safe, k);
    bool otherBefore = spentOf(g2, s2, k2);
    bool forestBefore = knownRaw(x2, y2, ep2);

    // No `@withrevert`: the claim is about calls that authorize.
    checkTransaction(e, safe, to, value, data, op, 0, context, access);

    assert !spentBefore && spentOf(e.msg.sender, safe, k),
        "an authorizing check spends exactly the Safe nonce it authorized, and that nonce was unspent before";
    assert (g2 != e.msg.sender || s2 != safe || k2 != k) => spentOf(g2, s2, k2) == otherBefore,
        "no other guard's, Safe's or nonce's spent flag is touched";
    assert knownRaw(x2, y2, ep2) == forestBefore,
        "the attestation path never changes the trusted epoch forest";
}

// R-SN-4: after a check that authorizes for (msg.sender, safe) at the Safe's nonce() - 1, every further
// checkTransaction from that guard for that Safe at that nonce reverts, a different valid attestation included.
rule R_SN_4(
    env e,
    env e2,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    bytes context,
    AccessSelector.T access,
    address to2,
    uint256 value2,
    bytes data2,
    SafenetHarness.Operation op2,
    address module2,
    bytes context2,
    AccessSelector.T access2
) {
    require safe == realSafe;
    require e2.msg.sender == e.msg.sender;
    require realSafe.nonce() >= 1;

    checkTransaction(e, safe, to, value, data, op, 0, context, access);

    checkTransaction@withrevert(e2, safe, to2, value2, data2, op2, module2, context2, access2);

    assert lastReverted,
        "at most one attestation is accepted per (guard, Safe, Safe nonce), whatever the second transaction is";
}

// R-SN-4 with an empty context2 (L-SN-10): a second check supplying no attestation never re-authorizes a spent nonce, a
// regression marker for L-POL-CTX; this conf leaves the defect's discriminator `precise_bitwise_ops` unset, which
// is the sound side for an `assert` (L-POL-CTX), so the marker records the shape rather than an exposure.
rule R_SN_4_emptyContext(
    env e,
    env e2,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    bytes context,
    AccessSelector.T access,
    address to2,
    uint256 value2,
    bytes data2,
    SafenetHarness.Operation op2,
    address module2,
    AccessSelector.T access2
) {
    require safe == realSafe;
    require e2.msg.sender == e.msg.sender;
    require realSafe.nonce() >= 1;

    bytes context2;
    require context2.length == 0;

    checkTransaction(e, safe, to, value, data, op, 0, context, access);
    checkTransaction@withrevert(e2, safe, to2, value2, data2, op2, module2, context2, access2);

    assert lastReverted,
        "a second check with an empty context is denied too: supplying no attestation never re-authorizes a spent nonce";
}

// R-SN-4 with an empty data2 (L-SN-10), the same regression marker for the other free bytes pair.
rule R_SN_4_emptyData(
    env e,
    env e2,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    bytes context,
    AccessSelector.T access,
    address to2,
    uint256 value2,
    SafenetHarness.Operation op2,
    address module2,
    bytes context2,
    AccessSelector.T access2
) {
    require safe == realSafe;
    require e2.msg.sender == e.msg.sender;
    require realSafe.nonce() >= 1;

    bytes data2;
    require data2.length == 0;

    checkTransaction(e, safe, to, value, data, op, 0, context, access);
    checkTransaction@withrevert(e2, safe, to2, value2, data2, op2, module2, context2, access2);

    assert lastReverted,
        "a second check whose transaction carries empty calldata is denied too";
}

// R-SN-5: the trusted (group key, epoch) forest changes only in updateEpoch and only from untrusted to trusted, with no
// pruning and no expiry; parametric over every non-view method with a free (x, y, ep).
rule R_SN_5(env e, method f, calldataarg args, uint256 x, uint256 y, uint64 ep)
    filtered { f -> !f.isView }
{
    bool before = knownRaw(x, y, ep);

    f(e, args);

    bool after = knownRaw(x, y, ep);

    assert after != before => (!before && after),
        "the trusted epoch forest is monotone: a recorded (group key, epoch) pair is never removed";
    assert after != before => f.selector == sig:updateEpoch(Secp256k1.Point,uint64,uint64,uint64,Secp256k1.Point,FROST.Signature).selector,
        "only updateEpoch extends the trusted epoch forest";
}

// R-SN-6: updateEpoch(pk, pe, qe, blk, nk, sig) succeeds iff it is unpaid, the parent pair (pk, pe) is trusted, qe >
// pe, the new key is non-zero (L-SN-2) and the parent group's FROST verdict over the rollover message accepts.
rule R_SN_6(
    env e,
    Secp256k1.Point pk,
    uint64 pe,
    uint64 qe,
    uint64 blk,
    Secp256k1.Point nk,
    FROST.Signature sgn
) {
    bool parentKnown = knownRaw(pk.x, pk.y, pe);
    bool nonZeroKey = !(nk.x == 0 && nk.y == 0);
    bytes32 m = rolloverMsgOf(getConsensusDomainSeparator(), pe, qe, blk, nk);
    bool accepts = frostVerdict(pk.x, pk.y, sgn.r.x, sgn.r.y, sgn.z, m);

    bool ok = e.msg.value == 0 && parentKnown && qe > pe && nonZeroKey && accepts;

    updateEpoch@withrevert(e, pk, pe, qe, blk, nk, sgn);
    bool reverted = lastReverted;

    assert !reverted => ok,
        "a rollover that is recorded came from a trusted parent, advanced the epoch, named a non-zero key and carried an accepting parent-group FROST verdict";
    assert ok => !reverted,
        "a zero-value rollover from a trusted parent to a strictly greater epoch with a non-zero key and an accepting FROST verdict is recorded";
}

// R-SN-6 (effect and frame): a successful rollover records exactly the (newGroupKey, proposedEpoch) pair, changes no
// other pair and never touches the spent-nonce map; idempotence follows with R_SN_6's liveness direction.
rule R_SN_6_effect(
    env e,
    Secp256k1.Point pk,
    uint64 pe,
    uint64 qe,
    uint64 blk,
    Secp256k1.Point nk,
    FROST.Signature sgn,
    uint256 x2,
    uint256 y2,
    uint64 ep2,
    address g2,
    address s2,
    uint256 k2
) {
    bool otherBefore = knownRaw(x2, y2, ep2);
    bool spentBefore = spentOf(g2, s2, k2);

    // No `@withrevert`: the claim is about rollovers that succeed. W_SN_1b witnesses that they exist.
    updateEpoch(e, pk, pe, qe, blk, nk, sgn);

    assert knownRaw(nk.x, nk.y, qe),
        "a successful rollover records exactly the (newGroupKey, proposedEpoch) pair it verified";
    assert (x2 != nk.x || y2 != nk.y || ep2 != qe) => knownRaw(x2, y2, ep2) == otherBefore,
        "a rollover changes no other (group key, epoch) pair";
    assert spentOf(g2, s2, k2) == spentBefore,
        "a rollover never touches the spent-nonce map";
}

// R-SN-6 (trust anchor): a newly trusted pair is exactly the one the call names, and every successful rollover started
// from a pair trusted at a strictly lower epoch whose verdict accepted; with R_SN_5 and INV-SN-1 this bounds the
// forest.
rule R_SN_6_anchor(
    env e,
    Secp256k1.Point pk,
    uint64 pe,
    uint64 qe,
    uint64 blk,
    Secp256k1.Point nk,
    FROST.Signature sgn,
    uint256 x,
    uint256 y,
    uint64 ep
) {
    require !frostCalled;

    bool before = knownRaw(x, y, ep);
    bool parentKnown = knownRaw(pk.x, pk.y, pe);
    bytes32 m = rolloverMsgOf(getConsensusDomainSeparator(), pe, qe, blk, nk);

    updateEpoch(e, pk, pe, qe, blk, nk, sgn);

    bool after = knownRaw(x, y, ep);

    assert after != before => (!before && x == nk.x && y == nk.y && ep == qe),
        "the only pair a rollover can newly trust is the (newGroupKey, proposedEpoch) it names";
    // Both conclusions hold unconditionally: `updateEpoch` above is called without `@withrevert`,
    // so only successful rollovers are in scope.
    assert parentKnown && qe > pe,
        "a successful rollover starts from a pair already trusted, at a strictly greater epoch";
    assert frostCalled && capKeyX == pk.x && capKeyY == pk.y && capMsg == m
            && frostVerdict(pk.x, pk.y, sgn.r.x, sgn.r.y, sgn.z, m),
        "a successful rollover consulted the parent group's FROST verdict over its own message, and that verdict accepted";
}

// INV-SN-1: (0, 0) is never a trusted group key at any epoch; the base case is the harness constructor running the real
// EpochRollover.initialize, the step every non-view method.
invariant INV_SN_1(uint64 ep)
    !currentContract.$epochs.entries[0][0][ep];

// R-SN-7: the signature is what authorizes a rollover, so anyone may relay it: two envs agreeing only on msg.value give
// the identical revert outcome and the identical forest, and R_SN_8 covers $spent.
rule R_SN_7(env eA, env eB, calldataarg args, uint256 x, uint256 y, uint64 ep) {
    require eA.msg.value == eB.msg.value;

    storage init = lastStorage;

    updateEpoch@withrevert(eA, args);
    bool revertedA = lastReverted;
    bool knownA = knownRaw(x, y, ep);

    updateEpoch@withrevert(eB, args) at init;
    bool revertedB = lastReverted;

    assert revertedA == revertedB,
        "whether a rollover is accepted does not depend on who relays it";
    assert knownRaw(x, y, ep) == knownA,
        "which pairs a rollover records does not depend on who relays it";
}

// R-SN-8: a spent flag changes only in checkTransaction, only in the calling guard's own namespace and only from
// unspent to spent, which is the nonce-rewind defence; the (safe, nonce) dimension is R_SN_8_checkKeys, pure under
// L-SN-13.
rule R_SN_8(env e, method f, calldataarg args, address g2, address s2, uint256 k2)
    filtered { f -> !f.isView }
{
    bool before = spentOf(g2, s2, k2);

    f(e, args);

    bool after = spentOf(g2, s2, k2);

    assert after != before => (!before && after),
        "spent flags are monotone: no path ever clears one";
    assert after != before => g2 == e.msg.sender,
        "a spent flag is only ever written in the calling guard's own namespace";
    assert after != before
        => f.selector == sig:checkTransaction(address,address,uint256,bytes,SafenetHarness.Operation,address,bytes,AccessSelector.T).selector,
        "only checkTransaction writes a spent flag";
}

// R-SN-8 (writer key, typed half, L-SN-8): the only spent slot checkTransaction may change is
// [msg.sender][safe][nonce() - 1], a dimension no calldataarg can name.
rule R_SN_8_checkKeys(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    SafenetHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    address g2,
    address s2,
    uint256 k2
) {
    require safe == realSafe;

    uint256 n = realSafe.nonce();
    require n >= 1;
    uint256 k = assert_uint256(n - 1);

    bool otherBefore = spentOf(g2, s2, k2);

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    assert spentOf(g2, s2, k2) != otherBefore => (g2 == e.msg.sender && s2 == safe && k2 == k),
        "checkTransaction writes only the spent flag of its own guard, its Safe and that Safe's nonce() - 1";
}

// R-SN-9: configure returns true and reverts iff it is paid, for every (safe, access, data), and writes nothing at all,
// which also discharges R-SN-3's configure clause; the parametric rules exclude it as pure (L-SN-13).
rule R_SN_9(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address g2,
    address s2,
    uint256 k2,
    uint256 x2,
    uint256 y2,
    uint64 ep2
) {
    bool spentBefore = spentOf(g2, s2, k2);
    bool forestBefore = knownRaw(x2, y2, ep2);

    bool ok = configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;

    assert reverted => e.msg.value != 0,
        "configure reverts only on a payable call";
    assert e.msg.value != 0 => reverted,
        "configure reverts on every payable call";
    assert !reverted => ok,
        "configure returns true for every safe, access selector and payload";
    assert spentOf(g2, s2, k2) == spentBefore,
        "configure never writes a spent flag";
    assert knownRaw(x2, y2, ep2) == forestBefore,
        "configure never changes the trusted epoch forest";
}

// R-SN-9 over raw calldata (L-SN-8): non-payability, and configure never returns false, for every input.
rule R_SN_9_anyCalldata(env e, calldataarg args) {
    bool ok = configure@withrevert(e, args);
    bool reverted = lastReverted;
    assert e.msg.value != 0 => reverted,
        "SafenetPolicy.configure is non-payable for every raw calldata";
    assert !reverted => ok,
        "on any calldata, a non-reverting configure returns true";
}

// W-SN-1 witness (W_SN_1a): a well-formed attestation for a trusted pair with an advanced, unspent nonce and an
// accepting FROST verdict exists, answers MAGIC and marks the nonce spent, the non-vacuity evidence for R_SN_1,
// R_SN_1_binding, R_SN_3 and R_SN_4.
rule W_SN_1a(
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
    require !frostCalled;

    uint256 n = realSafe.nonce();
    require n >= 1;
    uint256 k = assert_uint256(n - 1);

    bytes4 r = checkTransaction(e, safe, to, value, data, op, 0, context, access);

    satisfy r == MAGIC() && frostCalled && spentOf(e.msg.sender, safe, k),
        "an attestation for a trusted pair authorizes the Safe's current nonce and spends it";
}

// W-SN-1 witness (W_SN_1b): a rollover from a trusted parent to a new pair exists and records it, so R_SN_6,
// R_SN_6_effect and R_SN_6_anchor are not consistent with a forest that can never grow (the witness inherits L-SN-2).
rule W_SN_1b(
    env e,
    Secp256k1.Point pk,
    uint64 pe,
    uint64 qe,
    uint64 blk,
    Secp256k1.Point nk,
    FROST.Signature sgn
) {
    require !knownRaw(nk.x, nk.y, qe);

    updateEpoch(e, pk, pe, qe, blk, nk, sgn);

    satisfy knownRaw(nk.x, nk.y, qe) && knownRaw(pk.x, pk.y, pe) && qe > pe,
        "a rollover signed by a trusted parent group records a new trusted (group key, epoch) pair";
}

// W-SN-1 witness (W_SN_1c): a 256-byte context the ABI decoder rejects exists in the model, the non-vacuity evidence
// for R_SN_1's decodes conjunct under the two-step decode of L-SN-12.
rule W_SN_1c(bytes context) {
    decodeAttestation@withrevert(context);
    satisfy lastReverted && context.length == 256,
        "a 256-byte context that the ABI decoder rejects exists, so R_SN_1's decode conjunct is not vacuous";
}
