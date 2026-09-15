/* ERC20ApprovePolicy: R-ERC20A-1..6 and W-ERC20A-1, run by `conf/ERC20Approve.conf`. The subject is
 * `ERC20ApprovePolicyHarness` (harnesses/PolERC20Harness.sol), an additive subclass that overrides
 * nothing and exposes the real internal `_decodeERC20Approve` and the real
 * `abi.decode(data, (SpenderData[]))` that `configure` runs. File-wide: domain L-POL-12, an instance
 * of L-POL-6 and L-POL-9; bound L-POL-1; defect L-POL-CTX. */

import "Vocabulary.spec";

using LibHarness as lib;

methods {
    function getSpenderPermission(address, address, address, address) external
        returns (ERC20ApprovePolicyHarness.Permission) envfree;
    function decodeApproveSpender(bytes) external returns (address) envfree;
    function decodeApproveAmount(bytes) external returns (uint256) envfree;
    function configEntryCount(bytes) external returns (uint256) envfree;
    function configEntrySpender(bytes, uint256) external returns (address) envfree;
    function configEntryPermission(bytes, uint256) external returns (ERC20ApprovePolicyHarness.Permission) envfree;
    // `ALWAYS` is a reserved CVL token, so the {Permission} members are read through the harness.
    function permNone() external returns (ERC20ApprovePolicyHarness.Permission) envfree;
    function permOnce() external returns (ERC20ApprovePolicyHarness.Permission) envfree;
    function permAlways() external returns (ERC20ApprovePolicyHarness.Permission) envfree;
    function lib.selectorOf(bytes) external returns (bytes4) envfree;
    function lib.wordAt(bytes, uint256) external returns (uint256) envfree;
    function lib.getSelector(AccessSelector.T) external returns (bytes4) envfree;
    function lib.getOperation(AccessSelector.T) external returns (ERC20ApprovePolicyHarness.Operation) envfree;
    function lib.getTarget(AccessSelector.T) external returns (address) envfree;
    function lib.opCall() external returns (ERC20ApprovePolicyHarness.Operation) envfree;
}

// Read from the ABI so the magic value is the compiler's; R_ERC20A_1 also asserts it against the literal 0xcbd11d55
// (PolicyEngine.sol:202).
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,ERC20ApprovePolicyHarness.Operation,address,bytes,AccessSelector.T).selector
);

// The one ERC-20 selector this policy accepts (IERC20.sol:11), as a literal, so a change to either the policy
// comparison or the IERC20 declaration fails R_ERC20A_2 and R_ERC20A_5.
// SEL_APPROVE is declared in Vocabulary.spec.
// `transfer`, which this policy must not accept: R_ERC20A_5 asserts a `transfer` configure key is rejected.
// SEL_TRANSFER is declared in Vocabulary.spec.

// Longest `bytes` a rule calling `configure` admits: 64 + 64 * loop_iter with loop_iter = 3 (L-POL-1).
// CFG_MAX_BYTES is declared in Vocabulary.spec.

// R-ERC20A-1: `checkTransaction` reverts iff `msg.value != 0`, the approve payload does not decode, or the amount is
// nonzero and the decoded spender has Permission.NONE for (msg.sender, safe, to), and otherwise returns MAGIC
// (ERC20ApprovePolicy.sol:81-92).
rule R_ERC20A_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20ApprovePolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    address spender = decodeApproveSpender@withrevert(data);
    bool decodeReverted = lastReverted;
    uint256 amount = decodeApproveAmount@withrevert(data);
    bool decodeReverted2 = lastReverted;
    ERC20ApprovePolicyHarness.Permission perm = getSpenderPermission(e.msg.sender, safe, to, spender);

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert MAGIC() == to_bytes4(0xcbd11d55), "IPolicy.checkTransaction.selector is 0xcbd11d55";
    assert decodeReverted == decodeReverted2,
        "the spender and amount readers run one decoder and agree on decodability";
    assert reverted <=> (e.msg.value != 0 || decodeReverted
                         || (!decodeReverted && amount != 0 && perm == permNone())),
        "ERC20ApprovePolicy.checkTransaction reverts exactly on nonzero msg.value, an undecodable approve payload, or a nonzero-amount approval for a spender with no permission";
    assert !reverted => r == MAGIC(),
        "ERC20ApprovePolicy.checkTransaction returns the magic value on success";
    assert (e.msg.value == 0 && !decodeReverted && amount == 0) => !reverted,
        "a well-formed zero-amount approve always passes, whatever the spender's permission: revoking an allowance is never allowlisted";
    assert (e.msg.value == 0 && !decodeReverted && perm != permNone()) => !reverted,
        "a decodable approve for a permitted spender is always accepted";
    assert (!decodeReverted && amount != 0 && perm == permNone()) => reverted,
        "a nonzero-amount approve for a spender with no permission is always rejected";
}

// R-ERC20A-1 over `calldataarg`: on every byte string the check is non-payable and its only
// non-reverting answer is MAGIC (L-POL-12).
rule R_ERC20A_1_anyCalldata(env e, calldataarg args) {
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;

    assert e.msg.value != 0 => reverted,
        "checkTransaction is non-payable on any calldata";
    assert !reverted => r == MAGIC(),
        "every non-reverting checkTransaction call, on any calldata, returns the magic value";
}

// R-ERC20A-2: the real `_decodeERC20Approve` (ERC20ApprovePolicy.sol:95-102) succeeds iff `selectorOf(data)` is
// approve, `data.length >= 68` and `wordAt(data,4) < 2^160`, yielding spender `wordAt(data,4)` and amount
// `wordAt(data,36)`, never swapped; L-POL-11.
rule R_ERC20A_2(bytes data) {
    bytes4 sel = lib.selectorOf(data);
    uint256 w4 = lib.wordAt(data, 4);
    uint256 w36 = lib.wordAt(data, 36);
    bool wellFormed = sel == SEL_APPROVE() && data.length >= 68 && w4 < 2^160;

    address spender = decodeApproveSpender@withrevert(data);
    bool reverted = lastReverted;
    uint256 amount = decodeApproveAmount@withrevert(data);
    bool reverted2 = lastReverted;

    assert reverted == reverted2,
        "both exposures of the approve decoder revert together";
    assert !reverted <=> wellFormed,
        "the approve decoder succeeds exactly on an approve payload of 68+ bytes with a clean spender word";
    assert wellFormed => !reverted,
        "a well-formed approve payload always decodes";
    assert !wellFormed => reverted,
        "a foreign selector, a short payload or a dirty spender word never decodes";
    assert !reverted => assert_uint256(spender) == w4,
        "the spender is the word at offset 4";
    assert !reverted => amount == w36,
        "the amount is the word at offset 36, not the spender word";
    assert data.length < 4 => reverted,
        "calldata shorter than four bytes never decodes: bytes4(data) zero-pads and never equals the approve selector";
}

// R-ERC20A-3: a successful nonzero-amount check spends a ONCE permission and leaves an ALWAYS one standing (:84-91),
// while zero-amount, ALWAYS and reverting checks write nothing and no other (g', s', t', sp') moves.
rule R_ERC20A_3(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20ApprovePolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    address gp,
    address sp,
    address tp,
    address spp
) {
    address spender = decodeApproveSpender@withrevert(data);
    bool decodeReverted = lastReverted;
    uint256 amount = decodeApproveAmount@withrevert(data);
    ERC20ApprovePolicyHarness.Permission pre = getSpenderPermission(e.msg.sender, safe, to, spender);
    bool sameSlot = gp == e.msg.sender && sp == safe && tp == to && spp == spender;
    ERC20ApprovePolicyHarness.Permission otherBefore = getSpenderPermission(gp, sp, tp, spp);
    storage before = lastStorage;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted1 = lastReverted;

    assert (!reverted1 && amount != 0 && pre == permOnce()) =>
        getSpenderPermission(e.msg.sender, safe, to, spender) == permNone(),
        "a successful nonzero-amount check spends the ONCE permission it used";
    assert (!reverted1 && (amount == 0 || pre == permAlways())) => lastStorage == before,
        "a zero-amount approval and an ALWAYS approval write no state at all: a revocation never burns a grant";
    assert (!reverted1 && !sameSlot) => getSpenderPermission(gp, sp, tp, spp) == otherBefore,
        "a successful check leaves every other (guard, safe, token, spender) permission unchanged";
    assert reverted1 => lastStorage == before,
        "a reverting check changes no state";
    assert !reverted1 => !decodeReverted,
        "a successful check always decoded its spender and amount";

    // Replay the identical check from the post-state.
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted2 = lastReverted;

    assert (!reverted1 && amount != 0 && pre == permOnce()) => reverted2,
        "two consecutive identical nonzero-amount checks cannot both succeed on a ONCE permission";
    assert (!reverted1 && amount == 0) => !reverted2,
        "a zero-amount approve can always be repeated: revocation is not rate-limited";
    assert (!reverted1 && pre == permAlways()) => !reverted2,
        "an ALWAYS permission admits the identical approval again";
}

// R-ERC20A-4: the verdict and the state written depend on `data` only through the pair (spender, amount == 0) and not
// at all on value, operation, module, context or access.
rule R_ERC20A_4(
    env e,
    address safe,
    address to,
    uint256 value1,
    bytes data1,
    ERC20ApprovePolicyHarness.Operation op1,
    address module1,
    bytes context1,
    AccessSelector.T access1,
    uint256 value2,
    bytes data2,
    ERC20ApprovePolicyHarness.Operation op2,
    address module2,
    bytes context2,
    AccessSelector.T access2
) {
    address s1 = decodeApproveSpender@withrevert(data1);
    bool bad1 = lastReverted;
    uint256 a1 = decodeApproveAmount@withrevert(data1);
    address s2 = decodeApproveSpender@withrevert(data2);
    bool bad2 = lastReverted;
    uint256 a2 = decodeApproveAmount@withrevert(data2);
    bool sameKey = !bad1 && !bad2 && s1 == s2 && ((a1 == 0) == (a2 == 0));
    storage init = lastStorage;

    checkTransaction@withrevert(e, safe, to, value1, data1, op1, module1, context1, access1);
    bool reverted1 = lastReverted;
    storage after1 = lastStorage;

    checkTransaction@withrevert(e, safe, to, value2, data2, op2, module2, context2, access2) at init;
    bool reverted2 = lastReverted;

    assert sameKey => reverted1 == reverted2,
        "the verdict depends on `data` only through the decoded spender and whether the amount is zero, never on the amount's size, nor on value, operation, module, context or access";
    assert sameKey => lastStorage == after1,
        "the state written depends on `data` only through the decoded spender and whether the amount is zero";
}

// R-ERC20A-4 with `context1` empty and `context2` free (L-POL-CTX), so supplying any context gets the verdict
// and post-state that supplying none gets.
rule R_ERC20A_4_emptyContext(
    env e,
    address safe,
    address to,
    uint256 value1,
    bytes data1,
    ERC20ApprovePolicyHarness.Operation op1,
    address module1,
    bytes context1,
    AccessSelector.T access1,
    uint256 value2,
    bytes data2,
    ERC20ApprovePolicyHarness.Operation op2,
    address module2,
    bytes context2,
    AccessSelector.T access2
) {
    require context1.length == 0;

    address s1 = decodeApproveSpender@withrevert(data1);
    bool bad1 = lastReverted;
    uint256 a1 = decodeApproveAmount@withrevert(data1);
    address s2 = decodeApproveSpender@withrevert(data2);
    bool bad2 = lastReverted;
    uint256 a2 = decodeApproveAmount@withrevert(data2);
    bool sameKey = !bad1 && !bad2 && s1 == s2 && ((a1 == 0) == (a2 == 0));
    storage init = lastStorage;

    checkTransaction@withrevert(e, safe, to, value1, data1, op1, module1, context1, access1);
    bool reverted1 = lastReverted;
    storage after1 = lastStorage;

    checkTransaction@withrevert(e, safe, to, value2, data2, op2, module2, context2, access2) at init;
    bool reverted2 = lastReverted;

    assert sameKey => reverted1 == reverted2,
        "an arbitrary `context` gets the same verdict as no context at all";
    assert sameKey => lastStorage == after1,
        "an arbitrary `context` leaves the same state as no context at all";
}

// R-ERC20A-5, revert-iff half: `configure` reverts iff `msg.value != 0`, the access selector is not
// `approve`, the operation is not CALL, or `data` is not a decodable SpenderData[], and otherwise
// returns true (ERC20ApprovePolicy.sol:112-118).
rule R_ERC20A_5(env e, address safe, AccessSelector.T access, bytes data) {
    require data.length <= CFG_MAX_BYTES();

    bytes4 sel = lib.getSelector(access);
    bool selOk = sel == SEL_APPROVE();
    bool opOk = lib.getOperation(access) == lib.opCall();
    configEntryCount@withrevert(data);
    bool dataBad = lastReverted;

    bool ok = configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;

    assert reverted <=> (e.msg.value != 0 || !selOk || !opOk || dataBad),
        "ERC20ApprovePolicy.configure reverts exactly on nonzero msg.value, a selector other than approve, a non-CALL operation, or an undecodable SpenderData[]";
    assert !reverted => ok,
        "ERC20ApprovePolicy.configure returns true on every accepted input";
    assert (e.msg.value == 0 && selOk && opOk && !dataBad) => !reverted,
        "a CALL key carrying approve with a decodable entry list is always accepted";
    assert (e.msg.value != 0 || !selOk || !opOk || dataBad) => reverted,
        "value, a selector other than approve, a non-CALL operation or an undecodable entry list is always rejected";
    assert sel == SEL_TRANSFER() => reverted,
        "the approve policy never configures a transfer key";
}

// R-ERC20A-5, effect half: on success `configure` writes, for each of the n = configEntryCount(data) entries, the last
// entry naming that spender into [msg.sender][safe][getTarget(access)] and no other slot; the write is additive, so
// detach-reinstall resurrects old entries (WAIVED-S-6, :119-121).
rule R_ERC20A_5_effect(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address gp,
    address sp,
    address tp,
    address spp
) {
    require data.length <= CFG_MAX_BYTES();

    uint256 n = configEntryCount@withrevert(data);
    address s0 = configEntrySpender@withrevert(data, 0);
    address s1 = configEntrySpender@withrevert(data, 1);
    address s2 = configEntrySpender@withrevert(data, 2);
    ERC20ApprovePolicyHarness.Permission p0 = configEntryPermission@withrevert(data, 0);
    ERC20ApprovePolicyHarness.Permission p1 = configEntryPermission@withrevert(data, 1);
    ERC20ApprovePolicyHarness.Permission p2 = configEntryPermission@withrevert(data, 2);

    bool inNamespace = gp == e.msg.sender && sp == safe && tp == lib.getTarget(access);
    bool named0 = inNamespace && n >= 1 && spp == s0;
    bool named1 = inNamespace && n >= 2 && spp == s1;
    bool named2 = inNamespace && n >= 3 && spp == s2;
    ERC20ApprovePolicyHarness.Permission before = getSpenderPermission(gp, sp, tp, spp);

    configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;

    assert !reverted => n <= 3,
        "the ledgered byte bound admits at most loop_iter = 3 entries";
    assert !reverted => getSpenderPermission(gp, sp, tp, spp) ==
        (named2 ? p2 : (named1 ? p1 : (named0 ? p0 : before))),
        "configure writes the last entry naming each spender into [msg.sender][safe][getTarget(access)] and leaves every other slot, in every other namespace, unchanged";
}

// R-ERC20A-5 over `calldataarg`, non-payable half only: a `configure` carrying value always reverts at the
// dispatcher callvalue check before the entry loop, so the pessimistic unwinding assertion cannot fire;
// the success half is R_ERC20A_5 (L-POL-12).
rule R_ERC20A_5_anyCalldataNonPayable(env e, calldataarg args) {
    require e.msg.value != 0;

    configure@withrevert(e, args);

    assert lastReverted,
        "configure is non-payable on any calldata";
}

// R-ERC20A-6: for every scene method the `filtered` block admits and every (g', s', t', sp'), a change to
// `getSpenderPermission(g', s', t', sp')` implies g' == msg.sender; `configure` is covered by
// R_ERC20A_6_configureKeys (:85-88, :120).
rule R_ERC20A_6(env e, method f, calldataarg args, address gp, address sp, address tp, address spp)
    // All four excluded methods run `abi.decode(data, (SpenderData[]))` on an unbounded `bytes`, where
    // the pessimistic unwinding assertion fires; the three besides `configure` are pure harness
    // readers with no storage to write in any case.
    filtered {
        f -> f.selector != sig:configure(address,AccessSelector.T,bytes).selector
          && f.selector != sig:configEntryCount(bytes).selector
          && f.selector != sig:configEntrySpender(bytes,uint256).selector
          && f.selector != sig:configEntryPermission(bytes,uint256).selector
    }
{
    ERC20ApprovePolicyHarness.Permission before = getSpenderPermission(gp, sp, tp, spp);

    f(e, args);

    assert getSpenderPermission(gp, sp, tp, spp) != before => gp == e.msg.sender,
        "no method outside the filtered set writes a permission outside the caller's own guard namespace";
}

// R-ERC20A-6, writer-specific half for `checkTransaction`: it moves only the slot named by its own (msg.sender,
// safe, to, decoded spender), only by spending a ONCE permission and only at a nonzero amount, so the
// zero-amount path is write-free (:84-90).
rule R_ERC20A_6_checkKeys(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20ApprovePolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    address gp,
    address sp,
    address tp,
    address spp
) {
    address spender = decodeApproveSpender@withrevert(data);
    uint256 amount = decodeApproveAmount@withrevert(data);
    ERC20ApprovePolicyHarness.Permission before = getSpenderPermission(gp, sp, tp, spp);

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    ERC20ApprovePolicyHarness.Permission post = getSpenderPermission(gp, sp, tp, spp);
    assert post != before =>
        (gp == e.msg.sender && sp == safe && tp == to && spp == spender && amount != 0
         && before == permOnce() && post == permNone()),
        "checkTransaction writes only the permission named by its own (msg.sender, safe, to, spender), only for a nonzero amount, and only by spending ONCE";
}

// R-ERC20A-6, writer-specific half for `configure`: the permissionless writer lands in its own (msg.sender, safe,
// getTarget(access)) namespace, at named spenders only (ERC20ApprovePolicy.sol:120).
rule R_ERC20A_6_configureKeys(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address gp,
    address sp,
    address tp,
    address spp
) {
    require data.length <= CFG_MAX_BYTES();

    uint256 n = configEntryCount@withrevert(data);
    address s0 = configEntrySpender@withrevert(data, 0);
    address s1 = configEntrySpender@withrevert(data, 1);
    address s2 = configEntrySpender@withrevert(data, 2);
    ERC20ApprovePolicyHarness.Permission before = getSpenderPermission(gp, sp, tp, spp);

    configure@withrevert(e, safe, access, data);

    assert getSpenderPermission(gp, sp, tp, spp) != before =>
        (gp == e.msg.sender && sp == safe && tp == lib.getTarget(access)
         && ((n >= 1 && spp == s0) || (n >= 2 && spp == s1) || (n >= 3 && spp == s2))),
        "configure writes only spenders named by its own entry list, in its own (msg.sender, safe, target) namespace";
}

// W-ERC20A-1 witness (W_ERC20A_1a): a check that succeeds with a nonzero amount for an allowlisted spender.
rule W_ERC20A_1a(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20ApprovePolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    address spender = decodeApproveSpender(data);
    uint256 amount = decodeApproveAmount(data);
    ERC20ApprovePolicyHarness.Permission pre = getSpenderPermission(e.msg.sender, safe, to, spender);

    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);

    satisfy r == MAGIC() && amount != 0 && pre != permNone();
}

// W-ERC20A-1 witness (W_ERC20A_1b): a zero-amount approve succeeds for a spender with no permission, so the revocation
// branch is reachable (ERC20ApprovePolicy.sol:83-84).
rule W_ERC20A_1b(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20ApprovePolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    address spender = decodeApproveSpender(data);
    uint256 amount = decodeApproveAmount(data);
    ERC20ApprovePolicyHarness.Permission pre = getSpenderPermission(e.msg.sender, safe, to, spender);

    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);

    satisfy r == MAGIC() && amount == 0 && pre == permNone();
}

// W-ERC20A-1 witness (W_ERC20A_1c): a success that changes storage, a ONCE permission spent by the nonzero-amount
// approval that used it (ERC20ApprovePolicy.sol:87-89).
rule W_ERC20A_1c(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20ApprovePolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    address spender = decodeApproveSpender(data);
    ERC20ApprovePolicyHarness.Permission pre = getSpenderPermission(e.msg.sender, safe, to, spender);

    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);

    satisfy r == MAGIC() && pre == permOnce()
        && getSpenderPermission(e.msg.sender, safe, to, spender) == permNone();
}

// W-ERC20A-1 witness (W_ERC20A_1d): a single-entry ALWAYS configure under an `approve` CALL key, then a nonzero-amount
// approval by the same sender on that token from a slot that held no permission, neither call under @withrevert.
rule W_ERC20A_1d(
    env e1,
    env e2,
    address safe,
    AccessSelector.T access,
    bytes cfg,
    address to,
    uint256 value,
    bytes data,
    ERC20ApprovePolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access2
) {
    require cfg.length <= CFG_MAX_BYTES();

    address spender = configEntrySpender(cfg, 0);
    ERC20ApprovePolicyHarness.Permission pre0 =
        getSpenderPermission(e1.msg.sender, safe, lib.getTarget(access), spender);

    bool ok = configure(e1, safe, access, cfg);
    bytes4 r = checkTransaction(e2, safe, to, value, data, op, module, context, access2);

    satisfy ok && r == MAGIC()
        && e2.msg.sender == e1.msg.sender
        && pre0 == permNone()
        && configEntryCount(cfg) == 1
        && configEntryPermission(cfg, 0) == permAlways()
        && to == lib.getTarget(access)
        && decodeApproveAmount(data) != 0
        && assert_uint256(spender) == lib.wordAt(data, 4);
}

// W-ERC20A-1 witness (W_ERC20A_1e): the last-wins clause of R_ERC20A_5_effect is not vacuous, exhibited by a
// three-entry configure whose first and last entries name one spender with different permissions and whose post-state
// is the last.
rule W_ERC20A_1e(env e, address safe, AccessSelector.T access, bytes cfg) {
    require cfg.length <= CFG_MAX_BYTES();

    address s0 = configEntrySpender(cfg, 0);
    address s2 = configEntrySpender(cfg, 2);
    ERC20ApprovePolicyHarness.Permission p0 = configEntryPermission(cfg, 0);
    ERC20ApprovePolicyHarness.Permission p2 = configEntryPermission(cfg, 2);

    bool ok = configure(e, safe, access, cfg);

    satisfy ok
        && configEntryCount(cfg) == 3
        && s0 == s2
        && p0 == permOnce()
        && p2 == permAlways()
        && getSpenderPermission(e.msg.sender, safe, lib.getTarget(access), s0) == permAlways();
}
