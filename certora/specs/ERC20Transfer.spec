/* ERC20TransferPolicy: R-ERC20T-1..6 and W-ERC20T-1, run by `conf/ERC20Transfer.conf`, on
 * `ERC20TransferPolicyHarness` (harnesses/PolERC20Harness.sol), an additive subclass that overrides
 * nothing and exposes the real internal `_decodeERC20Transfer` and the real
 * `abi.decode(data, (RecipientData[]))` that `configure` runs. File-wide: domain L-POL-12 (L-POL-6,
 * L-POL-9 class), bound L-POL-1, defect L-POL-CTX, raw readers L-LIB-3. */

import "Vocabulary.spec";

using LibHarness as lib;

methods {
    function getRecipientPermission(address, address, address, address) external
        returns (ERC20TransferPolicyHarness.Permission) envfree;
    function decodeRecipient(bytes) external returns (address) envfree;
    function configEntryCount(bytes) external returns (uint256) envfree;
    function configEntryRecipient(bytes, uint256) external returns (address) envfree;
    function configEntryPermission(bytes, uint256) external returns (ERC20TransferPolicyHarness.Permission) envfree;
    // `ALWAYS` is a reserved CVL token, so the {Permission} members are read through the harness.
    function permNone() external returns (ERC20TransferPolicyHarness.Permission) envfree;
    function permOnce() external returns (ERC20TransferPolicyHarness.Permission) envfree;
    function permAlways() external returns (ERC20TransferPolicyHarness.Permission) envfree;
    function lib.selectorOf(bytes) external returns (bytes4) envfree;
    function lib.wordAt(bytes, uint256) external returns (uint256) envfree;
    function lib.getSelector(AccessSelector.T) external returns (bytes4) envfree;
    function lib.getOperation(AccessSelector.T) external returns (ERC20TransferPolicyHarness.Operation) envfree;
    function lib.getTarget(AccessSelector.T) external returns (address) envfree;
    function lib.opCall() external returns (ERC20TransferPolicyHarness.Operation) envfree;
}

// Read from the ABI so the magic value is the compiler's; R_ERC20T_1 also asserts it against the literal 0xcbd11d55
// (PolicyEngine.sol:202).
definition MAGIC() returns bytes4 = to_bytes4(
    sig:checkTransaction(address,address,uint256,bytes,ERC20TransferPolicyHarness.Operation,address,bytes,AccessSelector.T).selector
);

// The two ERC-20 selectors the policy accepts (IERC20.sol:9-10), as literals, so a change to either the policy
// comparison or the IERC20 declaration fails R_ERC20T_2 and R_ERC20T_5.
// SEL_TRANSFER and SEL_TRANSFER_FROM are declared in Vocabulary.spec.

// Longest `bytes` a rule calling `configure` admits: 64 + 64 * loop_iter with loop_iter = 3 (L-POL-1).
// CFG_MAX_BYTES is declared in Vocabulary.spec.

// R-ERC20T-1: `checkTransaction` reverts iff `msg.value != 0`, the recipient decode reverts, or the decoded recipient
// has Permission.NONE for (msg.sender, safe, to), and otherwise returns MAGIC (ERC20TransferPolicy.sol:81-89).
rule R_ERC20T_1(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20TransferPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    address recipient = decodeRecipient@withrevert(data);
    bool decodeReverted = lastReverted;
    ERC20TransferPolicyHarness.Permission perm = getRecipientPermission(e.msg.sender, safe, to, recipient);

    bytes4 r = checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted = lastReverted;

    assert MAGIC() == to_bytes4(0xcbd11d55), "IPolicy.checkTransaction.selector is 0xcbd11d55";
    assert reverted <=> (e.msg.value != 0 || decodeReverted || (!decodeReverted && perm == permNone())),
        "ERC20TransferPolicy.checkTransaction reverts exactly on nonzero msg.value, an undecodable transfer payload, or a recipient with no permission";
    assert !reverted => r == MAGIC(),
        "ERC20TransferPolicy.checkTransaction returns the magic value on success";
    assert (e.msg.value == 0 && !decodeReverted && perm != permNone()) => !reverted,
        "a decodable transfer to a permitted recipient is always accepted";
    assert (e.msg.value != 0 || decodeReverted || perm == permNone()) => reverted,
        "value, an undecodable payload, or a recipient with no permission is always rejected";
}

// R-ERC20T-1 over `calldataarg`: on every byte string the check is non-payable and its only
// non-reverting answer is MAGIC (L-POL-12).
rule R_ERC20T_1_anyCalldata(env e, calldataarg args) {
    bytes4 r = checkTransaction@withrevert(e, args);
    bool reverted = lastReverted;

    assert e.msg.value != 0 => reverted,
        "checkTransaction is non-payable on any calldata";
    assert !reverted => r == MAGIC(),
        "every non-reverting checkTransaction call, on any calldata, returns the magic value";
}

// R-ERC20T-2: `decodeRecipient`, the real `_decodeERC20Transfer` (ERC20TransferPolicy.sol:92-102), succeeds
// iff the payload is a `transfer` of 68+ bytes with a clean recipient word or a `transferFrom` of 100+
// bytes with two clean address words; L-POL-11.
rule R_ERC20T_2(bytes data) {
    bytes4 sel = lib.selectorOf(data);
    uint256 w4 = lib.wordAt(data, 4);
    uint256 w36 = lib.wordAt(data, 36);

    bool okTransfer = sel == SEL_TRANSFER() && data.length >= 68 && w4 < 2^160;
    bool okTransferFrom = sel == SEL_TRANSFER_FROM() && data.length >= 100 && w4 < 2^160 && w36 < 2^160;

    address recipient = decodeRecipient@withrevert(data);
    bool reverted = lastReverted;

    assert !reverted <=> (okTransfer || okTransferFrom),
        "the transfer decoder succeeds exactly on a transfer payload of 68+ bytes or a transferFrom payload of 100+ bytes with clean address words";
    assert (okTransfer || okTransferFrom) => !reverted,
        "a well-formed transfer or transferFrom payload always decodes";
    assert !(okTransfer || okTransferFrom) => reverted,
        "a foreign selector, a short payload or a dirty address word never decodes";
    assert (!reverted && okTransfer) => assert_uint256(recipient) == w4,
        "for transfer the recipient is the word at offset 4";
    assert (!reverted && okTransferFrom) => assert_uint256(recipient) == w36,
        "for transferFrom the recipient is the word at offset 36 (argument index 1), not the `from` at offset 4";
    assert data.length < 4 => reverted,
        "calldata shorter than four bytes never decodes: bytes4(data) zero-pads and matches neither selector";
}

// R-ERC20T-3: a successful check spends a ONCE permission and leaves an ALWAYS one standing
// (ERC20TransferPolicy.sol:85-88), while a reverting check changes nothing and no other (g', s', t', r') moves.
rule R_ERC20T_3(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20TransferPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    address gp,
    address sp,
    address tp,
    address rp
) {
    address recipient = decodeRecipient@withrevert(data);
    bool decodeReverted = lastReverted;
    ERC20TransferPolicyHarness.Permission pre =
        getRecipientPermission(e.msg.sender, safe, to, recipient);
    bool sameSlot = gp == e.msg.sender && sp == safe && tp == to && rp == recipient;
    ERC20TransferPolicyHarness.Permission otherBefore = getRecipientPermission(gp, sp, tp, rp);
    storage before = lastStorage;

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted1 = lastReverted;

    assert (!reverted1 && pre == permOnce()) =>
        getRecipientPermission(e.msg.sender, safe, to, recipient) == permNone(),
        "a successful check spends the ONCE permission it used";
    assert (!reverted1 && pre == permAlways()) =>
        getRecipientPermission(e.msg.sender, safe, to, recipient) == permAlways(),
        "a successful check leaves an ALWAYS permission standing";
    assert (!reverted1 && pre == permAlways()) => lastStorage == before,
        "an ALWAYS check writes no state at all (the approve twin's `lastStorage` form, not only the mapping form)";
    assert (!reverted1 && !sameSlot) => getRecipientPermission(gp, sp, tp, rp) == otherBefore,
        "a successful check leaves every other (guard, safe, token, recipient) permission unchanged";
    assert reverted1 => lastStorage == before,
        "a reverting check changes no state";
    assert !reverted1 => !decodeReverted,
        "a successful check always decoded its recipient";

    // Replay the identical check from the post-state.
    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);
    bool reverted2 = lastReverted;

    assert (!reverted1 && pre == permOnce()) => reverted2,
        "two consecutive identical checks cannot both succeed on a ONCE permission";
    assert (!reverted1 && pre == permAlways()) => !reverted2,
        "an ALWAYS permission admits the identical check again";
}

// R-ERC20T-4: the verdict and the state written depend on `data` only through the decoded recipient and not at
// all on value, operation, module, context or access, which is the executable form of an unconstrained
// `transferFrom` sender and an uncapped amount.
rule R_ERC20T_4(
    env e,
    address safe,
    address to,
    uint256 value1,
    bytes data1,
    ERC20TransferPolicyHarness.Operation op1,
    address module1,
    bytes context1,
    AccessSelector.T access1,
    uint256 value2,
    bytes data2,
    ERC20TransferPolicyHarness.Operation op2,
    address module2,
    bytes context2,
    AccessSelector.T access2
) {
    address r1 = decodeRecipient@withrevert(data1);
    bool bad1 = lastReverted;
    address r2 = decodeRecipient@withrevert(data2);
    bool bad2 = lastReverted;
    bool sameRecipient = !bad1 && !bad2 && r1 == r2;
    storage init = lastStorage;

    checkTransaction@withrevert(e, safe, to, value1, data1, op1, module1, context1, access1);
    bool reverted1 = lastReverted;
    storage after1 = lastStorage;

    checkTransaction@withrevert(e, safe, to, value2, data2, op2, module2, context2, access2) at init;
    bool reverted2 = lastReverted;

    assert sameRecipient => reverted1 == reverted2,
        "the verdict depends on `data` only through the decoded recipient, and not on value, operation, module, context or access";
    assert sameRecipient => lastStorage == after1,
        "the state written depends on `data` only through the decoded recipient, and not on value, operation, module, context or access";
}

// R-ERC20T-4 with `context1` empty and `context2` free (L-POL-CTX), so supplying any context gets the verdict and
// post-state that supplying none gets; the two rules are total in the `context` dimension.
rule R_ERC20T_4_emptyContext(
    env e,
    address safe,
    address to,
    uint256 value1,
    bytes data1,
    ERC20TransferPolicyHarness.Operation op1,
    address module1,
    bytes context1,
    AccessSelector.T access1,
    uint256 value2,
    bytes data2,
    ERC20TransferPolicyHarness.Operation op2,
    address module2,
    bytes context2,
    AccessSelector.T access2
) {
    require context1.length == 0;

    address r1 = decodeRecipient@withrevert(data1);
    bool bad1 = lastReverted;
    address r2 = decodeRecipient@withrevert(data2);
    bool bad2 = lastReverted;
    bool sameRecipient = !bad1 && !bad2 && r1 == r2;
    storage init = lastStorage;

    checkTransaction@withrevert(e, safe, to, value1, data1, op1, module1, context1, access1);
    bool reverted1 = lastReverted;
    storage after1 = lastStorage;

    checkTransaction@withrevert(e, safe, to, value2, data2, op2, module2, context2, access2) at init;
    bool reverted2 = lastReverted;

    assert sameRecipient => reverted1 == reverted2,
        "an arbitrary `context` gets the same verdict as no context at all";
    assert sameRecipient => lastStorage == after1,
        "an arbitrary `context` leaves the same state as no context at all";
}

// R-ERC20T-5, revert-iff half: `configure` reverts iff `msg.value != 0`, the access selector is neither `transfer`
// nor `transferFrom`, the operation is not CALL, or `data` is not a decodable RecipientData[], and otherwise
// returns true (ERC20TransferPolicy.sol:112-118).
rule R_ERC20T_5(env e, address safe, AccessSelector.T access, bytes data) {
    require data.length <= CFG_MAX_BYTES();

    bytes4 sel = lib.getSelector(access);
    bool selOk = sel == SEL_TRANSFER() || sel == SEL_TRANSFER_FROM();
    bool opOk = lib.getOperation(access) == lib.opCall();
    configEntryCount@withrevert(data);
    bool dataBad = lastReverted;

    bool ok = configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;

    assert reverted <=> (e.msg.value != 0 || !selOk || !opOk || dataBad),
        "ERC20TransferPolicy.configure reverts exactly on nonzero msg.value, a selector outside {transfer, transferFrom}, a non-CALL operation, or an undecodable RecipientData[]";
    assert !reverted => ok,
        "ERC20TransferPolicy.configure returns true on every accepted input";
    assert (e.msg.value == 0 && selOk && opOk && !dataBad) => !reverted,
        "a CALL key carrying transfer or transferFrom with a decodable entry list is always accepted";
    assert (e.msg.value != 0 || !selOk || !opOk || dataBad) => reverted,
        "value, a selector outside {transfer, transferFrom}, a non-CALL operation or an undecodable entry list is always rejected";
}

// R-ERC20T-5, effect half: on success `configure` writes, for each of the n = configEntryCount(data) entries, the last
// entry naming that recipient into [msg.sender][safe][getTarget(access)] and no other slot; the write is additive, so
// detach-reinstall resurrects old entries (WAIVED-S-6, :119-122).
rule R_ERC20T_5_effect(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address gp,
    address sp,
    address tp,
    address rp
) {
    require data.length <= CFG_MAX_BYTES();

    uint256 n = configEntryCount@withrevert(data);
    address r0 = configEntryRecipient@withrevert(data, 0);
    address r1 = configEntryRecipient@withrevert(data, 1);
    address r2 = configEntryRecipient@withrevert(data, 2);
    ERC20TransferPolicyHarness.Permission p0 = configEntryPermission@withrevert(data, 0);
    ERC20TransferPolicyHarness.Permission p1 = configEntryPermission@withrevert(data, 1);
    ERC20TransferPolicyHarness.Permission p2 = configEntryPermission@withrevert(data, 2);

    bool inNamespace = gp == e.msg.sender && sp == safe && tp == lib.getTarget(access);
    bool named0 = inNamespace && n >= 1 && rp == r0;
    bool named1 = inNamespace && n >= 2 && rp == r1;
    bool named2 = inNamespace && n >= 3 && rp == r2;
    ERC20TransferPolicyHarness.Permission before = getRecipientPermission(gp, sp, tp, rp);

    configure@withrevert(e, safe, access, data);
    bool reverted = lastReverted;

    assert !reverted => n <= 3,
        "the ledgered byte bound admits at most loop_iter = 3 entries";
    assert !reverted => getRecipientPermission(gp, sp, tp, rp) ==
        (named2 ? p2 : (named1 ? p1 : (named0 ? p0 : before))),
        "configure writes the last entry naming each recipient into [msg.sender][safe][getTarget(access)] and leaves every other slot, in every other namespace, unchanged";
}

// R-ERC20T-5 over `calldataarg`, non-payable half only: a `configure` carrying value always reverts at the
// dispatcher callvalue check before the entry loop, so the pessimistic unwinding assertion cannot fire;
// the success half is R_ERC20T_5 (L-POL-12).
rule R_ERC20T_5_anyCalldataNonPayable(env e, calldataarg args) {
    require e.msg.value != 0;

    configure@withrevert(e, args);

    assert lastReverted,
        "configure is non-payable on any calldata";
}

// R-ERC20T-6: for every scene method the `filtered` block admits and every (g', s', t', r'), a change to
// `getRecipientPermission(g', s', t', r')` implies g' == msg.sender; `configure` is covered by
// R_ERC20T_6_configureKeys (:83-86, :121).
rule R_ERC20T_6(env e, method f, calldataarg args, address gp, address sp, address tp, address rp)
    // All four excluded methods run `abi.decode(data, (RecipientData[]))` on an unbounded `bytes`,
    // where the pessimistic unwinding assertion fires; the three besides `configure` are pure harness
    // readers with no storage to write in any case.
    filtered {
        f -> f.selector != sig:configure(address,AccessSelector.T,bytes).selector
          && f.selector != sig:configEntryCount(bytes).selector
          && f.selector != sig:configEntryRecipient(bytes,uint256).selector
          && f.selector != sig:configEntryPermission(bytes,uint256).selector
    }
{
    ERC20TransferPolicyHarness.Permission before = getRecipientPermission(gp, sp, tp, rp);

    f(e, args);

    assert getRecipientPermission(gp, sp, tp, rp) != before => gp == e.msg.sender,
        "no method outside the filtered set writes a permission outside the caller's own guard namespace";
}

// R-ERC20T-6, writer-specific half for `checkTransaction`: it moves only the slot named by its own (msg.sender, safe,
// to, decoded recipient), and only by spending a ONCE permission (ERC20TransferPolicy.sol:85-88).
rule R_ERC20T_6_checkKeys(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20TransferPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access,
    address gp,
    address sp,
    address tp,
    address rp
) {
    address recipient = decodeRecipient@withrevert(data);
    ERC20TransferPolicyHarness.Permission before = getRecipientPermission(gp, sp, tp, rp);

    checkTransaction@withrevert(e, safe, to, value, data, op, module, context, access);

    ERC20TransferPolicyHarness.Permission post = getRecipientPermission(gp, sp, tp, rp);
    assert post != before =>
        (gp == e.msg.sender && sp == safe && tp == to && rp == recipient
         && before == permOnce() && post == permNone()),
        "checkTransaction writes only the permission named by its own (msg.sender, safe, to, recipient), and only by spending ONCE";
}

// R-ERC20T-6, writer-specific half for `configure`: the permissionless writer lands in its own (msg.sender, safe,
// getTarget(access)) namespace, at named recipients only (ERC20TransferPolicy.sol:121).
rule R_ERC20T_6_configureKeys(
    env e,
    address safe,
    AccessSelector.T access,
    bytes data,
    address gp,
    address sp,
    address tp,
    address rp
) {
    require data.length <= CFG_MAX_BYTES();

    uint256 n = configEntryCount@withrevert(data);
    address r0 = configEntryRecipient@withrevert(data, 0);
    address r1 = configEntryRecipient@withrevert(data, 1);
    address r2 = configEntryRecipient@withrevert(data, 2);
    ERC20TransferPolicyHarness.Permission before = getRecipientPermission(gp, sp, tp, rp);

    configure@withrevert(e, safe, access, data);

    assert getRecipientPermission(gp, sp, tp, rp) != before =>
        (gp == e.msg.sender && sp == safe && tp == lib.getTarget(access)
         && ((n >= 1 && rp == r0) || (n >= 2 && rp == r1) || (n >= 3 && rp == r2))),
        "configure writes only recipients named by its own entry list, in its own (msg.sender, safe, target) namespace";
}

// W-ERC20T-1 witness (W_ERC20T_1a): a check that succeeds through the `transfer` selector.
rule W_ERC20T_1a(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20TransferPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy r == MAGIC() && lib.selectorOf(data) == SEL_TRANSFER();
}

// W-ERC20T-1 witness (W_ERC20T_1b): a check that succeeds through the `transferFrom` selector, so the decoder's second
// branch is reachable and R_ERC20T_2's clause for it is not vacuous (ERC20TransferPolicy.sol:96-97).
rule W_ERC20T_1b(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20TransferPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);
    satisfy r == MAGIC() && lib.selectorOf(data) == SEL_TRANSFER_FROM();
}

// W-ERC20T-1 witness (W_ERC20T_1c): a success that changes storage, a ONCE permission spent by the transfer that used
// it (ERC20TransferPolicy.sol:85-88).
rule W_ERC20T_1c(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    ERC20TransferPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access
) {
    address recipient = decodeRecipient(data);
    ERC20TransferPolicyHarness.Permission pre = getRecipientPermission(e.msg.sender, safe, to, recipient);

    bytes4 r = checkTransaction(e, safe, to, value, data, op, module, context, access);

    satisfy r == MAGIC() && pre == permOnce()
        && getRecipientPermission(e.msg.sender, safe, to, recipient) == permNone();
}

// W-ERC20T-1 witness (W_ERC20T_1d): a single-entry ALWAYS configure under a `transfer` CALL key, then a check by the
// same sender on that token from a slot that held no permission, neither call under @withrevert.
rule W_ERC20T_1d(
    env e1,
    env e2,
    address safe,
    AccessSelector.T access,
    bytes cfg,
    address to,
    uint256 value,
    bytes data,
    ERC20TransferPolicyHarness.Operation op,
    address module,
    bytes context,
    AccessSelector.T access2
) {
    require cfg.length <= CFG_MAX_BYTES();

    address recipient = configEntryRecipient(cfg, 0);
    ERC20TransferPolicyHarness.Permission pre0 =
        getRecipientPermission(e1.msg.sender, safe, lib.getTarget(access), recipient);

    bool ok = configure(e1, safe, access, cfg);
    bytes4 r = checkTransaction(e2, safe, to, value, data, op, module, context, access2);

    satisfy ok && r == MAGIC()
        && e2.msg.sender == e1.msg.sender
        && pre0 == permNone()
        && configEntryCount(cfg) == 1
        && configEntryPermission(cfg, 0) == permAlways()
        && to == lib.getTarget(access)
        && lib.selectorOf(data) == SEL_TRANSFER()
        && assert_uint256(recipient) == lib.wordAt(data, 4);
}

// W-ERC20T-1 witness (W_ERC20T_1e): the last-wins clause of R_ERC20T_5_effect is not vacuous, exhibited by a
// three-entry configure whose first and last entries name one recipient with different permissions and whose post-state
// is the last.
rule W_ERC20T_1e(env e, address safe, AccessSelector.T access, bytes cfg) {
    require cfg.length <= CFG_MAX_BYTES();

    address r0 = configEntryRecipient(cfg, 0);
    address r2 = configEntryRecipient(cfg, 2);
    ERC20TransferPolicyHarness.Permission p0 = configEntryPermission(cfg, 0);
    ERC20TransferPolicyHarness.Permission p2 = configEntryPermission(cfg, 2);

    bool ok = configure(e, safe, access, cfg);

    satisfy ok
        && configEntryCount(cfg) == 3
        && r0 == r2
        && p0 == permOnce()
        && p2 == permAlways()
        && getRecipientPermission(e.msg.sender, safe, lib.getTarget(access), r0) == permAlways();
}
