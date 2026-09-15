/* R-MS-9, the closed recursive scene. `conf/MultiSendNested.conf` runs `R_MS_9` alone and it TIMEOUTs, so
 * the row is waived under WAIVED-H-7 against the nested-batch tests of `test/multiSendPolicy.spec.ts`.
 * Nothing is summarized: the real `SafePolicyGuard`, the real `MultiSendPolicy` and a recording leaf
 * policy are wired into a cycle by two per-signature DISPATCH lists (D-008, D-009), so nested batches
 * expand in real code at every level. L-MS-3 covers the entry point and the bounds: 324 bytes admit
 * depth 2, `loop_iter 4` follows L-MS-2, recursion limits L-W0-RECUR. Deeper nesting is WAIVED-H-7,
 * covered outside CVL by those tests. */

using MultiSendPolicyHarness as msPolicy;
using RecorderPolicyHarness as leaf;

methods {
    // Engine to policy, the CALL at PolicyEngine.sol:200.
    function _.checkTransaction(
        address,
        address,
        uint256,
        bytes,
        SafePolicyGuardHarness.Operation,
        address,
        bytes,
        AccessSelector.T
    ) external => DISPATCH [ MultiSendPolicyHarness._, RecorderPolicyHarness._ ] default NONDET;

    // Policy back to engine, the re-entrant call at MultiSendPolicy.sol:39.
    function _.checkTransaction(
        address,
        address,
        uint256,
        bytes,
        SafePolicyGuardHarness.Operation,
        bytes
    ) external => DISPATCH [ SafePolicyGuardHarness._ ] default NONDET;

    // `configure` is never reached from this entry point and is kept out of the scene.

    function exactKey(address, bytes, SafePolicyGuardHarness.Operation) external returns (AccessSelector.T) envfree;

    function msPolicy.opDelegateCall() external returns (SafePolicyGuardHarness.Operation) envfree;

    function leaf.calls() external returns (uint256) envfree;
    function leaf.accept() external returns (bool) envfree;
}

// `$checkingSafe` is private (PolicyEngine.sol:35), so it is read by direct storage access (D-007).
definition checkingSafe() returns address = currentContract.$checkingSafe;
definition policyAt(address safe, AccessSelector.T key) returns address = currentContract.$policies[safe][key];

// The nested-scene batch bound (L-MS-3): 324 bytes admit depth 2, as the file header states.
definition MSN_MAX_BYTES() returns mathint = 324;

// R-MS-9 (denial at depth): if any transaction a nested batch expands to, at any depth, resolves to a denying policy,
// the top-level check cannot clear.
rule R_MS_9(
    env e,
    address safe,
    address to,
    uint256 value,
    bytes data,
    bytes context
) {
    // L-MS-3: the mid-check state the guard entry creates before calling the engine (SafePolicyGuard.sol:227,255,
    // PolicyEngine.sol:221-225); the engine's NotChecking and CrossSafeCheck gates then run unmodified on it.
    require safe != 0 && checkingSafe() == safe;
    require e.msg.sender != 0;  // L-W0-SENDER: msg.sender is never address(0) on chain
    require to_mathint(data.length) <= MSN_MAX_BYTES();
    // Scene selection: the top-level transaction is a batch served by MultiSendPolicy, and the leaf policy is a denier
    // whose counter starts fresh.
    require policyAt(safe, exactKey(to, data, msPolicy.opDelegateCall())) == msPolicy;
    require leaf.calls() == 0;
    require !leaf.accept();

    checkTransaction@withrevert(e, safe, to, value, data, msPolicy.opDelegateCall(), context);
    bool cleared = !lastReverted;

    assert cleared => leaf.calls() == 0,
        "a batch cannot clear once any transaction it expands to - at any depth - reaches a denying policy";
}
