// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {Operation} from "./Operation.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Policy Interface
 */
interface IPolicy {
    /**
     * @notice Checks the transaction details.
     * @param safe The address of the safe.
     * @param to The address to which the transaction is intended.
     * @param value The value of the transaction in Wei.
     * @param data The transaction data.
     * @param operation The type of operation of the transaction.
     * @param module The module that authorized the transaction, or `address(0)` for an owner
     *        transaction. The engine sources this from the guard entry point and not from `context`,
     *        so unlike `context` it can be trusted.
     * @param context Additional caller-supplied data, **untrusted on every path**: on the
     *        transaction path any executor can choose it (the Safe transaction hash does not cover
     *        `signatures`), and on the module path it is always empty. Never treat it as an identity
     *        claim — use `module` for that.
     * @param access The access selector for the transaction.
     * @dev Implements the policy validation logic. This function MAY mutate state (stateful
     *      policies are supported). To preserve the security properties the engine relies on,
     *      policy authors MUST:
     *      1. Prefer no external calls; if reading external state, use a `STATICCALL` (e.g. a
     *         `view` helper) so the callee cannot reenter.
     *      2. Never make a state-mutating external call to an untrusted address during the check.
     *      3. Key state by `msg.sender` (the calling engine/guard) and treat `safe` as untrusted
     *         input — i.e. namespace storage as `(msg.sender, safe)` — to avoid cross-guard interference.
     *      4. Follow checks-effects-interactions and bound gas/storage growth.
     */
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address module,
        bytes calldata context,
        AccessSelector.T access
    ) external returns (bytes4 magicValue);

    /**
     * @notice Configures the policy.
     * @param safe The address of the safe.
     * @param access The access selector for the transaction.
     * @param data Additional data for the policy configuration.
     * @return success Indicates whether the configuration was successful.
     * @dev Reachable by **any** address for itself: `configureImmediately` passes its caller as
     *      `safe`, so `safe`, `access` and `data` are all caller-chosen and `safe` need not be a
     *      Safe. Namespace state by `(msg.sender, safe)` as for {checkTransaction}, and validate
     *      `access` and `data` rather than assuming a configuration flow produced them.
     */
    function configure(address safe, AccessSelector.T access, bytes memory data) external returns (bool success);
}
