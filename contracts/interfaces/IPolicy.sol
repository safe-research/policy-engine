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
     * @param context The context of the transaction.
     * @param access The access selector for the transaction.
     * @dev The function needs to implement policy validation logic (if any).
     */
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes calldata context,
        AccessSelector.T access
    ) external view returns (bytes4 magicValue);

    /**
     * @notice Configures the policy.
     * @param safe The address of the safe.
     * @param access The access selector for the transaction.
     * @param data Additional data for the policy configuration.
     * @return success Indicates whether the configuration was successful.
     */
    function configure(address safe, AccessSelector.T access, bytes memory data) external returns (bool success);
}
