// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {Operation} from "./Operation.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Policy Engine Interface
 */
interface IPolicyEngine {
    /**
     * @notice Function to get the policy for a given safe and access selector.
     * @param safe The address of the safe.
     * @param to The target address of the transaction.
     * @param data The data sent in the transaction.
     * @param operation The operation type (CALL or DELEGATECALL).
     * @return selector The access selector for the transaction.
     * @return policy The address of the policy contract.
     */
    function getPolicy(
        address safe,
        address to,
        bytes calldata data,
        Operation operation
    ) external view returns (AccessSelector.T, address);

    /**
     * @notice Checks the transaction details.
     * @param safe The address of the safe.
     * @param to The address to which the transaction is intended.
     * @param value The value of the transaction in Wei.
     * @param data The transaction data.
     * @param operation The type of operation of the transaction.
     * @param context The context of the transaction.
     * @dev The function needs to implement policy validation check.
     */
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes calldata context
    ) external view returns (address);
}
