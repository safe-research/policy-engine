// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

/**
 * @title Operation
 * @dev Enum representing the operation of a Safe transaction.
 */
enum Operation {
    CALL,
    DELEGATECALL
}
