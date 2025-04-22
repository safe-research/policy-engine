// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {Operation} from "../interfaces/Operation.sol";

/**
 * @title Safe Policy Access Selector
 * @dev Library for creating and unpacking access selectors for Safe transactions. These selectors
 *      are mapped to policies, that either allow or disallow Safe transactions from executing.
 */
library AccessSelector {
    /**
     * @dev The selector is a packed 32-byte word with the following layout:
     *
     *       | 00000000001111111111222222222233
     *  byte | 01234567890123456789012345678901
     * ------+----------------------------------
     *  data | sssso       tttttttttttttttttttt
     *
     * - _ssss_: The 4-byte function selector.
     * - _o_: The operation.
     * - _tttttttttttttttttttt_: The target address.
     */
    type T is uint256;

    /**
     * @dev Creates a new access selector with the given operation, selector, and target
     * @param to Target address
     * @param selector Function selector
     * @param operation Operation type (CALL or DELEGATECALL)
     * @return An access selector containing the packed components
     */
    function create(address to, bytes4 selector, Operation operation) internal pure returns (T) {
        uint256 packed = uint256(uint160(to)) | uint256(bytes32(selector)) | (uint256(operation) << 216);
        return T.wrap(packed);
    }

    function createFallback(Operation operation) internal pure returns (T) {
        return T.wrap(uint256(operation) << 216);
    }

    /**
     * @dev Extracts the target address from an access selector
     * @param self The access selector
     * @return The target address
     */
    function getTarget(T self) internal pure returns (address) {
        return address(uint160(T.unwrap(self)));
    }

    /**
     * @dev Extracts the function selector from an access selector
     * @param self The access selector
     * @return The function selector
     */
    function getSelector(T self) internal pure returns (bytes4) {
        return bytes4(bytes32(T.unwrap(self)));
    }

    /**
     * @dev Extracts the operation type from an access selector
     * @param self The access selector
     * @return The operation type (OP_CALL or OP_DELEGATECALL)
     */
    function getOperation(T self) internal pure returns (Operation) {
        return Operation((T.unwrap(self) >> 216) & 1);
    }
}
