// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {Operation} from "../interfaces/Operation.sol";
import {ISafe} from "../interfaces/ISafe.sol";

contract TestModule {
    /**
     * @dev This function executes a transaction in Safe without any validation.
     */
    function executeTx(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) external returns (bool success) {
        return ISafe(safe).execTransactionFromModule(to, value, data, uint8(operation));
    }
}
