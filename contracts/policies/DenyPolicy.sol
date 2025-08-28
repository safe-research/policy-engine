// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Deny Policy
 * @dev Denies a transaction.
 */
contract DenyPolicy is IPolicy {
    /**
     * @inheritdoc IPolicy
     * @dev This policy always returns zero selector for a particular access selector.
     *      This is to deny a certain transaction always.
     */
    // solhint-disable no-empty-blocks
    function checkTransaction(
        address,
        address,
        uint256,
        bytes calldata,
        Operation,
        bytes calldata,
        AccessSelector.T
    ) external pure override returns (bytes4 magicValue) {}
    // solhint-enable no-empty-blocks

    /**
     * @inheritdoc IPolicy
     * @dev This policy does not require any configuration.
     */
    function configure(address, AccessSelector.T, bytes memory) external pure override returns (bool) {
        return true;
    }
}
