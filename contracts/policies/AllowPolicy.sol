// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Allow Policy
 * @dev Allows a transaction.
 */
contract AllowPolicy is IPolicy {
    /**
     * @inheritdoc IPolicy
     * @dev This policy always returns the magic value for a particular access selector.
     */
    function checkTransaction(
        address,
        address,
        uint256,
        bytes calldata,
        Operation,
        bytes calldata,
        AccessSelector.T
    ) external pure override returns (bytes4 magicValue) {
        return IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     * @dev This policy does not require any configuration.
     */
    function configure(address, AccessSelector.T, bytes memory) external pure override returns (bool) {
        return true;
    }
}
