// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Context Recorder Policy
 * @dev Test-only policy that records the `context` the engine passed it and always allows. Lets a
 *      test assert what the guard decoded, rather than inferring it from another policy's verdict.
 */
contract ContextRecorderPolicy is IPolicy {
    bytes public lastContext;

    /**
     * @inheritdoc IPolicy
     */
    function checkTransaction(
        address,
        address,
        uint256,
        bytes calldata,
        Operation,
        address,
        bytes calldata context,
        AccessSelector.T
    ) external override returns (bytes4 magicValue) {
        lastContext = context;
        return IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     */
    function configure(address, AccessSelector.T, bytes memory) external pure override returns (bool) {
        return true;
    }
}
