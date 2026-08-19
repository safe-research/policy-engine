// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Reentrant Configure Policy
 * @dev Test-only policy that re-enters the guard's `applyConfiguration` from its own `configure`
 *      hook, to prove the pending root is consumed before any policy is called. It records the
 *      revert data so the test can assert which error fired.
 */
contract ReentrantConfigurePolicy is IPolicy {
    bytes public lastReentryError;
    bool public reenterSucceeded;

    // solhint-disable-next-line private-vars-leading-underscore
    bytes private $reentrantCalldata;

    /**
     * @notice Sets the `applyConfiguration` calldata to replay during `configure`.
     */
    function setReentrantCalldata(bytes calldata reentrantCalldata) external {
        $reentrantCalldata = reentrantCalldata;
    }

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
        bytes calldata,
        AccessSelector.T
    ) external pure override returns (bytes4 magicValue) {
        return IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     */
    function configure(address, AccessSelector.T, bytes memory) external override returns (bool) {
        // Deliberately a low-level call: the point is to replay arbitrary calldata against the
        // guard mid-configuration and observe the revert rather than propagate it.
        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returnData) = msg.sender.call($reentrantCalldata);
        if (success) {
            reenterSucceeded = true;
        } else {
            lastReentryError = returnData;
        }

        return true;
    }
}
