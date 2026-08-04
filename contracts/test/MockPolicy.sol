// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Mock Policy
 * @dev This is written mainly for testing.
 */
contract MockPolicy is IPolicy {
    bool public revertTransaction;

    bool public revertConfigure;

    bool public revertCheckWithReason;

    /**
     * @notice Error carrying a payload, so tests can assert the engine forwards a policy's own
     *         revert data rather than replacing it.
     */
    error MockDenied(uint256 code);

    /**
     * @notice This function is used to set the revertTransaction flag.
     * @param revert_ The value to set the revertTransaction flag to.
     * @dev This function is used to control whether the checkTransaction function should revert or not.
     */
    function setRevertTransaction(bool revert_) external {
        revertTransaction = revert_;
    }

    /**
     * @notice This function is used to set the revertConfigure flag.
     * @param revert_ The value to set the revertConfigure flag to.
     * @dev This function is used to control whether the configure function should revert or not.
     */
    function setRevertConfigure(bool revert_) external {
        revertConfigure = revert_;
    }

    /**
     * @notice Makes `checkTransaction` actually revert, as opposed to `revertTransaction` which only
     *         returns a zero magic value.
     */
    function setRevertCheckWithReason(bool revert_) external {
        revertCheckWithReason = revert_;
    }

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
        address,
        bytes calldata,
        AccessSelector.T
    ) external view override returns (bytes4 magicValue) {
        require(!revertCheckWithReason, MockDenied(42));
        return revertTransaction ? magicValue : IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     * @dev This policy does not require any configuration.
     */
    function configure(address, AccessSelector.T, bytes memory) external view override returns (bool) {
        return !revertConfigure;
    }
}
