// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Native Transfer Policy
 * @dev Allow native token transfers.
 * @dev The recipient comes from the access selector this is configured under, so it must be
 *      configured per target. The CALL fallback key also satisfies {configure}, where it permits any
 *      amount to any address, `address(0)` included.
 */
contract NativeTransferPolicy is IPolicy {
    using AccessSelector for AccessSelector.T;

    error InvalidTransfer();

    function checkTransaction(
        address,
        address,
        uint256 value,
        bytes calldata,
        Operation,
        address,
        bytes calldata,
        AccessSelector.T
    ) external pure override returns (bytes4 magicValue) {
        require(value > 0, InvalidTransfer());
        return IPolicy.checkTransaction.selector;
    }

    /**
     * @notice Configure the policy for native ETH transfer.
     */
    function configure(address, AccessSelector.T access, bytes memory) external pure override returns (bool) {
        return access.getSelector() == bytes4(0) && access.getOperation() == Operation.CALL;
    }
}
