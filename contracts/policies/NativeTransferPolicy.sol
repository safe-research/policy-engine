// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Native Transfer Policy
 * @dev Allow native token transfers, and only those: a `CALL` carrying a non-zero value and no
 *      calldata.
 * @dev The recipient comes from the access selector this is configured under, so it must be
 *      configured per target. The CALL fallback key also satisfies {configure}, where it permits
 *      any amount to any address, `address(0)` included. Under that key the engine routes every
 *      call without a more specific policy here, including ones with calldata, so the policy
 *      re-checks the transaction shape instead of inferring it from the key it was reached by.
 */
contract NativeTransferPolicy is IPolicy {
    using AccessSelector for AccessSelector.T;

    /**
     * @notice Error indicating the transfer moves no value.
     */
    error InvalidTransfer();

    /**
     * @notice Error indicating the transaction carries calldata.
     */
    error InvalidCalldata();

    /**
     * @notice Error indicating the operation is invalid.
     */
    error InvalidOperation();

    function checkTransaction(
        address,
        address,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address,
        bytes calldata,
        AccessSelector.T
    ) external pure override returns (bytes4 magicValue) {
        require(operation == Operation.CALL, InvalidOperation());
        require(data.length == 0, InvalidCalldata());
        require(value > 0, InvalidTransfer());
        return IPolicy.checkTransaction.selector;
    }

    /**
     * @notice Configure the policy for native ETH transfer.
     * @dev Takes no configuration data; non-empty data is rejected rather than ignored, so a
     *      configuration that expects this policy to read it fails loudly.
     */
    function configure(address, AccessSelector.T access, bytes memory data) external pure override returns (bool) {
        return access.getSelector() == bytes4(0) && access.getOperation() == Operation.CALL && data.length == 0;
    }
}
