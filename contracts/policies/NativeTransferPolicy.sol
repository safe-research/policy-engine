// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Native Transfer Policy
 * @dev Allow plain native token transfers: a `CALL` with non-zero value and no calldata.
 * @dev The recipient comes from the access selector this is configured under, so it must be
 *      configured per target. The CALL fallback key also satisfies {configure}, where it permits
 *      any amount to any address, `address(0)` included. The engine also routes calls with
 *      calldata to that key when no more specific policy matches, so {checkTransaction} checks
 *      the calldata and the operation.
 */
contract NativeTransferPolicy is IPolicy {
    using AccessSelector for AccessSelector.T;

    /**
     * @notice Error indicating the transfer moves no value.
     */
    error InvalidTransfer();

    /**
     * @notice Error indicating the transaction carries calldata, which this policy never permits.
     */
    error CalldataNotPermitted();

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
        require(data.length == 0, CalldataNotPermitted());
        require(value > 0, InvalidTransfer());
        return IPolicy.checkTransaction.selector;
    }

    /**
     * @notice Configure the policy for native ETH transfer.
     * @dev The policy reads no configuration data, so it rejects non-empty data instead of
     *      ignoring it.
     */
    function configure(address, AccessSelector.T access, bytes memory data) external pure override returns (bool) {
        return access.getSelector() == bytes4(0) && access.getOperation() == Operation.CALL && data.length == 0;
    }
}
