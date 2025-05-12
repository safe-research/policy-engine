// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {IMultiSend} from "../interfaces/IMultiSend.sol";
import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Multi Send Policy
 * @dev Apply policies to all transactions in a `MultiSend.multiSend` transaction.
 */
contract MultiSendPolicy is IPolicy {
    using AccessSelector for AccessSelector.T;

    error InvalidMultiSend();

    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes calldata context,
        AccessSelector.T
    ) external view override returns (bytes4 magicValue) {
        bytes calldata transactions = _decodeMultiSendTransactions(data);
        bytes calldata ctx;
        while (transactions.length > 0) {
            (to, value, data, operation, transactions) = _decodeNextTransaction(transactions);
            (ctx, context) = _decodeNextContext(context);
            IPolicyEngine(msg.sender).checkTransaction(safe, to, value, data, operation, ctx);
        }

        return IPolicy.checkTransaction.selector;
    }

    function _decodeMultiSendTransactions(bytes calldata data) internal pure returns (bytes calldata) {
        require(bytes4(data[:4]) == IMultiSend.multiSend.selector, InvalidMultiSend());
        data = data[4:];

        uint256 offset = uint256(bytes32(data[:32]));
        data = data[offset:];
        uint256 length = uint256(bytes32(data[:32]));
        data = data[32:];

        return data[:length];
    }

    function _decodeNextTransaction(
        bytes calldata transactions
    ) internal pure returns (address to, uint256 value, bytes calldata data, Operation operation, bytes calldata rest) {
        operation = Operation(uint8(transactions[0]));
        to = address(uint160(bytes20(transactions[1:21])));
        value = uint256(bytes32(transactions[21:53]));
        uint256 dataLength = uint256(bytes32(transactions[53:85]));
        data = transactions[85:85 + dataLength];

        rest = transactions[85 + dataLength:];
    }

    function _decodeNextContext(
        bytes calldata context
    ) internal pure returns (bytes calldata ctx, bytes calldata rest) {
        if (context.length == 0) {
            return (context, context);
        }

        uint256 length = uint256(bytes32(context[:32]));
        uint256 end = 32 + length;
        ctx = context[32:end];
        rest = context[end:];
    }

    /**
     * @notice Configure the policy for the `MultiSend.multiSend` transaction.
     */
    function configure(address, AccessSelector.T access, bytes memory) external pure override returns (bool) {
        return access.getSelector() == IMultiSend.multiSend.selector && access.getOperation() == Operation.DELEGATECALL;
    }
}
