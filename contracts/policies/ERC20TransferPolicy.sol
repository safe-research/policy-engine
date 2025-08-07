// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {IERC20} from "../interfaces/IERC20.sol";
import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title ERC-20 Transfer Policy
 * @dev Allow ERC-20 transfers only to a specific address list.
 */
contract ERC20TransferPolicy is IPolicy {
    using AccessSelector for AccessSelector.T;

    /**
     * @notice Recipient data structure.
     * @param recipient The recipient address.
     * @param allowed Whether the recipient is allowed to receive tokens.
     */
    struct RecipientData {
        address recipient;
        bool allowed;
    }

    /**
     * @dev Mapping of recipients for each Safe and token.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(address token => mapping(address recipient => bool))))
        private $recipients;

    /**
     * @notice Error indicating the transfer is invalid.
     */
    error InvalidTransfer();

    /**
     * @notice Error indicating the caller is not authorized.
     */
    error Unauthorized();

    /**
     * @notice Error indicating the selector is invalid.
     */
    error InvalidSelector();

    /**
     * @notice Error indicating the operation is invalid.
     */
    error InvalidOperation();

    function checkTransaction(
        address safe,
        address to,
        uint256,
        bytes calldata data,
        Operation,
        bytes calldata,
        AccessSelector.T
    ) external view override returns (bytes4 magicValue) {
        address token = to;
        address recipient = _decodeERC20Transfer(data);
        require($recipients[msg.sender][safe][token][recipient], Unauthorized());
        return IPolicy.checkTransaction.selector;
    }

    function _decodeERC20Transfer(bytes calldata data) internal pure returns (address recipient) {
        bytes4 selector = bytes4(data);
        if (selector == IERC20.transfer.selector) {
            (recipient, ) = abi.decode(data[4:], (address, uint256));
        } else if (selector == IERC20.transferFrom.selector) {
            (, recipient, ) = abi.decode(data[4:], (address, address, uint256));
        } else {
            revert InvalidTransfer();
        }
        return recipient;
    }

    /**
     * @notice Configure the recipient list for a Safe and token.
     * @param safe The Safe address.
     * @param access The access selector.
     * @param data The recipient address.
     * @dev This can only be called by the Safe Policy Guard.
     */
    function configure(address safe, AccessSelector.T access, bytes memory data) external returns (bool) {
        bytes4 selector = access.getSelector();
        Operation operation = access.getOperation();
        address target = access.getTarget();
        require(selector == IERC20.transfer.selector || selector == IERC20.transferFrom.selector, InvalidSelector());
        require(operation == Operation.CALL, InvalidOperation());
        RecipientData[] memory recipientList = abi.decode(data, (RecipientData[]));
        for (uint256 i = 0; i < recipientList.length; i++) {
            // solhint-disable-next-line reentrancy
            $recipients[msg.sender][safe][target][recipientList[i].recipient] = recipientList[i].allowed;
        }
        return true;
    }

    /**
     * @notice Check if a recipient is allowed for a specific Safe and token.
     * @param policyGuard The policy guard address.
     * @param safe The Safe address.
     * @param token The token address.
     * @param recipient The recipient address.
     * @return bool Whether the recipient is allowed.
     */
    function isRecipientAllowed(
        address policyGuard,
        address safe,
        address token,
        address recipient
    ) external view returns (bool) {
        return $recipients[policyGuard][safe][token][recipient];
    }
}
