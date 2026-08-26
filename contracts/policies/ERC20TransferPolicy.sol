// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IERC20} from "../interfaces/IERC20.sol";
import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {Permission} from "../interfaces/Permission.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title ERC-20 Transfer Policy
 * @dev Allow ERC-20 transfers only to a specific address list.
 * @dev `transferFrom`'s `from` argument is deliberately unconstrained: the policy restricts where
 *      tokens may go, not whose tokens they are.
 * @dev A recipient may be allowed indefinitely or once; a {Permission.ONCE} grant is spent by
 *      the transfer that uses it.
 */
contract ERC20TransferPolicy is IPolicy {
    using AccessSelector for AccessSelector.T;

    /**
     * @notice Recipient data structure.
     * @param recipient The recipient address.
     * @param permission How often the recipient may receive tokens.
     */
    struct RecipientData {
        address recipient;
        Permission permission;
    }

    /**
     * @dev Mapping of recipients for each Safe and token.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(address token => mapping(address recipient => Permission))))
        private $recipients;

    /**
     * @notice Error indicating the transfer is invalid.
     */
    error InvalidTransfer();

    /**
     * @notice Error indicating the recipient is not on the Safe's allowlist for this token.
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

    /**
     * @notice Emitted whenever the permission recorded for a recipient changes.
     * @param policyGuard The policy guard whose namespace the permission belongs to.
     * @param safe The Safe address.
     * @param token The token address.
     * @param recipient The recipient address.
     * @param permission How often the recipient may still receive tokens, after the change.
     * @dev Emitted on every write to the allowlist -- both {configure} and the transfer that spends
     *      a {Permission.ONCE} grant -- so the log replays the policy's state on its own, with no
     *      `eth_call` needed. {Permission.NONE} means the recipient is no longer allowlisted.
     */
    event RecipientPermissionChanged(
        address indexed policyGuard,
        address indexed safe,
        address indexed token,
        address recipient,
        Permission permission
    );

    function checkTransaction(
        address safe,
        address to,
        uint256,
        bytes calldata data,
        Operation,
        address,
        bytes calldata,
        AccessSelector.T
    ) external override returns (bytes4 magicValue) {
        address token = to;
        address recipient = _decodeERC20Transfer(data);
        Permission permission = $recipients[msg.sender][safe][token][recipient];
        require(permission != Permission.NONE, Unauthorized());
        if (permission == Permission.ONCE) {
            delete $recipients[msg.sender][safe][token][recipient];
            emit RecipientPermissionChanged(msg.sender, safe, token, recipient, Permission.NONE);
        }
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
     * @param data ABI-encoded {RecipientData} array. Each entry sets or clears one recipient, so a
     *        single call can both allow and revoke.
     * @dev Callable by anyone; state is namespaced by `msg.sender`, keeping the policy engine and policies logically separate.
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
            $recipients[msg.sender][safe][target][recipientList[i].recipient] = recipientList[i].permission;
            emit RecipientPermissionChanged(
                msg.sender,
                safe,
                target,
                recipientList[i].recipient,
                recipientList[i].permission
            );
        }
        return true;
    }

    /**
     * @notice Get the permission recorded for a recipient on a specific Safe and token.
     * @param policyGuard The policy guard address.
     * @param safe The Safe address.
     * @param token The token address.
     * @param recipient The recipient address.
     * @return permission How often the recipient may still receive tokens.
     */
    function getRecipientPermission(
        address policyGuard,
        address safe,
        address token,
        address recipient
    ) external view returns (Permission permission) {
        permission = $recipients[policyGuard][safe][token][recipient];
    }
}
