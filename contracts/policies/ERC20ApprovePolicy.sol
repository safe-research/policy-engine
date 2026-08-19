// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IERC20} from "../interfaces/IERC20.sol";
import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {Permission} from "../interfaces/Permission.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title ERC-20 Approve Policy
 * @dev Allow ERC-20 approvals only for specific spender addresses.
 * @dev `approve(spender, 0)` is permitted for any spender, so revoking never depends on the
 *      allowlist. Any spender's allowance can therefore be zeroed regardless of configuration.
 * @dev A spender may be allowed indefinitely or once; a {Permission.ONCE} grant is spent by the
 *      approval that uses it. A zero-amount approval bypasses the allowlist, so it spends nothing.
 */
contract ERC20ApprovePolicy is IPolicy {
    using AccessSelector for AccessSelector.T;

    /**
     * @notice Spender data structure.
     * @param spender The spender address.
     * @param permission How often the spender may be approved.
     */
    struct SpenderData {
        address spender;
        Permission permission;
    }

    /**
     * @dev Mapping of spenders for each Safe and token.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(address token => mapping(address spender => Permission))))
        private $spenders;

    /**
     * @notice Error indicating the approval is invalid.
     */
    error InvalidApproval();

    /**
     * @notice Error indicating the spender is not on the Safe's allowlist for this token.
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
        address,
        bytes calldata,
        AccessSelector.T
    ) external override returns (bytes4 magicValue) {
        address token = to;
        (address spender, uint256 amount) = _decodeERC20Approve(data);
        // Revoking an allowance is always permitted, and leaves any grant untouched.
        if (amount != 0) {
            Permission permission = $spenders[msg.sender][safe][token][spender];
            require(permission != Permission.NONE, Unauthorized());
            if (permission == Permission.ONCE) {
                delete $spenders[msg.sender][safe][token][spender];
            }
        }
        return IPolicy.checkTransaction.selector;
    }

    function _decodeERC20Approve(bytes calldata data) internal pure returns (address spender, uint256 amount) {
        bytes4 selector = bytes4(data);
        if (selector != IERC20.approve.selector) {
            revert InvalidApproval();
        }
        (spender, amount) = abi.decode(data[4:], (address, uint256));
        return (spender, amount);
    }

    /**
     * @notice Configure the spender list for a Safe and token.
     * @param safe The Safe address.
     * @param access The access selector.
     * @param data ABI-encoded {SpenderData} array. Each entry sets or clears one spender, so a
     *        single call can both allow and revoke.
     * @dev Callable by anyone; state is namespaced by `msg.sender`, keeping the policy engine and policies logically separate.
     */
    function configure(address safe, AccessSelector.T access, bytes memory data) external returns (bool) {
        bytes4 selector = access.getSelector();
        Operation operation = access.getOperation();
        address target = access.getTarget();
        require(selector == IERC20.approve.selector, InvalidSelector());
        require(operation == Operation.CALL, InvalidOperation());
        SpenderData[] memory spenderList = abi.decode(data, (SpenderData[]));
        for (uint256 i = 0; i < spenderList.length; i++) {
            $spenders[msg.sender][safe][target][spenderList[i].spender] = spenderList[i].permission;
        }
        return true;
    }

    /**
     * @notice Get the permission recorded for a spender on a specific Safe and token.
     * @param policyGuard The address of the policy guard.
     * @param safe The Safe address.
     * @param token The token address.
     * @param spender The spender address.
     * @return permission How often the spender may still be approved.
     */
    function getSpenderPermission(
        address policyGuard,
        address safe,
        address token,
        address spender
    ) external view returns (Permission permission) {
        permission = $spenders[policyGuard][safe][token][spender];
    }
}
