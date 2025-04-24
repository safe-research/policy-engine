// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {IERC20} from "../interfaces/IERC20.sol";
import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title ERC-20 Approve Policy
 * @dev Allow ERC-20 approvals only for specific spender addresses.
 */
contract ERC20ApprovePolicy is IPolicy {
    using AccessSelector for AccessSelector.T;

    /**
     * @notice Spender data structure.
     * @param spender The spender address.
     * @param allowed Whether the spender is allowed to be approved.
     */
    struct SpenderData {
        address spender;
        bool allowed;
    }

    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(address token => mapping(address spender => bool))))
        private $spenders;

    /**
     * @notice Error indicating the approval is invalid.
     */
    error InvalidApproval();

    /**
     * @notice Error indicating the caller is unauthorized.
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
        (address spender, uint256 amount) = _decodeERC20Approve(data);
        require(amount == 0 || $spenders[msg.sender][safe][token][spender], Unauthorized());
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
     * @param data The spender address.
     * @dev This can only be called by the Safe Policy Guard.
     */
    function configure(address safe, AccessSelector.T access, bytes memory data) external returns (bool) {
        bytes4 selector = access.getSelector();
        Operation operation = access.getOperation();
        address target = access.getTarget();
        require(selector == IERC20.approve.selector, InvalidSelector());
        require(operation == Operation.CALL, InvalidOperation());
        SpenderData[] memory spenderList = abi.decode(data, (SpenderData[]));
        for (uint256 i = 0; i < spenderList.length; i++) {
            $spenders[msg.sender][safe][target][spenderList[i].spender] = spenderList[i].allowed;
        }
        return true;
    }
}
