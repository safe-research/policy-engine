// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title One Time Allow Policy
 * @dev Allows a single transaction for an access selector, then denies until reconfigured.
 * @dev Keyed by the access selector the engine resolved, so a grant on a fallback authorises one
 *      *arbitrary* transaction of that operation kind rather than one specific one.
 * @dev Re-arming is a configuration change, so it goes through the guard's delay once installed.
 */
contract OneTimeAllowPolicy is IPolicy {
    /**
     * @dev Whether an unspent grant exists, for each policy guard, Safe and access selector.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(AccessSelector.T access => bool granted)))
        private $grants;

    /**
     * @notice Error indicating no unspent grant exists for the access selector.
     */
    error Unauthorized();

    /**
     * @inheritdoc IPolicy
     * @dev Spends the grant, so a batch replaying the same sub-transaction is allowed exactly once.
     */
    function checkTransaction(
        address safe,
        address,
        uint256,
        bytes calldata,
        Operation,
        address,
        bytes calldata,
        AccessSelector.T access
    ) external override returns (bytes4 magicValue) {
        require($grants[msg.sender][safe][access], Unauthorized());
        delete $grants[msg.sender][safe][access];
        return IPolicy.checkTransaction.selector;
    }

    /**
     * @notice Grants or revokes the single use for a Safe and access selector.
     * @param safe The Safe address.
     * @param access The access selector.
     * @param data ABI-encoded `bool`: `true` grants the single use, `false` revokes an unspent one.
     * @dev Callable by anyone; state is namespaced by `msg.sender`, keeping the policy engine and
     *      policies logically separate.
     */
    function configure(address safe, AccessSelector.T access, bytes memory data) external override returns (bool) {
        $grants[msg.sender][safe][access] = abi.decode(data, (bool));
        return true;
    }

    /**
     * @notice Whether an unspent grant exists.
     * @param policyGuard The policy guard address.
     * @param safe The Safe address.
     * @param access The access selector.
     * @return granted Whether the access selector may still be used once.
     */
    function isGranted(
        address policyGuard,
        address safe,
        AccessSelector.T access
    ) external view returns (bool granted) {
        granted = $grants[policyGuard][safe][access];
    }
}
