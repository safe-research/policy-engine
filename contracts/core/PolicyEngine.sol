// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {IPolicy} from "../interfaces/IPolicy.sol";
import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {Operation} from "../interfaces/Operation.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Policy Engine
 */
abstract contract PolicyEngine is IPolicyEngine {
    using AccessSelector for AccessSelector.T;

    /**
     * @notice Mapping of policies for each safe.
     * @dev The mapping is structured as follows:
     * - The first mapping is the safe address.
     * - The second mapping is the access selector, which is a combination of the target address,
     *   function selector, and operation type.
     * - The value is the address of the policy contract.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address safe => mapping(AccessSelector.T => address policy)) private $policies;

    /**
     * @notice Error indicating an invalid selector was provided.
     */
    error InvalidSelector();

    /**
     * @notice Error indicating access was denied.
     * @param policy The address of the policy that denied access.
     * @dev This error is thrown when a policy denies access to a transaction.
     *      The address of the policy that denied access is provided for debugging purposes.
     *      The address(0) indicates that no policy was found for the given access selector.
     */
    error AccessDenied(address policy);

    /**
     * @notice Error indicating the policy configuration failed.
     */
    error PolicyConfigurationFailed();

    /**
     * @notice Event emitted when a policy is confirmed.
     * @param safe The address of the safe.
     * @param target The target address of the policy.
     * @param selector The function selector of the policy.
     * @param operation The operation type of the policy.
     * @param policy The address of the policy contract.
     * @param data Additional data for the policy configuration.
     * @dev TODO: Revisit data type and size concerns.
     */
    event PolicyConfirmed(
        address indexed safe,
        address indexed target,
        bytes4 selector,
        Operation operation,
        address policy,
        bytes data
    );

    /**
     * @inheritdoc IPolicyEngine
     */
    function getPolicy(
        address safe,
        address to,
        bytes calldata data,
        Operation operation
    ) public view returns (AccessSelector.T, address) {
        bytes4 selector = _decodeSelector(data);
        AccessSelector.T access = AccessSelector.create(to, selector, operation);

        mapping(AccessSelector.T => address) storage policies = $policies[safe];
        address policy = policies[access];

        // Use the fallback policy for the given operation if there is no specific one.
        if (policy == address(0)) {
            access = AccessSelector.createFallback(operation);
            policy = policies[access];
        }

        // TODO(nlordell): We can use additional fallback policies, if there aren't any matching the
        // first access selector. For example, we can fall back to one or more of:
        // - AccessSelector.create(to, bytes4(0), operation)
        // - AccessSelector.create(address(0), selector, operation)
        //
        // **In my opinion**, we should only fallback to `(address(0), bytes4(0), operation)` (i.e.
        // what we have here), as adding to many fallbacks would not be good for gas efficiency of
        // the Safenet use case where most transactions will fallthrough to the "catch all" policy.

        return (access, policy);
    }

    /**
     * @inheritdoc IPolicyEngine
     */
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes calldata context
    ) public returns (address) {
        (AccessSelector.T access, address policy) = getPolicy(safe, to, data, operation);
        require(policy != address(0), AccessDenied(address(0)));
        try IPolicy(policy).checkTransaction(safe, to, value, data, operation, context, access) returns (
            bytes4 magicValue
        ) {
            require(magicValue == IPolicy.checkTransaction.selector, AccessDenied(policy));
        } catch {
            revert AccessDenied(policy);
        }
        return policy;
    }

    /**
     * @notice Internal function to decode the function selector from the provided data.
     * @param data The data containing the function selector.
     * @return selector The decoded function selector.
     * @dev This function checks if the length of the data is at least 4 bytes.
     *      If the length is 0, it returns a zero selector. If the length is less than 4,
     *      it reverts with an InvalidSelector error.
     */
    function _decodeSelector(bytes calldata data) internal pure returns (bytes4 selector) {
        if (data.length >= 4) {
            return bytes4(data);
        } else if (data.length == 0) {
            return bytes4(0);
        } else {
            revert InvalidSelector();
        }
    }

    /**
     * @notice Internal function to confirm a policy for a given safe and access selector.
     * @param safe The address of the safe.
     * @param target The target address of the policy.
     * @param selector The function selector of the policy.
     * @param operation The operation type of the policy.
     * @param policy The address of the policy contract.
     * @param data Additional data for the policy configuration.
     */
    function _confirmPolicy(
        address safe,
        address target,
        bytes4 selector,
        Operation operation,
        address policy,
        bytes memory data
    ) internal {
        // Creating access selector for a policy
        AccessSelector.T access = AccessSelector.create(target, selector, operation);
        $policies[safe][access] = policy;

        // Configuring policy
        require(IPolicy(policy).configure(safe, access, data), PolicyConfigurationFailed());

        emit PolicyConfirmed(safe, target, selector, operation, policy, data);
    }
}
