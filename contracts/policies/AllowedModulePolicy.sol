// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Allowed Module Policy
 * @dev Allows any transaction from a particular module.
 */
contract AllowedModulePolicy is IPolicy {
    /**
     * @notice Mapping of allowed modules for each safe.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(address module => bool allowed)))
        private $allowedModules;

    /**
     * @notice Error indicating that the module is not allowed.
     */
    error UnauthorizedModule();

    /**
     * @notice Error indicating that the module address is invalid.
     */
    error InvalidModule();

    /**
     * @inheritdoc IPolicy
     * @dev This policy returns the magic value if it is an allowed module.
     */
    function checkTransaction(
        address safe,
        address,
        uint256,
        bytes calldata,
        Operation,
        bytes calldata context,
        AccessSelector.T
    ) external view override returns (bytes4 magicValue) {
        address module = abi.decode(context, (address));

        require($allowedModules[msg.sender][safe][module], UnauthorizedModule());

        return IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     * @dev This policy does not require any configuration.
     *      QUESTION: Should we allow DELEGATECALLs to be configured?
     */
    function configure(address safe, AccessSelector.T, bytes memory data) external override returns (bool) {
        address module = abi.decode(data, (address));

        $allowedModules[msg.sender][safe][module] = true;

        return true;
    }

    /**
     * @notice Check if a module is allowed for a given safe.
     * @param safe The address of the safe.
     * @param module The address of the module.
     * @return True if the module is allowed, false otherwise.
     */
    function isModuleAllowed(address policyGuard, address safe, address module) external view returns (bool) {
        return $allowedModules[policyGuard][safe][module];
    }
}
