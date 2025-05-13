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
     * @dev The mapping is structured as follows:
     * - The first key is the address of the policy guard.
     * - The second key is the address of the safe.
     * - The third key is the address of the module.
     * - The value is a boolean indicating whether the module is allowed or not.
     */
    mapping(address => mapping(address => mapping(address => bool))) public allowedModules;

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

        require(allowedModules[msg.sender][safe][module], UnauthorizedModule());

        return IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     * @dev This policy does not require any configuration.
     *      QUESTION: Should we allow DELEGATECALLs to be configured?
     */
    function configure(address safe, AccessSelector.T, bytes memory data) external override returns (bool) {
        address module = abi.decode(data, (address));

        allowedModules[msg.sender][safe][module] = true;

        return true;
    }
}
