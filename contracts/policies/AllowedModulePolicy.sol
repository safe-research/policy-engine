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
     * @dev This policy returns the magic value if it is an allowed module. The zero check confines
     *      it to the module path, since `module` is engine-supplied and `address(0)` for owner
     *      transactions. Never read the module from `context`, which any executor can choose.
     */
    function checkTransaction(
        address safe,
        address,
        uint256,
        bytes calldata,
        Operation,
        address module,
        bytes calldata,
        AccessSelector.T
    ) external view override returns (bytes4 magicValue) {
        require(module != address(0), InvalidModule());
        require($allowedModules[msg.sender][safe][module], UnauthorizedModule());

        return IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     * @param data ABI-encoded `(address module, bool allowed)`. Pass `false` to revoke a module that
     *        was previously allowed.
     * @dev Both granting and revoking go through here, so an authorisation can be withdrawn without
     *      detaching the policy from its access selector. Note the allowlist is namespaced by
     *      `(msg.sender, safe)` and survives the policy being detached and later re-attached, so a
     *      revocation must be applied explicitly rather than implied by removing the policy.
     */
    function configure(address safe, AccessSelector.T, bytes memory data) external override returns (bool) {
        (address module, bool allowed) = abi.decode(data, (address, bool));
        // A zero entry would match every owner transaction, making this policy an allow-all.
        require(module != address(0), InvalidModule());

        $allowedModules[msg.sender][safe][module] = allowed;

        return true;
    }

    /**
     * @notice Check if a module is allowed for a given safe.
     * @param policyGuard The policy guard that configured the entry. State is namespaced by the
     *        configuring caller, so reading another namespace returns `false`.
     * @param safe The address of the safe.
     * @param module The address of the module.
     * @return True if the module is allowed, false otherwise.
     */
    function isModuleAllowed(address policyGuard, address safe, address module) external view returns (bool) {
        return $allowedModules[policyGuard][safe][module];
    }
}
