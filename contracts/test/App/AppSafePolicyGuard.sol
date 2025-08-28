// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {SafePolicyGuard, AccessSelector, Operation} from "../../SafePolicyGuard.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IPolicy} from "../../interfaces/IPolicy.sol";
// solhint-disable-next-line no-unused-import
import {IPolicyEngine} from "../../interfaces/IPolicyEngine.sol";

/**
 * @title App Safe Policy Guard
 * @dev Used for Safe App demo purposes.
 */
contract AppSafePolicyGuard is SafePolicyGuard {
    using AccessSelector for AccessSelector.T;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.UintSet;

    /**
     * @notice Configuration roots which are pending.
     */
    mapping(address safe => EnumerableSet.Bytes32Set) private _configureRoots;

    /**
     * @notice Configuration mapping for each root.
     */
    mapping(bytes32 configureRoot => Configuration[]) private _configurations;

    /**
     * @notice Mapping of safe to it's approved access selectors.
     */
    mapping(address safe => EnumerableSet.UintSet) private _accesses;

    /**
     * @notice Mapping of safe to it's approved access data.
     */
    mapping(address safe => mapping(uint256 access => bytes data)) private _accessData;

    /**
     * @notice Thrown when a root is not configured yet.
     */
    error RootNotConfiguredYet(bytes32 configureRoot);

    /**
     * @param delay The delay for the configuration change.
     */
    constructor(uint256 delay) SafePolicyGuard(delay) {}

    /**
     * @dev TODO: Consider the security considerations of calling `checkTransaction` as a Safe transaction,
     *      this can matter because the Safe can potentially modify state and might lead to unexpected interactions.
     */
    function _allowedCalls(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) internal view override returns (bool) {
        bytes4 selector = _decodeSelector(data);

        // Invalidate Root
        bool invalidateRootCall = to == address(this) &&
            value == 0 &&
            selector == this.invalidateRoot.selector &&
            operation == Operation.CALL;

        // Configure or confirm policy
        bool requestOrApplyConfiguration = to == address(this) &&
            value == 0 &&
            (selector == this.requestConfiguration.selector ||
                selector == this.complementRequestConfiguration.selector ||
                selector == this.applyConfiguration.selector) &&
            operation == Operation.CALL;

        return requestOrApplyConfiguration || invalidateRootCall;
    }

    /**
     * @notice Requests a policy configuration change.
     * @param configureRoot The root of the configuration to be applied.
     * @dev This can be used to set multiple policies at once.
     */
    function requestConfiguration(bytes32 configureRoot) external override {
        require(rootConfigured[msg.sender][configureRoot] == 0, RootAlreadyConfigured(configureRoot));
        rootConfigured[msg.sender][configureRoot] = block.timestamp + DELAY;
        emit RootConfigured(msg.sender, configureRoot, block.timestamp + DELAY);
    }

    /**
     * @notice Compliments a previously requested policy configuration change.
     * @param configurations The array of configurations to be applied.
     * @dev This function allows adding the configuration details to the root for the safe app.
     */
    function complementRequestConfiguration(Configuration[] calldata configurations) external {
        bytes32 configureRoot = keccak256(abi.encode(configurations));
        require(rootConfigured[msg.sender][configureRoot] != 0, RootNotConfiguredYet(configureRoot));
        _configureRoots[msg.sender].add(configureRoot);
        _configurations[configureRoot] = configurations;
    }

    /**
     * @notice Invalidates a policy configuration change.
     * @param configureRoot The root of the configuration to be invalidated.
     * @dev Invalidation can only be done if the configuration is pending.
     *      This is not behind a delay, as only pending configurations can be invalidated, and
     *      this allows invalidating unintended policies immediately before it is confirmed.
     */
    function invalidateRoot(bytes32 configureRoot) external override {
        require(rootConfigured[msg.sender][configureRoot] != 0, RootNotConfigured(configureRoot));
        delete rootConfigured[msg.sender][configureRoot];
        _configureRoots[msg.sender].remove(configureRoot);
        delete _configurations[configureRoot];
        emit RootInvalidated(msg.sender, configureRoot);
    }

    /**
     * @notice Applies a policy configuration change.
     * @param configurations The array of configurations to be applied.
     * @dev This can be used to set multiple policies at once.
     */
    function applyConfiguration(Configuration[] calldata configurations) external override {
        bytes32 configureRoot = keccak256(abi.encode(configurations));
        require(rootConfigured[msg.sender][configureRoot] != 0, RootNotConfigured(configureRoot));
        require(block.timestamp >= rootConfigured[msg.sender][configureRoot], RootConfigurationPending());
        delete rootConfigured[msg.sender][configureRoot];
        _configureRoots[msg.sender].remove(configureRoot);
        delete _configurations[configureRoot];
        for (uint256 i = 0; i < configurations.length; i++) {
            _confirmPolicy(
                msg.sender,
                configurations[i].target,
                configurations[i].selector,
                configurations[i].operation,
                configurations[i].policy,
                configurations[i].data
            );
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
    ) internal override {
        // Creating access selector for a policy
        AccessSelector.T access = AccessSelector.create(target, selector, operation);

        // Update the policy mapping
        _updatePolicy(safe, access, policy);

        if (policy != address(0)) {
            _accesses[safe].add(AccessSelector.T.unwrap(access));
            _accessData[safe][AccessSelector.T.unwrap(access)] = data;
        } else {
            // Remove from tracking when policy is set to zero address
            _accesses[safe].remove(AccessSelector.T.unwrap(access));
            delete _accessData[safe][AccessSelector.T.unwrap(access)];
        }

        // Configuring policy
        if (policy != address(0)) {
            require(IPolicy(policy).configure(safe, access, data), PolicyConfigurationFailed());
        }

        emit PolicyConfirmed(safe, target, selector, operation, policy, data);
    }

    /**
     * @notice Gets the configurations for a given configuration root.
     * @param configureRoot The root hash of the configurations.
     * @return The array of configurations.
     */
    function getConfigurations(bytes32 configureRoot) external view returns (Configuration[] memory) {
        return _configurations[configureRoot];
    }

    /**
     * @notice Gets all configuration roots for a safe address.
     * @param safe The safe address.
     * @return The array of configuration root hashes.
     */
    function getConfigurationRoots(address safe) external view returns (bytes32[] memory) {
        return _configureRoots[safe].values();
    }

    /**
     * @notice Gets the accesses for a given safe address.
     * @param safe The safe address.
     * @return The array of access selectors as uint256 values.
     */
    function getAccesses(address safe) external view returns (uint256[] memory) {
        return _accesses[safe].values();
    }

    /**
     * @notice Gets the access information for a given access selector.
     * @param access The access selector as a uint256 value.
     * @return target The target address.
     * @return selector The function selector.
     * @return operation The operation type.
     */
    function getAccessInfo(
        address safe,
        uint256 access
    ) external view returns (address target, bytes4 selector, Operation operation, bytes memory data) {
        AccessSelector.T accessSelector = AccessSelector.T.wrap(access);
        target = AccessSelector.getTarget(accessSelector);
        selector = AccessSelector.getSelector(accessSelector);
        operation = AccessSelector.getOperation(accessSelector);
        data = _accessData[safe][access];
    }
}
