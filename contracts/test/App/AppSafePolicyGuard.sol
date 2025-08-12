// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {SafePolicyGuard, AccessSelector} from "../../SafePolicyGuard.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title App Safe Policy Guard
 * @dev Used for Safe App demo purposes.
 */
contract AppSafePolicyGuard is SafePolicyGuard {
    using AccessSelector for AccessSelector.T;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /**
     * @notice Configuration roots which are either pending or confirmed.
     */
    mapping(address => EnumerableSet.Bytes32Set) private _configureRoots;

    /**
     * @notice Configuration mapping for each root.
     */
    mapping(bytes32 => Configuration[]) private _configurations;

    /**
     * @notice Thrown when a root is not configured yet.
     */
    error RootNotConfiguredYet(bytes32 configureRoot);

    /**
     * @param delay The delay for the configuration change.
     */
    constructor(uint256 delay) SafePolicyGuard(delay) {}

    /**
     * @notice Configures and confirms multiple policies for an address.
     * @param configurations The array of configurations to be applied.
     * @dev This does not have to check if the guard is enabled, as if the guard is set,
     *      then this tx will fail in `checkTransaction`.
     *      This is a convenience function to avoid having to call `configurePolicy` and then
     *      `confirmPolicy` separately with a delay.
     */
    function configureImmediately(Configuration[] calldata configurations) external override {
        bytes32 configureRoot = keccak256(abi.encode(configurations));

        // Store the configurations for this root
        _configureRoots[msg.sender].add(configureRoot);
        _configurations[configureRoot] = configurations;

        // Apply the policies immediately
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
}
