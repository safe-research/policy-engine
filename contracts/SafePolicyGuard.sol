// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {PolicyEngine, AccessSelector} from "./core/PolicyEngine.sol";
import {IERC165} from "./interfaces/IERC165.sol";
import {ISafeModuleGuard} from "./interfaces/ISafeModuleGuard.sol";
import {ISafeTransactionGuard} from "./interfaces/ISafeTransactionGuard.sol";
import {Operation} from "./interfaces/Operation.sol";

/**
 * @title Safe Policy Guard
 * @dev Apply security policy to all Safe transactions.
 */
contract SafePolicyGuard is PolicyEngine, ISafeModuleGuard, ISafeTransactionGuard {
    using AccessSelector for AccessSelector.T;

    /**
     * @notice The configuration data struct for a policy.
     * @custom:member target The target address for the policy.
     * @custom:member selector The selector for the policy.
     * @custom:member operation The operation for the policy.
     * @custom:member policy The policy address.
     * @custom:member data The data for the policy.
     */
    struct Configuration {
        address target;
        bytes4 selector;
        Operation operation;
        address policy;
        bytes data;
    }

    /**
     * @notice The delay for the configuration change and guard removal.
     */
    uint256 public immutable DELAY;

    /**
     * @notice The pending policies root for a Safe.
     * @dev The mapping is structured as follows:
     *      safe address where policies are pending => configuration root => timestamp when policy can be confirmed.
     */
    mapping(address => mapping(bytes32 => uint256)) public rootConfigured;

    // TODO(nlordell): The access control mechanism currently only checks transaction pre-conditions
    // and not post conditions. If we decide that post checks in policies are needed, we could use
    // an execution stack to push policies to check post-executions for. This would have a large
    // impact on gas - although we can use things like transient storage to offset it a little.
    // Stack.T $afterExecutionChecks;

    /**
     * @notice Error indicating the root is already configured.
     * @param root The root that is already configured.
     */
    error RootAlreadyConfigured(bytes32 root);

    /**
     * @notice Error indicating non zero gas price is not allowed.
     */
    error NonZeroGasPrice();

    /**
     * @notice Error indicating the root is not configured.
     * @param root The root that is not configured.
     */
    error RootNotConfigured(bytes32 root);

    /**
     * @notice Error indicating the policy root configuration is pending.
     */
    error RootConfigurationPending();

    /**
     * @notice Emitted when a policy root is configured.
     * @param safe The address of the Safe.
     * @param root The root is a hash of the policy configurations.
     * @param timestamp The timestamp when the policy can be confirmed.
     */
    event RootConfigured(address indexed safe, bytes32 indexed root, uint256 timestamp);

    /**
     * @notice Emitted when a policy root is invalidated.
     * @param safe The address of the Safe.
     * @param root The root is a hash of the policy configurations.
     */
    event RootInvalidated(address indexed safe, bytes32 indexed root);

    /**
     * @param delay The delay for the configuration change.
     */
    constructor(uint256 delay) {
        DELAY = delay;
    }

    /**
     * @inheritdoc IERC165
     */
    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return
            interfaceId == type(ISafeModuleGuard).interfaceId || // 0x58401ed8
            interfaceId == type(ISafeTransactionGuard).interfaceId || // 0xe6d7a83a
            interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }

    /**
     * @dev TODO: Consider the security considerations of calling `checkTransaction` as a Safe transaction,
     *      this can matter because the Safe can potentially modify state and might lead to unexpected interactions.
     */
    function _allowedCalls(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) internal returns (bool) {
        bytes4 selector = _decodeSelector(data);

        // Invalidate Root
        bool invalidateRootCall = to == address(this) &&
            value == 0 &&
            selector == this.invalidateRoot.selector &&
            operation == Operation.CALL;

        // Configure or confirm policy
        bool requestOrApplyConfiguration = to == address(this) &&
            value == 0 &&
            (selector == this.requestConfiguration.selector || selector == this.applyConfiguration.selector) &&
            operation == Operation.CALL;

        return requestOrApplyConfiguration || invalidateRootCall;
    }

    /**
     * @inheritdoc ISafeTransactionGuard
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256,
        uint256,
        uint256 gasPrice,
        address,
        address payable,
        bytes calldata signatures,
        address
    ) external override {
        // TODO(nlordell): To simplify policies, we do not support gas prices for transaction
        // execution payment. This would add another mechanism for extracting funds from a Safe
        // transaction that is rarely used, and therefore should not be covered by the access
        // control system.
        require(gasPrice == 0, NonZeroGasPrice());

        if (_allowedCalls(to, value, data, operation)) {
            return;
        }

        checkTransaction(msg.sender, to, value, data, operation, _decodeContext(signatures));
    }

    /* solhint-disable no-empty-blocks */
    /**
     * @inheritdoc ISafeTransactionGuard
     */
    function checkAfterExecution(bytes32 hash, bool success) external override {}
    /* solhint-enable no-empty-blocks */

    /**
     * @inheritdoc ISafeModuleGuard
     */
    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address
    ) external override returns (bytes32 moduleTxHash) {
        checkTransaction(msg.sender, to, value, data, operation, _emptyContext());
        return bytes32(0);
    }

    /* solhint-disable no-empty-blocks */
    /**
     * @inheritdoc ISafeModuleGuard
     */
    function checkAfterModuleExecution(bytes32 txHash, bool success) external override {}
    /* solhint-enable no-empty-blocks */

    /**
     * @dev Decodes additional context to pass to the policy from the signatures bytes.
     */
    function _decodeContext(bytes calldata signatures) internal pure returns (bytes calldata) {
        // We intentionally don't fail when the signatures are too short to decode the context. This
        // is so that signatures for normal transactions without any additional context (i.e. with
        // ECDSA signatures from the owners) works for policies that don't require any additional
        // context without needing to append `uint256(0)` to the signatures bytes.

        if (signatures.length < 32) {
            return _emptyContext();
        }

        uint256 end = signatures.length - 32;
        uint256 length = uint256(bytes32(signatures[end:]));
        if (length > end) {
            return _emptyContext();
        }

        return signatures[end - length:end];
    }

    function _emptyContext() internal pure returns (bytes calldata) {
        return msg.data[0:0];
    }

    /**
     * @notice Configures and confirms multiple policies for an address.
     * @param configurations The array of configurations to be applied.
     * @dev This does not have to check if the guard is enabled, as if the guard is set,
     *      then this tx will fail in `checkTransaction`.
     *      This is a convenience function to avoid having to call `configurePolicy` and then
     *      `confirmPolicy` separately with a delay.
     */
    function configureImmediately(Configuration[] calldata configurations) external {
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
    function requestConfiguration(bytes32 configureRoot) external {
        require(rootConfigured[msg.sender][configureRoot] == 0, RootAlreadyConfigured(configureRoot));
        rootConfigured[msg.sender][configureRoot] = block.timestamp + DELAY;
        emit RootConfigured(msg.sender, configureRoot, block.timestamp + DELAY);
    }

    /**
     * @notice Invalidates a policy configuration change.
     * @param configureRoot The root of the configuration to be invalidated.
     * @dev Invalidation can only be done if the configuration is pending.
     *      This is not behind a delay, as only pending configurations can be invalidated, and
     *      this allows invalidating unintended policies immediately before it is confirmed.
     */
    function invalidateRoot(bytes32 configureRoot) external {
        require(rootConfigured[msg.sender][configureRoot] != 0, RootNotConfigured(configureRoot));
        delete rootConfigured[msg.sender][configureRoot];
        emit RootInvalidated(msg.sender, configureRoot);
    }

    /**
     * @notice Applies a policy configuration change.
     * @param configurations The array of configurations to be applied.
     * @dev This can be used to set multiple policies at once.
     */
    function applyConfiguration(Configuration[] calldata configurations) external {
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
}
