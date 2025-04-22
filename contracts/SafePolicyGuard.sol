// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {PolicyEngine, AccessSelector} from "./core/PolicyEngine.sol";
import {IERC165} from "./interfaces/IERC165.sol";
import {ISafeModuleGuard} from "./interfaces/ISafeModuleGuard.sol";
import {ISafeTransactionGuard} from "./interfaces/ISafeTransactionGuard.sol";
import {Operation} from "./interfaces/Operation.sol";
import {ISafe} from "./interfaces/ISafe.sol";

/**
 * @title Safe Policy Guard
 * @dev Apply security policy to all Safe transactions.
 */
contract SafePolicyGuard is PolicyEngine, ISafeModuleGuard, ISafeTransactionGuard {
    using AccessSelector for AccessSelector.T;

    // keccak256("guard_manager.guard.address")
    bytes32 internal constant _GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /**
     * @notice The delay for the configuration change and guard removal.
     */
    uint256 public immutable DELAY;

    mapping(address safe => uint256 timestamp) public removeGuard;

    /**
     * @notice The pending policies for a Safe.
     * @dev The mapping is structured as follows:
     *      safe address where policy is pending => access data hash => timestamp when policy can be confirmed.
     *      NOTE: This is not important for PolicyEngine, rather it is more important for the SafePolicyGuard.
     *      So, this might be moved to the SafePolicyGuard later on.
     */
    mapping(address safe => mapping(bytes32 accessDataHash => uint256 timestamp)) public pendingPolicies;

    // TODO(nlordell): The access control mechanism currently only checks transaction pre-conditions
    // and not post conditions. If we decide that post checks in policies are needed, we could use
    // an execution stack to push policies to check post-executions for. This would have a large
    // impact on gas - although we can use things like transient storage to offset it a little.
    // Stack.T $afterExecutionChecks;

    error NonZeroGasPrice();

    /**
     * @notice Error indicating there is no pending policy for the given access selector.
     */
    error NoPendingPolicy();

    /**
     * @notice Error indicating the policy confirmation is pending.
     */
    error PolicyConfirmationPending();

    /**
     * @notice Error indicating the guard is already set.
     */
    error GuardAlreadySet(address guard);

    event PolicyConfigured(
        address indexed safe,
        address indexed target,
        bytes4 selector,
        Operation operation,
        address policy,
        bytes data
    );

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

    function scheduleGuardRemoval() external {
        removeGuard[msg.sender] = DELAY + block.timestamp;
    }

    /**
     * @dev TODO: Consider the security considerations of calling `checkTransaction` as a Safe transaction,
     *      this can matter because the Safe can potentially modify state and might lead to unexpected interactions.
     */
    function _allowedCalls(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) internal returns (bool) {
        bytes4 selector = _decodeSelector(data);

        // Configure or confirm policy
        bool configureOrConfirmPolicy = to == address(this) &&
            value == 0 &&
            (selector == this.configurePolicy.selector || selector == this.confirmPolicy.selector) &&
            operation == Operation.CALL;

        // Schedule guard removal
        bool guardRemovalScheduled = to == address(this) &&
            value == 0 &&
            selector == this.scheduleGuardRemoval.selector &&
            operation == Operation.CALL;

        // Set guard (here the intention is to remove the guard)
        bool setGuard = to == safe &&
            value == 0 &&
            selector == ISafe.setGuard.selector &&
            operation == Operation.DELEGATECALL &&
            removeGuard[safe] > 0 &&
            removeGuard[safe] <= block.timestamp;

        if (setGuard) removeGuard[safe] = 0;

        return configureOrConfirmPolicy || setGuard || guardRemovalScheduled;
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

        if (_allowedCalls(msg.sender, to, value, data, operation)) {
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
     * @notice Configures and confirms a policy for a specific access selector immediately if no guard is set.
     * @param target The target address.
     * @param selector The function selector.
     * @param operation The operation type (CALL or DELEGATECALL).
     * @param policy The policy address.
     * @param data The call data for the policy to be called at confirmation.
     * @dev This has to be called by the Safe owner.
     *      This could also be used to reconfigure and disable a policy as well.
     *      This is a convenience function to avoid having to call `configurePolicy` and then
     *      `confirmPolicy` separately with a delay.
     */
    function configureAndConfirmPolicy(
        address target,
        bytes4 selector,
        Operation operation,
        address policy,
        bytes memory data
    ) external {
        address guard = abi.decode(ISafe(msg.sender).getStorageAt(uint256(_GUARD_STORAGE_SLOT), 1), (address));
        require(guard == address(0), GuardAlreadySet(guard));

        _confirmPolicy(msg.sender, target, selector, operation, policy, data);
    }

    /**
     * @notice Configures a policy for a specific access selector.
     * @param target The target address.
     * @param selector The function selector.
     * @param operation The operation type (CALL or DELEGATECALL).
     * @param policy The policy address.
     * @param data The call data for the policy to be called at confirmation.
     * @dev This has to be called by the Safe owner.
     *      This could also be used to reconfigure and disable a policy as well.
     */
    function configurePolicy(
        address target,
        bytes4 selector,
        Operation operation,
        address policy,
        bytes memory data
    ) public {
        bytes32 accessDataHash = keccak256(abi.encodePacked(target, selector, operation, policy, data));

        pendingPolicies[msg.sender][accessDataHash] = block.timestamp + DELAY;

        emit PolicyConfigured(msg.sender, target, selector, operation, policy, data);
    }

    /**
     * @notice Confirms a policy for a specific access selector.
     * @param safe The Safe address.
     * @param target The target address.
     * @param selector The function selector.
     * @param operation The operation type (CALL or DELEGATECALL).
     * @param policy The policy address.
     * @param data The call data for the policy to be called at confirmation.
     * @dev This can be called by any user on behalf of Safe.
     */
    function confirmPolicy(
        address safe,
        address target,
        bytes4 selector,
        Operation operation,
        address policy,
        bytes memory data
    ) external {
        bytes32 accessDataHash = keccak256(abi.encodePacked(target, selector, operation, policy, data));
        uint256 activationTimestamp = pendingPolicies[safe][accessDataHash];
        delete pendingPolicies[safe][accessDataHash];

        require(activationTimestamp != 0, NoPendingPolicy());
        require(block.timestamp >= activationTimestamp, PolicyConfirmationPending());

        // Confirm policy
        _confirmPolicy(safe, target, selector, operation, policy, data);
    }
}
