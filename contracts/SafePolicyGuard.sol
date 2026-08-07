// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {PolicyEngine, AccessSelector} from "./core/PolicyEngine.sol";
import {IERC165} from "./interfaces/IERC165.sol";
import {ISafe} from "./interfaces/ISafe.sol";
import {ISafeModuleGuard} from "./interfaces/ISafeModuleGuard.sol";
import {ISafeTransactionGuard} from "./interfaces/ISafeTransactionGuard.sol";
import {Operation} from "./interfaces/Operation.sol";
import {SignatureExtension} from "./libraries/SignatureExtension.sol";

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
     * @dev `keccak256("guard_manager.guard.address")` — Safe's `GuardManager.GUARD_STORAGE_SLOT`.
     */
    bytes32 private constant _GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /**
     * @dev `keccak256("module_manager.module_guard.address")` — Safe's
     *      `ModuleManager.MODULE_GUARD_STORAGE_SLOT`.
     */
    bytes32 private constant _MODULE_GUARD_STORAGE_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    /**
     * @dev `keccak256("SafePolicyGuard.PolicyContext.v1")` — the {SignatureExtension} type carrying
     *      policy context in the Safe `signatures` tail.
     */
    bytes32 private constant _CONTEXT_TYPE_HASH = 0x5aa463b48748f9162d63ae93151d31fed6a96b34cd2ae84ef33d25b0bdea62e4;

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
     * @notice Error indicating non zero safe transaction gas is not allowed.
     */
    error NonZeroSafeTxGas();

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
     * @notice Error indicating this contract is already installed as a guard on the caller.
     */
    error GuardAlreadyEnabled();

    /**
     * @notice Error indicating the guarded transaction failed to execute.
     */
    error ExecutionFailed();

    /**
     * @notice Error indicating the guarded module transaction failed to execute.
     */
    error ModuleExecutionFailed();

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
    ) internal view virtual override returns (bool) {
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
        uint256 safeTxGas,
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

        // A non-zero `safeTxGas` lets a Safe transaction whose inner call fails complete without
        // reverting. Once policy checks can mutate state, that would commit any state a policy
        // staged during the pre-check against a failed action. Forbid it so a failed execution
        // always reverts atomically, keeping policy state in sync with execution outcome.
        require(safeTxGas == 0, NonZeroSafeTxGas());

        // An owner transaction has no authorizing module.
        _enterCheck(msg.sender, address(0));
        checkTransaction(msg.sender, to, value, data, operation, _decodeContext(signatures));
        _exitCheck();
    }

    /**
     * @inheritdoc ISafeTransactionGuard
     * @dev The hook still runs on a successful transaction; what it cannot observe while
     *      `safeTxGas == 0` and `gasPrice == 0` are enforced is a *failure*, because the Safe
     *      reverts before calling it. Kept so atomicity is enforced locally rather than assumed of
     *      the Safe version in use.
     */
    function checkAfterExecution(bytes32, bool success) external pure override {
        require(success, ExecutionFailed());
    }

    /**
     * @inheritdoc ISafeModuleGuard
     */
    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address module
    ) external override returns (bytes32 moduleTxHash) {
        // The module travels out-of-band so policies receive it authenticated; passing it through
        // `context` let any executor forge a module identity from the Safe `signatures`.
        _enterCheck(msg.sender, module);
        checkTransaction(msg.sender, to, value, data, operation, _emptyContext());
        _exitCheck();
        return bytes32(0);
    }

    /**
     * @inheritdoc ISafeModuleGuard
     * @dev Checks are pre-execution only, so any state a policy wrote during the check commits with
     *      the transaction. The module path has no `safeTxGas` equivalent —
     *      `execTransactionFromModule` returns `false` instead of reverting — so without this a
     *      policy's writes would commit against an action that never took effect.
     */
    function checkAfterModuleExecution(bytes32, bool success) external pure override {
        require(success, ModuleExecutionFailed());
    }

    /**
     * @dev Decodes additional context to pass to the policy from the signatures bytes.
     *      Absence is not an error, so signatures carrying no context (plain ECDSA owner signatures)
     *      work for policies that do not need any. A blob that claims the type but is malformed does
     *      revert, which denies the transaction rather than silently yielding empty context.
     */
    function _decodeContext(bytes calldata signatures) internal pure returns (bytes calldata) {
        if (!SignatureExtension.has(signatures, _CONTEXT_TYPE_HASH)) {
            return _emptyContext();
        }

        return SignatureExtension.payload(signatures, _CONTEXT_TYPE_HASH);
    }

    function _emptyContext() internal pure returns (bytes calldata) {
        return msg.data[0:0];
    }

    /**
     * @dev Whether this contract is installed on `safe` as either its transaction or module guard.
     */
    function _isGuardEnabled(address safe) internal view returns (bool) {
        return
            _readGuardSlot(safe, _GUARD_STORAGE_SLOT) == address(this) ||
            _readGuardSlot(safe, _MODULE_GUARD_STORAGE_SLOT) == address(this);
    }

    /**
     * @dev Reads a guard address out of `safe`'s storage. Returns `address(0)` when `safe` does not
     *      answer `getStorageAt` as a Safe would, so that non-Safe callers keep working rather than
     *      reverting on a failed decode.
     */
    function _readGuardSlot(address safe, bytes32 slot) private view returns (address guard) {
        (bool success, bytes memory returnData) = safe.staticcall(
            abi.encodeCall(ISafe.getStorageAt, (uint256(slot), 1))
        );

        // A Safe answers with `bytes` holding a single word, ABI-encoded as
        // 32 offset + 32 length + 32 data.
        if (!success || returnData.length < 96) {
            return address(0);
        }

        // Read the data word directly rather than via `abi.decode`, which would revert on a caller
        // that answers with a malformed encoding instead of leaving it to the length check above.
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            guard := and(mload(add(returnData, 0x60)), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    /**
     * @notice Configures and confirms multiple policies for an address, bypassing the delay.
     * @param configurations The array of configurations to be applied.
     * @dev Only usable before this contract is installed as a guard, which is what keeps the delay
     *      unavoidable afterwards. Relying on the guard check to reject the call is not sufficient:
     *      any policy permitting a `CALL` to this contract (a permissive fallback, for example)
     *      would let it through and defeat the timelock, including for guard removal.
     */
    function configureImmediately(Configuration[] calldata configurations) external virtual {
        require(!_isGuardEnabled(msg.sender), GuardAlreadyEnabled());

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
    function requestConfiguration(bytes32 configureRoot) external virtual {
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
    function invalidateRoot(bytes32 configureRoot) external virtual {
        require(rootConfigured[msg.sender][configureRoot] != 0, RootNotConfigured(configureRoot));
        delete rootConfigured[msg.sender][configureRoot];
        emit RootInvalidated(msg.sender, configureRoot);
    }

    /**
     * @notice Applies a policy configuration change.
     * @param configurations The array of configurations to be applied.
     * @dev This can be used to set multiple policies at once.
     */
    function applyConfiguration(Configuration[] calldata configurations) external virtual {
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
