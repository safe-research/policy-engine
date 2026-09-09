// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IPolicy, Operation} from "../../contracts/interfaces/IPolicy.sol";
import {IPolicyEngine} from "../../contracts/interfaces/IPolicyEngine.sol";
import {ISafeModuleGuard} from "../../contracts/interfaces/ISafeModuleGuard.sol";
import {ISafeTransactionGuard} from "../../contracts/interfaces/ISafeTransactionGuard.sol";
import {AccessSelector} from "../../contracts/libraries/AccessSelector.sol";
import {SafePolicyGuard} from "../../contracts/SafePolicyGuard.sol";

/**
 * @notice The adversarial policy of the closed scenes: one contract whose check and configure
 *         behaviour is selected by storage the prover havocs per rule (L-W0-2).
 * @dev Never a `verify` target and never in `parametric_contracts`: there are no setters, and a rule
 *      fixes the havoced mode and parameter storage it needs with `require` (L-W0-1).
 * @dev `depth` makes a nested invocation plain ACCEPT, so recursion is bounded to one level and
 *      `contract_recursion_limit` proves it (L-EC-6, L-CFG-RECUR).
 */
contract MockPolicyHarness is IPolicy {
    enum CheckMode {
        // Returns the magic value: the AllowPolicy class.
        ACCEPT,
        // Answers with `wrongMagic`, forced away from the magic: the AccessDenied(policy) class.
        WRONG_MAGIC,
        // Reverts `MockCheckReverted(revertCode)`: the PolicyReverted(policy, reason) class.
        REVERTS,
        // Calls one guard configuration entry point on msg.sender, catches, returns the magic value.
        CALL_CONFIG,
        // Re-enters the transaction guard hook on msg.sender with the check's own arguments.
        REENTER_GUARD_TX,
        // Module-guard twin of the mode above, using `reenterModule`.
        REENTER_GUARD_MODULE,
        // Calls the engine `checkTransaction` on msg.sender with free value and skipped data and
        // context, so the nested arguments differ from the outer ones.
        REENTER_ENGINE
    }

    enum ConfigureMode {
        // Return the verdict; FALSE drives the PolicyConfigurationFailed class.
        TRUE,
        FALSE,
        // Reverts `MockConfigureReverted(revertCode)`.
        REVERTS,
        // Records the call, reads `rootConfigured(safe, primedRoot)` back, returns true.
        RECORD,
        // Re-enters one configuration entry point on msg.sender, records the outcome, returns true.
        CALL_CONFIG
    }

    enum ConfigCall {
        REQUEST,
        APPLY,
        INVALIDATE,
        IMMEDIATE
    }

    struct Invocation {
        address sender;
        address safe;
        address to;
        uint256 value;
        bytes32 dataHash;
        uint256 dataLength;
        Operation operation;
        address module;
        bytes32 contextHash;
        uint256 contextLength;
        AccessSelector.T access;
    }

    /// @notice Distinct custom errors so the engine's forwarded `reason` is recognisable.
    error MockCheckReverted(uint256 code);
    error MockConfigureReverted(uint256 code);

    bytes4 private constant MAGIC = IPolicy.checkTransaction.selector;

    // Modes and parameters, havoced per rule.
    CheckMode public checkMode;
    ConfigureMode public configureMode;
    ConfigCall public configCall;
    bytes4 public wrongMagic;
    uint256 public revertCode;

    address public reenterSafe;
    address public reenterTo;
    uint256 public reenterValue;
    Operation public reenterOperation;
    address public reenterModule;
    uint256 public reenterDataSkip;
    uint256 public reenterContextSkip;

    bytes32 public reenterRoot;
    address public cfgTarget;
    bytes4 public cfgSelector;
    Operation public cfgOperation;
    address public cfgPolicy;
    bytes32 public primedRoot;

    // Observables.
    uint256 public depth;
    bool public innerCalled;
    bool public innerReverted;
    bytes4 public innerErrorSelector;
    uint256 public innerErrorLength;
    address public innerReturnedPolicy;

    uint256 public calls;
    Invocation[2] private $inv;

    uint256 public configureCalls;
    address public lastConfigureSender;
    address public lastConfigureSafe;
    AccessSelector.T public lastConfigureAccess;
    uint256 public lastConfigureDataLength;
    bytes32 public lastConfigureDataHash;
    uint256 public observedRootValue;

    // Recorder getters; ring index 0 is the first invocation of the transaction, 1 the second.
    function invSender(uint256 i) external view returns (address) {
        return $inv[i].sender;
    }

    function invSafe(uint256 i) external view returns (address) {
        return $inv[i].safe;
    }

    function invTo(uint256 i) external view returns (address) {
        return $inv[i].to;
    }

    function invValue(uint256 i) external view returns (uint256) {
        return $inv[i].value;
    }

    function invDataHash(uint256 i) external view returns (bytes32) {
        return $inv[i].dataHash;
    }

    function invDataLength(uint256 i) external view returns (uint256) {
        return $inv[i].dataLength;
    }

    function invOperation(uint256 i) external view returns (Operation) {
        return $inv[i].operation;
    }

    function invModule(uint256 i) external view returns (address) {
        return $inv[i].module;
    }

    function invContextHash(uint256 i) external view returns (bytes32) {
        return $inv[i].contextHash;
    }

    function invContextLength(uint256 i) external view returns (uint256) {
        return $inv[i].contextLength;
    }

    function invAccess(uint256 i) external view returns (AccessSelector.T) {
        return $inv[i].access;
    }

    /// @inheritdoc IPolicy
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address module,
        bytes calldata context,
        AccessSelector.T access
    ) external override returns (bytes4 magicValue) {
        uint256 n = calls;
        $inv[n % 2] = Invocation({
            sender: msg.sender,
            safe: safe,
            to: to,
            value: value,
            dataHash: keccak256(data),
            dataLength: data.length,
            operation: operation,
            module: module,
            contextHash: keccak256(context),
            contextLength: context.length,
            access: access
        });
        unchecked {
            calls = n + 1;
        }

        CheckMode m = checkMode;
        if (m == CheckMode.ACCEPT) {
            return MAGIC;
        }
        if (m == CheckMode.WRONG_MAGIC) {
            bytes4 w = wrongMagic;
            return w == MAGIC ? bytes4(0) : w;
        }
        if (m == CheckMode.REVERTS) {
            revert MockCheckReverted(revertCode);
        }
        // Re-entry modes: exactly one level; a nested invocation of this mock is plain ACCEPT.
        if (depth != 0) {
            return MAGIC;
        }
        depth = 1;
        if (m == CheckMode.CALL_CONFIG) {
            _callConfig(context);
        } else if (m == CheckMode.REENTER_GUARD_TX) {
            try
                ISafeTransactionGuard(msg.sender).checkTransaction(
                    to,
                    value,
                    data,
                    operation,
                    0,
                    0,
                    0,
                    address(0),
                    payable(address(0)),
                    context,
                    address(0)
                )
            {
                _innerOk();
            } catch (bytes memory err) {
                _innerFail(err);
            }
        } else if (m == CheckMode.REENTER_GUARD_MODULE) {
            try ISafeModuleGuard(msg.sender).checkModuleTransaction(to, value, data, operation, reenterModule) returns (
                bytes32
            ) {
                _innerOk();
            } catch (bytes memory err) {
                _innerFail(err);
            }
        } else {
            // REENTER_ENGINE
            try
                IPolicyEngine(msg.sender).checkTransaction(
                    reenterSafe,
                    reenterTo,
                    reenterValue,
                    _tail(data, reenterDataSkip),
                    reenterOperation,
                    _tail(context, reenterContextSkip)
                )
            returns (address policy) {
                innerReturnedPolicy = policy;
                _innerOk();
            } catch (bytes memory err) {
                _innerFail(err);
            }
        }
        depth = 0;
        return MAGIC;
    }

    /// @inheritdoc IPolicy
    function configure(address safe, AccessSelector.T access, bytes memory data) external override returns (bool) {
        ConfigureMode m = configureMode;
        if (m == ConfigureMode.TRUE) {
            return true;
        }
        if (m == ConfigureMode.FALSE) {
            return false;
        }
        if (m == ConfigureMode.REVERTS) {
            revert MockConfigureReverted(revertCode);
        }
        unchecked {
            configureCalls = configureCalls + 1;
        }
        lastConfigureSender = msg.sender;
        lastConfigureSafe = safe;
        lastConfigureAccess = access;
        lastConfigureDataLength = data.length;
        lastConfigureDataHash = keccak256(data);
        if (m == ConfigureMode.RECORD) {
            observedRootValue = SafePolicyGuard(msg.sender).rootConfigured(safe, primedRoot);
            return true;
        }
        // CALL_CONFIG: exactly one level of re-entry.
        if (depth == 0) {
            depth = 1;
            _callConfig(data);
            depth = 0;
        }
        return true;
    }

    function _callConfig(bytes memory payload) private {
        ConfigCall c = configCall;
        if (c == ConfigCall.REQUEST) {
            try SafePolicyGuard(msg.sender).requestConfiguration(reenterRoot) {
                _innerOk();
            } catch (bytes memory err) {
                _innerFail(err);
            }
        } else if (c == ConfigCall.INVALIDATE) {
            try SafePolicyGuard(msg.sender).invalidateRoot(reenterRoot) {
                _innerOk();
            } catch (bytes memory err) {
                _innerFail(err);
            }
        } else {
            SafePolicyGuard.Configuration[] memory cfg = new SafePolicyGuard.Configuration[](1);
            cfg[0] = SafePolicyGuard.Configuration({
                target: cfgTarget,
                selector: cfgSelector,
                operation: cfgOperation,
                policy: cfgPolicy,
                data: payload
            });
            if (c == ConfigCall.APPLY) {
                try SafePolicyGuard(msg.sender).applyConfiguration(cfg) {
                    _innerOk();
                } catch (bytes memory err) {
                    _innerFail(err);
                }
            } else {
                try SafePolicyGuard(msg.sender).configureImmediately(cfg) {
                    _innerOk();
                } catch (bytes memory err) {
                    _innerFail(err);
                }
            }
        }
    }

    function _innerOk() private {
        innerCalled = true;
        innerReverted = false;
        innerErrorSelector = bytes4(0);
        innerErrorLength = 0;
    }

    function _innerFail(bytes memory err) private {
        innerCalled = true;
        innerReverted = true;
        innerErrorLength = err.length;
        innerErrorSelector = err.length >= 4 ? bytes4(err) : bytes4(0);
    }

    /// @dev `b[skip:]` with `skip` clamped to `b.length`; the nested bytes differ from the outer ones
    ///      exactly when `0 < skip` and `b` is non-empty.
    function _tail(bytes calldata b, uint256 skip) private pure returns (bytes calldata) {
        uint256 s = skip > b.length ? b.length : skip;
        return b[s:];
    }
}
