// SPDX-License-Identifier: LGPL-3.0-only
// Negative-control harness: certora/harnesses/SafePolicyGuardHarness.sol, except for the one
// rewritten import (it extends the negative-control SafePolicyGuard of NegSafePolicyGuard.sol, which
// in turn extends the negative-control PolicyEngine of NegPolicyEngine.sol) and the one-argument
// constructor (:39), which follows from the 177de07 copy those two files carry, with no EXPIRY
// argument (#101); plus three added blank lines (:40, :73, :131) and three doc comments re-tagged
// @notice to @dev with NegPolicyEngine.sol citations (:52, :63-64, :122).
// `diff certora/harnesses/SafePolicyGuardHarness.sol certora/prover-defects/NegGuardHarness.sol`
// shows all of them. The contract name is kept, so the same specs and the same rule text run
// against it with no spec edit.
pragma solidity =0.8.30;

import {SafePolicyGuard} from "./NegSafePolicyGuard.sol";
import {AccessSelector} from "../../contracts/libraries/AccessSelector.sol";
import {Operation} from "../../contracts/interfaces/Operation.sol";

/**
 * @notice Certora harness for {SafePolicyGuard}: forwards the constructor and exposes the internal
 *         members the specs need as external wrappers with no logic of their own.
 * @dev `$policies`, `$checkingSafe` and `$checkingModule` stay private and are read by direct
 *      storage access (D-007); `_readGuardSlot` stays private so its staticcall stays real.
 * @dev No wrapper for `_updatePolicy` or `_confirmPolicy`: it would be a third writer of `$policies`,
 *      beside `configureImmediately` and `applyConfiguration`.
 */
contract SafePolicyGuardHarness is SafePolicyGuard {
    using AccessSelector for AccessSelector.T;

    /// @notice The context type hash, computed rather than copied.
    /// @dev Pinned by R-LIB-7 and by the EngineCheck context rules: a wrong value makes `decodeContext`
    ///      disagree with the engine.
    bytes32 public constant CONTEXT_TYPE_HASH = keccak256("SafePolicyGuard.PolicyContext.v1");

    /// @notice The Safe transaction-guard slot, computed from its preimage.
    /// @dev Pinned by the EngineConfig gate rules, which probe `SafeSlotMock` at exactly this slot number.
    bytes32 public constant GUARD_STORAGE_SLOT = keccak256("guard_manager.guard.address");

    /// @notice The Safe module-guard slot, computed from its preimage.
    bytes32 public constant MODULE_GUARD_STORAGE_SLOT = keccak256("module_manager.module_guard.address");

    constructor(uint256 delay) SafePolicyGuard(delay) {}

    /// @notice The real escape-hatch predicate `_allowedCalls`.
    function allowedCalls(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) external view returns (bool) {
        return _allowedCalls(to, value, data, operation);
    }

    /// @dev The real selector decoder (`NegPolicyEngine.sol:243-251`): reverts `InvalidSelector` for 1-3 bytes.
    function decodeSelector(bytes calldata data) external pure returns (bytes4) {
        return _decodeSelector(data);
    }

    /// @notice The real context decoder: empty when there is no envelope, reverting
    ///         `MalformedSignatureExtension` when the envelope claims the type but is malformed.
    function decodeContext(bytes calldata signatures) external pure returns (bytes memory) {
        return _decodeContext(signatures);
    }

    /// @dev The exact key `getPolicy` looks up first (`NegPolicyEngine.sol:132-133`), and the fallback key
    ///      (`:140`). Thin compositions of library calls, no logic.
    function exactKey(address to, bytes calldata data, Operation operation) external pure returns (AccessSelector.T) {
        return AccessSelector.create(to, _decodeSelector(data), operation);
    }

    function fallbackKey(Operation operation) external pure returns (AccessSelector.T) {
        return AccessSelector.createFallback(operation);
    }

    /// @notice Mirror of the configuration root expression `keccak256(abi.encode(c))`.
    /// @dev Pinned to the real keccak by the EngineConfig apply and root rules.
    function configurationRoot(Configuration[] calldata configurations) external pure returns (bytes32) {
        return keccak256(abi.encode(configurations));
    }

    // Field decoders, one per function (CVL2 has no tuple destructuring of struct arrays).
    function configTarget(Configuration[] calldata c, uint256 i) external pure returns (address) {
        return c[i].target;
    }

    function configSelector(Configuration[] calldata c, uint256 i) external pure returns (bytes4) {
        return c[i].selector;
    }

    function configOperation(Configuration[] calldata c, uint256 i) external pure returns (Operation) {
        return c[i].operation;
    }

    function configPolicy(Configuration[] calldata c, uint256 i) external pure returns (address) {
        return c[i].policy;
    }

    function configDataLength(Configuration[] calldata c, uint256 i) external pure returns (uint256) {
        return c[i].data.length;
    }

    function configDataHash(Configuration[] calldata c, uint256 i) external pure returns (bytes32) {
        return keccak256(c[i].data);
    }

    /// @notice The first 32-byte word of entry `i` data, `0` when shorter than 32 bytes. Total.
    /// @dev The word `OneTimeAllowPolicy.configure` feeds to `abi.decode(data, (bool))`, which reverts
    ///      iff the length is under 32 or the word exceeds 1: the scene-fixed verdict the EngineConfig
    ///      rules read.
    function configDataWord0(Configuration[] calldata c, uint256 i) external pure returns (uint256 w) {
        bytes calldata d = c[i].data;
        if (d.length >= 32) {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                w := calldataload(d.offset)
            }
        }
    }

    /// @dev The key `_confirmPolicy` writes for entry `i` (`NegPolicyEngine.sol:281`).
    function configKey(Configuration[] calldata c, uint256 i) external pure returns (AccessSelector.T) {
        return AccessSelector.create(c[i].target, c[i].selector, c[i].operation);
    }

    /// @notice Raw hash of arbitrary bytes, for data-identity comparisons against the recorder mocks.
    function keccak(bytes calldata data) external pure returns (bytes32) {
        return keccak256(data);
    }

    /// @notice Calls the real engine entry through `this` and decodes the outcome (L-EC-8).
    /// @dev `errSelector` is the first four bytes of the revert data and `errArg` the following word
    ///      as an address, which is the `policy` argument of AccessDenied and of PolicyReverted.
    /// @dev Sound to observe through because the engine never reads `msg.sender` (L-EC-8).
    function tryCheck(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes calldata context
    ) external returns (bool ok, bytes4 errSelector, address errArg, uint256 errLength, address ret) {
        try this.checkTransaction(safe, to, value, data, operation, context) returns (address policy) {
            return (true, bytes4(0), address(0), 0, policy);
        } catch (bytes memory reason) {
            errLength = reason.length;
            if (reason.length >= 4) {
                errSelector = bytes4(reason);
            }
            if (reason.length >= 36) {
                uint256 word;
                // solhint-disable-next-line no-inline-assembly
                assembly ("memory-safe") {
                    word := mload(add(reason, 0x24))
                }
                errArg = address(uint160(word));
            }
            return (false, errSelector, errArg, errLength, address(0));
        }
    }
}
