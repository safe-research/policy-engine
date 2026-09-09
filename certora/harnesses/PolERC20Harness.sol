// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {ERC20TransferPolicy} from "../../contracts/policies/ERC20TransferPolicy.sol";
import {ERC20ApprovePolicy} from "../../contracts/policies/ERC20ApprovePolicy.sol";
import {Permission} from "../../contracts/interfaces/Permission.sol";

/**
 * @notice Each contract here is an additive subclass of an ERC-20 policy, exposing the real
 *         internal decoders and the `configure` payload readers.
 * @dev No subclass overrides or shadows anything, so a rule here is a rule about the code
 *      `checkTransaction` and `configure` run. Every function is `pure`, hence `envfree` in the specs.
 */
contract ERC20TransferPolicyHarness is ERC20TransferPolicy {
    /// @notice The real `_decodeERC20Transfer`, exposed.
    /// @dev Reverts exactly as it does inside `checkTransaction`.
    function decodeRecipient(bytes calldata data) external pure returns (address recipient) {
        return _decodeERC20Transfer(data);
    }

    /// @notice Entry count of a `configure` payload, from the same decode `configure` runs.
    /// @dev The readers re-run the decoder rather than restate it; R_ERC20T_5 asserts `configEntryCount`
    ///      reverts exactly when `configure` does, and src/utils.ts fixes the struct byte layout outside CVL.
    function configEntryCount(bytes memory data) external pure returns (uint256) {
        RecipientData[] memory list = abi.decode(data, (RecipientData[]));
        return list.length;
    }

    /// @notice Recipient of entry `i`, or `address(0)` at or past the end (total).
    function configEntryRecipient(bytes memory data, uint256 i) external pure returns (address) {
        RecipientData[] memory list = abi.decode(data, (RecipientData[]));
        if (i >= list.length) {
            return address(0);
        }
        return list[i].recipient;
    }

    /// @notice Permission of entry `i`, or `Permission.NONE` at or past the end (total).
    function configEntryPermission(bytes memory data, uint256 i) external pure returns (Permission) {
        RecipientData[] memory list = abi.decode(data, (RecipientData[]));
        if (i >= list.length) {
            return Permission.NONE;
        }
        return list[i].permission;
    }

    /// @notice The {Permission} values as first-class CVL values.
    /// @dev `ALWAYS` is a reserved CVL token, so the enum members cannot be named in a spec; `NONE == 0`
    ///      is why an unconfigured slot denies.
    function permNone() external pure returns (Permission) {
        return Permission.NONE;
    }

    function permOnce() external pure returns (Permission) {
        return Permission.ONCE;
    }

    function permAlways() external pure returns (Permission) {
        return Permission.ALWAYS;
    }
}

contract ERC20ApprovePolicyHarness is ERC20ApprovePolicy {
    /// @notice The real `_decodeERC20Approve`, exposed as two single-value readers.
    /// @dev A two-value return cannot be used inside a `satisfy` expression, so both readers run the whole
    ///      decoder and revert on exactly the conditions `checkTransaction` does.
    function decodeApproveSpender(bytes calldata data) external pure returns (address spender) {
        (spender, ) = _decodeERC20Approve(data);
    }

    function decodeApproveAmount(bytes calldata data) external pure returns (uint256 amount) {
        (, amount) = _decodeERC20Approve(data);
    }

    /// @notice Entry count of an approve `configure` payload, from the decode `configure` runs.
    /// @dev R-ERC20A-5 asserts these readers against `configure`; src/utils.ts fixes the byte layout.
    function configEntryCount(bytes memory data) external pure returns (uint256) {
        SpenderData[] memory list = abi.decode(data, (SpenderData[]));
        return list.length;
    }

    /// @notice Spender of entry `i`, or `address(0)` at or past the end (total).
    function configEntrySpender(bytes memory data, uint256 i) external pure returns (address) {
        SpenderData[] memory list = abi.decode(data, (SpenderData[]));
        if (i >= list.length) {
            return address(0);
        }
        return list[i].spender;
    }

    /// @notice Permission of entry `i`, or `Permission.NONE` at or past the end (total).
    function configEntryPermission(bytes memory data, uint256 i) external pure returns (Permission) {
        SpenderData[] memory list = abi.decode(data, (SpenderData[]));
        if (i >= list.length) {
            return Permission.NONE;
        }
        return list[i].permission;
    }

    /// @notice The {Permission} values as first-class CVL values (`ALWAYS` is a reserved CVL token).
    function permNone() external pure returns (Permission) {
        return Permission.NONE;
    }

    function permOnce() external pure returns (Permission) {
        return Permission.ONCE;
    }

    function permAlways() external pure returns (Permission) {
        return Permission.ALWAYS;
    }
}
