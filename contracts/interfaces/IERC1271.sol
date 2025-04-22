// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

/**
 * @title ERC-1271 Interface
 * @dev <https://eips.ethereum.org/EIPS/eip-1271>
 */
interface IERC1271 {
    function isValidSignature(bytes32 message, bytes calldata signature) external view returns (bytes4 magicValue);
}
