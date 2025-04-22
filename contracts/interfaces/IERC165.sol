// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

/**
 * @title ERC-165 Interface
 * @dev <https://eips.ethereum.org/EIPS/eip-165>
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by `interfaceId`.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
