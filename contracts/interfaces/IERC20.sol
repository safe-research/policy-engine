// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

/**
 * @title ERC-20 Interface
 * @dev <https://eips.ethereum.org/EIPS/eip-20>
 */
interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool success);
}
