// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {SafePolicyGuard} from "../SafePolicyGuard.sol";

/**
 * @dev Reverts from `getStorageAt` with return data shaped like a successful answer, planting the
 *      guard's own address in the word the guard reads. Only the call status distinguishes this from
 *      a real answer.
 */
contract TestRevertingStorageConfigurer {
    // solhint-disable-next-line private-vars-leading-underscore
    address private $guard;

    function configure(SafePolicyGuard guard, SafePolicyGuard.Configuration[] calldata configurations) external {
        $guard = address(guard);
        guard.configureImmediately(configurations);
    }

    function getStorageAt(uint256, uint256) external view {
        address planted = $guard;

        // `bytes` holding one word, as a Safe answers: 32 offset + 32 length + 32 data. Reverting
        // with this payload makes the return data well-formed but the call unsuccessful.
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 1)
            mstore(add(ptr, 0x40), planted)
            revert(ptr, 0x60)
        }
    }
}
