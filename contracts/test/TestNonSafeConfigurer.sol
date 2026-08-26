// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import {SafePolicyGuard} from "../SafePolicyGuard.sol";

/**
 * @dev Has no `getStorageAt` and no fallback, so the guard's probe for an installed guard reverts
 *      with no return data.
 */
contract TestNonSafeConfigurer {
    function configure(SafePolicyGuard guard, SafePolicyGuard.Configuration[] calldata configurations) external {
        guard.configureImmediately(configurations);
    }
}
