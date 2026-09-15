// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";

/**
 * @notice Safe v1.5.0 itself, inherited unchanged, plus the two owner reads CVL has no other route to
 *         (L-SAFE-1).
 * @dev `OwnerManager` keeps `ownerCount` and the `owners` linked list `internal`
 *      (`SAFE/base/OwnerManager.sol:19-20`), so no getter answers them; direct storage access, the route
 *      the policy specs take to the policy's own private mappings (D-007), type-checks and then fails to
 *      compile on certora-cli 8.19.1 for any contract other than the verified one. Nothing else is added:
 *      `nonce`, `getThreshold`, `getOwners`, `getTransactionHash`, `domainSeparator`, `getStorageAt` and
 *      `checkNSignatures` are already on the Safe's own ABI, and no setter is needed because the prover
 *      havocs this storage and a rule fixes the value it wants with `require`.
 */
contract RealSafeHarness is Safe {
    /// @notice `OwnerManager.ownerCount`, the owner total that has no getter of its own.
    function harnessOwnerCount() external view returns (uint256) {
        return ownerCount;
    }

    /// @notice One link of the `owners` list: `owners[SENTINEL_OWNERS]` is the first owner, the last points back.
    function harnessOwnerAfter(address prev) external view returns (address) {
        return owners[prev];
    }
}
