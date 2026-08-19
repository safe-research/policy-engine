// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import {FROST} from "../libraries/FROST.sol";
import {Secp256k1} from "../libraries/Secp256k1.sol";

/**
 * @dev Exposes {FROST}'s challenge derivation so tests can build a real signature. Verification
 *      still recomputes it and checks `z*G == R + c*Y`, so a wrong scalar is rejected either way.
 */
contract TestFROST {
    function challenge(
        Secp256k1.Point memory r,
        Secp256k1.Point memory y,
        bytes32 message
    ) public view returns (uint256) {
        return FROST.challenge(r, y, message);
    }
}
