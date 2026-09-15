// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {SafenetPolicy} from "../../contracts/policies/SafenetPolicy.sol";
import {FROST} from "../../contracts/libraries/FROST.sol";
import {Secp256k1} from "../../contracts/libraries/Secp256k1.sol";

/**
 * @notice The Safenet unit verify target: the real SafenetPolicy plus a forwarding constructor and an
 *         external attestation decode (L-SN-6).
 * @dev Overrides nothing, so INV_SN_1's base case runs the real EpochRollover.initialize.
 * @dev `$epochs` and `$spent` are read by direct storage access (D-007) and pinned by
 *      R_SN_5_gettersAgree; `_ATTESTATION_LENGTH` by the R_SN_1 iff.
 */
contract SafenetHarness is SafenetPolicy {
    constructor(
        uint256 consensusChainId,
        address consensusAddress,
        uint64 initialEpoch,
        Secp256k1.Point memory initialGroupKey
    ) SafenetPolicy(consensusChainId, consensusAddress, initialEpoch, initialGroupKey) {}

    /// @notice Decodes a Safenet attestation context, tuple type verbatim from SafenetPolicy.sol.
    /// @dev solc generates this decoder separately from the policy one; R_SN_1 asserts the two equal.
    function decodeAttestation(bytes memory context)
        external
        pure
        returns (
            uint64 epoch,
            address oracle,
            bytes32 oracleDataHash,
            Secp256k1.Point memory groupKey,
            FROST.Signature memory signature
        )
    {
        (epoch, oracle, oracleDataHash, groupKey, signature) =
            abi.decode(context, (uint64, address, bytes32, Secp256k1.Point, FROST.Signature));
    }
}
