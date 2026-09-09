// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

/**
 * @notice Discharges the decode half of L-CFG-DECODE, the summary of `SafePolicyGuard._readGuardSlot`
 *         on the guard-slot probe.
 * @dev `decodeCopy` is the decode of `_readGuardSlot` (`G:309-320`) copied byte for byte, with the
 *      `staticcall` replaced by its two outputs, `success` and the return buffer. `decodeModel` is the
 *      function the CVL summary computes, written without assembly and without offset arithmetic, so the
 *      equality is a real check of the `0x60` offset and of the 160-bit mask rather than a restatement.
 *      `R_CFG_DECODE_pin` asserts the two agree on every answer of at most 160 bytes, the bound the probe
 *      decode rules put on the responder.
 * @dev What the copy elides (L-CFG-DECODE): this is a copy of the private function, not the function
 *      itself, and an ABI-decoded `bytes memory` parameter stands in for a `staticcall`'s
 *      `(bool, bytes memory)` return buffer. Both are a length word followed by the bytes, so
 *      `mload(add(p, 0x60))` is word 3 of the answer in both; they differ only past `length`, which the
 *      decode never reads because the load happens only under `length >= 96`. Keeping this copy in step
 *      with the contract is a review obligation, not a proved one.
 */
contract GuardSlotDecodePin {
    /// @notice The decode half of `SafePolicyGuard._readGuardSlot`, verbatim.
    function decodeCopy(bool success, bytes memory returnData) external pure returns (address guard) {
        // A Safe answers with `bytes` holding a single word, ABI-encoded as
        // 32 offset + 32 length + 32 data.
        if (!success || returnData.length < 96) {
            return address(0);
        }

        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            guard := and(mload(add(returnData, 0x60)), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    /// @notice The function L-CFG-DECODE models: `(success, len >= 96, word3 & mask)`, no assembly.
    function decodeModel(bool success, bytes calldata returnData) external pure returns (address) {
        if (!success || returnData.length < 96) {
            return address(0);
        }
        return address(uint160(uint256(bytes32(returnData[64:96]))));
    }

    /// @notice Word 3 of the answer, unmasked, so a rule can witness a dirty word.
    function word3Of(bytes calldata returnData) external pure returns (uint256) {
        return uint256(bytes32(returnData[64:96]));
    }
}
