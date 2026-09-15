// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

/**
 * @notice A Safe-shaped `getStorageAt` responder that keeps its slot words in a mapping (L-CFG-SLOTMOCK).
 * @dev SafeMockHarness keeps the verbatim Safe body, whose dynamic `sload(add(offset, index))` the
 *      prover cannot relate to a constant-slot write; a mapping makes the word a rule fixes and the
 *      word the guard probes the same location by construction (L-CFG-SLOTMOCK).
 * @dev The guard only ever calls `getStorageAt(slot, 1)`; other lengths are outside the modelled
 *      surface (L-CFG-SLOTMOCK).
 */
contract SafeSlotMock {
    /// @dev The rules leave `$slots` havoced, so all four guard-slot states are one symbolic run
    ///      (L-W0-1); there is no setter, and a rule that wants one state fixes it with `require`.
    mapping(uint256 slot => uint256 word) private $slots;

    /// @notice The word masked to 160 bits, exactly as the guard decodes it.
    /// @dev Keeps bitwise arithmetic out of the specs.
    function slotAddress(uint256 slot) external view returns (address) {
        return address(uint160($slots[slot]));
    }

    /// @notice The `ISafe.getStorageAt` answer for `length == 1`, one word ABI-encoded as 96 bytes.
    /// @dev Statically sized, so the caller's raw returndata read stays inside a block the pointer
    ///      analysis can follow (L-CFG-SLOTMOCK).
    function getStorageAt(uint256 offset, uint256) external view returns (bytes memory) {
        return abi.encodePacked($slots[offset]);
    }
}

/**
 * @notice Answers `getStorageAt` per slot in one of three modes, covering every observable response
 *         to `SafePolicyGuard._readGuardSlot` (L-W0-3).
 * @dev Each mode fixes the three things the guard decodes, so one rule ranges over every responder a
 *      real contract could be (L-CFG-PROBE).
 */
contract GuardProbeResponderMock {
    enum Mode {
        // `revert(0, 0)`. `_readGuardSlot` maps it to `address(0)`, the same answer it gives a
        // STATICCALL to an account with no code, which succeeds with empty return data.
        REVERT_EMPTY,
        // Reverts with the 96-byte payload [0x20][1][word3]: well-formed data, failed call.
        REVERT_96,
        // Returns `retLen` bytes whose first three words are w0, w1, word3. Under 96 bytes is the
        // short answer, 96 or more the lenient decode; bytes past the third word are zero.
        RETURNS
    }

    struct Answer {
        Mode mode;
        uint256 retLen;
        uint256 w0;
        uint256 w1;
        uint256 word3;
    }

    /// @dev The rules leave `$answers` havoced and fix the answer a case needs with `require`, so
    ///      there is no setter.
    mapping(uint256 slot => Answer) private $answers;

    function mode(uint256 slot) external view returns (Mode) {
        return $answers[slot].mode;
    }

    function retLen(uint256 slot) external view returns (uint256) {
        return $answers[slot].retLen;
    }

    /// @notice `word3` masked to 160 bits, exactly as the guard decodes it.
    /// @dev Keeps bitwise arithmetic out of the specs.
    function word3Address(uint256 slot) external view returns (address) {
        return address(uint160($answers[slot].word3));
    }

    /// @notice The guard probe entry, in the `ISafe.getStorageAt` shape.
    /// @dev `length` is ignored: the guard always passes 1, and the mode dictates the answer shape
    ///      (L-W0-3). Gas forwarding under EIP-150 is not modelled by the prover.
    function getStorageAt(uint256 offset, uint256) external view returns (bytes memory) {
        Answer storage a = $answers[offset];
        Mode m = a.mode;
        uint256 len = a.retLen;
        uint256 w0 = a.w0;
        uint256 w1 = a.w1;
        uint256 w3 = a.word3;

        if (m == Mode.REVERT_EMPTY) {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                revert(0, 0)
            }
        } else if (m == Mode.REVERT_96) {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                mstore(ptr, 0x20)
                mstore(add(ptr, 0x20), 1)
                mstore(add(ptr, 0x40), w3)
                revert(ptr, 0x60)
            }
        } else {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                // Zero the tail so bytes past the third word are deterministic. `len` is symbolic,
                // so the fill copies zeros from past the end of calldata rather than looping.
                calldatacopy(ptr, calldatasize(), len)
                mstore(ptr, w0)
                mstore(add(ptr, 0x20), w1)
                mstore(add(ptr, 0x40), w3)
                return(ptr, len)
            }
        }
    }
}
