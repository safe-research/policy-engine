// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {AccessSelector} from "../../contracts/libraries/AccessSelector.sol";
import {SignatureExtension} from "../../contracts/libraries/SignatureExtension.sol";
import {Operation} from "../../contracts/interfaces/Operation.sol";

/**
 * @notice Pure wrappers over {AccessSelector} and {SignatureExtension} plus raw calldata and envelope
 *         readers. Every function is `envfree` in specs.
 * @dev The raw readers are total functions of the bytes, not mirrors of contract logic; R-LIB-6 and
 *      R-LIB-7 here, and every policy rule that reads one of them, assert real-decoder output against
 *      them.
 */
contract LibHarness {
    using AccessSelector for AccessSelector.T;

    function create(address to, bytes4 selector, Operation operation) external pure returns (AccessSelector.T) {
        return AccessSelector.create(to, selector, operation);
    }

    function createFallback(Operation operation) external pure returns (AccessSelector.T) {
        return AccessSelector.createFallback(operation);
    }

    function getTarget(AccessSelector.T self) external pure returns (address) {
        return self.getTarget();
    }

    function getSelector(AccessSelector.T self) external pure returns (bytes4) {
        return self.getSelector();
    }

    function getOperation(AccessSelector.T self) external pure returns (Operation) {
        return self.getOperation();
    }

    /// @notice The {Operation} values. `CALL` and `DELEGATECALL` are reserved CVL tokens, so
    ///         certora-cli 8.19.1 answers `Operation.CALL` with "Syntax error: unexpected token near
    ///         `CALL`"; there is no spelling of an {Operation} literal in CVL, hence these two.
    function opCall() external pure returns (Operation) {
        return Operation.CALL;
    }

    function opDelegateCall() external pure returns (Operation) {
        return Operation.DELEGATECALL;
    }

    /// @notice The selector 4 bytes as a big-endian integer, so the access key layout rule states the layout
    ///         equation arithmetically rather than bitwise (L-LIB-3). A pure ABI cast, pinned by the access key
    ///         round-trip rule.
    /// @dev The address and operation components of that equation are CVL casts (`to_mathint`); this
    ///      one is not, since 8.19.1 answers `to_mathint(sel)` with "can not cast bytes4 into mathint".
    function selUint(bytes4 s) external pure returns (uint256) {
        return uint256(uint32(s));
    }

    function has(bytes calldata signatures, bytes32 typeHash) external pure returns (bool) {
        return SignatureExtension.has(signatures, typeHash);
    }

    /// @notice Reverts `MalformedSignatureExtension` exactly as the library does.
    function payload(bytes calldata signatures, bytes32 typeHash) external pure returns (bytes memory) {
        return SignatureExtension.payload(signatures, typeHash);
    }

    function payloadLength(bytes calldata signatures, bytes32 typeHash) external pure returns (uint256) {
        return SignatureExtension.payload(signatures, typeHash).length;
    }

    function payloadHash(bytes calldata signatures, bytes32 typeHash) external pure returns (bytes32) {
        return keccak256(SignatureExtension.payload(signatures, typeHash));
    }

    /// @notice Terminal 32-byte word, the envelope type hash position; `0` when shorter than 32 bytes.
    function tailWord(bytes calldata signatures) external pure returns (bytes32) {
        if (signatures.length < 32) {
            return bytes32(0);
        }
        return bytes32(signatures[signatures.length - 32:]);
    }

    /// @notice The `payloadLength` word, the one before the type hash; `0` when shorter than 64 bytes.
    function lengthWord(bytes calldata signatures) external pure returns (uint256) {
        if (signatures.length < 64) {
            return 0;
        }
        uint256 end = signatures.length - 64;
        return uint256(bytes32(signatures[end:end + 32]));
    }

    /// @notice Byte `i` of the region the documented envelope layout designates as the payload, as a
    ///         `uint256` in 0..255; `0` outside that region.
    /// @dev Computed from `signatures.length` and the length word alone, never by calling
    ///      {SignatureExtension}, which is what lets R-LIB-6 and R-LIB-7 assert against it.
    function envelopeByteAt(bytes calldata signatures, uint256 i) external pure returns (uint256) {
        if (signatures.length < 64) {
            return 0;
        }
        uint256 end = signatures.length - 64;
        uint256 lw = uint256(bytes32(signatures[end:end + 32]));
        if (lw > end || i >= lw) {
            return 0;
        }
        return uint256(uint8(signatures[end - lw + i]));
    }

    /// @notice The first four bytes of `data`, zero-padded when shorter, as the policies compute it.
    function selectorOf(bytes calldata data) external pure returns (bytes4) {
        return bytes4(data);
    }

    /// @notice Byte `i` of `data` as a `uint256` in 0..255, `0` at or past `data.length`.
    /// @dev Total on any `bytes` a rule holds, including one returned by a call (R-LIB-6, R-LIB-7).
    function byteAt(bytes calldata data, uint256 i) external pure returns (uint256) {
        if (i >= data.length) {
            return 0;
        }
        return uint256(uint8(data[i]));
    }

    /// @notice The 32-byte word at byte offset `off` of `data`, zero-padded past its end.
    function wordAt(bytes calldata data, uint256 off) external pure returns (uint256 word) {
        if (off >= data.length) {
            return 0;
        }
        uint256 avail = data.length - off;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            word := calldataload(add(data.offset, off))
        }
        if (avail < 32) {
            word &= ~((uint256(1) << (8 * (32 - avail))) - 1);
        }
        return word;
    }
}
