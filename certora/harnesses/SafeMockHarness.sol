// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {Operation} from "../../contracts/interfaces/Operation.sol";

/**
 * @notice Stands in for a Safe v1.5.0 as the callee of every `ISafe` call the production contracts
 *         make (L-W0-1). Environment code is copied verbatim from Safe v1.5.0.
 * @dev Every slot is storage the prover havocs per rule (L-W0-1), and the verbatim `getStorageAt`
 *      reads it, so a rule fixes the answer it wants with `require` rather than planting a word.
 */
contract SafeMockHarness {
    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), Safe v1.5.0 Safe.sol:57
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256
    // gasPrice,address gasToken,address refundReceiver,uint256 nonce)"), Safe v1.5.0 Safe.sol:62
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    /// @notice Never meant to run: a scene that reaches `checkNSignatures` summarizes it.
    error NotSummarized();

    uint256 public nonce;
    uint256 private $ownerCount;
    uint256 private $threshold;

    constructor() {
        $ownerCount = 1;
        $threshold = 1;
    }

    /// @notice Sets owner count and threshold, keeping `1 <= threshold <= ownerCount` (L-IT-2).
    /// @dev The only writer of the two, which is what makes that well-formedness inductive (L-IT-2).
    function setOwnersAndThreshold(uint256 ownerCount_, uint256 threshold_) external {
        require(1 <= threshold_ && threshold_ <= ownerCount_, "SafeMock: ill-formed");
        $ownerCount = ownerCount_;
        $threshold = threshold_;
    }

    function ownerCount() external view returns (uint256) {
        return $ownerCount;
    }

    /// @notice `1 <= threshold <= ownerCount`, the well-formedness predicate (L-IT-2).
    function mockSafeWellFormed() external view returns (bool) {
        return 1 <= $threshold && $threshold <= $ownerCount;
    }

    /// @notice Verbatim `StorageAccessible.getStorageAt` from Safe v1.5.0 (`StorageAccessible.sol:16-29`).
    function getStorageAt(uint256 offset, uint256 length) public view returns (bytes memory) {
        // We use `<< 5` instead of `* 32` as SHR / SHL opcode only uses 3 gas, while DIV / MUL opcode uses 5 gas.
        bytes memory result = new bytes(length << 5);
        for (uint256 index = 0; index < length; ++index) {
            /* solhint-disable no-inline-assembly */
            /// @solidity memory-safe-assembly
            assembly {
                let word := sload(add(offset, index))
                mstore(add(add(result, 0x20), mul(index, 0x20)), word)
            }
            /* solhint-enable no-inline-assembly */
        }
        return result;
    }

    /// @notice An owner array of the right length with zero entries.
    /// @dev Only `.length` is read by production code; a storage-array copy would add a loop bounded
    ///      by `loop_iter`.
    function getOwners() external view returns (address[] memory) {
        return new address[]($ownerCount);
    }

    function getThreshold() external view returns (uint256) {
        return $threshold;
    }

    /// @notice Always reverts `NotSummarized()`.
    /// @dev A scene that reaches it must summarize it, so a forgotten summary fails closed.
    function checkNSignatures(address, bytes32, bytes memory, uint256) external view {
        revert NotSummarized();
    }

    /// @notice Verbatim `Safe.domainSeparator` from Safe v1.5.0 (`Safe.sol:389-399`).
    function domainSeparator() public view returns (bytes32) {
        uint256 chainId;
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            chainId := chainid()
        }
        /* solhint-enable no-inline-assembly */

        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, this));
    }

    /// @notice Verbatim `Safe.getTransactionHash` from Safe v1.5.0 (`Safe.sol:404-473`), with this
    ///         repo's `Operation` type.
    /// @dev Equality of this copy with a real Safe's answer is WAIVED-H-5: not proven here, the body is
    ///      copied verbatim.
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes32 txHash) {
        bytes32 domainHash = domainSeparator();

        // Assembly, so no memory is allocated for the keccak256 temporaries. Dirty high bits in the
        // sub-256-bit types (`to`, `operation`, `gasToken`, `refundReceiver`) are not cleaned here.
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)

            // Step 1: hash the transaction data.
            calldatacopy(ptr, data.offset, data.length)
            let calldataHash := keccak256(ptr, data.length)

            // Step 2: lay the SafeTx struct out one word each, typehash first, nonce last.
            mstore(ptr, SAFE_TX_TYPEHASH)
            mstore(add(ptr, 32), to)
            mstore(add(ptr, 64), value)
            mstore(add(ptr, 96), calldataHash)
            mstore(add(ptr, 128), operation)
            mstore(add(ptr, 160), safeTxGas)
            mstore(add(ptr, 192), baseGas)
            mstore(add(ptr, 224), gasPrice)
            mstore(add(ptr, 256), gasToken)
            mstore(add(ptr, 288), refundReceiver)
            mstore(add(ptr, 320), _nonce)

            // Step 3: hash the 352-byte struct, then wrap it with the EIP-712 prefix.
            mstore(add(ptr, 64), keccak256(ptr, 352))
            // The 0x1901 prefix is left-padded, so the encoded data starts at add(ptr, 30).
            mstore(ptr, 0x1901)
            mstore(add(ptr, 32), domainHash)
            txHash := keccak256(add(ptr, 30), 66)
        }
        /* solhint-enable no-inline-assembly */
    }
}
