// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {Operation} from "../../contracts/interfaces/Operation.sol";
import {ConsensusMessages} from "../../contracts/libraries/ConsensusMessages.sol";
import {FROST} from "../../contracts/libraries/FROST.sol";
import {Secp256k1} from "../../contracts/libraries/Secp256k1.sol";
import {SafeMockHarness} from "./SafeMockHarness.sol";

/**
 * @notice Parameterized mirrors of the Safe v1.5.0 EIP-712 hash steps, plus external wrappers over
 *         the unsummarized ConsensusMessages library (L-BIND-4, L-BIND-8).
 * @dev Subclasses SafeMockHarness and overrides nothing, so the Safe hashed here stays verbatim, and
 *      the two private steps carry its assembly unchanged (L-BIND-4).
 * @dev certora-cli 8.19.1 cannot decompose the offset-30 Step 3 hash; eip712Of restates it
 *      word-aligned, and that restatement is not proven in CVL (L-BIND-8, WAIVED-B-3).
 */
contract BindingHarness is SafeMockHarness {
    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), Safe v1.5.0; re-declared
    // because the base declares it private. Pinned by R_BIND_1_domainPin.
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256
    // safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,
    // uint256 nonce)") Safe v1.5.0, re-declared because the base declares it private. This
    // copy is pinned by nothing: R_BIND_1_structPin compares two functions that both read
    // it (L-BIND-9, WAIVED-B-3).
    bytes32 private constant SAFE_TX_TYPEHASH =
        0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    /// @notice Safe.domainSeparator with the chain id and verifying contract as parameters.
    function domainHashOf(uint256 chainId, address verifyingContract) external pure returns (bytes32) {
        return _domainHashOf(chainId, verifyingContract);
    }

    /// @notice True when the parameterized domain mirror equals the inherited domainSeparator().
    /// @dev One EVM frame, so both sides read the same block.chainid (L-BIND-1).
    function domainMirrorAgrees() external view returns (bool) {
        return _domainHashOf(block.chainid, address(this)) == domainSeparator();
    }

    /// @notice Safe.getTransactionHash with the domain separator lifted to a parameter.
    /// @dev R_BIND_1_mirrorPin proves the composition equals the inherited function (L-BIND-4).
    function safeTxHashOf(
        bytes32 domainHash,
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
    ) external pure returns (bytes32) {
        return
            _eip712SafeStyle(
                domainHash,
                _structHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce)
            );
    }

    /// @notice Steps 1 and 2 of Safe.getTransactionHash: the EIP-712 SafeTx struct hash.
    /// @dev The step R_BIND_1 proves injective, over all ten transaction fields.
    function structHashOf(
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
    ) external pure returns (bytes32) {
        return _structHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce);
    }

    /// @notice The EIP-712 encoding of the same three parts, written with no assembly.
    /// @dev Provably injective where the Safe optimized form is not (L-BIND-8, WAIVED-B-3).
    function eip712Of(bytes32 domainHash, bytes32 structHash) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainHash, structHash));
    }

    /// @notice keccak256 of a calldata slice.
    /// @dev The same modelled hash Step 1 applies to `data`, so the binding rules compare like with like (L-BIND-4).
    function dataHashOf(bytes calldata data) external pure returns (bytes32) {
        return keccak256(data);
    }

    /// @notice The same 352-byte SafeTx pre-image built with abi.encode and hashed word-aligned.
    /// @dev The discriminating form of _structHash (R_BIND_1_structPin, L-BIND-9): the prover
    ///      decomposes the word-aligned form, where R_BIND_1_mirrorPin is blind to the same change.
    function structHashAlignedOf(
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
    ) external pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    SAFE_TX_TYPEHASH,
                    to,
                    value,
                    keccak256(data),
                    operation,
                    safeTxGas,
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    _nonce
                )
            );
    }

    /// @notice External wrapper over the unsummarized ConsensusMessages.transactionProposal.
    function transactionProposalOf(
        bytes32 domainSeparator_,
        uint64 epoch,
        address oracle,
        bytes32 oracleDataHash,
        bytes32 safeTxHash
    ) external pure returns (bytes32) {
        return ConsensusMessages.transactionProposal(domainSeparator_, epoch, oracle, oracleDataHash, safeTxHash);
    }

    /// @notice Hashes an epoch rollover message with the real ConsensusMessages library.
    /// @dev Uses mcopy, hence the cancun EVM version in the confs.
    function epochRolloverOf(
        bytes32 domainSeparator_,
        uint64 activeEpoch,
        uint64 proposedEpoch,
        uint64 rolloverBlock,
        Secp256k1.Point calldata groupKey
    ) external pure returns (bytes32) {
        return ConsensusMessages.epochRollover(domainSeparator_, activeEpoch, proposedEpoch, rolloverBlock, groupKey);
    }

    /// @notice Decodes a Safenet attestation context; tuple type verbatim from SafenetPolicy.sol.
    /// @dev solc generates this decoder separately from the policy one, so R_BIND_2 asserts the two equal.
    function decodeAttestation(
        bytes memory context
    )
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
        (epoch, oracle, oracleDataHash, groupKey, signature) = abi.decode(
            context,
            (uint64, address, bytes32, Secp256k1.Point, FROST.Signature)
        );
    }

    /// @dev Steps 1 and 2 of the inherited assembly (SafeMockHarness), unchanged (L-BIND-4).
    function _structHash(
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
    ) private pure returns (bytes32 structHash) {
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

            structHash := keccak256(ptr, 352)
        }
        /* solhint-enable no-inline-assembly */
    }

    /// @dev Step 3 of the inherited assembly, unchanged: the offset-30 keccak (L-BIND-8).
    function _eip712SafeStyle(bytes32 domainHash, bytes32 structHash) private pure returns (bytes32 txHash) {
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(add(ptr, 64), structHash)
            // The 0x1901 prefix is left-padded, so the encoded data starts at add(ptr, 30).
            mstore(ptr, 0x1901)
            mstore(add(ptr, 32), domainHash)
            txHash := keccak256(add(ptr, 30), 66)
        }
        /* solhint-enable no-inline-assembly */
    }

    function _domainHashOf(uint256 chainId, address verifyingContract) private pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, verifyingContract));
    }
}
