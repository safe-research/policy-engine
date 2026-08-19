// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {ISafe} from "../interfaces/ISafe.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Increased Threshold Policy
 * @dev Requires more owner signatures than the Safe's own threshold, for a given access selector:
 *      all but `maxAbsent` owners, never fewer than `threshold + 1` nor more than the owner count.
 *      `maxAbsent` is configured per access selector and is how much owner unavailability the Safe
 *      tolerates -- `0` demands every owner, a large value falls back to `threshold + 1`.
 * @dev The signatures are read from the caller-supplied context and verified by the Safe against
 *      its own owner set, so the context is self-authenticating and cannot be forged. `executor` is
 *      always `address(0)`: a `v == 1` signature is satisfied by `executor == owner`, so taking the
 *      executor from context would let anyone forge a signature for any owner.
 * @dev Transaction path only. The hash pins `ISafe.nonce() - 1`, which
 *      `execTransactionFromModule` never advances, and the module path carries no signatures.
 * @dev The hash is derived with `baseGas`, `gasToken` and `refundReceiver` zeroed, as
 *      {CoSignerPolicy} does. Owners sign the real hash, so a transaction setting any of them
 *      derives a different one and fails closed.
 * @dev An access selector with nothing configured reads `maxAbsent` as `0` and so demands every
 *      owner, which fails closed.
 */
contract IncreasedThresholdPolicy is IPolicy {
    /**
     * @dev Owners permitted to be absent, for each policy guard, Safe and access selector.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(AccessSelector.T access => uint256 maxAbsent)))
        private $maxAbsent;

    /**
     * @dev Transaction hashes already spent, for each policy guard and Safe.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(bytes32 safeTxHash => bool spent))) private $spent;

    /**
     * @notice Error indicating the policy was reached on the module path, which carries no signatures.
     */
    error ModulePathUnsupported();

    /**
     * @notice Error indicating these signatures were already spent within this transaction.
     */
    error SignaturesAlreadySpent();

    /**
     * @inheritdoc IPolicy
     * @dev Spends the hash, so a batch repeating a sub-transaction cannot satisfy every occurrence
     *      with one set of signatures -- the same bound {CoSignerPolicy} applies.
     */
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address module,
        bytes calldata context,
        AccessSelector.T access
    ) external override returns (bytes4 magicValue) {
        require(module == address(0), ModulePathUnsupported());

        // The Safe increments its nonce before invoking the guard.
        bytes32 safeTxHash = ISafe(safe).getTransactionHash(
            to,
            value,
            data,
            operation,
            0,
            0,
            0,
            address(0),
            address(0),
            ISafe(safe).nonce() - 1
        );

        // Reverts unless the required number of owner signatures is present.
        ISafe(safe).checkNSignatures(
            address(0),
            safeTxHash,
            context,
            _requiredSignatures(safe, $maxAbsent[msg.sender][safe][access])
        );

        require(!$spent[msg.sender][safe][safeTxHash], SignaturesAlreadySpent());
        $spent[msg.sender][safe][safeTxHash] = true;

        return IPolicy.checkTransaction.selector;
    }

    /**
     * @notice Configures how many owners may be absent for a Safe and access selector.
     * @param safe The Safe address.
     * @param access The access selector.
     * @param data ABI-encoded `uint256`, the number of owners permitted to be absent.
     * @dev Callable by anyone; state is namespaced by `msg.sender`, keeping the policy engine and
     *      policies logically separate.
     */
    function configure(address safe, AccessSelector.T access, bytes memory data) external override returns (bool) {
        $maxAbsent[msg.sender][safe][access] = abi.decode(data, (uint256));
        return true;
    }

    /**
     * @notice The number of signatures the access selector currently requires.
     * @param policyGuard The policy guard address.
     * @param safe The Safe address.
     * @param access The access selector.
     * @return required The required number of owner signatures.
     */
    function getRequiredSignatures(
        address policyGuard,
        address safe,
        AccessSelector.T access
    ) external view returns (uint256 required) {
        required = _requiredSignatures(safe, $maxAbsent[policyGuard][safe][access]);
    }

    /**
     * @notice The number of owners permitted to be absent for a Safe and access selector.
     * @param policyGuard The policy guard address.
     * @param safe The Safe address.
     * @param access The access selector.
     * @return maxAbsent The configured tolerance.
     */
    function getMaxAbsentOwners(
        address policyGuard,
        address safe,
        AccessSelector.T access
    ) external view returns (uint256 maxAbsent) {
        maxAbsent = $maxAbsent[policyGuard][safe][access];
    }

    /**
     * @dev All but `maxAbsent` owners, clamped to `[threshold + 1, owners]`. Both bounds are
     *      load-bearing: the upper one covers an N-of-N Safe, where `threshold + 1` exceeds the
     *      owner count and an unclamped requirement could never be met. The subtraction saturates
     *      rather than leaning on checked arithmetic, which reverts with panic 0x11 once
     *      `maxAbsent` exceeds the owner count -- reachable by configuration, and later by removing
     *      owners.
     */
    function _requiredSignatures(address safe, uint256 maxAbsent) internal view returns (uint256 required) {
        uint256 owners = ISafe(safe).getOwners().length;
        uint256 minimum = ISafe(safe).getThreshold() + 1;

        required = maxAbsent >= owners ? 0 : owners - maxAbsent;
        if (required < minimum) {
            required = minimum;
        }
        if (required > owners) {
            required = owners;
        }
    }
}
