// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {ISafe} from "../interfaces/ISafe.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";
import {ConsensusMessages} from "../libraries/ConsensusMessages.sol";
import {EpochRollover} from "../libraries/EpochRollover.sol";
import {FROST} from "../libraries/FROST.sol";
import {Secp256k1} from "../libraries/Secp256k1.sol";

/**
 * @title Safenet Policy
 * @dev Allow a Safe transaction carrying a Safenet FROST threshold-signature attestation. This is
 *      the attestation half of `safe-research/safenet`'s `SafenetGuard`; its announcement escape
 *      hatch is omitted, since the engine's timelocked configuration already provides recovery.
 *      The trusted `(group key, epoch)` forest is global to this contract, seeded at construction
 *      and extended only by {updateEpoch}.
 * @dev Transaction path only: the hash pins `ISafe.nonce() - 1`, which
 *      `execTransactionFromModule` never advances. {ModulePathUnsupported} rejects that path.
 * @dev `baseGas`, `gasToken` and `refundReceiver` are not in the policy interface, so the hash is
 *      derived with them zeroed. For an ordinary transaction that equals the real Safe transaction
 *      hash, so an attestation needs no special form -- but those fields are consequently
 *      **unbound**, which is harmless only because the guard requires `gasPrice == 0`. Revisit if
 *      gas refunds are ever supported.
 * @dev Best configured as the `CALL` and `DELEGATECALL` fallback. Combining it with
 *      {MultiSendPolicy} is unsupported, and fails closed via the once-per-nonce rule below.
 */
contract SafenetPolicy is IPolicy {
    using EpochRollover for EpochRollover.T;

    /**
     * @dev `abi.encode(uint64, address, bytes32, Secp256k1.Point, FROST.Signature)` -- eight words,
     *      matching `AttestationTrailer`'s payload. The guard has already unwrapped its own
     *      envelope, so only the payload reaches here.
     */
    uint256 private constant _ATTESTATION_LENGTH = 256;

    /**
     * @dev EIP-712 domain separator of the Consensus deployment the attestations are bound to.
     */
    bytes32 private immutable _CONSENSUS_DOMAIN_SEPARATOR;

    /**
     * @dev Trusted `(group key, epoch)` forest, seeded at construction and extended by {updateEpoch}.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    EpochRollover.T private $epochs;

    /**
     * @dev Safe nonces already authorised by an attestation, for each policy guard and Safe.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(uint256 nonce => bool spent))) private $spent;

    /**
     * @notice Error indicating the Consensus address is zero.
     */
    error InvalidAddress();

    /**
     * @notice Error indicating the context is not a well-formed attestation.
     */
    error MalformedAttestation();

    /**
     * @notice Error indicating the attesting `(group key, epoch)` pair is not trusted.
     */
    error UntrustedAttestationKey();

    /**
     * @notice Error indicating this Safe nonce was already authorised by an attestation.
     */
    error AttestationAlreadySpent();

    /**
     * @notice Error indicating the policy was reached on the module path, which it cannot serve.
     */
    error ModulePathUnsupported();

    /**
     * @param consensusChainId The chain ID hosting the Consensus contract.
     * @param consensusAddress The Consensus contract address; with `consensusChainId` this derives
     *        the immutable domain separator, which cannot be corrected after deployment.
     * @param initialEpoch The genesis epoch number.
     * @param initialGroupKey The genesis FROST group key; must be a non-zero secp256k1 point.
     */
    constructor(
        uint256 consensusChainId,
        address consensusAddress,
        uint64 initialEpoch,
        Secp256k1.Point memory initialGroupKey
    ) {
        require(consensusAddress != address(0), InvalidAddress());
        _CONSENSUS_DOMAIN_SEPARATOR = ConsensusMessages.domain(consensusChainId, consensusAddress);
        $epochs.initialize(initialEpoch, initialGroupKey);
    }

    /**
     * @inheritdoc IPolicy
     */
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address module,
        bytes calldata context,
        AccessSelector.T
    ) external override returns (bytes4 magicValue) {
        require(module == address(0), ModulePathUnsupported());
        require(context.length == _ATTESTATION_LENGTH, MalformedAttestation());

        (
            uint64 epoch,
            address oracle,
            bytes32 oracleDataHash,
            Secp256k1.Point memory groupKey,
            FROST.Signature memory signature
        ) = abi.decode(context, (uint64, address, bytes32, Secp256k1.Point, FROST.Signature));

        // Cheap membership check first, so an untrusted key short-circuits before the hashing.
        require($epochs.isKnown(groupKey, epoch), UntrustedAttestationKey());

        // The Safe increments its nonce before invoking the guard.
        uint256 nonce = ISafe(safe).nonce() - 1;
        require(!$spent[msg.sender][safe][nonce], AttestationAlreadySpent());

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
            nonce
        );

        // Rebuild the message the validator set signed. Which oracle is acceptable is a
        // validator-side policy, so the oracle is bound by the signature rather than pinned here.
        bytes32 message = ConsensusMessages.transactionProposal(
            _CONSENSUS_DOMAIN_SEPARATOR,
            epoch,
            oracle,
            oracleDataHash,
            safeTxHash
        );
        FROST.verify(groupKey, signature, message);

        $spent[msg.sender][safe][nonce] = true;

        return IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     * @dev The attestation authorises the transaction on its own, so there is nothing to configure
     *      per access selector.
     */
    function configure(address, AccessSelector.T, bytes memory) external pure override returns (bool) {
        return true;
    }

    /**
     * @notice Records a new trusted `(group key, epoch)` pair from a rollover signed by a trusted group.
     * @param parentKey The group key being rolled over from.
     * @param parentEpoch The epoch of `parentKey`.
     * @param proposedEpoch The new epoch; must be strictly greater than `parentEpoch`.
     * @param rolloverBlock The Consensus-chain block number folded into the signed message.
     * @param newGroupKey The new group public key.
     * @param signature The FROST signature by the parent group over the rollover message.
     * @dev Permissionless: the signature is what authorises the change, so anyone may relay it.
     */
    function updateEpoch(
        Secp256k1.Point calldata parentKey,
        uint64 parentEpoch,
        uint64 proposedEpoch,
        uint64 rolloverBlock,
        Secp256k1.Point calldata newGroupKey,
        FROST.Signature calldata signature
    ) external {
        $epochs.rollover(
            _CONSENSUS_DOMAIN_SEPARATOR,
            parentKey,
            parentEpoch,
            proposedEpoch,
            rolloverBlock,
            newGroupKey,
            signature
        );
    }

    /**
     * @notice Whether a `(group key, epoch)` pair is trusted.
     * @param groupKey The group public key.
     * @param epoch The epoch.
     * @return known Whether the pair is recorded.
     */
    function isKnownEpoch(Secp256k1.Point calldata groupKey, uint64 epoch) external view returns (bool known) {
        known = $epochs.isKnown(groupKey, epoch);
    }

    /**
     * @notice The EIP-712 domain separator attestations are bound to.
     * @return domainSeparator The domain separator.
     */
    function getConsensusDomainSeparator() external view returns (bytes32 domainSeparator) {
        domainSeparator = _CONSENSUS_DOMAIN_SEPARATOR;
    }

    /**
     * @notice Whether a Safe nonce has already been authorised by an attestation.
     * @param policyGuard The policy guard address.
     * @param safe The Safe address.
     * @param nonce The Safe nonce.
     * @return spent Whether an attestation has been spent for that nonce.
     */
    function isAttestationSpent(address policyGuard, address safe, uint256 nonce) external view returns (bool spent) {
        spent = $spent[policyGuard][safe][nonce];
    }
}
