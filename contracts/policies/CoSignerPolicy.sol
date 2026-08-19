// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {ISafe} from "../interfaces/ISafe.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @title Co-Signer Policy
 * @dev Ensure a Safe transaction has been co-signed.
 * @dev Transaction path only: the `nonce() - 1` below assumes the nonce increment that
 *      `execTransactionFromModule` never performs, so no co-signature can validate on the module
 *      path. It fails closed, but do not rely on this policy to gate module transactions.
 * @dev Each co-signature is single-use. The hash pins the Safe nonce, but a batch may repeat a
 *      sub-transaction and {MultiSendPolicy} checks each occurrence separately, so one co-signature
 *      would otherwise authorise them all. A batch needing the same action twice must vary it.
 */
contract CoSignerPolicy is IPolicy {
    /**
     * @dev Mapping of cosigners for each Safe and access selector.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(AccessSelector.T access => address cosigner)))
        private $cosigners;

    /**
     * @dev Co-signed transaction hashes already spent, for each policy guard and Safe.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(bytes32 safeTxHash => bool spent))) private $spent;

    error Unauthorized();
    error InvalidSelector();
    error NoCosignerConfigured();

    /**
     * @notice Error indicating the co-signature was already spent within this transaction.
     */
    error CoSignatureAlreadySpent();

    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address,
        bytes calldata context,
        AccessSelector.T access
    ) external override returns (bytes4 magicValue) {
        // Compute the Safe transaction hash.
        bytes32 safeTxHash = ISafe(safe).getTransactionHash(
            to,
            value,
            data,
            operation,
            // TODO(nlordell): We assume 0 values here - they aren't available in the policy engine.
            // See the `PolicyEngine` contract for more details and rationale.
            0,
            0,
            0,
            address(0),
            address(0),
            ISafe(safe).nonce() - 1 // The Guard check is executed post nonce increment, so we need to subtract 1 from the nonce.
        );

        // Retrieve the co-signer configured for the Safe account.
        address cosigner = $cosigners[msg.sender][safe][access];
        if (cosigner == address(0)) revert NoCosignerConfigured();

        bool validSignature = SignatureChecker.isValidSignatureNow(cosigner, safeTxHash, context);
        require(validSignature, Unauthorized());

        require(!$spent[msg.sender][safe][safeTxHash], CoSignatureAlreadySpent());
        $spent[msg.sender][safe][safeTxHash] = true;

        return IPolicy.checkTransaction.selector;
    }

    /**
     * @dev Configure the policy.
     */
    function configure(address safe, AccessSelector.T access, bytes memory data) external override returns (bool) {
        address cosigner = abi.decode(data, (address));
        $cosigners[msg.sender][safe][access] = cosigner;
        return true;
    }

    /**
     * @notice Get the co-signer for a given Safe and access selector.
     * @param safe The address of the Safe.
     * @param access The access selector.
     * @return cosigner The address of the co-signer.
     */
    function getCoSigner(address safe, AccessSelector.T access) external view returns (address cosigner) {
        cosigner = $cosigners[msg.sender][safe][access];
    }

    /**
     * @notice Whether a co-signed transaction hash has already been spent.
     * @param policyGuard The policy guard address.
     * @param safe The address of the Safe.
     * @param safeTxHash The co-signed transaction hash.
     * @return spent Whether the co-signature has been spent.
     */
    function isCoSignatureSpent(
        address policyGuard,
        address safe,
        bytes32 safeTxHash
    ) external view returns (bool spent) {
        spent = $spent[policyGuard][safe][safeTxHash];
    }
}
