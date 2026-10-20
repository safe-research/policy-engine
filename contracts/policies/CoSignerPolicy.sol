// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {ISafe} from "../interfaces/ISafe.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @title Co-Signer Policy
 * @dev Requires a co-signer to approve each transaction. Works on both authorization paths, but
 *      not in the same way.
 * @dev Safe Transaction path: the co-signer signs the Safe transaction hash. The signature is passed in
 *      `context` and checked against the hash at `nonce() - 1`, since the Safe increments its nonce
 *      before calling the guard.
 * @dev Module path: `execTransactionFromModule` passes no signatures and does not change the Safe
 *      nonce, so the co-signer approves the transaction in advance instead. A module transaction is
 *      identified by {getModuleTransactionHash}, which hashes the policy guard, the Safe, the module
 *      and the transaction itself. The policy recomputes this hash at check time, so it cannot
 *      contain a nonce. As a result approvals are not ordered: an approved transaction can run at
 *      any time, two identical transactions share the same approval, and every run spends one use.
 * @dev A co-signer approves by calling {approveModuleTransaction} itself, or by signing
 *      {getModuleTransactionApprovalHash} and letting anyone submit the signature with
 *      {approveModuleTransactionWithSignature}. The signed message includes a nonce chosen by the
 *      co-signer that can only be submitted once. Approvals do not expire: unspent uses last until
 *      {revokeModuleTransaction}, and an unsubmitted signature until {invalidateApprovalNonce}.
 *      The check itself makes no external calls; signatures are verified when they are submitted.
 * @dev The signed message uses this contract's EIP-712 domain, not the Safe's, so a Safe
 *      transaction hash the co-signer signed earlier can never serve as a module approval.
 * @dev On the transaction path each co-signature is single-use. A MultiSend batch can repeat a
 *      sub-transaction, and {MultiSendPolicy} checks each copy against the same hash, so the policy
 *      records spent hashes; a batch that needs the same action twice must vary it. On the module
 *      path each copy simply spends one use.
 */
contract CoSignerPolicy is IPolicy {
    /**
     * @dev `keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")`.
     */
    bytes32 private constant _DOMAIN_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    /**
     * @dev `keccak256("ModuleTransaction(address policyGuard,address safe,address module,address to,uint256 value,"
     *      "bytes data,uint8 operation)")`.
     */
    bytes32 private constant _MODULE_TRANSACTION_TYPEHASH =
        0x7a30b3c623213c71da04ec7e7be3dbb7ae8f68bb2912b2da8496eed58060f125;

    /**
     * @dev `keccak256("ModuleTransactionApproval(bytes32 moduleTxHash,uint256 uses,uint256 nonce)")`.
     */
    bytes32 private constant _MODULE_TRANSACTION_APPROVAL_TYPEHASH =
        0x9f98d3d5a8abe6d54b5557b242fd8a9c90da1d728835c35f4b66184952b8a44e;

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

    /**
     * @dev Unspent uses of a module transaction, for each policy guard, Safe and approving
     *      co-signer. Keyed by the approver so nobody can grant or clear uses in another's name;
     *      only the co-signer configured for the access selector counts at check time.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(address cosigner => mapping(bytes32 digest => uint256))))
        private $moduleApprovals;

    /**
     * @dev Approval nonces already relayed or invalidated, for each policy guard, Safe and co-signer.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address policyGuard => mapping(address safe => mapping(address cosigner => mapping(uint256 nonce => bool))))
        private $usedApprovalNonces;

    error Unauthorized();
    error InvalidSelector();
    error NoCosignerConfigured();

    /**
     * @notice Error indicating the co-signature was already spent within this transaction.
     */
    error CoSignatureAlreadySpent();

    /**
     * @notice Error indicating a relayed module transaction approval does not carry the named
     *         co-signer's signature.
     */
    error InvalidCoSignature();

    /**
     * @notice Error indicating a relayed approval's nonce was already relayed or invalidated.
     */
    error ApprovalNonceUsed();

    /**
     * @notice Error indicating an approval granting no use at all.
     */
    error ZeroUses();

    /**
     * @notice Emitted when a co-signer grants uses of a module transaction.
     * @param policyGuard The policy guard the approval is scoped to.
     * @param safe The Safe address.
     * @param cosigner The approving co-signer.
     * @param moduleTxHash The module transaction, see {getModuleTransactionHash}.
     * @param uses The uses granted by this approval, on top of any unspent ones.
     */
    event ModuleTransactionApproved(
        address indexed policyGuard,
        address indexed safe,
        address indexed cosigner,
        bytes32 moduleTxHash,
        uint256 uses
    );

    /**
     * @notice Emitted when a co-signer clears its unspent uses of a module transaction.
     * @param policyGuard The policy guard the approval was scoped to.
     * @param safe The Safe address.
     * @param cosigner The revoking co-signer.
     * @param moduleTxHash The module transaction.
     * @param uses The uses cleared.
     */
    event ModuleTransactionRevoked(
        address indexed policyGuard,
        address indexed safe,
        address indexed cosigner,
        bytes32 moduleTxHash,
        uint256 uses
    );

    /**
     * @notice Emitted when a co-signer burns an approval nonce, so a signature carrying it can no
     *         longer be relayed.
     * @param policyGuard The policy guard the approval was scoped to.
     * @param safe The Safe address.
     * @param cosigner The co-signer.
     * @param nonce The burnt nonce.
     */
    event ApprovalNonceInvalidated(
        address indexed policyGuard,
        address indexed safe,
        address indexed cosigner,
        uint256 nonce
    );

    /**
     * @notice Emitted when a module transaction spends a use.
     * @param policyGuard The policy guard that ran the check.
     * @param safe The Safe address.
     * @param module The module that authorized the transaction.
     * @param moduleTxHash The module transaction.
     * @param remaining The uses left after this one.
     */
    event ModuleCoSignatureUsed(
        address indexed policyGuard,
        address indexed safe,
        address indexed module,
        bytes32 moduleTxHash,
        uint256 remaining
    );

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
        // Retrieve the co-signer configured for the Safe account.
        address cosigner = $cosigners[msg.sender][safe][access];
        if (cosigner == address(0)) revert NoCosignerConfigured();

        // `module` is engine-supplied, so this is the authorization path and not a claim.
        if (module != address(0)) {
            _spendModuleApproval(safe, to, value, data, operation, module, cosigner);
            return IPolicy.checkTransaction.selector;
        }

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
     * @notice Grants uses of a module transaction as the caller. Meant for a co-signer that acts
     *         on-chain, such as a Safe, which can approve with an ordinary transaction and no
     *         ERC-1271 round trip.
     * @param policyGuard The policy guard the approval is scoped to.
     * @param safe The Safe the module transaction is for.
     * @param moduleTxHash The module transaction, see {getModuleTransactionHash}.
     * @param uses How many times it may run, added to any unspent uses.
     * @dev Callable by anyone: uses only count if their approver is the co-signer configured for
     *      the access selector the module transaction resolves to.
     */
    function approveModuleTransaction(address policyGuard, address safe, bytes32 moduleTxHash, uint256 uses) external {
        require(uses != 0, ZeroUses());
        $moduleApprovals[policyGuard][safe][msg.sender][moduleTxHash] += uses;
        emit ModuleTransactionApproved(policyGuard, safe, msg.sender, moduleTxHash, uses);
    }

    /**
     * @notice Grants uses of a module transaction on behalf of `cosigner`, whose signature over
     *         {getModuleTransactionApprovalHash} anyone may relay. An EOA co-signer signs the
     *         EIP-712 digest; a contract co-signer is asked through ERC-1271, so a Safe co-signer
     *         may also pre-sign the digest with `signMessage` and have an empty signature relayed.
     * @param policyGuard The policy guard the approval is scoped to.
     * @param safe The Safe the module transaction is for.
     * @param cosigner The co-signer the signature is attributed to.
     * @param moduleTxHash The module transaction, see {getModuleTransactionHash}.
     * @param uses How many times it may run, added to any unspent uses.
     * @param nonce The co-signer's nonce for this approval: unordered, and good once.
     * @param signature The co-signer's signature over the approval digest.
     */
    function approveModuleTransactionWithSignature(
        address policyGuard,
        address safe,
        address cosigner,
        bytes32 moduleTxHash,
        uint256 uses,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(uses != 0, ZeroUses());
        require(!$usedApprovalNonces[policyGuard][safe][cosigner][nonce], ApprovalNonceUsed());
        bytes32 approvalHash = getModuleTransactionApprovalHash(moduleTxHash, uses, nonce);
        require(SignatureChecker.isValidSignatureNow(cosigner, approvalHash, signature), InvalidCoSignature());

        $usedApprovalNonces[policyGuard][safe][cosigner][nonce] = true;
        $moduleApprovals[policyGuard][safe][cosigner][moduleTxHash] += uses;
        emit ModuleTransactionApproved(policyGuard, safe, cosigner, moduleTxHash, uses);
    }

    /**
     * @notice Clears the caller's unspent uses of a module transaction.
     * @param policyGuard The policy guard the approval was scoped to.
     * @param safe The Safe the module transaction was for.
     * @param moduleTxHash The module transaction.
     */
    function revokeModuleTransaction(address policyGuard, address safe, bytes32 moduleTxHash) external {
        uint256 uses = $moduleApprovals[policyGuard][safe][msg.sender][moduleTxHash];
        delete $moduleApprovals[policyGuard][safe][msg.sender][moduleTxHash];
        emit ModuleTransactionRevoked(policyGuard, safe, msg.sender, moduleTxHash, uses);
    }

    /**
     * @notice Burns one of the caller's approval nonces, so a signature it issued under that nonce
     *         but no longer stands behind cannot be relayed.
     * @param policyGuard The policy guard the signature was scoped to.
     * @param safe The Safe the signature was for.
     * @param nonce The nonce to burn.
     */
    function invalidateApprovalNonce(address policyGuard, address safe, uint256 nonce) external {
        $usedApprovalNonces[policyGuard][safe][msg.sender][nonce] = true;
        emit ApprovalNonceInvalidated(policyGuard, safe, msg.sender, nonce);
    }

    /**
     * @notice Identifies a module transaction: the EIP-712 struct hash of
     *         `ModuleTransaction(address policyGuard,address safe,address module,address to,
     *         uint256 value,bytes data,uint8 operation)`. Deliberately nonce-free, since the check
     *         has to re-derive it from the transaction alone.
     * @param policyGuard The policy guard that will run the check.
     * @param safe The Safe the module transaction is for.
     * @param module The module that will authorize it.
     * @param to The target address.
     * @param value The value in Wei.
     * @param data The transaction data.
     * @param operation The operation.
     * @return moduleTxHash The module transaction hash.
     */
    function getModuleTransactionHash(
        address policyGuard,
        address safe,
        address module,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) public pure returns (bytes32 moduleTxHash) {
        moduleTxHash = keccak256(
            abi.encode(_MODULE_TRANSACTION_TYPEHASH, policyGuard, safe, module, to, value, keccak256(data), operation)
        );
    }

    /**
     * @notice The digest a co-signer signs to grant uses of a module transaction: EIP-712 typed
     *         data `ModuleTransactionApproval(bytes32 moduleTxHash,uint256 uses,uint256 nonce)`
     *         under this contract's domain, `EIP712Domain(uint256 chainId,address verifyingContract)`.
     * @param moduleTxHash The module transaction, see {getModuleTransactionHash}.
     * @param uses How many times it may run.
     * @param nonce The co-signer's nonce for this approval.
     * @return approvalHash The digest.
     */
    function getModuleTransactionApprovalHash(
        bytes32 moduleTxHash,
        uint256 uses,
        uint256 nonce
    ) public view returns (bytes32 approvalHash) {
        bytes32 structHash = keccak256(abi.encode(_MODULE_TRANSACTION_APPROVAL_TYPEHASH, moduleTxHash, uses, nonce));
        approvalHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), structHash));
    }

    /**
     * @notice The EIP-712 domain separator of this contract.
     */
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(_DOMAIN_TYPEHASH, block.chainid, address(this)));
    }

    /**
     * @notice The unspent uses `cosigner` has granted of a module transaction.
     * @param policyGuard The policy guard address.
     * @param safe The address of the Safe.
     * @param cosigner The approving co-signer.
     * @param moduleTxHash The module transaction.
     * @return uses How many more times it may run.
     */
    function getModuleTransactionApprovals(
        address policyGuard,
        address safe,
        address cosigner,
        bytes32 moduleTxHash
    ) external view returns (uint256 uses) {
        uses = $moduleApprovals[policyGuard][safe][cosigner][moduleTxHash];
    }

    /**
     * @notice Whether `cosigner` has had an approval nonce relayed or has invalidated it.
     * @param policyGuard The policy guard address.
     * @param safe The address of the Safe.
     * @param cosigner The co-signer.
     * @param nonce The nonce.
     * @return used Whether the nonce can no longer be relayed.
     */
    function isApprovalNonceUsed(
        address policyGuard,
        address safe,
        address cosigner,
        uint256 nonce
    ) external view returns (bool used) {
        used = $usedApprovalNonces[policyGuard][safe][cosigner][nonce];
    }

    /**
     * @notice Get the co-signer for a given Safe and access selector.
     * @param policyGuard The policy guard address.
     * @param safe The address of the Safe.
     * @param access The access selector.
     * @return cosigner The address of the co-signer.
     */
    function getCoSigner(
        address policyGuard,
        address safe,
        AccessSelector.T access
    ) external view returns (address cosigner) {
        cosigner = $cosigners[policyGuard][safe][access];
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

    /**
     * @dev Spends one of the configured co-signer's uses of this exact module transaction. Pure
     *      storage: nothing here calls out.
     */
    function _spendModuleApproval(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address module,
        address cosigner
    ) private {
        bytes32 moduleTxHash = getModuleTransactionHash(msg.sender, safe, module, to, value, data, operation);

        uint256 uses = $moduleApprovals[msg.sender][safe][cosigner][moduleTxHash];
        require(uses != 0, Unauthorized());
        unchecked {
            uses -= 1;
        }
        $moduleApprovals[msg.sender][safe][cosigner][moduleTxHash] = uses;

        emit ModuleCoSignatureUsed(msg.sender, safe, module, moduleTxHash, uses);
    }
}
