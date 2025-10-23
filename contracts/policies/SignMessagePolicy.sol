// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title SignMessageLib interface
 */
interface ISignMessageLib {
    function signMessage(bytes calldata _data) external;
}

/**
 * @title SignMessage Policy
 * @dev Allows only signMessage signatures.
 */
contract SignMessagePolicy is IPolicy {
    using AccessSelector for AccessSelector.T;

    /**
     * @dev Struct representing a domain hash and primary type hash.
     */
    struct SignatureDomain {
        bytes32 domainHash;
        bytes32 primaryTypeHash;
    }

    /**
     * @dev Mapping of allowed domain hashes and primary type hashes for each Safe.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    mapping(address safe => mapping(bytes32 domainHash => mapping(bytes32 primaryTypeHash => bool allowed)))
        private _domains;

    /**
     * @dev Error indicating the domain or type hash is not allowed.
     */
    error DomainOrTypeNotAllowed();

    /**
     * @dev Error indicating the message hash is invalid.
     */
    error InvalidMsgHash();

    /**
     * @inheritdoc IPolicy
     * @dev This policy always returns the magic value for a particular access selector.
     */
    function checkTransaction(
        address safe,
        address,
        uint256,
        bytes calldata data,
        Operation,
        bytes calldata context,
        AccessSelector.T
    ) external view override returns (bytes4 magicValue) {
        (bytes32 domainHash, bytes32 primaryTypeHash, bytes memory structData) = abi.decode(
            context,
            (bytes32, bytes32, bytes)
        );
        require(_domains[safe][domainHash][primaryTypeHash], DomainOrTypeNotAllowed());
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19\x01", domainHash, keccak256(abi.encodePacked(primaryTypeHash, structData)))
        );
        bytes memory messageToSign = abi.decode(data[4:], (bytes));
        require(
            messageToSign.length == 32 && bytes32(abi.decode(messageToSign, (bytes32))) == messageHash,
            InvalidMsgHash()
        );
        return IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     * @dev This policy requires configuration with allowed domain and type hashes.
     */
    function configure(address safe, AccessSelector.T selector, bytes memory data) external override returns (bool) {
        SignatureDomain[] memory domains = abi.decode(data, (SignatureDomain[]));
        for (uint256 i = 0; i < domains.length; i++) {
            _domains[safe][domains[i].domainHash][domains[i].primaryTypeHash] = true;
        }
        return
            selector.getOperation() == Operation.DELEGATECALL &&
            selector.getSelector() == ISignMessageLib.signMessage.selector;
    }
}
