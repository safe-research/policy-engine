// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

/**
 * @title Multi Send Library Interface
 * @dev <https://eips.ethereum.org/EIPS/eip-165>
 */
interface IMultiSend {
    /**
     * @notice Sends multiple transactions and reverts all if one fails.
     * @param transactions Encoded transactions. Each transaction is encoded as a packed bytes of
     *                     operation has to be uint8(0) or uint8(1) (=> 1 byte),
     *                     to as a address (=> 20 bytes),
     *                     value as a uint256 (=> 32 bytes),
     *                     data length as a uint256 (=> 32 bytes),
     *                     data as bytes.
     *                     see abi.encodePacked for more information on packed encoding
     * @dev This method is payable as delegatecalls keep the msg.value from the previous call
     *      If the calling method (e.g. execTransaction) received ETH this would revert otherwise
     */
    function multiSend(bytes memory transactions) external payable;
}
