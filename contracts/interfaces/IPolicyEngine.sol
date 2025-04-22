// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {Operation} from "./Operation.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Policy Engine Interface
 */
interface IPolicyEngine {
    function getPolicy(
        address safe,
        address to,
        bytes calldata data,
        Operation operation
    ) external view returns (AccessSelector.T, address);

    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes calldata context
    ) external returns (address);
}
