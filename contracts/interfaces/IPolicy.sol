// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {Operation} from "./Operation.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Policy Interface
 */
interface IPolicy {
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes calldata context,
        AccessSelector.T access
    ) external returns (bytes4 magicValue);

    function configure(address safe, AccessSelector.T access, bytes memory data) external returns (bool success);
}
