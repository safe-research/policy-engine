// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {AccessSelector} from "../libraries/AccessSelector.sol";
import {Operation} from "../interfaces/Operation.sol";

contract TestAccessSelector {
    function create(address to, bytes4 selector, Operation operation) public pure returns (AccessSelector.T) {
        return AccessSelector.create(to, selector, operation);
    }

    function createFallback(Operation operation) public pure returns (AccessSelector.T) {
        return AccessSelector.createFallback(operation);
    }

    function getTarget(AccessSelector.T self) public pure returns (address) {
        return AccessSelector.getTarget(self);
    }

    function getSelector(AccessSelector.T self) public pure returns (bytes4) {
        return AccessSelector.getSelector(self);
    }

    function getOperation(AccessSelector.T self) public pure returns (Operation) {
        return AccessSelector.getOperation(self);
    }
}
