// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

/**
 * @title Stack
 * @dev Storage stack implemented with as a linked list.
 */
library Stack {
    /**
     * @title The stack type.
     */
    struct T {
        mapping(uint256 => uint256) list;
    }

    /**
     * @dev Error thrown when trying to pop from an empty stack.
     */
    error StackEmpty();

    /**
     * @dev Push an item onto the stack.
     * @param self The stack.
     * @param item The item to push.
     */
    function push(T storage self, uint256 item) internal {
        self.list[item] = self.list[uint256(0)];
        self.list[uint256(0)] = item;
    }

    /**
     * @dev Pop an item from the stack. Reverts if the stack is empty.
     * @param self The stack.
     * @return The popped item.
     */
    function pop(T storage self) internal returns (uint256) {
        uint256 item = self.list[uint256(0)];
        require(item != uint256(0), StackEmpty());
        self.list[uint256(0)] = self.list[item];
        self.list[item] = uint256(0); // Clean up storage for gas refund
        return item;
    }
}
