// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestERC20Token is ERC20 {
    constructor() ERC20("Test", "T") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
