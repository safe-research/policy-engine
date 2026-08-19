// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

/**
 * @title Permission
 * @dev How often an allowlisted account may be used, in ascending order of permissiveness.
 */
enum Permission {
    NONE,
    ONCE,
    ALWAYS
}
