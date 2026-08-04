// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.28;

import {IPolicy, Operation} from "../interfaces/IPolicy.sol";
import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";
import {ISafeTransactionGuard} from "../interfaces/ISafeTransactionGuard.sol";
import {AccessSelector} from "../libraries/AccessSelector.sol";

/**
 * @title Reentrant Mock Policy
 * @dev Test-only policy that exercises the non-`view` check path guards. During its
 *      `checkTransaction` it performs an action selected by `mode`:
 *      - `ReenterGuardEntry`: re-enters the transaction-guard entry (as a Safe reentry would)
 *        — expected to be blocked by `Reentrancy`.
 *      - `ReenterEngine`: re-enters the engine `checkTransaction` for `reenterSafe`/`reenterTo`
 *        — used to test both the blocked cross-Safe case (`reenterSafe` != the checked Safe) and
 *        the allowed same-Safe case (`reenterSafe` == the checked Safe, the `MultiSendPolicy`
 *        mechanism).
 *      - `WriteState`: mutates its own state, to stand in for a stateful policy and to prove
 *        stateful writes commit.
 *      For the re-entry modes it catches any revert and records the returned error data (and
 *      whether the re-entry succeeded) so tests can assert which guard fired, then returns the
 *      magic value so the outer check still succeeds.
 */
contract ReentrantMockPolicy is IPolicy {
    enum Mode {
        None,
        ReenterGuardEntry,
        ReenterEngine,
        WriteState
    }

    Mode public mode;
    address public reenterSafe;
    address public reenterTo;
    uint256 public writes;
    bytes public lastReentryError;
    bool public reenterSucceeded;

    /**
     * @notice Thrown if a reentry attempt unexpectedly succeeds (the guard failed to block it).
     */
    error ReentryDidNotRevert();

    function setMode(Mode mode_) external {
        mode = mode_;
    }

    function setReenter(address reenterSafe_, address reenterTo_) external {
        reenterSafe = reenterSafe_;
        reenterTo = reenterTo_;
    }

    /**
     * @inheritdoc IPolicy
     */
    function checkTransaction(
        address,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address,
        bytes calldata,
        AccessSelector.T
    ) external override returns (bytes4 magicValue) {
        if (mode == Mode.ReenterGuardEntry) {
            try
                ISafeTransactionGuard(msg.sender).checkTransaction(
                    to,
                    value,
                    data,
                    operation,
                    0,
                    0,
                    0,
                    address(0),
                    payable(address(0)),
                    hex"",
                    address(0)
                )
            {
                revert ReentryDidNotRevert();
            } catch (bytes memory err) {
                lastReentryError = err;
            }
        } else if (mode == Mode.ReenterEngine) {
            try IPolicyEngine(msg.sender).checkTransaction(reenterSafe, reenterTo, 0, hex"", operation, hex"") returns (
                address
            ) {
                reenterSucceeded = true;
            } catch (bytes memory err) {
                lastReentryError = err;
            }
        } else if (mode == Mode.WriteState) {
            writes++;
        }

        return IPolicy.checkTransaction.selector;
    }

    /**
     * @inheritdoc IPolicy
     */
    function configure(address, AccessSelector.T, bytes memory) external pure override returns (bool) {
        return true;
    }
}
