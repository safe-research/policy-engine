// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity =0.8.30;

import {MultiSendPolicy} from "../../contracts/policies/MultiSendPolicy.sol";
import {IMultiSend} from "../../contracts/interfaces/IMultiSend.sol";
import {Operation} from "../../contracts/interfaces/Operation.sol";
import {IPolicy} from "../../contracts/interfaces/IPolicy.sol";
import {AccessSelector} from "../../contracts/libraries/AccessSelector.sol";

/**
 * @notice Contracts for the MultiSend unit: an additive subclass of {MultiSendPolicy} exposing
 *         its real internal decoders and a recording engine callee; the recording leaf policy is commented out.
 * @dev The walkers call the same inherited decoders as the subject, so R_MS_3_headDecoder,
 *      R_MS_5_itemDecoder and R_MS_6_ctxDecoder state each decoder against LibHarness byte readers.
 */
contract MultiSendPolicyHarness is MultiSendPolicy {
    /// @notice The batch body exactly as `checkTransaction` obtains it.
    /// @dev Reverts `InvalidMultiSend` on a foreign selector and on a malformed envelope, as the real
    ///      decoder does.
    function batchBody(bytes calldata data) external pure returns (bytes memory) {
        return _decodeMultiSendTransactions(data);
    }

    /// @notice Number of sub-transactions the policy loop would decode from `data`.
    /// @dev The one mirrored line in this file is the iteration, pinned in both directions in the same
    ///      run (L-MS-5): R_MS_4 the count, R_MS_3_malformed and R_MS_3_liveness the revert condition,
    ///      R_MS_5 every field. Every walker call is at a literal index below 4 except R_MS_6_ctxDecoder,
    ///      which carries neither L-MS-2 nor L-MS-4.
    function batchLength(bytes calldata data) external pure returns (uint256 n) {
        bytes calldata t = _decodeMultiSendTransactions(data);
        while (t.length > 0) {
            (, , , , t) = _decodeNextTransaction(address(0), t);
            n++;
        }
    }

    /// @notice Sub-transaction `i` of `data`, decoded by the real `_decodeNextTransaction`.
    /// @dev `safe == address(0)` yields the raw `to`, since the rewrite is then the identity, which
    ///      is how R_MS_5 names the unresolved field.
    function subTx(
        address safe,
        bytes calldata data,
        uint256 i
    ) external pure returns (address to, uint256 value, bytes memory sub, Operation operation) {
        bytes calldata t = _decodeMultiSendTransactions(data);
        for (uint256 j = 0; j < i; j++) {
            (, , , , t) = _decodeNextTransaction(safe, t);
        }
        bytes calldata s;
        (to, value, s, operation, ) = _decodeNextTransaction(safe, t);
        sub = s;
    }

    /// @notice One application of the real `_decodeNextTransaction` to a batch body, no iteration.
    /// @dev The pinning counterpart of `subTx`: every field reads the same `bytes` value, so a rule can
    ///      state the decoder against LibHarness readers (R_MS_5_itemDecoder). `restLength` is what
    ///      remains after the item, the step the policy loop takes.
    function nextTx(
        address safe,
        bytes calldata transactions
    )
        external
        pure
        returns (address to, uint256 value, bytes memory sub, Operation operation, uint256 restLength)
    {
        bytes calldata s;
        bytes calldata rest;
        (to, value, s, operation, rest) = _decodeNextTransaction(safe, transactions);
        sub = s;
        restLength = rest.length;
    }

    /// @notice Context item `i`, from `i + 1` applications of the real `_decodeNextContext`.
    /// @dev Past the last item the real function answers the empty string.
    function ctxItem(bytes calldata context, uint256 i) external pure returns (bytes memory) {
        bytes calldata rest = context;
        bytes calldata c = context[0:0];
        for (uint256 j = 0; j <= i; j++) {
            (c, rest) = _decodeNextContext(rest);
        }
        return c;
    }

    /// @notice The envelope remaining after `n` real `_decodeNextContext` steps.
    /// @dev A zero length is the spec-side test "exhausted before item `i`"; a revert here is the
    ///      spec-side test "malformed at or before item `n`".
    function ctxTail(bytes calldata context, uint256 n) external pure returns (bytes memory) {
        bytes calldata rest = context;
        for (uint256 j = 0; j < n; j++) {
            (, rest) = _decodeNextContext(rest);
        }
        return rest;
    }

    /// @notice The selector `_decodeMultiSendTransactions` compares against, read from IMultiSend.
    function selMultiSend() external pure returns (bytes4) {
        return IMultiSend.multiSend.selector;
    }

    /// @notice The {Operation} values, since `CALL` and `DELEGATECALL` are reserved CVL tokens.
    function opCall() external pure returns (Operation) {
        return Operation.CALL;
    }

    function opDelegateCall() external pure returns (Operation) {
        return Operation.DELEGATECALL;
    }
}

/**
 * @notice Real-contract stand-in for the engine callback, used only by the real-callee pin rules.
 * @dev Records into storage rather than ghosts, so those rules read what a real EVM CALL
 *      delivered (L-MS-1). Deliberately not `is IPolicyEngine`: only the called signature is needed.
 */
contract EngineRecorderHarness {
    uint256 public calls;

    mapping(uint256 => address) public recCaller;
    mapping(uint256 => address) public recSafe;
    mapping(uint256 => address) public recTo;
    mapping(uint256 => uint256) public recValue;
    mapping(uint256 => bytes32) public recDataHash;
    mapping(uint256 => uint256) public recDataLength;
    mapping(uint256 => Operation) public recOperation;
    mapping(uint256 => bytes32) public recContextHash;
    mapping(uint256 => uint256) public recContextLength;

    /// @notice Free verdict oracle: arbitrary initial storage leaves `verdict` and `ret` unconstrained.
    mapping(uint256 => bool) public verdict;
    mapping(uint256 => address) public ret;

    error RecorderDenied(uint256 index);

    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes memory context
    ) external returns (address) {
        uint256 i = calls;
        recCaller[i] = msg.sender;
        recSafe[i] = safe;
        recTo[i] = to;
        recValue[i] = value;
        recDataHash[i] = keccak256(data);
        recDataLength[i] = data.length;
        recOperation[i] = operation;
        recContextHash[i] = keccak256(context);
        recContextLength[i] = context.length;
        calls = i + 1;
        require(verdict[i], RecorderDenied(i));
        return ret[i];
    }
}

// Commented out with the rule that used it.
// /**
//  * @notice Leaf policy for the nested scene, counting every invocation (conf/MultiSendNested.conf).
//  * @dev With the engine in the scene nothing is summarized, so the observation that a sub-transaction
//  *      of a nested batch reached a policy of its own cannot be made with ghosts (R-MS-9).
//  */
// contract RecorderPolicyHarness is IPolicy {
//     /// @notice The count is the whole observation R-MS-9 makes of this leaf; nothing reads a recorded field,
//     ///         so no per-call mapping is kept.
//     uint256 public calls;
//
//     /// @notice Free oracle: arbitrary initial storage means the leaf may accept or deny.
//     bool public accept;
//
//     error RecorderPolicyDenied();
//
//     function checkTransaction(
//         address,
//         address,
//         uint256,
//         bytes calldata,
//         Operation,
//         address,
//         bytes calldata,
//         AccessSelector.T
//     ) external override returns (bytes4) {
//         calls = calls + 1;
//         require(accept, RecorderPolicyDenied());
//         return IPolicy.checkTransaction.selector;
//     }
//
//     function configure(address, AccessSelector.T, bytes memory) external pure override returns (bool) {
//         return true;
//     }
// }
