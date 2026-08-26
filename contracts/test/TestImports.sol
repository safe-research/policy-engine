// SPDX-License-Identifier: LGPL-3.0
// Pinned to the version the `hardhat.config.ts` override compiles this file with: the Safe
// contracts it pulls in are built without the IR pipeline, separately from this package's sources.
// solhint-disable-next-line compiler-version
pragma solidity 0.8.28;

/* solhint-disable no-unused-import */
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";

// This file here just imports contracts we use in tests, so
// hardhat compiles them and creates Typechain types for them.
/* solhint-disable-next-line no-empty-blocks */
contract TestImports {}
