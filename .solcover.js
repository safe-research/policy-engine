module.exports = {
  skipFiles: [
    // Test-only contracts: mocks, harnesses, and the demo-only `AppSafePolicyGuard`. Reporting on
    // them buries the production numbers -- `AppSafePolicyGuard` alone is never exercised by the
    // suite and drags the total down by around 15 points.
    'test/',
    // Vendored verbatim from `safe-research/safenet`, which owns their unit tests under
    // `contracts/test/libraries/` (`SignatureExtension.t.sol`, `FROST.t.sol`, `Secp256k1.t.sol`,
    // `ConsensusMessages.t.sol`, `EpochRollover.t.sol`). Their standalone paths are covered there
    // rather than duplicated here; this repo exercises them end-to-end through the guard's context
    // decoding and `SafenetPolicy`.
    'libraries/SignatureExtension.sol',
    'libraries/ConsensusMessages.sol',
    'libraries/EpochRollover.sol',
    'libraries/FROST.sol',
    'libraries/Secp256k1.sol'
  ]
}
