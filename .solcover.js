module.exports = {
  skipFiles: [
    // Test-only contracts: mocks, harnesses, and the demo-only `AppSafePolicyGuard`. Reporting on
    // them buries the production numbers -- `AppSafePolicyGuard` alone is never exercised by the
    // suite and drags the total down by around 15 points.
    'test/',
    // Vendored verbatim from `safe-research/safenet`, which owns its unit tests:
    // `contracts/test/libraries/SignatureExtension.t.sol`. Its standalone rejection paths are
    // covered there rather than duplicated here; this repo exercises it end-to-end through the
    // guard's context decoding.
    'libraries/SignatureExtension.sol'
  ]
}
