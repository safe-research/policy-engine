module.exports = {
  // Test-only contracts: mocks, harnesses, and the demo-only `AppSafePolicyGuard`. Reporting on
  // them buries the production numbers -- `AppSafePolicyGuard` alone is never exercised by the
  // suite and drags the total down by around 15 points.
  skipFiles: ['test/']
}
