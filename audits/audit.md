# Audit Results

## Audit 1

### Auditor

Certora (<https://www.certora.com/>).

### Notes

The audit was performed from August 17th to August 25th, 2026, starting from commit [bcb5032](https://github.com/safe-research/policy-engine/tree/bcb5032) and finalised on commit [405ba1d](https://github.com/safe-research/policy-engine/tree/405ba1d).

The following contracts were in scope:

- `contracts/core/PolicyEngine.sol`
- `contracts/SafePolicyGuard.sol`
- `contracts/libraries/AccessSelector.sol`
- `contracts/libraries/SignatureExtension.sol`

The policy implementations under `contracts/policies/` were not in scope.

Five low severity findings were reported, of which two were fixed and three acknowledged.

### Files

- [Final audit report](audit-report-certora-policy-engine-core.pdf)
