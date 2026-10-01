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

The policy implementations under `contracts/policies/` were not in scope. Audit 2 covers them.

Five low severity findings were reported, of which two were fixed and three acknowledged.

### Files

- [Final audit report](audit-report-certora-policy-engine-core.pdf)

## Audit 2

### Auditor

Certora (<https://www.certora.com/>).

### Notes

The audit was performed from September 16th to September 21st, 2026, starting from commit [405ba1d](https://github.com/safe-research/policy-engine/tree/405ba1d) and finalised on commit [8c30032](https://github.com/safe-research/policy-engine/tree/8c30032).

The following contracts were in scope:

- `contracts/policies/AllowPolicy.sol`
- `contracts/policies/AllowedModulePolicy.sol`
- `contracts/policies/CoSignerPolicy.sol`
- `contracts/policies/DenyPolicy.sol`
- `contracts/policies/ERC20ApprovePolicy.sol`
- `contracts/policies/ERC20TransferPolicy.sol`
- `contracts/policies/IncreasedThresholdPolicy.sol`
- `contracts/policies/MultiSendPolicy.sol`
- `contracts/policies/NativeTransferPolicy.sol`
- `contracts/policies/SafenetPolicy.sol`

`contracts/policies/OneTimeAllowPolicy.sol` was not in scope.

Two informational findings were reported. One was fixed, and the other was documented as a design limitation, as the report recommended.

### Files

- [Final audit report](audit-report-certora-individual-policies.pdf)
