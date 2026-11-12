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

## Audit 3

### Auditor

ack3 (<https://ack3.ai/>).

### Notes

The audit was performed from September 14th to September 25th, 2026, starting from commit [405ba1d](https://github.com/safe-research/policy-engine/tree/405ba1d) and finalised on commit [8ee68a8](https://github.com/safe-research/policy-engine/tree/8ee68a8) after a fix review from November 5th to November 7th, 2026.

The following files were in scope:

- `contracts/SafePolicyGuard.sol`
- `contracts/core/PolicyEngine.sol`
- `contracts/interfaces/IERC1271.sol`
- `contracts/interfaces/IERC165.sol`
- `contracts/interfaces/IERC20.sol`
- `contracts/interfaces/IMultiSend.sol`
- `contracts/interfaces/IPolicy.sol`
- `contracts/interfaces/IPolicyEngine.sol`
- `contracts/interfaces/ISafe.sol`
- `contracts/interfaces/ISafeModuleGuard.sol`
- `contracts/interfaces/ISafeTransactionGuard.sol`
- `contracts/interfaces/Operation.sol`
- `contracts/interfaces/Permission.sol`
- `contracts/libraries/AccessSelector.sol`
- `contracts/libraries/ConsensusMessages.sol`
- `contracts/libraries/EpochRollover.sol`
- `contracts/libraries/FROST.sol`
- `contracts/libraries/Secp256k1.sol`
- `contracts/libraries/SignatureExtension.sol`
- `contracts/policies/AllowPolicy.sol`
- `contracts/policies/AllowedModulePolicy.sol`
- `contracts/policies/CoSignerPolicy.sol`
- `contracts/policies/DenyPolicy.sol`
- `contracts/policies/ERC20ApprovePolicy.sol`
- `contracts/policies/ERC20TransferPolicy.sol`
- `contracts/policies/MultiSendPolicy.sol`
- `contracts/policies/NativeTransferPolicy.sol`
- `contracts/policies/SafenetPolicy.sol`

`contracts/policies/IncreasedThresholdPolicy.sol` and `contracts/policies/OneTimeAllowPolicy.sol` were not in scope. Audit 2 covers `IncreasedThresholdPolicy.sol`.

Twenty-two findings were reported: two medium, three low, nine warning and eight informational. Fourteen were fixed and eight acknowledged.

### Files

- [Final audit report](audit-report-ack3-policy-engine.pdf)
