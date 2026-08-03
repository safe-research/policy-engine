# Plan: Non-view policy checks

Component: policy-engine smart contracts (`contracts/`)

---

## Overview

Today the entire policy check path is `view`, so a policy cannot mutate state during
`checkTransaction`. This is enforced at every layer (`IPolicy`, `IPolicyEngine`,
`PolicyEngine`, `SafePolicyGuard`) and, critically, makes the engine → policy call a
`STATICCALL`. See issues #27 (docs correction) and #28 (RFC).

This epic makes the check path **non-`view`** so that stateful policies (e.g. periodic
spend limits / usage accounting) become possible, while adding the guardrails that the
`view`/`STATICCALL` boundary provides for free today. It is delivered as a stack of small,
single-purpose PRs on top of this plan.

Steps (each a separate, stacked PR):

1. **Enforce `safeTxGas == 0`** — a standalone restriction that keeps failed execution
   atomic (prerequisite for correct stateful state).
2. **Non-`view` check path + reentrancy gate + same-Safe confinement** — the atomic
   security unit: drop `view` and add the mitigations together (production code as 2a,
   its dedicated test suite as 2b).
3. **Docs** — reconcile the README/NatSpec with the new stateful model (updates #27).
4. **Cleanup** — remove this epic file.

A separate follow-up issue tracks moving the reentrancy flags from persistent storage to
EIP-1153 transient storage once all target chains support it.

---

## Architecture Decision

**Drop `view` from the check path and rely on runtime guards instead of the compiler's
`STATICCALL` sandbox.** The security-critical change is a single call site,
`PolicyEngine.checkTransaction` (`contracts/core/PolicyEngine.sol:128`): while `IPolicy`
is `view`, the compiler emits that call as a `STATICCALL`, which is what makes reentrancy
and mid-check state corruption impossible today. Removing `view` turns it into a `CALL`,
opening a reentrancy graph. We replace the lost guarantee with:

- **A reentrancy gate** (`_enterCheck` / `_exitCheck` internal functions) on the two guard
  entry points (`SafePolicyGuard.checkTransaction` 11-arg and `checkModuleTransaction`). It
  reverts any reentry into a new top-level check, which blocks a policy from reentering the
  Safe (`execTransaction`) or the configuration functions mid-check. It is intentionally NOT
  placed on the internal 6-arg `PolicyEngine.checkTransaction`, because `MultiSendPolicy`
  legitimately recurses into that per sub-transaction. Internal functions (rather than a
  modifier) avoid duplicating the guard bytecode at each entry point.
- **An in-check + same-Safe gate** on the 6-arg `PolicyEngine.checkTransaction`:
  `require($checkingSafe != address(0))` makes it unreachable outside a live guard check
  (closing the new ability to call a now-stateful check directly to mutate policy state),
  and `require(safe == $checkingSafe)` confines every recursive check to the Safe of the
  top-level transaction. This prevents a malicious policy configured on Safe A from
  driving checks — and thus corrupting stateful policy state — for an unrelated Safe B.
  `MultiSendPolicy` always recurses with the same `safe`, so it is unaffected.
- **`safeTxGas == 0`** enforced alongside the existing `gasPrice == 0`, so a Safe
  transaction whose inner call fails always reverts atomically and rolls back any state a
  policy staged during the pre-check (avoiding pre-check/post-execution desync given that
  `checkAfterExecution`/`checkAfterModuleExecution` remain no-ops).

A single reentrancy/checked-Safe flag (`$checkingSafe`, an `address`) serves as both the
"in-check" sentinel (`address(0)` means no check in progress) and the identity of the Safe
being checked. It uses **persistent storage (SSTORE)** for now, because EIP-1153 transient
storage is not available on every chain the guard may be deployed to. Migration to
transient storage is a tracked follow-up.

Non-mutating policies keep their `view`/`pure` mutability (a stricter override of a
non-`view` interface method compiles), so only `MultiSendPolicy` changes among the
policies (it must become non-`view` because it calls the non-`view` engine).

### Alternatives Considered

- **Post-execution hook for state (rejected for now).** Keep the pre-check `view`/
  `STATICCALL` and do accounting in `checkAfterExecution`. Pros: preserves the sandbox,
  fixes the success/failure desync via the `success` flag. Cons: larger interface change
  (new `IPolicy` method + a transient execution stack), converts enforcement from
  fail-closed to fail-open, cannot serve pre-conditions (only post-hoc accounting), and
  still needs a reentrancy guard. Recorded on #28 as the lower-risk option; not pursued
  because there is a concrete near-term writing-policy use case and the direct model is
  simpler to reason about with the guards above.
- **Config-during-check lockout (dropped).** Adding `require(!$checking)` to the config
  functions was considered as defense-in-depth. Dropped: the entry-point gate already
  blocks the only dangerous path (policy → Safe → config), and it has no current use case.
- **Global vs. per-policy protection.** We do both: a global gate at the guard boundary,
  plus a documented security contract that policy authors must follow (minimal external
  calls, `STATICCALL` for reads, own-namespace writes, CEI, bounded gas).

---

## Tech Specs

**Signatures losing `view`:**

- `IPolicy.checkTransaction` — `contracts/interfaces/IPolicy.sol:30`
- `IPolicyEngine.checkTransaction` — `contracts/interfaces/IPolicyEngine.sol:37`
- `PolicyEngine.checkTransaction` (6-arg) — `contracts/core/PolicyEngine.sol:114`
- `SafePolicyGuard.checkTransaction` (11-arg) — `contracts/SafePolicyGuard.sol:135`
- `SafePolicyGuard.checkModuleTransaction` — `contracts/SafePolicyGuard.sol:167`
- `MultiSendPolicy.checkTransaction` — `contracts/policies/MultiSendPolicy.sol:26`

**Staying `view`/`pure` (no change):** `getPolicy`, `_allowedCalls`, `_decodeSelector`,
`AccessSelector.*`, `supportsInterface`, and policies `AllowPolicy`, `DenyPolicy`,
`NativeTransferPolicy`, `ERC20TransferPolicy`, `ERC20ApprovePolicy`, `AllowedModulePolicy`,
`CoSignerPolicy`, `MockPolicy`. `IPolicy.configure` / `_confirmPolicy` are already
non-`view`.

**New state (`PolicyEngine`) — one variable:**

```solidity
// solhint-disable-next-line private-vars-leading-underscore
address private $checkingSafe; // address(0) => no check in progress; otherwise the Safe being checked
// TODO(#<transient-issue>): move to transient storage once all target chains support EIP-1153.
```

**New errors:** `Reentrancy()`, `NotChecking()`, `CrossSafeCheck()` (`PolicyEngine`);
`NonZeroSafeTxGas()` (`SafePolicyGuard`).

**New internal functions (`PolicyEngine`)** — shared bytecode instead of an inlined modifier:

```solidity
function _enterCheck(address safe) private {
    require($checkingSafe == address(0), Reentrancy()); // reentrancy gate
    $checkingSafe = safe;
}

function _exitCheck() private {
    $checkingSafe = address(0); // must reset (persistent storage); removable once transient
}
```

**6-arg `PolicyEngine.checkTransaction` preamble** (single site, kept inline):

```solidity
require($checkingSafe != address(0), NotChecking()); // checked before the equality, so `safe` can never match as address(0)
require(safe == $checkingSafe, CrossSafeCheck());
```

**Guard entry points:** `checkTransaction(11-arg)` and `checkModuleTransaction` call
`_enterCheck(msg.sender)` first and `_exitCheck()` last, and lose `view`.
`checkTransaction(11-arg)` additionally gains
`require(safeTxGas == 0, NonZeroSafeTxGas())` next to the existing `gasPrice == 0` check,
and names its 5th parameter `safeTxGas`.

**Selectors:** unchanged — state mutability is not part of the 4-byte function selector.

**Test cases:**

- `execTransaction` with `safeTxGas != 0` reverts `NonZeroSafeTxGas`.
- A policy reentering `guard.checkTransaction` / `Safe.execTransaction` during its check
  reverts `Reentrancy`.
- A policy calling the 6-arg engine `checkTransaction` for a different `safe` reverts
  `CrossSafeCheck`.
- A direct external 6-arg `checkTransaction` call outside a check reverts `NotChecking`.
- A `MultiSend` batch still passes (recursion allowed while `$checking`, same Safe).
- A state-writing policy's write commits on a successful transaction.
- Gas benchmark updated for `CALL` (vs `STATICCALL`) + the single `$checkingSafe` SSTORE (set/reset).

**Test contracts / fixtures:** new `contracts/test/ReentrantMockPolicy.sol` with modes
(reenter guard, reenter Safe, cross-Safe 6-arg call, plain state write) and a deploy
fixture under `test/deploy/`. Existing `MockPolicy` unchanged.

**Docs:** README stateful-model section (pre-execution only; `gasPrice`/`safeTxGas` must be
zero and why; reentrancy gate + same-Safe confinement; accepted residuals) and the
policy-author security contract in `IPolicy` NatSpec.

---

## Implementation Phases

Each phase is a separate, stacked PR (base = previous phase's branch). Target: one purpose,
< ~300 LOC, < 10 files, optimize for the reviewer.

### Phase 0 — This epic (PR, no implementation code)

- Files: `epics/2026_07_24_non_view_policy_checks.md`.
- Purpose: agree the plan before code.

### Prerequisite build-fix PRs (stacked on the epic, before the feature phases)

Single-purpose PRs that make the toolchain build/test-able:

- **P1 — `chore(deps)`: published safe-smart-account `^1.5.0`** (branch
  `chore/deps-safe-smart-account`, base epic). `package.json` + `package-lock.json` +
  `test/deploy/SafeContracts.ts` (drop `SafeToL2Migration`, removed in 1.5.0). Replaces the
  git dependency — whose install-time `build:zk` can't download compilers (old Hardhat/undici)
  — with the published package that ships prebuilt artifacts.
- **P2 — `chore(deps)`: upgrade hardhat `^2.29.0`** (branch `chore/upgrade-hardhat`, base P1).
  `package.json` + `package-lock.json`. Fixes the EDR error-inferrer panic (SIGABRT) on reverts
  from the guard entry, making those reverts testable.
- **P3 — `test(deploy)`: drop unused Safe fixture deployments** (branch
  `test/drop-unused-safe-fixtures`, base P2). `test/deploy/SafeContracts.ts` — remove 7
  deployed-but-unconsumed contracts, leaving `safe`, `compatibilityFallbackHandler`,
  `multiSend`, `safeProxyFactory`.

The feature phases below stack on P3 (Phase 1 `safeTxGas` bases on P3, not `main`).

### Phase 1 — Enforce `safeTxGas == 0`  (branch `feat/enforce-zero-safe-tx-gas`, base P3)

- Files: `contracts/SafePolicyGuard.sol`, `test/safePolicyGuard.spec.ts`.
- Components: transaction-guard entry (`NonZeroSafeTxGas` error + `require`).
- Standalone and safe on its own (function stays `view` in this phase). Existing tests
  already pass `safeTxGas = 0` (`src/utils.ts` default), so no breakage expected.

### Phase 2a — Non-`view` check path + reentrancy gate + same-Safe confinement  (branch `feat/non-view-check-path`, base Phase 1)

- Files: `contracts/interfaces/IPolicy.sol`, `contracts/interfaces/IPolicyEngine.sol`,
  `contracts/core/PolicyEngine.sol`, `contracts/SafePolicyGuard.sol`,
  `contracts/policies/MultiSendPolicy.sol`, plus a minimal smoke test.
- Components: drop `view` (6 signatures); single `$checkingSafe` flag + `_enterCheck`/
  `_exitCheck`; 6-arg gates (`NotChecking`, `CrossSafeCheck`); `MultiSendPolicy` non-`view`;
  security-contract NatSpec on `IPolicy`.
- Atomic security unit — dropping `view` and adding the guards land together.
- Verify during implementation that no existing spec calls the engine/guard 6-arg
  `checkTransaction` directly (would now hit `NotChecking`); migrate any that do.

### Phase 2b — Reentrancy / gate test suite  (branch `feat/non-view-check-path-tests`, base Phase 2a)

- Files: `contracts/test/ReentrantMockPolicy.sol` (new), `test/deploy/…` (new fixture),
  `test/reentrancy.spec.ts` (new), `test/gasBenchmark.spec.ts`.
- Components: mock policy with reenter-guard / reenter-Safe / cross-Safe-6-arg / state-write
  modes; specs for `Reentrancy`, `NotChecking`, `CrossSafeCheck`, MultiSend-still-passes, and
  state-commit-on-success; gas benchmark update.

### Phase 3 — Docs  (branch `docs/stateful-policy-model`, base Phase 2)

- Files: `README.md` (and any other affected docs).
- Components: reconcile with #27; document stateful model, requirements, residuals.

### Phase 4 — Cleanup (final)

- Remove `epics/2026_07_24_non_view_policy_checks.md`.

**Follow-up (separate issue, not a phase):** move `$checkingSafe` to EIP-1153 transient
storage on Cancun-capable targets.

---

## Open Questions and Assumptions

**Assumptions**

- There is a concrete near-term stateful ("writing") policy use case that justifies this
  change; the epic proceeds on that basis.
- Deployment targets include chains without EIP-1153, so persistent storage is used for the
  reentrancy flags now.
- `checkAfterExecution` / `checkAfterModuleExecution` remain no-ops (no post-execution hook
  in this epic).
- Removing `view` is not selector-breaking; off-chain consumers that call `checkTransaction`
  via `eth_call`/`staticCall` semantics may need to adjust, which is acceptable.

**Accepted residual risks (documented, not mitigated in code)**

- **Module-path execution-success gap:** the module guard has no `safeTxGas`, so whether the
  underlying `execTransactionFromModule` succeeded is up to the module. A stateful policy on
  the module path cannot guarantee its staged state matches execution outcome.
- **Within-Safe cross-policy interference:** the same-Safe confinement stops cross-Safe
  attacks, but a Safe's own malicious/buggy configured policy can still trigger checks of
  other policies for that same Safe. This is "be careful what you activate" — bounded to the
  misconfiguring Safe.

**Open questions**

- Final list of target deployment chains (drives the transient-storage follow-up timing).
- Who creates the transient-storage follow-up issue (no `gh`/token available in this
  environment)?
