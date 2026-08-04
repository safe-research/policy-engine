# Plan: Audit-readiness hardening

Component: policy-engine smart contracts (`contracts/`)

---

## Overview

An adversarial audit-readiness review of the engine core (`PolicyEngine`, `SafePolicyGuard`,
`contracts/interfaces/`, `AccessSelector`, `Stack`, and `MultiSendPolicy` as the recursion
boundary) produced three demonstrated High findings, one demonstrated Medium, and a set of
documentation and hygiene gaps. This epic closes them so an external audit can start on a clean
tree.

Every code finding below was reproduced with an executed test against `main` (baseline: 81
passing). None of them were fixed by the non-view stack's merge edits.

Two of the findings are **not new** — the deleted non-view epic recorded them as accepted
residual risks:

- *"Module-path execution-success gap: the module guard has no `safeTxGas` … a stateful policy on
  the module path cannot guarantee its staged state matches execution outcome."* → now fixed
  (**M-1**).
- *"Within-Safe cross-policy interference … bounded to the misconfiguring Safe."* → already
  documented on `main` (`README.md:39`), so **no work in this epic**.

The first is the reason this epic exists: a residual risk recorded only in an epic file
disappears when that file is deleted. This epic therefore ends by putting its own residuals in
the README and NatSpec rather than here.

Steps, each a separate stacked PR:

1. **Authenticated `module` parameter** — kills the module-identity spoof (H-1); production code
   as phase 1, security tests as phase 2. Sequenced first because it changes `IPolicy`, and
   everything downstream should build on the final signature.
2. **Block `configureImmediately` once the guard is live** — restores the DELAY timelock (H-3).
3. **Module-execution atomicity** — `checkAfterModuleExecution` reverts on failure (M-1).
4. **Typed signature extension** — replaces the ambiguous context envelope (L-1).
5. **Bubble policy revert reasons** (L-4).
6. **Chore** — delete `Stack.sol`, pin `evmVersion`, clear TODOs (I-3, I-4, I-1).
7. **Test coverage** — close the gaps the review found (I-8 and the untested-controls list).
8. **Docs** — mandatory dual-guard setup, interface contracts, residual risks (H-2, I-5, I-7).
9. **Cleanup** — remove this epic file.

**Deliberately out of scope.** M-4 (MultiSend pairs sub-transaction contexts positionally and
yields empty once exhausted), L-2 (fallback access key aliases `(address(0), 0x00000000, op)`),
L-3 (1–3 byte calldata rejected with `InvalidSelector`), I-2 (transient storage — existing
follow-up), I-6 (Safe-version assumptions document). All fail closed and are documented rather
than changed. M-3 (timelock observability) becomes a separate follow-up issue.

**Out of scope but blocking in practice.** `setModuleGuard` appears nowhere in `app/` — the Safe
App handles only `setGuard` (`app/src/App.tsx:122,135,164,356-358,377,405-407,692`;
`app/src/utils/constants.ts:127,188`). The App therefore produces exactly the configuration that
H-2 shows is a complete bypass. Tracked as a separate high-priority issue against `app/`, since
it is a different codebase area with a different review path; H-2 remains live in the product
until it lands.

---

## Architecture Decisions

### H-1 — the module identity moves out of `context` and into engine state

**The finding.** `context` carries two semantically different things with no discriminator:
executor-chosen bytes carved out of `signatures` on the transaction path
(`SafePolicyGuard.sol:166`), and an engine-authenticated module address on the module path
(`SafePolicyGuard.sol:188`). Safe does not cover `signatures` with the transaction hash and
accepts arbitrary trailing bytes (`checkNSignatures` only enforces
`signatures.length >= requiredSignatures * 65`), so any executor — including a non-owner
relayer replaying signatures — chooses `context` freely. `AllowedModulePolicy` reads it as a
module address, so a forged 32-byte context satisfies it from the transaction path.

**The decision.** This is not a policy *selection* problem, it is a policy *input* problem.
Selection stays exactly as it is: one policy list, two fallback keys, no new dimension in
`AccessSelector`. `IPolicy.checkTransaction` gains an `address module` parameter.

**Where the value comes from is the security-critical part: engine storage, not an argument.**
If the recursive entry point (`IPolicyEngine.checkTransaction`) took `module` as an argument, a
malicious policy would pass a forged one and the spoof would move from the signatures blob into
the recursion path. So the guard records the module at `_enterCheck` time and the engine injects
it into every policy call, recursive ones included. `IPolicyEngine.checkTransaction` and
`MultiSendPolicy`'s recursion call (`MultiSendPolicy.sol:35`) are therefore **unchanged**.

A second storage slot is genuinely required. A module-initiated MultiSend batch must carry the
module identity into its sub-checks, or `AllowedModulePolicy` on a sub-transaction would see
`address(0)` and deny — a functional regression. There is no way to thread it through the public
recursion entry point without trusting the caller.

**Consequence.** On the module path `context` becomes empty, and `context` acquires a single
uniform meaning across both paths: *executor-supplied extension data, untrusted everywhere*.
Modules gain no way to pass context; nothing is lost, because `abi.encode(module)` was the only
thing it ever carried there.

### H-3 — read the Safe's guard slots rather than latching

`configureImmediately` (`SafePolicyGuard.sol:234`) has no guard-enabled check. Its NatSpec
asserts the function is self-limiting ("if the guard is set, then this tx will fail in
`checkTransaction`"), which holds only when no configured policy authorizes a `CALL` to the
guard. The condition for it to fail is simply that *some* configured policy authorizes a `CALL` to
this contract; a permissive fallback is one way to get there, and the README already advertises
fallback policies as a supported shape (line 83). It then allows a full policy rewrite and guard
removal with zero delay.

**The decision.** `require(!_isGuardEnabled(msg.sender))`, implemented by reading the two
well-known Safe guard storage slots via `ISafe.getStorageAt` and comparing against
`address(this)`.

**A monotonic latch was evaluated and rejected.** Setting `$hardened[safe] = true` on the first
`_enterCheck` is layout-independent and closes its own bootstrap window — the
`configureImmediately` call passes through the guard hook first, so the latch is already set when
the function body runs. It was rejected for two reasons:

- **Permanent griefing.** Anyone can call the 11-arg `checkTransaction` directly. A Safe tricked
  into calling the guard entry point before installing the guard would latch itself out of the
  bootstrap path forever, forced through a `DELAY`-long wait for initial setup.
- **It breaks the documented re-bootstrap flow** at `README.md:103` ("if the Safe reactivates the
  guard, this policy should be removed … with `configureImmediately` before the guard is
  enabled"), because the latch never clears when the guard is removed.

Reading the slots has neither problem and expresses the actual condition. The cost is coupling to
Safe's storage layout, which is acceptable: both slots are documented `internal constant`s in
Safe 1.5.0 (`GuardManager.sol:66`, `ModuleManager.sol:65`) and both were verified twice — against
that source and by independent keccak of their preimages.

Both slots are checked: either the transaction guard or the module guard pointing at this
contract means "live". Only `== address(this)` blocks — a *different* guard being installed is
irrelevant, since this engine is not enforcing anything for that Safe. The read must be a
**low-level staticcall with graceful failure**, so a non-Safe caller (an EOA calling
`configureImmediately` for itself, exercised today at `test/policyEngine.spec.ts:95`) keeps
working instead of reverting on a failed ABI decode.

### M-1 — atomicity enforced locally instead of assumed from Safe

`checkAfterModuleExecution` (`SafePolicyGuard.sol:197`) stops being a no-op and reverts when
`success == false`. This is the only path where the hook is load-bearing:
`execTransactionFromModule` returns `false` without reverting, so there is no `safeTxGas`
equivalent to force atomicity. The transaction path is already atomic — Safe reverts when
`!success && safeTxGas == 0 && gasPrice == 0`, and both are enforced at `SafePolicyGuard.sol:157`
and `:163`.

`checkAfterExecution` (`SafePolicyGuard.sol:174`) also gets `require(success)` as
belt-and-braces. It is unreachable while `safeTxGas == 0` and `gasPrice == 0` hold, and the
comment will say so. It is included anyway because converting a cross-contract assumption about
Safe into a locally-enforced invariant is exactly what would have prevented the module-path bug
in the first place.

Neither hook needs a reentrancy gate: they hold no state, and an external caller passing
`success == false` merely reverts its own call.

**Behavioural change to document:** modules that deliberately tolerate a failing inner call will
now revert. That is the intent.

### L-1 — vendor `SignatureExtension`

Replace the `[sigs][context][uint256 len]` envelope at `SafePolicyGuard.sol:203` with
`[sigs][payload][uint256 len][bytes32 typeHash]`, from
`safe-research/safenet`'s `SignatureExtension` library.

The fix is that the discriminator is the **terminal** word. Today the last 32 bytes are a length,
which is exactly where an honest EIP-1271 contract-signature tail lands — Safe requires the
contract-signature pointer to sit past the static part — and `length <= end` can accidentally
hold. Anchoring a type hash there drops accidental collision to ~2⁻²⁵⁶.

Three further properties matter: the format is typed *and versioned*, so a later change is
non-breaking and older consumers read it as "no extension"; `has()` is non-reverting, preserving
the property that plain ECDSA signatures need no `uint256(0)` padding (which
`SafePolicyGuard.sol:204-207` exists to provide); and `payload()` is self-verifying and reverts
on a malformed envelope instead of silently yielding empty context.

Vendored into `contracts/libraries/SignatureExtension.sol` with a provenance header. Licensing is
not a concern — both repositories are `safe-research`. The pragma relaxes from `^0.8.30` to
`^0.8.28`; nothing in the library needs 0.8.30 (`require(cond, CustomError())` is available from
0.8.26 under viaIR, already used throughout this repo).

**This does not fix H-1.** It makes context unambiguous, not authenticated — any executor can
still build a well-formed envelope with any payload. H-1's fix is independent and is what closes
the spoof.

### L-4 — bubble the policy revert reason

`catch { revert AccessDenied(policy); }` (`PolicyEngine.sol:166-172`) erases all diagnostics, and
it compounds: for a MultiSend batch the inner `AccessDenied(realPolicy)` is caught by the outer
engine and re-emitted as `AccessDenied(multiSendPolicy)`, so the actually-denying policy and
sub-transaction are unknowable on chain. Out-of-gas and deliberate deny are also
indistinguishable.

Note for review: the construction can only ever turn success into denial, never denial into
success — the magic-value `require` sits inside the `try` block, and an out-of-gas policy call
under the 63/64 rule leaves the outer frame enough gas to revert. There is no bypass here; the
cost is purely diagnostic.

**The decision.** Add `error PolicyReverted(address policy, bytes reason)` and wrap the caught data
once, unconditionally: `catch (bytes memory reason) { revert PolicyReverted(policy, reason); }`.

An earlier draft of this plan re-threw the caught bytes verbatim when they already began with an
engine error's selector (`AccessDenied` or `PolicyReverted`), to keep the root cause intact through
`MultiSendPolicy`'s recursion without growing the payload. **That is unsafe and was dropped during
review.** Selectors are public, so a policy can revert with `AccessDenied(someOtherPolicy)` and the
engine would forward it unchanged — making the policy address in the top-level error forgeable, which
is precisely the property the change exists to provide. The impact is diagnostics-only (the
transaction reverts either way, so there is no bypass), but it falsifies the guarantee.

No marker mechanism can rescue the re-throw: any selector is forgeable, and state written in a frame
that reverts is discarded — transient storage included — so the engine cannot attest its own nested
revert. Wrapping unconditionally means every layer's `policy` field is engine-supplied and therefore
trustworthy, and the nesting becomes visible rather than collapsed.

**No length cap**, and no assembly. The reasoning, since this is the one place attacker-influenced
data is copied into memory:

- *The returndata-bomb class exists but is inert here.* A policy returning enormous revert data
  forces a quadratic memory expansion and an out-of-gas in the catch. That cannot turn a deny into
  an allow — the magic-value `require` sits inside the `try`, so approval requires the call to have
  succeeded — and the outcome is a revert of a transaction that was already reverting. The gas is
  paid by whoever submitted that transaction, not from the Safe.
- *Nesting growth is real but small.* Wrapping at every level adds roughly one error frame per
  level, and realistic `MultiSendPolicy` nesting is one to three deep. Depths large enough to matter
  already exhaust gas on the 63/64 rule regardless.
- *Bounding the copy would cost more than it buys.* Solidity copies all returndata before the size
  can be inspected, so capping it means abandoning `try/catch` for a low-level `call` with a manual
  `returndatacopy` — hand-rolled assembly in the engine's most security-critical line.

Trade-off accepted: the top-level error names the outermost policy with the inner data nested inside,
rather than surfacing the root cause directly. Attribution that is trustworthy at every layer is
worth more than a shorter payload.

### M-2 — no work required (closed on `main`)

The review flagged that a policy can drive any other policy of the same Safe with arbitrary
parameters, and that this was documented nowhere durable. `main` already closes the
documentation gap: `README.md:39` describes the within-Safe surface and its bound,
`PolicyEngine.sol:147-156` explains that `msg.sender` is deliberately unchecked because the
legitimate re-entrant caller is a policy whose address is not known in advance, and
`test/reentrancy.spec.ts` now proves the cross-Safe case end to end (policy X on Safe A cannot
reach Safe B's stateful policy Y) plus the same-Safe case as intended behaviour.

No code mechanism is proposed, because none works:

- **Active-policy pinning fails.** Requiring `msg.sender == $activePolicy` for recursion does
  nothing — the attacker *is* the active policy, mid-check, and passes its own gate.
- **A declared-capability flag fails.** A malicious policy simply declares itself
  recursion-capable. It buys UI visibility, not enforcement.
- **A recursion depth cap was considered and not taken.** It bounds gas amplification but not
  the primitive, and adds a branch to the hot path.

Under the trust model — policies are deliberately installed, individually-audited contracts —
nothing on-chain stops a policy the Safe *chose* to install from using the API `MultiSendPolicy`
needs. The containment that matters is cross-Safe, and `CrossSafeCheck`
(`PolicyEngine.sol:158`) delivers it. The only residue is that `_enterCheck`'s own docstring
(`PolicyEngine.sol:177-183`) is still silent on what the gate permits; a one-line cross-reference
is folded into the docs phase.

---

## Tech Specs

### Signature changes

`IPolicy.checkTransaction` — `contracts/interfaces/IPolicy.sol:30`:

```solidity
function checkTransaction(
    address safe,
    address to,
    uint256 value,
    bytes calldata data,
    Operation operation,
    address module,          // NEW: engine-authenticated; address(0) on the transaction path
    bytes calldata context,  // UNTRUSTED on every path; never an identity claim
    AccessSelector.T access
) external returns (bytes4 magicValue);
```

**Unchanged:** `IPolicyEngine.checkTransaction` (6-arg), so `MultiSendPolicy`'s recursion needs no
edit. Also `getPolicy`, `AccessSelector.*`, `_decodeSelector`, `_allowedCalls`,
`supportsInterface`, the entire configuration lifecycle, and the selectors of all existing
functions.

**Mechanical implementer updates** (add the parameter, ignore it): `AllowPolicy`, `DenyPolicy`,
`NativeTransferPolicy`, `ERC20TransferPolicy`, `ERC20ApprovePolicy`, `CoSignerPolicy`,
`MultiSendPolicy`, and the test mocks `MockPolicy` and `ReentrantMockPolicy`.

**Semantic update — `AllowedModulePolicy` only:**

```solidity
-  address module = abi.decode(context, (address));
-  require($allowedModules[msg.sender][safe][module], UnauthorizedModule());
+  require(module != address(0), InvalidModule());   // InvalidModule is declared today and unused
+  require($allowedModules[msg.sender][safe][module], UnauthorizedModule());
```

`configure` should also reject `abi.decode(data, (address)) == address(0)`, so no
`$allowedModules[…][address(0)]` entry can exist for a transaction-path check to match.

### New state — `PolicyEngine`

```solidity
// solhint-disable-next-line private-vars-leading-underscore
address private $checkingModule; // module driving the current check; address(0) on the tx path

function _enterCheck(address safe, address module) internal {
    require($checkingSafe == address(0), Reentrancy());
    $checkingSafe = safe;
    $checkingModule = module;
}

function _exitCheck() internal {
    $checkingSafe = address(0);
    $checkingModule = address(0);
}
```

Written unconditionally, maintaining the same "zero outside a check" invariant as
`$checkingSafe`. A conditional write to skip the transaction-path cost was considered and
rejected: the branch needs an `SLOAD` costing about the same as the no-op `SSTORE` it saves.

Policy invocation reads from storage, never from an argument:

```solidity
try IPolicy(policy).checkTransaction(
    safe, to, value, data, operation, $checkingModule, context, access
) returns (bytes4 magicValue) {
    require(magicValue == IPolicy.checkTransaction.selector, AccessDenied(policy));
} catch (bytes memory reason) {
    revert PolicyReverted(policy, reason);
}
```

The caught data is always wrapped, never re-thrown verbatim, so the `policy` field is
engine-supplied at every layer and cannot be forged by the policy — see the L-4 decision above.

### New constants — `SafePolicyGuard`

```solidity
/// @dev keccak256("guard_manager.guard.address") — Safe `GuardManager.GUARD_STORAGE_SLOT`.
bytes32 private constant _GUARD_STORAGE_SLOT =
    0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
/// @dev keccak256("module_manager.module_guard.address") — Safe `ModuleManager.MODULE_GUARD_STORAGE_SLOT`.
bytes32 private constant _MODULE_GUARD_STORAGE_SLOT =
    0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

/// @dev keccak256("SafePolicyGuard.PolicyContext.v1")
bytes32 private constant _CONTEXT_TYPE_HASH =
    0x5aa463b48748f9162d63ae93151d31fed6a96b34cd2ae84ef33d25b0bdea62e4;
```

`MODULE_GUARD_STORAGE_SLOT` is also added to `lib/constants.ts` alongside the existing
`GUARD_STORAGE_SLOT`.

### New errors

`GuardAlreadyEnabled()`, `ExecutionFailed()`, `ModuleExecutionFailed()` (`SafePolicyGuard`);
`PolicyReverted(address policy, bytes reason)` (`PolicyEngine`). `AccessDenied(address policy)`
is retained for the no-policy-configured and wrong-magic-value cases.

### Entry points

```solidity
// transaction guard
require(gasPrice == 0, NonZeroGasPrice());
require(safeTxGas == 0, NonZeroSafeTxGas());
_enterCheck(msg.sender, address(0));
checkTransaction(msg.sender, to, value, data, operation, _decodeContext(signatures));
_exitCheck();

// module guard — context is now empty; the module travels out-of-band
_enterCheck(msg.sender, module);
checkTransaction(msg.sender, to, value, data, operation, _emptyContext());
_exitCheck();
return bytes32(0);

// after-execution hooks
function checkAfterExecution(bytes32, bool success) external override {
    // Unreachable while `safeTxGas == 0` and `gasPrice == 0` are enforced (the Safe reverts
    // first); kept so atomicity is a local invariant rather than an assumption about the Safe.
    require(success, ExecutionFailed());
}

function checkAfterModuleExecution(bytes32, bool success) external override {
    // The module path has no `safeTxGas`: `execTransactionFromModule` returns `false` without
    // reverting, so without this a policy's pre-check writes commit against a failed action.
    require(success, ModuleExecutionFailed());
}
```

### Guard-enabled check

```solidity
function configureImmediately(Configuration[] calldata configurations) external virtual {
    require(!_isGuardEnabled(msg.sender), GuardAlreadyEnabled());
    // ... existing loop
}

function _isGuardEnabled(address safe) internal view returns (bool) {
    return _guardSlot(safe, _GUARD_STORAGE_SLOT) == address(this) ||
        _guardSlot(safe, _MODULE_GUARD_STORAGE_SLOT) == address(this);
}
```

`_guardSlot` performs a low-level `staticcall` to `getStorageAt(uint256(slot), 1)` and returns
`address(0)` when the call fails or the return data is malformed, so non-Safe callers keep
working. Safe returns ABI-encoded `bytes` (96 bytes: offset, length, word).

### Context decoding

```solidity
function _decodeContext(bytes calldata signatures) internal pure returns (bytes calldata) {
    if (!SignatureExtension.has(signatures, _CONTEXT_TYPE_HASH)) return _emptyContext();
    return SignatureExtension.payload(signatures, _CONTEXT_TYPE_HASH);
}
```

Behaviour change: a malformed envelope now reverts `MalformedSignatureExtension` (a deny) instead
of silently returning empty context. `src/utils.ts`'s `additionalData` packing and every
`CoSignerPolicy` spec move to the new format.

### Test cases

New negative tests, each of which fails against `main` today:

- A non-owner executor appending `abi.encode(module)` to `signatures` must **not** satisfy
  `AllowedModulePolicy` on the transaction path (H-1).
- A failed `execTransactionFromModule` must leave stateful policy state **unchanged** (M-1), with
  the transaction path as control.
- `configureImmediately` must revert `GuardAlreadyEnabled` post-guard **even with a permissive
  fallback installed** (H-3); must still work pre-guard, from an EOA, and again after the guard
  is removed.
- A module-initiated MultiSend must still satisfy `AllowedModulePolicy` on its sub-transactions,
  proving `$checkingModule` propagates through recursion.

Gap-closing tests from the review:

- `gasPrice != 0` rejected end to end through `execTransaction` — **no test exists today**.
- `safeTxGas != 0` rejected end to end, not only via a direct guard call
  (`test/safePolicyGuard.spec.ts:817` currently calls the guard directly).
- Fallback dispatch: exact match wins over fallback; fallback used when no exact match exists;
  a `DELEGATECALL` fallback does not authorize a `CALL`.
- Full guard-removal lifecycle: `requestConfiguration` → delay → `applyConfiguration` +
  `setGuard(0)` in one MultiSend; negatives at `DELAY - 1` and after `invalidateRoot`.
- A policy that **actually reverts** → `PolicyReverted(policy, reason)`; a policy returning a
  wrong non-zero `bytes4` → `AccessDenied(policy)`.
- Reentrancy into `applyConfiguration` from a malicious `IPolicy.configure` → `RootNotConfigured`,
  locking in the CEI ordering at `SafePolicyGuard.sol:280`.
- `Reentrancy` via the **module** guard entry — only the transaction entry is covered today.
- **I-8:** legitimate nested Safe-A → Safe-B execution under the same guard singleton must
  **succeed**, asserting the gate does not over-block (`_exitCheck` runs before execution
  begins).
- Module-guard-absent behaviour pinned explicitly, so H-2 is an asserted property rather than a
  surprise.

**Test contract changes.** `ReentrantMockPolicy` was refactored on `main` — `Mode.CrossSafe` is
now `Mode.ReenterEngine`, `setOtherSafe(address)` is now `setReenter(address,address)`, and there
is a new `reenterSucceeded` flag. New tests must use that API. Additions needed: a mock that
genuinely reverts with a custom error (a `MockPolicy` flag is enough, since the existing
`revertTransaction` flag only returns a zero magic value), a malicious `configure` that re-enters
`applyConfiguration`, and a module able to execute a MultiSend batch.

---

## Implementation Phases

Each phase is a separate stacked PR (base = previous phase's branch). Target: one purpose,
< ~300 LOC, < 10 files, optimize for the reviewer.

### Phase 0 — This epic (PR, no implementation code)

- Files: `epics/2026_08_04_audit_readiness_hardening.md`.
- Purpose: agree the plan before code.

### Phase 1 — Authenticated `module` parameter (branch `feat/authenticated-module-param`, base Phase 0)

- Files: `contracts/interfaces/IPolicy.sol`, `contracts/core/PolicyEngine.sol`,
  `contracts/SafePolicyGuard.sol`, all `contracts/policies/`, `contracts/test/MockPolicy.sol`,
  `contracts/test/ReentrantMockPolicy.sol`.
- Components: the new parameter; `$checkingModule` with the two-argument `_enterCheck`;
  `AllowedModulePolicy` reading `module` instead of `context`; mechanical updates elsewhere.
- Sequenced first so later phases build on the final `IPolicy` signature.
- The only semantic edit is in `AllowedModulePolicy`; every other policy change is additive.

### Phase 2 — H-1 security tests (branch `feat/authenticated-module-param-tests`, base Phase 1)

- Files: `test/moduleContext.spec.ts` (new), `test/allowedModulePolicy.spec.ts`.
- Components: the forged-context negative test with a non-owner executor; module-path positive;
  module-initiated MultiSend propagation.

### Phase 3 — Block `configureImmediately` when guarded (branch `feat/block-configure-immediately-when-guarded`, base Phase 2)

- Files: `contracts/SafePolicyGuard.sol`, `lib/constants.ts`, `test/safePolicyGuard.spec.ts`.
- Components: the two slot constants; `_isGuardEnabled` / `_guardSlot`; the `require`; NatSpec
  correction on `configureImmediately`.
- The existing test at `test/safePolicyGuard.spec.ts:251` still passes unchanged — the guard check
  denies before the function body runs, so it keeps reverting `AccessDenied`. All fixtures
  configure before `setGuard`, so no fixture breakage is expected.

### Phase 4 — Module-execution atomicity (branch `feat/module-execution-atomicity`, base Phase 3)

- Files: `contracts/SafePolicyGuard.sol`, `test/safePolicyGuard.spec.ts`.
- Components: both after-execution hooks; the desync test with its transaction-path control.

### Phase 5 — Typed signature extension (branch `feat/signature-extension-context`, base Phase 4)

- Files: `contracts/libraries/SignatureExtension.sol` (new, vendored), `contracts/SafePolicyGuard.sol`,
  `src/utils.ts`, `test/coSignerPolicy.spec.ts`.
- Components: vendored library with provenance header and relaxed pragma; `_decodeContext`
  rewrite; the `additionalData` helper and its consumers moved to the new envelope.

### Phase 6 — Bubble policy revert reasons (branch `feat/bubble-policy-revert-reason`, base Phase 5)

- Files: `contracts/core/PolicyEngine.sol`, affected specs.
- Components: `PolicyReverted`; `catch (bytes memory reason)`; specs updated where they assert
  `AccessDenied` for a reverting policy.

### Phase 7 — Chore (branch `chore/audit-readiness-cleanup`, base Phase 6)

- Files: delete `contracts/libraries/Stack.sol`, `contracts/SafePolicyGuard.sol` (the commented
  `Stack.T $afterExecutionChecks;` at line 49 and its TODO), `hardhat.config.ts`, TODO removals
  across `contracts/core/PolicyEngine.sol` and `contracts/SafePolicyGuard.sol`.
- **`evmVersion`:** pin `paris` explicitly on every remaining (0.8.28) configuration — the main
  compiler plus both `overrides`, which replace settings wholesale. Today `paris` comes from
  Hardhat's default, so a Hardhat upgrade that changes that default would silently change deployed
  bytecode.
- **Delete the 0.7.6 compiler entry.** It is dead config, added in `cb19d2c` (#2) and superseded by
  the `safe-smart-account@^1.5.0` upgrade (`e639317`). Four independent checks confirm nothing
  selects it:
  1. Every pragma under `contracts/` is 0.8.28 (17 × `^0.8.28`, 11 × `=0.8.28`, 1 × `0.8.28`).
  2. Across every source in `artifacts/build-info/`, including transitive dependencies, the only
     pragmas are `>=0.7.0 <0.9.0` (75 Safe files), `^0.8.20` (16 OpenZeppelin files), and the
     0.8.28 variants above — none of which excludes 0.8.28.
  3. Hardhat has only ever downloaded solc 0.8.28 (native and wasm caches contain nothing else).
     Compilers are fetched lazily per requirement, so a needed 0.7.6 would be present.
  4. All `artifacts/build-info/*.json` report `solcVersion: 0.8.28`.

  Deleting it also removes a trap for the `evmVersion` pin, since solc 0.7.6's maximum
  `evmVersion` is `berlin` and pinning `paris` there would break the build. If something does turn
  out to need it, CI fails loudly on the next build.
- **TODOs.** `SafePolicyGuard.sol:111` and `PolicyEngine.sol:123` ("Consider the security
  considerations of calling `checkTransaction` as a Safe transaction") are resolved by Phase 3 and
  should be removed. `SafePolicyGuard.sol:45` (post-condition checks / execution stack) is
  partly superseded by Phase 4. `PolicyEngine.sol:31` (transient storage), `:78` (event data
  type), and `:110` (additional fallback policies) become tracked issues. Nothing security-
  relevant should remain as an inline TODO.

### Phase 8 — Test coverage (branch `test/engine-security-coverage`, base Phase 7)

- Files: `test/engineSecurity.spec.ts` (new), `test/safePolicyGuard.spec.ts`,
  `test/gasBenchmark.spec.ts`, `contracts/test/` mock additions.
- Components: the gap-closing list above, including the missing `gasPrice` control and I-8; gas
  benchmark updated for the second `SSTORE` pair.

### Phase 9 — Docs (branch `docs/audit-readiness`, base Phase 8)

- Files: `README.md`, `contracts/interfaces/IPolicy.sol`, `contracts/core/PolicyEngine.sol`.
- Components:
  - A new **"Setup with Safe"** section: `setGuard` **and** `setModuleGuard` are both mandatory
    and co-equal; installing only one leaves a complete bypass; set both atomically via MultiSend;
    any module enabled before hardening is unconstrained until the module guard is set. This
    section is the whole of H-2 — there is no code fix.
  - Guard-removal section updated to require removing both.
  - `README.md:31` corrected: the `safeTxGas == 0` atomicity claim is currently unqualified and
    was only ever true for the transaction path. Phase 4 makes it true for both; the sentence must
    say how.
  - `IPolicy.checkTransaction`: `context` is untrusted on every path and never an identity claim;
    `module` is authenticated by the engine; `access` degrades to the fallback key under fallback
    dispatch, so policies must authorize on `to`/`data` (L-2 documented, not fixed).
  - `IPolicy.configure` security contract: `configureImmediately` is callable by any address for
    itself, so `configure` may be invoked with a caller-chosen `safe`, `access`, and `data`;
    namespace by `(msg.sender, safe)` and never assume a real Safe (I-5).
  - `baseGas` / `gasToken` / `refundReceiver` are not forwarded, so policies cannot bind to the
    Safe transaction hash — stated as a deliberate limitation (I-7).
  - `_enterCheck` NatSpec: one line pointing at what the gate permits, cross-referencing the
    `checkTransaction` comment block and `README.md:39`.
  - Redeployment note (see below).

### Phase 10 — Cleanup (final)

- Remove `epics/2026_08_04_audit_readiness_hardening.md`.

---

## Open Questions and Assumptions

**Assumptions**

- The `IPolicy` interface break is acceptable pre-audit; no third-party policies are deployed
  against the current signature.
- Safe 1.5.0's storage slots for both guards are stable across all target deployments. Phase 3
  couples to them.
- Modules that rely on a failing inner call *not* reverting are not a supported use case
  (Phase 4).
- `checkAfterExecution` / `checkAfterModuleExecution` are the only hooks needed; no execution
  stack is introduced.
- Policy business logic remains out of scope; only `AllowedModulePolicy` changes, and only
  because it is the direct consumer of the H-1 fix.

**Operational note**

- Every phase changes the guard bytecode, so the CREATE2 singleton address changes. Existing
  deployments must be redeployed and Safes re-pointed. A redeploy/migration note belongs in
  Phase 9.

**Accepted residual risks (to be documented, not mitigated in code)**

- **Dual-guard installation (H-2).** Not enforceable in the guard; documentation only, plus the
  separate `app/` issue.
- **Within-Safe cross-policy interference (M-2).** Already documented on `main`; no mechanism
  exists under the current trust model.
- **Unauthenticated context payload.** `SignatureExtension` makes context unambiguous, not
  authenticated; any executor still chooses the payload.
- **MultiSend context/sub-transaction count mismatch (M-4).** Contexts are paired positionally
  and silently yield empty once exhausted.
- **Fallback key aliasing (L-2)** and **1–3 byte calldata rejection (L-3).** Both fail closed.

**Resolved during planning** (recorded here so the decisions survive this file's deletion)

- **`PolicyReverted` reason length:** no cap; re-throw engine errors verbatim instead. Rationale in
  the L-4 decision above.
- **The 0.7.6 compiler entry:** deleted in Phase 7. Evidence in that phase.
- **`AllowedModulePolicy.configure` with a zero module address:** rejected. Strictly safer, and
  nothing is deployed against the current behaviour.
- **Follow-up issues** (the unresolved TODOs, M-3 timelock observability, the `app/` dual-guard
  gap, and the transient-storage migration) are tracked outside this epic. Drafts were produced
  during planning; filing them is a manual step, as no `gh` or token is available in this
  environment.
