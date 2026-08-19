> [!WARNING]
> Code in this repository is not audited and may contain serious security holes. Use at your own risk.

![Policy Engine](./app/public/policy-engine.svg)

# Safe{Policies}

This sub-package contains an on-chain policy engine for the Safe smart account. It implements a fine-grained and extensible mandatory access control system on transactions.

## Design

The core contract is the `SafePolicyGuard` contract which is both a Safe transaction guard and a module guard. This guard ensures that all executed transactions have an associated policy that they satisfy, regardless of the authorization method. Policy matching and verification are implemented by the `PolicyEngine` abstract contract (which the `SafePolicyGuard` inherits).

### Policy Interface

```solidity
interface IPolicy {
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address module,
        bytes calldata context,
        AccessSelector.T access
    ) external returns (bytes4 magicValue);

    function configure(address safe, AccessSelector.T access, bytes memory data) external returns (bool success);
}
```

A policy is a stripped down version of the Safe transaction guard interface, supporting only the pre-transaction checks, as well as only the common transaction data to regular Safe transactions and Safe module transactions. This means that Safe transaction gas refund parameters cannot be checked, and to work around this, we require that `gasPrice == 0` in the Safe guard to ensure that there is no gas refund payment. With `gasPrice == 0` the Safe skips its payment step entirely, so `baseGas`, `gasToken` and `refundReceiver` cannot move value and need no policy check. A consequence of the reduced parameter set is that a policy cannot reconstruct the exact Safe transaction hash, so policies cannot bind to it.

The policy is **not** a `view` method and is allowed to make state changes, enabling stateful policies (for example, accounting or rate-limiting). Policy *checks* are **pre-execution only** — a policy is never re-invoked afterwards — so any state a policy writes during the check is committed with the transaction. Keeping that state consistent with the execution outcome therefore requires that a failed execution reverts the whole transaction, which the guard enforces on both authorization paths:

* **Transaction path:** `safeTxGas == 0` is required. A non-zero `safeTxGas` lets a Safe transaction whose inner call fails complete without reverting, which would leave a policy's staged state committed against a failed action.
* **Module path:** there is no `safeTxGas` equivalent — `execTransactionFromModule` returns `false` instead of reverting — so `checkAfterModuleExecution` reverts when execution failed. `checkAfterExecution` does the same on the transaction path. That hook still runs on a successful transaction; what it cannot observe while `safeTxGas` and `gasPrice` are zero is a *failure*, because the Safe reverts before calling it. It exists so atomicity is enforced locally rather than assumed of the Safe version in use.

Without the module-path check, an attacker able to trigger a module could exhaust a stateful policy's budget with calls engineered to fail, moving no funds.

For any transaction executed by a Safe (be it a regular transaction or a module transaction), a policy MUST be configured, and the `checkTransaction` function MUST return the 4-byte magic value (equal to `IPolicy.checkTransaction.selector`).

#### Security model for stateful checks

Because `checkTransaction` may mutate state, the guard invokes policies with a `CALL` rather than a `STATICCALL`. To preserve the system's safety, the `SafePolicyGuard` keeps a reentrancy gate around each top-level check: while a check is in progress a policy cannot start a new top-level check — and since the Safe invokes the guard on every execution, it therefore cannot re-enter the Safe to run another guarded transaction mid-check. The engine's `checkTransaction` is also reachable only during a top-level check and only for the Safe being checked. This confines any recursive check (including `MultiSendPolicy`'s per-sub-transaction recursion, which targets the same Safe) to that Safe, so a malicious or buggy policy configured on one Safe **cannot** reach, mutate, or consume another Safe's policy state — this cross-Safe guarantee is enforced by the `safe == $checkingSafe` check and is covered by an end-to-end test. (Direct calls to the configuration functions are not blocked by this gate; they stay safe because their state is keyed by `msg.sender`.)

Within a *single* Safe, however, a policy can trigger checks of that same Safe's other policies — this is exactly the mechanism `MultiSendPolicy` relies on. That surface is therefore bounded to the Safe's own configured (and, per the trust model, audited) policy set: a policy a Safe installs can drive that Safe's other policies, but nothing on any other Safe. Policies must key their state by `(msg.sender, safe)` per the `IPolicy.checkTransaction` security contract so they cannot be driven from an unexpected namespace.

#### Trusting the check inputs

Two of the arguments a policy receives have very different trust levels, and conflating them is a privilege-escalation bug:

* **`module`** is supplied by the engine from the guard entry point — `address(0)` for an owner transaction, otherwise the module that authorized it. It is held in engine state rather than passed through the recursive entry point, so a policy driving a recursive check cannot forge it. This is the *only* trustworthy indicator of the authorization path.
* **`context`** is caller-supplied and **untrusted on every path**. On the transaction path it is carried in the tail of the Safe `signatures` bytes, which the Safe transaction hash does not cover and whose trailing bytes Safe ignores — so *any* executor, including a relayer that signed nothing, chooses it freely. On the module path it is always empty.

A policy must therefore treat `context` only as self-authenticating material — a signature over a hash the policy recomputes, say — and never as an identity or authorization claim. `AllowedModulePolicy` reads `module`, not `context`, for exactly this reason.

Context is carried using the [`SignatureExtension`](./contracts/libraries/SignatureExtension.sol) envelope, `[payload][uint256 payloadLength][bytes32 typeHash]`. The type hash is the terminal word rather than a length, so unrelated trailing data — an EIP-1271 contract signature, for instance — is not mistaken for context. Signatures carrying no envelope are not an error; a blob that claims the type but is malformed is, and denies the transaction.

Policy authors MUST uphold the following to keep those guarantees:

* Prefer no external calls. If reading external state, use a `STATICCALL` (e.g. a `view` helper such as OpenZeppelin's `SignatureChecker`) so the callee cannot reenter.
* Never make a state-mutating external call to an untrusted address during a check.
* Write only to storage namespaced by `(policyGuard, safe)`.
* Authorize on `to` and `data`, not on `access`. When a policy is reached through a fallback, `access` is the fallback key — target `address(0)` and selector `0x00000000` — not the transaction's real target and selector.
* Follow checks-effects-interactions and bound gas and storage growth.

#### Accepted limitations

These are known and deliberate. All of them fail closed — they deny or revert rather than letting something through — but they shape what is expressible:

* **A transaction carrying 1–3 bytes of calldata is always rejected** with `InvalidSelector`, because no function selector can be decoded from it. Empty calldata is fine and decodes to the zero selector.
* **The fallback key is indistinguishable from a real access selector for `address(0)`.** `create(address(0), bytes4(0), operation)` and `createFallback(operation)` are the same value, so a plain value transfer to `address(0)` resolves to the catch-all policy. A fallback policy therefore also authorizes burning value to the zero address.
* **`MultiSendPolicy` pairs contexts with sub-transactions positionally** and yields an empty context once the supplied list is exhausted. A batch cannot give context to only its last sub-transaction without padding the earlier ones.

### Access Selectors

The policy to enforce is chosen based on an _access selectors_. These are similar to [external function pointers](https://docs.soliditylang.org/en/latest/types.html#function-types) with a slightly different representation, and also encoding the Safe `operation` kind (`CALL` or `DELEGATECALL`). The layout of an access selector in an EVM word is:

```
      | 00000000001111111111222222222233
 byte | 01234567890123456789012345678901
------+----------------------------------
 data | sssso       tttttttttttttttttttt
```

* `ssss`: the 4 byte function selector
* `o`: the operation flag, 0 for `CALL` and 1 for `DELEGATECALL` (just like the function parameter for Safe transactions).
* `tttttttttttttttttttt`: the address of the contract being (delegate-)called

Some examples of the access selector for various Safe operations:

* `0xa9059cbb00000000000000005afe3855358e112b5647b952709e6165e1c1eeee`: Calling `transfer` on the Safe token
* `0x8d80ff0a01000000000000009641d764fc13c8b624c04430c7356c1c7c8102e2`: Delegatecalling `multiSend` on the Safe multi-send contract
* `0x000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045`: Transferring Eth to Vitalik

The encoding was designed this way for both efficiency, and ease of parsing. Specifically, encoding just requires no shifting for either the selector or the target address, and they can just be bitwise-or-ed together. Additionally, reading the selector and address from the value just requires masking. Parsing these 32-byte values is also visually easy, with the selector being at the start, and the address being at the end.

Additionally, there are two _special_ access selectors that are used as fallback policies, in case there was no exact match:

* `0x0000000000000000000000000000000000000000000000000000000000000000`: Fallback policy for `CALL` transactions
* `0x0000000001000000000000000000000000000000000000000000000000000000`: Fallback policy for `DELEGATECALL` transactions

### Policy Engine

The core contract for access control for Safe transactions. Some opinionated design choices were made with how access control is enforced:

* Mandatory access control; all transactions are enforced by a **single** policy associated with an access selector, instead of cascading policies; this was mainly done to keep things simple (for example, what happens if the order of policies has an affect on whether or not the transaction is accepted? How do you configure this order? etc.). We believe the policy interface is general enough that it would be possible to configure cascading policies if needed
* All transactions are enforced equally regardless of authorization mechanism; this means that a module does not have special permissions compared to a regular transaction signed by users. This ensures that, regardless of the Safe setup, policies will always be respected, thus reducing the attack surface that can be leveraged by sophisticated threat actors (for example social engineering of allowance module signers instead of the Safe signers themselves)
* Transactions are denied by default; this requires that policies be created for allowed transactions instead of selectively disallowing transactions. While this adds UX friction at setup time, it makes the system as a whole more secure and easy to reason about
* Fallback policy; this allows use-cases of the kind "allow these transactions, and defer to an off-chain co-signer for all other transactions"

### Safe Policy Guard

A Safe transaction and module guard implementation that checks Safe transactions with the policy engine.

## Prior Art

In principle, this provides similar features to what a Zodiac `Roles` modifier as a guard would. The main difference is that instead of having the roles modifier allow customisation with a DSL, `IPolicy` contracts implement the customization. The rationale here is that:

1. It makes the core contracts much simpler and easier to formally verify
2. Individual policies can be complicated, and as a general rule `Roles` configurations aren't audited which is a potential security risk
3. Policy implementations can be independently audited and formally verified

## Setup with Safe

> [!IMPORTANT]
> The `SafePolicyGuard` must be installed as **both** the transaction guard and the module guard. Installing only one leaves a complete bypass of the policy system, and the guard cannot detect or prevent this itself.

Safe keeps the two guards in separate storage slots, set by two separate calls:

- `setGuard(policyGuard)` — checks owner transactions (`execTransaction`).
- `setModuleGuard(policyGuard)` — checks module transactions (`execTransactionFromModule` and `execTransactionFromModuleReturnData`).

With only the transaction guard installed, **any enabled module executes with no policy enforcement at all** — including calling `setGuard(address(0))` to remove the guard outright, with none of the configuration delay. The reverse holds too: with only the module guard installed, owner transactions are unchecked.

So the hardening sequence is:

1. Configure the intended policies with `configureImmediately(...)`, while no guard is installed.
2. Install **both** guards, ideally atomically via MultiSend so there is no window with only one active.

Two things to check when hardening an existing Safe:

- **Modules enabled before hardening are unconstrained until the module guard is set.** Enumerate them first; `enableModule` afterwards requires a configured policy, but existing modules do not.
- `configureImmediately` is rejected once either guard points at the policy guard, so all configuration after this point goes through the delay. Bootstrap fully before installing the guards.

## Guard Removal

To remove a guard, instead of baking in the delay mechanism within the guard contract, we use the delay mechanism which is already present for any policy to get activated. To remove a guard:
- We `requestConfiguration(...)` with the `configureRoot` as the data with [AllowPolicy](./contracts/policies/AllowPolicy.sol) and selector as `setGuard(...)`, target as Safe itself, and operation as `CALL`
- Once the delay is over, we can apply the policy using `applyConfiguration(...)` and also remove the Guard (we can use MultiSend for the same to do in a single transaction).

Removing the module guard works the same way, with `setModuleGuard(...)` as the selector. Remove **both** if the intent is to uninstall the policy engine; removing only one leaves the Safe partly guarded rather than unguarded.

Note: If the Safe reactivates the guard, this policy should be removed. This needs `configureImmediately(...)` while no guard is installed — once either guard is set, `configureImmediately` reverts `GuardAlreadyEnabled` and the delay applies.

## Deployment note

Contracts compile for the **Cancun** EVM, which the vendored Safenet libraries require (they use `mcopy`). Chains that have not activated the Cancun upgrade are not deployment targets.

Every change to the guard changes its bytecode and therefore its CREATE2 address. Existing deployments must be redeployed and Safes re-pointed at the new address; a Safe keeps referencing whichever address it was given.

## Testing

Run the test suite:
```bash
npm test
```

Run gas benchmarks:
```bash
npm run test:bench
```

## Deployment

Deploy contracts:
```bash
npm run deploy -- <network>
```

Note: Ensure proper configuration of delay parameters based on your security requirements. 

### `AppSafePolicyGuard` is for the demo only

`SafePolicyGuard` is the guard intended for use. Setting the `DEMO` flag deploys `AppSafePolicyGuard`
in its place — a subclass that exists so the Safe App demo can read configurations from the contract
instead of running an indexer. To do that it widens `_allowedCalls` and overrides the configuration
entry points.

It is recorded in `networks.json` on mainnets as well as testnets, but **those deployments are
demonstrations and must not be used in production.** It lives under `contracts/test/`, carries no
tests, and is outside the audited surface.
