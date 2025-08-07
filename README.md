> [!WARNING]
> Code in this repository is not audited and may contain serious security holes. Use at your own risk.

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
        bytes calldata context
    ) external returns (bytes4 magicValue);
}
```

A policy is a stripped down version of the Safe transaction guard interface, supporting only the pre-transaction checks, as well as only the common transaction data to regular Safe transactions and Safe module transactions. This means that Safe transaction gas refund parameters cannot be checked, and to work around this, we require that `gasPrice == 0` in the Safe guard to ensure that there is no gas refund payment. Also worth noting, is that the policy is **not** a `view` method, and is allowed to make state changes. This allows use cases for policies that do some accounting (for example, a ERC-20 transfer policy with daily limits).

For any transaction executed by a Safe (be it a regular transaction or a module transaction), a policy MUST be configured, and the `checkTransaction` function MUST return the 4-byte magic value (equal to `IPolicy.checkTransaction.selector`).

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
* `ffffffffffffffffffff`: the address of the contract being (delegate-)called

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

## Guard Removal

To remove a guard, instead of baking in the delay mechanism within the guard contract, we use the delay mechanism which is already present for any policy to get activated. To remove a guard:
- We `requestConfiguration(...)` with the `configureRoot` as the data with [AllowPolicy](./contracts/policies/AllowPolicy.sol) and selector as `setGuard(...)`, target as Safe itself, and operation as `CALL`
- Once the delay is over, we can apply the policy using `applyConfiguration(...)` and also remove the Guard (we can use MultiSend for the same to do in a single transaction).

Note: If the Safe reactivates the guard, this policy should be removed (can be done without any delay with `configureImmediately(...)` before the guard is enabled) 

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
