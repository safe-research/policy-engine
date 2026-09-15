# Formal verification: Policy Engine

Certora/CVL suite for `contracts/SafePolicyGuard.sol`, `contracts/core/PolicyEngine.sol` and the libraries and policies the report's section 1 lists; every harness mirrors the deployed code, so `git diff main -- contracts/` is empty in this tree.

## Results

11 of 11 property rows are green. The table with every row's rule, conf, status and job is in `certora/VERIFICATION_REPORT.md`.

## Install and run

From the repository root:

```sh
pip install -r certora/requirements.txt      # certora-cli==8.19.1
```

Also required: a `solc` 0.8.30 binary named `solc-0.8.30` on `PATH`, which every conf pins together with `solc_via_ir: true`, `solc_evm_version: cancun` and `solc_optimize: 10000000`, and `CERTORAKEY` in the environment.

```sh
certoraRun certora/conf/Lib.conf --wait_for_results all      # one conf, waiting for the cloud verdict
certoraRun certora/conf/Lib.conf --compilation_steps_only    # local compile and CVL type-check, no key
```

Grade a run in the Certora web UI: the Rules tab is the authority for a verdict, listing every rule's verdict, and the conf is green only when every leaf there is SUCCESS; the Job Info tab is the authority for the flags the run actually used, which a conf only requests. `Results.txt` is neither: for `satisfy` rules its `FAIL:`/`Violated:` wording is inverted and healthy sanity sub-rules print `Violated`. Submit one conf at a time: a conf can hold the prover for its whole `smt_timeout`, which 3 of the 6 raise to 1800 or 3600 seconds.

## Layout

| Path | Holds |
|---|---|
| `certora/specs/` | 5 CVL specs. `Vocabulary.spec` holds scene-free definitions, which a spec imports whatever its scene. `Common.spec` imports it and carries the shared `methods` block and the shared definitions of the guard's scene. |
| `certora/conf/` | 6 run configurations, one or more per spec. A spec is split across confs where one run does not converge or needs a different flag. |
| `certora/harnesses/` | 5 files, 6 contracts: `LibHarness`, `MockPolicyHarness`, `SafeSlotMock`, `GuardProbeResponderMock`, `SafeMockHarness`, `SafePolicyGuardHarness`. |
| `certora/requirements.txt` | The pinned prover client, `certora-cli==8.19.1`. |
| `certora/README.md` | This file: install, layout, conventions, the unit tables and the evidence rules. |
| `certora/VERIFICATION_REPORT.md` | Results, property table, assumption table, findings, not-proven list. |

## Conventions

| Convention | Rule |
|---|---|
| Path shorthands | In the assumption and waiver tables `P/<Name>` is `contracts/policies/<Name>.sol`, `E:` is `contracts/core/PolicyEngine.sol`, `G:` is `contracts/SafePolicyGuard.sol` and `SAFE/` is Safe v1.5.0; every other path is repository-relative. |
| Rule ids | `R_<UNIT>_<n>` for safety rules, `INV_<UNIT>_<n>` for invariants, `W_<UNIT>_<n>` for `satisfy` witnesses and `*_PIN_*` for a row restated against a concrete callee; the report's rows use the same unit token with a hyphen, so `R-LIB-6` is carried by the `R_LIB_6*` rules. A row's rule cell names every rule that carries it, a rule named for what it proves rather than for a row id included. |
| Id namespaces | `L-<UNIT>-<n>` and named forms such as `L-W0-HASH` for an assumption, `WAIVED-<UNIT>-<n>` for a waived claim, `B-<n>` for a documentation finding and `D-0<nn>` for a modelling decision; a `require`, summary, ghost or flag resting on one carries a trailing comment naming the id. |
| Evidence | The job id in the report's property table is the authority for a row, and a conf's `rule` filter defines the rule set that job graded, so a rule outside the filter was not run by it. Where half a spec needs a different flag or budget, that spec is split across a conf pair and the unit table below names both confs; every other filter is a budget split within one unit. |
| Harness naming | `<Subject>Harness.sol` subclasses or mirrors a deployed contract and adds only view accessors, a mock stands in for code outside the verified set, and the two shared mocks live together in `Mocks.sol`, which a conf picks from with the `Mocks.sol:<Contract>` form and never as a bare path; a single-use mock sits beside the harness that needs it. Neither is compiled into the production build. |
| Safe in scene | The Safe a rule talks about is `SafeMockHarness` in the 3 `EngineCheck*`/`EngineConfig*` confs of `certora/conf/` (`L-W0-1`). The guard scenes keep the mock because their subject is the guard slot, which on a real Safe has no state variable to `require`, `getGuard` being `internal` and `setGuard` `authorized`; the mock answers `getStorageAt` over havoced storage, so a rule fixes the slot word with `require`. |
| Compiler | Every conf pins `solc-0.8.30`, `solc_via_ir: true`, `solc_evm_version: cancun` and `solc_optimize: 10000000`, matching `hardhat.config.ts`, and any divergence proves something about different bytecode. |
| Budget | 3 of the 6 confs raise `smt_timeout` to 1800 or 3600 seconds and the rest run at the certora-cli default of 300 seconds per SMT query, a rule over budget reporting TIMEOUT and never green. `rule_sanity: basic` is set in every conf, and a `SANITY_FAIL` leaf is advisory: the rule's own assert still reports its verdict and the report dispositions each one. |

## Units

### Infrastructure

| conf | spec | rules | status |
|---|---|---|---|
| `Lib.conf` | `Lib.spec` | 2 | `R-LIB-6`, `R-LIB-7` green |
| `LibBitwise.conf` | `Lib.spec` | 8 | `R-LIB-1` to `R-LIB-5`, `R-LIB-8`, `W-LIB-1` green |

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `D-007` | `$policies` is read by direct storage access `currentContract.$policies[s][a]`, not by a hook-ghost mirror; any ghost that must survive an unresolved CALL is `persistent` | modelling decision |
| `L-EC-8` | `tryCheck` is an external self-call (`msg.sender == guard`), used only to classify the engine-level revert as `AccessDenied`, `PolicyReverted` or raw |  |
| `L-LIB-1` | Executions hashing a `bytes` longer than 3200 bytes are dropped, an instance of L-W0-HASH. It is inert: no rule run under it hashes a symbolic `bytes`, and `conf/Lib.conf`, which runs the two length rules, sets neither key, so their claims hold at every length | argument: inert, so nothing rests on it here |
| `L-LIB-2` | Bitwise ops modelled exactly with bitvector theory for the AccessSelector packing rules, the Lib adoption of L-W0-BITWISE | job [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054) |
| `L-LIB-3` | Arithmetic and reader vocabulary are pure total functions of their inputs, ABI casts and zero-padded calldata reads, not mirrors of contract logic | job [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054) |
| `L-LIB-4` | A rule pinning selector content ties `selectorOf(d)` to `wordAt(d,0)` (an aligned `calldataload` plus a tail mask) and `byteAt(d,0)`, but not to `byteAt(d,1..3)`, so the selector's trailing three bytes are tied to the word reader, not the byte reader | job [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054) |
| `L-W0-BITWISE` | Bitwise operations are modelled exactly with bitvector theory instead of the default over-approximation | job [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054) |
| `L-W0-HASH` | Executions hashing a `bytes` value longer than the conf's own bound are dropped, an assumed bound | argument: the flag drops executions that hash past the bound, so a violation beyond it is missed, and no rule of the suite hashes an unbounded bytes |
| `L-W0-LOOP` | `loop_iter` is 3 in the shared scene: a configuration array is bounded to 3 entries where a rule carries one, and the calldata-to-memory copies of the library readers are unrolled 3 times where it does not | argument: optimistic_loop is false, so a bound too low fails an unwinding assertion rather than assuming the rest away |
| `W-LIB-1` | Witnesses for the library readers | witness row |
| `WAIVED-EC-2` | Selector content: `selectorOf(data)` equals the first four bytes of `data`, waived on the premise that CVL cannot index `bytes` | waived: the premise is false: `LibHarness.byteAt(bytes,uint256)` indexes `bytes` and is already used by R-LIB-6 and R-LIB-7. The claim is R-LIB-8 above, green in `LibBitwise.conf` |

### EngineConfig

| conf | spec | rules | status |
|---|---|---|---|
| `EngineConfig.conf` | `EngineConfig.spec` | 7 | green: `requestConfiguration` and `invalidateRoot` fully characterised (`R_CFG_4`, `R_CFG_5`); an expired root requestable again with no `invalidateRoot` in between (`R_CFG_12_reRequest`); witnesses of request then apply after the delay, of a re-request, of `DELAY == 0` and of the empty array (`W_CFG_1_W1`, `W_CFG_1_W2`, `W_CFG_1_W3`, `W_CFG_1_W6`) |
| `EngineConfigRoot.conf` | `EngineConfig.spec` | 1 | green: two configuration arrays with the same root have the same length (`R_CFG_8_length`) |
| `EngineConfigRootPin.conf` | `EngineConfig.spec` | 1 | green at one entry: an unrequested, immature, expired or paid `applyConfiguration` always reverts (`R_CFG_6a_one`) |
| `SafeMock.conf` | `SafeMock.spec` | 2 | green: the mock Safe of the guard scenes is well-formed, `1 <= threshold <= ownerCount` holding inductively (`mockSafeWellFormed`), and its `getOwners()` returns exactly `ownerCount()` entries at up to three owners (`ownersLengthIsOwnerCount`) |

Tests: `test/policyEngine.spec.ts`, 5 cases under `Policies with no usable return`.

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `D-008` | An unresolved policy CALL defaults to `HAVOC_ECF` with nondeterministic return data, so "policy revert implies PolicyReverted" could be proven only against a really-reverting scene policy, and no rule of this tree proves it (section 7) | modelling decision |
| `D-009` | Policy recursion is summarized per signature: `function _.checkTransaction(<8 args>) external => DISPATCH [...]` does inline the policy scene, and no second engine scene is built for a nested MultiSend batch, whose expansion this tree does not prove (section 7) | modelling decision |
| `L-CFG-FRAME` | The opcode-hook observer ghosts start at zero | argument |
| `L-CFG-GATE` | The `GuardAlreadyEnabled` iff is stated with an empty configuration array | argument |
| `L-CFG-HASH` | Executions hashing a `bytes` value longer than the conf's own bound are dropped (assumed bound) | argument |
| `L-CFG-LOOP` | Configuration arrays are bounded to 3 entries, a scope under-approximation at `G:344`, `G:397` and the `abi.encode` walk feeding `G:390` | argument |
| `L-CFG-LOOP-N1` | These rules bound the configuration array to at most one entry instead of the unit's usual three: `W_CFG_1_W2`, `W_CFG_1_W3` and `R_CFG_6a_one` | argument |
| `L-CFG-PROBE` | Senders of the `GuardAlreadyEnabled` family are restricted to the two mocks, and the responder's answer length is bounded at 160 bytes | test/safePolicyGuardConfiguration.spec.ts |
| `L-CFG-RECUR` | Re-entrant `configure`, the `MockPolicyHarness` `ConfigureMode.CALL_CONFIG` mode that calls one of the four configuration entry points on `msg.sender`, chosen by `configCall`, is modelled to one nested level with an asserted bound | argument |
| `L-CFG-SCENE` | The iff halves are stated only where the scene fixes the `configure` verdict, `policy in {0, Allow, Deny, OneTimeAllow, MockPolicyHarness}`, and those rules pin the mock away from its re-entrant `CALL_CONFIG` mode | test/policyEngine.spec.ts: "Should reject configuring an account with no code as a policy" |
| `L-CFG-SLOTMOCK` | The Safe answering the guard's slot probe in the `GuardAlreadyEnabled` family is `SafeSlotMock`, a Safe's observable answer with slot words in a mapping, and `SafeMockHarness` is out of that DISPATCH list | test/safePolicyGuardConfiguration.spec.ts |
| `L-EC-6` | Re-entry through `MockPolicyHarness` is modelled to one nested dispatched frame, with an asserted bound |  |
| `L-ENV-TIME` | Block timestamps are non-decreasing across transactions | argument |
| `L-IT-1` | The Safe's `checkNSignatures` verdict is a free function of `(dataHash, signatures, required)`, a wildcard over every callee, with `executor` captured and asserted `== 0` (`P/IncreasedThresholdPolicy:82-87`) |  |
| `L-IT-2` | The Safe in scene is set up: `1 <= threshold <= ownerCount`, an invariant against the mock, whose only writer `SafeMockHarness.setOwnersAndThreshold` requires it, and a precondition of the rules that put Safe v1.5.0 in scene, whose own writers are `authorized` and therefore unreachable from a policy rule | job [335e2ef1](https://prover.certora.com/output/950385/335e2ef18dc6432faed47cebc7fcb542?anonymousKey=c2e1256ff0e44b4ecc333201615dc59d02e4e8c4) |
| `L-IT-4` | The owner list is bounded to 4 entries and hashing to `hashing_length_bound 3200`, the L-W0-HASH instance, because `_requiredSignatures` reads `ISafe(safe).getOwners().length` (`P/IncreasedThresholdPolicy:147`) |  |
| `L-IT-9` | An unknown Safe's owner list is a free array of at most four entries, in the three rules over an arbitrary `safe`; the rules over the Safe in scene assume nothing here, `getOwners()` there being Safe v1.5.0's own walk of its owner list. `SafeMock.conf`'s `ownersLengthIsOwnerCount` proves the same length fact against `SafeMockHarness`'s own body at up to three owners: a sanity check on the shape of the summary, not its discharge, since no IncreasedThreshold conf links the mock and the rules that read the summary run at four owners |  |
| `L-POL-CTX-M` | An audit of the exposure class: each rule the prover's empty-`bytes` pair defect leaves unmeasured is probed in three emptiness cases (`context` empty, `data` empty, both), 75 probes verdicting 69 SUCCESS, 6 vacuous and 0 FAIL, the vacuous ones being empty-`data` probes of rules whose antecedents need `batchLength(data)` to decode; the `configureImmediately` effects rule is covered instead by four pinned cases with the flag off, all SUCCESS. An exposed rule that carries a companion pinning `context1.length == 0` is answered by that companion rather than by a probe, so the `data1`/`data2` pair of such an independence rule is unmeasured | job [a1318175](https://prover.certora.com/output/950385/a1318175b20042e88501662982d419fd?anonymousKey=153d0f62ccc55542b1c2b75aa3b53ef0b5365c45), whose conf is not part of this tree, so the job cannot be re-run from it |
| `L-W0-1` | `SafeMockHarness` stands in for the Safe in the guard scenes, whose subject is the guard slot: `getStorageAt` (`StorageAccessible.sol:16-29`) and `getTransactionHash`/`domainSeparator` (`Safe.sol:389-399,404-473`) verbatim, guard values at the real keccak slots (`G:49,55-56`), `nonce`/`getOwners`/`getThreshold` as storage | argument: getStorageAt, getTransactionHash and domainSeparator are Safe v1.5.0's code copied verbatim |
| `L-W0-2` | The closed scene {Allow, Deny, OneTimeAllow, MockPolicyHarness} stands in for arbitrary policy code on the check (`E:200`) and configure (`E:292`) paths, dispatched by the per-signature `DISPATCH [...]` summaries. Each spec sets its own `default` for a policy outside that list, and the two settings are not the same adversary: under `HAVOC_ECF` an out-of-scene policy may write storage and re-enter the guard's configuration entry points, under `NONDET` it is a side-effect-free function returning a free value, which can neither revert nor re-enter. The configuration specs set `HAVOC_ECF`; a check spec sets what its own header states | job [f2ef38dc](https://prover.certora.com/output/950385/f2ef38dc32074acca3ec5c6d381fd363?anonymousKey=ad922e5d6e6893f7d73eabdd601d93f7cf2cdc44) |
| `L-W0-3` | The responder mock's per-slot modes cover every observable of `_readGuardSlot` (`G:311-320`): revert, short return and symbolic return words, with the rules over the answer's decode bounding `retLen <= 160` | test/safePolicyGuardConfiguration.spec.ts |
| `L-W0-RECUR` | A method of the guard may appear at most twice on the call stack (guard, mock, guard, policy), and deeper cycles are cut by asserted pessimistic bounds rather than assumed away | job [f2ef38dc](https://prover.certora.com/output/950385/f2ef38dc32074acca3ec5c6d381fd363?anonymousKey=ad922e5d6e6893f7d73eabdd601d93f7cf2cdc44) |
| `L-W0-SENDER` | `msg.sender` is never `address(0)` on chain: no key has that address and a contract cannot be deployed there | argument |
| `WAIVED-ENV-3` | Timelock semantics for `DELAY == 0` deployments; validator timestamp skew | waived: environment; the `W_CFG_1_W3` witness covers `DELAY == 0` |
| `WAIVED-H-5` | Equality of the mock `getTransactionHash` with a real Safe's | waived: environment code copied verbatim |

## Evidence rules

- Job ids live in the report's property table, one per row, as links under `https://prover.certora.com/output/950385/` that carry a share key (`anonymousKey`) and open without a Certora account; the conf, with its `rule` filter where it has one, is the reproducible evidence.
- The `discharge` column of a unit table shows a job id as its first eight hex characters, each a link to the job with its share key, like the links of the report's property and assumption tables.
- Regrade any job in the web UI: open its URL and check the Rules tab, where every rule must show SUCCESS.
- Re-run a claim with `certoraRun certora/conf/<X>.conf --wait_for_results all`, then grade it the same way.
- Waivers name their test or their reason in the report's section 3.2; run the repo tests with `npm test`.

## Not in this tree

- A conf for the properties the report's section 7 lists as having no rule run, and the spec of the nested-batch rule. The other rules stay in their specs as comments.
