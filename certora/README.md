# Formal verification: Policy Engine

Certora/CVL suite for `contracts/SafePolicyGuard.sol`, `contracts/core/PolicyEngine.sol` and the libraries and policies the report's section 1 lists; every harness mirrors the deployed code, so `git diff main -- contracts/` is empty in this tree.

## Results

112 of 112 property rows are green. The table with every row's rule, conf, status and job is in `certora/VERIFICATION_REPORT.md`.

## Install and run

From the repository root:

```sh
pip install -r certora/requirements.txt      # certora-cli==8.19.1
```

Also required: a `solc` 0.8.30 binary named `solc-0.8.30` on `PATH`, which every conf pins together with `solc_via_ir: true`, `solc_evm_version: cancun` and `solc_optimize: 10000000` (the eight real-Safe confs map three of the four per file and keep one `solc` for the whole conf, see "Real Safe in scene" below), and `CERTORAKEY` in the environment.

```sh
certoraRun certora/conf/Lib.conf --wait_for_results all      # one conf, waiting for the cloud verdict
certoraRun certora/conf/Lib.conf --compilation_steps_only    # local compile and CVL type-check, no key
```

Grade a run in the Certora web UI: the Rules tab is the authority for a verdict, listing every rule's verdict, and the conf is green only when every leaf there is SUCCESS; the Job Info tab is the authority for the flags the run actually used, which a conf only requests. `Results.txt` is neither: for `satisfy` rules its `FAIL:`/`Violated:` wording is inverted and healthy sanity sub-rules print `Violated`. Submit one conf at a time: a conf can hold the prover for its whole `smt_timeout`, which 21 of the 49 raise to 1800 or 3600 seconds.

## Layout

| Path | Holds |
|---|---|
| `certora/specs/` | 30 CVL specs. `Vocabulary.spec` holds scene-free definitions, which a spec imports whatever its scene. `Common.spec` imports it and carries the shared `methods` block and the shared definitions of the guard's scene. `Common.spec` also carries the invariant `sentinelsClear`. |
| `certora/conf/` | 49 run configurations, one or more per spec. A spec is split across confs where one run does not converge or needs a different flag. |
| `certora/harnesses/` | 11 files, 14 contracts: `SafePolicyGuardHarness`, `SafeMockHarness`, `RealSafeHarness`, `MockPolicyHarness`, `LibHarness`, `MultiSendPolicyHarness` and `EngineRecorderHarness` (both in `MultiSendHarness.sol`), `ERC20TransferPolicyHarness` and `ERC20ApprovePolicyHarness` (both in `PolERC20Harness.sol`), `SafenetHarness`, `BindingHarness`, and `GuardProbeResponderMock`, `SafeSlotMock` together in `Mocks.sol`, and `GuardSlotDecodePin`. |
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
| Safe in scene | The Safe a rule talks about is `SafeMockHarness` in the 24 `EngineCheck*`/`EngineConfig*` confs of `certora/conf/` (`L-W0-1`). The guard scenes keep the mock because their subject is the guard slot, which on a real Safe has no state variable to `require`, `getGuard` being `internal` and `setGuard` `authorized`; the mock answers `getStorageAt` over havoced storage, so a rule fixes the slot word with `require`. |
| Real Safe in scene | The Safe a rule talks about is Safe v1.5.0 itself, inherited unchanged by `RealSafeHarness` (`L-SAFE-1`), in the eight policy confs (`IncreasedThreshold.conf`, `IncreasedThresholdArgs.conf`, `IncreasedThresholdOpenSafe.conf`, `CoSigner.conf`, `CoSignerArgs.conf`, `CoSignerModulePath.conf`, `Safenet.conf`, `SafenetArgs.conf`), whose rows bind the verdict to Safe's own nonce, transaction hash, owner list and threshold. Safe's own source does not compile via IR, so those confs carry `solc_via_ir_map`, `solc_evm_version_map` and `solc_optimize_map` in place of the three scalar flags: the verified policy keeps the suite's settings and `RealSafeHarness` compiles for `paris` with the optimizer off, the settings `hardhat.config.ts:68-77` builds Safe's own source with. The fourth setting, the compiler binary, is one scalar per conf, so that code is verified under `solc-0.8.30` rather than the 0.8.28 the repo pins for it (`L-SAFE-1`). |
| Compiler | Every conf pins `solc-0.8.30`, `solc_via_ir: true`, `solc_evm_version: cancun` and `solc_optimize: 10000000`, matching `hardhat.config.ts`, and any divergence proves something about different bytecode. |
| Budget | 21 of the 49 confs raise `smt_timeout` to 1800 or 3600 seconds and the rest run at the certora-cli default of 300 seconds per SMT query, a rule over budget reporting TIMEOUT and never green. `rule_sanity: basic` is set in every conf, and a `SANITY_FAIL` leaf is advisory: the rule's own assert still reports its verdict and the report dispositions each one. |

Every rule of the suite is named in the rule cell of some row.

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
| `L-EC-8` | `tryCheck` is an external self-call (`msg.sender == guard`), used only to classify the engine-level revert as `AccessDenied`, `PolicyReverted` or raw | job [f040044a](https://prover.certora.com/output/950385/f040044ae724499c9d4512aa3c6c393e?anonymousKey=b09a1d54d7ebdd50761556e21c20e0ffc939c165) |
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
| `EngineConfigApply.conf` | `EngineConfig.spec` | 5 | green at one entry: `applyConfiguration` reverts iff the root is missing, immature, expired or paid or an entry's configure verdict is not OK (`R_CFG_6b_one`); on success the root is consumed, each named key holds the last entry's policy and the guard's own arguments reach configure (`R_CFG_6c_one`); equal roots agree entry by entry (`R_CFG_8_fields_one`); a configuration applies only in `[T + DELAY, T + DELAY + EXPIRY)` after its request (`R_CFG_11_one`); a matured sound root reverts iff `block.timestamp >= validFrom + EXPIRY` (`R_CFG_12`) |
| `EngineConfigEffects.conf` | `EngineConfig.spec` | 1 | green: `configureImmediately` has the per-entry policy effects and call frame of an application, at up to three entries, and leaves `rootConfigured` untouched (`R_CFG_9_effects`) |
| `EngineConfigFrame.conf` | `EngineConfig.spec` | 2 | green on `configureImmediately`, `requestConfiguration` and `invalidateRoot`: the written-namespace frame and `$policies` writer set, sound under re-entrant `configure` (`R_CFG_2`), and the root transition rule, value direction and state machine (`R_CFG_3`); both rules filter out `applyConfiguration` |
| `EngineConfigFrameApply.conf` | `EngineConfig.spec` | 2 | green: the same frame (`R_CFG_2_apply1`) and root transition rule (`R_CFG_3_apply1`) on `applyConfiguration` at one entry |
| `EngineConfigFrameCheck.conf` | `EngineConfig.spec` | 2 | `R-CFG-2`, `R-CFG-3` green on the check path |
| `EngineConfigGate.conf` | `EngineConfigGate.spec` | 5 | `R-CFG-9` (gate pair) and `R-CFG-10` with `_readGuardSlot` summarized (`L-CFG-DECODE`), plus the summary's audit trail `R_CFG_9_probeArgs`; green at this tree's job |
| `EngineConfigLight.conf` | `EngineConfig.spec` | 7 | green: the root is already deleted when each `configure` runs (`R_CFG_7`); every guard-slot probe targets the caller, at most two are made and none after a configure CALL, stated at the opcode level (`R_CFG_9_probe`); witnesses of a clearing entry (`W_CFG_1_W5`) and of the four guard-slot states (`W_CFG_1_W4a` to `W_CFG_1_W4d`) |
| `EngineConfigRoot.conf` | `EngineConfig.spec` | 1 | green: two configuration arrays with the same root have the same length (`R_CFG_8_length`) |
| `EngineConfigRootPin.conf` | `EngineConfig.spec` | 1 | green at one entry: an unrequested, immature, expired or paid `applyConfiguration` always reverts (`R_CFG_6a_one`) |
| `GuardSlotDecode.conf` | `GuardSlotDecode.spec` | 3 | green at a return buffer of at most 160 bytes: the decode pin that discharges the decode half of `L-CFG-DECODE` against a copy of the guard's assembly (`R_CFG_DECODE_pin`, `R_CFG_DECODE_pin_len`), the mask witnessed by `W_CFG_DECODE_dirty` |
| `SafeMock.conf` | `SafeMock.spec` | 2 | green: the mock Safe of the guard scenes is well-formed, `1 <= threshold <= ownerCount` holding inductively (`mockSafeWellFormed`), and its `getOwners()` returns exactly `ownerCount()` entries at up to three owners (`ownersLengthIsOwnerCount`) |

Tests: `test/policyEngine.spec.ts`, 5 cases under `Policies with no usable return`.

The same cases stand behind the no-code scene of `R-CFG-6`.

The same cases stand behind `WAIVED-EC-1`.

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `D-008` | An unresolved policy CALL defaults to `HAVOC_ECF` with nondeterministic return data, so "policy revert implies PolicyReverted" could be proven only against a really-reverting scene policy, and no rule of this tree proves it (section 7) | modelling decision |
| `D-009` | Policy recursion is summarized per signature: `function _.checkTransaction(<8 args>) external => DISPATCH [...]` does inline the policy scene, and no second engine scene is built for a nested MultiSend batch, whose expansion this tree does not prove (section 7) | modelling decision |
| `L-CFG-BITWISE` | Bitwise operations are modelled exactly with a bitvector encoding instead of the default over-approximation, for the one conf whose claims depend on 160-bit masks | argument |
| `L-CFG-DECODE` | One guard-slot probe of slot `s` at target `t` returns exactly `(success && returndata.length >= 96) ? word3(returndata) & 0xff..ff : address(0)`, summarizing `_readGuardSlot` so that the four gate leaves rest on that function rather than on the prover's pointer analysis, which on that function's raw `mload` of the `staticcall` return buffer falls back to an unconstrained byte load and reports the four gate leaves FAIL on probe answers no Safe can give; the pin that discharges it holds a copy of the guard's decode assembly rather than the private function itself, with an ABI-decoded `bytes memory` parameter standing in for the `staticcall` return buffer. The decode is proved for a return buffer of at most 160 bytes, the bound each of the pin's three rules requires and the bound the gate rules require of the responder (L-W0-3, L-CFG-PROBE); a longer answer is out of model, and the guard reads word 3 whatever the total length. Keeping the copy in step with `G:309-320` is a review obligation and not a proved one | decode half proved by the decode pin against the copy of the guard's assembly, the mask witnessed there; staticcall half by the opcode-level probe-discipline rule and L-W0-3, with a rule re-proving the target and the two slots through the summary |
| `L-CFG-FRAME` | The opcode-hook observer ghosts start at zero | argument |
| `L-CFG-GATE` | The `GuardAlreadyEnabled` iff is stated with an empty configuration array | argument |
| `L-CFG-HASH` | Executions hashing a `bytes` value longer than the conf's own bound are dropped (assumed bound) | argument |
| `L-CFG-LOOP` | Configuration arrays are bounded to 3 entries, a scope under-approximation at `G:344`, `G:397` and the `abi.encode` walk feeding `G:390` | argument |
| `L-CFG-LOOP-N1` | These rules bound the configuration array to at most one entry instead of the unit's usual three: `W_CFG_1_W2`, `W_CFG_1_W3`, `R_CFG_6a_one`, `R_CFG_11_one`, `R_CFG_6b_one`, `R_CFG_6c_one`, `R_CFG_8_fields_one`, `R_CFG_12`, `R_CFG_2_apply1` and `R_CFG_3_apply1` | argument |
| `L-CFG-PROBE` | Senders of the `GuardAlreadyEnabled` family are restricted to the two mocks, and the responder's answer length is bounded at 160 bytes | test/safePolicyGuardConfiguration.spec.ts |
| `L-CFG-RECUR` | Re-entrant `configure`, the `MockPolicyHarness` `ConfigureMode.CALL_CONFIG` mode that calls one of the four configuration entry points on `msg.sender`, chosen by `configCall`, is modelled to one nested level with an asserted bound | argument |
| `L-CFG-SCENE` | The iff halves are stated only where the scene fixes the `configure` verdict, `policy in {0, Allow, Deny, OneTimeAllow, MockPolicyHarness}`, and those rules pin the mock away from its re-entrant `CALL_CONFIG` mode | test/policyEngine.spec.ts: "Should reject configuring an account with no code as a policy" |
| `L-CFG-SLOTMOCK` | The Safe answering the guard's slot probe in the `GuardAlreadyEnabled` family is `SafeSlotMock`, a Safe's observable answer with slot words in a mapping, and `SafeMockHarness` is out of that DISPATCH list | test/safePolicyGuardConfiguration.spec.ts |
| `L-EC-6` | Re-entry through `MockPolicyHarness` is modelled to one nested dispatched frame, with an asserted bound | job [f040044a](https://prover.certora.com/output/950385/f040044ae724499c9d4512aa3c6c393e?anonymousKey=b09a1d54d7ebdd50761556e21c20e0ffc939c165) |
| `L-ENV-TIME` | Block timestamps are non-decreasing across transactions | argument |
| `L-IT-1` | The Safe's `checkNSignatures` verdict is a free function of `(dataHash, signatures, required)`, a wildcard over every callee, with `executor` captured and asserted `== 0` (`P/IncreasedThresholdPolicy:82-87`) | job [64532b9f](https://prover.certora.com/output/950385/64532b9f1a8d4e0abc16d6b546144fc1?anonymousKey=5197c493131284b9d0ec73a613a81a2604920475) |
| `L-IT-2` | The Safe in scene is set up: `1 <= threshold <= ownerCount`, an invariant against the mock, whose only writer `SafeMockHarness.setOwnersAndThreshold` requires it, and a precondition of the rules that put Safe v1.5.0 in scene, whose own writers are `authorized` and therefore unreachable from a policy rule | job [335e2ef1](https://prover.certora.com/output/950385/335e2ef18dc6432faed47cebc7fcb542?anonymousKey=c2e1256ff0e44b4ecc333201615dc59d02e4e8c4) |
| `L-IT-4` | The owner list is bounded to 4 entries and hashing to `hashing_length_bound 3200`, the L-W0-HASH instance, because `_requiredSignatures` reads `ISafe(safe).getOwners().length` (`P/IncreasedThresholdPolicy:147`) | job [64532b9f](https://prover.certora.com/output/950385/64532b9f1a8d4e0abc16d6b546144fc1?anonymousKey=5197c493131284b9d0ec73a613a81a2604920475) |
| `L-IT-9` | An unknown Safe's owner list is a free array of at most four entries, in the three rules over an arbitrary `safe`; the rules over the Safe in scene assume nothing here, `getOwners()` there being Safe v1.5.0's own walk of its owner list. `SafeMock.conf`'s `ownersLengthIsOwnerCount` proves the same length fact against `SafeMockHarness`'s own body at up to three owners: a sanity check on the shape of the summary, not its discharge, since no IncreasedThreshold conf links the mock and the rules that read the summary run at four owners | job [ac415a6d](https://prover.certora.com/output/950385/ac415a6d6211436292c82080b05094a1?anonymousKey=5693299df613ee4bd3860d879845e89d13f6c3eb) |
| `L-POL-CTX-M` | An audit of the exposure class: each rule the prover's empty-`bytes` pair defect leaves unmeasured is probed in three emptiness cases (`context` empty, `data` empty, both), 75 probes verdicting 69 SUCCESS, 6 vacuous and 0 FAIL, the vacuous ones being empty-`data` probes of rules whose antecedents need `batchLength(data)` to decode; the `configureImmediately` effects rule is covered instead by four pinned cases with the flag off, all SUCCESS. An exposed rule that carries a companion pinning `context1.length == 0` is answered by that companion rather than by a probe, so the `data1`/`data2` pair of such an independence rule is unmeasured | job [a1318175](https://prover.certora.com/output/950385/a1318175b20042e88501662982d419fd?anonymousKey=153d0f62ccc55542b1c2b75aa3b53ef0b5365c45), whose conf is not part of this tree, so the job cannot be re-run from it |
| `L-W0-1` | `SafeMockHarness` stands in for the Safe in the guard scenes, whose subject is the guard slot: `getStorageAt` (`StorageAccessible.sol:16-29`) and `getTransactionHash`/`domainSeparator` (`Safe.sol:389-399,404-473`) verbatim, guard values at the real keccak slots (`G:49,55-56`), `nonce`/`getOwners`/`getThreshold` as storage | argument: getStorageAt, getTransactionHash and domainSeparator are Safe v1.5.0's code copied verbatim |
| `L-W0-2` | The closed scene {Allow, Deny, OneTimeAllow, MockPolicyHarness} stands in for arbitrary policy code on the check (`E:200`) and configure (`E:292`) paths, dispatched by the per-signature `DISPATCH [...]` summaries. Each spec sets its own `default` for a policy outside that list, and the two settings are not the same adversary: under `HAVOC_ECF` an out-of-scene policy may write storage and re-enter the guard's configuration entry points, under `NONDET` it is a side-effect-free function returning a free value, which can neither revert nor re-enter. The configuration specs set `HAVOC_ECF`; a check spec sets what its own header states | jobs [f2ef38dc](https://prover.certora.com/output/950385/f2ef38dc32074acca3ec5c6d381fd363?anonymousKey=ad922e5d6e6893f7d73eabdd601d93f7cf2cdc44), [93dcfd18](https://prover.certora.com/output/950385/93dcfd187d8049fdb1129e1b7ecf659f?anonymousKey=2112208b566bc2e5c8b5470ad84902420b84e0e2) |
| `L-W0-3` | The responder mock's per-slot modes cover every observable of `_readGuardSlot` (`G:311-320`): revert, short return and symbolic return words, with the rules over the answer's decode bounding `retLen <= 160` | test/safePolicyGuardConfiguration.spec.ts |
| `L-W0-RECUR` | A method of the guard may appear at most twice on the call stack (guard, mock, guard, policy), and deeper cycles are cut by asserted pessimistic bounds rather than assumed away | job [f2ef38dc](https://prover.certora.com/output/950385/f2ef38dc32074acca3ec5c6d381fd363?anonymousKey=ad922e5d6e6893f7d73eabdd601d93f7cf2cdc44) |
| `L-W0-SENDER` | `msg.sender` is never `address(0)` on chain: no key has that address and a contract cannot be deployed there | argument |
| `W-CFG-1` | Witnesses for the configuration lifecycle, `satisfy`: one per lifecycle step, and one per guard-slot state | witness row |
| `WAIVED-EC-3` | Revert *names* and their precedence at the hooks (`NonZeroGasPrice`, `NonZeroSafeTxGas`, `Reentrancy`) | waived: the EngineCheck hook rows prove the revert set as an iff, not the order of names |
| `WAIVED-ENV-3` | Timelock semantics for `DELAY == 0` deployments; validator timestamp skew | waived: environment; the `W_CFG_1_W3` witness covers `DELAY == 0` |
| `WAIVED-H-5` | Equality of the mock `getTransactionHash` with a real Safe's | waived: environment code copied verbatim |

### EngineCheck

| conf | spec | rules | status |
|---|---|---|---|
| `EngineCheck.conf` | `EngineCheck.spec` | 8 | green: with a check in progress, `checkTransaction` reverts iff it is paid, the safe differs, `badLen(data)`, the hatch is taken with a non-zero module, the target off the hatch is the guard, or the resolved policy is absent or does not accept (`R_EC_4a`), and on success returns `address(0)` on the hatch and the policy otherwise, calling it exactly once iff the hatch was missed (`R_EC_4b`); the owner-path hook's revert-iff over value, gas fields, sentinel state, well-formedness and the verdict, with one policy CALL iff the hatch was missed (`R_EC_5`, `R_EC_5_callCount`); the module-path hook's revert-iff over value, sentinel state, length, hatch and verdict, its one policy CALL carrying the hook's own module and an empty context (`R_EC_6`, `R_EC_6_invocation`); a checked transaction whose `to` is the guard is denied at both hooks and no policy runs (`R_EC_17_owner`, `R_EC_17_module`) |
| `EngineCheckCall.conf` | `EngineCheck.spec` | 2 | green: during a check every outgoing CALL the guard makes is `IPolicy.checkTransaction` with no value to the resolved policy (`R_EC_14`); owner-path hook calls differing only in `baseGas`, `gasToken`, `refundReceiver` and `msgSender` have the same outcome and storage, the fifth class, the pre-envelope signature bytes, un-attempted (`R_EC_15`) |
| `EngineCheckClass.conf` | `EngineCheck.spec` | 4 | `R-EC-4` green for (a), (b) and two of the three (c) classes, the `PolicyReverted` class having no rule run (report section 7); `R-EC-17` green at `R_EC_17_engine` |
| `EngineCheckDelegate.conf` | `EngineCheck.spec` | 1 | green: the guard never delegatecalls, every parametric node of `R_EC_14_noDelegateCall` included |
| `EngineCheckDelegateApply.conf` | `EngineCheck.spec` | 1 | `R-EC-14` green, stating the `applyConfiguration` node of `R_EC_14_noDelegateCall` again at `n <= 1` (`R_EC_14_noDelegateCall_apply1`) |
| `EngineCheckFrame.conf` | `EngineCheckFrame.spec` | 2 | green, the `n <= 3` half of the spec: from a state with a check in progress every non-reverting guard method but the two Safe hooks leaves the sentinels unchanged (`R_EC_1`), and the written-namespace frame and `$policies` writer set hold in this scene too (`EC_ConfigFrame`) |
| `EngineCheckFrameApply.conf` | `EngineCheckFrame.spec` | 2 | `R-EC-1` green; also `EC_ConfigFrame_apply1`, which re-instantiates `R-CFG-2` in the EngineCheck scene and is carried by that row |
| `EngineCheckHavoc.conf` | `EngineCheckHavoc.spec` | 2 | `R-EC-3`, `R-EC-12` green |
| `EngineCheckInv.conf` | `EngineCheckFrame.spec` | 1 | `INV-EC-1` green, the induction base and all seven induction nodes |
| `EngineCheckLaw.conf` | `EngineCheck.spec` | 10 | `R-EC-2`, `R-EC-4`, `R-EC-9` to `R-EC-11`, `R-EC-13`, `R-EC-16` green |
| `EngineCheckNative.conf` | `EngineCheckNative.spec` | 1 | `W-EC-1` green |
| `EngineCheckNested.conf` | `EngineCheck.spec` | 5 | green: every top-level policy invocation carries the caller's own arguments on the owner path (`R_EC_7`) and on the module path, the module coming from state (`R_EC_7_module`); the owner-path context is the envelope payload when present and empty otherwise (`R_EC_8_owner`); witnesses that the mid-check state is reached through the hook (`W_EC_1_g`) and that a nested engine call targeting the hatch is refused when the top-level check is module-authorised (`W_EC_1_j`) |
| `EngineCheckNestedRecur.conf` | `EngineCheck.spec` | 6 | `R-EC-5` to `R-EC-8` green, at `contract_recursion_limit 1` with an asserted summary bound, which the `limit 2` confs do not converge under |
| `EngineCheckWitness.conf` | `EngineCheck.spec` | 9 | green: non-vacuity witnesses of the engine's success and denial classes (`W_EC_1_a` to `W_EC_1_e`, `W_EC_1_i`), of the `AccessDenied(0)` and `AccessDenied(p)` denials (`W_EC_1_f_accessDeniedZero`, `W_EC_1_f_accessDeniedPolicy`) and of the guard-target denial (`W_EC_1_l_guardTargetDenied`); no witness rule runs for the `PolicyReverted` denial |

Tests: `test/safePolicyGuardExecution.spec.ts`, 4 cases under `Spend lifetime`, the concrete `afterExecution` behaviour.

The same cases stand behind `WAIVED-S-4`.

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `B-2` | NativeTransferPolicy shared access key: any value-bearing CALL whose calldata starts with `0x00000000` shares the access key of empty calldata. #104 documents the neighbouring case, a target's fallback function serving calls its selector never named, and `README.md:74` the collision at `address(0)`; neither states this one, which is about the calldata rather than the target | documentation finding, open |
| `B-4` | IncreasedThresholdPolicy source comment: the comment claims fail-closed behaviour on non-zero refund fields; the code is not fail-closed there. `contracts/policies/` is byte-identical between 177de07 and 405ba1d, so the comment still stands | documentation finding, open |
| `L-EC-2` | Module path: `module == msg.sender` of `execTransactionFromModule`, an enabled non-zero module (`ModuleManager.sol:104-107`) | test/moduleConfigurationBlocked.spec.ts |
| `L-EC-3` | Both guard slots hold the same `SafePolicyGuard` (the root `README.md` both-guards warning) | job [2ba73a89](https://prover.certora.com/output/950385/2ba73a89cfee41ca996ea316c7e1b629?anonymousKey=334be8203f48951c877040d7bf9fb59a862a35ff) |
| `L-EC-4` | Hashing on the check path enters only through the recorder mock's `keccak(data)` and `keccak(context)`, the Lib reader set's `payloadHash` and `keccak(abi.encode(Configuration[]))` (`G:390`), all bounded at 3200, except in the EngineCheck variants unit, where the conf whose rules run the configuration array at one entry bounds at 448 | test/safePolicyGuardContext.spec.ts |
| `L-EC-5` | Per-row `default` for the engine call to the policy (`PolicyEngine.sol:200`): `NONDET` for the closed-scene check rows: the engine-outcome, hook, invocation, call-discipline and witness rows; `HAVOC_ECF` for the sentinel frame row and its invariant and `HAVOC_ALL` for the deny-by-default and liveness rows, both in the EngineCheck variants unit | job [93dcfd18](https://prover.certora.com/output/950385/93dcfd187d8049fdb1129e1b7ecf659f?anonymousKey=2112208b566bc2e5c8b5470ad84902420b84e0e2) |
| `L-EC-7` | Every non-zero configured policy had code at configuration time returning at least 32 bytes or reverting, the raw-revert class being fail-closed and out of model | test/policyEngine.spec.ts: "Should revert without a reason when a configured policy returns fewer than 32 bytes" |
| `L-EC-9` | The mid-check rules start from `S != 0` | job [4f00ea39](https://prover.certora.com/output/950385/4f00ea3924fa48588f78b9b44fea248d?anonymousKey=48b56a581eaf0b75f8b9af05c23a9f7f9aad52ae) |
| `L-EC-11` | The iff rows run with `MockPolicyHarness.checkMode()` pinned to {ACCEPT, WRONG_MAGIC, REVERTS}, so its four re-entrant modes (CALL_CONFIG, REENTER_GUARD_TX, REENTER_GUARD_MODULE, REENTER_ENGINE) are out of the iff run | job [2ba73a89](https://prover.certora.com/output/950385/2ba73a89cfee41ca996ea316c7e1b629?anonymousKey=334be8203f48951c877040d7bf9fb59a862a35ff) |
| `L-EC-12` | The nested engine call's `data` is the outer call's `data` at skip 0, so CVL can name it when computing the nested `getPolicy` expectation | argument |
| `L-EC-13` | The iff rows range over a typed `operation in {CALL, DELEGATECALL}` domain; the hook-closure rule and the not-checking engine rule cover the raw `calldataarg` domain instead | argument |
| `L-EC-FRAME` | Opcode-hook counters, zeroed by `resetFrame()`; no `Sstore`/`Sload` hook anywhere in the unit | job [2ba73a89](https://prover.certora.com/output/950385/2ba73a89cfee41ca996ea316c7e1b629?anonymousKey=334be8203f48951c877040d7bf9fb59a862a35ff) |
| `L-EC-INVFILTER` | The parametric quantification of `R_EC_1` omits the two pre-execution hooks, which `R_EC_2` proves revert from `S != 0` | job [2dd4b861](https://prover.certora.com/output/950385/2dd4b861a0a54b1983c0ec332ad54922?anonymousKey=8d5176b22e20ef13070fd1b9093091702cb68190) |
| `L-EC-LOOP` | The two `Configuration[]` entry points are exercised at `n <= 3` under a pessimistic unwinding assertion | job [f040044a](https://prover.certora.com/output/950385/f040044ae724499c9d4512aa3c6c393e?anonymousKey=b09a1d54d7ebdd50761556e21c20e0ffc939c165) |
| `L-EC-LOOP-N1` | The `applyConfiguration` node of three parametric rules is proven at `n <= 1` instead of the unit's `n <= 3` | job [bb0c7c8d](https://prover.certora.com/output/950385/bb0c7c8dade241bb944ba92f66179293?anonymousKey=7eaa9adb5293202d3b94a64ae7ba8a69c00c7919) |
| `L-W0-INVFILTER` | The engine entry `checkTransaction(address,address,uint256,bytes,Operation,bytes)`, at six arguments, is excluded from the invariant's induction step | job [f040044a](https://prover.certora.com/output/950385/f040044ae724499c9d4512aa3c6c393e?anonymousKey=b09a1d54d7ebdd50761556e21c20e0ffc939c165) |
| `L-W0-SENTINEL` | No rule of this tree assumes `$checkingSafe == 0 && $checkingModule == 0` in the pre-state of a hook call through `requireInvariant`; that state is the sentinel invariant's own claim | job [f040044a](https://prover.certora.com/output/950385/f040044ae724499c9d4512aa3c6c393e?anonymousKey=b09a1d54d7ebdd50761556e21c20e0ffc939c165) |
| `W-EC-1` | Witnesses for non-vacuity of every success and denial class, twelve classes (a) to (l) | witness row |
| `WAIVED-S-4` | Spend rollback when execution fails (a spent ONCE/OTA grant is restored because the Safe transaction reverts), needed by the OneTimeAllow and the two ERC20 spend rows | waived: only the Safe-atomicity limb is environment. The guard half is in-scope production code and unproven: `SafePolicyGuard.sol:239-241` and `:268-270` are the only thing stopping a policy's spend from committing against an action that never took effect |

### Simple policies

| conf | spec | rules | status |
|---|---|---|---|
| `Allow.conf` | `Allow.spec` | 2 | `R-ALLOW-1` green |
| `AllowWitness.conf` | `Allow.spec` | 1 | `W-ALLOW-1` green |
| `Deny.conf` | `Deny.spec` | 2 | `R-DENY-1` green |
| `DenyWitness.conf` | `Deny.spec` | 1 | `W-DENY-1` green |
| `NativeTransfer.conf` | `NativeTransfer.spec` | 7 | `R-NATIVE-1`, `R-NATIVE-2`, `W-NATIVE-1` green |
| `OneTimeAllow.conf` | `OneTimeAllow.spec` | 12 | `R-OTA-1` to `R-OTA-5`, `W-OTA-1` green; `R-OTA-3`'s independence from `data` rests on L-POL-CTX, whose measurement did not cover the data buffers |
| `AllowedModule.conf` | `AllowedModule.spec` | 11 | `R-AMOD-1` to `R-AMOD-3`, `INV-AMOD-1`, `W-AMOD-1` green; `R-AMOD-1`'s independence from `data` rests on L-POL-CTX, whose measurement did not cover the data buffers |

Tests: `test/nativeTransferPolicy.spec.ts`, the op-mask case behind `R-NATIVE-2`.

Tests: `test/oneTimeAllowPolicy.spec.ts`, one decoder case, for the boundary behind `R-OTA-4`.

Tests: `test/allowedModulePolicy.spec.ts`, one decoder case, for the boundary behind `R-AMOD-2`.

The grant rollback behind `R-OTA-2` is tested in `test/safePolicyGuardExecution.spec.ts`, among the EngineCheck unit's cases.

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `B-6` | AllowedModulePolicy ignores `access`: the allowlist is keyed per `(guard, safe, module)`; `configure` ignores `access`. Unchanged on `main` | documentation finding, open |
| `L-POL-2` | The companion rule's four access words are pinned to concrete non-canonical instances: 2^217, 2^200, 2^216 and 2^224 | job [7a510af2](https://prover.certora.com/output/950385/7a510af231a74154bc9259278e5e32b7?anonymousKey=875075a643c737e76b16e6f1ba72aab875c66182) |
| `L-POL-3` | Exact bitvector modelling for the NativeTransfer scene | job [7a510af2](https://prover.certora.com/output/950385/7a510af231a74154bc9259278e5e32b7?anonymousKey=875075a643c737e76b16e6f1ba72aab875c66182) |
| `L-POL-4` | The loop and hashing template keys carried into the OneTimeAllow and AllowedModule confs | job [772d811a](https://prover.certora.com/output/950385/772d811a12c2438fb997f1bab37458bd?anonymousKey=63f6e9088b09a47ce78b016f567b982e4d2431af) |
| `L-POL-5` | The decode characterisations of `R_OTA_4` and `R_AMOD_2` are stated in the raw-reader vocabulary rather than in a re-implementation of `abi.decode` | job [772d811a](https://prover.certora.com/output/950385/772d811a12c2438fb997f1bab37458bd?anonymousKey=63f6e9088b09a47ce78b016f567b982e4d2431af) |
| `L-POL-6` | The typed revert-iff rules `R_ALLOW_1`, `R_DENY_1`, `R_NATIVE_1` and `R_NATIVE_2` range over canonical ABI encodings of the parameter tuple, not raw calldata, which `calldataarg` widens to encodings solc's decoder rejects; their `_anyCalldata` twins take the raw domain | argument |
| `L-POL-7` | Exact bitvector modelling for every `satisfy` rule in the unit, with the `assert` rules left on the default encoding in `Allow.conf` and `Deny.conf` | job [1dad762d](https://prover.certora.com/output/950385/1dad762d6a0d410b963792b88e971a5b?anonymousKey=005f8d141665d81eeabd2cc51d814e80d9d1e997) |
| `L-POL-8` | Per-unit instance of L-W0-HASH and the loop template keys: executions hashing a `bytes` longer than 3200 bytes are dropped. The bound is inert in this unit, no policy it verifies and no rule of its specs hashing a variable-length value, so the revert-iff rows hold at every calldata length | job [982fe202](https://prover.certora.com/output/950385/982fe20275cc42a594f7bcf1c4edc770?anonymousKey=a4a2e30026bd3e8512daeb011d79ad84ff36578a) |
| `L-POL-9` | The typed-argument rules of `OneTimeAllow.spec` and `AllowedModule.spec` take CVL arguments instead of `calldataarg`, so they quantify over canonically decodable tuples, the OneTimeAllow and AllowedModule instance of L-POL-6 | job [772d811a](https://prover.certora.com/output/950385/772d811a12c2438fb997f1bab37458bd?anonymousKey=63f6e9088b09a47ce78b016f567b982e4d2431af) |
| `L-POL-10` | Exact bitvector modelling for both grant-policy scenes, the OneTimeAllow and AllowedModule instance of L-W0-BITWISE and of the stateless-policy entries L-POL-3 and L-POL-7 | job [772d811a](https://prover.certora.com/output/950385/772d811a12c2438fb997f1bab37458bd?anonymousKey=63f6e9088b09a47ce78b016f567b982e4d2431af) |
| `L-POL-CTX` | A prover unsoundness, a property of the prover rather than of the files that cite it: under `precise_bitwise_ops: true` on 8.19.1 the `assert` model reaches no empty free CVL `bytes`, so an `assert` rule with two or more free `bytes` and any external call drops every input pair in which exactly one buffer is empty. Every rule of that shape under the flag is exposed, whether or not its own file cites this id. With the flag off that model is sound for an `assert` and unsound for a `satisfy` instead. L-POL-CTX-M measures every rule of this tree this row left unmeasured | jobs [3d8e8b7d](https://prover.certora.com/output/950385/3d8e8b7d8e6b41fda867803650d85612?anonymousKey=43ce95db540589b67809b8e12a7317721f9d0f7e), [df18bce5](https://prover.certora.com/output/950385/df18bce53b94438bae9eee4e6c683397?anonymousKey=892b22949ff9972fff04b6d5f24e394705d7732f), whose confs are not part of this tree, so the jobs cannot be re-run from it |
| `W-ALLOW-1` | a `checkTransaction` returning `MAGIC` with `value > 0`, `data.length >= 4`, `module != 0` | witness row |
| `W-AMOD-1` | a check returning `MAGIC`, and configure-then-check under the same sender and a different access selector | witness row |
| `W-DENY-1` | a non-reverting `checkTransaction` returning zero on the shape W-ALLOW-1 pins | witness row |
| `W-NATIVE-1` | a check returning `MAGIC` with `value > 0`, and one on DELEGATECALL | witness row |
| `W-OTA-1` | a check returning `MAGIC`, and two-step configure-then-check liveness | witness row |

### ERC20 policies

| conf | spec | rules | status |
|---|---|---|---|
| `ERC20Transfer.conf` | `ERC20Transfer.spec` | 17 | `R-ERC20T-1` to `R-ERC20T-6`, `W-ERC20T-1` green |
| `ERC20Approve.conf` | `ERC20Approve.spec` | 17 | `R-ERC20A-1` to `R-ERC20A-6`, `W-ERC20A-1` green |

Tests: `test/erc20ApprovePolicy.spec.ts`, two cases: the decoder boundary behind `R-ERC20A-2` and the spender-list walk.

Tests: `test/erc20TransferPolicy.spec.ts`, two cases: the decoder boundary behind `R-ERC20T-2` and the recipient-list walk.

The two list walks stand behind `WAIVED-S-3`.

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `L-POL-1` | `configure`'s allowlist array is bounded to `loop_iter` (3) entries, and the frame rows do not run `configure` or the entry readers on unbounded calldata at all | job [40612834](https://prover.certora.com/output/950385/406128341b9a485094aec874f73e9ef6?anonymousKey=350a7a4cf11fff9aa0f877b930873948c7f7cc35) |
| `L-POL-11` | Each policy's decoder characterisation (`R_ERC20A_2` and `R_ERC20T_2`) and its `configure` key-shape iff are stated in the raw-reader vocabulary rather than in a CVL re-implementation of `abi.decode` or of the `AccessSelector` bit layout | argument |
| `L-POL-12` | Those rules take typed CVL arguments instead of `calldataarg`, so they quantify over canonically decodable tuples, the PolERC20 instance of L-POL-6 and L-POL-9 | job [40612834](https://prover.certora.com/output/950385/406128341b9a485094aec874f73e9ef6?anonymousKey=350a7a4cf11fff9aa0f877b930873948c7f7cc35) |
| `L-POL-13` | The unit's instance of L-W0-HASH and of the loop template keys: executions hashing a `bytes` longer than 3200 bytes are dropped, and the decoded array is unrolled to 3 entries. The hashing bound is inert here, neither policy nor either spec hashing a variable-length value; the unrolling is not, and L-POL-1 states it | job [40612834](https://prover.certora.com/output/950385/406128341b9a485094aec874f73e9ef6?anonymousKey=350a7a4cf11fff9aa0f877b930873948c7f7cc35) |
| `L-POL-14` | Exact bitvector modelling for both PolERC20 scenes, the PolERC20 instance of L-W0-BITWISE, L-POL-3, L-POL-7 and L-POL-10 | job [40612834](https://prover.certora.com/output/950385/406128341b9a485094aec874f73e9ef6?anonymousKey=350a7a4cf11fff9aa0f877b930873948c7f7cc35) |
| `W-ERC20A-1` | success with a non-zero amount, success with a zero amount, a storage-changing success, configure-then-approve, and last-entry-wins | witness row |
| `W-ERC20T-1` | success via `transfer` and via `transferFrom`, a storage-changing success, configure-then-check, and last-entry-wins | witness row |
| `WAIVED-S-6` | Detaching a policy (`policy = 0`, no `configure` call, `E:291`) does not clear policy-side state; re-attaching resurrects old ERC20 entries, AMOD entries and unspent OTA grants | waived: cross-contract history; frames on both sides hold, neither states the composition; section 7 |

### MultiSend

| conf | spec | rules | status |
|---|---|---|---|
| `MultiSend.conf` | `MultiSend.spec` | 19 | `R-MS-1` to `R-MS-3` and `R-MS-8` green; against the recording engine summary, every decoded sub-transaction is checked exactly once in batch order (`R_MS_4`) with its decoded target, value, calldata and operation (`R_MS_5`, `R_MS_5_itemDecoder`) and its positional context (`R_MS_6`, `R_MS_6_ctxDecoder`), and a reverting sub-check reverts the batch while magic is returned only if every sub-check returned (`R_MS_7_denial`, `R_MS_7_magic`); witnesses `W_MS_1a`, `W_MS_1b` and `W_MS_1c` |
| `MultiSendPin.conf` | `MultiSendPin.spec` | 5 | `R-MS-4` to `R-MS-7`, `W-MS-1` green |

Tests: `test/multiSendPolicy.spec.ts`, 7 cases under `Nested Batches` and `Long Batches`.

The same cases are the evidence for `WAIVED-H-7`.

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `L-MS-1` | The engine callback at `P/MultiSendPolicy:39` is summarized by a reverting recording CVL function, over persistent indexed ghosts, so the unit treats the engine as an arbitrary verdict oracle | job [4aa94063](https://prover.certora.com/output/950385/4aa940637688463292e6f5fbea2b6afa?anonymousKey=3b67cf96d9c2b63c72edd763b4bbc9f4c4734284) |
| `L-MS-2` | Assumed `data.length <= 375`, with at most three sub-transactions and four loop entries derived from that bound and asserted | job [4aa94063](https://prover.certora.com/output/950385/4aa940637688463292e6f5fbea2b6afa?anonymousKey=3b67cf96d9c2b63c72edd763b4bbc9f4c4734284) |
| `L-MS-4` | The recording summary hashes `data_i` and `ctx_i` on every sub-call, so executions hashing more than 416 bytes are dropped and the context envelope is bounded to 416 bytes | job [4aa94063](https://prover.certora.com/output/950385/4aa940637688463292e6f5fbea2b6afa?anonymousKey=3b67cf96d9c2b63c72edd763b4bbc9f4c4734284) |
| `L-MS-5` | The walkers mirror one line, the iteration, and decode with the real inherited `internal pure` decoders, so no offset arithmetic is re-derived in the harness | job [4aa94063](https://prover.certora.com/output/950385/4aa940637688463292e6f5fbea2b6afa?anonymousKey=3b67cf96d9c2b63c72edd763b4bbc9f4c4734284) |
| `L-MS-6` | Every rule of the pin spec fixes the callee, and therefore `msg.sender`, to `EngineRecorderHarness`, and starts its cursor at zero | job [fc8e42b3](https://prover.certora.com/output/950385/fc8e42b349bf47d1a3beb6629d80a3e2?anonymousKey=5d24d2f3b08504e640e53f520cd531d047e830f2) |
| `L-MS-7` | Those rules take typed CVL arguments rather than `calldataarg`, so they quantify over canonically decodable tuples, the MultiSend instance of L-POL-6, L-POL-9 and L-POL-12 | job [4aa94063](https://prover.certora.com/output/950385/4aa940637688463292e6f5fbea2b6afa?anonymousKey=3b67cf96d9c2b63c72edd763b4bbc9f4c4734284) |
| `L-MS-8` | Exact bit-vector modelling for the two MultiSendPolicy scenes, the MultiSend instance of L-W0-BITWISE, L-POL-3 and L-POL-14 | job [4aa94063](https://prover.certora.com/output/950385/4aa940637688463292e6f5fbea2b6afa?anonymousKey=3b67cf96d9c2b63c72edd763b4bbc9f4c4734284) |
| `L-MS-9` | The three decoders of `P/MultiSendPolicy:45-89` are characterised in raw-byte-reader vocabulary, meaning offsets, length words and byte content, rather than in the vocabulary of the harness walkers that call those same decoders | job [4aa94063](https://prover.certora.com/output/950385/4aa940637688463292e6f5fbea2b6afa?anonymousKey=3b67cf96d9c2b63c72edd763b4bbc9f4c4734284) |
| `W-MS-1` | a two-item batch clearing with both contexts, a one-item batch, an empty batch, and the two-item batch against the real recording callee | witness row |
| `WAIVED-H-7` | Nested MultiSend batches, at any depth; batches beyond 3 items | waived: bounds asserted pessimistically: the 3-item bound is asserted (L-MS-2), never assumed. No rule of this tree expands a nested batch (section 7) |

### CoSigner and IncreasedThreshold

| conf | spec | rules | status |
|---|---|---|---|
| `CoSigner.conf` | `CoSigner.spec` | 16 | `R-COS-1`, `R-COS-3` to `R-COS-5` and `W-COS-1` green; the cosigner, signature and verdict asserts of `R_COS_2` green, its hash assert and the whole of `R_COS_2_hashBinding` blind under `L-BIND-9` |
| `CoSignerArgs.conf` | `CoSignerArgs.spec` | 3 | `R-COS-2` and the hash dimension of `R-COS-3` green |
| `CoSignerModulePath.conf` | `CoSignerModulePath.spec` | 3 | `R-COS-6` green |
| `IncreasedThreshold.conf` | `IncreasedThreshold.spec` | 13 | green against Safe v1.5.0 in scene: a non-zero module reverts before the Safe is touched and before any storage change (`R_IT_1`); the revert characterisation over value, module, nonce, the `checkNSignatures` verdict and the unspent hash (`R_IT_2`, `R_IT_2_zeroNonce`); the Safe is asked to validate the transaction hash at `nonce - 1` with the context and the required count, the hash assert blind under `L-BIND-9` (`R_IT_3`); the required-count formula (`R_IT_4`, `R_IT_4_saturates`); a non-reverting call marks the hash spent and an immediate repeat reverts (`R_IT_5`); the only `$spent` slot `checkTransaction` may change and the only `$maxAbsent` slot `configure` may change (`R_IT_6_checkKeys`, `R_IT_6_configureKeys`); `configure` reverts iff `msg.value != 0` or `data.length < 32` (`R_IT_7`, `R_IT_7_anyCalldata`); witnesses `W_IT_1` and `W_IT_1b` |
| `IncreasedThresholdArgs.conf` | `IncreasedThresholdArgs.spec` | 3 | green: the ten `getTransactionHash` arguments the verdict's hash (`R_IT_3_args`) and the spend key (`R_IT_5_argsSpendKey`) are built from, with the witness `W_IT_args` |
| `IncreasedThresholdOpenSafe.conf` | `IncreasedThresholdOpenSafe.spec` | 3 | `R-IT-3` and `R-IT-6` green over an unknown Safe. Its `R_IT_1_anyCalldata` rule is the raw-calldata half of both `R-IT-1` and `R-IT-2`: it adds non-payability and the returned selector only, and proves no revert cause. |

Tests: `test/coSignerPolicy.spec.ts`, 8 cases, none of them on the module path (D-006).

Tests: `test/increasedThresholdPolicy.spec.ts`, 13 cases.

The 5 cases of `test/increasedThresholdPolicy.spec.ts` under `Signature modes` run against a real 2-of-4 Safe and are the `WAIVED-H-4` evidence.

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `B-1` | IncreasedThresholdPolicy required-count claim: the root `README.md:99` says "Requires more owner signatures than the Safe's threshold, spent on use"; the code clamps for N-of-N Safes. The line moved from `:91` when #100 added a section above it; its wording is unchanged | documentation finding, open |
| `D-006` | On CoSigner's module path the guard passes an empty context (`SafePolicyGuard.sol:256`), so no cosignature can be supplied there | modelling decision |
| `L-BIND-9` | On 8.19.1 an `assert` over two values that each passed through Safe's offset-30 keccak is a false green, proved even when false (`Safe.sol:461-470`) | job [504a62a6](https://prover.certora.com/output/950385/504a62a65afc43c8abca0819de2a872f?anonymousKey=e9471d19fd6efdca4765976a62efcda9d10fa20b), whose conf is not part of this tree, so the job cannot be re-run from it |
| `L-COS-1` | The co-signature verdict (`P/CoSignerPolicy:72`) is a free non-reverting function of `(signer, hash, signature)`: the persistent ghost `V[signer][hash][signature]`, with the six `cap*` capture ghosts, `capCalled` to `capVerdict` | job [362bf78d](https://prover.certora.com/output/950385/362bf78da23e419e9a01b72810e78dae?anonymousKey=69563cdef5b5d42556b3725f473cf73bdd9a3583) |
| `L-COS-2` | No cosigner accepts the empty signature: `V(s, h, "") == false` for every signer and hash, used by one assert only, the denial half of R-COS-6 | argument: an axiom, assumed and not proven, whose residual is WAIVED-H-3 |
| `L-COS-3` | The two `ISafe` calls this policy makes resolve to Safe v1.5.0's own body when `safe` is the Safe in scene, and to a havoc'd return with no state effect otherwise | job [362bf78d](https://prover.certora.com/output/950385/362bf78da23e419e9a01b72810e78dae?anonymousKey=69563cdef5b5d42556b3725f473cf73bdd9a3583) |
| `L-COS-4` | The revert-iff, binding and effect rules quantify over canonically decodable argument tuples, not raw calldata, an instance of L-POL-6 and L-POL-9 | job [362bf78d](https://prover.certora.com/output/950385/362bf78da23e419e9a01b72810e78dae?anonymousKey=69563cdef5b5d42556b3725f473cf73bdd9a3583) |
| `L-COS-5` | Two classes, neither about reachable contract state: initialisation of the observation ghosts, spec-local instrumentation rather than contract storage; and the antecedent of a conditional property, its own hypothesis | job [362bf78d](https://prover.certora.com/output/950385/362bf78da23e419e9a01b72810e78dae?anonymousKey=69563cdef5b5d42556b3725f473cf73bdd9a3583) |
| `L-COS-6` | The reconstructed hash pins `ISafe(safe).nonce() - 1` (`P/CoSignerPolicy:65`), checked arithmetic that panics 0x11 at nonce 0, so these rows need the subtraction in range | job [362bf78d](https://prover.certora.com/output/950385/362bf78da23e419e9a01b72810e78dae?anonymousKey=69563cdef5b5d42556b3725f473cf73bdd9a3583) |
| `L-COS-7` | Executions hashing a `bytes` value longer than 3200 bytes are dropped, an instance of the class entry L-W0-HASH | job [362bf78d](https://prover.certora.com/output/950385/362bf78da23e419e9a01b72810e78dae?anonymousKey=69563cdef5b5d42556b3725f473cf73bdd9a3583) |
| `L-COS-8` | R-COS-6 is a claim about a composition, so the engine call to the policy at `contracts/core/PolicyEngine.sol:200` is resolved over a one-element closed scene rather than havoc'd | job [f1b6ad55](https://prover.certora.com/output/950385/f1b6ad556ff048a899734ed3ee309e45?anonymousKey=cbace38d70608acf8af05a760e5a7df52b8ccf9d) |
| `L-COS-9` | The engine's sentinels are clear when the module hook is entered | argument |
| `L-COS-10` | The module hook reaches a policy only on the path where the selector decodes, the configuration escape hatch is not taken, and the engine resolves `CoSignerPolicy` | job [f1b6ad55](https://prover.certora.com/output/950385/f1b6ad556ff048a899734ed3ee309e45?anonymousKey=cbace38d70608acf8af05a760e5a7df52b8ccf9d) |
| `L-COS-11` | In this scene the `assert` model does reach the pair with exactly one empty free CVL `bytes`, measured rather than argued, so `R_COS_1_emptyContext` adds no coverage over `R_COS_1` and is kept as a regression marker | job [362bf78d](https://prover.certora.com/output/950385/362bf78da23e419e9a01b72810e78dae?anonymousKey=69563cdef5b5d42556b3725f473cf73bdd9a3583) |
| `L-COS-12` | The write-provenance quantifier ranges over the subject's non-`view` methods only | argument |
| `L-COS-13` | `ISafe.getTransactionHash` is summarized capture-only: it records the ten arguments and returns a fresh unconstrained `bytes32` per call (`gthRetOf[gthCount]`), so the rules that read its result assert its arguments, not two hashes | job [04470d6e](https://prover.certora.com/output/950385/04470d6eb7284145b03fee9c74fcd44e?anonymousKey=a910e978a55e78554ee6dc7ed338e36a1dfc4a34) |
| `L-HASHBLIND` | No rule may rest on comparing two Safe-style offset-30 hash outputs (`keccak256(add(ptr, 30), 66)`, `Safe.sol:461-470`), and such a value used as a ghost key does not prove the value keys this transaction | job [504a62a6](https://prover.certora.com/output/950385/504a62a65afc43c8abca0819de2a872f?anonymousKey=e9471d19fd6efdca4765976a62efcda9d10fa20b), whose conf is not part of this tree, so the job cannot be re-run from it |
| `L-IT-3` | The Safe those rows talk about is the Safe in scene, Safe v1.5.0 itself through `RealSafeHarness`, so `nonce`, `getOwners`, `getThreshold` and the derived hash are that package's own code rather than a havoc'd return | job [64532b9f](https://prover.certora.com/output/950385/64532b9f1a8d4e0abc16d6b546144fc1?anonymousKey=5197c493131284b9d0ec73a613a81a2604920475) |
| `L-IT-5` | The four non-verdict `ISafe` calls resolve to Safe v1.5.0's own code when `safe` is the Safe in scene, and to a havoc'd return value with no state effect for any other `safe` | job [64532b9f](https://prover.certora.com/output/950385/64532b9f1a8d4e0abc16d6b546144fc1?anonymousKey=5197c493131284b9d0ec73a613a81a2604920475) |
| `L-IT-6` | The revert-iff, binding and effect rules quantify over canonically decodable argument tuples, not raw calldata, an instance of L-POL-6 and L-POL-9 | job [64532b9f](https://prover.certora.com/output/950385/64532b9f1a8d4e0abc16d6b546144fc1?anonymousKey=5197c493131284b9d0ec73a613a81a2604920475) |
| `L-IT-7` | Two classes, neither about reachable contract state: initialisation of the observation ghost `capCalled`, which a `persistent` ghost havocs at rule start; and the antecedent of a conditional property, its own hypothesis | job [64532b9f](https://prover.certora.com/output/950385/64532b9f1a8d4e0abc16d6b546144fc1?anonymousKey=5197c493131284b9d0ec73a613a81a2604920475) |
| `L-IT-8` | The reconstructed hash pins `ISafe(safe).nonce() - 1` (`P/IncreasedThresholdPolicy:78`), checked arithmetic that panics 0x11 at nonce 0, so these rows need the subtraction in range | job [64532b9f](https://prover.certora.com/output/950385/64532b9f1a8d4e0abc16d6b546144fc1?anonymousKey=5197c493131284b9d0ec73a613a81a2604920475) |
| `L-IT-10` | `ISafe.getTransactionHash` is summarized capture-only: it records the ten arguments and returns a fresh unconstrained `bytes32` per call, so the rules that read its result assert its arguments, not two hashes | job [fc2dc2b4](https://prover.certora.com/output/950385/fc2dc2b440b64b5faa3e3cc456773967?anonymousKey=132892f595a3cb34fa1f3517a3b552af8b182d93) |
| `L-IT-11` | The write-provenance quantifier ranges over the subject's own methods only (`parametric_contracts`), its two `external view` getters included, the IncreasedThreshold instance of L-COS-12 | argument |
| `L-SAFE-1` | The Safe's owner linked list is well-formed: sentinel-terminated, no cycle, length equals `ownerCount`. Assumed, not proven: `OwnerManager` builds the list in `setupOwners`, `addOwnerWithThreshold` and `removeOwner`, all `authorized`, so no rule of these units can reach a writer, and `getOwners()` (`SAFE/base/OwnerManager.sol`) walks the list into a `new address[](ownerCount)` array, which an ill-formed list overruns or walks past `loop_iter`. `RealSafeHarness` inherits that code unchanged and the confs compile it for `paris` with the optimizer off, the settings the package ships under, but under the suite's `solc-0.8.30`: the compiler version is one scalar for the whole conf, so the verified bytecode is Safe v1.5.0's source built one minor version above the 0.8.28 `hardhat.config.ts` pins for `Safe.sol` | argument: the shape is what setupOwners establishes and what only an authorized self-call can change |
| `W-COS-1` | a valid cosignature returns magic and marks the hash spent | witness row |
| `W-IT-1` | an owner-path call with a valid signature set returns magic and marks the hash spent | witness row |
| `WAIVED-H-3` | ECDSA recovery semantics and the ERC-1271 wire format; ERC-1271 cosigners accepting an empty signature | waived: verdict symbolic; axiom countersigned for EOA cosigners only |
| `WAIVED-H-4` | Safe `checkNSignatures` internals (`GS020/021/025/026`, `v` modes, owner order, `approvedHashes`) | waived: safe is environment |
| `WAIVED-H-9` | CoSigner `InvalidSelector` (`P/CoSignerPolicy:34`) is dead code | waived: no property can cover unreachable code; cosmetic report item |

### Safenet and Binding

| conf | spec | rules | status |
|---|---|---|---|
| `Safenet.conf` | `Safenet.spec` | 26 | green, SafenetPolicy in isolation: the revert characterisation over value, module, context shape, a known epoch key, nonce, unspent and the FROST verdict, the `safeTxHash` clause of `R_SN_1_binding` blind under `L-BIND-9` (`R_SN_1`, `R_SN_1_zeroNonce`, `R_SN_1_failClosed`, `R_SN_1_gatesBeforeVerdict`, `R_SN_1_binding`, `R_SN_1_verdictNotTransferable`, `R_SN_1_anyCalldata`); a non-zero module reverts before the verdict (`R_SN_2`); a non-reverting check marks the nonce spent and touches nothing else (`R_SN_3`); once per nonce (`R_SN_4`, `R_SN_4_emptyContext`, `R_SN_4_emptyData`); `known` changes only in `updateEpoch`, false to true (`R_SN_5`, `R_SN_5_gettersAgree`); the rollover in both directions (`R_SN_6`, `R_SN_6_effect`, `R_SN_6_anchor`); the zero key is never trusted (`INV_SN_1`); `updateEpoch` is permissionless (`R_SN_7`); `$spent` write provenance (`R_SN_8`, `R_SN_8_checkKeys`); `configure` returns `true`, reverts iff `msg.value != 0` and has no storage effect (`R_SN_9`, `R_SN_9_anyCalldata`); witnesses `W_SN_1a`, `W_SN_1b` and `W_SN_1c` |
| `SafenetArgs.conf` | `SafenetArgs.spec` | 2 | `R-SN-1` green, with the `W_SN_args` witness |
| `Binding.conf` | `Binding.spec` | 17 | green, CoSignerPolicy, IncreasedThresholdPolicy and SafenetPolicy in one scene with Safe v1.5.0's hash mirrors: `R_BIND_1` and its pins state that each signature verdict receives the Safe's EIP-712 transaction hash with zeroed refund fields at `nonce - 1`, their output-level asserts blind under `L-BIND-9` and two steps of the chain open under `WAIVED-B-3`; `FROST.verify` sees the decoded key and signature over the transaction proposal message (`R_BIND_2`); `transactionProposal` is injective in its five fields, modulo keccak (`R_BIND_3`); in `updateEpoch`, `FROST.verify` is called with the parent key over the epoch rollover message (`R_BIND_4`); with four `W_BIND_*` witnesses |
| `BindingArgs.conf` | `BindingArgs.spec` | 7 | `R-BIND-1` and `R-BIND-2` green, with three `W_BINDA_*` witnesses |

Tests: `test/safenetPolicy.spec.ts`, 11 cases under `Epoch rollover: signature binding` and `Curve checks`.

The rollover cases stand behind `WAIVED-B-2`.

The curve cases stand behind `WAIVED-H-2`.


No repo test covers the Binding unit, whose subject is the hash derivation itself. Its confs put the same mock Safe in scene as the guard scenes, `BindingHarness` subclassing `SafeMockHarness` so that `chainid()` and `this` can be lifted to parameters (`L-W0-1`, `L-BIND-8`), and `WAIVED-B-3` bounds what stays open.

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `L-BIND-1` | The three cryptographic verdicts are capture-only, and two of them never revert where the CoSigner, IncreasedThreshold and Safenet specs keep a reverting verdict, `requireNonZero` rejecting `(0,0)` only | job [ce659059](https://prover.certora.com/output/950385/ce6590595b154c8697240b6cc38c292a?anonymousKey=536039cb7e18451c9afd4d847891857c31a5f53d) |
| `L-BIND-2` | Two things: keccak is modelled as an injective function, so a hash collision is out of model; and the Safe the policies call is the modelled one, since for any other `safe` the `ISafe` STATICCALLs take the `default NONDET` branch | job [ce659059](https://prover.certora.com/output/950385/ce6590595b154c8697240b6cc38c292a?anonymousKey=536039cb7e18451c9afd4d847891857c31a5f53d) |
| `L-BIND-4` | Five Safe v1.5.0 mirrors: `domainHashOf` (`Safe.sol:389-399`) and `safeTxHashOf` (`:404-473`), with `chainid()` and `this` lifted to parameters; `structHashOf` its first half; `eip712Of` it without assembly; `dataHashOf` a calldata-slice keccak | job [ce659059](https://prover.certora.com/output/950385/ce6590595b154c8697240b6cc38c292a?anonymousKey=536039cb7e18451c9afd4d847891857c31a5f53d) |
| `L-BIND-5` | The IncreasedThreshold rules are proven for Safes of 1..4 owners | job [ce659059](https://prover.certora.com/output/950385/ce6590595b154c8697240b6cc38c292a?anonymousKey=536039cb7e18451c9afd4d847891857c31a5f53d) |
| `L-BIND-6` | The unit's one instance of the L-POL-CTX defect: `R_BIND_1` carries two free CVL `bytes` (`data1`, `data2`), but `conf/Binding.conf` leaves `precise_bitwise_ops` unset, which is the sound side for an `assert`, so the pair with exactly one empty buffer is reached. `R_BIND_1_emptyData` is kept as a regression marker against a conf that turns the flag on | job [ce659059](https://prover.certora.com/output/950385/ce6590595b154c8697240b6cc38c292a?anonymousKey=536039cb7e18451c9afd4d847891857c31a5f53d) |
| `L-BIND-7` | Executions hashing a `bytes` value longer than 3200 bytes are dropped (instance of L-W0-HASH) | job [ce659059](https://prover.certora.com/output/950385/ce6590595b154c8697240b6cc38c292a?anonymousKey=536039cb7e18451c9afd4d847891857c31a5f53d) |
| `L-BIND-8` | The one link of the hash chain `R_BIND_1` asserts that CVL cannot close on 8.19.1: that Safe v1.5.0's `keccak256(add(ptr, 30), 66)` (`Safe.sol:461-470`, copied verbatim into `SafeMockHarness.getTransactionHash`) computes `keccak256(0x1901 \|\| domainSeparator \|\| structHash)` | job [ce659059](https://prover.certora.com/output/950385/ce6590595b154c8697240b6cc38c292a?anonymousKey=536039cb7e18451c9afd4d847891857c31a5f53d) |
| `L-BIND-10` | Initialisation of the observation ghosts is spec-local instrumentation that a `persistent` ghost havocs at rule start, not contract state, the Binding instance of L-COS-5 | argument |
| `L-BIND-11` | The rules that rebuild the co-signed message in CVL require `nonce() >= 1`, the parent property's own hypothesis, because the `nonce() - 1` subtraction each policy performs panics 0x11 at nonce 0 | argument |
| `L-BIND-12` | `ISafe.getTransactionHash` is summarized capture-only and the real hash code does not run, so the `R_BINDA_*` rules assert the arguments of the derivation, never a recomputed offset-30 hash | argument |
| `L-SN-1` | The FROST verdict is not computed: it is a free `persistent ghost` function of the key, signature and message, and the summary reverts when it is false at both call sites | job [ebc38a39](https://prover.certora.com/output/950385/ebc38a3935284313ae1a10c97eb3dac7?anonymousKey=e41c54a08f097276d1bb204407c356e8c4131021) |
| `L-SN-2` | The model rejects `(0,0)` only, where the real function also rejects every off-curve non-zero point (`Secp256k1.sol:181-183,226-233`) | test/safenetPolicy.spec.ts: "Should reject a non-zero genesis group key that is off the curve" |
| `L-SN-3` | The two message constructions are free deterministic uninterpreted functions of their arguments rather than `NONDET`, while `domain` keeps `NONDET` under L-SN-14 | job [ebc38a39](https://prover.certora.com/output/950385/ebc38a3935284313ae1a10c97eb3dac7?anonymousKey=e41c54a08f097276d1bb204407c356e8c4131021) |
| `L-SN-4` | Rules whose right-hand side mentions the Safe's nonce or its derived transaction hash are stated about the Safe in scene, Safe v1.5.0 itself through `RealSafeHarness`, the `default NONDET` branch being the exact summary of a STATICCALL to an unknown contract | argument: the default NONDET branch is the exact summary of a STATICCALL to an unknown contract |
| `L-SN-6` | The verify target is `SafenetHarness is SafenetPolicy`, which adds exactly two things: a constructor forwarding the four production arguments, and `decodeAttestation(bytes)`, `SafenetPolicy.sol:115-121` as an external function | job [ebc38a39](https://prover.certora.com/output/950385/ebc38a3935284313ae1a10c97eb3dac7?anonymousKey=e41c54a08f097276d1bb204407c356e8c4131021) |
| `L-SN-7` | Antecedent and observation-ghost requires: each states the property's own hypothesis (`module != 0`, `nonce() == 0`, the pair is new) or initialises a `persistent ghost` that is not contract state (`!frostCalled`) | argument |
| `L-SN-8` | The typed rules quantify over canonically decodable argument tuples, not raw calldata, as in L-POL-6 and its instances | job [ebc38a39](https://prover.certora.com/output/950385/ebc38a3935284313ae1a10c97eb3dac7?anonymousKey=e41c54a08f097276d1bb204407c356e8c4131021) |
| `L-SN-9` | The `nonce() == 0` branch is excluded from the iff and given its own rule | job [ebc38a39](https://prover.certora.com/output/950385/ebc38a3935284313ae1a10c97eb3dac7?anonymousKey=e41c54a08f097276d1bb204407c356e8c4131021) |
| `L-SN-10` | The unit's instance of L-POL-CTX: on certora-cli 8.19.1, under `precise_bitwise_ops: true`, the prover's `assert` model drops every input pair in which exactly one free CVL `bytes` is the empty byte string, once the rule makes a call carrying a `bytes`. `conf/Safenet.conf` and `conf/SafenetArgs.conf` leave the flag unset, which is the sound side for an `assert`, so the unit's `assert` rules are not exposed and its empty-`bytes` rules are regression markers; what runs on the coarse model there is the `satisfy` witnesses, section 7 | job [ebc38a39](https://prover.certora.com/output/950385/ebc38a3935284313ae1a10c97eb3dac7?anonymousKey=e41c54a08f097276d1bb204407c356e8c4131021) |
| `L-SN-11` | The suite-wide hashing bound, and a pessimistic loop bound that is inert in this scene | job [ebc38a39](https://prover.certora.com/output/950385/ebc38a3935284313ae1a10c97eb3dac7?anonymousKey=e41c54a08f097276d1bb204407c356e8c4131021) |
| `L-SN-12` | Not an assumption about the code but a measured prover artifact, and the minimal shape that works around it: reading the `uint64`, `address` or struct return of a `@withrevert` call trips an internal prover assert on the reverting branch | job [ebc38a39](https://prover.certora.com/output/950385/ebc38a3935284313ae1a10c97eb3dac7?anonymousKey=e41c54a08f097276d1bb204407c356e8c4131021) |
| `L-SN-13` | `method f` ranges over the subject's own methods only, not over the whole scene | job [ebc38a39](https://prover.certora.com/output/950385/ebc38a3935284313ae1a10c97eb3dac7?anonymousKey=e41c54a08f097276d1bb204407c356e8c4131021) |
| `L-SN-14` | The EIP-712 domain-separator derivation is not modelled: `NONDET` replaces `ConsensusMessages.sol:45-53`, and every message is built from the immutable the constructor stored (`SafenetPolicy.sol:42`) | test/safenetPolicy.spec.ts |
| `L-SN-15` | `ISafe.getTransactionHash` is summarized capture-only and the real hash code does not run, so a rule that reads its result asserts the arguments of the derivation, never a recomputed offset-30 hash | job [43293a9c](https://prover.certora.com/output/950385/43293a9c9b60419f87d08be2f70a54a8?anonymousKey=9473b4e252fa9a32363496ea0f63461fd3f5496e) |
| `W-SN-1` | a well-formed attestation clearing, and a rollover recording a new trusted pair | witness row |
| `WAIVED-B-1` | Refund fields (`safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, `refundReceiver`) never reach any policy, `IPolicy.sol:36-45`, so no CVL statement can distinguish them | waived: documented non-binding, not a rule |
| `WAIVED-B-3` | Two steps of the hash chain `R_BIND_1` asserts: that Safe v1.5.0's `keccak256(add(ptr, 30), 66)` computes the standard `keccak256(0x1901 \|\| domainSeparator \|\| structHash)`, and that `getTransactionHash(args)` equals the parameterized mirror | waived: not expressible on 8.19.1, measured rather than asserted: a keccak pre-image beginning 30 bytes into a memory word is not decomposed by the prover, so that hash is neither injective nor equal to the same bytes written otherwise (measured by job [76273dee](https://prover.certora.com/output/950385/76273dee762c4fa6bb48e24f3bd0a1af?anonymousKey=9f5022d1846e9a54276efe22e86aeaf0bd1c0eb8), the `BindingHash` probe, whose conf is not part of this tree, so the job cannot be re-run from it) |
| `WAIVED-H-1` | FROST/Schnorr cryptographic soundness (`FROST.verify`, `challenge`, `mulmuladd`, ecrecover trick, `_divmod`) | waived: not expressible; verdict symbolic |
| `WAIVED-H-2` | On-curve check for non-zero points (`_satisfiesCurveEquation`) | waived: modelled zero-point-only, the superset `L-SN-2` records |

## Evidence rules

- Job ids live in the report's property table, one per row, as links under `https://prover.certora.com/output/950385/` that carry a share key (`anonymousKey`) and open without a Certora account; the conf, with its `rule` filter where it has one, is the reproducible evidence.
- The `discharge` column of a unit table shows a job id as its first eight hex characters, each a link to the job with its share key, like the links of the report's property and assumption tables.
- Regrade any job in the web UI: open its URL and check the Rules tab, where every rule must show SUCCESS.
- Re-run a claim with `certoraRun certora/conf/<X>.conf --wait_for_results all`, then grade it the same way.
- Waivers name their test or their reason in the report's section 3.2; run the repo tests with `npm test`.
- The `ApplyEffects`, `Delay` and `RootFields` confs merged into `EngineConfigApply.conf` are not part of this tree, so their jobs cannot be re-run from it.
- Each unit section lists, in one clause each, the assumption, waiver, finding and decision ids its own files first cite, with the report's full sentence as the source; 29 further ids are carried by the report alone and cited by no other shipped file, 3 assumption, 18 waiver, 5 decision and 3 finding; 4 withdrawn assumption ids (`L-CFG-MIRROR`, `L-SN-5`, `L-W0-4`, `L-W0-REVERT`) are named outside the report only in this line.

## Not in this tree

- A conf for the properties the report's section 7 lists as having no rule run, and the spec of the nested-batch rule. The other rules stay in their specs as comments.
- The reproductions of the prover defects that `L-HASHBLIND`, `L-BIND-9`, `L-POL-CTX` and `L-CFG-DECODE` describe, and the negative control for the recursion budget of `INV-EC-1`; the jobs that ran them are cited where each is described, and say that their confs are not part of this tree.
