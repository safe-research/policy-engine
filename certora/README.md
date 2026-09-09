# Formal verification: Policy Engine

Certora/CVL suite for `contracts/SafePolicyGuard.sol`, `contracts/core/PolicyEngine.sol` and the libraries and policies the report's section 1 lists; every harness mirrors the deployed code, so `git diff main -- contracts/` is empty in this tree.

## Results

43 of 43 property rows are green. The table with every row's rule, conf, status and job is in `certora/VERIFICATION_REPORT.md`.

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

Grade a run in the Certora web UI: the Rules tab is the authority for a verdict, listing every rule's verdict, and the conf is green only when every leaf there is SUCCESS; the Job Info tab is the authority for the flags the run actually used, which a conf only requests. `Results.txt` is neither: for `satisfy` rules its `FAIL:`/`Violated:` wording is inverted and healthy sanity sub-rules print `Violated`. Submit one conf at a time: a conf can hold the prover for its whole `smt_timeout`, which 21 of the 30 raise to 1800 or 3600 seconds.

## Layout

| Path | Holds |
|---|---|
| `certora/specs/` | 12 CVL specs. `Vocabulary.spec` holds scene-free definitions, which a spec imports whatever its scene. `Common.spec` imports it and carries the shared `methods` block and the shared definitions of the guard's scene. `Common.spec` also carries the invariant `sentinelsClear`. |
| `certora/conf/` | 30 run configurations, one or more per spec. A spec is split across confs where one run does not converge or needs a different flag. |
| `certora/harnesses/` | 6 files, 7 contracts: `GuardSlotDecodePin`, `LibHarness`, `MockPolicyHarness`, `SafeSlotMock`, `GuardProbeResponderMock`, `SafeMockHarness`, `SafePolicyGuardHarness`. |
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
| Safe in scene | The Safe a rule talks about is `SafeMockHarness` in the 23 `EngineCheck*`/`EngineConfig*` confs of `certora/conf/` (`L-W0-1`). The guard scenes keep the mock because their subject is the guard slot, which on a real Safe has no state variable to `require`, `getGuard` being `internal` and `setGuard` `authorized`; the mock answers `getStorageAt` over havoced storage, so a rule fixes the slot word with `require`. |
| Compiler | Every conf pins `solc-0.8.30`, `solc_via_ir: true`, `solc_evm_version: cancun` and `solc_optimize: 10000000`, matching `hardhat.config.ts`, and any divergence proves something about different bytecode. |
| Budget | 21 of the 30 confs raise `smt_timeout` to 1800 or 3600 seconds and the rest run at the certora-cli default of 300 seconds per SMT query, a rule over budget reporting TIMEOUT and never green. `rule_sanity: basic` is set in every conf, and a `SANITY_FAIL` leaf is advisory: the rule's own assert still reports its verdict and the report dispositions each one. |

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
| `L-IT-1` | The Safe's `checkNSignatures` verdict is a free function of `(dataHash, signatures, required)`, a wildcard over every callee, with `executor` captured and asserted `== 0` (`P/IncreasedThresholdPolicy:82-87`) |  |
| `L-IT-2` | The Safe in scene is set up: `1 <= threshold <= ownerCount`, an invariant against the mock, whose only writer `SafeMockHarness.setOwnersAndThreshold` requires it, and a precondition of the rules that put Safe v1.5.0 in scene, whose own writers are `authorized` and therefore unreachable from a policy rule | job [335e2ef1](https://prover.certora.com/output/950385/335e2ef18dc6432faed47cebc7fcb542?anonymousKey=c2e1256ff0e44b4ecc333201615dc59d02e4e8c4) |
| `L-IT-4` | The owner list is bounded to 4 entries and hashing to `hashing_length_bound 3200`, the L-W0-HASH instance, because `_requiredSignatures` reads `ISafe(safe).getOwners().length` (`P/IncreasedThresholdPolicy:147`) |  |
| `L-IT-9` | An unknown Safe's owner list is a free array of at most four entries, in the three rules over an arbitrary `safe`; the rules over the Safe in scene assume nothing here, `getOwners()` there being Safe v1.5.0's own walk of its owner list. `SafeMock.conf`'s `ownersLengthIsOwnerCount` proves the same length fact against `SafeMockHarness`'s own body at up to three owners: a sanity check on the shape of the summary, not its discharge, since no IncreasedThreshold conf links the mock and the rules that read the summary run at four owners |  |
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
| `WAIVED-S-4` | Spend rollback when execution fails (a spent ONCE/OTA grant is restored because the Safe transaction reverts), needed by the OneTimeAllow and the two ERC20 spend rows | waived: only the Safe-atomicity limb is environment. The guard half is in-scope production code and unproven: `SafePolicyGuard.sol:239-241` and `:268-270` are the only thing stopping a policy's spend from committing against an action that never took effect |

### Simple policies

| conf | spec | rules | status |
|---|---|---|---|
| `Allow.conf` | `Allow.spec` | 2 | `R-ALLOW-1` green |
| `AllowWitness.conf` | `Allow.spec` | 1 | `W-ALLOW-1` green |
| `Deny.conf` | `Deny.spec` | 2 | `R-DENY-1` green |

#### Ids introduced here

| id | claim | discharge |
|---|---|---|
| `L-POL-6` | The typed revert-iff rules `R_ALLOW_1` and `R_DENY_1` range over canonical ABI encodings of the parameter tuple, not raw calldata, which `calldataarg` widens to encodings solc's decoder rejects; their `_anyCalldata` twins take the raw domain | argument |
| `L-POL-7` | Exact bitvector modelling for every `satisfy` rule in the unit, with the `assert` rules left on the default encoding in `Allow.conf` and `Deny.conf` | job [1dad762d](https://prover.certora.com/output/950385/1dad762d6a0d410b963792b88e971a5b?anonymousKey=005f8d141665d81eeabd2cc51d814e80d9d1e997) |
| `L-POL-8` | Per-unit instance of L-W0-HASH and the loop template keys: executions hashing a `bytes` longer than 3200 bytes are dropped. The bound is inert in this unit, no policy it verifies and no rule of its specs hashing a variable-length value, so the revert-iff rows hold at every calldata length | job [982fe202](https://prover.certora.com/output/950385/982fe20275cc42a594f7bcf1c4edc770?anonymousKey=a4a2e30026bd3e8512daeb011d79ad84ff36578a) |
| `W-ALLOW-1` | a `checkTransaction` returning `MAGIC` with `value > 0`, `data.length >= 4`, `module != 0` | witness row |

## Evidence rules

- Job ids live in the report's property table, one per row, as links under `https://prover.certora.com/output/950385/` that carry a share key (`anonymousKey`) and open without a Certora account; the conf, with its `rule` filter where it has one, is the reproducible evidence.
- The `discharge` column of a unit table shows a job id as its first eight hex characters, each a link to the job with its share key, like the links of the report's property and assumption tables.
- Regrade any job in the web UI: open its URL and check the Rules tab, where every rule must show SUCCESS.
- Re-run a claim with `certoraRun certora/conf/<X>.conf --wait_for_results all`, then grade it the same way.
- Waivers name their test or their reason in the report's section 3.2; run the repo tests with `npm test`.
- The `ApplyEffects`, `Delay` and `RootFields` confs merged into `EngineConfigApply.conf` are not part of this tree, so their jobs cannot be re-run from it.

## Not in this tree

- A conf for the properties the report's section 7 lists as having no rule run, and the spec of the nested-batch rule. The other rules stay in their specs as comments.
