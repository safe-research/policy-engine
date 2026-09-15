# Verification report: Safe Policy Engine, Certora FV suite

Results, evidence and limits for the Certora suite under `certora/`. Job ids link to `https://prover.certora.com/output/950385/<id>`; in the tables `P/<Name>` is `contracts/policies/<Name>.sol`, `E:` is `contracts/core/PolicyEngine.sol`, `G:` is `contracts/SafePolicyGuard.sol`, `SAFE/` is Safe v1.5.0, and every other path is repository-relative.

## 1. Scope and units

Verified sources: `SafePolicyGuard.sol` configuration path; `AccessSelector.sol`, `SignatureExtension.sol`; Safe v1.5.0, mocked. `contracts/` is byte-identical to `main`, the suite adding specs, confs and harnesses only.

| unit | subject | specs | confs |
|---|---|---|---|
| EngineConfig (CFG) | `SafePolicyGuard.sol` configuration path | `EngineConfig`, `Common` | `EngineConfig`, `EngineConfigRoot`, `EngineConfigRootPin` |
| Lib (LIB) | `AccessSelector.sol`, `SignatureExtension.sol` | `Lib` | `Lib`, `LibBitwise` |
| shared | Safe v1.5.0, mocked | `SafeMock` | `SafeMock` |

Harnesses: `LibHarness`, `MockPolicyHarness`, `SafeSlotMock`, `GuardProbeResponderMock`, `SafeMockHarness`, `SafePolicyGuardHarness`: 5 files, 6 contracts. Repo tests: `test/*.spec.ts`, run by `npm test`.

## 2. Results summary

| | |
|---|---|
| Green properties | 11 of 11: 10 unqualified, 1 qualified in the status cell |
| Blocked on prover limits | none |
| Waived with measured evidence | 0 |
| Confs and their jobs | 6 confs, each row citing a graded job: 6 have every leaf SUCCESS, 0 carry a non-SUCCESS leaf |
| Repo tests | 180 passing, the `npm test` summary line (section 8) |

## 3. Property table

One row per property, `status` as recorded; `job` is the graded job whose rule-name fingerprint matches the conf, or the job the row itself cites where the conf has no such job.

| id | statement | rule id(s) | conf | status | job |
|---|---|---|---|---|---|
| `R-CFG-4` | `requestConfiguration(r)` full characterisation: revert-iff, the timestamp written, everything else unchanged | `R_CFG_4` | `EngineConfig.conf` | green | [f2ef38dc](https://prover.certora.com/output/950385/f2ef38dc32074acca3ec5c6d381fd363?anonymousKey=ad922e5d6e6893f7d73eabdd601d93f7cf2cdc44)  |
| `R-CFG-5` | `invalidateRoot(r)` full characterisation: revert-iff, the slot cleared, everything else unchanged | `R_CFG_5` | `EngineConfig.conf` | green | [f2ef38dc](https://prover.certora.com/output/950385/f2ef38dc32074acca3ec5c6d381fd363?anonymousKey=ad922e5d6e6893f7d73eabdd601d93f7cf2cdc44)  |
| `R-LIB-1` | Access key round-trip, hence injectivity | `R_LIB_1` | `LibBitwise.conf` | green | [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054)  |
| `R-LIB-2` | Access key layout facts, as the README states them | `R_LIB_2` | `LibBitwise.conf` | green | [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054)  |
| `R-LIB-3` | Intended collision of the zero selector with empty calldata | `R_LIB_3` | `LibBitwise.conf` | green | [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054)  |
| `R-LIB-4` | Getters are total over every key | `R_LIB_4` | `LibBitwise.conf` | green | [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054)  |
| `R-LIB-5` | Canonicalisation of the packed key | `R_LIB_5` | `LibBitwise.conf` | green | [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054)  |
| `R-LIB-6` | `payload` revert-iff, with its length and content | `R_LIB_6` | `Lib.conf` | green | [8a1d1edd](https://prover.certora.com/output/950385/8a1d1eddd41345778af248e6fa9eba50?anonymousKey=292eef4663347ae41630fe1e5380fd77a5587659)  |
| `R-LIB-7` | Envelope detection and `_decodeContext` composition, fail closed | `R_LIB_7` | `Lib.conf` | green | [8a1d1edd](https://prover.certora.com/output/950385/8a1d1eddd41345778af248e6fa9eba50?anonymousKey=292eef4663347ae41630fe1e5380fd77a5587659)  |
| `R-LIB-8` | Selector content of a key | `R_LIB_8` | `LibBitwise.conf` | green, the selector's trailing three bytes tied to the word reader only (`L-LIB-4`) | [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054)  |
| `W-LIB-1` | Witnesses for the library readers | `W_LIB_1_envelope`<br>`W_LIB_1_selector` | `LibBitwise.conf` | green | [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054)  |

### 3.1 Blocked rows

No property row of this tree is blocked.

### 3.2 Waivers

9 written waivers. A written waiver takes a claim out of scope and is not a property row: section 2's `Waived with measured evidence` row counts the property rows instead. A waiver names a repo test only by quoting that test's `it(` title and the concrete boundary it reaches (D-012), each quoted title matching exactly one `it(` title in `test/`; the others waive with an argument, a superseding rule or a section of this report.

| id | what was waived | reason | test |
|---|---|---|---|
| `WAIVED-EC-5` | Envelope payload content exactness (the bytes returned equal the bytes the client appended) | R-LIB-6/7 prove the library-level half, that the bytes `payload` and `_decodeContext` return are byte for byte `sig[len-64-lengthWord : len-64]`. What stays waived is that the region holds what the client encoded. | `test/safePolicyGuardContext.spec.ts`: "Should treat signatures not ending in the type hash as carrying no context" |
| `WAIVED-CFG-1` | Events (`RootConfigured`/`RootInvalidated`/`RootApplied`/`PolicyConfirmed` incl. `policy == 0`) | CVL2 has no event assertions | `test/safePolicyGuardDelayedConfiguration.spec.ts`: "Should emit an event when the configuration is requested" |
| `WAIVED-CFG-2` | Malformed ABI encoding of `Configuration[]` calldata (dirty selector bits, `operation == 2`, dirty `policy` word) reverts in solc's decoder | Decoder, not contract code; revert-iff rules range over ABI-valid calldata (README scope line) | none: solc decoder scope |
| `WAIVED-CFG-3` | keccak collision resistance for roots | prover model = injective | n/a |
| `WAIVED-CFG-4` | Real Safe proxy semantics of `getStorageAt` and of `setGuard`/`setModuleGuard` writing the slots; slot constants equal the Safe's | Safe is environment; constants are `private` | `test/safePolicyGuardConfiguration.spec.ts`: "Should not be able to configure immediately even when a policy permits calling the guard" |
| `WAIVED-CFG-5` | Non-canonical calldata of the same logical `Configuration[]` yields the same root | solc re-encoding fact, not a rule | none: solc re-encoding fact |
| `WAIVED-H-5` | Equality of the mock `getTransactionHash` with a real Safe's | environment code copied verbatim | n/a |
| `WAIVED-ENV-3` | Timelock semantics for `DELAY == 0` deployments; validator timestamp skew | environment; the `W_CFG_1_W3` witness covers `DELAY == 0` | n/a |
| `WAIVED-ENV-4` | Guard as generic caller of `configure(address,uint256,bytes)` on caller-chosen addresses | guard holds no assets/roles; threat-model note | n/a |

One id of the series is retired, proven rather than waived, and is not counted above.

| id | what it waived | why it is retired |
|---|---|---|
| `WAIVED-EC-2` | Selector content: `selectorOf(data)` equals the first four bytes of `data`, waived on the premise that CVL cannot index `bytes` | The premise is false: `LibHarness.byteAt(bytes,uint256)` indexes `bytes` and is already used by R-LIB-6 and R-LIB-7. The claim is R-LIB-8 above, green in `LibBitwise.conf` |

## 4. Assumptions

| id | where | justification | discharge |
|---|---|---|---|
| `L-IT-1` | `specs/SafeMock.spec` | The Safe's `checkNSignatures` verdict is a free function of `(dataHash, signatures, required)`, a wildcard over every callee, with `executor` captured and asserted `== 0` (`P/IncreasedThresholdPolicy:82-87`). |  |
| `L-W0-2` | `harnesses/MockPolicyHarness.sol`, the DISPATCH lists of `specs/EngineConfig.spec` | The closed scene {Allow, Deny, OneTimeAllow, MockPolicyHarness} stands in for arbitrary policy code on the check (`E:200`) and configure (`E:292`) paths, dispatched by the per-signature `DISPATCH [...]` summaries. Each spec sets its own `default` for a policy outside that list, and the two settings are not the same adversary: under `HAVOC_ECF` an out-of-scene policy may write storage and re-enter the guard's configuration entry points, under `NONDET` it is a side-effect-free function returning a free value, which can neither revert nor re-enter. The configuration specs set `HAVOC_ECF`; a check spec sets what its own header states. | job [f2ef38dc](https://prover.certora.com/output/950385/f2ef38dc32074acca3ec5c6d381fd363?anonymousKey=ad922e5d6e6893f7d73eabdd601d93f7cf2cdc44) |
| `L-CFG-SCENE` | `specs/EngineConfig.spec` | The iff halves are stated only where the scene fixes the `configure` verdict, `policy in {0, Allow, Deny, OneTimeAllow, MockPolicyHarness}`, and those rules pin the mock away from its re-entrant `CALL_CONFIG` mode. | `test/policyEngine.spec.ts`: "Should reject configuring an account with no code as a policy" |
| `L-W0-1` | `harnesses/SafeMockHarness.sol`, the 3 `EngineCheck*`/`EngineConfig*` confs, `conf/SafeMock.conf` | `SafeMockHarness` stands in for the Safe in the guard scenes, whose subject is the guard slot: `getStorageAt` (`StorageAccessible.sol:16-29`) and `getTransactionHash`/`domainSeparator` (`Safe.sol:389-399,404-473`) verbatim, guard values at the real keccak slots (`G:49,55-56`), `nonce`/`getOwners`/`getThreshold` as storage. | argument: `getStorageAt`, `getTransactionHash` and `domainSeparator` are Safe v1.5.0's code copied verbatim |
| `L-BIND-3` | applies at `harnesses/SafeMockHarness.sol`; defined here | The mock's hash equals a real Safe's EIP-712 transaction hash for the same fields at the mock's address and chain. | argument: the mock's `getTransactionHash` and `domainSeparator` are Safe v1.5.0's code copied verbatim, as L-W0-1 states |
| `L-CFG-LOOP-N1` | `specs/EngineConfig.spec`, `conf/EngineConfig.conf`, `conf/EngineConfigRootPin.conf` | These rules bound the configuration array to at most one entry instead of the unit's usual three: `W_CFG_1_W2`, `W_CFG_1_W3` and `R_CFG_6a_one`. | argument |
| `L-IT-4` | `specs/SafeMock.spec` | The owner list is bounded to 4 entries and hashing to `hashing_length_bound 3200`, the L-W0-HASH instance, because `_requiredSignatures` reads `ISafe(safe).getOwners().length` (`P/IncreasedThresholdPolicy:147`). |  |
| `L-W0-HASH` | `conf/LibBitwise.conf`, `conf/SafeMock.conf` | Executions hashing a `bytes` value longer than the conf's own bound are dropped, an assumed bound. | argument: the flag drops executions that hash past the bound, so a violation beyond it is missed, and no rule of the suite hashes an unbounded `bytes` |
| `L-W0-SENTINEL` | `specs/Common.spec` | No rule of this tree assumes `$checkingSafe == 0 && $checkingModule == 0` in the pre-state of a hook call through `requireInvariant`; that state is the sentinel invariant's own claim. |  |
| `L-W0-SENDER` | `specs/EngineConfig.spec` (the `msg.sender != 0` requires) | `msg.sender` is never `address(0)` on chain: no key has that address and a contract cannot be deployed there. | argument |
| `L-ENV-TIME` | applies at `specs/EngineConfig.spec`; defined here | Block timestamps are non-decreasing across transactions | argument |
| `L-W0-BITWISE` | `conf/LibBitwise.conf` and every conf setting `precise_bitwise_ops` | Bitwise operations are modelled exactly with bitvector theory instead of the default over-approximation. | job [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054) |
| `L-W0-3` | `conf/EngineConfig.conf`, `conf/EngineConfigRoot.conf`, `conf/EngineConfigRootPin.conf`, `harnesses/Mocks.sol`, `specs/EngineConfig.spec` | The responder mock's per-slot modes cover every observable of `_readGuardSlot` (`G:311-320`): revert, short return and symbolic return words, with the rules over the answer's decode bounding `retLen <= 160`. | `test/safePolicyGuardConfiguration.spec.ts` |
| `L-W0-LOOP` | `specs/Common.spec` preserved blocks | `loop_iter` is 3 in the shared scene: a configuration array is bounded to 3 entries where a rule carries one, and the calldata-to-memory copies of the library readers are unrolled 3 times where it does not. | argument: `optimistic_loop` is false, so a bound too low fails an unwinding assertion rather than assuming the rest away |
| `L-W0-RECUR` | the 3 confs setting `contract_recursion_limit`, 1 of them also `summary_recursion_limit` | A method of the guard may appear at most twice on the call stack (guard, mock, guard, policy), and deeper cycles are cut by asserted pessimistic bounds rather than assumed away. | job [f2ef38dc](https://prover.certora.com/output/950385/f2ef38dc32074acca3ec5c6d381fd363?anonymousKey=ad922e5d6e6893f7d73eabdd601d93f7cf2cdc44) |
| `L-LIB-1` | `conf/LibBitwise.conf` | Executions hashing a `bytes` longer than 3200 bytes are dropped, an instance of L-W0-HASH. It is inert: no rule run under it hashes a symbolic `bytes`, and `conf/Lib.conf`, which runs the two length rules, sets neither key, so their claims hold at every length. | argument: inert, so nothing rests on it here |
| `L-LIB-2` | `conf/LibBitwise.conf` | Bitwise ops modelled exactly with bitvector theory for the AccessSelector packing rules, the Lib adoption of L-W0-BITWISE. | job [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054) |
| `L-LIB-3` | `harnesses/LibHarness.sol` | Arithmetic and reader vocabulary are pure total functions of their inputs, ABI casts and zero-padded calldata reads, not mirrors of contract logic. | job [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054) |
| `L-LIB-4` | `specs/Lib.spec` | A rule pinning selector content ties `selectorOf(d)` to `wordAt(d,0)` (an aligned `calldataload` plus a tail mask) and `byteAt(d,0)`, but not to `byteAt(d,1..3)`, so the selector's trailing three bytes are tied to the word reader, not the byte reader. | job [adee3e24](https://prover.certora.com/output/950385/adee3e24e67b4ec1a07d93e439a9fba0?anonymousKey=a9cce25ceba0a520563a069811cc664c3e679054) |
| `L-CFG-LOOP` | `specs/EngineConfig.spec`, `conf/EngineConfig*.conf` | Configuration arrays are bounded to 3 entries, a scope under-approximation at `G:344`, `G:397` and the `abi.encode` walk feeding `G:390`. | argument |
| `L-CFG-PROBE` | `specs/EngineConfig.spec` | Senders of the `GuardAlreadyEnabled` family are restricted to the two mocks, and the responder's answer length is bounded at 160 bytes. | `test/safePolicyGuardConfiguration.spec.ts` |
| `L-CFG-HASH` | the 3 `conf/EngineConfig*.conf` files: 1 bound at 3200 bytes, 1 at 448 and 1 at 1216 | Executions hashing a `bytes` value longer than the conf's own bound are dropped (assumed bound) | argument |
| `L-CFG-RECUR` | `conf/EngineConfig*.conf` | Re-entrant `configure`, the `MockPolicyHarness` `ConfigureMode.CALL_CONFIG` mode that calls one of the four configuration entry points on `msg.sender`, chosen by `configCall`, is modelled to one nested level with an asserted bound. | argument |
| `L-CFG-GATE` | `specs/EngineConfig.spec` | The `GuardAlreadyEnabled` iff is stated with an empty configuration array | argument |
| `L-CFG-FRAME` | `specs/EngineConfig.spec` | The opcode-hook observer ghosts start at zero | argument |
| `L-CFG-SLOTMOCK` | `harnesses/Mocks.sol` (`SafeSlotMock`), `specs/EngineConfig.spec` | The Safe answering the guard's slot probe in the `GuardAlreadyEnabled` family is `SafeSlotMock`, a Safe's observable answer with slot words in a mapping, and `SafeMockHarness` is out of that DISPATCH list. | `test/safePolicyGuardConfiguration.spec.ts` |
| `L-EC-6` | `harnesses/MockPolicyHarness.sol` | Re-entry through `MockPolicyHarness` is modelled to one nested dispatched frame, with an asserted bound. |  |
| `L-EC-8` | `harnesses/SafePolicyGuardHarness.sol` | `tryCheck` is an external self-call (`msg.sender == guard`), used only to classify the engine-level revert as `AccessDenied`, `PolicyReverted` or raw. |  |
| `L-IT-2` | `specs/SafeMock.spec`, `conf/SafeMock.conf` | The Safe in scene is set up: `1 <= threshold <= ownerCount`, an invariant against the mock, whose only writer `SafeMockHarness.setOwnersAndThreshold` requires it, and a precondition of the rules that put Safe v1.5.0 in scene, whose own writers are `authorized` and therefore unreachable from a policy rule | job [335e2ef1](https://prover.certora.com/output/950385/335e2ef18dc6432faed47cebc7fcb542?anonymousKey=c2e1256ff0e44b4ecc333201615dc59d02e4e8c4) |
| `L-IT-9` | `conf/SafeMock.conf`, `specs/SafeMock.spec` | An unknown Safe's owner list is a free array of at most four entries, in the three rules over an arbitrary `safe`; the rules over the Safe in scene assume nothing here, `getOwners()` there being Safe v1.5.0's own walk of its owner list. `SafeMock.conf`'s `ownersLengthIsOwnerCount` proves the same length fact against `SafeMockHarness`'s own body at up to three owners: a sanity check on the shape of the summary, not its discharge, since no IncreasedThreshold conf links the mock and the rules that read the summary run at four owners. |  |
| `L-POL-CTX-M` | applies at `specs/EngineConfig.spec`; defined here | An audit of the exposure class: each rule the prover's empty-`bytes` pair defect leaves unmeasured is probed in three emptiness cases (`context` empty, `data` empty, both), 75 probes verdicting 69 SUCCESS, 6 vacuous and 0 FAIL, the vacuous ones being empty-`data` probes of rules whose antecedents need `batchLength(data)` to decode; the `configureImmediately` effects rule is covered instead by four pinned cases with the flag off, all SUCCESS. An exposed rule that carries a companion pinning `context1.length == 0` is answered by that companion rather than by a probe, so the `data1`/`data2` pair of such an independence rule is unmeasured. | argument: the enumeration's 75 probe jobs, not linked here, whose confs are not part of this tree, and job [a1318175](https://prover.certora.com/output/950385/a1318175b20042e88501662982d419fd?anonymousKey=153d0f62ccc55542b1c2b75aa3b53ef0b5365c45) for the four pinned cases, whose conf is not part of this tree, so the job cannot be re-run from it |

## 5. Modelling decisions

| id | decision |
|---|---|
| `D-002` | The suite pins certora-cli 8.19.1 in `certora/requirements.txt`, not the repo's pre-existing 8.6.4. |
| `D-005` | The Rules tab, equivalently `output.json` per-rule status, is the authority for a verdict, and the Job Info tab is the authority for the flags a job ran with (`Results.txt` is neither); a "Violated" log line for `rule_not_vacuous` is the probe being refuted, which is the intended result. |
| `D-007` | `$policies` is read by direct storage access `currentContract.$policies[s][a]`, not by a hook-ghost mirror; any ghost that must survive an unresolved CALL is `persistent`. |
| `D-008` | An unresolved policy CALL defaults to `HAVOC_ECF` with nondeterministic return data, so "policy revert implies PolicyReverted" could be proven only against a really-reverting scene policy, and no rule of this tree proves it (section 7). |
| `D-009` | Policy recursion is summarized per signature: `function _.checkTransaction(<8 args>) external => DISPATCH [...]` does inline the policy scene, and no second engine scene is built for a nested MultiSend batch, whose expansion this tree does not prove (section 7). |
| `D-012` | A waiver may not name a repo test unless the row quotes that test's `it(` title and the concrete boundary it reaches. |

## 6. Findings

### 6.1 Documentation defects

Every finding of this suite is a documentation or precision defect in the engine's own documents, not a contract flaw, and each is still open at `main` 405ba1d. The three documentation changes over the same ground, #100, #102 and #104, add one README section, "Where the check and the execution can diverge", with three bullets of their own; none of them states any of these, and no policy source changed with them, so the contract-comment findings stand.

| id | title | description | status |
|---|---|---|---|
| `B-5` | Delay guarantees over-broad | The README's delay guarantees do not hold when a policy permits a DELEGATECALL to untrusted code. #100's new bullet says a DELEGATECALL carries a `msg.value` no policy sees, which is a different divergence: it does not say the callee can rewrite the guard slots, the nonce or the owners and so undo the delay. #101's expiry window shortens how long a matured root stays usable but changes nothing here. | open |

## 7. Not proven

- Cryptography is modelled, not proven: each verdict is a free uninterpreted function, and the fixtures that exercise it in `test/` sign with the same library code the policy verifies.

No conf of this tree runs a rule for the properties below. Their rules stay in their specs as comments, except the nested-batch rule, whose spec is not in this tree.

- The nested MultiSend batch: a sub-transaction that is itself a `multiSend` delegatecall, expanded at depth 2.

## 8. How to verify any claim

```bash
# grade a job at https://prover.certora.com/output/950385/<32-hex job id>: the Rules tab lists every
# rule's verdict (green only if all are SUCCESS), the Job Info tab the flags the server ran with,
# which are the authority over conf text
npm test                                                              # 180 repo tests at this tree
certoraRun certora/conf/<name>.conf --wait_for_results all
```

The repo-test count is the runner's own summary line, `npm test` ending in `180 passing`; it excludes every `[@bench]` title through `--grep` (`package.json`), so a raw `it(` count over `test/` is higher. Count from the `status` column, not by grepping a row's prose, and treat a job as evidence only for the conf whose rule set it ran: check that the job's Rules tab lists exactly that conf's `rule` filter. The conf and its `rule` filter are the reproducible evidence either way.

Every one of the 6 confs under `certora/conf` has every leaf SUCCESS in the job its rows cite.

The other jobs this report cites ran confs that are not part of this tree, and each citation says so; each such job stays readable through its link.
