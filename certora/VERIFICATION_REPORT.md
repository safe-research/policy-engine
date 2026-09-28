# Verification report: Safe Policy Engine, Certora FV suite

Results, evidence and limits for the Certora suite under `certora/`. Job ids link to `https://prover.certora.com/output/950385/<id>`; in the tables `P/<Name>` is `contracts/policies/<Name>.sol`, `E:` is `contracts/core/PolicyEngine.sol`, `G:` is `contracts/SafePolicyGuard.sol`, `SAFE/` is Safe v1.5.0, and every other path is repository-relative.

## 1. Scope and units

Verified sources: `AccessSelector.sol`, `SignatureExtension.sol`. `contracts/` is byte-identical to `main`, the suite adding specs, confs and harnesses only.

| unit | subject | specs | confs |
|---|---|---|---|
| Lib (LIB) | `AccessSelector.sol`, `SignatureExtension.sol` | `Lib` | `Lib` |

Harnesses: `LibHarness`, `SafePolicyGuardHarness`: 2 files, 2 contracts. Repo tests: `test/*.spec.ts`, run by `npm test`.

## 2. Results summary

| | |
|---|---|
| Green properties | 2 of 2: 2 unqualified, 0 qualified in the status cell |
| Blocked on prover limits | none |
| Waived with measured evidence | 0 |
| Confs and their jobs | 1 conf, each row citing a graded job: 1 has every leaf SUCCESS, 0 carry a non-SUCCESS leaf |
| Repo tests | 175 passing, the `npm test` summary line (section 8) |

## 3. Property table

One row per property, `status` as recorded; `job` is the graded job whose rule-name fingerprint matches the conf, or the job the row itself cites where the conf has no such job.

| id | statement | rule id(s) | conf | status | job |
|---|---|---|---|---|---|
| `R-LIB-6` | `payload` revert-iff, with its length and content | `R_LIB_6` | `Lib.conf` | green | [8a1d1edd](https://prover.certora.com/output/950385/8a1d1eddd41345778af248e6fa9eba50?anonymousKey=292eef4663347ae41630fe1e5380fd77a5587659)  |
| `R-LIB-7` | Envelope detection and `_decodeContext` composition, fail closed | `R_LIB_7` | `Lib.conf` | green | [8a1d1edd](https://prover.certora.com/output/950385/8a1d1eddd41345778af248e6fa9eba50?anonymousKey=292eef4663347ae41630fe1e5380fd77a5587659)  |

### 3.1 Blocked rows

No property row of this tree is blocked.

### 3.2 Waivers

1 written waiver. A written waiver takes a claim out of scope and is not a property row: section 2's `Waived with measured evidence` row counts the property rows instead. A waiver names a repo test only by quoting that test's `it(` title and the concrete boundary it reaches (D-012), each quoted title matching exactly one `it(` title in `test/`; the others waive with an argument, a superseding rule or a section of this report.

| id | what was waived | reason | test |
|---|---|---|---|
| `WAIVED-EC-5` | Envelope payload content exactness (the bytes returned equal the bytes the client appended) | R-LIB-6/7 prove the library-level half, that the bytes `payload` and `_decodeContext` return are byte for byte `sig[len-64-lengthWord : len-64]`. What stays waived is that the region holds what the client encoded. | `test/safePolicyGuardContext.spec.ts`: "Should treat signatures not ending in the type hash as carrying no context" |

One id of the series is retired, proven rather than waived, and is not counted above.

## 4. Assumptions

| id | where | justification | discharge |
|---|---|---|---|
| `L-W0-HASH` | defined here | Executions hashing a `bytes` value longer than the conf's own bound are dropped, an assumed bound. | argument: the flag drops executions that hash past the bound, so a violation beyond it is missed, and no rule of the suite hashes an unbounded `bytes` |
| `L-W0-BITWISE` | defined here | Bitwise operations are modelled exactly with bitvector theory instead of the default over-approximation. |  |
| `L-W0-LOOP` | `conf/Lib.conf` | `loop_iter` is 3 in the shared scene: a configuration array is bounded to 3 entries where a rule carries one, and the calldata-to-memory copies of the library readers are unrolled 3 times where it does not. | argument: `optimistic_loop` is false, so a bound too low fails an unwinding assertion rather than assuming the rest away |
| `L-LIB-1` | `specs/Lib.spec` | Executions hashing a `bytes` longer than 3200 bytes are dropped, an instance of L-W0-HASH. It is inert: no rule run under it hashes a symbolic `bytes`, and `conf/Lib.conf`, which runs the two length rules, sets neither key, so their claims hold at every length. | argument: inert, so nothing rests on it here |
| `L-LIB-2` | `specs/Lib.spec` | Bitwise ops modelled exactly with bitvector theory for the AccessSelector packing rules, the Lib adoption of L-W0-BITWISE. |  |
| `L-LIB-3` | `harnesses/LibHarness.sol` | Arithmetic and reader vocabulary are pure total functions of their inputs, ABI casts and zero-padded calldata reads, not mirrors of contract logic. |  |
| `L-LIB-4` | `specs/Lib.spec` | A rule pinning selector content ties `selectorOf(d)` to `wordAt(d,0)` (an aligned `calldataload` plus a tail mask) and `byteAt(d,0)`, but not to `byteAt(d,1..3)`, so the selector's trailing three bytes are tied to the word reader, not the byte reader. |  |
| `L-EC-8` | `harnesses/SafePolicyGuardHarness.sol` | `tryCheck` is an external self-call (`msg.sender == guard`), used only to classify the engine-level revert as `AccessDenied`, `PolicyReverted` or raw. |  |

## 5. Modelling decisions

| id | decision |
|---|---|
| `D-002` | The suite pins certora-cli 8.19.1 in `certora/requirements.txt`, not the repo's pre-existing 8.6.4. |
| `D-005` | The Rules tab, equivalently `output.json` per-rule status, is the authority for a verdict, and the Job Info tab is the authority for the flags a job ran with (`Results.txt` is neither); a "Violated" log line for `rule_not_vacuous` is the probe being refuted, which is the intended result. |
| `D-007` | `$policies` is read by direct storage access `currentContract.$policies[s][a]`, not by a hook-ghost mirror; any ghost that must survive an unresolved CALL is `persistent`. |
| `D-012` | A waiver may not name a repo test unless the row quotes that test's `it(` title and the concrete boundary it reaches. |

## 7. Not proven

- Cryptography is modelled, not proven: each verdict is a free uninterpreted function, and the fixtures that exercise it in `test/` sign with the same library code the policy verifies.

No conf of this tree runs a rule for the properties below. Their rules stay in their specs as comments, except the nested-batch rule, whose spec is not in this tree.

- The nested MultiSend batch: a sub-transaction that is itself a `multiSend` delegatecall, expanded at depth 2.

## 8. How to verify any claim

```bash
# grade a job at https://prover.certora.com/output/950385/<32-hex job id>: the Rules tab lists every
# rule's verdict (green only if all are SUCCESS), the Job Info tab the flags the server ran with,
# which are the authority over conf text
npm test                                                              # 175 repo tests at this tree
certoraRun certora/conf/<name>.conf --wait_for_results all
```

The repo-test count is the runner's own summary line, `npm test` ending in `175 passing`; it excludes every `[@bench]` title through `--grep` (`package.json`), so a raw `it(` count over `test/` is higher. Count from the `status` column, not by grepping a row's prose, and treat a job as evidence only for the conf whose rule set it ran: check that the job's Rules tab lists exactly that conf's `rule` filter. The conf and its `rule` filter are the reproducible evidence either way.

The one conf under `certora/conf` has every leaf SUCCESS in the job its rows cite.

The other jobs this report cites ran confs that are not part of this tree, and each citation says so; each such job stays readable through its link.
