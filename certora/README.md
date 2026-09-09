# Formal verification: Policy Engine

Certora/CVL suite for `contracts/SafePolicyGuard.sol`, `contracts/core/PolicyEngine.sol` and the libraries and policies the report's section 1 lists; every harness mirrors the deployed code, so `git diff main -- contracts/` is empty in this tree.

## Results

9 of 9 property rows are green. The table with every row's rule, conf, status and job is in `certora/VERIFICATION_REPORT.md`.

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

Grade a run in the Certora web UI: the Rules tab is the authority for a verdict, listing every rule's verdict, and the conf is green only when every leaf there is SUCCESS; the Job Info tab is the authority for the flags the run actually used, which a conf only requests. `Results.txt` is neither: for `satisfy` rules its `FAIL:`/`Violated:` wording is inverted and healthy sanity sub-rules print `Violated`.

## Layout

| Path | Holds |
|---|---|
| `certora/specs/` | 1 CVL spec. |
| `certora/conf/` | 2 run configurations, one or more per spec. A spec is split across confs where one run does not converge or needs a different flag. |
| `certora/harnesses/` | 2 files, 2 contracts: `LibHarness`, `SafePolicyGuardHarness`. |
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
| Compiler | Every conf pins `solc-0.8.30`, `solc_via_ir: true`, `solc_evm_version: cancun` and `solc_optimize: 10000000`, matching `hardhat.config.ts`, and any divergence proves something about different bytecode. |
| Budget | No conf raises `smt_timeout`: all 2 confs run at the certora-cli default of 300 seconds per SMT query, a rule over budget reporting TIMEOUT and never green. `rule_sanity: basic` is set in every conf, and a `SANITY_FAIL` leaf is advisory: the rule's own assert still reports its verdict and the report dispositions each one. |

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

## Evidence rules

- Job ids live in the report's property table, one per row, as links under `https://prover.certora.com/output/950385/` that carry a share key (`anonymousKey`) and open without a Certora account; the conf, with its `rule` filter where it has one, is the reproducible evidence.
- The `discharge` column of a unit table shows a job id as its first eight hex characters, each a link to the job with its share key, like the links of the report's property and assumption tables.
- Regrade any job in the web UI: open its URL and check the Rules tab, where every rule must show SUCCESS.
- Re-run a claim with `certoraRun certora/conf/<X>.conf --wait_for_results all`, then grade it the same way.
- Waivers name their test or their reason in the report's section 3.2; run the repo tests with `npm test`.

## Not in this tree

- A conf for the properties the report's section 7 lists as having no rule run, and the spec of the nested-batch rule. The other rules stay in their specs as comments.
