# Candidate B2 observations — 2026-11-06, 679ccf

## Decision and immutable candidate

Full REA replacement, complete cost benefit and production qualification remain **HOLD / NO_GO**.
This document records finite observations for one actual source/build/runtime tuple.
It does not transfer these passes to the subsequent combined source.

| Binding | Exact identity |
| --- | --- |
| Source commit | `6c224e4d913dd596e44fb936e22b447531f8962b` |
| Git tree | `5d75e3bfdcaa20b43b4f170288b4221ceb9040ad` |
| Runtime | 51,493,184 bytes; SHA-256 `170117339fdeeb6632a6df545fbfba4fce8254f41dd763b55df6b38cee57858f` |
| Binding record | 5,046 bytes; SHA-256 `c5e8d129b2acb434a5de3d4e0510635b07c3b7693e241b98d9935bae1fcc58fa` |
| Build configuration | Rust 1.95.0; all features; dev optimization level 1; debug assertions and overflow checks enabled; debuginfo 0 |
| Matrix summary | 55,971 bytes; SHA-256 `568f5d4d156762f667aa340478e8e471be72c3eaee5c3e802e1459c57915ac33` |
| Complete selected source inventory | SHA-256 `078c75f489768ce4d6a7528ada587975ce42cf4fb4ab20cc5d4f1632076bcf07` |

The original target remains the authenticated `rea-agents@6.8.0` npm archive,
SHA-256 `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`.
Its 229 public operations in 18 families are the coverage denominator. The
current ledger still has zero completely qualified replacements; checkpoints
are native extensions. See the [P0–P5 integration record](P0P5_CONTINUATION_20261106_679CCF.md)
and [compatibility ledger](compatibility/REA_6_8_0_LEDGER.json).

The original B2 evidence root is
`/home/qian-qi/work/hepta-rea-p0p5-679ccf-20261105-evidence/candidate-b-r2`.
The fresh public differential root is
`/home/qian-qi/work/hepta-rea-p0p5-679ccf-20261105-p1-checkpoint-evidence`.
Paths below identify retained original receipts, rather than a newly generated
substitute for those receipts.

## Fresh regression and public comparison results

| Observation | Actual result | Original receipt |
| --- | --- | --- |
| Full all-feature Rust matrix | 2,326 passed; 40 skipped | B2 `matrix-r1/summary.json` |
| Full no-default-feature Rust matrix | 2,296 passed; 28 skipped | Same matrix summary |
| Formatting and both strict Clippy configurations | Passed | Same nine-stage matrix |
| Four separately selected original corpus gates | One actual test passed per gate; all four complete | B2 `run-summary.json`, SHA-256 `8514a03abd84ea41f33ba705acdf90f3148a49401edbc1ae67beb77f0aeb4e37` |
| Python regression | 20/20 command groups, 565/565 top-level tests; no skips or errors | B2 `python-regression-r1/summary.json`, SHA-256 `cdd9ce4d9435ccea6eb9dd53a3fbff6060a2165d8b6e4cc9f4cabb1370b85357` |
| 116-input public MCP replay | 116/116 parsed responses, Evidence states and complete response objects; **0/116 raw transport frames** | `candidate-b2-json116-r1/comparison-summary.json`, SHA-256 `9b564de78f2de46e29d038eb8d5b8347c33649bbe6cfcc034fd22c09e155d8b6` |
| Strengthened 118-input profile | 118/118; all 38 JSON error bodies match complete member order and exact UTF-8; all four plain SDK exceptions match | `candidate-b2-imports-r1/summary.json`, SHA-256 `28de1d2f391ed1014b5adcf1f29aeb5c5727cede73f646aff4358aeb63df9c5f` |
| Strengthened 22-input profile | **20/22**; producer body-overflow and imported bundle-overflow have equal parsed values but different error member order and exact text | Same imports summary and retained raw audit |
| JavaScript observations | Seven actual Node, original REA and native observations agree; seven raw worker executions complete | `candidate-b2-javascript-r1/summary.json`, SHA-256 `024e081e1b2b2cac1290572c0a7c1095524c4d27a2295321e62a9f8378de60ec` |
| Two ignored GNU backend tests, separately selected | Requested = attempted = executed = passed = 2 | `candidate-b2-gnu-libtests-r1/qualification.json`, SHA-256 `32eb0337e7e9c9730c9bd2d3be8b5a916568bf6f647e8b245a0510a9abdb033b` |

The four original corpus gates and the two GNU backend tests used the actual
source-bound library test artifact, SHA-256
`00c21dbb4c7015c73490da3575b73a186429f4c9c33ac2044a7a1790a362f44e`.
The compiler reported the selected artifacts as fresh. No forced rebuild is
claimed. Separate selected tests are not added again to the full-matrix totals.

The matrix took 2,516.269773006439 seconds end to end. That is an observed
qualification duration, **not a cost comparison or a release performance result**.
Every skip remains a skip. The 22-input failures block cost execution even
though the 118-input profile passes.

## Six actual provider profiles

All six finite profiles were re-executed against the B2 runtime. A separate
read-only consumer preserved the original failed outer receipt and completed
the missing validation of existing results.

| Profile | Actual finite checks |
| --- | --- |
| Ghidra | 11 |
| JADX | 8 |
| Chrome | 14, including actual process-environment negative controls |
| APK three-way oracle | 19 positive, one forged and four malformed inputs; 2,398 original package files checked |
| APK public MCP | Six gates and two clean controller closures |
| Actual AAPT2/signing/worker production | Fourteen original commands and fourteen checks: twelve zero exits and two expected refusal exits |

The first provider outer process failed because the external consumer template
omitted `COMMAND_NAMES`, `COMMAND_BUDGETS` and `MISSING`. The sixth helper had
already finished all fourteen commands. The corrected independent consumer
restored only the exact constants from the previously reviewed source and read
the same original reports, command receipts, byte streams, inventories and input
identities. It launched no new payload and retried no original command.

The composed receipt is B2 `provider-gates-b-composed-r2.json`, 9,946 bytes,
SHA-256 `414b060897106e296dbe7db0943c842342d85ca8e1a856f094d2b2ec98bee857`.
Its independent consumer outer is
`provider-gates-b-consume-r2-outer.json`, SHA-256
`1d967507758c4fff315907a6463d8448ace54f1882182cf19e7ffcfc62bef000`.
The original R1 outer remains failed with exit code 1.

These results do not qualify the later Ghidra instruction-window implementation,
licensed IDA/Hopper integrations, native GDB/LLDB adapters, ADB, Frida, or device
execution.

## GNU persistent public MCP lifecycle

The independently consumed GNU profile passed all twelve finite checks with:

- Four actual readelf jobs: headers, sections, symbols and relocations.
- One separately compiled synthetic backend for cancellation and recovery.
- Three private controllers, including two intentional SIGKILL restarts.
- Five complete, durable, confirmed original terminal records and exact paged byte streams.
- Same-key reuse, changed-operation/profile refusal, observation-only behavior,
  frozen admission, cancellation and stored-result recovery.
- Zero executions of the authored object being inspected.

The independent receipt is B2 `gnu-profile-b-r2-independent.json`, 3,708 bytes,
SHA-256 `d13e20f0dc4d70b2bb2f80b58e776bc2c5e9fbae7f2e5cb00f32c037e5cb533e`.
Its actual consumer job `1a1af8c8db6-fc05-6992` exited 0 with complete, durable,
confirmed output. Its literal original outer is
`gnu-profile-b-r2-independent-outer.json`.

The earlier profile failed when its test harness treated a kernel memfd label
as a disk path. Its four GNU jobs had completed; its controlled cancellation
task was cancelled and both controllers were reaped. The replacement checks the
owned PID/start identity and pidfd, reads the process's executable descriptor,
and verifies exact bytes, size, seals and descriptor identity. A separate actual
owned-process probe also proved the former failure and refusal of wrong hash,
size and start identity.

The final consumer revision checks the actual original `/usr/bin/python3`
invocation. The older consumer had assumed `/usr/bin/python3.12`. The original
manifest and execution records were retained unchanged. Interpreter binary
identity and equivalence of those two pathnames were not attested.

This is an operator-host profile with job network access enabled and no
command-sandbox claim. Notes were not executed. The synthetic backend is
lifecycle evidence, not an additional GNU semantic comparison.

## Recovery, upgrade and cost boundaries

The fresh desktop+x230 recovery R2 runner completed its original thirteen
phases using two original jobs and three private controllers. Both original
jobs reached cancelled terminals with graceful exit code 0 and complete durable
logs. Repeated cold reads retained the original nonce, terminal and bytes.
The independent final receipt is B2 `multihost-recovery-b-r2-final.json`,
9,545 bytes, SHA-256
`922f0511add8c6783054172a149a25c01bb49771a42b1198cf9d9ea18feb2347`.
It verified 45 original RPC pairs and cleanup of all three private controllers.
This finite profile excludes host reboot, network partition, storage failure,
x230 controller restart and engine/device workloads.

The first recovery attempt remains failed: private authority directories were
created without the required owner records, so the first desktop request was
refused before a job ID or launch intent existed. The private job/state
directories on both hosts were observed empty. The revision initializes only
new private authority files, keeps the required fence enabled, and verifies
configuration, ownership, permissions and before/after identities.

The A → B → A → B checkpoint profile passed all four actual phases and
independent consumption. B2 `checkpoint-upgrade-r4-independent-r1/qualification.json`
is 11,634 bytes, SHA-256
`faf1454b7d4823532d8290639d27144f3494b676e0f8c7ed24f7062b8403f4a9`.
The consumer checked 222 retained files, seventeen raw HTTP tool calls, all four
original server SIGKILL/wait/pidfd/group terminals, and checkpoint manifest,
bundle and retention bytes/inodes. The old version rolled back without changing
the checkpoint. The final new process began empty, listed the one checkpoint,
and explicitly resumed the same five Evidence records and three Unknown revisions
after three original input paths were deleted. Exact CallToolResult values,
public text and member order remained required throughout.

The complete Hepta tool catalog was 100 entries for A and 103 for B; the 35
native REA interfaces are a different denominator. A rollback had one refused
initialization readiness connection before becoming ready, with zero tool or
logical-phase retries. The scope is Linux, private authenticated HTTP and
checkpoint-v1 for the recorded c25 → 6c → c25 → 6c pair. It does not establish
outer JSON-RPC wire equivalence, general upgrade/rollback, release or production
qualification.

Earlier failed attempts remain retained: an incorrect assumption that HTTP text
and structured channels share member order, an external entrypoint location
guard refusal, and an imported optional-field order expectation built from
fixture construction order. The final expected record envelopes use the actual
original seventeen-field public frame. Actual responses were never reordered;
no cross-version comparison requirement was relaxed.

Whole-lifecycle CPU, memory and wall-time accounting has a separate finite
calibration with a late descendant. The current configured cgroups do not
expose attributable `io.stat`; wait4 block operations are not I/O byte counts.
No real cost benchmark has run. B2's two public error-text differences, the
remaining accounting scope, and the dev build configuration prohibit a complete
cost-benefit claim.

## Subsequent combined source is a new candidate

Three independently reviewed changes were combined without conflicts at code
commit `d0b4f86386b5b7e04a674c34dbbc1704513f6c52`, tree
`6fea63516f8b295e36645d439d4d4acc8f8bf32e`. The 29 changed paths are the exact
content/mode union of their original commits.

| Change | Original commit | Actual validation boundary |
| --- | --- | --- |
| Source Map content/UTF-16 position support | `f4995f314226c8c2bd3abb84e50a7ccc7ad61e92` | 23 actual focused native tests passed; 133 original point cases retain 121 exact admitted comparisons, six common refusals and six explicit surrogate gaps |
| Ghidra instruction window | `fb864979e819c5d3706e7068ffa92010da168092` | Source and schema preparation reviewed; twelve added Rust tests and actual engine behavior remain unexecuted |
| Two observed overflow error orders | `2cc04da0f397d1a57cb87ed2b83ff27519f5bef5` | Two exact original/native frame fixtures retained; five added Rust tests and fresh public replay remain unexecuted |

The overflow formatter is reached only from the actual overflow factory. It
requires the complete observed field sets, limits, message, remediation and
retained-ID relationship. Unknown, missing or extra fields preserve the complete
previous projection. It does not delete data to obtain an equality result.

These commits and later runner/documentation changes require a newly frozen
source tuple, compiler artifacts, runtime and applicable external observations.
The B2 results above cannot qualify that new binary.
