# A43 A46/A47 results: qualified owner barrier and local lifecycle validation

**Evidence update: 2026-10-26 UTC. X230 qualification and the declared local
lifecycle cases passed; a stable performance or memory improvement is not
established.**

A new A46 attempt completed all six qualification stages for A43. A47 then
completed **10/10 correctness cases and 128/128 measured business jobs**, with
no unexpected failure, timeout, retry or unexecuted measurement. The fixed
local ABBA observed C1/C4 throughput changes of **+0.695% / +1.373%**. C4 CPU
and median business-completion latency also increased, so this result is a
bounded correctness result and a mixed performance observation.

This update follows the preserved [A43 checkpoint](a43-owner-barrier.md) and
[PR #72](https://github.com/TrillionniumFoundation/hepta-runtime/pull/72).
The earlier preformat/unqualified checkpoint, no-clear observations and
unresolved historical CI outcomes remain records of their own times. They
are not rewritten as successful executions. The [machine-readable summary](a43-a46-a47-summary.json)
contains the full tested source map, raw numerical summaries and evidence
identities used below.

## Exact source and new six-stage qualification

The input was the separate A43 experiment published at
[`e0c509858e36a14953e96eaeb596972b1afee8d3`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/e0c509858e36a14953e96eaeb596972b1afee8d3),
above the shared r07 recovery parent
[`57453f74c2967246fc961c02fbf0e6e4104103b2`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/57453f74c2967246fc961c02fbf0e6e4104103b2).
A42 and A48 source changes and results are not included.

The complete compiler-input inventory has **166 files**. Its original compact
map SHA-256 is
`80a73b1f41c886c8b7d3d08d8cc6f99356729f979a707bf943bf675592222b6f`.
The formatter changed only `jobs_owner_publication_tests.rs`; the complete
tested and final maps are identical, with compact SHA-256
`b9eaddec7cb30de7e18f2131bebeee98145e3d41e00243b13ec50f6fe01c0d9b`.
The original 165-file r07 parent retained its source bytes and file identities
before and after this attempt.
The [qualified-source object map](evidence/a43-a46-a47/qualified-git-object-map.json)
was computed by reading all 166 actual X230 qualified source bodies, verifying
their SHA-256 values against the qualification, and computing Git blob IDs.
An [independent pinned-tree comparison](evidence/a43-a46-a47/source-readback.json)
found 165 GitHub blobs and byte lengths unchanged, with only the formatted
owner-publication test changing to Git blob
`2408d39a5dca163b0509f3ad23e0be6828a1a9cd`. Thus that one source replacement
binds the published source inventory to the complete tested map; the new
documentation and evidence files are outside that source inventory. These exact three A43 file bodies are bound by
the final map:

| File under `src/mcp/runtime/` | Bytes | Tested SHA-256 |
| --- | ---: | --- |
| `jobs.rs` | 121,889 | `0defe762cc1ead6b7ca99eec4ae753e4cc55b93841a0058fdcc23e06ed4a6275` |
| `jobs_output_durability_tests.rs` | 103,909 | `1394d11f7c327ed29d999727c0e02b36781c8997cd539589bc86a51806ceb8a0` |
| `jobs_owner_publication_tests.rs` | 17,694 | `938efba52e2dcae80565cfff53378b21392e3f0dbb23bdd9c990e0b3c393fc9b` |

Qualification ran from **03:29:15.471 to 03:43:18.853 UTC** on X230 with Rust
1.95.0. All six stages were executed in this new attempt:

| Stage | Seconds | Return code |
| --- | ---: | ---: |
| Format | 1.951517 | 0 |
| Format check | 1.871327 | 0 |
| Package clean | 0.382299 | 0 |
| Strict Clippy | 40.585884 | 0 |
| All-feature tests | 492.131895 | 0 |
| Release binaries | 303.162035 | 0 |

Every stage had its own complete immediate host gate and retained the
2 GiB available-memory and disk floors. Build jobs, Tokio workers and Rust
test threads stayed at **2**, with incremental compilation disabled. Budgets
remained 1,800 s per stage, 6,600 s for the worker and 7,000 s for the outer
entry, with one 30+30 s cleanup window. All six stage rows record one
execution and a clear gate. The original worker was reaped with raw wait
status **0**, retained custody and a quiet group; it received no signal.
The durable operator job is `job1a176414f7d-96a-ad7`. [Q, E, W]

The full test log records **1,241 top-level passes, 0 failures and 23 ignored**:
**18 + 1,215 + 8**. Two nested filtered single-test child summaries are not
added again. All **seven** newly added owner-publication Rust tests have
explicit successful execution lines. Those tests exercise real file
operations and controlled failure paths with an intercepted business-launch
boundary; their exception cuts are not relabeled as process-kill tests. [T]

Both test and release compiler artifacts were strictly `fresh=false`, with
the expected source binding. The new release copy is **13,497,648 bytes**,
SHA-256 `60f6955cc77a07b5a95b24c175611a59901c7d912abfb960f7c8673e472354f7`.
The test executable SHA-256 is
`4348bdc67f54b96f1863ca76c761ec9a685e69b296638c34d2dc944316178eb6`.
These X230 results do not change an earlier GitHub Actions job conclusion. [W, L]

## Structural change and real owner-lifecycle cases

A43 retains both owner-file writes, flushes, file syncs and closes, followed
by a single sync of the already pinned job-directory descriptor before the
business `Popen`. The lifetime owner lock, surviving-name tombstones,
ambiguous-launch refusal and later output/exit publication ordering remain.

| Nominal explicit pre-business owner-publication operations | r07 | A43 |
| --- | ---: | ---: |
| Owner-file syncs | 2 | 2 |
| Owner-directory syncs | 2 | 1 |
| Extra directory opens / closes | 2 / 2 | 0 / 0 |

These are source-level operation counts for this publication boundary, not
whole-job fsync counts or a measured percentage speedup.

A47 ran from **03:44:44.354 to 03:45:10.200 UTC**, with durable operator job
`job1a1764f7317-96a-b3c`. It bound the actual qualified source and copied
artifacts, then executed the **exact extracted original Python supervisor,
launcher and status code** on Linux with isolated local synthetic effects.
The comparison itself did not drive the Rust MCP server or SSH transport.
Each normal business child really ran, emitted start/completion events,
created an exclusive durable effect and reached terminal publication and
the original supervisor's raw `wait4` completion. [L]

Both r07 and A43 passed each row below, for **10/10 cases**:

| Case, once per version | Original supervisor exit / raw wait status | Business starts / completions | Observed recovery behavior |
| --- | --- | --- | --- |
| Business exit 0 | 0 / 0 | 1 / 1 | Confirmed succeeded terminal; same key reused the result |
| Business exit 7 | 7 / 1792 | 1 / 1 | Confirmed failed terminal preserves exit 7; same key reused the result |
| SIGKILL after owner-intent close | −9 / 9 | 0 / 0 | `owner_unknown`, non-authoritative; ambiguous relaunch refused |
| SIGKILL after started close | −9 / 9 | 0 / 0 | `finalizing`, outcome unknown, terminal unconfirmed; relaunch refused |
| SIGKILL after final owner-directory sync | −9 / 9 | 0 / 0 | `finalizing`, outcome unknown, terminal unconfirmed; relaunch refused |

All direct attempts to restart an original runner were refused with exit 1.
No case produced a second business effect, and the retained files of all ten
original jobs remained unchanged after restart/status checks. The expected exit 7,
SIGKILL and refusal exits are not unexpected test failures. All statuses
retain `automatic_retry=false`. [L]

The six actual SIGKILLs targeted only the bound original fixture supervisor's
pidfd after the original close or sync operation completed. Every cut reports
zero business `Popen` calls before the kill. At the started-file-close cut,
r07 had completed one directory sync and A43 none; at the final-directory-sync
cut, the counts were two and one. All six killed originals were explicitly
reaped. These cases cover the three declared **pre-business** boundaries;
they do not test a crash after partial business execution or a machine power
loss. No partial-status parser failure was observed in these ten cases. [L]

## Complete fixed ABBA comparison

The frozen order was **r07 → A43 → A43 → r07**. Each round had C1 and C4 cells
of 16 jobs, yielding **32 measured jobs per version per concurrency**, and
128 in total. All 128 had actual start, completion, effect and confirmed
durable terminal evidence, with raw supervisor wait status 0. There were
**0 failed, 0 timed-out and 0 unexecuted measurements**, no automatic retry
and no best-round substitution. [L]

The job and client wait limits stayed at 10 s; the correctness/performance
budgets stayed at 400/300 s with 30+30 s cleanup. The same fixed identity/GO
startup gate was included in both versions' measurements. Performance cells
had no fault hooks. Measured cells start the extracted original supervisor
against already prepared private job fixtures; the launcher is exercised by
the correctness/reconciliation cases. Cell wall time includes task launch, collection and
harness stdout/stderr synchronization through original supervisor reap;
fixture preparation and post-run verification/report serialization are
outside that timer. CPU is original-supervisor raw `wait4` usage, with parent
harness CPU reported separately. Per-business self-usage also remains in the
original report. [L]

Pooled rate is 32 divided by both cells' total elapsed time. Medians use all
32 individual observations in the relevant version/concurrency pair:

| Concurrency | Metric | r07 | A43 | A43 relative change |
| --- | --- | ---: | ---: | ---: |
| C1 | Completed jobs/s | 6.787901 | 6.835106 | +0.695% |
| C1 | Whole-lifecycle supervisor wait4 CPU, s | 4.229883 | 4.186100 | -1.035% |
| C1 | Separately recorded harness CPU, s | 0.237937 | 0.228115 | -4.128% |
| C1 | Submit → business-start median, ms | 118.720 | 117.589 | -0.953% |
| C1 | Submit → business-complete median, ms | 119.925 | 118.746 | -0.983% |
| C1 | Submit → original supervisor-reap median, ms | 147.493 | 146.734 | -0.515% |
| C4 | Completed jobs/s | 15.337808 | 15.548363 | +1.373% |
| C4 | Whole-lifecycle supervisor wait4 CPU, s | 6.185351 | 6.361896 | +2.854% |
| C4 | Separately recorded harness CPU, s | 0.213494 | 0.215299 | +0.845% |
| C4 | Submit → business-start median, ms | 181.173 | 186.946 | +3.187% |
| C4 | Submit → business-complete median, ms | 182.631 | 188.244 | +3.074% |
| C4 | Submit → original supervisor-reap median, ms | 250.279 | 251.825 | +0.618% |

The two A43 cells at each concurrency had slightly higher observed throughput
than the two r07 cells. C4 nevertheless used **2.854% more wait4 CPU** and had
**3.074% higher median business-completion latency**. This single fixed ABBA
does not establish that the throughput difference is stable across runs or
that overall resource cost improved. `passed=true` and `comparison_valid=true`
mean that the declared functional cases and complete measurement inventory
passed; the harness does not define those fields as a performance-superiority
gate.

All eight original cells are retained here:

| Round | Version | Concurrency | Successful / planned | Wall, s | Jobs/s | Wait4 CPU, s | Wait4 max RSS, KiB |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 0 | r07 | C1 | 16/16 | 2.361843509 | 6.774369 | 2.100155 | 27,916 |
| 0 | r07 | C4 | 16/16 | 1.034463918 | 15.466948 | 3.122500 | 29,836 |
| 1 | a43 | C1 | 16/16 | 2.339343368 | 6.839526 | 2.086113 | 32,908 |
| 1 | a43 | C4 | 16/16 | 1.024704252 | 15.614261 | 3.191119 | 34,196 |
| 2 | a43 | C1 | 16/16 | 2.342369246 | 6.830691 | 2.099987 | 37,384 |
| 2 | a43 | C4 | 16/16 | 1.033390213 | 15.483019 | 3.170777 | 39,808 |
| 3 | r07 | C1 | 16/16 | 2.352426896 | 6.801487 | 2.129728 | 42,624 |
| 3 | r07 | C4 | 16/16 | 1.051883748 | 15.210806 | 3.062851 | 45,140 |

### RSS interpretation

The pooled maximum wait4 RSS values were **42,624 → 37,384 KiB at C1** and
**45,140 → 39,808 KiB at C4** for r07 → A43. They are retained observations,
not an attributed memory saving. Every cell's 16 jobs had the same wait4
`ru_maxrss`, and the eight cell maxima increased strictly with execution
order: 27,916, 29,836, 32,908, 34,196, 37,384, 39,808, 42,624 and 45,140 KiB.
A43 occupies the middle ABBA rounds, while r07 includes the last round.
The cause of this sequence was not isolated, and this update adds no rerun.

The per-job median bounded owner/direct-child RSS samples were
**31,360 → 31,552 KiB at C1** and **32,640 → 32,576 KiB at C4**. These finite
samples and individual wait4 high-water marks are not a continuously observed
total peak for all concurrent processes, and do not establish steady-state
memory savings. The complete original metrics are retained in the summary. [L]

## Retained evidence and claim boundary

The labels used above identify these exact original records. The summary
retains their development-tree locations, helper identities and the input
source/artifact bindings. The [lossless original-evidence archive](evidence/a43-a46-a47/original-evidence.tar.gz)
and [member manifest](evidence/a43-a46-a47/manifest.json) preserve all five captured
records byte-for-byte. They include nonsecret development paths, stat/custody
metadata, the qualification worker's own process observation, owned synthetic
fixture process samples and identifiers, and test/bootstrap Python snippets.
The content audit found no authentication credentials, private-key material,
unrelated host-process inventories or compiled executable bytes in these records.
The manifest states which referenced sidecars and other stage-log bodies are
not included; this archive is not the entire original development tree.

| Record | Bytes | SHA-256 |
| --- | ---: | --- |
| Q — qualification | 58,801 | `4d11845e1306869cb3ca13a402e00c3aa600605eda79c861cc2e98a9892a7617` |
| E — qualification entry | 295,692 | `141606221523fd4ee6588b7d304fa47caacb4c48d6601f316ff2ddee3b2c91fb` |
| W — guarded worker | 14,668 | `9d94a5878b654b4d8563721fd68a00f0285eba4d51db1bdd70235fa0b5ae1294` |
| T — complete test log | 417,603 | `a8fa1e071e03e001b8e55046887c7ba15fd4bc5b8092ff59cd1186579776a211` |
| L — A47 lifecycle report | 4,334,722 | `d0d7aa1a783a7f8cd79147362b739fdbc3cadc5f6ec23fd3c73150c08825d611` |

The A47 harness is 46,020 bytes, SHA-256
`a6672e5ebe87fd0fda7ded00b72b9f1c6213eedb952fb9be9b6a7c6e99367455`.
The A46 wrapper is 17,403 bytes, SHA-256
`7ce825966b413ab5e2d31979fbd5bb0e47a67a9105827d742ea986124610b176`.
Both source and artifact bindings remained unchanged during A47, with zero
foreign signals and zero service changes.

This is executed X230 Linux qualification plus local extracted-owner-path
evidence. It does not establish end-to-end MCP or multi-host throughput,
SSH behavior, native macOS acceptance, reboot or power-loss durability,
recovery after partial external business effects, a global exactly-once
guarantee, production adoption, deployment, merge or a global optimization
limit. The directory-barrier reduction is established structurally; a stable
performance or memory benefit remains unproven.

## Offline verification

[The archived tools and read-only recomputation helper](../../../tools/x230/a43/README.md)
verify original archive bytes, full-suite counts, declared kill/restart cases,
all 128 measured terminal receipts and the pooled arithmetic without launching
a workload. An optional checkout-source pass hashes all 166 source bodies.
This verification does not rehash executable bodies or whole-host gate sidecars,
and it does not convert record consistency into a stable performance claim.
