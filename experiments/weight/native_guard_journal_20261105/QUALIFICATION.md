# Qualification and cost ledger

All timestamps below retain UTC and America/New_York scope. The final software
binary is SHA-256
`a576b51e3fcb3d3a657e9d723bf2a9bfa579a3f6912178ee6e71a14c4ccd9854`.
This ledger concerns software behavior, not neural-model or trading improvement.

## Native subprocess interruption evidence

Each configuration executes eight actual SIGKILL/restart cases. A parent waits
for a test-only phase marker, kills its own subprocess with signal 9, waits for
termination and starts a fresh process for same-request reconciliation. These
test failpoints are compiled only in `cfg(test)` builds.

The 16 records are **eight scenarios repeated in two feature configurations**.
They are not 16 independent scientific samples or a statistical estimate of
recovery reliability.

| Boundary or failure | At interruption | Observed result after explicit retry |
| --- | --- | --- |
| After durable intent | No candidate artifact or candidate record | Outer rejection; full guard replay creates and then inversely restores an isolated artifact; 2 immutable artifacts |
| After guard, before candidate journal record | Candidate artifact exists; no candidate journal record | Outer rejection; candidate located by authenticated idempotent guard replay; inverse restored SHA equals parent; 2 artifacts |
| After candidate record, before completion | Candidate and its journal record exist; no completion | Outer rejection and verified inverse publication; 2 artifacts |
| After durable completion | Candidate and completion both exist | Full current guard revalidation; accepted on supplied synthetic rows; 1 artifact |
| Source removed after killed intent | Original content unavailable | `accepted=false`, recovery unverified, 0 model artifacts |
| Source altered after killed intent | Original content fails authentication | `accepted=false`, recovery unverified, 0 model artifacts |
| Artifact store exhausted after killed intent | Publication cannot complete | `accepted=false`, recovery unverified, 0 newly published model artifacts |
| A live process holds the journal flock | A competing process times out as busy | No model artifacts while locked; after owned lock holder is killed, a fresh process verifies recovery |

The original/inversely restored synthetic source SHA is
`45cc03791e0ca65d945385c4c4ec445cfe83ac8c0dd708d5ec8dffd4fc274670`.
No observed recovery rewrites the source. The record extracts retain each
phase's wall measurements. Per-killed-child CPU was not separately measured;
it is not reported as zero. Native test and compiler CPU are included in their
combined command accounting.

All-feature raw log SHA is
`48ce68f5114f772c3a8c5812e3636dca7d94c13ccf9748ebacc37d3f1360d3bc`;
no-default-feature raw log SHA is
`961fee06ce4e9270c24a828b8b0667336ea99d230cf262aab2900088cf8cd84b`.
The public JSON extracts contain only the `JOURNAL_*_RECEIPT` records from those
logs. Extracting records does not rerun the tests. The all-feature test execution
was 13.25 seconds; no-default test execution was 14.91 seconds. The command costs
below also include compilation and are not additional test-only costs.

## Actual MCP contract

The actual run started **2026-11-04 20:53:10.198 EST / 2026-11-05 01:53:10.198 UTC**
and finished at **20:53:29.763 EST / 01:53:29.763 UTC**. The runtime job completed
with exit 0. All 11 `tools/call` requests were executed against a private pinned
copy of the final binary.

| Request group | Calls | Required and observed result |
| --- | ---: | --- |
| Over exact L2 budget, wrong old bytes, duplicate address, bad labels | 4 | Each fresh response `isError=true`, correct original error family, first failure retained, zero candidate artifacts |
| Identical retry of each invalid request | 4 | Structured `accepted=false`, `rejected_recovery_unverified`, zero artifacts and original source unchanged |
| Valid synthetic edit | 1 | Accepted, durable completion, legacy top-level fields preserved, 1 artifact |
| Identical completed retry | 1 | Current full guard revalidation; accepted; still 1 artifact |
| Same request after owned accepted artifact is changed | 1 | Rejected, no cached acceptance, recovery not falsely claimed, parent unchanged |

This fixture's parent is SHA
`f7ede95a986b715826882dbe598d57f28cc1408b6bac2ba80858eab92bb65a05`;
its valid candidate is SHA
`c78707ec5049771ef7473b506123e6476cdab705199c659446fb0fc74af017f5`.
The driver intentionally changes only its own synthetic accepted artifact for
the final negative case. The MCP driver does not itself perform SIGKILL testing.

Inner receipt SHA:
`9d66f4265ec81942cddea2febe56aa86e8588fa4b15bf7a6d582885a7b07b08c`.
Outer whole-process receipt SHA:
`7d692fc0ca4cb54faf38c687992d755a7a85d7ffd621ac6d275c738d825e97c2`.

The independent outer `wait4` measured **19.563341260 seconds wall**,
**4.180270 seconds CPU** (3.615762 user + 0.564508 system), and a **27,352 KiB**
maximum RSS high-water field. RSS is not the sum of concurrent process memory.
This scope includes the complete Python driver, imports, final saves, shutdown
and the waited-for MCP runtime child. The inner driver wall/CPU timers are
nested within it and must not be added. The 240-second outer deadline did not
fire. A per-process 8 GiB address-space cap and 1,024-file-descriptor cap applied.
GPU execution was not requested or used.

## Shared combined build/test costs

The successful combined journal + Bellman qualification ran from
**2026-11-04 20:22:55.363 EST / 2026-11-05 01:22:55.363 UTC** through
**20:47:42.117 EST / 01:47:42.117 UTC**. All six commands completed successfully,
and all 14 qualified Rust source hashes remained unchanged after formatting.
This cost is shared by the journal and Bellman integration and must not be
charged twice when the research report combines both components.

| Command scope | Wall seconds | Child CPU seconds |
| --- | ---: | ---: |
| Format | 2.925216 | 2.888759 |
| All-feature focused tests, including compilation | 600.287097 | 1,088.235722 |
| All-feature/all-target Clippy, warnings denied | 59.386708 | 93.741066 |
| No-default focused tests, including compilation | 548.307680 | 985.258089 |
| All-feature binary build | 272.819017 | 492.611989 |
| Final format check | 2.925323 | 2.770160 |
| Sum of six command measurements | 1,486.651041 | 2,665.505785 |

The enclosing successful driver reported 1,486.703156 seconds wall; this is an
overlapping enclosing interval, not another cost to add. Compiler parallelism
explains CPU exceeding wall time. Two Cargo build jobs and one native test
thread were configured; no-default and all-feature tests were sequential.
Compiler version, Cargo lock, actual checkout identity, explicit public parent,
source snapshots and binary identity are in `combined_qualification.json`, SHA
`c2953b97c8ba515a9c2fe6f768a206274b3bced285bd82cd558f16a78ca6beab`.

## Review-aborted first implementation

The first compile began **2026-11-04 20:08:26.287 EST / 2026-11-05 01:08:26.287 UTC**.
Its cancelled state was observed by **20:15:26.239 EST / 01:15:26.239 UTC**,
approximately 419.952 seconds after start. Review had identified a fresh MCP
error-contract regression. Only that owned job was terminated. The attempt
contains zero completed tests and is marked
`REVIEW_INVALIDATED_COMPILATION_ABORTED_BEFORE_TEST_EXECUTION`.

Its completed format command cost 2.624055 seconds wall and 2.544817 seconds CPU.
The remaining compilation CPU and peak memory could not be recovered: the
runtime's transient unit had already disappeared and systemd reported the
accounting fields unset. Those costs are **unknown**, not zero, and are not
hidden in a successful-attempt average. The observation interval is not an exact
CPU measurement or exact termination instant. Original partial receipt and raw
log hashes are retained; the published log is an explicitly sanitized derivative.

## Limitations and non-claims

This qualification does not establish full repository CI, power-loss recovery,
background unattended reconciliation, safe production cutover, a complete
execution-semantic closure, live checkpoint repair, or superior model quality.
It provides a concrete bounded journal, real process interruption evidence and
an actual MCP compatibility/authentication check. Compilation, code review,
remote dispatch, transfers, agent inference and energy are outside the MCP
whole-process cost. The earlier aborted compile remains a separate cost with
unknown CPU. Separate model experiments must retain their own provenance and
must not inherit this software PASS as a capability improvement.
