# REA integration qualification — 2026-11-03

Implementation scope is described in [FULL_INTEGRATION.md](FULL_INTEGRATION.md). This index keeps each result attached to its source, executable, workload and environment. The integration starts from #84 at `f9756508462ebc72e814a12f5dbba1b067edabe4` and includes the #83 publication correction.

## Completed functional gates

The [final complete matrix](../qualification/rea-full-tmpfs-20261103-r2/README.md) passed formatting, strict all-target Clippy in both feature configurations, **1,844/1,844 all-feature tests** and **1,820/1,820 no-default tests**. Nextest used one thread, zero retries, no fail-fast and explicit child umask 0022. The suites respectively skipped 39 and 27 ignored tests; doctests and ignored opt-in cases are outside those totals.

The test fixture root was explicitly `/run/user/1000/hr2` on executable tmpfs. Source inventories and the Linux source-change monitor stayed unchanged throughout:

`8faa46cb7ab44f019a2d912b97d608d73ad51bb0dacbcff42279d0513396ac3f`

This qualifies functional behavior under that storage input. It is not a disk-latency SLA or physical power-loss experiment. [PR #84 checks](https://github.com/TrillionniumFoundation/hepta-runtime/pull/84/checks) record the separate committed-head and prospective-merge GitHub results.

## Evidence by workload

| Workload | Receipt | Actual scope |
| --- | --- | --- |
| Complete Rust gates | [Final tmpfs matrix](../qualification/rea-full-tmpfs-20261103-r2/README.md) | Both feature configurations, all targets, source monitor, exact commands and logs |
| Private-state bootstrap and REA MCP | [Earlier focused state run](../qualification/rea-state-root-ci-20261103-r2/summary.json) | 256 passed under 0022; targeted filter and its exact source inventory |
| Original CI permission failure | [Paired pre-fix reproduction](../qualification/rea-state-root-umask-20261103-r1/README.md) | Same pre-fix binary, separate 022/077 fixtures |
| JADX 1.5.6 | [Final operator run](../qualification/rea-jadx-operator-umask022-20261103-r1/README.md) | Class/source observations, source marker/hash, original-job restart and cancellation |
| Ghidra 12.2 / JDK 25 | [Final operator run](../qualification/rea-ghidra-operator-umask022-20261103-r1/README.md) | Fixed ELF import inventory; complete 3,078-file installation manifest |
| APK/JAR | [Manifest scope](APPLICATION_MANIFESTS.md) | Real owned AAPT/AAPT2 and javac/jar fixtures, unchanged input hashes |
| Retained model sessions | [Session contract](MODEL_SESSIONS.md) | Actual HTTP restart after source removal; authority refusal; indexed queries and verified chunks |
| Saved web and packages | [Web contract](WEB_OBSERVATIONS.md) | Offline HAR/literal package declarations and actual MCP restart |
| Existing Python workflow regressions | [Python receipt](../qualification/rea-python-ci-20261103-r1/README.md) | 19 commands, 392 tests on its separately recorded earlier source snapshot |
| macOS preview publication | [Real helper probe](../qualification/rea-macos-atomic-publish-20261103/README.md) | Create-only publication helper on the stated actual Mac/filesystem |
| Weight transport, release | [Release comparison](../weight-runtime/BENCHMARK_CLIENTS_RELEASE_20261103.md) | 210 measurements and five semantic checks on its exact older release binary |
| Weight transport, development | [Development comparison](../weight-runtime/BENCHMARK_CLIENTS_DEV_20261103.md) | 210 measurements and five semantic checks on its exact older development binary |
| Ext4 audit-statistics budget | [Original focused failure](../qualification/rea-final-focused-20261103-r1/README.md) and [single diagnostic](../qualification/rea-audit-budget-diagnostic-20261103-r1/README.md) | Failed query retained; traced reproduction locates final store-lock acquisition |

## Engine and performance interpretation

The final actual Java runs use pinned all-feature runtime SHA-256 `290fa949b7744c85018f9f26b32fbdd1884cce1c31ff202a9f076bc3d6a89c63`. They passed original-job same-key replay, controller restart, frozen-owner observation/cancellation and unchanged-input checks. These are operator-host runs, not isolated-host or GitHub-hosted engine qualifications. Their harnesses precreate private state; separate bootstrap tests establish missing-root creation.

Observed 0022 process conditions cover the wrapper, harness, local MCP controllers and direct native workers, not the unmeasured remote SSH/systemd owner's umask. Ghidra imports with automatic analysis and decompilation disabled. Installed Java/Ghidra paths are checked but are not sealed executable closures. Scratch limits are sampled rather than hard filesystem quotas.

The development/release weight cohorts retain their exact historical source/binary bindings. In the release workload native cold-helper CPU was higher, full-MCP medians were mixed, and client lifetime RSS did not distinguish the transports. Native transport remains opt-in. Both transports used the same Python/PyTorch backend. These are workload-specific measurements, not a general Rust speedup claim.

The Python receipt predates later Rust/test corrections and is not relabeled as a final-whole-tree or GitHub run. The macOS receipt qualifies the actual preview helper, not complete macOS MCP/model-store operation, every filesystem, or physical power-loss durability.

## Ext4 query-budget boundary

On the same development host's ext4 temporary storage, the corrected existing concurrency test completed all 64 durable writes but one audit-statistics observation exhausted the unchanged three-second query budget. The separate one-attempt diagnostic, with tracing and error-construction backtrace, reproduced the refusal at final store-lock acquisition before pending/content validation.

That diagnostic does not include every earlier phase or writer-fsync/lock-holder timing. It cannot establish a unique physical cause or retroactively locate every earlier failure. The successful tmpfs matrix and later CI results do not erase the ext4 result. No production deadline, FIFO locking, original-content fence or synchronization was relaxed to obtain a pass.

## Preserved attempts and corrections

- [Full r1](../qualification/rea-full-integration-20261103-r1/README.md): real AAPT2 local ZIP padding exposed a compatibility gap; the original fixture remains unchanged.
- [Full r2](../qualification/rea-full-integration-20261103-r2/README.md): stopped to align inherited 0077 with CI's explicit 0022.
- [First state-root focused gate](../qualification/rea-state-root-ci-20261103-r1/README.md): one new test incorrectly assumed tempfile's private mode; only its setup was corrected.
- [Full r3](../qualification/rea-full-integration-20261103-r3/README.md): an original whole-workload ten-second assertion failed, followed by deliberate cancellation. Missing monitor finalization is stated explicitly.
- [Ext4 focused run](../qualification/rea-final-focused-20261103-r1/README.md): 263 of 264 passed; the original three-second query refusal is retained.
- [First tmpfs matrix](../qualification/rea-full-tmpfs-20261103-r1/README.md): an overlong fixture root hit the existing socket limit; a no-default fixture also required actual private-state initialization. The later matrix uses a short private root and one test-only state-path correction.
- Final engine receipts retain their two wrapper-preflight failures before engine execution; frozen engine harness checks were not weakened.

The actual implemented coverage is bounded. Full upstream REA parity, general Rust model inference, live browser-state replay, GPU execution and production deployment are not asserted by these receipts.
