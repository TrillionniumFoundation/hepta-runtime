# R35: qualified allocation candidate; original CI and performance acceptance pending

R35 starts from accepted R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`. It moves the legacy direct-read JSON allocation into the branch that consumes it and transfers ownership of the observation command instead of cloning it. Exactly three compiler input paths differ from R24. No cancellation reserve, concurrency threshold, transport authority check, cleanup rule, or acceptance threshold was changed.

## Actual first qualification

The original first qualification job `1a1af619097-fc05-6813` completed successfully. All eight original stages returned zero: format, fmt-check, harness tests, Clippy, test build, isolated tests, isolated-test audit, and release. Native terminal publication and both output streams are complete: 1,109 stdout bytes and zero stderr bytes. No automatic retry occurred.

| Result | Actual count |
|---|---:|
| Passed | 1,645 |
| Failed | 0 |
| Ignored | 34 |
| Selected | 1,679 |
| Retries | 0 |

The complete tested source map contains 220 compiler inputs, including 17 embedded Python files; all 19 original harness files are unchanged. The map SHA-256 is `87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313`. Rustfmt changed the pool execution-chain layout and the existing test fixture closure layout, including an optional trailing comma. This commit carries the actual formatted source that was tested; the original candidate package is preserved unchanged.

| Retained program | Bytes | SHA-256 |
|---|---:|---|
| hepta-runtime | 14,373,416 | `416662310fef6ca6d68907658bb1b882584d1e431bf4ed4263f62984495d8251` |
| hepta-runtime-jobctl | 739,016 | `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62` |
| native_process_driver | 2,896,240 | `31d90610e618041faa5f562c029e496afc39c603fbe3a51d740e4eec3aacd54e` |

Original qualification report, preparation, map, summary, full audit, raw native terminal/read and postflight records are in [qualification-originals-01](qualification-originals-01/). The actual postflight job `1a1af7ee913-fc05-690e` succeeded after rechecking all 220 input paths, all 19 harnesses, and all three retained ELF files. It also preserved the 14 small installation originals and the two original qualification native records without overwriting existing evidence. The sealed input changes only the previously reviewed template's payload assignment.

## Measurement preparation and current limits

The original parent/normal-observation/lifecycle tools were installed once by job `1a1af801235-fc05-6921`, with complete successful native output and zero workloads started. The installation receipt and actual generated examples are preserved in [parent-installed-originals-01](parent-installed-originals-01/). Exact original CI tools are being sealed from this completed qualification; no CI or performance result is claimed in this checkpoint.

Qualification success is not performance acceptance. The six-host normal ABBA, boundary/recovery checks, and gated lifecycle ABBA have not run for R35. The original C1/C8/C16 throughput, p95, controller-CPU and RSS thresholds remain unchanged. R24 remains the accepted runtime. R34 was rejected on its first C8 throughput gate and is not a source baseline for this candidate.

## Preserved provenance

The first large-inline installation attempt has an unresolved `launch_unknown` result, with original error texts and a separate read-only reconciliation. It has no invented native terminal status or exit code. A separate bounded staged upload and installer succeeded before the original qualification was launched once. See [installation-originals-01](installation-originals-01/) and the earlier sealed preparation records. These installation events are not test retries.

The original immutable candidate input, patch and history-overlap review remain available alongside the actual tested source. In particular, the legacy-read allocation change overlaps the earlier R26 candidate; R35 does not claim it as a newly discovered optimization.

The separate [R24 phase-cost diagnostic plan](../r24-headroom-review/diagnostic-plan-01/README.md) is a static proposal. It contains no measurement result or accepted runtime change. Its large-stdin appendix does not attribute the unresolved installation event to an argv limit.
