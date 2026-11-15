# R35: rejected by original normal lifecycle cancellation-throughput gate

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

The original parent/normal-observation/lifecycle tools were installed once by job `1a1af801235-fc05-6921`, with complete successful native output and zero workloads started. The installation receipt and actual generated examples are preserved in [parent-installed-originals-01](parent-installed-originals-01/). The first exact original Rust CI job `1a1af88c330-fc05-696f` completed on x230 with all six original stages returning zero. Its complete 1,541/0-byte native streams, full 1,679-case inventory and original independent audit agree: 1,645 plain PASS, zero failed, 34 ignored and zero retries. All owned children and process groups were closed; source inputs stayed unchanged. This is the original workflow-equivalent Rust CI executed on x230; hosted GitHub Actions execution is not claimed.

Qualification success is not performance acceptance. The first six-host normal ABBA plus boundary/recovery campaign completed under the unchanged Mac holder job `1a1af9bb312-fc05-6a14`. All seven original parent stages returned zero, all observation nonregression gates passed, and no automatic retry occurred. The original 90-second quiet period, fixed ABBA order, C1/C8/C16 workload and acceptance gates were preserved. The holder closed its foreground process and reaped its owned SSH agent; both its socket and owned directory were absent afterward. The normal lifecycle materializer and holder have not been invoked; they remain gated on the actual normal-observation result. The original C1/C8/C16 throughput, p95, controller-CPU and RSS thresholds remain unchanged. R24 remains the accepted runtime. R34 was rejected on its first C8 throughput gate and is not a source baseline for this candidate.

## Preserved provenance

The first large-inline installation attempt has an unresolved `launch_unknown` result, with original error texts and a separate read-only reconciliation. It has no invented native terminal status or exit code. A separate bounded staged upload and installer succeeded before the original qualification was launched once. See [installation-originals-01](installation-originals-01/) and the earlier sealed preparation records. These installation events are not test retries.

The original immutable candidate input, patch and history-overlap review remain available alongside the actual tested source. In particular, the legacy-read allocation change overlaps the earlier R26 candidate; R35 does not claim it as a newly discovered optimization.

The separate [R24 phase-cost diagnostic plan](../r24-headroom-review/diagnostic-plan-01/README.md) is a static proposal. It contains no measurement result or accepted runtime change. Its large-stdin appendix does not attribute the unresolved installation event to an argv limit.

## Complete original evidence archives

Both archives were collected once after their original jobs closed. Each transferred byte range was bound to its immutable file version and digest, the complete file hash was checked, and local verification checked all members without extracting files. No original test, benchmark or auditor was rerun for collection.

| Evidence | Archive bytes | Selected files / bytes | SHA-256 |
|---|---:|---|---|
| First qualification | 2,676,768 | 3,631 / 11,907,283 | `a40f7d42c4c17bad59e81f07736ba6999f66d35973ce8c62c9655b9d88476b3a` |
| First exact CI | 317,683 | 36 / 2,042,421 | `f5f569ccd51d3f2f8cdb11aee115967f0df367a04cf0fd9f50c21a8b5d86d42f` |

The complete artifacts and original collection receipts are in [qualification-results-01](qualification-results-01/) and [exact-ci-results-01](exact-ci-results-01/). Exact-CI collection has zero receipt-binding errors. Full plans, reports, original nextest output, selected tool inputs and both original native streams remain available. The qualification archive records the excluded historical large-stdin source identity and prior cache-owner references explicitly; those original bodies remain in their separately published provenance records.

The create-only Mac launcher installation succeeded once as `1a1af93b3b9-fc05-69ca`; all five package members matched their sealed identities. Observation inputs were materialized once as `1a1af949683-fc05-69d5`, with zero workloads started. Actual input SHA-256 is `eec0348217f6c679d1f965004f1bd8ecded2886fc1c654d45a9ad6ea700391e4`. The launcher bundle retains its at-creation CI-pending snapshot; a separate original-receipt closure note binds the completed CI without rewriting that history.

## First normal-observation result

This finite campaign passes the original nonregression gates. It does not establish a consistent throughput improvement, a statistical confidence claim, or final candidate adoption. R24 remains accepted. The subsequent first normal lifecycle ABBA rejected R35, as recorded below.

| Concurrency | R24 calls/s | R35 calls/s | Throughput change | P95 change | Controller CPU/call change | P99 change (diagnostic) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 7.729945 | 7.845292 | +1.49% | +1.98% | +1.27% | +13.07% |
| 8 | 54.868183 | 53.410216 | -2.66% | +2.80% | +0.54% | +2.07% |
| 16 | 55.257313 | 55.413634 | +0.28% | -0.83% | +1.19% | -6.04% |

Controller sampled peak RSS was **18,908 KiB for R24 and 18,592 KiB for R35**, a reduction of 316 KiB. The original candidate ceiling was 19,420 KiB. RSS is a 100 ms sampled process peak, not an exact allocation bound or total cluster memory. Controller CPU excludes the harness and remote processes.

The boundary test reported 32 successful admissions, 32 capacity refusals and zero other errors; drain and recovery passed. The original six-host cancellation/recovery correctness canary passed. It is separate from the normal lifecycle ABBA result recorded below. The independent compiler monitor validated 301 observations at 1 Hz with zero validation errors; this sampling does not rule out activity between observations.

The completed original report, gate summary, independent native audit, compiler-monitor audit, original Mac holder report and complete raw native terminal/read are preserved in [observation-originals-01](observation-originals-01/). The first workflow ran from 2026-11-06 06:46:19 UTC to 06:51:19 UTC. Complete bounded observation collection and postflight precede the normal lifecycle materialization.

### Preparation executor interruption

The local preparation executor became unavailable after the completed observation result had been retrieved. It did not restart the measurement or alter the measured source. Already published source, qualification, CI and launcher packages remain immutable; the original observation files remain on x230 and Mac, and these original receipt bytes are now published directly. Any unfinished preparation recovery is recorded explicitly, with original-byte identity required before calling a recovered artifact identical.

## Complete original observation archive and lifecycle launch

The first observation evidence collector completed once with zero receipt-binding errors. Its complete `observation-evidence-01.tar.gz` is **3,077,414 bytes**, SHA-256 `941e03e20ddcab8baa6049b806e2b447242055abb2f72eefb2a6ed87a9a74b8c`. It retains **4,172 files / 31,238,250 selected bytes**. All 47 immutable transfer chunks and the full archive hash were verified. The same collector verified every selected member locally without extracting files, executing archived programs, or rerunning auditors or benchmarks.

The archive, manifest, compact result and original archive terminal/read records are in [observation-originals-01](observation-originals-01/). Eight nonempty Mac holder log bodies are included separately; twelve empty logs are represented by their original report identities. The observation archive itself records that Mac log bodies are outside that archive. Its first historical postflight and archive snapshot correctly show normal lifecycle not yet started at their capture time; they are preserved unchanged.

The postflight source was recovered with its original reviewed identity. The observation collector and sealer are explicitly recorded as new recovery revisions after the preparation executor interruption. Their static review, actual binding, deployment and zero-extraction verification records are included; no missing prior review body has been reconstructed as an original.

The original lifecycle materializer completed once (`1a1afb8c456-fc05-6b1d`) with zero workloads or remote effects. The original normal lifecycle ABBA holder was then started once on Mac at **2026-11-06 07:31:24 UTC**, job `1a1afc4fb4a-fc05-6b7f`. Its input binds the same qualified R35 binaries and complete source inventory. The first attempt completed at **2026-11-06 07:33:52 UTC** with native exit 1 and complete durable logs (296 stdout bytes, zero stderr). During measurement the coordinator made no other target-host queries, file transfers, or builds and only polled this original holder. **R24 remains the accepted release.**

## First normal lifecycle result: rejected

The original normal lifecycle ABBA completed four rounds and all four independent correctness audits. The original fourteen lifecycle tool tests passed without failures, skips, or retries. The original performance analyzer then returned failure because the **required concurrent live-cancellation throughput ratio was 0.9293926468, below the unchanged 0.95 minimum**. R35 is therefore **not adopted**. The result will not be replaced by a rerun or by a less demanding gate.

| Required comparison | R24 RPC/s | R35 RPC/s | Throughput change | P95 change | Result |
|---|---:|---:|---:|---:|---|
| All operations (60 calls per arm) | 6.614869 | 7.744640 | +17.08% | -12.31% | Pass |
| Launch (12 calls per arm) | 4.746698 | 7.590582 | +59.91% | -47.21% | Pass |
| Concurrent live cancel (12 calls per arm) | 6.879689 | 6.393932 | **-7.06%** | +6.85% | **Reject: throughput** |

The aggregate improvement does not override the required cancellation gate. Controller CPU for the required groups passed the original declared tick-tolerance tests. The additional, non-adoption-required `cancel_after_terminal` CPU comparison failed (0.07 s versus a 0.06 s allowed value); it is retained in the original gates file. Sampled controller peak RSS was 17,588 KiB for R24 and 17,416 KiB for R35, within the unchanged 18,100 KiB limit. This finite C6 ABBA supports descriptive comparison only, not statistical significance, saturation capacity, or whole-cluster CPU claims.

The parent returned failure after the original analyzer rejected the performance result. Both parent stages and every ABBA-owned stage were waited and reaped, with owned process groups absent. The Mac holder reaped its owned agent and removed its socket and directory. The independent compiler monitor validated 149 samples with no errors; this is a sampled check and does not prove absence between observations. Candidate and baseline source inputs remained unchanged and measurement attribution remained valid.

The complete original parent, ABBA report, round index, summary, gates, four round audits, tool tests, monitor audit, Mac holder report and native terminal/read are in [lifecycle-originals-01](lifecycle-originals-01/). The complete lifecycle raw-log archive is now retained and verified as described below; it preserves this rejection. Further phase-cost diagnostic work starts from accepted R24 and is separate from this rejected candidate.

## Complete lifecycle evidence closure

The original lifecycle collector ran once as job `1a1afd67423-fc05-6c13`, succeeded with native exit 0, and retained 872 stdout bytes and zero stderr bytes. Its success means evidence collection succeeded; the original lifecycle workflow and adoption gate remain false.

The complete [lifecycle archive](lifecycle-originals-01/lifecycle-evidence-01.tar.gz) is **1,269,721 bytes**, SHA-256 `b5eaadc62a6121e20cd6047f90d506c95374f8068cf77a03218d60484102df28`. It retains **1,663 files / 12,029,141 selected bytes**, including all three lifecycle result trees, four raw round reports, four original independent audits, request/response and resource logs, the original monitor ledger, and bound prerequisites. All 20 immutable chunks and the whole archive were verified; the same collector then verified every member locally with zero extraction and zero receipt-binding errors.

All four rounds and eight standard shutdowns are present and clean. There are no unavailable core originals, original JSON parse errors, or missing standard shutdown records. The four original audits sum to **360 native calls, 144 independent SSH calls, 24 new starts, 48 same-key lookups, 48 cancellations, and zero automatic RPC retries**. These counts include correctness and recovery operations beyond the 120 calls used by the aggregate lifecycle performance comparison; they must not be used as that comparison's denominator. Intentional controller crashes are retained separately from normal shutdowns.

The original Mac holder report retains all log identities. Eight nonempty Mac log bodies were also retrieved, hashed and published separately in [mac-holder-logs](lifecycle-originals-01/mac-holder-logs/); twelve zero-byte log identities remain in the original report. The x230 lifecycle archive explicitly states that it does not contain these full Mac log bodies. No raw original report or native JSON was parsed and reserialized for publication, and no original benchmark or auditor was rerun.

R35's source, qualification, exact CI, observation and normal-lifecycle evidence are now published with their original outcomes. **The cancellation-throughput rejection remains final for this first attempt; R35 is not promoted and accepted R24 is unchanged.** The D1 phase-cost experiment is a separate diagnostic based on R24.
