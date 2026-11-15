# R29 actual rejected candidate and complete companion evidence

**R29 is rejected. Production source remains accepted R24.** Full qualification, the exact external Rust CI, all 18 Python commands and OBS passed. The normal six-host lifecycle ABBA failed the required live-cancel throughput gate: B/A **0.9235250428578928 < 0.95**. Four canaries and four independent correctness audits passed; the performance rejection remains the original failed/1 native result. Cancellation saturation was not submitted, and the performance capture observed its directory absent.

The [detailed report](../../../../docs/X230_OPTIMIZATION_20261105_R29.md), [actual facts](reviews/rejected-facts-01.json) and [blocker ledger](reviews/remaining-blockers-03.json) distinguish completed checks from open acceptance and publication work. No unchanged R29 workload is rerun and no threshold is relaxed.

## Results to read first

| Scope | Actual result | Original evidence |
|---|---|---|
| Qualification | 8 stages returned 0; 1,655 passed, 0 failed, 34 ignored, 1,689 selected, 0 retries | [report](receipts/qualification-report.json), [summary](receipts/isolated-summary.json), [source map](receipts/qualified-source-map.json) |
| Exact external Rust CI | 6 stages returned 0; 1,655 plain PASS/34 ignored/0 retries | [report](receipts/rust-report.json), [native terminal](receipts/rust-native.json) |
| Python CI | All 18 commands returned 0; 85 dependency inputs and source bindings unchanged | [outer](receipts/python-outer.json), [runner](receipts/python-report.json) |
| OBS | C1, C8 and C16 throughput/p95/CPU gates and combined RSS gate passed | [parent](receipts/observation-parent-01.json), [summary](receipts/observation-summary-01.json) |
| Normal lifecycle | Required live-cancel RPS 6.521274284 → 6.022560113; p95 and CPU/RSS conditions passed | [gates](receipts/lifecycle-original-gates-01.json), [ABBA parent](receipts/lifecycle-normal-ABBA-01.json), [native failed/1](receipts/lifecycle-native-terminal-01.json) |
| Saturation | Unsubmitted after normal performance rejection; directory absent at capture | [performance capture](receipts/performance-capture-report-01.json), manifest inside complete performance archive |

OBS throughput ratios were C1 1.087227224, C8 0.992955471 and C16 1.015217855. Observation sampled controller RSS decreased 1,504 KiB; normal-lifecycle sampled controller RSS decreased 1,364 KiB. Those results do not cancel the required live-cancel throughput failure. The descriptive `same_key_after_cancel` throughput/p95 comparison also regressed and is retained in the full gate report; it was not an adoption-required group under the frozen protocol.

Both actual compiler-monitor ledgers passed their independent validator: 283 OBS samples and 150 lifecycle samples, no missed scheduled slots or observed compiler records, joined threads and cost below the original 0.02-core limit. These facts have the original 1 Hz sampling scope. All original stage and Mac owned-process cleanup fields remain available with their source and original logs.

## Exact source evidence

The [candidate patch](candidate/accepted-R24-to-actual-qualified-R29.patch) and [source index](receipts/qualified-source-index-01.json) preserve the actual qualified candidate separately from production. There are eight differences from accepted R24: seven modified files and the added direct-cancellation test file, with 213 unchanged compiler inputs. Only two files are new relative to R28: the shared router implementation and its tests. The shared raw router does not cache dynamic visibility or a particular `OctofsServer` instance.

The candidate bodies are under [candidate/qualified-source/src/mcp](candidate/qualified-source/src/mcp/). `server_tests.rs` is the real formatted 50,094-byte output, SHA256 `2baea2dc0a15db50fc70a3648f002706fb3a74ca30b3f0c6923a749f0eba1213`. Production `src` is unchanged at accepted tree `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`. Optional later pidfd/capacity proposals are not included in this candidate's map or result.

## Three complete original archives

| Archive | Bytes | Members | Independent QA |
|---|---:|---:|---|
| [qualification-ci-01.tar.xz](evidence/qualification-ci-01.tar.xz) | 1,942,216 | 3,820 | [Passed](reviews/qualification-CI-full-verification-01.json) |
| [performance-01.tar.xz](evidence/performance-01.tar.xz) | 2,183,968 | 5,740 | [Passed](reviews/performance-full-verification-01.json) |
| [formal-holders-01.tar.gz](evidence/formal-holders-01.tar.gz) | 84,013 | 59 | [Passed](reviews/Mac-full-verification-01.json) |

Archive byte hashes and actual content-addressed Git blob IDs are in [actual facts](reviews/rejected-facts-01.json). A successful Git blob creation is not a branch update; the publication's actual tree/ref receipts establish that separately.

The QC archive contains all qualified source, retained ELF identities, full qualification and per-case logs, exact Rust inventory/streams and all Python gate streams. The performance archive contains the complete OBS and normal-lifecycle raw evidence, all four round audits, frozen gate policy, monitor sources/ledgers and output-absence witness. The Mac archive contains both original 22-file holder directories and the exact terminal/read DTOs. The consumers verify all members and compressed-stream integrity without executing archived code.

The frozen local consumers and helpers are retained in [sources/qualification-CI](sources/qualification-CI/), [sources/performance](sources/performance/) and [sources/Mac-companion](sources/Mac-companion/). Their original invocation, stdout, stderr and exit receipts belong to the native-call custody handoff. Those verification results prove evidence consistency; they preserve the lifecycle failed/1 result and do not imply runtime adoption.

## Boundaries for the cross check and remaining blockers

The completed [three-companion cross check](reviews/native-custody/three-companion-cross-verification-01.json) compared the exact qualified preparation/report/map/terminal bodies between QC and performance packages. Its performance/Mac comparisons used the original native UTF-8 text bytes without fabricating an aggregate DTO, and bound the transmitted parent sources, both original holder reports and their forwarded flags. A Mac footer does not contain the whole X230 report SHA, and the cross check did not order clocks on different hosts.

The [native coverage](reviews/native-custody/native-coverage-01.json) closes all **21 original jobs** with strong terminal records and complete lossless dual streams: 19 succeeded/0 and two failed/1, retaining both the first cache metadata-probe failure and the lifecycle rejection. The [7,443,600-byte custody archive](evidence/native-operations-custody-01.tar.xz), SHA256 `8fe9b50926f919a6e1a74f8df1b6ed80c0f4080ff6ed1a178cafb1f25ba1c05c`, contains 1,300 regular members, including 1,292 original files. Its [manifest](reviews/native-custody/manifest.json) and [independent full verification](reviews/native-custody/independent-verification-01.json) bind all original bytes and the three-companion cross proof. The five local cross/snapshot/coverage/build/verify invocations each returned 0 on their first invocation with empty stderr; [original operation records](reviews/native-custody/operations-01/) and [cross source](sources/cross-package/crosscheck_three_companions_01.py) are retained.

Individual archive QA, the completed cross-package/native-custody checks and final Git publication are distinct checks. The [ledger](reviews/remaining-blockers-03.json) now records the actual evidence closure while leaving Git tree/ref publication pending at this snapshot, along with the original acceptance conditions. Hosted exact-head and current-base prospective-merge results remain separate from external CI; no future hosted pass or PR-only skipped job is promoted to success here. Required lifecycle performance, real cancellation saturation and supported capacity attribution remain open despite this candidate's completed rejection decision.
