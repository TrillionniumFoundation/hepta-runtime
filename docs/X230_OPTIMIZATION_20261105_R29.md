# X230 R29: shared tool router candidate, rejected by the lifecycle throughput gate

**R29 is rejected and has not been adopted.** Its original full qualification, exact external Rust CI, all 18 Python commands, and the observation campaign passed. The subsequent normal six-host lifecycle ABBA failed one predeclared required condition: live concurrent cancellation throughput. The observed B/A ratio was **0.9235250428578928**, below the unchanged **0.95** minimum. The candidate's cancellation p95, CPU and RSS conditions passed. Production `src` remains accepted R24 tree `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`.

The lifecycle holder's original native result is **failed/1**, with 298 bytes of stdout and no stderr. Four ordinary lifecycle canaries and all four independent audits passed; the final performance gate rejected the candidate. The parent stopped before cancellation saturation. The complete performance capture subsequently observed `/home/qian/hepta-runtime-optimization-20261105-r29/cancel-saturation-01` absent. No saturation result is filled in. See the [original lifecycle gates](../tools/x230/20261105/r29/receipts/lifecycle-original-gates-01.json), [parent](../tools/x230/20261105/r29/receipts/lifecycle-parent-01.json), and [native terminal](../tools/x230/20261105/r29/receipts/lifecycle-native-terminal-01.json).

The [machine-readable actual facts](../tools/x230/20261105/r29/reviews/rejected-facts-01.json) bind the source, original results, archive identities and scope limits. The [updated blocker ledger](../tools/x230/20261105/r29/reviews/remaining-blockers-03.json) distinguishes completed checks, the rejected adoption decision, and work that remains open.

## Exact candidate and production boundary

R29 starts from the actual qualified R28 source and adds a shared immutable raw `ToolRouter` for `OctofsServer`. The generated unfiltered route table is initialized once and borrowed by the existing routing/listing entry points. Runtime visibility, request authority, native-session ownership, per-instance service context, audit state and sanitized tool listings remain evaluated through their original paths. The cache does not retain a particular server instance. The source change avoids repeated route-table construction; this document does not claim that every request previously regenerated every schema, because the locked rmcp implementation already has schema caching.

Only `server.rs` and its regression tests are new relative to R28. The complete qualified candidate also retains the earlier bounded cancellation reserve, deferred Python read request construction and fixed cancellation-command cache. Consequently the complete difference from accepted R24 is **seven modified files and one added file**, with 213 other compiler inputs unchanged. This publication keeps the eight actual qualified postimages under `candidate/qualified-source/` and the [complete R24-to-R29 patch](../tools/x230/20261105/r29/candidate/accepted-R24-to-actual-qualified-R29.patch) as evidence. It makes no production-source change.

The [qualified source map](../tools/x230/20261105/r29/receipts/qualified-source-map.json) has 221 inputs. The [source index](../tools/x230/20261105/r29/receipts/qualified-source-index-01.json) binds each retained postimage to it and each old body to accepted R24. Only `server_tests.rs` changed during the actual formatting stage; its retained 50,094-byte body has SHA256 `2baea2dc0a15db50fc70a3648f002706fb3a74ca30b3f0c6923a749f0eba1213`. The earlier unformatted test proposal is not substituted for this body.

| Candidate source path | Actual qualified SHA256 |
|---|---|
| `src/mcp/runtime/jobs.rs` | `061c2576e3c1dd8a1e4f5bfd7d3498f7cc4141d6577d53365a9a4738c7980af6` |
| `src/mcp/runtime/ssh.rs` | `b674dfcb60bc57c46a08f1ab1f424a8aadcdb2078abdcfdff30f71632e807b3d` |
| `src/mcp/runtime/ssh_direct.rs` | `e6551f77683d80959e7f7c56f818edeb2ecb3d029442bbc87df475df5ab8ae0d` |
| `src/mcp/runtime/ssh_direct_cancellation_tests.rs` | `5d3f850d932e0a2b40f299a011f0f47d120def145293a7b5297b040cd4800332` |
| `src/mcp/runtime/ssh_direct_tests.rs` | `e5ee9166587a1f4c24daf9304c0a2737c57ce4df50e4e5085e7d2e533ec4b2d2` |
| `src/mcp/runtime/ssh_tests.rs` | `d7401408ead79d7604b9acf13139bcccde06e967d6f0d861bd7eb06dfad40cd6` |
| `src/mcp/server.rs` | `e6f34ef9ace819f72ceafaeee40a957210362f87cc4317d6ebfe4b76ba2fa4d4` |
| `src/mcp/server_tests.rs` | `2baea2dc0a15db50fc70a3648f002706fb3a74ca30b3f0c6923a749f0eba1213` |

The actual qualified `hepta-runtime` binary has SHA256 `152fea06599fa50b0fb82485011f0c9b3d9032aab9fcfa4c574b003da4cc10e5`. A is the accepted R24 binary `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13`. No later pidfd, capacity-cap or other proposed change is part of R29.

## Qualification and external CI

| Original operation | Original native job | Actual result |
|---|---|---|
| Full qualification | `1a1ad4261c8-fc05-593b` | All eight stages returned 0; 1,655 passed, 0 failed, 34 ignored, 1,689 selected, 0 retries. |
| Exact external Rust CI | `1a1ad69c247-fc05-59c8` | All six stages returned 0; exact workflow commands and full inventory; 1,655 plain PASS, 34 ignored, 0 retries. |
| External Python CI | `1a1ad72111c-fc05-59eb` | All 18 original commands returned 0; all 85 dependency inputs and candidate source bindings unchanged; 0 retries. |

The two added router tests actually passed: `mcp::server::server_tests::cached_router_keeps_mcp_sessions_and_teardown_independent` and `mcp::server::server_tests::cached_router_rechecks_runtime_mode_and_native_session_owner`. They exercise instance/session isolation and re-evaluation of runtime mode/ownership after warming the shared raw cache. These results are recorded in the complete original isolated-test ledger, not inferred from a prepared test plan.

The [qualification preparation](../tools/x230/20261105/r29/receipts/qualification-preparation.json), [report](../tools/x230/20261105/r29/receipts/qualification-report.json), [isolated summary](../tools/x230/20261105/r29/receipts/isolated-summary.json), [Rust report](../tools/x230/20261105/r29/receipts/rust-report.json), and [Python outer](../tools/x230/20261105/r29/receipts/python-outer.json)/[runner report](../tools/x230/20261105/r29/receipts/python-report.json) retain their original bytes. The large per-case audit, every stage stream, full qualified source, exact CI inventory, all 36 Python gate streams and retained ELF identities are in the [complete QC archive](../tools/x230/20261105/r29/evidence/qualification-ci-01.tar.xz), whose [independent QA](../tools/x230/20261105/r29/reviews/qualification-CI-full-verification-01.json) checked all 3,820 regular members. ELF bodies are omitted with their observed identities recorded; no claim is made that executable bodies are inside the archive.

“85” is the count of dependency inputs, not the number of Python tests. These are actual external executions against the candidate; they do not establish hosted GitHub Actions results for the eventual evidence commit or a future prospective merge. A wrong-host Rust `process_read` request was rejected and retained before reading the same original job on X230; it did not restart CI.

The qualification preparation also preserves the actual cache-space history and transfer receipt. The selected cache was moved once without replacement rather than duplicated. The original 3 GiB reserve, source/harness checks, retained binaries and failed read-only admission history remain in the evidence. Space probes are point-in-time observations, not proof that all system processes are readable or that every possible writer is absent.

## Observation: all fixed gates passed

The original observation holder was `1a1ad77dfe5-fc05-59f9`, with a complete succeeded/0 terminal and 299/0 native stream bytes. All seven parent stages returned 0: native observation, its audit, the capacity-boundary probe and audit, cancellation/recovery canary and audit, and the fixed summary. The [original summary](../tools/x230/20261105/r29/receipts/observation-summary-01.json) and [parent](../tools/x230/20261105/r29/receipts/observation-parent-01.json) both report `observation_gate_passed: true`.

The fixed experiment uses ABBA with A = accepted R24 and B = this actual qualified R29, C1/C8/C16, 192 measured calls and 24 warmups per cell, two Tokio workers, and the same controller allocator setting. Throughput uses successful calls divided by the measured cell spans; p95 pools measured latencies with the frozen nearest-rank rule. No historical campaign is pooled into these results.

| Concurrency | R24 calls/s | R29 calls/s | B/A throughput | R24 p95 ms | R29 p95 ms | B/A CPU/call | Result |
|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 8.303297 | 9.027571 | 1.087227224 | 182.345187 | 158.750974 | 0.933669186 | Passed |
| 8 | 59.348820 | 58.930736 | 0.992955471 | 182.676725 | 185.195505 | 0.964566929 | Passed |
| 16 | 59.270818 | 60.172793 | 1.015217855 | 323.530431 | 324.550473 | 0.964467005 | Passed |

Every concurrency retains the same throughput minimum 0.95, p95 maximum 1.10 and controller CPU/call maximum 1.10. Sampled controller RSS was 18,704 KiB for A and 17,200 KiB for B, a reduction of 1,504 KiB. B is below the combined ceiling of 19,216 KiB: `min(A + 512 KiB, A × 1.05)`.

The boundary test recorded 32 successful requests, 32 capacity refusals and no other errors, then drained and recovered. This counts refusals separately from successful throughput. The independent cancellation/recovery canary passed; its finite correctness checks do not substitute for the later lifecycle performance and cancellation-saturation gates.

In this run C1 throughput rose 8.7227% and its p95 fell 12.9393%. C8 and C16 throughput ratios were 0.992955471 and 1.015217855. These observations meet this campaign's gates. They are not statistical significance, a claim that all capacity bottlenecks have been found, or causal attribution of every difference to router construction.

## Normal lifecycle: correctness passed, required cancellation throughput failed

After observation passed, the original lifecycle holder `1a1ad8309eb-fc05-5a1b` ran the 14 local harness checks with no skips and the one fixed normal lifecycle ABBA. Each round used six fresh owned jobs on six physical hosts. The four original canaries and four independent audits returned 0. Across all four rounds there were 24 new starts, 48 same-key lookups and 48 cancellation calls, with original exact job/idempotency bindings retained. The [normal ABBA parent](../tools/x230/20261105/r29/receipts/lifecycle-normal-ABBA-01.json) preserves all ten stage results: nine 0 results followed by the performance-gate exit 1.

The adoption-required groups are all operations, launch and live concurrent cancellation. Each arm has 60 aggregate operation calls, including 12 launches and 12 live cancellations. The required throughput ratio remains at least 0.95 and the p95 ratio at most 1.10. CPU retains its predeclared per-window tick tolerance, and RSS retains both limits. The table is calculated by the original [gate report](../tools/x230/20261105/r29/receipts/lifecycle-original-gates-01.json); it does not average the separate descriptive phase-rate output.

| Group | Required for adoption | R24 RPC/s | R29 RPC/s | B/A throughput | R24 p95 ms | R29 p95 ms | B/A p95 | Result |
|---|---|---:|---:|---:|---:|---:|---:|---|
| `all_operations` | Yes | 7.301545 | 7.192761 | 0.985101175 | 841.609489 | 876.408621 | 1.041348312 | Passed |
| `launch` | Yes | 5.615863 | 5.928610 | 1.055690063 | 1084.561053 | 1014.919153 | 0.935787939 | Passed |
| `concurrent_cancel` | Yes | 6.521274 | 6.022560 | 0.923525043 | 1036.225582 | 1114.330669 | 1.075374598 | **Required throughput failed** |
| `same_key_after_crash` | No; descriptive | 7.880502 | 8.111781 | 1.029348224 | 822.755733 | 772.672693 | 0.939127692 | Passed |
| `same_key_after_cancel` | No; descriptive | 8.996333 | 7.923141 | 0.880707825 | 667.185312 | 782.738101 | 1.173194444 | Descriptive throughput/p95 below comparison bounds |
| `cancel_after_terminal` | No; descriptive | 8.671269 | 9.014096 | 1.039535963 | 708.586943 | 674.178921 | 0.951441355 | Passed |

The live-cancel throughput dropped from **6.521274284** to **6.022560113 RPC/s**, a **7.6475%** decrease. The original RPC spans were 1.840131158 seconds for A's 12 calls and 1.992508132 seconds for B's 12 calls. Its p95 ratio was 1.075374598, which passed; controller CPU was 0.07 seconds for A and 0.05 seconds for B against the declared 0.09-second limit. The required cancellation failure is throughput only. Sampled lifecycle controller RSS was 17,420 KiB for A and 16,056 KiB for B, below the 17,932-KiB ceiling.

The descriptive `same_key_after_cancel` group also has worse throughput and p95 in the original report. It is retained explicitly in the table and full logs. Its `adoption_required` field is false under the frozen protocol; it is not silently discarded, and it is not turned into an additional post-hoc acceptance condition. Conversely, the passing aggregate and launch groups do not override the required live-cancel failure.

The outer parent therefore reports `passed: false` and `adoption_passed: false`, with `normal-lifecycle-abba returned nonzero; original output retained`. It entered only `lifecycle-tool-tests` and `normal-lifecycle-abba`. No saturation or saturation-audit stage was submitted. The full performance manifest independently records the saturation directory absent at capture. That is a missing execution result, not a successful saturation check.

The fixture correctness and cleanup did not fail. The finite performance rejection is preserved without repeating R29 for a more favorable sample or loosening a threshold. It does not identify whether a particular remote polling step, transport phase or host caused the cancellation-rate difference.

## Measurement coverage, cleanup and original outcomes

The original observation compiler monitor has 283 samples covering 282 required slots; lifecycle has 150 samples covering 149 required slots. Both retained zero missed slots and zero observed compiler records, joined their monitor threads, and passed the frozen independent validator. Monitor CPU was 0.0069443520 core for observation and 0.0064837245 core for lifecycle, below the unchanged 0.02-core bound. The complete [observation ledger](../tools/x230/20261105/r29/receipts/observation-compiler-monitor-01.json)/[audit](../tools/x230/20261105/r29/receipts/observation-compiler-monitor-audit-01.json) and [lifecycle ledger](../tools/x230/20261105/r29/receipts/lifecycle-compiler-monitor-01.json)/[audit](../tools/x230/20261105/r29/receipts/lifecycle-compiler-monitor-audit-01.json) are retained. The archive consumer replayed the pure validator against their full original bytes.

These are 1 Hz sampled observations. They do not prove that arbitrarily short activity never occurred between samples. Controller CPU and sampled controller RSS likewise do not measure total cluster CPU or memory.

The original parents preserve owned child wait/reap and process-group cleanup. Both Mac holders report the foreground process completed, the owned agent reaped, and its owned directory/socket absent. The Mac collector's subsequent metadata witness and independent archive verification retain that closure while preserving OBS succeeded/0 and lifecycle failed/1. No private key, SSH configuration dump or environment dump is added to the evidence.

The native ready/footer output binds the actual transmitted script SHA and the original Mac report path. The forwarded footer names the X230 parent report and original flags; it does **not** contain the whole X230 report's SHA. The completed [cross-package verification](../tools/x230/20261105/r29/reviews/native-custody/three-companion-cross-verification-01.json) compared the actual parent/body/source/input and the original native text bytes across all three packages. It did not invent a whole-report hash in that footer or order clocks on separate hosts.

## Complete original companions and publication scope

All three remote-original companions were captured once and independently verified. Archive capture success preserves the original lifecycle rejection.

| Archive | Bytes | Regular members | SHA256 | Full QA |
|---|---:|---:|---|---|
| [qualification-ci-01.tar.xz](../tools/x230/20261105/r29/evidence/qualification-ci-01.tar.xz) | 1,942,216 | 3,820 | `bfe5852ce915f8430862d6ac456bf366cac4df33b03c542cfb80290d49a895b3` | [Passed](../tools/x230/20261105/r29/reviews/qualification-CI-full-verification-01.json) |
| [performance-01.tar.xz](../tools/x230/20261105/r29/evidence/performance-01.tar.xz) | 2,183,968 | 5,740 | `9d54e46cf25606290906ed584c4ad3c097a0957c795b1adbfaf4e895f924a448` | [Passed](../tools/x230/20261105/r29/reviews/performance-full-verification-01.json) |
| [formal-holders-01.tar.gz](../tools/x230/20261105/r29/evidence/formal-holders-01.tar.gz) | 84,013 | 59 | `cf229ad6ab2c7cda19029048d1b714fe23d095c4034aba6c35401f0fe4ef76be` | [Passed](../tools/x230/20261105/r29/reviews/Mac-full-verification-01.json) |

The QC and performance XZ archives each have a verified single stream, SHA256 integrity check and exact compressed EOF. The Mac gzip archive has verified CRC/ISIZE, a single member and exact EOF. The consumers checked every retained member; they did not execute archive contents. The full performance archive contains all four normal rounds' raw RPCs, independent summaries, resource observations, original logs, the gate policy, monitor sources/ledgers and the observed saturation absence. The Mac archive retains both 22-file holder directories, exact transmitted scripts, original terminal/read DTOs and reconstructed original streams. All required original bytes are included or have an explicit recorded omission; ELF bodies are identity-only in the QC scope.

The three individual full-QA receipts remain scoped to their own archives. The separate [three-companion cross proof](../tools/x230/20261105/r29/reviews/native-custody/three-companion-cross-verification-01.json) and [native RPC coverage](../tools/x230/20261105/r29/reviews/native-custody/native-coverage-01.json) have now completed. All **21 original native jobs** have strong terminal records and complete lossless stdout/stderr. This includes **19 succeeded/0 and two failed/1** originals: the first cache metadata probe and the lifecycle holder. Their failed states, original request/read bodies, and retained local failures remain unchanged.

The [sealed native-call archive](../tools/x230/20261105/r29/evidence/native-operations-custody-01.tar.xz) is **7,443,600 bytes**, SHA256 `8fe9b50926f919a6e1a74f8df1b6ed80c0f4080ff6ed1a178cafb1f25ba1c05c`. Its [manifest](../tools/x230/20261105/r29/reviews/native-custody/manifest.json) contains **1,300 regular members**, including **1,292 original files**. The [independent verifier](../tools/x230/20261105/r29/reviews/native-custody/independent-verification-01.json) checked the complete member bytes and single-stream XZ integrity/exact end, with no archive-code execution. Cross check, snapshot, native coverage, bundle build and independent verification each completed on their first invocation with exit 0 and empty stderr; their [original local operation records](../tools/x230/20261105/r29/reviews/native-custody/operations-01/) and [cross source](../tools/x230/20261105/r29/sources/cross-package/crosscheck_three_companions_01.py) are retained separately.

These completed evidence checks preserve the rejected candidate. The final Git tree/ref and exact-head or prospective-merge hosted results require their own actual receipts; those publication and hosted outcomes are not inferred here.

The retained [R26 rejection](X230_OPTIMIZATION_20261105_R26.md) and [R28 rejection](X230_OPTIMIZATION_20261105_R28.md) remain historical results. R29 does not overwrite them, apply its candidate to production, or convert a later proposal into a completed optimization. The open work is the original required lifecycle non-regression, real cancellation saturation, supported capacity attribution, and exact-head/prospective-merge integration evidence. The [blocker ledger](../tools/x230/20261105/r29/reviews/remaining-blockers-03.json) records those limits and the separate publication-chain handoff.
