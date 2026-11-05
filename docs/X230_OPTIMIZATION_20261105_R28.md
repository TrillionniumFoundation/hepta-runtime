# X230 R28: qualified cancellation-command cache candidate, rejected by observation gate

**R28 is rejected and has not been adopted.** The original observation campaign completed its workloads, audits and cleanup, but C1 throughput was 7.9594% below the accepted R24 baseline. The unchanged minimum ratio is 0.95; the observed ratio was **0.920406142147403**. Dedicated lifecycle ABBA and cancellation saturation were not submitted after this rejection.

The complete qualification/CI, performance and Mac companion archives have now been downloaded and independently verified. Their cross-package check also passed, and the sealed native-call custody archive preserves all 19 original operations with strong terminal status and complete stdout/stderr. Those evidence checks preserve the rejected outcome; they do not turn it into a performance pass. The [actual handoff](../tools/x230/20261105/r28/reviews/native-custody/handoff-01.json) binds the completed checks and original local execution records.

Production `src` remains accepted R24 tree `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`. The previous R25/R26 evidence publication is commit `1c23ba9ad4e7c9436eb76d1508f6f0bd8ee7ce64`, which retained that source tree. Its original publication receipt is preserved [here](../tools/x230/20261105/r28/receipts/prior-R25-R26-publication-actual-01.json). This evidence update does not apply the rejected candidate patch to production.

## Candidate and exact source

R28 used the qualified R26 candidate as its source parent and added a cache for the fixed Python cancellation command. The added cache stores compiled cancellation source and the fixed `python3` command. Request serialization, host selection, authority checks, deadline calculation and cancellation admission remain per call. The optional pidfd change was not selected.

The candidate retained the earlier cancellation reserve and deferred Python read-payload construction from the qualified R25/R26 work. Therefore its complete difference from accepted R24 is six files, even though the cache proposal itself touches three files. The actual qualified source map contains 221 compiler inputs; the R24 map contains 220. Only the actual formatter output is used in the candidate patch, including the 4,944-byte qualified `ssh_tests.rs` postimage.

The [rejected qualified patch](../tools/x230/20261105/r28/rejected-qualified-candidate-02.patch) is evidence, not an applied production change. Its [source proof](../tools/x230/20261105/r28/qualified-source-patch-proof-01.json) binds every old body to the accepted R24 source map and every new body to the actual R28 qualified map. It does not use a pre-format R24 or R28 image to manufacture a difference.

| Source path | R28 SHA256 |
|---|---|
| `src/mcp/runtime/jobs.rs` | `061c2576e3c1dd8a1e4f5bfd7d3498f7cc4141d6577d53365a9a4738c7980af6` |
| `src/mcp/runtime/ssh.rs` | `b674dfcb60bc57c46a08f1ab1f424a8aadcdb2078abdcfdff30f71632e807b3d` |
| `src/mcp/runtime/ssh_direct.rs` | `e6551f77683d80959e7f7c56f818edeb2ecb3d029442bbc87df475df5ab8ae0d` |
| `src/mcp/runtime/ssh_direct_cancellation_tests.rs` | `5d3f850d932e0a2b40f299a011f0f47d120def145293a7b5297b040cd4800332` |
| `src/mcp/runtime/ssh_direct_tests.rs` | `e5ee9166587a1f4c24daf9304c0a2737c57ce4df50e4e5085e7d2e533ec4b2d2` |
| `src/mcp/runtime/ssh_tests.rs` | `d7401408ead79d7604b9acf13139bcccde06e967d6f0d861bd7eb06dfad40cd6` |

## Qualification and CI: actual results, original failures retained

| Original operation | Native job | Actual result |
|---|---|---|
| Qualification admission 01 | `1a1ac274e49-fc05-5286` | Failed before source/cache copy or Cargo because the unchanged free-space reserve was not met. |
| Read-only cache inventory 02 | `1a1ac456b07-fc05-532a` | Failed; its original result remains a failed inventory result. It is not a successful cleanup or qualification. |
| Full qualification 02 | `1a1ac5d5a29-fc05-53d9` | All eight stages returned 0; 1,653 passed, 0 failed, 34 ignored, 1,687 selected, 0 retries. |
| Exact external Rust CI | `1a1ac8bfc0c-fc05-552c` | Succeeded; original workflow check/nextest commands retained, complete inventory compared, 1,653 plain PASS, 34 ignored, 0 retries. |
| Python CI launch 01 | `1a1ac97d8cb-fc05-55a2` | Failed in the launcher's source guard before the 18-gate runner started. |
| Read-only Python source-mode probe | `1a1aca4ad22-fc05-561a` | Succeeded; preserved the actual mode, owner, link count, byte/hash identities and absent first runner output. |
| Python CI recovery 02 | `1a1acb64a3e-fc05-5682` | Succeeded; all 18 original gates returned 0, all 85 dependencies and all 221 source inputs remained unchanged. |

The [qualification report](../tools/x230/20261105/r28/receipts/qualification-report-01.json), [isolated-test summary](../tools/x230/20261105/r28/receipts/isolated-tests-summary-01.json), [Rust CI report](../tools/x230/20261105/r28/receipts/rust-ci-report-01.json), and [Python runner report](../tools/x230/20261105/r28/receipts/python-ci-runner-report-02.json) retain their original bytes. The large per-test ledger, independent test audit, all stage stdout/stderr and source bodies are retained in the complete [qualification/CI companion archive](../tools/x230/20261105/r28/evidence/qualification-ci-01.tar.xz). Its [full independent verification](../tools/x230/20261105/r28/reviews/qualification_ci-full-verification-01.json) checked all 3,830 members, including the individual Python gate streams and both original Python attempts.

The qualification recovery used the same 3 GiB space reserve and actual source transformation. It preserved the first failed admission and failed inventory instead of overwriting them. The later observed space was sufficient; this was not a cleanup claim. The [preparation 02 receipt](../tools/x230/20261105/r28/receipts/qualification-preparation-02.json) records that distinction.

The original Python failure came from the launcher's no-group-write guard encountering two inherited source files with mode `0660`. The generic error said “unsafe or oversized”; the actual issue was the mode guard, not the size of the independent qualification audit. A bounded metadata read established the exact files and preserved the absent first runner output. Recovery 02 corrected that guard and ran a fresh original CI operation while checking the old failure before and after. The [failed outer receipt](../tools/x230/20261105/r28/receipts/python-ci-original-failed-outer-01.json), [metadata report](../tools/x230/20261105/r28/receipts/python-ci-mode-metadata-01.json) and [successful recovery outer receipt](../tools/x230/20261105/r28/receipts/python-ci-outer-02.json) remain separate.

These are the actual external gates against the exact candidate. They do not establish hosted GitHub Actions results for a future publication commit. The prior publication's Python dependency continuity proof confirms unchanged input trees, not a new CI execution.

## Original observation result

The only R28 observation holder was `1a1acbbcbec-fc05-56a0`, key `mac-x230-runtime-r28-observation-campaign-20261105-01`. Its original native terminal was successful and complete, with 299 bytes of stdout and no stderr. The source-bound Mac holder closed its owned SSH foreground process and agent. All seven original parent stages returned 0: observation, its audit, the capacity boundary, its audit, the cancellation/recovery canary, its audit and the fixed summary.

The parent nevertheless reports `observation_gate_passed: false`; its summary rejects `C1 regression gate`. The [parent](../tools/x230/20261105/r28/receipts/observation-parent-01.json), [summary](../tools/x230/20261105/r28/receipts/observation-summary-01.json), [original native terminal](../tools/x230/20261105/r28/receipts/observation-native-terminal-01.json) and [Mac holder report](../tools/x230/20261105/r28/receipts/observation-Mac-holder-01.json) preserve those distinct meanings of completion and acceptance.

The frozen A/B/B/A measurement uses A = accepted R24 and B = the actual qualified R28 binary. Its same workload, warmup, concurrency, summary aggregation and thresholds are retained. No historical run is pooled into this result. Throughput is total successful measured calls divided by the sum of measured cell spans, and p95 is the nearest-rank value over the pooled measured latencies. Controller CPU is the original synchronous controller CPU per measured call.

| Concurrency | R24 calls/s | R28 calls/s | B/A throughput | R24 p95 ms | R28 p95 ms | B/A CPU | Result |
|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 8.344921 | 7.680716 | **0.920406142** | 180.223586 | 186.227604 | 1.041450777 | **Throughput gate failed** |
| 8 | 55.778977 | 54.471880 | 0.976566483 | 196.535597 | 196.317967 | 0.982781457 | All three observation gates passed |
| 16 | 56.195557 | 56.253846 | 1.001037244 | 331.093040 | 347.243706 | 1.000000000 | All three observation gates passed |

At every concurrency the throughput ratio must be at least 0.95, the p95 ratio at most 1.10 and the controller CPU ratio at most 1.10. C1 CPU increased from 30.15625 to 31.40625 ms/call, which passes the CPU limit. Its p95 increased by 3.3314%, which passes the p95 limit. The C1 throughput failure remains decisive.

Sampled controller RSS was 19,112 KiB for A and 18,880 KiB for B, a reduction of 232 KiB. B passes both frozen RSS conditions: at most A + 512 KiB and at most A × 1.05. This is a sampled controller peak, not a total-cluster memory or allocation bound.

The original compiler monitor audit passed with 292 samples. The full ledger and audit are preserved [here](../tools/x230/20261105/r28/receipts/observation-compiler-monitor-01.json) and [here](../tools/x230/20261105/r28/receipts/observation-compiler-monitor-audit-01.json). A 1 Hz monitor describes what those samples observed; it does not prove the absence of arbitrarily short activity between samples.

The capacity boundary drained and recovered successfully; refusals are recorded separately from successful throughput. The original six-host cancellation/recovery canary also passed. That canary does not stand in for the dedicated lifecycle A/B/B/A or cancellation-reserve saturation campaign. Those were not submitted after the observation rejection. The complete performance and Mac captures checked the corresponding unexecuted output paths for absence, and the cross-package proof retained that result; no lifecycle or saturation pass is filled in.

The finite run establishes that this candidate did not meet its frozen observation gate. It does not isolate a causal explanation for the C1 difference. The candidate will not be replayed unchanged to obtain a more favorable sample, and its gate is not relaxed.

## Complete evidence delivery and custody

All three remote-original companions and the local original-call custody bundle are complete. Each listed archive has an independent verification receipt; the checks preserve every original result and do not rerun the workloads.

| Artifact | Bytes | Regular members | Actual verification |
|---|---:|---:|---|
| [Qualification and CI](../tools/x230/20261105/r28/evidence/qualification-ci-01.tar.xz) | 1,915,620 | 3,830 | [Passed](../tools/x230/20261105/r28/reviews/qualification_ci-full-verification-01.json): complete qualification, per-test audit/logs, source bodies, exact Rust CI, both Python attempts and all gate streams. |
| [Performance](../tools/x230/20261105/r28/evidence/performance-01.tar.xz) | 1,704,632 | 4,155 | [Passed](../tools/x230/20261105/r28/reviews/performance-full-verification-01.json): full observation, boundary and canary originals, monitor, fixed tools and actual lifecycle/saturation absence. |
| [Mac holder](../tools/x230/20261105/r28/evidence/formal-holders-01.tar.gz) | 71,892 | 33 | [Passed](../tools/x230/20261105/r28/reviews/mac-full-verification-01.json): 32 payload files, including the 22 original holder files, source, foreground streams, agent ownership/cleanup and absent lifecycle output. |
| [Original native-call custody](../tools/x230/20261105/r28/evidence/native-operations-custody-01.tar.xz) | 5,861,604 | 691 | [Passed](../tools/x230/20261105/r28/reviews/native-custody/independent-verification-01.json): 683 original files, complete requests/results and lossless dual-stream coverage for all 19 original operations. |

| Archive | SHA-256 |
|---|---|
| `qualification-ci-01.tar.xz` | `442586ded13a4cfde54531e6f05ddddcf26c2f53d40d15b04c5993ece5f04186` |
| `performance-01.tar.xz` | `ba420b2e0a34a23b9d0330b3c5f38e743b08110d02db9c7dd599b25943070613` |
| `formal-holders-01.tar.gz` | `fc7bf702c4b41e073b0cd37891f0b0970c7e30170b6aa3c0e2b92ef297ff4ce6` |
| `native-operations-custody-01.tar.xz` | `7c6bd7881500089732e933fa4212a47fbff4fe6f5950b7c718a3a6ea4ebb8ba5` |

The qualification/CI capture was original job `1a1acd29fba-fc05-5724`, with complete stdout/stderr of 505/0 bytes. The performance capture was `1a1aceda220-fc05-57a1`, with 500/0 bytes, and the Mac capture was `1a1ace26662-fc05-5775`, with 498/0 bytes. All three capture jobs succeeded. Their successful capture results are separate from the original C1 performance rejection. The original qualification/CI [capture report](../tools/x230/20261105/r28/receipts/qualification-CI-capture-report-01.json) and [40-chunk manifest](../tools/x230/20261105/r28/receipts/qualification-CI-capture-chunks-01.json) are joined to the complete delivered body by its full verification receipt.

The [cross-package verification](../tools/x230/20261105/r28/reviews/native-custody/three-companion-cross-verification-01.json) passed against the three actual archive bodies. It joined the exact 221 source inputs, qualification and measured binary identities, original parent/report bodies and holder streams. It compared the Mac wrapper's original `content.text` UTF-8 bytes with the X230 inner native DTO without re-encoding JSON. It also preserved the original qualification/Python failures, the observation rejection and the unexecuted lifecycle/saturation outcome.

The final local chain—cross-check, snapshot, native coverage, archive build and independent archive verification—ran once per step. All five first invocations returned 0 with empty stderr and no automatic retry. Their original command, stdout, stderr and result files are retained in the [operation records](../tools/x230/20261105/r28/reviews/native-custody/operations-01/00-cross.result.json) and indexed by the [actual publication map](../tools/x230/20261105/r28/reviews/native-custody/publication-map-01.json). The [native coverage receipt](../tools/x230/20261105/r28/reviews/native-custody/native-coverage-01.json) reports 19/19 strong terminal and complete dual-stream bindings with no gaps. Qualification admission 01, read-only inventory 02 and Python launch 01 remain the three original failed operations; none was rewritten as success.

The compact XZ archives retain full raw coverage; compression does not remove test logs, audit evidence or errors. ELF and private configuration/key bodies remain explicit identity-only omissions, classified before text marker scanning. Original transport responses and failed reads in the fixed R28 scope are retained. Consumers verify the complete compressed end, regular member inventory and every member identity without extracting or executing archive code. The sealed custody archive's own packing/verification operations and later Git publication responses remain outside that archive to avoid circular references. Previously published R25/R26 custody is referenced through commit `1c23ba9a…`, not duplicated.

The complete evidence supports the recorded rejection of R28 while accepted production remains R24. It does not establish that all optimization blockers are closed, that the rejected candidate improves production performance, or that hosted CI for a later publication has passed.
