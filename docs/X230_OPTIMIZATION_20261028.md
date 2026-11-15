# X230 concurrency, resource and recovery integration — 2026-10-28

## Provenance and review boundary

This branch composes A55 (`463963580c2f34ef46032f7d80c79b4d4c59edb3`), the native-library and audit qualification work from PR 75 (`d7d039458c8745bea1bafd24f03635e75a66a2f4`), and the previously unpublished A56–A62 source retained on the X230. The preserved A62 source archive contains 175 files and has SHA-256 `3aab0e642709af973df3fe2932bfc9acd36d34d2bfd5ea57b91116da281e647c`. The PR 75 input remains fixed at `d7d0394`; later API additions at `a3c8b5a` are outside this integration and its qualification.

R3 completes this iteration with 1,500 passing exact tests, all eight native stages passing, and completed reuse and registry ABBA cohorts. Its buffer reuse reduces cold registry lookup median by 20.217% relative to R2 in a direct interleaved comparison. The final candidate still has a 52.283% higher cold lookup median than A62 in its separate A62 comparison, and cold local reuse throughput remains lower despite substantially better MCP ping responsiveness at C4/C8. The results below retain those regressions and the resource observation failures; they do not establish a general throughput or memory improvement.

Historical results qualify their original source and ELF only. R2's cold-lookup regression led to the separately qualified R3 buffering change. The first R3 native attempt was refused by the unchanged load preflight before any stage helper ran; a fresh, explicitly identified cohort subsequently completed. Original reports and exact source maps are retained under `tests/evidence/20261028-x230/`. No production runtime service is changed by these experiments.

## Qualification status and candidate identity

| Run or validation | Actual result | Scope and remaining work |
| --- | --- | --- |
| R1 composed-source qualification | 1,477 passed, 0 failed, 23 explicitly ignored; release build passed | The original R1 source and binaries passed their qualification. A separately executed independent audit confirmed the exact-case evidence. These results do not qualify the later R2 edits. |
| R2 intermediate-source qualification | 1,497 executed and passed, 0 failed, 23 explicitly ignored; all eight stages passed | R2 passed `format`, `fmt-check`, `harness-tests`, `clippy`, `test-build`, `isolated-tests`, `audit-isolated-tests`, and `release`. The harness suite contained 29 tests. These results do not qualify the later R3 edits. |
| R3 buffer-reuse qualification | 1,500 passed, 0 failed, 23 explicitly ignored; all eight stages passed | The exact R3 snapshot passed its independent test audit and release build. Its 189 source files match the local candidate exactly. This establishes qualification, not a performance improvement. |
| Local Python control-plane regressions | 284 unittest cases passed across 15 suites | Local Linux control-plane coverage; initial environment failures and the explained reruns are retained separately. |
| R2 six-host native validation | All eight stages passed | Covers the R2 inherited-pipe cases, controller SIGKILL recovery, file ABBA and configured 120-second soak. It remains evidence for the intermediate R2 candidate. |
| R2 local reuse throughput ABBA | All 576 calls passed | Independent analysis found lower cold throughput and higher CPU per call alongside improved cold-load MCP ping responsiveness. |
| R2 synchronous registry lookup ABBA | All 16 process samples passed | Eight A62 and eight R2 samples were retained. Cold lookup median increased 92.302%; hot reuse median decreased 26.957%. |
| R3 initial native attempt | Refused before any stage helper was launched | The gate observed unrelated live `cargo` PID 4011451 and `heptabao_server` PID 4036605. The original main SSH child and remote runner child were both reaped. No third-party process was stopped. |
| R3 six-host native validation, `r3-r02` | All eight stages passed | Fresh nonce `bd8a1e718ff25f5e3534019eb5f18538`; includes R3 recovery/identity checks, 1,152 measured file ABBA calls and 2,400 successful calls in the configured 120-second soak. |
| R3 local reuse throughput ABBA | All 576 calls passed | The qualified R3 release was measured against A62; real SSH execution and remote effects were zero. Cold throughput and CPU regressions remain explicit. |
| R3 synchronous registry ABBA | Both 16-process-sample cohorts passed | Separate direct R2/R3 and A62/R3 comparisons, eight process samples per binary in each cohort; all samples, including outliers, are retained. |

The [R3 qualification summary](../tests/evidence/20261028-x230/qualification-r3-summary.json) records all eight successful stages: `format`, `fmt-check`, `harness-tests`, `clippy`, `test-build`, `isolated-tests`, `audit-isolated-tests`, and `release`. The tested and post-run maps are identical for all 189 source files, the harness maps are unchanged, and a local rehash matches that tested source map exactly. R3's original qualification paths are under `/home/qian/hepta-runtime-optimization-20261028/qualification-r3/`.

| R3 evidence or release artifact | SHA-256 |
| --- | --- |
| `report.json` | `736ce6511462f0bef63ed8e2d0741dd74e9a740f5bf95974d52da0cefdd481c5` |
| `isolated-tests.audit.json` | `dfe3e4dce34f92c0d32a6d8c15ec2d6407ef54451d42173f727b80f4c55eabe2` |
| `source-map.json` | `68d411fd95d517801cb189ff641065fe4540fcf6c95e59cdf7af2bc74ca33e65` |
| `hepta-runtime` | `5e670e58d1c8067df594fcc256a2b88bd52cb60a443cadb36e2a7dc0f49effa7` |
| `hepta-runtime-jobctl` | `84572095b80a56ff893ea41b01e170444dc2483a49091277d0b4ada4fbc1c1b0` |
| `native_process_driver` | `4e66120642e7d45e5a3cc77fbdb3aa16aeb7fc2e67ef3b989abc1e5790dcc6d0` |

R2 covers 189 source files. Its tested and post-qualification source maps are identical, and the qualification harness file maps are unchanged before and after the run. The exact R2 report, independent audit and release artifacts are bound below; the original paths are under `/home/qian/hepta-runtime-optimization-20261028/qualification-r2/`.

| Evidence or release artifact | SHA-256 |
| --- | --- |
| R1 `qualification-r1/report.json` | `c890fafc6671d504fe0e2a0142451edb0ab137c1276ad10462d27f257c21b9c3` |
| R2 `report.json` | `41d3319166fc80dd7ae4bde98ad1bd1a73db312f8f900ae79cf1d2d1d7c2503e` |
| R2 `isolated-tests.audit.json` | `534849d550608535de28e4607727350ebc3312a8e153ce5b9aaabc5054addd25` |
| R2 `hepta-runtime` | `2f0e92e0225f0396565aa0939ef010574c888fd308f34f6de7aa65e53b513639` |
| R2 `hepta-runtime-jobctl` | `84572095b80a56ff893ea41b01e170444dc2483a49091277d0b4ada4fbc1c1b0` |
| R2 `native_process_driver` | `0a462f072dbc1a0109da6f6865f87cc6a4d828dd801cc1b124ad5434dd099e3a` |

Qualification success establishes the listed source, test and build results. Native and performance evidence remains bound to the exact candidate used in each experiment. A passing microbenchmark case alone does not establish a throughput gain.

## R2 findings and the R3 response

R2 passed the eight-stage native series, all 576 reuse calls and all 16 registry microbenchmark process samples. The completed original evidence package retains 6,522 files, including the results that motivated further work. R2 remains an intermediate version because the registry measurements showed a clear cold-lookup regression. Independent recomputation from all eight samples per variant gives a cold-lookup median of 78.195 ms for A62 and 150.3705 ms for R2. The four paired ABBA blocks all have the same regression direction; the detailed R2 results below retain both gains and regressions.

A separate `strace` diagnostic recorded 156,036 `read` calls for A62 and 468,038 for R2. These counts cover the entire instrumented microbenchmark case, including its internal work; they are not counts for one registry scan. The diagnostic's elapsed times are excluded from the performance sample set. Its purpose was to locate the added read activity without replacing the original uninstrumented ABBA evidence.

R3 changes only `jobs.rs` and `jobs_security_tests.rs` relative to R2. The reader uses fallible allocation to reserve the already validated opened-file length plus one byte, and each scan reuses one scratch buffer across records. The buffer is cleared after both success and failure. Retained buffer capacity is bounded at four MiB plus one byte; that retained-capacity limit is not a claim about instantaneous allocation or total process-memory peaks. The patch retains the existing file, metadata, content, size and final-validation checks, including conservative error handling. Three new tests cover the changed behavior.

The final R2/R3 instrumented comparison records `read` calls falling from 468,038 to 156,038. Each whole fixture includes 13 full scans of 6,000 records, or 78,000 record visits, so the reduction is consistent with removing four extra reads per record. `openat` and `close` each remain at 84,048 for both binaries. These traces did not select `statx`; the 19 reported `fstat` calls do not represent all metadata work. Both the aggregate trace duration and the traced command's wall time are excluded from performance comparisons. The original [R2](../tests/evidence/20261028-x230/r2.syscalls.txt) and [R3](../tests/evidence/20261028-x230/r3.syscalls.txt) trace summaries are retained.

R3 completed qualification in the separate `/home/qian/hepta-runtime-optimization-20261028/source-r3` snapshot. The R2 source and its original evidence remain unchanged. R3's first native attempt stopped at the load preflight because unrelated `cargo` PID 4011451 and `heptabao_server` PID 4036605 were live. Its failed attempt and both child-reaping records are retained; it supplies no workload performance sample. No third-party process was stopped. After a later gate sample was clear, the fresh `native-r3-r02` cohort, nonce `bd8a1e718ff25f5e3534019eb5f18538`, passed all eight stages under the unchanged admission rules. Its original native report has SHA-256 `b4364a84b67eec628888661ab7fbca0ff052e237426f512cb8f4a9a570a2a17f`.

## R3 measured results

The [A62/R3 independent analysis](../tests/evidence/20261028-x230/r3-a62-independent-analysis.json) recomputes the final native, archive, reuse and registry results from their original reports and journals. The [R2/R3 registry analysis](../tests/evidence/20261028-x230/r3-r2-registry-independent-analysis.json) covers the separate direct buffering comparison. Comparisons apply within each original experiment: the R2 and R3 native/reuse sessions were conducted at different times and are not paired R2/R3 experiments. The [benchmark pipeline report](../tests/evidence/20261028-x230/benchmark-r3-report.original.json) records completed measurement steps, zero automatic retries and clear sampled load gates. Those gates sample local `/proc`; they do not prove absence of remote-host load or activity between samples.

### Registry lookup: the direct R2/R3 comparison

Four fixed ABBA blocks retain 16 process samples, eight per binary, with no failed, discarded or retried sample. R2 and R3 library test executables have SHA-256 `8a7a043f2296f41aaea91c95ce58b9cef1e08dbc86a03fecbaadd215a830a18d` and `2d932d972ac7dae751bfeffdcdd925893e5267ecec460ba391fc8625c94257d3` respectively.

| Metric | R2 median ms | R3 median ms | Change | R3/R2 in the four paired blocks |
| --- | ---: | ---: | ---: | --- |
| Cold lookup | 151.380500 | 120.775500 | −20.217% | 0.823764, 1.085000, 0.806813, 0.784304 |
| Hot reuse | 0.042000 | 0.040500 | −3.571% | 2.059524, 1.088889, 1.000000, 0.943182 |
| Legacy sorted scan | 140.303000 | 110.767500 | −21.051% | 0.791893, 0.778893, 0.791607, 0.789488 |
| Streamed scan | 131.163000 | 103.745500 | −20.903% | 0.790532, 0.786831, 0.793104, 0.781991 |

The R3 cold sample of 219.189 ms remains in the result. Cold arithmetic mean decreased from 152.563125 to 133.691375 ms (−12.370%), while the second paired block increased 8.500%. The R3 hot sample of 0.133 ms is also retained: hot arithmetic mean increased from 0.042625 to 0.054125 ms (+26.979%), and the first two paired blocks regressed. The small hot median reduction therefore does not establish a consistent hot-path gain. Both sorted and streamed scan block ratios show the same improvement direction.

### Registry lookup: the separate A62/R3 comparison

This cohort also contains four fixed ABBA blocks and 16 successful process samples, eight per binary. Its A62 test executable has SHA-256 `5951a3222468ce17daa427eb0d936464fad85b69bf6a8ac8d7b41bb0bc722e33`. R3's improvement over R2 removes part of the regression; it does not make the final cold scan faster than A62.

| Metric | A62 median ms | R3 median ms | Change | R3/A62 in the four paired blocks |
| --- | ---: | ---: | ---: | --- |
| Cold lookup | 79.746500 | 121.440000 | +52.283% | 1.458251, 1.505225, 1.490321, 1.539533 |
| Hot reuse | 0.057000 | 0.040000 | −29.825% | 0.481481, 0.754386, 0.718182, 0.761905 |
| Legacy sorted scan | 75.113000 | 112.584500 | +49.887% | 1.451168, 1.461200, 1.504252, 1.524722 |
| Streamed scan | 65.563000 | 104.095000 | +58.771% | 1.527583, 1.632315, 1.633457, 1.628521 |

In both registry cohorts, cold means an empty process-local cache; the operating-system page cache was uncontrolled. Each emitted legacy/streamed value is itself a median of six internal runs, whose individual raw timings were not printed. These synchronous fixture results do not measure async MCP or multi-host launch throughput. The A62/R3 comparison includes the integration's validation and concurrency changes, whereas the direct R2/R3 comparison isolates the buffer-reuse revision.

### Six-host file observation and soak

Each concurrency level has 192 successful measured calls per arm, for 1,152 measured file calls. Throughput divides the total successful calls by the summed original cell durations; request percentiles pool the original call rows.

| Concurrency | A62 calls/s | R3 calls/s | Rate change | Controller CPU ms/call, A62 → R3 | Request p99 ms, A62 → R3 |
| --- | ---: | ---: | ---: | ---: | ---: |
| C1 | 4.092679 | 4.038427 | −1.326% | 130.000000 → 133.072917 | 311.452756 → 322.398854 |
| C4 | 15.606778 | 15.966181 | +2.303% | 76.145833 → 74.791667 | 382.504814 → 334.073808 |
| C8 | 21.661346 | 21.922985 | +1.208% | 73.958333 → 74.322917 | 482.646398 → 471.561185 |

This is one short ABBA block over six immutable 44–48 byte files, using `file_info` and `binary_read`. The modest rate differences do not establish a stable production gain or quantify launch throughput or bulk bandwidth. C1 p99 increased 3.515%, while C4/C8 p99 decreased 12.662%/2.297%. Controller CPU excludes remote CPU.

The configured 120-second C8 soak completed 2,400 measured calls with zero failures. Measured cell time was 120.438207 seconds and helper lifetime was 128.153636 seconds. Rate was 19.927231 calls/s; p95, p99 and maximum latency were 502.670708, 586.868841 and 1,137.310083 ms. Controller CPU was 77.237500 ms per successful call. This separately timed R3 soak is not a paired R2 comparison or a 600-second experiment.

### Small archive guard

With 64 records, C1 and 2,048 measured calls per arm, rate was 129.673025 → 127.966011 calls/s (−1.316%). Controller CPU was 6.689453 → 6.772461 ms/call (+1.241%); overall p99 was 12.250622 → 12.196032 ms (−0.446%).

| Tool | Mean latency ms, A62 → R3 | Mean change | p99 ms, A62 → R3 |
| --- | ---: | ---: | ---: |
| `usage_stats` | 5.398073 → 5.460231 | +1.151% | 7.447629 → 6.753308 |
| `request_history` | 4.262724 → 4.315983 | +1.249% | 6.029923 → 5.404914 |
| `request_archive` | 10.146619 → 10.288426 | +1.398% | 14.143559 → 13.890042 |

These values belong to the final R3 native cohort. The earlier R2 archive guard had different absolute rates and is retained separately below; subtracting those sessions would not isolate the R3 buffering patch.

### Local MCP reuse: throughput, CPU and responsiveness

All 576 calls passed with 576 denied local status attempts, `real_ssh_execs=0` and `remote_effects=0`. Each arm and concurrency level has 12 cold and 84 warm calls. The workload includes real stdio MCP, original-key lookup and audit; its denied SSH status probes do not exercise the network. The C8 cold wave contains six unique keys and at most six simultaneous distinct requests.

| Phase | Concurrency | A62 calls/s | R3 calls/s | Rate change | Controller CPU ms/call, A62 → R3 | CPU change |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Cold | C1 | 7.705637 | 5.767703 | −25.150% | 90.000000 → 133.333333 | +48.148% |
| Cold | C4 | 19.257637 | 14.951479 | −22.361% | 84.166667 → 159.166667 | +89.109% |
| Cold | C8 | 18.901793 | 15.043315 | −20.413% | 86.666667 → 170.000000 | +96.154% |
| Warm | C1 | 23.323447 | 23.802383 | +2.053% | 7.023810 → 6.785714 | −3.390% |
| Warm | C4 | 59.511911 | 62.502283 | +5.025% | 5.357143 → 5.357143 | 0.000% |
| Warm | C8 | 60.805765 | 63.451710 | +4.351% | 5.833333 → 5.714286 | −2.041% |

Cold throughput remains lower and controller CPU per successful call remains higher at every concurrency level. Warm throughput increased in this short cohort, with flat or slightly lower own-process CPU. The simultaneous ping observations show why a throughput-only conclusion would be incomplete:

| Phase | Concurrency | Request p99 ms, A62 → R3 | Ping p99 ms, A62 → R3 | Ping p99 change | Ping observations, A62 / R3 |
| --- | --- | ---: | ---: | ---: | ---: |
| Cold | C1 | 154.606888 → 195.909928 | 1.066114 → 1.933074 | +81.320% | 77 / 102 |
| Cold | C4 | 278.485575 → 261.395619 | 76.946960 → 8.817094 | −88.541% | 11 / 38 |
| Cold | C8 | 323.663187 → 402.216345 | 146.709393 → 5.177863 | −96.471% | 10 / 38 |
| Warm | C1 | 55.468590 → 50.565643 | 1.254528 → 1.109631 | −11.550% | 175 / 172 |
| Warm | C4 | 95.569278 → 91.517544 | 7.037382 → 10.201156 | +44.957% | 64 / 61 |
| Warm | C8 | 234.798170 → 167.838331 | 8.491099 → 21.117504 | +148.702% | 60 / 57 |

Cold C4/C8 ping responsiveness improved substantially while warm C4/C8 ping p99 regressed. The 20-millisecond ping loop and resource sampler remain inside the experiment. A blocked ping loop produces fewer observations, so the ping counts differ. Each cold request p99 has only 12 samples per arm and equals the sample maximum; the 84-sample warm request p99 also equals its sample maximum. These are recorded short-cohort extremes, not production tail estimates. Controller CPU uses the controller's own `/proc` ticks and excludes deny-wrapper CPU.

### Resource observations and their limits

The following aggregates cover complete original controller rounds, including initialization, warmup where applicable, negative cases, ping and shutdown. They do not isolate a single lookup phase.

| Workload and resource | A62 | R3 | Change |
| --- | ---: | ---: | ---: |
| File ABBA waited process-tree CPU, seconds | 68.101304 | 68.510342 | +0.601% |
| File ABBA maximum sampled controller RSS, KiB | 17,148 | 17,704 | +3.242% |
| File ABBA maximum sampled tree RSS, KiB | 111,764 | 112,944 | +1.056% |
| Reuse whole-round `wait4` CPU, seconds | 17.014444 | 19.325804 | +13.585% |
| Reuse maximum sampled controller RSS, KiB | 16,156 | 16,620 | +2.872% |
| Reuse maximum sampled tree RSS, KiB | 99,916 | 97,720 | −2.198% |

The R3 soak's sampled controller/tree RSS maxima were 18,404/128,764 KiB. The small-archive `wait4` maxRSS values were A62 22,256/34,872 KiB and R3 25,224/30,080 KiB. Reuse `wait4` maxRSS values were A62 32,316/43,832 KiB and R3 40,540/42,400 KiB. OS process-lifetime maxRSS, sampled controller RSS and a sampled sum of visible descendants are different measurements; none is a steady-state Rust heap measurement or a separate phase peak.

The four file ABBA rounds recorded 3/2/3/1 resource observation errors in ABBA order, and the R3 soak recorded 16. Reuse rounds recorded 20/24/10/12 errors, for 66 total; four were FD permission errors and the rest included short-lived descendants disappearing and incomplete `/proc` reads. These are retained observation failures, not failed tool calls. Sampled process-tree sums are non-atomic, phase-embedded peaks accumulate from controller startup, and missing observations prevent complete RSS/FD bounds. In particular, the lower sampled reuse tree RSS alone does not establish reduced memory use.

## R2 measured results

These values were independently recomputed from the original R2 evidence package, SHA-256 `24267c691bb12bccfa8b3baa257c4dda57573456c064de5961eb6353374a1d37`, using the original call journals, reuse event logs and registry samples. A62 is the baseline in every table in this section; none of these measurements describe R3. The [package verification record](../tests/evidence/20261028-x230/r2-package-verification.json) and compressed original manifest preserve the evidence identities.

### Six-host file observation and soak

Each concurrency level has 192 successful measured calls per arm, for 1,152 measured calls across the file ABBA. Throughput is total measured calls divided by the sum of the two original cell durations; latency percentiles merge the original calls.

| Concurrency | A62 calls/s | R2 calls/s | Rate change | Controller CPU ms/call, A62 → R2 | Request p99 ms, A62 → R2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| C1 | 3.870138 | 3.862015 | −0.210% | 126.666667 → 130.520833 | 453.279993 → 432.405375 |
| C4 | 14.742280 | 15.143127 | +2.719% | 77.395833 → 76.718750 | 440.600389 → 464.180298 |
| C8 | 21.552221 | 21.610235 | +0.269% | 73.437500 → 72.864583 | 564.505857 → 578.118931 |

This is one short ABBA block over six immutable 44–48 byte outputs. The small C4/C8 rate increases accompany p99 increases of 5.352% and 2.412%; they do not establish a stable production gain. The measured operations are `file_info` and `binary_read`, so the result does not quantify multi-host launch throughput or bulk bandwidth.

The configured 120-second C8 soak completed 2,592 measured calls with zero failures. Measured cell time totaled 121.539283 seconds and helper lifetime was 129.282278 seconds. Rate was 21.326438 calls/s; p95, p99 and maximum latency were 501.802441, 594.433297 and 994.189709 ms. Controller CPU was 74.039352 ms per successful call. This is the recorded 120-second experiment, not a 600-second soak.

### Small archive guard

With 64 records, C1 and 2,048 measured calls per arm, rate decreased from 176.889428 to 169.628267 calls/s (−4.105%). Controller CPU increased from 4.868164 to 5.097656 ms/call (+4.714%); overall p99 was 11.801555 → 11.808256 ms.

| Tool | Mean latency ms, A62 → R2 | Mean change | p99 ms, A62 → R2 |
| --- | ---: | ---: | ---: |
| `usage_stats` | 3.941527 → 4.099538 | +4.009% | 6.671276 → 6.587533 |
| `request_history` | 3.087835 → 3.123452 | +1.153% | 5.379246 → 4.827424 |
| `request_archive` | 7.399732 → 7.890880 | +6.637% | 12.215804 → 12.655037 |

### Local MCP reuse: cold and warm results

The 576 successful calls cover real MCP, lookup and audit with locally denied status probes, as specified in the method below. All 576 status attempts were denied before real SSH execution; real SSH execution and remote effects were zero. Each arm and concurrency level contributes 12 cold calls and 84 warm calls.

| Phase | Concurrency | A62 calls/s | R2 calls/s | Rate change | Controller CPU ms/call, A62 → R2 | CPU change |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Cold, six original keys | C1 | 8.511469 | 5.391451 | −36.657% | 81.666667 → 147.500000 | +80.612% |
| Cold, six original keys | C4 | 19.664729 | 12.041549 | −38.766% | 85.000000 → 210.000000 | +147.059% |
| Cold, six original keys | C8 | 20.538150 | 12.232071 | −40.442% | 85.000000 → 220.000000 | +158.824% |
| Warm | C1 | 23.967081 | 23.765074 | −0.843% | 6.547619 → 6.785714 | +3.636% |
| Warm | C4 | 62.987500 | 58.455391 | −7.195% | 5.119048 → 5.714286 | +11.628% |
| Warm | C8 | 61.747631 | 65.215872 | +5.617% | 5.595238 → 5.714286 | +2.128% |

Cold request p99 was 154.651749 → 236.646712 ms at C1, 271.928606 → 315.358447 ms at C4, and 294.632379 → 494.412669 ms at C8. Each of these percentiles has only 12 observations per arm and equals the corresponding sample maximum; it is not a production p99 estimate.

At the same time, the async executor remained more responsive during cold load: C4 ping p99 fell from 141.485076 to 5.537629 ms (−96.086%, 11/47 A62/R2 ping observations), and C8 from 232.745298 to 6.155174 ms (−97.355%, 7/46 observations). These responsiveness gains coexist with lower cold throughput and increased CPU. Warm C4 ping p99 increased from 4.998414 to 16.565649 ms; short warm cells do not establish a stable benefit from the C8 rate increase. Controller CPU here measures the controller's own `/proc` ticks and excludes deny-wrapper CPU.

### Synchronous registry microbenchmark

Four fixed ABBA blocks retain 16 process samples, eight per binary, with zero failures and zero retries.

| Metric | A62 median ms | R2 median ms | Change | R2/A62 in the four paired blocks |
| --- | ---: | ---: | ---: | --- |
| Cold lookup | 78.195000 | 150.370500 | +92.302% | 1.916378, 1.749816, 1.940858, 1.941023 |
| Hot reuse | 0.057500 | 0.042000 | −26.957% | 0.775862, 0.690265, 0.745283, 0.787611 |
| Legacy sorted scan | 74.792500 | 139.059000 | +85.926% | 1.815163, 1.869834, 1.888272, 1.864661 |
| Streamed scan | 64.509000 | 130.442500 | +102.208% | 1.964382, 2.022809, 2.018788, 2.032959 |

Cold means an empty process-local cache; the operating-system page cache was uncontrolled. Each legacy/streamed value emitted by a test process is itself the median of six internal measurements. Those 12 internal raw times were not printed and are not claimed as retained evidence. This synchronous test does not measure async MCP throughput or multi-host TPS.

### Resource observations and their limits

Whole-round waited process-tree CPU for the file ABBA was 66.531621 → 68.019886 seconds (+2.237%), including warmup, negative cases and shutdown. Maximum sampled controller RSS was 17,188 → 17,884 KiB (+4.049%); maximum sampled tree RSS was 119,888 → 127,776 KiB (+6.579%). The soak's sampled controller/tree RSS maxima were 18,468/128,300 KiB.

For reuse, whole-round `wait4` CPU totaled 16.690276 → 20.731739 seconds (+24.214%). Maximum sampled controller RSS was 15,684 → 16,752 KiB (+6.809%). Sampled tree RSS maxima were 100,596 → 87,400 KiB (−13.118%), but sampling time, visible descendants and non-atomic summation prevent treating that decrease alone as a memory improvement. Resource peaks embedded in a phase accumulate from controller startup and are not independent phase peaks. The small-archive `wait4` maxRSS values were A62 22,264/35,216 KiB and R2 25,476/30,392 KiB; these are process-lifetime OS accounting values, not steady-state Rust heap measurements.

Resource observation was incomplete. The four native file ABBA rounds recorded 4/2/2/0 observation errors, and the soak recorded 19; these were descendant `/proc/PID/fd` permission errors. Reuse rounds recorded 20/19/20/32 errors, mainly short-lived descendants exiting and FD permission errors. A62 round 0 also observed the controller exiting during shutdown. These are preserved observation failures rather than failed tool calls. They make the FD maxima incomplete and prevent claims of zero observation errors or generally lower memory use. R2 therefore demonstrates recovery correctness and improved cold-load executor responsiveness, together with explicit cold-throughput, CPU and other regressions.

## Changes in this integration

### Bounded lookup work without blocking the async executor

Job binding lookup moves its synchronous filesystem scan into a blocking worker with four global admission permits. A permit follows the actual worker even if its caller is cancelled. Cancelling while waiting for admission does not submit work. The existing per-key launch lane and execution fence remain with the caller; a read worker cannot launch or replay a job.

Exact-key lookup validates every existing JSON receipt, including unrelated corrupt history and duplicate bindings. The positive reuse cache is capped at 4,096 entries. Linux content watches invalidate positive hits on in-place writes and permission changes as well as directory changes. A missing watch never authorizes a positive hit. Each event drain is limited to 64 read attempts and 16,384 events, including interrupted attempts; exhaustion retires its tokens and returns an error rather than monopolizing a shared lock.

Without a reliable watch, lookup uses two complete streaming scans with decoded-record fingerprints. It does not collect or sort all pathnames. The same root identity is pinned, sustained mutation is limited to three attempts, and malformed or duplicate history fails immediately. Memory scales with the selected record and one current input, subject to the existing four-MiB record limit, rather than the number of receipts. The four-worker cap bounds concurrent work, not the duration of a stalled filesystem operation.

A previously strict original is re-read within the final validation fence, preventing a permission downgrade between the first read and a compatibility scan. Strict cached reads use `O_NONBLOCK` as well as `O_NOFOLLOW`, so a regular-file-to-FIFO race cannot occupy a worker indefinitely. Only an actually strict-validated record can acquire strict cache status; compatible legacy records continue through full validation.

### Archive concurrency and allocation work retained from A56–A62

Two FIFO shared readers may validate eligible snapshots concurrently. Queued writers cannot be bypassed, and reservations cover actual I/O completion rather than only the lifetime of the waiting future. The batching collection window is two milliseconds; existing three-second operation deadlines remain unchanged.

Snapshot reuse requires a reliable content watch, a stable owned root, matching generations, no pending write, and final database/watch identity checks. Borrowed JSON field validation, reused binary identifiers, stack filename buffers and shared namespace metadata reduce repeated allocations and syscalls. Removed diagnostics are not counted as performance improvements.

### Durable execution and conservative recovery

Startup intent and owner namespaces retain their required directory-sync barriers. Captured output tracks EOF, byte caps, errors, truncation and fsync; file EOF alone does not prove complete output. A versioned terminal result is confirmed only by the witness bound to the exact original receipt bytes.

`jobctl status` re-reads terminal evidence after querying systemd. A collected or failed unit without a confirmed terminal result is reported as non-authoritative with unknown outcome and automatic retry disabled. Reboot without terminal evidence also preserves unknown outcome. A late cancellation acknowledgment cannot overwrite an already witnessed original success or failure. Legacy receipt behavior remains explicit and compatible.

Native lost-ack observation and safe persisted record reads from PR 75 are retained. Shutdown now freezes direct SSH transport alongside queued requests, operations and pooled observations. Linux direct SSH children retain the parent-death ownership guard from A62.

## Validation method

The qualification runner formats the frozen source, runs strict all-target/all-feature Clippy, builds all test executables, and executes every non-ignored exact case in a fresh process. Each original command, inventory, output and executable hash is retained. An independent auditor rejects exit-zero-with-no-test and running-zero-tests false positives, checks exact coverage and ignored identities, and verifies original compressed logs and executable hashes. Tests are not automatically retried.

Release binaries and source maps are bound to the completed gates. Native validation uses a current forwarded SSH agent and the existing pinned host-key profile, with fresh private fixtures on the six configured hosts. Its stages include inherited-pipe cases, six original running jobs surviving controller SIGKILL, file observation ABBA at C1/C4/C8, and a separately labelled 120-second C8 soak. No credentials or host-key checks are bypassed. A sampled compiler or heptabao workload invalidates the affected performance stage rather than being stopped.

The registry microbenchmarks compare retained A62/R2/R3 test executables in separately identified fixed ABBA cohorts. They measure synchronous exact-key lookup, not end-to-end job launch throughput. The six-host file benchmark measures tiny immutable files, not bulk transfer bandwidth. Every measured sample and failure remains part of its report.

### Local reuse throughput method — R2 and R3 series completed

Each separate reuse benchmark measures **real stdio MCP + original-key lookup + audit + denied local SSH status probes**. It uses the retained A62 release and the qualified candidate release in four fixed ABBA rounds: one series for R2 and another for R3. Each round starts one controller with two Tokio workers, uses one stdio connection, and runs C1, C4 and C8 cells with 48 reuse calls each: 576 calls per complete series. A 20-millisecond ping loop and resource sampling remain part of the measured local workload.

Each cell explicitly invalidates the positive cache and first submits six distinct original keys, followed by 42 warm calls. The C8 cold wave therefore contains only six unique keys and has at most six requests in flight. “Cold” means the explicit in-process cache invalidation; the operating-system page cache is uncontrolled. The registry also contains 6,000 clearly synthetic historical receipts whose keys are never submitted.

Pooling the two rounds per arm gives 12 cold and 84 warm requests per concurrency level; nearest-rank p99 equals the sample maximum for both phases.

Original-key reuse still attempts to observe remote status. The harness places only a private deny-wrapper on the controller's SSH search path; the wrapper records each attempt and exits before executing real SSH. Both completed series passed all 576 calls with `real_ssh_execs=0` and `remote_effects=0`, retained the original job identities and receipt bytes, returned `reused=true`, `retried_launch=false`, `launch=null` and the expected `status_unavailable`, and allocated no replacement key. Each result remains bound to its own candidate and cohort. This workload does not measure remote launch throughput, normal remote status latency or multi-host network throughput.

Every original RPC/ping event, denied probe, measured resource sample and `wait4` result is retained. Failed requests are not retried to improve the reported outcome.

## Original evidence packages

The canonical archives retain original commands, logs, reports and selected journals under `tests/evidence/20261028-x230/`. Their exact byte identities are:

| Archive | Bytes | Original files | SHA-256 |
| --- | ---: | ---: | --- |
| [R2 originals](../tests/evidence/20261028-x230/r2-originals.tar.gz) | 8,318,165 | 6,522 | `24267c691bb12bccfa8b3baa257c4dda57573456c064de5961eb6353374a1d37` |
| [R3 originals](../tests/evidence/20261028-x230/r3-originals.tar.gz) | 7,425,655 | 3,537 | `642ebfcf2c98091903d8c4ccf80f687a26767ec3a7971f83cccf0c619af9ac5b` |
| [R3 supplement originals](../tests/evidence/20261028-x230/r3-supplement-originals.tar.gz) | 1,598,520 | 3,090 | `4161b7bfc82ef8403e4306442562da8889a6412f6f024e4f41ced9705c89f3f2` |
| [R3 diagnostic originals](../tests/evidence/20261028-x230/r3-diagnostics-originals.tar.gz) | 925,330 | 34 | `2ad3449db5482f0a82ab247f0609d56a3c717e950a4e4db6b1833c4ac3663944` |

R2's compressed [manifest](../tests/evidence/20261028-x230/r2-originals.manifest.json.gz) records its selected files and omitted executable, configuration and duplicate-fixture classes. The R3 main archive contains qualification, the successful native cohort and remote lease, reuse, and A62/R3 registry evidence. Its supplement retains the initial native preflight refusal and lease together with the direct R2/R3 registry comparison. The [R3 package verification](../tests/evidence/20261028-x230/r3-packages-verification.json) checks all 3,537 main and 3,090 supplement members against their manifests. The diagnostic archive retains original syscall diagnostics, benchmark preflight/load samples and stdout/stderr; traced elapsed times remain excluded from performance samples.

Main-side lease evidence is retained separately in [R2](../tests/evidence/20261028-x230/native-main-originals.tar.gz), [R3 completed](../tests/evidence/20261028-x230/native-main-r3-originals.tar.gz), and [R3 preflight-refused](../tests/evidence/20261028-x230/native-main-r3-preflight-originals.tar.gz) archives so nonce and remote-completion identities can be matched to the corresponding remote lease. The completed R3 main lease records its original child reaped with return code zero; the refused attempt records its child reaped with return code one. Package completeness describes retained evidence, not experiment success or a performance gain.

## Persistence trust boundary

The private registry and its cooperating owner are part of the trust boundary. These scans are not filesystem transactions: two scans cannot prove a single atomic snapshot against an unrelated same-UID writer that repeatedly changes bindings between reads. Inotify also does not report memory-mapped writes; see the Linux [inotify(7) limitations](https://man7.org/linux/man-pages/man7/inotify.7.html). Consequently, positive caching is not an integrity boundary against an uncooperative process with the same filesystem authority. Such a threat model requires a shared write protocol or a separate protected storage service. Normal receipt publication, detectable mutation, watcher loss and bounded validation failures remain conservative.

## Practical stopping criteria and remaining limits

A candidate is accepted only after the exact source passes the required gates and each performance claim has an appropriate measured scope. A failed gate is retained with its explanation. Repeating measurements merely to obtain a favorable run is not an optimization.

The cold-lookup review found no second small patch after R3 with both established cost attribution and unchanged validation semantics. The remaining linear scan still validates every historical receipt: pathname metadata, a guarded open, opened-file metadata, bounded reading and complete decoding, then descriptor/path metadata checks. Those checks cover different objects or times. Removing them, decoding only selected fields, or accepting an unchecked positive cache would change the current contract. Minor loop or epoch-probe changes have no profile evidence showing a comparable removable cost.

This iteration stops at R3 because its exact qualification, applicable native checks and fixed benchmark cohorts are complete, the attributed read amplification has been removed, and the remaining review found no second small patch justified by both measured cost and unchanged validation semantics. This is a stopping decision for this design and workload, with the cold-throughput, CPU and resource regressions above retained. The completed checks are:

1. R3 passed its own qualification, recovery/identity checks and eight native stages. The first preflight refusal and reaping evidence remain preserved alongside the fresh successful cohort.
2. The report separates cold lookup, warm reuse, streamed scans, C1/C4/C8 throughput, CPU per call, ping responsiveness and resources. Direct R2/R3 registry ABBA and A62/R3 experiments are identified separately; no cross-session R2/R3 native or reuse speedup is claimed.
3. The direct R2/R3 registry medians and repeated scan ratios support the buffer-reuse change, while the diagnostic read counts agree with the removed read amplification. The cold outlier, regressing paired block and hot mean regression remain included. The A62 comparison still shows substantial cold-scan and cold-reuse regressions.
4. No additional avoidable cost with a small, semantics-preserving remedy was established. Further source changes require new evidence of a concrete failure or attributable cost, such as unexpected repeated scans, watcher degradation, a redundant syscall or a function shown to dominate CPU without a required validation purpose.

Larger gains from sharing one scan across concurrent cold requests or adding a persistent index need a separate coordination and recovery design. Shared scans need per-key duplicate and strict-final-read rules, cancellation ownership, fairness and bounded memory. A persistent index additionally needs atomic receipt/index publication, fsync and crash authority, reconstruction and conservative handling of missing or stale entries. The current evidence does not justify approximating those protocols with another local fast path, and does not establish a theoretical performance optimum.

These experiments do not prove behavior during physical power loss, target reboot, WAN partition or production ownership transfer. They do not establish globally optimal throughput. Further work that changes the persistence contract, relaxes validation, depends on new hardware, or requires a distinct workload needs a separate design and experiment; those changes are not implied by a faster microbenchmark.
