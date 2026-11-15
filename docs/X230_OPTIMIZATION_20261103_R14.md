# X230 R14: independent cancellation preparation admission

Date: 2026-11-03 UTC. Lineage: X230 PR #87 following R13.

R14 limits physical receipt validation and durable-intent preparation to two operations while retaining eight publication/remote continuations. The new preparation semaphore is independent of launch and observation pools. Both permits are acquired asynchronously before spawn_blocking; submitted work retains custody after caller cancellation. Preparation ends before remote awaits, and completion auditing never requires a preparation permit.

Only jobs.rs, jobs_cancel_io_tests.rs and jobs_cancel_read_tests.rs change. Receipt validation, original errors, descriptor/host bindings, durable file-sync/rename/directory-sync ordering, idempotency and remote protocol remain intact. Waiting for the audit lock occupies preparation capacity. This is a physical-work budget, not a process-wide memory limit or a limit on every remote attempt that outlives an abandoned caller.

## Decision and measured tradeoff

For large escaped receipts, R13 to R14 reduces CPU/mixed RPC by 30.83%/28.14%, host_list p95 by 58.00%/57.20%, VmHWM by 16.42%/26.37% and post-workload VmRSS by 10.89%/21.38% at one/two Tokio workers. The cost is throughput -14.33%/-19.45% and cancellation p95 +12.10%/+32.30%.

Against R11, large-receipt CPU remains +7.01%/+3.80%, and post-workload RSS remains about 6.68/6.23 times the baseline snapshot. One-worker throughput improves 76.90%; two-worker throughput falls 2.18%. The approximately 100 MiB residual memory motivates further diagnosis.

Native six-host throughput changes are -0.98%/-1.11%/-3.45% at C1/C4/C8; C8 p95 rises 7.71%. This checkpoint does not establish a general multi-host speedup. All expected functional and recovery outcomes passed.

## Qualification

Final qualification-01 completed at 2026-11-03T21:13:05.189319Z. Raw independent audit: **1637 passed, 0 failed, 33 ignored, 1670 unique selected cases, zero retries**. Ignored cases are not executed passes. All **219 compiler inputs** match frozen, tested, post-qualification and current maps. Three release artifacts and the retained libtest were independently hashed.

The new test preserves eight publication continuations with only two preparation slots. Extended tests cover submitted versus unsubmitted cancellation, queued blocking work, real audit-lock contention, closed preparation admission, exact original refusal errors, zero remote effects before intent, executor liveness, original bytes and completion auditing while preparation capacity is fully occupied. One test was added and two renamed; remaining identities/statuses are unchanged.

Rust 1.95.0, offline/locked/all-features/all-targets, two Cargo jobs and disabled incremental compilation follow the recorded qualification. Release uses panic=abort: test-profile unwind capture is not in-process release panic recovery.

| Stage | Exit | Seconds |
|---|---:|---:|
| format | 0 | 2.420 |
| fmt-check | 0 | 2.521 |
| harness-tests | 0 | 6.185 |
| clippy | 0 | 49.738 |
| test-build | 0 | 703.822 |
| isolated-tests | 0 | 249.893 |
| audit-isolated-tests | 0 | 5.426 |
| release | 0 | 329.006 |

| Artifact | SHA-256 |
|---|---|
| hepta-runtime | `51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d` |
| hepta-runtime-jobctl | `84572095b80a56ff893ea41b01e170444dc2483a49091277d0b4ada4fbc1c1b0` |
| native_process_driver | `551aa5ba0f990908d0143c34f513a0f1937f14198335c5e4a611a112b82f944e` |
| retained libtest | `fe880a56037ace61fa44a33156e3465792a77a2096adc81af1d7704f5aed445f` |

## Cancellation campaigns

Each comparison is a separate ABBA campaign: 16 fresh controller processes, 24 measured plus two warmup waves per process; each wave contains eight cancellations and one host_list. Per arm/case, **432 measured mixed RPCs = 384 cancellations + 48 host-list calls**. Each full campaign has 3,456 measured + 288 warmup = 3,744 validated replies.

Fixtures deliberately bind to the wrong host. Expected refusals occur before audit intent or SSH; this is not successful remote-cancellation throughput. CPU is controller CPU divided by all measured mixed RPCs. Rate is total calls divided by measured wall time. P95 uses nearest-rank over 48 host-list or 384 cancel observations. Memory medians use two children: VmHWM is lifetime high water including startup/warmup; VmRSS-after is the post-workload snapshot. These are not per-request allocations.

Every paired cell below is baseline to candidate. Negative small-receipt outcomes are retained. The independent audit rechecks matrices, finite values, denominators, retained response hashes and refusal semantics. Separate campaigns are not pooled; two children per arm do not establish statistical significance. Projection was not repeated because its decoder is unchanged.

### R13 to R14

| Workers | Receipt bytes | CPU ms/mixed RPC | Mixed RPC/s | Host-list p95 ms | Cancel p95 ms | VmHWM KiB | VmRSS-after KiB |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1024 | 1.7593 → 1.7593 | 536.967 → 539.833 | 18.7118 → 18.6818 | 17.5623 → 17.8287 | 14314 → 14250 | 14314 → 14250 |
| 1 | 4194272 | 36.3426 → 25.1389 | 91.385 → 78.290 | 42.2022 → 17.7235 | 105.8392 → 118.6445 | 125306 → 104736 | 117540 → 104736 |
| 2 | 1024 | 1.8750 → 1.8981 | 532.737 → 519.500 | 18.7060 → 19.3124 | 17.1327 → 17.8749 | 15600 → 15490 | 15600 → 15490 |
| 2 | 4194272 | 36.1111 → 25.9491 | 93.605 → 75.395 | 46.2571 → 19.7995 | 97.2212 → 128.6218 | 137380 → 101152 | 128656 → 101152 |

### R11 to R14

| Workers | Receipt bytes | CPU ms/mixed RPC | Mixed RPC/s | Host-list p95 ms | Cancel p95 ms | VmHWM KiB | VmRSS-after KiB |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1024 | 1.7130 → 1.7824 | 525.066 → 518.760 | 18.7816 → 20.9807 | 17.8987 → 21.3611 | 13836 → 14242 | 13836 → 14242 |
| 1 | 4194272 | 23.4491 → 25.0926 | 44.630 → 78.948 | 211.7348 → 16.4686 | 208.1860 → 117.6233 | 22026 → 94424 | 14136 → 94424 |
| 2 | 1024 | 1.8056 → 1.8519 | 538.250 → 545.105 | 17.5102 → 17.7381 | 16.5628 → 16.3894 | 15362 → 15460 | 15362 → 15460 |
| 2 | 4194272 | 24.9769 → 25.9259 | 77.235 → 75.553 | 134.9406 → 26.8917 | 131.6251 → 124.5512 | 33926 → 96786 | 15532 → 96786 |

## Six-host native observation

Hosts: ai395, mac, main, pocket4, rog and x230, using frozen job references and the recorded profile. Operations are process_status and process_read, not process_wait. ABBA order, C1/C4/C8, 96 measured and 24 warmup calls per cell: each arm/C has 192 measured calls. Totals: **1,152 measured + 288 warmup + 72 verification = 1,512 calls**, zero automatic retries. Warmup/verification are excluded from performance denominators.

CPU uses synchronous utime+stime deltas for the same controller PID/start generation, not whole-cluster CPU. Native reports do not retain complete transport envelopes; the independent audit checks saved results and statistics without claiming to recompute hashes of unretained response bodies.

| C | CPU ms/call | Calls/s | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|
| 1 | 129.7917 → 128.4375 | 4.3047 → 4.2625 | 290.4175 → 295.6455 | 302.5247 → 334.0002 |
| 4 | 72.2396 → 72.8646 | 18.1780 → 17.9762 | 291.8243 → 283.2627 | 308.8488 → 344.2123 |
| 8 | 71.4062 → 72.7604 | 23.4318 → 22.6239 | 408.4860 → 439.9937 | 438.2807 → 459.9188 |

C1/C4 p99 rises 10.40%/11.45%; C8 p95 rises 7.71%. Whole-controller VmHWM and sampled RSS-peak medians are 17,210 to 17,188 KiB, spanning all concurrency levels, warmup and checks rather than per-C allocations. FD permission errors and incomplete/non-simultaneous sampled process-tree metrics remain in the evidence. No sampled tree CPU substitutes for the controller numerator.

## Concurrent cancellation and recovery

The selected R14 release passes **90 native replies, 36 independent SSH probes, 72 stream-file checks and 150 embedded-file hashes** (224,885 embedded bytes). Six starts and twelve same-key lookups preserve original identities and exactly one execution witness per host. Twelve cancellations have zero automatic retries or extra terminal polls.

The six initial cancellation RPCs start within 2.330 ms with C6 peak overlap. This is live RPC concurrency, not proof of successful C8 remote throughput. The campaign kills its private ROG SSH master and isolated controller, restarts the controller, confirms terminal status and retained exit/output/witness data, then repeats terminal cancellation.

Linux live ACKs say stop_requested, macOS says term_sent, and terminal repeats say already_exited. These ACKs do not themselves prove termination; independent status and durable exit/witness data do. No production-service restart, physical power loss, target reboot, WAN partition, cross-owner migration or universal external-side-effect exactly-once guarantee is claimed.

## Additional memory diagnosis

Two short diagnostic campaigns use fresh children with the same qualified R14 binary and large escaped fixture: default/arena-2/arena-2/default, then arena-1/arena-4/arena-4/arena-1. Each child runs two warmup and 24 load waves, then remains idle for 12 seconds. Each wave contains eight cancellation refusals plus one host_list. CPU covers ready through load, including warmup: **234 mixed RPCs per child = 208 cancellations + 26 host-list calls**.

The following are descriptive means of two children per setting. VmHWM covers the whole child lifetime. Idle VmRSS is the snapshot after 12 seconds; neither is a per-request allocation.

| Allocator setting | Ready-to-load CPU s | Whole-child VmHWM KiB | Idle VmRSS KiB |
|---|---:|---:|---:|
| default | 6.225 | 102028 | 102028 |
| arena 1 | 6.315 | 30788 | 17244 |
| arena 2 | 6.375 | 39014 | 17476 |
| arena 4 | 6.340 | 52988 | 36424 |

Arena 1 has the lowest observed high water, 21.08% below arena 2; idle RSS is similar. Its descriptive CPU mean is 1.45% above default. Settings 1 and 4 were measured in a separate campaign, and background archive/audit I/O may overlap: small cross-campaign CPU differences are not strong causal comparisons, and no diagnostic throughput improvement is claimed.

All settings reach approximately 19-20 process threads and retain 10 after idle. Multiple Tokio-named thread generations accumulate preparation CPU. Default idle RSS remains about 100 MiB after thread retirement, while explicit arena limits reduce retained memory. Anonymous reservation-like address-map pairs support allocator retention but are not a direct enumeration of glibc arenas. Limiting arenas does not limit Tokio threads or change the preparation/publication budgets.

The independent summary rechecks all eight children, CPU ticks, 41 snapshots, 1,872 complete response hashes and semantics, and 24 smaps hashes. No SSH dispatch or intent occurs, and fixtures remain unchanged. Summary SHA-256: 053996e41ebb0b29d9e76f92ed381bb7af0c9db5a22298ae2d92cb6803586020. Arena 1 is selected for formal R15 configuration evaluation; these diagnostics do not establish its final native-concurrency cost.

The next candidate evaluates a separately recorded X230/glibc execution profile. Qualified Rust source remains immutable during configuration experiments. A custom worker executor would require new lifecycle, panic and shutdown evidence and is not assumed necessary or beneficial.

## Evidence and provenance

| Independent audit | SHA-256 |
|---|---|
| qualification | `667e9e966b43ce1e14c228b0ab7ab9b8fc017c26c95a41adba4e97cea1487ff3` |
| performance | `03e030f4329b0037069ba63687e1a1ebcaf42ccba472b026d8d5b5ddffe0dba7` |
| recovery | `128d0408c8674b21c5c53cd11f46bdeafdcdbd803bebc9a70a3e66be54fa982e` |

Precision-preserving report-data.json SHA-256: `ffa94324ddc72f4a7fe1976621d22e9fe052990b9697eded9917667e52b4c0fd`. Individual RSS/HWM samples and exact values are retained there. The three independent audits completed at 21:18:23 UTC with exit zero and no retry.

The candidate Git source tree was independently checked for all 219 input blobs/modes before qualification; the later audit binds the same frozen bytes to actual tests. Preupload metadata honestly retains candidate-awaiting-qualification status from its creation time. Later qualification/audit artifacts establish the successful outcome; those earlier records are not rewritten.

The [original evidence archive](../tests/evidence/20261103-x230-r14/r14-original-evidence-01.tar.gz) preserves **21,815 original files / 128,579,625 original bytes**. Its **21,816 members** include the selection manifest; every member was reread and hash-verified. Source trees, targets and compiled binaries are excluded. The separate compressed selection index makes original path, size and digest bindings inspectable without relying on this narrative. The known credential-pattern scan found zero matches.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| r14-original-evidence-01.tar.gz | 6012006 | 3e7117c5cc229cb75b8aeff68eef382bd1b539a969fad3487519ef6344b5a619 |
| archive-selection-01.json.gz | 1619313 | 40fd2a1da591cae075ea1af123788c6be0093ca37c925f866470de9af5ce6cde |
| archive-summary-01.json | 3098 | 0d56154aaaa0e7a082233128a208bfc2495d330737a53983fa19146d552257c8 |

The archive includes the original qualification and isolated-test logs, both local comparisons, native observation, the six-host cancellation/recovery records, independent audits, compiler bindings, and both allocator diagnostics with their independent summary. Reviewed packaging tools and fixed selection rules are published alongside it. The packaging and staging I/O completed before R15 performance was released.


No absolute optimum, default-branch merge or production deployment is claimed. The checkpoint preserves successful correctness/recovery results, resource/latency tradeoffs and the next experimentally supported optimization.
