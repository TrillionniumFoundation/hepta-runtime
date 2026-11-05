# X230 runtime optimization R11 — 2026-11-03

## Status and decision boundary

This report describes the R11 source changes against the actual X230 R10e baseline.
Qualification, the comparative inventory and native observation campaigns, the independent
C4 recheck, and the bounded candidate recovery canary have completed successfully.
R11 is retained conditionally for bounded observation receipt offload and the measured
large-plain-payload inventory gains. Smaller inventory cases and native end-to-end results
remain mixed; the retention decision does not establish a general six-host speedup or
resource reduction. The controlled RSS follow-up is accounted for separately below.
The publication target is `perf/x230-r11-20261103`, with the independent R10e snapshot
`9efb50d35ed70caf59e13a430762884eb551ed23` selected as the direct parent.

The separate persistence experiment has completed and its two-pass streaming candidate
was rejected for this round. Its measured CPU cost outweighed its transient-allocation
benefit for the current serialization-under-write-lock design.
This is a bounded, evidence-based stopping decision, not proof of an absolute optimum.

## Baseline identity and lineage

| Item | Recorded identity |
|---|---|
| Historical R9 lineage anchor | `94d7fecdb02f5a7ef3d5ff072665360eb0115e0f` |
| Actual comparison baseline | X230 `source-r10e`, retained as immutable local `baseline-r10e` |
| Independent R10e snapshot commit | `9efb50d35ed70caf59e13a430762884eb551ed23`, selected direct parent for R11 publication |
| R10e source manifest | 210 path-to-SHA256 entries |
| R10e runtime SHA256 | `b4e9022de0c764f84450cb7ade4947de0858460f09a898d3c830270006cc1504` |
| R11 tested source/binary binding | 213 source entries; runtime SHA256 `660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c` |
| R11 publication binding | Branch `perf/x230-r11-20261103`; the commit containing this report has the R10e snapshot above as its direct parent |

The [R10e source map](../tests/evidence/20261103-x230-r11/r10e-source-map.json)
matches all 210 files in the immutable baseline used for this source comparison.
It also matches the input, tested, and after-run source maps in the retained
[R10e qualification record](../tests/evidence/20261103-x230-r11/r10e-qualification.json.gz).
The runtime digest above is recorded in that qualification artifact.
The historical R9 anchor does not substitute for this actual R10e source/binary identity.
The [R10e snapshot report](X230_OPTIMIZATION_20261103_R10E_SNAPSHOT.md) records that baseline's
changes and qualification. The R11 source/evidence commit uses this independent
snapshot as its direct parent on `perf/x230-r11-20261103`, preserving the actual comparison
baseline in its ancestry. Branch publication and the resulting final SHA are established
by the GitHub publication receipt, not inferred from the source or benchmark reports.

The [earlier integration report](X230_OPTIMIZATION_20261028.md) supplies campaign context.
Historical evidence applies to its original source and executable; it does not qualify R11.
The retained baseline recovery report does not record a Git commit, so no additional
commit binding is inferred from that report.

## Production delta: observation receipt reads

In [jobs.rs](../src/mcp/runtime/jobs.rs), `status_job`, `wait_job`, and `read_job`
now await `check_ref_async` instead of synchronously calling `check_ref`.
The new helper runs the complete original receipt read and validation in `spawn_blocking`.
A process-wide, independent semaphore permits at most four submitted receipt-read closures.

The permit is acquired before submission and moved into the physical closure.
It covers both time queued in the Tokio blocking pool and time executing the read.
Dropping the caller after submission does not release that permit early or stop the read.
Cancelling while still waiting for a permit submits no physical work.
The permit is released when the closure exits, before subsequent remote observation.

The original decoder, filename/record identity checks, descriptor checks, host configuration
binding, and caller-host comparison remain in `check_ref`.
No new receipt cache or remote effect is introduced.
Worker failure and a closed capacity semaphore return explicit errors.

This semaphore is independent of inventory, registry lookup, start-I/O, and audit capacity.
The Tokio blocking pool itself remains shared; there are no four dedicated OS threads.
Waiting callers are not a globally bounded admission queue.
The four slots are per process, shared across hosts, and do not bound SSH concurrency,
end-to-end request count, or the memory held by completed reads awaiting later processing.

`cancel_job` remains on its original synchronous `check_ref` and cancel intent/publication
path. It does not wait for the new observation semaphore, and its local validation can
still block the async executor. Start/reuse reconciliation and remote SSH routing are unchanged.

## Production delta: inventory projection

Both compatibility and paged inventory now decode through the complete shared
`job_record_schema!` using `JobRecordData<BorrowedJobString>`, then retain public fields.
The existing [borrowed-string module](../src/mcp/runtime/jobs_record_projection.rs)
changes only its module description in R11; its decoding implementation predates this round.

Eligible plain JSON strings borrow the current scan's input buffer.
Strings requiring JSON unescaping retain owned decoded data.
Eligible fields are `ssh_target`, `unit`, `remote_job_dir`, `executable`, `args`,
`cwd`, `env_keys`, `request_digest`, and `launch_error`.
Public string fields, `idempotency_key`, and the Vec containers still allocate.
This removes selected discarded payload copies; it is not zero-allocation decoding.

The projection closure is higher-ranked over the input lifetime, so its returned row
cannot retain the borrowed scan buffer.
Every source record is fully decoded before filtering or projection.
Malformed private fields in a host-filtered-out neighbor still reject the entire inventory.
Required fields, defaults, known-field duplicate rejection, and unknown-field compatibility
retain the original owned decoder's behavior; no private field is replaced with IgnoredAny.

The public row remains `id`, `host`, `created_unix_ms`, `execution_mode`, and `launch_state`.
Compatibility output keeps its stable creation-time ordering.
Paged output keeps identity ordering and the same serialized namespace/host/public-row digest.
The retained cursor format and response bytes are covered against an independent owned oracle.
The digest is a public-inventory binding, not a hash of every private payload byte.

Paged reads additionally reserve declared file length plus one byte using `try_reserve_exact`.
The spare byte allows EOF observation without an avoidable input-buffer growth.
Descriptor ownership, mode, link count, metadata stamps, directory identity,
membership recheck, and refusal on changes remain intact.

## Preserved durability and limits

`save_record_at` still serializes with `to_vec_pretty`, rejects oversized records before
creating a temporary receipt, uses exclusive creation and 0600 permissions, writes the
file, calls file `sync_all`, renames, and syncs the parent directory on Unix.
The registry write lock still spans path creation, serialization, and both durability barriers.
Owned recovery decoding, launch identity, pending/outcome publication, and cancel audit
ordering are unchanged. No WAL, deferred fsync, weaker identity, or new recovery protocol is added.

| Scope | Existing or new bound |
|---|---|
| Observation receipt work | New: four submitted/queued physical closures per process |
| Inventory work | Existing: four submitted/queued physical closures per process |
| Saved and ordinary-read receipt | Existing: 4 MiB |
| Paged inventory source | Existing: 65,536 JSON records and 128 MiB total source bytes |
| Paged source file | Existing: 4 MiB + 64 KiB per metadata file |
| Paged scan time | Existing: five-second cooperative checks, not syscall preemption |
| Page output | Existing: at most 128 identities and 64 KiB serialized MCP response |
| Compatibility output | Existing: 1 MiB response limit after full source validation |

Each page still scans and validates the whole source, sorts rows, and recomputes the digest.
There is no long-lived snapshot cache or page-sized-only disk read.
The compatibility API does not acquire the paged source count/byte/time limits.
Inventory results retain `status_authoritative: false` and observation-time metadata semantics.
Unchanged SSH routing and host bindings must not be described as a new multi-host protocol.

## Qualification and added functional coverage

The [R11 qualification](../tests/evidence/20261103-x230-r11/r11-qualification.json.gz) reports
`qualified: true`: format, format check, harness tests, strict Clippy, test build, isolated
tests, independent test audit, and release all exited zero. Release took 329.938 seconds.
The [isolated summary](../tests/evidence/20261103-x230-r11/r11-isolated-summary.json) records
**1,621 passed, 0 failed, 31 ignored, and 1,652 selected**, with zero automatic retries.
The [test archive](../tests/evidence/20261103-x230-r11/r11-tests.tar.gz) retains the exact-case
logs, inventories, original artifact/source manifests, and independent audit.
The [213-entry source map](../tests/evidence/20261103-x230-r11/r11-source-map.json) equals
`source_tested`, `source_after`, and all current local compiler inputs. Initial `source_input`
differs only in the benchmark module formatted by qualification; it is not claimed identical.
The following seven new functional tests are included in that completed qualification.

| Module | Exact test name | Main check |
|---|---|---|
| observation_read_tests | `cancelled_observers_keep_four_physical_readers_and_executor_responsive` | Physical capacity survives caller cancellation; executor heartbeat progresses |
| observation_read_tests | `cancelled_receipt_reads_in_blocking_queue_keep_slots_until_actual_exit` | Queued blocking work keeps permits until actual exit |
| observation_read_tests | `observation_reader_preserves_real_receipt_and_validation_errors` | Receipt/errors preserved; panic/closed-capacity failures remain errors |
| observation_read_tests | `status_wait_and_read_share_only_the_observation_receipt_pool` | Public entry wiring and independent semaphore identity |
| inventory_borrowed_tests | `paged_inventory_borrows_plain_payloads_and_preserves_complete_original_records` | Borrowed/plain and owned/escaped behavior; complete record equivalence |
| inventory_borrowed_tests | `borrowed_inventory_source_keeps_owned_responses_and_restart_cursor_bytes` | Owned response, digest, and retained cursor byte compatibility |
| inventory_borrowed_tests | `both_inventory_paths_validate_unselected_private_fields_before_filtering` | Bad type, missing field, and duplicate field remain refusals |

Sources: [observation tests](../src/mcp/runtime/jobs_observation_read_tests.rs) and
[inventory projection tests](../src/mcp/runtime/jobs_inventory_borrowed_tests.rs).
The inventory tests require Unix; the observation tests also exercise a current-thread executor.

## Comparative benchmark results and method

### Local inventory: complete 20-case matrix

The corrected campaign completed **20 cases, 80 measurement processes, 688 successful
calls, zero failed calls, and zero automatic retries**. Every case used one ABBA block,
with two independent processes per arm. An independent calculation matched all 580
reported statistical fields exactly. Full cases, raw-source identities, all directional
regressions and dispersion are in the
[inventory analysis](../tests/evidence/20261103-x230-r11/inventory-campaign-02-summary.json)
and [complete tables](../tests/evidence/20261103-x230-r11/inventory-campaign-02-tables.md).

These are **opt-level 1 libtest** measurements of the actual guarded local inventory and
wire serialization paths, with two Tokio workers and four physical inventory permits.
They are not release-server, cold-disk, or SSH throughput figures. Each fixture has 128
receipts. Its full hashes and one warmup precede timing; every measured response is checked.
All four fixture manifests and every per-case response digest match across A/B.

| Binding | SHA256 |
|---|---|
| R10e plus benchmark libtest A | `cd5e73d1df2a6def1385dd6699711ffeeeef78feea3ae7e2e0106fc360e26597` |
| Qualified R11 libtest B | `664e821762647be2bea2224aa566be2fb9d9983131c77af22f6f085cb556668b` |
| Identical benchmark module | `e0bd1eb185404122773c11415413e631d21bd04970ed1fb2764d654bdd3d1f56` |

The [baseline rebuild receipt](../tests/evidence/20261103-x230-r11/baseline-build-v2-receipt.json.gz)
binds 211 unchanged compiler inputs and exact profile/features equality with B. Only the
benchmark module and its test hook differ from the qualified R10e source.
The following table shows C4; A is R10e and B is R11.

| Payload (decoded) | Mode | CPU ms/call A → B | CPU change | Calls/s A → B | Rate change |
|---|---|---:|---:|---:|---:|
| plain 1 KiB | list | 5.299 → 5.365 | +1.24% | 374.62 → 468.60 | +25.09% |
| plain 1 KiB | page | 6.339 → 5.910 | -6.78% | 401.11 → 430.62 | +7.36% |
| plain 64 KiB | list | 12.101 → 11.563 | -4.45% | 210.63 → 230.52 | +9.44% |
| plain 64 KiB | page | 12.299 → 11.652 | -5.26% | 205.40 → 191.93 | -6.56% |
| plain 768 KiB | list | 95.566 → 77.840 | -18.55% | 28.64 → 34.97 | +22.10% |
| plain 768 KiB | page | 94.788 → 78.066 | -17.64% | 26.54 → 29.03 | +9.38% |
| escaped 64 KiB | list | 158.978 → 154.745 | -2.66% | 17.50 → 17.89 | +2.20% |
| escaped 64 KiB | page | 157.066 → 146.317 | -6.84% | 15.11 → 19.21 | +27.11% |

All six plain 768 KiB cases reduced CPU/call by **16.45–20.27%** and increased measured
calls/s by **9.38–23.37%**. This is the most consistent result in the matrix. CPU/call fell
in 18/20 cases and calls/s rose in 17/20. Smaller and escaped cases are mixed:
plain 64 KiB list C8 lost 9.60% calls/s and its p95 rose 37.37%; plain 64 KiB page C4
lost 6.56% calls/s. The complete tables retain all smaller reversals as well.
No universal throughput or tail-latency improvement is claimed.

This was a shared X230. Both endpoint snapshots recorded cargo PID 1950444, with no
rustc entry; snapshots cannot establish absence of intervening/background work.
Temperatures changed from 65/69°C to 74/73°C. Some two-sample arm rates differ widely
(max/min differences reach 92.68%). Per-arm latency counts are only 4/16/32 at C1/C4/C8;
nearest-rank p95 at C1 and C4 is the maximum observed latency. These are descriptive
measurements without a statistical-significance claim.

### RSS measurement qualification

The original full-process RSS columns remain in the immutable reports. Their medians are
identical in 19/20 cases (plain typically 25,320 KiB, escaped 20,464 KiB); they do not
establish broad RSS savings. A [small accounting probe](../tests/evidence/20261103-x230-r11/rss-floor-probe.json.gz)
confirmed inherited pre-exec high-water contamination: after a Python parent touched
32 MiB, both a direct true process and a fresh Python interpreter reported 49,408 KiB.
Running the same interpreter as GNU time's direct child instead gave 9,344 KiB internally
and 9,472 KiB at exit, while the outer wrapper still reported 49,408 KiB.

The controlled follow-up completed **four C4 cases, 16 measurement processes and 128
successful calls**, with no failed calls or automatic retries. It used the identical
qualified Rust binaries and benchmark module. The Python runner optionally launches
the Rust test as GNU time's direct child, pins the launcher's SHA256 before and after,
retains the native usage text/hash and wrapper wait4 RSS separately, and checks both exit
statuses. Original evidence is in the
[follow-up campaign](../tests/evidence/20261103-x230-r11/inventory-rss-campaign-03.json.gz),
[plain samples](../tests/evidence/20261103-x230-r11/inventory-rss-plain.json.gz), and
[escaped samples](../tests/evidence/20261103-x230-r11/inventory-rss-escaped.json.gz).
The [independent analysis](../tests/evidence/20261103-x230-r11/inventory-rss-campaign-03-summary.json)
reproduces all 132 numeric statistical fields exactly and verifies all 20 native usage
receipts (16 measurement children and four enumeration children). The
[complete RSS tables](../tests/evidence/20261103-x230-r11/inventory-rss-campaign-03-tables.md)
also retain every individual peak, latency reversal and host-environment limitation.

| C4 payload | Mode | Median whole-child peak RSS KiB A → B | RSS change | CPU ms/call A → B | Calls/s A → B |
|---|---|---:|---:|---:|---:|
| plain 768 KiB | list | 25,022 → 20,664 | -17.42% | 92.656 → 78.618 | 28.90 → 32.72 |
| plain 768 KiB | page | 23,992 → 21,470 | -10.51% | 93.951 → 76.266 | 28.52 → 34.00 |
| escaped 64 KiB | list | 15,824 → 16,150 | +2.06% | 155.451 → 145.876 | 18.01 → 16.85 |
| escaped 64 KiB | page | 16,414 → 16,724 | +1.89% | 158.044 → 145.494 | 14.23 → 19.48 |

Each median contains two whole-child peaks per arm. These peaks include fixture handling,
warmup, measured work and report construction; they are not incremental memory for a
single request or a production-controller resource bound. The outer Python-child wait4
floor remained 25,572 KiB for plain and 20,916 KiB for escaped, and is not substituted for
the native direct-child result. Large plain cases reduced measured RSS, while escaped
cases used about 2% more. This does not establish a general memory reduction.
Escaped-list throughput was also 6.43% lower in this follow-up despite lower CPU/call;
the short repeated measurements remain workload- and scheduling-dependent.
CPU/wall timing intervals are unchanged by the RSS accounting issue. This supplemental
ABBA block is kept separate from the original 20-case performance matrix.

### Six-host native release MCP observations

The first release ABBA completed **1,152 measurement calls and 1,224 total tool calls**,
all successful, across ai395/mac/main/pocket4/rog/x230. Each cell has 96 calls, balanced
by host and status/read operation. Each arm also performs a normal controller restart
and checks the same original jobs and outputs. Source records and executable hashes
remain unchanged. Original evidence is in the
[native report](../tests/evidence/20261103-x230-r11/native-observation-abba.json.gz).

| Concurrency | Calls/s A → B | Rate change | Controller CPU ms/call A → B | p95 ms A → B |
|---:|---:|---:|---:|---:|
| 1 | 6.128 → 6.070 | -0.95% | 68.021 → 69.167 | 210.330 → 206.761 |
| 4 | 15.697 → 15.115 | -3.71% | 80.729 → 81.615 | 308.131 → 372.530 |
| 8 | 18.032 → 18.288 | +1.42% | 85.000 → 83.073 | 526.539 → 517.132 |

The first block does not establish a general multi-host speedup. At C4, throughput was
3.71% lower and p95 was **20.90% higher**; that specific tail-latency risk prompted one
additional C4-only ABBA block. The initial observation is retained regardless of the repeat.

The independent C4 recheck completed **384 measurement calls and 456 total tool calls**,
all successful. It used the same qualified A/B runtimes, original jobs, native stdio
transport, two Tokio workers, 96 calls per cell, and ABBA order. Each version contributes
192 measurement calls within each campaign. The
[recheck report](../tests/evidence/20261103-x230-r11/native-observation-abba-c4-recheck.json.gz),
[independent summary](../tests/evidence/20261103-x230-r11/native-observation-summary-c4-recheck.json),
and [comparison tables](../tests/evidence/20261103-x230-r11/native-observation-results-c4-recheck.md)
retain all four new rounds alongside the first campaign's unchanged evidence.

| C4 campaign | Calls/s A → B | Rate change | Controller CPU ms/call A → B | CPU change |
|---|---:|---:|---:|---:|
| First C1/C4/C8 block | 15.697410 → 15.114576 | -3.713% | 80.729167 → 81.614583 | +1.097% |
| Independent C4-only block | 16.000809 → 15.952858 | -0.300% | 78.958333 → 79.947917 | +1.253% |

| C4 campaign | p50 ms A → B | p50 change | p95 ms A → B | p95 change |
|---|---:|---:|---:|---:|
| First C1/C4/C8 block | 249.446904 → 251.818554 | +0.951% | 308.131457 → 372.530156 | +20.900% |
| Independent C4-only block | 243.063639 → 241.403344 | -0.683% | 322.669224 → 315.412781 | -2.249% |

The two blocks are separate performance samples: rates, CPU costs, and latency values
are not pooled across campaigns. Within each campaign, calls/s uses total calls divided
by summed cell durations, CPU/call uses summed direct controller CPU divided by calls,
and percentiles use the pooled raw per-call latencies with nearest-rank selection.
No successful-call filtering or averaging of per-round percentiles is used.

The first C4 cell followed its C1 cell; the recheck's C4 cell began directly after
preflight. This preconditioning difference limits cross-campaign attribution.
The initial p95 regression did not repeat directionally: p50 and p95 improved in the
recheck. Throughput remained lower in both blocks, with the measured decline narrowing,
while CPU/call increased by about 1% in both. The first **+20.900% p95** observation
is preserved; the repeat does not erase it or establish general equivalence.
Two runs per version in each finite campaign do not establish statistical significance
or code-level causation.

CPU above is the same-controller-PID/start-ticks /proc/stat delta, not the sampled process
tree counter. Nine /proc file-descriptor sampling permission errors remain in the first
native report; eight remain in the recheck. Each includes a controller FD-directory error,
so neither establishes complete tree RSS/FD/CPU measurements. The raw per-cell sampled
tree-CPU differences also have asynchronous endpoint error of either sign despite their
lower-bound label; they are retained but not used for the CPU/call results above.
No target reboot, WAN partition, new-launch throughput, system jobctl,
or distributed ownership transfer was tested by this read-only workload.

### Preserved benchmark preflight failure

`inventory-campaign-01` was refused by `ValueError: benchmark modules differ` before any
measurement process ran. All 72 planned entries remained unexecuted. The
[failed receipt](../tests/evidence/20261103-x230-r11/inventory-preflight-01.json.gz) and
[original baseline module](../tests/evidence/20261103-x230-r11/inventory-preflight-01-baseline-benchmark.rs)
are retained. Differences were parity spelling in expected-row construction before timing
and a cache-description field emitted after timing. The identical-source gate was kept.
The baseline was rebuilt in a fresh source directory in 748.389 seconds; no production
source or qualified R11 binary changed. The old attempt is not silently replaced or
counted as a performance sample.

## Rejected persistence candidate: completed independent probe

The candidate counted pretty-JSON bytes before any filesystem effect, then serialized again
through a 16 KiB BufWriter, explicitly flushed, and used `into_parts` to avoid Drop retries.
It retained oversize-before-temp behavior and file-sync/rename/directory-sync ordering.
The [probe report](../tools/x230/20261103/experiments/persistence-probe.md) and
[raw evidence](../tests/evidence/20261103-x230-r11/persistence-probe.json) preserve all samples.

This used fixed JobRecord-like `serde_json::Value` data, not the production JobRecord type.
A global System allocator wrapper was present; counters were enabled only for separate
allocation samples and disabled during timing, leaving the wrapper's switch-read overhead.
Peak allocation means logical live requested bytes, excluding fixture/report storage,
allocator metadata, and internal realloc overlap. It is not RSS or production TPS.

| Encoded bytes | Payload | CPU µs/call: Vec → stream | Wall µs/call: Vec → stream | Peak requested bytes: Vec → stream |
|---:|---|---:|---:|---:|
| 1024 | plain | 3.188 → 4.417 | 15.531 → 4.396 | 1660 → 1024 |
| 1024 | escaped | 3.373 → 6.012 | 3.353 → 5.991 | 1024 → 1024 |
| 65536 | plain | 85.432 → 166.193 | 189.545 → 292.113 | 129854 → 16384 |
| 65536 | escaped | 147.952 → 435.505 | 267.264 → 573.974 | 65536 → 16384 |
| 786432 | plain | 1232.833 → 2022.313 | 1952.054 → 2772.442 | 1571646 → 16384 |
| 786432 | escaped | 1713.568 → 5228.835 | 5813.509 → 6349.965 | 1048576 → 16384 |
| 4194272 | plain | 5509.750 → 10616.587 | 5677.738 → 13580.689 | 8387326 → 16384 |
| 4194272 | escaped | 9150.478 → 27580.648 | 11253.971 → 66469.801 | 4194304 → 16384 |

Each pure case used two ABBA cycles; the table gives per-mode block medians.
CPU uses CLOCK_PROCESS_CPUTIME_ID and wall uses Instant.
Background R11 compilation and CPUQuota 50% can disturb wall; the small plain-case wall
reversal is not a throughput claim. All eight groups used more CPU with the two-pass method.
Large plain cases added about 64–95% CPU; escaped cases added about 194–205%.
Only one serialized receipt buffer is protected by the process-wide writer lock at a time;
the measured allocation saving must not be multiplied by the number of workers.

The 22 dedicated checks completed: ten byte-equality cases, four oversize/no-file cases,
and eight injected write/flush failures with original I/O errors and no post-failure Drop retry.
Eight actual durable saves also had byte-equal output. The report accounts separately for
2,790 explicit source-loop assertions; these are not 2,790 independent recovery scenarios.
Only two durable observations per mode/size were collected, insufficient for broad fsync claims.

Successful probe job: `1a1a0fa780c-96a-6bf1`; standalone compile 7.393 s, run 1.883 s.
It reused serde_json 1.0.151 with rustc 1.95.0, nice 15, CPUQuota 50%, 512 MiB, and a 120 s cap.
The first setup job `1a1a0f6cbe9-96a-6bca` failed on an incorrect Cargo.lock path before
compilation. Its traceback is retained; the single authorized correction kept the Rust source
and measurement design unchanged. Exact commands are in the
[correction launcher](../tools/x230/20261103/experiments/launch_persistence_probe_v2.py).
The [executed Rust source](../tools/x230/20261103/experiments/persistence_probe.rs) already
contains the required 2026 copyright and Apache-2.0 header; its executed hash is unchanged.

## Recovery evidence and scope

The retained [baseline recovery summary](../tests/evidence/20261103-x230-r11/recovery-baseline-summary.json)
and [original archive](../tests/evidence/20261103-x230-r11/recovery-baseline.json.gz)
cover six private jobs and owned-controller/transport interruption. The completed
[candidate summary](../tests/evidence/20261103-x230-r11/recovery-candidate-summary.json) and
[original archive](../tests/evidence/20261103-x230-r11/recovery-candidate.json.gz) bind the run
to the qualified runtime SHA256 above and record **58/58 native calls and 31/31 independent SSH calls successful**.
The proved private ROG SSH master was killed; other hosts progressed and ROG reconnected to
its original job. After the separate controller SIGKILL/restart, all six original jobs were
reused with preserved identities and output witnesses: six original starts, six same-key
lookups, no duplicate launches, zero automatic RPC retries, and no production service mutations.
The candidate canary elapsed **14.616 seconds**; this is its bounded scenario duration, not throughput.
Its shutdown sampler recorded one `/proc/1937021/fd` PermissionError. The baseline also retains
its own sampler errors. Sampled resource peaks/tree CPU remain lower bounds, not complete measurements.
Neither run establishes target reboot, physical power-loss survival, WAN partition tolerance,
production owner transfer, or transactional exactly-once external effects; the original reports
do not record Git commit identities. Reproduction inputs are the
[six-running canary](../tools/x230/20261103/recovery/x230_six_running_recovery_canary.py) and
[owned SSH interruption helper](../tools/x230/20261103/recovery/owned_ssh_interruption.py).

## Publication and interpretation

Qualification, comparative inventory/native performance measurements, the independent C4
recheck, and baseline/candidate recovery evidence are complete. Retain R11 conditionally:
the bounded receipt offload preserves physical capacity through cancellation, and the
large plain inventory cases show consistent CPU savings. This disposition also retains
the smaller inventory regressions, mixed native results, resource-accounting limitations,
and the rejected persistence alternative. It is not a production deployment decision or
a claim of overall six-host acceleration.

The source/evidence snapshot is bound to branch `perf/x230-r11-20261103` and direct parent
`9efb50d35ed70caf59e13a430762884eb551ed23`. The Git commit containing this report is the
version under review; its tree must preserve the 213 compiler-input hashes above.
The GitHub branch and PR head provide the publication reference without embedding a
self-referential commit hash in this document.
The [execution ledger](../tests/evidence/20261103-x230-r11/execution-ledger.json) records the
source, executable, experiment and publication evidence bindings as they are established.
Performance statements remain specific to the measured workload, build, host conditions,
concurrency and resource metric; native observations and inventory microbenchmarks are
not interchangeable throughput claims.
The optimization frontier remains workload-dependent: full source scans, escaped-string
allocations, shared blocking capacity, and serialization/fsync under a writer lock still cost work.
This report records scoped changes and a rejected tradeoff; it makes no absolute-optimality claim.
