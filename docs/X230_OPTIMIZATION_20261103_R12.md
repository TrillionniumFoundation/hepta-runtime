# X230 runtime optimization R12 — 2026-11-03

## Status and interpretation

R12 is a retained, qualified checkpoint with mixed performance results. It moves
complete cancellation-receipt preparation off the asynchronous executor and adds
a single-pass receipt-encoding capacity hint. The large-receipt responsiveness
and selected buffer-capacity improvements come with material resource
regressions. This checkpoint does not establish an unconditional production-wide
throughput, CPU, or memory improvement.

This report was assembled by read-only inspection and independent recalculation
of existing R12 artifacts. Preparing it did not rerun qualification, performance
measurements, or recovery scenarios. R13 is being evaluated separately to address
the full-record CPU and memory costs. Its changes and measurements do not qualify
R12 retroactively.

The intended publication parent is the R11 checkpoint
[fe7d2b8afba882d06b607ec00b8756eed62f6a1f](https://github.com/TrillionniumFoundation/hepta-runtime/commit/fe7d2b8afba882d06b607ec00b8756eed62f6a1f),
the head of [PR #87](https://github.com/TrillionniumFoundation/hepta-runtime/pull/87)
when this work was resumed. The commit containing this report identifies the R12
publication without embedding a self-referential commit hash.

## Source, executable, and qualification binding

| Item | Recorded identity |
|---|---|
| R11 comparison parent | fe7d2b8afba882d06b607ec00b8756eed62f6a1f |
| R11 release runtime SHA256 | 660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c |
| R12 qualified release runtime SHA256 | e7f1f8275c6735a6823f35b6367baf9fc9f943ea7e62a1114fe1187e82cd1c1f |
| R12 qualified persistence libtest SHA256 | ddb82ef4c511ccf85f97a733515798b19283732091b7c187e9d581af995f550e |
| R12 compiler-input map | 216 entries; matches qualification source_tested, source_after, and the inspected R12 source |
| Isolated qualification | 1,631 passed; 0 failed; 32 ignored; 1,663 selected; zero automatic retries |
| Release build | Rust 1.95.0; offline, locked, all features; 331.353 seconds |

The retained qualification reports successful format, format check, harness
checks, strict Clippy, test build, isolated tests, independent isolated-test
audit, and release stages. The persistence benchmark and the local cancellation,
native observation, and recovery campaigns documented below have separate,
previously recorded explicit-driver results. All 32 isolated-test entries remain
ignored; this report does not claim that every ignored test was exercised or
count them as isolated-test passes.

Primary bindings:
[source map](../tests/evidence/20261103-x230-r12/source-map.json),
[baseline binding](../tests/evidence/20261103-x230-r12/baseline-binding.json),
[isolated summary](../tests/evidence/20261103-x230-r12/isolated-summary.json), and
[original qualification](../tests/evidence/20261103-x230-r12/qualification.json.gz).

The original X230 workspace is
/home/qian/hepta-runtime-optimization-20261103-r12; qualification used
qualification-02. The [original evidence archive](../tests/evidence/20261103-x230-r12/r12-original-evidence.tar.gz)
retains the earlier experiment history and main campaigns. The independent C1
follow-up was produced after that archive and is supplied separately as
[native-c1-followup.json.gz](../tests/evidence/20261103-x230-r12/native-c1-followup.json.gz).

## Production changes and execution boundaries

### Cancellation preparation

In [jobs.rs](../src/mcp/runtime/jobs.rs), R11 performed check_ref synchronously
inside cancel_job, before acquiring cancellation publication capacity. That read
performs descriptor checks, complete owned JSON decoding, identity validation,
and host binding, with the existing 4 MiB source limit.

R12 includes the entire preparation in the existing run_cancel_intent blocking
closure. One of the existing eight cancellation permits is acquired before
submission. The closure validates the receipt, prepares the original intent,
appends and synchronizes it, and returns the permit with the verified record to
the continuation. The observation semaphore remains separate.

A submitted physical preparation keeps its permit through blocking-pool queueing
and execution even if its caller is dropped. Cancellation before admission
submits no worker. An abandoned preparation may finish its original intent
append, but it does not independently submit the remote cancellation. On the
normal continuation, the permit passes through the remote response and
completion-audit path.

**The eight slots are preparation/publication capacity, not a global bound on
physically outstanding remote cancellation attempts.** If a caller future is
dropped during the remote await, its local permit can be released while the
existing SSH transport owner continues to own the original child. That behavior
predates R12. The slots also do not bound all queued request parameters, the
shared Tokio blocking pool, or total process memory.

Admission now precedes full receipt allocation. This avoids full owned records
waiting outside the eight permits for valid cancellations. Wrong-host rejection
pressure has a different tradeoff: eight blocking preparations can decode at
once, whereas the old synchronous path was limited by available executor workers.
The measured large-receipt RSS increase below must be retained.

Saturation now delays invalid-receipt validation too; a closed cancellation pool
can fail before reading an invalid receipt. With capacity available, receipt
errors still precede intent preparation and append errors. Intent timestamps now
reflect actual blocking preparation time. Installed runtime configuration remains
immutable, so the relocated repeated host lookup does not introduce a policy
switch window.

The original remote request, job identity, grace limit, cancellation protocol,
and completion-audit sequence remain unchanged. The
[concurrency review](../tools/x230/20261103/r12/concurrency-review.md) records
these boundaries and the deferred proposal to reuse remote request validation.

### Single-pass receipt encoding

[jobs_persistence.rs](../src/mcp/runtime/jobs_persistence.rs) uses string lengths,
array counts, and a fixed allowance to reserve likely encoding capacity. It does
not scan string contents or perform a second encoding pass. Small receipts retain
a small initial reservation; larger receipts reserve their hint and use
serde_json::to_writer_pretty into the Vec.

The hint is capped, but the Vec may grow during JSON escaping. The original
post-encoding 4 MiB length rejection remains. Neither the hint nor the encoded
byte limit is a 4 MiB heap-allocation bound.

The registry writer lock still spans serialization and durable publication.
The save path rejects an oversized encoding before creating its temporary
receipt, uses exclusive temporary-file creation with 0600 mode, writes and
synchronizes the file, renames it, and synchronizes the parent directory on Unix.
R12 does not add a WAL, defer synchronization, shorten this write-lock interval,
or introduce a new recovery/ownership protocol.

## Cancellation-pressure responsiveness and resource cost

Source: cancel-responsiveness-01/report.json in the
[original archive](../tests/evidence/20261103-x230-r12/r12-original-evidence.tar.gz).
The [driver](../tools/x230/20261103/r12/run_cancel_responsiveness.py) starts fresh
local native MCP controllers with identical escaped JSON receipts, eight
concurrent wrong-host cancellation requests per wave, and one host_list request.
Every cancellation must fail with the expected binding error after receipt
validation. Two waves warm up each controller; 24 waves are measured.

The completed ABBA contains 16 processes, 3,456 measured tool calls, and 288
warmup calls. Each measured process contains 192 expected cancellation refusals
and 24 host-list successes. All measured calls had the expected result. Receipt
bytes remained unchanged; there was no cancellation intent, SSH dispatch, or
automatic retry. This is control-plane responsiveness under refusal load, not
successful remote-cancellation or production execution throughput.

A is qualified R11; B is qualified R12. Latency and memory values are medians of
the two processes per arm. CPU/call is summed measured controller CPU divided by
all measured calls in that arm.

| Tokio workers | Encoded receipt bytes | Host-list p95 ms A → B | Change | Controller CPU ms/call A → B | Change | Whole-child VmHWM KiB A → B |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1,024 | 17.898 → 19.006 | +6.19% | 1.736 → 1.690 | -2.67% | 14,034 → 14,424 |
| 1 | 4,194,272 | 209.555 → 42.459 | -79.74% | 23.264 → 37.292 | **+60.30%** | **21,846 → 140,778** |
| 2 | 1,024 | 18.065 → 17.959 | -0.59% | 1.782 → 1.829 | +2.60% | 15,206 → 15,582 |
| 2 | 4,194,272 | 148.786 → 54.363 | -63.46% | 25.625 → 37.245 | **+45.35%** | **34,656 → 152,280** |

For large receipts, cancellation-request p95 itself fell from 206.004 to
108.671 ms with one worker (-47.25%), and from 145.910 to 108.857 ms with two
workers (-25.39%). Host-list responsiveness improved, but whole-child high-water
memory increased by 544.41% and 339.40%. Small-receipt results are mixed.

VmHWM is high-water memory since exec, including startup, warmup, measured work,
and allocator retention. It is not a single-request allocation, a measured
interval increment, or a complete process-tree bound. The source-size limit does
not account for all decoded collections, strings, input buffers, and allocator
overhead. These results motivate the separate R13 work on full-record decoding
and retention.

## Six-host native release observations

Sources: native-observation-01/report.json in the
[original archive](../tests/evidence/20261103-x230-r12/r12-original-evidence.tar.gz),
the separate [C1 follow-up](../tests/evidence/20261103-x230-r12/native-c1-followup.json.gz),
the [measurement wrapper](../tools/x230/20261103/r12/run_native_observation.py),
and the [independent analyzer](../tools/x230/20261103/r12/analyze_native_observation.py).

Both campaigns use the same qualified R11/R12 release runtimes, six original
completed jobs on ai395/mac/main/pocket4/rog/x230, native stdio MCP, two Tokio
workers, and ABBA order. Each measured cell contains 96 calls, balanced over
six hosts and status/read operations: eight calls per host/operation pair. Every
cell has its own 24-call balanced warmup, excluded from its measurement
denominator.

| Campaign | Measured calls | Warmup calls | Preflight/restart checks | Total tool calls | Failed calls |
|---|---:|---:|---:|---:|---:|
| Initial C1/C4/C8 | 1,152 | 288 | 72 | 1,512 | 0 |
| Independent C1 follow-up | 384 | 96 | 72 | 552 | 0 |
| Counts only, summed | 1,536 | 384 | 144 | 2,064 | 0 |

The drivers record original job identities and expected complete outputs,
unchanged source receipts and executables, zero remote mutation calls, zero new
starts, zero automatic RPC retries, and successful normal controller restart
checks. These observations do not test new-launch throughput.

### Statistical convention and results

Throughput is pooled calls divided by pooled measured wall time within one
campaign, concurrency, and arm. CPU/call is pooled controller CPU divided by
pooled measured calls. p95 is nearest-rank over all raw measured latencies in
that group. The two campaigns are reported separately.

| Campaign | Concurrency | Calls/s A → B | Change | Controller CPU ms/call A → B | Change | Pooled p95 ms A → B | Change |
|---|---:|---:|---:|---:|---:|---:|---:|
| Initial | 1 | 4.7486 → 4.4901 | **-5.44%** | 108.385 → 126.667 | **+16.87%** | 285.818 → 282.791 | -1.06% |
| Initial | 4 | 15.2488 → 17.3863 | +14.02% | 79.948 → 75.208 | -5.93% | 372.613 → 295.774 | -20.62% |
| Initial | 8 | 17.2022 → 20.2965 | +17.99% | 81.354 → 78.542 | -3.46% | 687.628 → 511.065 | -25.68% |
| Independent follow-up | 1 | 4.5809 → 4.1949 | **-8.43%** | 112.500 → 130.417 | **+15.93%** | 297.230 → 304.666 | **+2.50%** |

C1 throughput and CPU regressions occurred in both campaigns. They are retained
alongside the initial C4/C8 improvements. Pooling the campaigns or selecting only
favorable concurrency levels would conceal that result.

Independent recalculation checked raw row counts, successes, balanced
host/operation identities, per-cell rates, CPU/call, and nearest-rank latency
statistics. The median of two per-process rates is a different statistic: it
gives C1 changes of -6.37% and -8.83%. Those values are not substituted into the
pooled table.

### Measurement and causality limits

The CPU numerator is the synchronous difference of the same controller
PID/start-ticks utime + stime counters immediately around each measured cell.
It excludes startup and warmup. Child CPU and asynchronously sampled tree
counters are not used as the performance numerator. VmHWM does not determine CPU
or throughput. Python thread-pool setup/teardown is included in cell wall time
with identical code for both arms.

Controller argv and explicitly constructed environment are shared between arms,
including prewarm, audit group commit, the newly pinned observation-pool profile,
and TOKIO_WORKER_THREADS=2. The current SSH agent is held for the campaign.
Qualification uses the same Rust version, release command, and Cargo.toml hash;
the common harness clears Rust flags and disables incremental compilation.

The reports do not establish equality of every effective build or host input.
They do not fully capture inherited Cargo profile variables, CPU temperature/
frequency, or simultaneous external load. Each arm has only two controller
processes. Dispersion is material: initial A/C8 processes measured 22.83 and
13.80 calls/s. There is no statistical significance claim.

R12's production observation path is unchanged from R11. The finite end-to-end
C1 differences are retained as measured outcomes, not attributed causally to an
unmodified observation function. The next candidate requires its own same
baseline verification.

The resource sampler preserves readable CPU/RSS/child observations even when
an FD observation fails. Sampled tree sums remain asynchronous and incomplete;
their deltas can have endpoint error of either sign. They do not establish a
complete controller-plus-descendant resource budget.

## Qualified single-pass persistence experiment

The separately exposed
[persistence-qualified.json.gz](../tests/evidence/20261103-x230-r12/persistence-qualified.json.gz)
is original qualified-matrix-01/persistence-cargo.json. Its uncompressed SHA256
is db7be7966e8fc4e9c5861e2d9838293951bc43fc27bf25c2c5d69e9342807afe.
The [persistence analyzer](../tools/x230/20261103/r12/analyze_persistence.py)
provides the reproducible statistical definitions.

Both arms run in the same qualified Cargo libtest on the actual production
JobRecord structure. Here A is the original serde_json::to_vec_pretty encoder;
B is the production reserved-Vec encoder. The durable arm calls the real save
path. The recorded profile is opt-level 1, debuginfo 2, debug assertions and
overflow checks enabled, and test=true. These are local libtest measurements,
not release-server throughput measurements.

The matrix contains eight plain/escaped and encoded-size cases, 96 pure waves
totaling 14,088 calls, and 64 durable saves. Each case has three pure ABBA cycles
and two durable ABBA cycles: six pure samples and four durable samples per arm.
Independent checks verified that all eight A/B encoded lengths and SHA256 values
are identical.

CPU is CLOCK_THREAD_CPUTIME_ID for the main benchmark thread. CPU and wall values
below are medians of per-wave/per-save values. Buffer capacity is final Vec
capacity, excluding fixture/report data and allocator metadata. It is not RSS or
an allocation count.

### Encoding CPU and final capacity

| Encoded bytes | Payload | Pure CPU µs/call A → B | CPU change | Final Vec capacity bytes A → B |
|---:|---|---:|---:|---:|
| 1,024 | plain | 2.959 → 3.028 | +2.35% | 1,024 → 1,024 |
| 1,024 | escaped | 16.045 → 15.626 | -2.61% | 1,024 → 1,024 |
| 65,536 | plain | 48.531 → 47.921 | -1.26% | 130,424 → 65,932 |
| 65,536 | escaped | 1,986.446 → 1,970.312 | -0.81% | 65,536 → 66,952 |
| 786,432 | plain | 565.360 → 566.889 | +0.27% | 1,572,216 → 786,828 |
| 786,432 | escaped | 23,966.099 → 23,741.908 | -0.94% | 1,048,576 → 787,848 |
| 4,194,272 | plain | 3,148.190 → 3,129.541 | -0.59% | 8,387,896 → 4,194,304 |
| 4,194,272 | escaped | 128,261.659 → 127,432.982 | -0.65% | 4,194,304 → 4,195,688 |

Three larger plain cases reduce final capacity by approximately 49.45–50.00%.
Escaped 768 KiB reduces it by 24.86%; escaped 64 KiB increases it by 2.16%.
The near-4-MiB escaped candidate ends at 4,195,688 bytes, above 4 MiB, while its
encoded length remains 4,194,272 bytes. This directly illustrates the distinction
between the preserved encoded-byte limit and an allocation bound.

### Durable save CPU and wall time

| Encoded bytes | Payload | CPU ms/save A → B | CPU change | Wall ms/save A → B | Wall change |
|---:|---|---:|---:|---:|---:|
| 1,024 | plain | 0.290 → 0.265 | -8.81% | 1.106 → 1.083 | -2.09% |
| 1,024 | escaped | 0.271 → 0.262 | -3.27% | 1.006 → 1.166 | **+15.90%** |
| 65,536 | plain | 0.333 → 0.361 | **+8.19%** | 1.331 → 1.303 | -2.06% |
| 65,536 | escaped | 2.395 → 2.386 | -0.38% | 3.455 → 3.402 | -1.55% |
| 786,432 | plain | 1.790 → 1.894 | **+5.81%** | 4.803 → 4.707 | -2.01% |
| 786,432 | escaped | 25.111 → 24.914 | -0.79% | 28.146 → 27.801 | -1.23% |
| 4,194,272 | plain | 7.882 → 8.216 | **+4.24%** | 17.408 → 16.991 | -2.39% |
| 4,194,272 | escaped | 134.231 → 136.233 | **+1.49%** | 144.418 → 146.900 | **+1.72%** |

The retention rationale is reduced buffer capacity in selected large plain
cases with broadly similar pure-encoding CPU. Durable-save CPU and wall time are
mixed. Four saves per arm do not establish a general fsync-latency or sustained
persistence-throughput improvement.

### Rejected experiments and retained setup failure

| Evidence | Disposition |
|---|---|
| Earlier R11 two-pass streaming | Rejected for large-input CPU increases of approximately 64–205%; retained in the R11 report. |
| persistence-fastprobe-01 | Compilation returned 1; no benchmark ran. Preserve as a setup failure, not a measured performance result. |
| persistence-fastprobe-02, bounded writer v1 | Rejected. Escaped pure CPU increased approximately 162–344%. |
| persistence-fastprobe-03, bounded writer v2 | Rejected. Escaped pure CPU increased approximately 6.32–21.32%. |
| persistence-fastprobe-04, reserved Vec | Preliminary support for the final single-pass direction, followed by the qualified experiment above. |

Extracted fastprobes used rustc opt-level 3 and their own harness. Their absolute
times are not pooled with, or substituted for, the qualified opt-level 1 Cargo
results. The three rejected designs are R11 two-pass streaming and R12 bounded
writer v1/v2; the initial compile failure is a separate historical event.

## Six-host cancellation and fault recovery

Sources: baseline-cancel-recovery-01/report.json and
candidate-cancel-recovery-01/report.json in the
[original archive](../tests/evidence/20261103-x230-r12/r12-original-evidence.tar.gz).
Reproduction and verification:
[run_six_host_cancel_recovery.py](../tools/x230/20261103/r12/run_six_host_cancel_recovery.py)
and [verify_cancel_recovery.py](../tools/x230/20261103/r12/verify_cancel_recovery.py).

| Check | R11 baseline | R12 candidate |
|---|---:|---:|
| Native calls successful | 90/90 | 90/90 |
| Independent SSH calls successful | 36/36 | 36/36 |
| Original new starts | 6 | 6 |
| Same-key lookups | 12; all reused original identity | 12; all reused original identity |
| Cancellation calls | 12 | 12 |
| Automatic retries | 0 | 0 |
| Production service mutations | 0 | 0 |
| Remote cleanup operations | 0 | 0 |
| Execution count per private fixture | 1 | 1 |

Independent inspection verified SHA256 for all 180 original native reply files,
and lengths and SHA256 for all 144 SSH stdout/stderr files. It also verified each
arm's exact set of six original controller receipts, unchanged bytes, and every
same-key lookup with reused=true, retried_launch=false, and unchanged job ID.

Both scenarios observed all six bounded private jobs running, interrupted only
the proved private ROG SSH master, reconnected to the same job, killed the owned
controller, and resumed the original identities. The controller SIGKILL exit was
-9. All six jobs subsequently reached cancelled; a further controller restart
preserved that terminal state and execution count 1.

Linux cancellation acknowledgements were stop_requested; macOS returned
term_sent. Completion was established by subsequent independent durable terminal
and output checks, not by treating signal acknowledgement as terminal proof.
Repeated cancellation after terminal state returned already_exited.

Original recovery-report SHA256 values:

- Baseline: 5bfd506093d1e5b2ba1d70ffa6394a2efbaf7e5c484f343532654da045ccf55a.
- Candidate: d203da5933dd334c4cef740e0ed2d4ff9a4ed892b944e66c2239e6485826ea43.

These scenarios establish the recorded private controller/transport interruption,
same-key resumption, successful cancellation, and restart observations. They do
not establish target-host reboot, physical power-loss survival, WAN partition
tolerance, production owner transfer, or transactional exactly-once external
effects. macOS retains its existing best-effort account/PID/start-time signal
identity limitation. Each arm also retains an FD-sampling PermissionError;
sampled resources are not complete process-tree accounting.

## Reproduction and next checkpoint

The [R12 tool directory](../tools/x230/20261103/r12/) contains original drivers,
independent analyzers, harness checks, concurrency review, and rejected
experiment sources. Use fresh private output directories and bind every new run
to its actual qualified source and executable. Original controller/SSH identities
and receipts belong to their original campaigns; later results cannot replace
their failure or regression history.

R12's retained findings are:

- Large-receipt refusal-load responsiveness improves while CPU and VmHWM rise
  substantially.
- Selected plain receipt buffers shrink by about half, with mixed durable-save
  cost and no RSS or hard-allocation-bound claim.
- Initial six-host C4/C8 observations improve, while C1 throughput and CPU regress
  in both the initial campaign and its separate follow-up.
- Bounded six-host cancellation/recovery scenarios pass with preserved original
  execution identities and terminal readback.

R13 work addresses the full owned-record allocation and retention costs
highlighted here. It requires its own qualification, controlled local comparison,
release refusal-load measurements, and relevant multi-host recovery evidence.
R12 remains an auditable checkpoint; these finite measurements establish neither
an absolute optimization frontier nor unconditional production adoption.
