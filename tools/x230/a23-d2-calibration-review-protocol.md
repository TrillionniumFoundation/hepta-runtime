<!-- Copyright 2026 Muvon Un Limited -->
<!-- Copyright 2026 TrillionniumFoundation -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# A23 D2 instrumentation calibration: frozen independent review protocol

> Publication note: the original frozen protocol has SHA-256
> `07de7671208af6714f99312264ffd3fe7987c8c882edd0306be5839e8e812410`.
> Its original text and predeclared gates remain below. This copy adds
> only publication headers and this note. Historical hashes identify the
> recorded original inputs; a new run of a portable helper records its own
> current SHA. Use the explicit bindings and commands in
> [D2 diagnostic calibration](README.md#d2-diagnostic-calibration).
> Reproduction remains limited to the same pinned D2 r02 source map.

This protocol was agreed with the root reviewer before any off/on calibration result was examined. It is an analysis protocol, not a performance result, runtime qualification, or authorization to run remote work. The review helper and all work in this subtask are local only.

## Fixed experiment and evidence

Run the frozen `x230_observation_diagnostic_d2.py` (SHA-256 `7d44502e1977b99aa663260870984b300d2125dab1a19cbef1b27b32b27b9e8a`) four times, serially, with explicit modes **off, on, on, off**. Every invocation uses the same actually qualified D2 binary as both `--baseline` and `--candidate`, `--order B --calls 384 --concurrency 8 --workers 2`, the same six original completed jobs and profile template. Each invocation has a new `--out`. `--socket-parent` remains the previously validated short private parent; `fresh_profile` creates a new unique child. The root operator runs all four invocations within one continuous forwarded-agent SSH session, without overlapping compilation. The report can confirm serial timing and within-run agent checks; it does not independently prove the external session or absence of other host work.

Retain every raw report, including failures, and both controller stderr files as exact bytes. Bind each raw SHA, stderr SHA, summary-payload SHA, the frozen driver SHA, all 151 actual qualified source-file hashes, and the actual qualification report and binary SHA. No binary or qualification placeholder is acceptable. A shutdown `profile_diagnostic` object is a reference into `controller_diagnostics`, not a second measurement.

The normal expected workload is 4 x 384 = 1,536 timed rows, 24 initial full-output rows, 48 restart rows, and eight clean EOF exits. Each run has a measurement controller (`first`: initialization, six preflight reads, 384 timed observations, shutdown) and a distinct restart controller (`restart`: initialization, 12 readbacks, shutdown). Keep the two roles separate. Every row must retain its actual outcome and latency; no failure filtering, retry substitution, changed workload, or replacement run is allowed.

## Predeclared quality and cost gates

Before comparing cost, require all four runs, all timed and non-timed observations, metadata/original receipts, binary identity, normal EOF/child cleanup, all diagnostic records, and source qualification checks to pass. Verify all row counts, host/tool order, complete output receipts, independent success totals and nearest-rank quantiles. An explicit `false` is a failure; missing evidence is unknown and cannot be upgraded to success. Off mode must have an available stderr file containing zero summary/event records. Missing off-mode summaries are expected, but do not mean zero phase cost.

For on mode require exactly one complete summary per controller; all 32 unique fixed metrics; checked finite unsigned counters; no saturation, recording loss, unclosed interval, or invalid clock sample; correct scope flags; exact stderr/JSON payload binding; and complete failure-event accounting. Agent metrics must have `cpu_applicable=false`, with no purported CPU samples. A clean native pass remains necessary even if a failure event is perfectly recorded. Failed, missing, malformed, capped, or partially written evidence is retained and prevents a trusted cost or phase conclusion.

Only after that quality gate, calculate the two temporal pairs: **off1 versus on2**, and **off4 versus on3**. Runs 2 and 3 are both on and are not a cost pair. Also pool the two off cells and two on cells, using sums of counts, elapsed seconds, and controller CPU seconds; do not average ratios. Pool every latency sample before taking nearest-rank p95.

The following practical tolerance gates are fixed in advance:

| Comparison | CPU per attempted observation | Successful goodput | All-row p95 latency |
| --- | --- | --- | --- |
| Pooled on versus off | increase <= 5% | decrease <= 5% | increase <= 10% |
| Each temporal pair | increase <= 10% | decrease <= 10% | increase <= 20% |

These thresholds are exploratory acceptance criteria, not confidence intervals, noise estimates, or statistical significance tests. Two pairs cannot establish absence of instrumentation effects. Passing only permits a qualified description of this D2 calibration. It does not establish the cost of the disabled D2 hooks relative to the separately qualified A23 binary, or prove that on-mode phase shares equal uninstrumented shares. If a valid result exceeds a threshold, label instrumentation cost or instability and withhold an unperturbed-hotspot claim. Do not change thresholds after observing the data.

CPU here is same-controller-PID/start-ticks `/proc/stat` user+system difference around the timed cell, divided by all attempted calls. Goodput is successful calls divided by whole cell seconds. All failures remain in latency and CPU denominators. A failed quality gate produces no overhead ratio verdict; individual cell facts and failure records remain available.

## Meaning of the 32 metrics

The source is the formatted D2 r02 module, SHA-256 `9bf57f5ef9783b61e90d701f3ebb51df780ebc329f03cb7849d218375fcde8de`; profile callsite SHA-256 `e767fd4455d796494384f76ee5366825e00f368cdd7c133b17dbcd33e7c4b62b`; pool callsite SHA-256 `5ef36b10ec49b4fb0457336e2dc62ef7e4bad2dca64dc85654a0d0a8da2cc6e1`.

| Metrics | Count | Scope and valid denominator |
| --- | ---: | --- |
| `verify_files.total` | 1 | Synchronous inclusive file-validation CPU / that controller's owner-thread lifetime CPU |
| Seven file categories x four phases | 28 | Categories: profile, ssh_config, known_hosts, ssh_executable, false_executable, shell_executable, unclassified. Phases: total, open_and_before_checks, read_and_hash, after_stamps_and_digest. CPU and wall averages use their own valid interval counts. A zero-count category is unobserved, not a zero-time operation. |
| `shell_resolution.total` | 1 | Synchronous fixed-shell resolver within verify_files; closes before shell executable verification starts |
| `policy_parent_and_environment.total` | 1 | Synchronous parent-directory, current runtime-policy serialization/digest, and agent environment checks within verify_files |
| `agent_snapshot.wall_only` | 1 | Wall time including local checks and asynchronous agent I/O/await. Intervals may overlap. No CPU attribution and no additive wall percentage. |

Owner-thread lifetime begins at the dedicated owner thread's diagnostic activation and ends after runtime drain/destruction, before summary serialization/stderr write and final thread teardown. It excludes profile loading and private-root creation performed before the owner thread exists. It is not whole-controller CPU and is not restricted to the timed cell. Initialization, preflight, request activity, background activity and shutdown share this denominator. Do not divide lifetime totals by 384 and label the result timed CPU per call. Do not assume a fixed number of validation intervals per request or count master renewals from duration.

Parent spans include their children and timer/recorder overhead. Within `verify_files`, the file total spans, shell-resolution span, and policy span execute sequentially. Within each file, open-before, read-and-hash, and after-stamps-and-digest execute sequentially. For complete records, compute the signed residual at each level as parent CPU minus the sum of these non-overlapping child CPU totals. A negative residual is an inconsistency; retain it and invalidate trusted attribution rather than clamp it to zero. A positive residual includes uninstrumented code, bookkeeping and measurement overhead. It is not pure exclusive business CPU. Never sum a parent with its children.

`read_and_hash` includes buffer creation, reads, retry-on-interruption and digest updates. Digest finalization/comparison is in `after_stamps_and_digest`, alongside descriptor/path/length stamp checks. Consequently this experiment does not isolate cryptographic hashing cost from reads or memory handling. `bytes_on_marked_success` counts only successfully completed read-and-hash intervals; later stamp, digest, or request checks can still fail. It is not accepted-data throughput or successful-RPC bytes.

`not_marked_success` means a span was dropped without its explicit success marker. It includes error, cancellation and unwinding and is not an RPC failure count. Sum/maximum/valid-sample fields yield interval means and maxima only; no phase latency quantiles or request-phase correlation can be reconstructed. Asynchronous wall intervals cannot be added to synchronous wall time, used as a CPU fraction, or interpreted as a master renewal count.

## Reproducible phase report

For each on controller, independently validate metric counts, closure, success-marker identities, sample identities, u64 bounds, sums/maxima, correct parent tags, zero non-applicable CPU fields, byte-field placement, and owner bounds. Retain raw summaries and all events even when invalid. A complete zero-count metric has null mean and no observed-cost claim. If any clock/counter/evidence check is invalid, derived trusted phase attribution is null.

For valid records report the 32 raw totals, interval means/maxima, file-category inclusive CPU shares of verify_files and owner lifetime, the three aggregate file-phase CPU totals and signed residuals, verify_files versus the rest of owner lifetime, and agent wall sum/mean/max with an overlap warning. Keep each on `first` controller and each on `restart` controller separate. Aggregate only the two controllers of the same role by summing numerators and denominators; never average percentages or concatenate the shutdown references as extra samples.

The two on measurement controllers can show whether the same measured category leads in both runs. That is descriptive repeatability within this diagnostic build, not proof of a production hotspot. A read-and-hash lead supports investigating its combined read/hash work; it does not prove SHA alone is the bottleneck or authorize relaxing authority checks. Failed native cells, excess instrumentation cost, unstable pairs, or invalid diagnostic evidence block any clean extrapolation. Restart-only data may describe restart behavior but cannot rescue a failed measurement calibration.

Failure events describe the original spawn proof and cleanup statuses, not inferred remote causes. Keep unknown/short-circuited fields unknown. A missing identity observation is not a positive identity mismatch. Event timestamps are relative to the owner lifetime; no exact alignment with caller cell starts is recorded. Failure-event writes can perturb timing. Absence of a recorded event, especially with missing stderr or incomplete counters, is not proof that no underlying fault occurred.

## Required local review inputs

Supply the actual D2 r02 qualification JSON and its SHA; the actual binary SHA; the frozen driver; the full 151-file r02 source map and source tree; and four `--run MODE REPORT RAW_SHA STDERR_ROOT` inputs in off/on/on/off order. `STDERR_ROOT` contains `round-0-B/first/stderr.log` and `round-0-B/restart/stderr.log`. Root must preserve the exact downloaded bytes. Review output is create-only and binds its own helper SHA and this protocol SHA. No actual calibration output is represented by this protocol.
