# X230 R12 measurement and recovery drivers

These drivers use fresh private experiment directories. They do not replace a
runtime service, change network configuration, or stop unrelated work. Baseline
and candidate must be independently bound to their tested source and executable.

## Native read-only comparison

`run_native_observation.py` reuses `../recovery/x230_observation_benchmark.py`.
It accepts that driver's arguments plus `--warmup-calls` (default 24). Use the
same fresh held SSH agent, profile template, six frozen records, socket parent,
worker count and driver for both binaries.

A compact initial ABBA with `--calls 96 --concurrency 1 4 8 --workers 2` contains
1,152 measured status/read calls, 288 balanced warmup calls and 72 preflight /
normal-restart checks, for 1,512 total calls. Keep every failure and the original
report. Run a second, separately reported block only if a concrete performance
regression or excessive dispersion requires resolution. Do not pool separate
campaigns to erase a reversal.

Every concurrency cell now has an equal, explicitly recorded preconditioning
step. CPU/call still uses synchronous same-PID/start-ticks controller CPU deltas.
The optional sampler handles FD, RSS, task discovery and process CPU failures
independently; a denied FD directory can no longer silently discard readable
memory and CPU observations. Missing metrics and sample errors remain visible.
Asynchronously sampled tree sums are not synchronized or complete, and their
interval differences are not a valid performance numerator.

This workload measures existing completed-job observations, not execution-start,
persistence-write, cancellation throughput, or a new distributed protocol.

## Six-host cancellation and recovery

`run_six_host_cancel_recovery.py` reuses the existing descriptor-checked remote
fixture helper, bounded child workload, and native MCP client. Its output must
be a new direct child of `/home/qian/hepta-runtime-optimization-20261103-r12`.
Arguments are `--candidate`, `--profile-template`, `--frozen-jobs`,
`--socket-parent`, `--out`, optionally `--workers 2` and `--interrupt-host rog`.
The relative `../recovery` helper directory must accompany this driver.

The workflow starts six distinct private jobs, confirms their original input,
execution marker and actual reported hostnames, optionally interrupts only the
proved private SSH master, then kills only its own controller. A new controller
must observe and reuse all six original jobs. Six concurrent cancellation calls
must be followed by independent durable exit and exact-byte witness checks.
Another normal controller restart must preserve terminal observations, same-key
reuse, and harmless `already_exited` cancellation acknowledgements.

A complete run contains exactly six new starts, twelve same-key lookups and
twelve cancellation calls. Polling is read-only; uncertain start or cancel
operations are never resent automatically. Every native and independent SSH
reply has an original artifact hash. Failure leaves the unique identities and
artifacts available; the private children have the original 210-second gate and
240-second supervisor timeout. No remote fixture cleanup is attempted.

The normal test should fit well inside five minutes; use a 600-second outer job
budget to retain a delayed failure. Acknowledged signalling is not counted as
terminal proof. Linux uses the original pidfd binding; macOS retains its existing
explicit best-effort PID/start/account identity limitation. The test does not
establish host reboot, physical power loss, WAN partition, production-owner
transfer, or transactional exactly-once external effects.

## Local harness checks

`python3 test_measurements.py` checks four measurement regressions: denied FD
access still retains CPU/RSS and child discovery; changed process generations
cannot publish samples; warmup has its own denominator; failed warmup cannot
create a successful measured cell. These are Python harness checks, not Rust
product qualification or remote lifecycle evidence.

## Independent cancellation evidence verification

After the lifecycle driver finishes, run `verify_cancel_recovery.py --report
REPORT.json --output NEW_SUMMARY.json` (gzip input is also accepted). It verifies
the original embedded base64 lengths/hashes and independently compares request,
nonce, one-execution marker, input, cancellation request, full outputs, terminal
receipts and exact-byte witnesses across the two restarts. It also checks actual
call counts and all original write outcomes. It refuses incomplete reports and
creates a new summary without altering the original bytes.
