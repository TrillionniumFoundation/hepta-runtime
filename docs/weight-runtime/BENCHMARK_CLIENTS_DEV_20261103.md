# Native weight client: development-profile measurements, 2026-11-03

## Result and decision

The native Rust helper passed the selected semantic cases but was slower than
the Python compatibility helper in this development-profile experiment. Across
inspect, probe and query, native cold helpers took about 2.8–3.0 seconds at the
median, compared with 0.15–0.28 seconds for Python. The complete MCP path took
6.9–7.3 seconds for native versus 1.6–1.7 seconds for Python. These observations
do not support enabling native transport by default for performance.

This compares transport helpers. Every route still used the Python/PyTorch CPU
engine. It does not measure Rust tensor execution, training, arbitrary model
loading or all REA capabilities. These development data require separate release-profile evidence before
interpreting their costs as production Rust performance.
Preserve this negative result separately from the release experiment.

The [release follow-up](BENCHMARK_CLIENTS_RELEASE_20261103.md) is complete with
its own 210-sample cohort and source manifest. A complete build-input manifest
was not captured for this development cohort, so a strictly identical whole-source
compiler-profile A/B is not established. The primary comparison is native versus
Python within each cohort.

The formal cohort contains **210 measured samples**, five passing semantic
checks, no failed measured requests and no recorded cleanup error. Source
weights remained unchanged. Preparation failures are separate from the cohort.

## Exact identity

| Item | Recorded identity |
| --- | --- |
| Frozen driver SHA-256 | `10ec5cb1510dbb0da2e1ef0cdfeba3417cd7f0edc1864c628b80d89a90125381` |
| Runtime SHA-256 | `a41c7b4b1675c94078e76507a65e588359129f9a4e56075e4246f385e4bd0612` |
| Runtime bytes | 391,130,912 |
| Profile label | `dev-opt-level-1-debug-true-lto-false-codegen-units-256` |
| Source label | `f9756508462ebc72e814a12f5dbba1b067edabe4-plus-uncommitted-rea-full-20261103` |
| Worker entry SHA-256 | `10c09efcb24d65ce850ccbee61f3034262fa026ee5d19adab90bc9eda67049c0` |
| Worker package SHA-256 | `4ea015d5844e5b4d2df4025b39aad39f5a7e96a44952e507e857add2d9fd100e` |
| Synthetic weights SHA-256 | `4c1975369a276b70bef42960ec208308389559af14ac10e05e16945dad580593` |
| Host | Linux 7.0.0-38-generic, x86_64, 48 visible logical CPUs |
| Python/PyTorch | Python 3.12.3; pre-existing torch 2.6.0+cpu |
| Formal operator job | `1a1a134fc45-96a-6dc4` |
| Raw result SHA-256 | `44e21c5c232e3b6eb2ec9685fdce8241653a1d2c980a1308c44a13661cd51bde` |

The source label is an uncommitted integration checkout based on PR84, not a
claim that this binary equals a later final commit. The binary SHA identifies
exactly what ran. The driver copied from one open descriptor, checked
device/inode/size/mtime/ctime before and after copying, synchronized the copy,
verified its hash and ran that private read/execute-only copy. Later builds
could not replace it. This cohort's profile has opt-level 1, debug information
enabled, no LTO and 256 codegen units. Its 391 MB executable is materially
different from a stripped release binary.

## Workload and measurement boundaries

The model is a 64 x 64 F32 identity Linear without bias. Each probe has one
64-element example with values `float(i % 8) / 8`. Query reads all 64 outputs
and checks exact equality with the input. Inspect requests hashes. Every engine
uses one intra-op and one inter-op CPU thread, in inference/evaluation mode.
No PyTorch engine or model backend was rewritten.

| Layer | Interval | Samples per operation |
| --- | --- | --- |
| Cold helper | Fresh helper launch, local Unix socket to shared resident worker, helper exit | 20 native and 20 Python |
| Resident socket | Driver connect/send to same resident worker through response EOF | 20 direct |
| Complete MCP | `weight_call` through original localhost SSH job to first response observed with `weight_read` | 5 native and 5 Python |

Linux `wait4` supplies child user/system CPU and lifetime peak RSS; timeout
control uses the owned child's pidfd. Resident socket time includes scheduling
and durable request-ledger work. Worker dispatch CPU/wall fields exclude
pending/done ledger synchronization and transport.

Complete MCP uses one separate private resident worker per transport with the
same model, Python and package. It excludes controller startup and model open,
which are separately recorded. It includes submission, SSH/process startup,
polling and response observation. It stops at the first response, not an
additional helper-terminal status query. Both resident terminal states were
checked during cleanup; each short-lived helper was not separately qualified
by a terminal-status poll.

Measured calls use unique request IDs. Route order alternates AB/BA by round
(ABBA over pairs); direct socket runs alternate before/after the pair. OS file
cache is warm and uncontrolled. Identical probe inputs can reuse content-addressed
output artifacts despite distinct request IDs executing separate operations.

The private MCP host explicitly uses `execution_mode = operator`,
`system_jobctl = false`, localhost SSH and user systemd. Operator mode claims
no executable/path argument sandbox and requires network permission under
the runtime's validation. Both shipped helpers keep **50% CPU quota, nice 10
and 512 MiB memory**. The shipped native MCP wrapper sets
`TOKIO_WORKER_THREADS=1`; standalone helpers use normal native CLI defaults.
Each model worker is limited to one CPU thread and 1 GiB. These results qualify
only that operator configuration, not isolated/system-jobctl mode.

## Latency

Milliseconds, nearest-rank **p50 / p95**. Helper/socket cells have n = 20.

| Operation | Native cold helper | Python cold helper | Resident socket |
| --- | ---: | ---: | ---: |
| inspect | 2928.3 / 3805.4 | 151.9 / 239.8 | 89.1 / 562.4 |
| probe | 2966.3 / 4969.0 | 277.6 / 436.1 | 200.6 / 520.5 |
| query | 2845.5 / 3958.4 | 155.9 / 595.0 | 102.4 / 586.9 |

Complete-MCP cells have n = 5; p95 is the observed maximum, not a stable
production-tail estimate.

| Operation | Native complete MCP | Python complete MCP | Native/Python p50 |
| --- | ---: | ---: | ---: |
| inspect | 6860.8 / 7861.8 | 1738.4 / 1852.7 | 3.95x |
| probe | 6987.9 / 7239.5 | 1612.6 / 1910.3 | 4.33x |
| query | 7344.4 / 7437.7 | 1569.8 / 2565.6 | 4.68x |

Native operations required a median of nine `weight_read` calls versus one for
Python. Worker dispatch CPU remains small: roughly 0.5–0.8 ms for inspect,
4–7 ms for probe and 1–3 ms for query. These helper differences do not show
a change in PyTorch inference performance.

## CPU, memory and interpretation

Fresh-helper CPU, milliseconds, **p50 / p95 of each sample's user + system CPU**.
Quantiles are not sums of independently summarized components.

| Operation | Native helper CPU | Python helper CPU |
| --- | ---: | ---: |
| inspect | 2765.9 / 2922.7 | 75.0 / 83.1 |
| probe | 2720.7 / 2935.2 | 76.5 / 84.1 |
| query | 2718.3 / 2865.6 | 75.9 / 78.7 |

All measured helpers returned exactly 22,260 KiB lifetime `ru_maxrss`. This
metric does not resolve post-exec steady-state working sets in this run and
supports no native memory-saving claim. Shared resident peak RSS after samples
was 241,420 KiB,
including the common Python/PyTorch engine.

`src/mcp/weight_native.rs::verify_pins` hashes the entire running native binary
on each invocation as well as the worker/package. Python compatibility checks
the worker/package but does not hash the interpreter itself. Native therefore
verifies 391,130,912 executable bytes per fresh invocation here. The
operation-independent CPU cost is consistent with startup and identity
verification overhead. There was no separate profiler, so the data do not
assign every millisecond to hashing.

The existing 50% helper CPU quota can amplify CPU-intensive startup in MCP
wall time. The quota, integrity checks and inputs remained unchanged. A
stripped optimized binary may change the result; dropping checks or changing
one route's budget would measure a different contract.

## Correctness and cleanup

Same-ID inspect, probe and query responses were byte-for-byte equal through
both helpers. Replayed probe kept the forward-example total at one. Both
returned the same bounded `UNKNOWN_TENSOR` and `IDEMPOTENCY_CONFLICT` errors.
Every measured query checked the exact identity output. This is selected real
protocol coverage, not exhaustive engine or transport parity.

The direct worker closed with exit 0. Both MCP resident jobs reached
authoritatively recorded terminal states with durable output and terminal
publication confirmed:

| Route | Resident job | Terminal |
| --- | --- | --- |
| Native | `1a1a139279f-31fb92-1` | cancelled, exit -15, timed_out false |
| Python | `1a1a1399681-320609-1` | cancelled, exit -15, timed_out false |

These cancellations are the actual `weight_close` behavior. Private MCP
fixtures were deleted only after successful cleanup. The result records
`fixture_retained = false` and no cleanup error.

## Host pressure and excluded preparation attempts

An independent read-only observer collected 34 five-second samples,
from 2026-11-03T11:44:27.352066+00:00 to 2026-11-03T11:47:12.466040+00:00, during the later MCP phase
only. Maximum host-wide PSI avg10 was 3.72% CPU some,
20.44% I/O some and 19.92%
I/O full; memory some/full remained zero. This does not attribute pressure to
a particular build or workload. Shared-host I/O noise limits wall-time
generalization; no confidence interval or universal speedup is claimed.

Earlier preparation attempts are excluded: capture rejected a concurrently
rebuilt binary, one cold worker open exceeded an initial deadline, a same-ID
trace filename collided, and an invalid operator configuration was refused
before initialization. A legacy isolated/system-jobctl attempt could not use
an installed backend. That old harness did not confirm cleanup and removed
private state before preserving the accepted job ID. It is not confirmed
cleanup or isolated-mode qualification. The frozen formal driver retains failed
fixtures and records MCP transcripts and admitted job IDs.

## Evidence and repetition

- [All 210 samples and metadata](benchmarks/20261103-dev-client-comparison.json)
- [Semantic response frames](benchmarks/20261103-dev-semantic-frames.jsonl)
- [Partial-window pressure samples](benchmarks/20261103-dev-host-pressure.jsonl)
- [Excluded preparation records](benchmarks/20261103-dev-preparation-failures.json)

Full traces, MCP transcripts, logs and private executable remain at
`/home/qian-qi/work/hepta-rea-benchmark-dev-20261103-formal-r1`. Keep the Python
venv pathname; resolving it to its system interpreter changes the environment.

~~~sh
python3 scripts/weight_client_benchmark.py \
  --binary /path/to/exact/hepta-runtime \
  --python /home/qian-qi/work/hepta-weight-runtime-20261103-venv/bin/python \
  --worker /home/qian-qi/hepta-runtime-rea-full-20261103-r1/workers/weight/worker.py \
  --output /new/private/benchmark-directory \
  --build-profile ACTUAL_BUILD_PROFILE \
  --source-revision ACTUAL_SOURCE_IDENTITY \
  --samples 20 --mcp-samples 5 --with-mcp
~~~

Use a new output directory and retain unfavorable results. Native transport
remains opt-in while release and broader workloads are evaluated. No existing
production model, profile, service, credential or training job was changed.
