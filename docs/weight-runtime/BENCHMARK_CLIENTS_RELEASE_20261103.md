# Native weight client: release qualification, 2026-11-03

## Result and decision

The release build and all 210 measured requests passed, with five selected
semantic checks passing. Original weights, frozen driver and captured production
source remained unchanged. Both owned MCP resident workers reached terminal
states and their private fixture was cleaned.

**Keep native transport opt-in.** Release native helpers used more CPU and had
higher median standalone wall time than Python compatibility. Complete MCP
medians were nearly equal for inspect and lower for native probe/query. However,
n = 5 per operation and large shared-host I/O tails do not establish a general
end-to-end benefit. Preserve both favorable medians and negative CPU findings,
without replacing the earlier negative development dataset or retuning budgets.

This compares Rust and Python **client/transport helpers**. Every computation
still uses the unchanged Python/PyTorch CPU engine. It establishes no Rust
tensor-engine, training or whole-REA performance claim.

## Build and source identity

| Item | Identity |
| --- | --- |
| Git baseline | `f9756508462ebc72e814a12f5dbba1b067edabe4` plus integration changes |
| Production-source manifest SHA-256 | `d2e3016c002ca8a06a38ef4dcdd096e4b8686b348dcee91931fd2b20ccfe1ca6` |
| Runtime SHA-256 | `a697e102520cc483fe047665d86a3fab3049c74e7298936319d0f4bb224d0a82` |
| Runtime bytes | 16,486,368 |
| Frozen driver SHA-256 | `10ec5cb1510dbb0da2e1ef0cdfeba3417cd7f0edc1864c628b80d89a90125381` |
| Compiler | `rustc 1.95.0 (59807616e 2026-04-14)` |
| Cargo | `cargo 1.95.0 (f2d3ce0bd 2026-03-21)` |
| Release profile | opt-level 3, LTO true, strip true, codegen-units 1, panic abort; overflow-checks false |
| Build jobs / elapsed | 2 / 575.754 seconds |
| Outer build/benchmark job | `1a1a14efda3-96a-6e38` |
| Raw result SHA-256 | `9e8500faa8f15ccb973c00d4aaedbe8595c596db1c59dfc5b3834e0e5b8ae7ae` |
| Worker entry SHA-256 | `10c09efcb24d65ce850ccbee61f3034262fa026ee5d19adab90bc9eda67049c0` |
| Worker package SHA-256 | `4ea015d5844e5b4d2df4025b39aad39f5a7e96a44952e507e857add2d9fd100e` |
| Fixture weights SHA-256 | `4c1975369a276b70bef42960ec208308389559af14ac10e05e16945dad580593` |

The manifest includes production files beneath `src` and existing Cargo inputs,
build script, toolchain/config inputs. It excludes test directories and names
ending `_tests.rs` or `_test.rs`. Exact path/hash lists were captured before
build, after build and after benchmark; all three aggregates match. The frozen
driver hash also matches after the run. This intentionally excludes tests-only
lint edits and does not claim tests were identical across earlier builds.

Actual command from the isolated integration checkout:

~~~sh
CARGO_HOME=/home/qian-qi/.cargo \
CARGO_TARGET_DIR=/home/qian-qi/work/hepta-rea-full-20261103-r1-release-target \
CARGO_BUILD_JOBS=2 \
/home/qian-qi/.cargo/bin/cargo build \
  --locked --offline --all-features --release --bin hepta-runtime \
  --jobs 2 \
  --target-dir /home/qian-qi/work/hepta-rea-full-20261103-r1-release-target
~~~

The development gate used private cache
`/home/qian-qi/work/hepta-rea-full-20261103-r1-cargo`. This release was already
compiling normally with `/home/qian-qi/.cargo` when the difference was
confirmed, so it was not restarted. An audit found no Cargo `config` or
`config.toml` in either cache, the repository or its ancestors. Recorded
RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS/RUSTUP_TOOLCHAIN overrides were empty.
Locked dependency inputs are in the source manifest. The audit emitted no
credentials. The benchmark ran a private copied binary with a verified digest,
independent of later debug rebuilds.

## Relation to the development cohort

The earlier development binary was
`a41c7b4b1675c94078e76507a65e588359129f9a4e56075e4246f385e4bd0612`,
391,130,912 bytes. Release has an exact production-source manifest; the
development cohort has a binary digest and uncommitted source label, but no
complete captured build-input manifest including source and dependency features.
Consequently, **a strictly identical whole-source compiler-profile A/B between
dev and release is not established**. Different binary digests alone do not
prove a production-source change.

A separate byte comparison proves that all 26
selected production Rust weight modules and Python worker source files remain
identical to PR84. Worker entry/package and fixture identities match both runs.
Those facts support consistent helper/engine contracts, but do not make the
whole executables identical. Do not attribute the cross-run change entirely
to optimization, stripping, binary size or one source edit.

The primary valid comparison here is **native versus Python within this release
cohort**, using the same release controller, model, worker package, operator
mode and budgets. [The development report](BENCHMARK_CLIENTS_DEV_20261103.md)
and its unfavorable raw data remain separate.

## Fixed workload and measurement boundaries

The frozen `scripts/weight_client_benchmark.py` was unchanged. A 64 x 64 F32
identity Linear receives one fixed 64-element example per probe. Query checks
all expected values. Inspect requests hashes. Models use torch 2.6.0+cpu with
one intra-op and one inter-op thread, inference/evaluation mode, one CPU thread
and a 1 GiB profile envelope. The existing Python 3.12.3 venv and worker were
reused without installation or backend modification.

| Layer | Interval | n per operation |
| --- | --- | --- |
| Cold helper | Fresh helper launch, local socket round trip through shared resident worker, process exit | 20 native; 20 Python |
| Resident socket | Driver connect/send through same resident worker and ledger to response EOF | 20 direct |
| Complete MCP | `weight_call` submission, original localhost SSH job, response observed by `weight_read` | 5 native; 5 Python |

MCP excludes controller startup/model open, recorded separately, and ends at
the first response rather than an extra helper-terminal query. Each transport
uses a private MCP resident worker with the same model/backend; standalone
routes share one resident worker. Measured request IDs are unique. Same-input
content-addressed probe artifacts can be reused. Route order alternates AB/BA
per round (ABBA over pairs), with direct socket alternating before/after that
pair. OS file cache is warm and uncontrolled.

The MCP path explicitly uses **operator mode**, existing localhost SSH, user
systemd and `system_jobctl=false`. It claims no command sandbox and requires
operator network permission. It does not qualify isolated/system-jobctl mode.
Both helpers retain **50% CPU quota, nice 10 and 512 MiB**. The shipped native
MCP wrapper sets `TOKIO_WORKER_THREADS=1`; standalone CLI samples keep normal
native defaults. Budgets, request contracts and identity checks were unchanged.

## Latency

Milliseconds, nearest-rank **p50 / p95**. Helper/socket cells have n = 20.

| Operation | Release native cold helper | Python cold helper | Resident socket |
| --- | ---: | ---: | ---: |
| inspect | 247.3 / 1004.6 | 191.0 / 1130.0 | 126.2 / 1151.6 |
| probe | 383.7 / 3376.7 | 334.9 / 3484.2 | 267.6 / 3017.6 |
| query | 257.9 / 1220.6 | 186.6 / 1444.5 | 120.9 / 1139.0 |

Native cold-helper medians are higher for all three operations. Means are
affected by shared-host stalls; all individual samples are preserved.

Complete MCP cells have n = 5; p95 therefore equals the maximum observation.

| Operation | Release native MCP | Python MCP | Native/Python p50 |
| --- | ---: | ---: | ---: |
| inspect | 1584.0 / 7513.7 | 1565.4 / 7208.0 | 1.012x |
| probe | 1925.7 / 8822.8 | 2789.0 / 4757.2 | 0.690x |
| query | 1581.8 / 1811.2 | 1911.7 / 7355.7 | 0.827x |

Native probe/query medians are lower, while inspect is nearly equal. The native
probe maximum is 8.8 seconds; Python inspect/query maxima exceed seven seconds.
Every complete-MCP request needed exactly one `weight_read`. No consistent
operation-wide tail advantage or confidence bound establishes general gain.

Resident socket medians are about 121–268 ms despite small engine dispatch
CPU. Socket time includes durable-ledger synchronization and scheduling. Worker
`cost` counters exclude ledger/transport work and cannot replace full latency.

## CPU and memory

Cold-helper CPU is per-sample user plus system CPU from Linux `wait4`.
Values are milliseconds, p50 / p95; ratios compare p50. Quantiles are not sums
of independently summarized components.

| Operation | Native helper CPU | Python helper CPU | Native/Python |
| --- | ---: | ---: | ---: |
| inspect | 133.3 / 142.6 | 76.7 / 82.2 | 1.74x |
| probe | 131.2 / 151.3 | 77.5 / 88.3 | 1.69x |
| query | 130.7 / 145.9 | 76.5 / 85.5 | 1.71x |

Native CPU is about 1.69–1.74 times Python here. Native verifies its complete
16.5 MB executable and worker/package per call. Python compatibility checks
worker/package but not its interpreter. Native default Tokio startup and other
client work also fall in this measurement. No attribution profiler was used;
do not assign a precise fraction to hashing/threads or infer identical CPU
for the differently configured MCP wrapper.

Per-client-process lifetime peak RSS from `wait4`, in KiB:

| Route | Samples | p50 | p95 | min–max |
| --- | ---: | ---: | ---: | ---: |
| native_rust | 60 | 23,056 | 23,056 | 23,056–23,056 |
| python_compat | 60 | 23,056 | 23,056 | 23,056–23,056 |

The metric does not distinguish post-exec steady-state working sets in this
run. There is **no demonstrated native memory reduction** and these are not
whole-job or backend RSS. The common resident PyTorch worker's separate
observed high-water RSS was
240,740 KiB.

## Semantic and lifecycle results

| Check | Result |
| --- | --- |
| Same-ID inspect/probe/query across helpers | Byte-equal response frames |
| Replayed probe | Forward-example total remains one |
| Missing tensor | Same `UNKNOWN_TENSOR` response |
| Conflicting same ID | Same `IDEMPOTENCY_CONFLICT` response |
| Every measured query | Exact expected identity output |
| Source weights in direct and MCP routes | SHA-256 unchanged |
| Direct resident close | Exit 0 |
| Native MCP resident | `1a1a15a4982-3439a0-1`; cancelled, exit -15, timed_out false |
| Python MCP resident | `1a1a15a95cb-344662-1`; cancelled, exit -15, timed_out false |

Both MCP terminal records confirm publication and durable output. Cancellation
is the actual `weight_close` behavior. There is no cleanup error and
`fixture_retained=false`. This is not a separate terminal poll for every
short-lived helper. Selected real-protocol coverage does not cover model
mutation operations, other providers, GPU or multi-host performance.

## Host conditions

An independent observer recorded 27 five-second samples, from
2026-11-03T12:20:23.445514+00:00 to 2026-11-03T12:22:33.625665+00:00. It began after the benchmark
started and covers that window only. Maximum host-wide avg10 PSI:

| Pressure | Maximum |
| --- | ---: |
| CPU some | 2.06% |
| I/O some | 23.00% |
| I/O full | 21.82% |
| Memory some | 0.53% |
| Memory full | 0.53% |

The host has 48 visible logical CPUs. One-minute load was
7.17 at start and
19.96 at end. These host-wide data
do not attribute pressure to a particular build/service. Large wall-time tails
and n = 5 MCP cells limit inference despite all measured calls succeeding.
The raw CPU, wall and semantic evidence remains useful without a universal
speedup claim.

## Evidence and repetition

- [Complete release cohort](benchmarks/20261103-release-client-comparison.json)
- [Authoritative outer-job receipts](benchmarks/20261103-benchmark-runtime-receipts.json)
- [Build command and before/after source manifests](benchmarks/20261103-release-build-provenance.json)
- [Compiler configuration audit](benchmarks/20261103-release-compiler-config-audit.json)
- [Weight implementation byte comparison](benchmarks/20261103-weight-implementation-identity.json)
- [Actual build log](benchmarks/20261103-release-build.log)
- [Semantic response frames](benchmarks/20261103-release-semantic-frames.jsonl)
- [Partial-window pressure](benchmarks/20261103-release-host-pressure.jsonl)

The host retains full traces, MCP transcripts, logs and private executable at
`/home/qian-qi/work/hepta-rea-benchmark-release-20261103-formal-r1`. Exact
benchmark arguments are in the build provenance: `--samples 20 --mcp-samples 5
--with-mcp` with actual release profile and production-source digest.
Development preparation failures remain documented in that report; they are
not silently counted as success or isolated-mode qualification.

No production profile, model, credential, service or training job changed.
Python compatibility remains available and native selection stays explicit.
