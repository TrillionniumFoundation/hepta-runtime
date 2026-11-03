# Native weight client: closure measurements, 2026-11-03

## Result and decision

The reviewed release candidate lowers standalone helper CPU and median wall time
for this fixed workload while preserving the measured protocol and lifecycle
contracts. Native mean helper CPU is **78.31–80.97 ms**, compared with
**95.72–96.58 ms** for Python compatibility in the same formal cohort. All three
helper wall p50 values are lower. A separate fixed-binary ABBA comparison also
shows lower whole-process cost on native paths reaching executable content
hashing and on both bounded large-response paths.

**Keep native transport opt-in.** Complete MCP results remain mixed: native
inspect/probe p50 values are slightly lower, query p50 is higher, and probe/query
p95 values are higher. This supports the concrete client change, without
establishing a universal end-to-end speedup, a default-selection change, or a
Rust replacement for the compute engine. Both routes still use the same
Python/PyTorch CPU backend.
[Derived distributions](../qualification/rea-weight-client-closure-20261103-r1/derived-statistics.json)
and both complete cohorts are retained.

The original identity job completed with 240 validated samples and no failures;
the formal job completed with 300 successful timed samples. No benchmark was
rerun while preparing this report.
[Original-job receipts](../qualification/rea-weight-client-closure-20261103-r1/runtime-receipts.json)
confirm both succeeded with exit 0 and complete output. The
[earlier release](BENCHMARK_CLIENTS_RELEASE_20261103.md) and
[development](BENCHMARK_CLIENTS_DEV_20261103.md) cohorts remain separate historical
evidence. Different binaries, source states, host windows and MCP sample counts
are not pooled or treated as a controlled compiler-profile comparison.

## Exact build and source identity

| Item | Recorded identity |
| --- | --- |
| Baseline source | Clean `23246a5313957e9e97e324303bc47a91808f1ea8` at build time |
| Baseline source-inventory SHA-256 | `91ef2f78dbbba8ebb53263cbc555050dcab8f6c43f627e981e26c116583da787` |
| Baseline executable | `adaf8c26d3e4cbcc34699cbfeca6d678cc3f2f40d148babab9d4224424e1e820`; 16,502,624 bytes |
| Candidate source | Same base commit **plus six reviewed modified files** |
| Candidate source-inventory SHA-256 | `0d4d316c6ea9de52276e359e711749a404d3e60191c4d37d7fcd8dcb2c39a28c` |
| Candidate Git diff SHA-256 | `79cef8bff8213a1f159c310a98ce5fdf29505113745a93b07debd2f61ef651ec` |
| Candidate executable | `201fa5df3559bb4c22a9d5745ef3a086343e40c74298e1a3903d4d8a41c7131a`; 16,502,688 bytes |
| Build | Rust 1.95.0; `--locked --offline --all-features --release --bin hepta-runtime` |
| Worker entry SHA-256 | `10c09efcb24d65ce850ccbee61f3034262fa026ee5d19adab90bc9eda67049c0` |
| Worker package SHA-256 | `4ea015d5844e5b4d2df4025b39aad39f5a7e96a44952e507e857add2d9fd100e` |
| Fixture weights SHA-256 | `4c1975369a276b70bef42960ec208308389559af14ac10e05e16945dad580593` |
| Identity driver SHA-256 | `f5767d02fe71cff8c86b350a10cea7e271d5575ef4e7d6d99224b1a0fe4b8c30` |
| Formal driver SHA-256 | `10ec5cb1510dbb0da2e1ef0cdfeba3417cd7f0edc1864c628b80d89a90125381` |

The candidate is **not a clean build of 23246 and is not identified here as a
newly published head**. Comparing complete build inventories finds exactly six
changed content paths: `request_archive_index.rs`,
`request_archive_index_tests.rs`, `request_usage_batch.rs`, `server.rs`,
`weight_native.rs` and `weight_native_tests.rs` under the recorded `src/mcp`
paths. Full MCP measures that integrated artifact, including audit admission and
tool-description changes.
[Source selections and full-manifest references](../qualification/rea-weight-client-closure-20261103-r1/source-manifest-selection.json)
preserve the linkage.

The [baseline](../qualification/rea-weight-client-closure-20261103-r1/baseline-release-result.json)
and [R3 candidate](../qualification/rea-weight-client-closure-20261103-r1/candidate-build-r3-result.json)
build results are qualified. Before/after inventories match; source monitors
completed with zero events and errors. R3 reuses R2's successfully compiled
all-feature test library, SHA-256
`924180ac166d07051d2aae8ffb349a99c086ad4964f420ddb5f089fbefedcd91`.
R2's enclosing result remains `qualified=false` because its summary regex was
incorrect, although compilation and the exact warm regression exited 0.
The [original failure](../qualification/rea-weight-client-closure-20261103-r1/candidate-build-r2-result.json)
and [correction receipt](../qualification/rea-weight-client-closure-20261103-r1/candidate-prior-harness-correction.json)
are retained. Successful artifact reuse does not erase the failed outer summary.

The client uses existing `ring` SHA-256 for full-byte file identity and returns
the already validated frame with its success flag, removing a second parse.
The same descriptor/metadata checks, full executable/worker/package pins,
duplicate-key and response-ID validation, bounded framing, owner/socket
boundaries, cancellation and no-resend behavior remain. No dependency or
path/mtime identity shortcut was introduced.
[Implementation](../../src/mcp/weight_native.rs) and
[regressions](../../src/mcp/weight_native_tests.rs) describe those contracts.
[All-feature](../qualification/rea-weight-client-closure-20261103-r1/candidate-weight-native-all.log)
and [no-default-feature](../qualification/rea-weight-client-closure-20261103-r1/candidate-weight-native-no-default.log)
logs each record ten passing native-client tests. Those are the specific test
gates cited here.

### Tokio attribution

Baseline and candidate native CLIs both already select Tokio `current_thread`.
Only the `mcp` server command selects `new_multi_thread` in the
[main entry point](../../src/main.rs), identical in both source inventories.
The wrapper's existing `TOKIO_WORKER_THREADS=1` is not evidence that this change
removed a host-sized Tokio pool from the standalone helper. Other helper work
and threads remain within measured CPU; no thread/function profiler was collected.

## Workload and measurement method

| Cohort/layer | Comparison and workload | Timed samples |
| --- | --- | ---: |
| Identity | Fixed baseline/candidate binaries; four pre-send exits and two fixture responses | 20 per binary per stage; 240 total |
| Cold helper | Fresh native/Python helper through a shared resident worker | 20 per route per operation; 120 total |
| Resident socket | Direct call through that worker and ledger | 20 per operation; 60 total |
| Complete MCP | Candidate controller; separate owned resident worker per route | 20 per route per operation; 120 total |

Identity ran **18:21:17–18:21:49 UTC**; formal ran **18:30:02–18:34:34 UTC**, on
2026-11-03. Formal operations are inspect with hashing, probe with one fixed
example, and query of all 64 expected values from an F32 64 × 64 identity Linear.
The model uses torch 2.6.0+cpu, `torch_sequential`, inference/evaluation mode and
one intra-op/inter-op thread. The backend was not rewritten.
[Identity results](../qualification/rea-weight-client-closure-20261103-r1/identity-results.json)
and [formal results](../qualification/rea-weight-client-closure-20261103-r1/formal-results.json)
retain the environments and all sample arrays.

Routes alternate A,B and B,A per round, forming complete ABBA blocks. Direct
socket alternates before/after the helper pair. The unchanged formal driver has
explicit warmups and separate semantic checks; identity excludes no warmup
samples. Every recorded timed sample is retained. No outlier filtering, retry,
deadline retuning or helper resource-quota change was introduced. Fresh helpers
use a **warm, uncontrolled OS file cache**, including warming from input
copying/hashing; this is not a cold-cache experiment.

Helper wall time starts immediately before `Popen` and ends at `wait4` reap:
launch, exec, validation, socket work, output and exit are included. Preparation,
later trace validation and evidence persistence are excluded. Direct-child
`wait4` CPU includes its threads, excluding driver/worker/responder CPU.
For each sample we calculate **user CPU + system CPU before summarizing**.
Independent component p50 values are never added. Nearest rank is
`sorted[ceil(q*n)-1]`; at n = 20, p50 is the tenth and p95 the nineteenth ordered
value.
[Derived statistics](../qualification/rea-weight-client-closure-20261103-r1/derived-statistics.json)
include this method, means and unrounded values.

Complete MCP wall time covers `weight_call` submission, the original localhost
SSH request job and the response observed by `weight_read`. Controller/model
startup is recorded separately; the interval ends at response observation, not
an extra per-helper terminal poll. Empty reads retain the driver's 20 ms poll
interval. Both routes use administrator-configured **operator mode**, localhost
SSH, user systemd and `system_jobctl=false`. This does not qualify isolated/jobctl
mode. Native selection is explicit in its benchmark profile.
[Exact formal arguments](../qualification/rea-weight-client-closure-20261103-r1/formal-launch.json)
include `--samples 20 --mcp-samples 20 --with-mcp`.

## Formal helper results

Milliseconds, n = 20 per cell. Wall cells show **p50 / mean / p95**.

| Operation | Native cold-helper wall | Python cold-helper wall |
| --- | ---: | ---: |
| inspect | 113.02 / 123.34 / 211.80 | 122.93 / 137.24 / 213.48 |
| probe | 140.71 / 147.63 / 202.01 | 155.86 / 172.87 / 251.40 |
| query | 113.07 / 124.71 / 182.11 | 130.51 / 130.81 / 136.38 |

Native p50 is lower for every operation. Tails remain mixed: native query p95
is higher despite its lower p50 and mean.

CPU cells summarize actual per-sample user+system totals:

| Operation | Native CPU p50 | Native CPU mean | Python CPU p50 | Python CPU mean | Native/Python mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| inspect | 79.43 | 80.33 | 96.64 | 96.07 | 0.836x |
| probe | 78.67 | 78.31 | 96.29 | 95.72 | 0.818x |
| query | 80.42 | 80.97 | 96.08 | 96.58 | 0.838x |

Observed native mean CPU is about 16–18% lower within this cohort. Historical
release Python CPU values of 76–78 ms belong to another window and are not the
comparison denominator. Native still verifies its approximately 16.5 MB
executable and worker/package; Python verifies worker/package without the same
interpreter-content check. Different identity obligations remain part of the
real helper contracts.
[Raw samples](../qualification/rea-weight-client-closure-20261103-r1/formal-results.json)
and [computed totals](../qualification/rea-weight-client-closure-20261103-r1/derived-statistics.json)
support these values.

The same worker's direct-socket measurements provide context:

| Operation | Socket wall p50 / mean / p95 | Worker dispatch CPU p50 |
| --- | ---: | ---: |
| inspect | 21.88 / 27.72 / 32.60 | 0.59 |
| probe | 51.80 / 76.30 / 167.02 | 4.93 |
| query | 22.97 / 27.61 / 29.62 | 1.86 |

RTT includes durable-ledger synchronization and transport. Worker dispatch cost
excludes pending/done ledger fsync and transport. These different intervals must
not be subtracted to invent isolated component costs.

## Complete MCP results

Milliseconds, **p50 / mean / p95**, n = 20 per route per operation.

| Operation | Native complete MCP | Python complete MCP |
| --- | ---: | ---: |
| inspect | 1184.19 / 1497.16 / 3688.07 | 1197.76 / 2012.77 / 5177.41 |
| probe | 1187.09 / 1597.99 / 5040.87 | 1193.55 / 1509.29 / 3685.40 |
| query | 1193.71 / 1429.71 / 1563.33 | 1165.65 / 1364.66 / 1438.75 |

Native p50 is 13.57 ms lower for inspect and 6.47 ms lower for probe, but 28.06 ms
higher for query. Native inspect has lower mean/p95; native probe/query have
higher means and p95 values. Small mixed medians and large tails do not establish
a general end-to-end advantage. Lower standalone CPU can coexist with mixed
timings across admission, job, transport and observation boundaries.

All 120 MCP samples succeeded. Native always required one `weight_read`; Python
required one except for one probe requiring two. Raw rows retain submit time,
observation time, original request-job ID and worker counters. Per-operation MCP
helper CPU was not collected; standalone CPU is not whole-MCP CPU.
[Formal records](../qualification/rea-weight-client-closure-20261103-r1/formal-results.json)
preserve these fields.

## Identity and bounded large-response comparison

This cohort compares the fixed clean-baseline and reviewed-candidate releases
using one private real Unix socket fixture. The real Python path and full
worker/package identity are pinned and rechecked. The responder supplies
deterministic frames; no model/Python compute-backend work is measured.
[Exact launch](../qualification/rea-weight-client-closure-20261103-r1/identity-launch.json)
records both digests, source labels, `--samples 20` and a 786,432-byte budget.

### Four cumulative pre-send exits

| Stage | Intended stop | Result in all 40 samples |
| --- | --- | --- |
| `request_validation` | Wrong request session, before identity hashing | `INVALID_REQUEST`; `not_sent`; zero connections |
| `client_hash` | Wrong executable digest after full executable hashing | `IDENTITY_MISMATCH`; `not_sent`; zero connections |
| `worker_hash` | Correct executable pin; wrong worker digest | `IDENTITY_MISMATCH`; `not_sent`; zero connections |
| `package_hash` | Correct executable/worker pins; wrong package digest | `IDENTITY_MISMATCH`; `not_sent`; zero connections |

Exact error envelopes, exit 1 and disabled automatic retry are checked.
Milliseconds, n = 20 per binary:

| Stage | Baseline wall p50 | Candidate wall p50 | Baseline CPU p50 / mean | Candidate CPU p50 / mean |
| --- | ---: | ---: | ---: | ---: |
| request_validation | 2.68 | 2.59 | 2.51 / 2.68 | 2.45 / 2.57 |
| client_hash | 128.74 | 77.84 | 127.73 / 129.31 | 76.76 / 78.38 |
| worker_hash | 129.24 | 76.90 | 128.42 / 129.19 | 75.98 / 76.50 |
| package_hash | 130.61 | 78.96 | 129.64 / 128.19 | 78.19 / 77.73 |

The validation-only path changes little; paths reaching executable content
hashing show a much larger whole-process reduction. This localizes the observed
difference to paths reaching identity work. These remain cumulative
startup/validation paths with different exits, not isolated SHA-256 timers.
Subtracting p50 values does not identify an exact hashing cost.
[Outcome/trace reconciliation](../qualification/rea-weight-client-closure-20261103-r1/semantic-validation.json)
preserves the boundaries.

### Bounded real-socket responses

All 80 samples preserve the exact expected raw frame and response ID. Frames
are 786,430 bytes, within the 786,432-byte fixture budget and 1 MiB client bound.
Each sample records one connection, one response, the correct request hash and
no resubmission. Success exits 0; `CONTROLLED_WORKER_ERROR` remains a worker error
and exits 1.

Wall cells show **p50 / mean / p95**, CPU **p50 / mean**; milliseconds,
n = 20 per binary per stage.

| Stage | Baseline wall | Candidate wall | Baseline CPU | Candidate CPU |
| --- | ---: | ---: | ---: | ---: |
| large_success | 153.34 / 150.06 / 157.20 | 91.99 / 91.89 / 98.34 | 152.16 / 149.04 | 90.87 / 90.84 |
| large_worker_error | 153.45 / 154.79 / 170.22 | 91.91 / 96.07 / 128.53 | 152.05 / 153.41 | 90.68 / 90.44 |

Complete-client cost is lower on both paths. That interval includes startup,
all content pins, transport, validation, output and exit. Hashing and repeated
parsing change together. **No parser-only speedup or exact parser CPU saving is
established.**
[Complete results](../qualification/rea-weight-client-closure-20261103-r1/identity-results.json)
retain frame hashes, outcomes, source labels and original trace paths.

## Semantics, input integrity and original owners

| Formal native/Python check | Result |
| --- | --- |
| Same-ID inspect replay | Exact response bytes equal |
| Same-ID probe replay | Exact bytes equal; semantic forward count remains one |
| Query | Equal bytes and all 64 expected values |
| Missing tensor | Equal `UNKNOWN_TENSOR` worker error |
| Changed payload with same ID | Equal `IDEMPOTENCY_CONFLICT` response |

The ten small [semantic frames](../qualification/rea-weight-client-closure-20261103-r1/semantic-response-frames.json)
retain both routes' original bytes and hashes. Documentation-time reconciliation
checks all 300 measured raw-response hashes and all 100 measured query arrays.
Forward counters match every measured call: shared worker **61** (one semantic
probe plus 60 timed probes), each MCP worker **21** (one warm probe plus 20 timed
probes). Measured IDs are unique within their owning session; distinct MCP
sessions reuse readable `mcp-...` labels, not a global owner identity.
[Reconciliation](../qualification/rea-weight-client-closure-20261103-r1/semantic-validation.json)
uses retained data and does not rerun the workload.

| Original owner | Actual completion |
| --- | --- |
| Identity benchmark | `1a1a2a4e0d8-96a-74a6`; succeeded, exit 0, complete output |
| Formal benchmark | `1a1a2ace298-96a-74ca`; succeeded, exit 0, complete output |
| Shared resident worker | Protocol close followed by exit 0 |
| Native MCP resident | `1a1a2ad5ae1-16a7d6-1`; cancelled, exit -15, not timed out |
| Python MCP resident | `1a1a2adaa95-16af06-1`; cancelled, exit -15, not timed out |

MCP cancellation is the actual `weight_close` behavior. Subsequent `weight_status`
records confirm terminal publication and durable, complete output for each
original resident owner; stop-request receipts alone are not terminal evidence.
The formal fixture was removed (`fixture_retained=false`); identity reports
`closed_and_removed`. These are resident closure checks, not extra terminal polls
for every short-lived helper.
[Formal lifecycle records](../qualification/rea-weight-client-closure-20261103-r1/formal-results.json)
and [benchmark receipts](../qualification/rea-weight-client-closure-20261103-r1/runtime-receipts.json)
remain separate.

All seven identity-driver final full-content checks report unchanged: driver,
Python, both source binaries, both captured binaries and full worker package.
Formal checks the source-weight SHA-256 in all three model fixtures. The
additional [documentation-time recheck](../qualification/rea-weight-client-closure-20261103-r1/documentation-input-recheck.json)
rehashes retained releases, both drivers, Python, all worker/package files and
the six reviewed sources. Its timestamp/scope are distinct from original
in-run checks; this is not an invented continuous benchmark source monitor.

## Resource and inference limits

All 120 formal helper lifetime peak-RSS values are **22,672 KiB**. Identity
pre-send samples report 21,896 KiB; large-response p50 is 29,460 KiB.
These are `wait4.ru_maxrss` lifetime values, potentially retaining an inherited
pre-exec high-water mark. **They cannot establish post-exec or steady-state RSS,
or a native memory reduction.** The shared PyTorch worker's separate observed
post-sample high-water is 246,820 KiB, not helper or whole-MCP memory.

The recorded host exposes 48 logical CPUs, all in the affinity mask.
One-minute load changes from 10.42 to 9.13 for identity and 7.89 to 7.86 for
formal. Launch receipts contain point-in-time pressure readings, not continuous
pressure traces. ABBA and full sample retention do not remove shared-host
variability or provide a speedup confidence bound.
[Launch snapshots](../qualification/rea-weight-client-closure-20261103-r1/formal-launch.json)
and [raw environments](../qualification/rea-weight-client-closure-20261103-r1/identity-results.json)
support this limited host description.

The evidence covers this CPU model, these client paths/executables and these
observed windows. It does not measure GPU, other providers, mutation/training,
multi-host capacity, arbitrary REA engines or production activation. The
concrete helper CPU concern has a measured implementation improvement with
retained semantics; mature backends and explicit native selection remain the
integration policy.

## Evidence archive and repetition

The [bounded archive](../qualification/rea-weight-client-closure-20261103-r1/README.md)
contains byte-exact full result JSON, derived distributions, selected
build/launch/terminal receipts, R2's original failure, test logs, source
selections, small semantic frames and input checks. `SHA256SUMS` covers the archive
and reports.

| Complete result | SHA-256 |
| --- | --- |
| `identity-results.json` | `4757c844895d4d1adf6260fae665f13ac69e8a0ff7904f32e795a1eeb85318d5` |
| `formal-results.json` | `1e0c8cdced14c162d7f040ec2d5471eedd44663614a612c1a7744abc31a217df` |

The [external trace manifest](../qualification/rea-weight-client-closure-20261103-r1/external-trace-manifest.json)
records **1,465 files totaling 126,987,011 bytes**, with original paths, sizes and
SHA-256. Large responses, full MCP RPC transcripts and executables remain outside
Git at their owned locations:

~~~text
/home/qian-qi/work/hepta-rea-blockers-20261103-r1/client-identity-abba-r1
/home/qian-qi/work/hepta-rea-blockers-20261103-r1/client-formal-r1
/home/qian-qi/work/hepta-rea-blockers-20261103-r1/baseline-release
/home/qian-qi/work/hepta-rea-blockers-20261103-r1/candidate-build-r2
/home/qian-qi/work/hepta-rea-blockers-20261103-r1/candidate-build-r3
~~~

[Build references](../qualification/rea-weight-client-closure-20261103-r1/external-build-artifacts.json)
retain full-manifest hashes and test-library identities. Test-library hashes
come from recorded immutable build receipts; releases also received the later
content recheck.

For repetition, preserved launch JSON gives exact arguments and frozen drivers
give measurement logic. Use new output directories and fresh owning sessions
with the stated binary, package, workload and resource identities. Keep original
attempts and raw data unchanged. This report changes no default transport,
production profile, model, service or compute backend.
