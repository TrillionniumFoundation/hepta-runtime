# X230 R13: validated operation-record projection

Date: 2026-11-03 (UTC). Repository: TrillionniumFoundation/hepta-runtime.
Lineage: PR #87, following the R12 checkpoint
`fd37e1aeed7f945b352d2a45bc13a8200cdb79fa`.
The R11 comparison binary remains the previously qualified PR #87 baseline.
This report records one frozen R13 implementation and its successful final qualification;
failed earlier qualifications and all unfavorable measurements remain part of the evidence.

## Decision and result

R13 reduces the receipt data retained while status, read, wait and cancel operations
await remote work. The implementation validates the complete original receipt schema
and retains the eight routing fields needed by these operations. It does not retain
private command and payload strings solely to route an already-bound job.

In the dedicated guarded-read experiment, held-cohort resident memory fell
46.76%–87.75% for the tested large plain and escaped receipts. Plain-receipt CPU
fell 42.76%–57.84%; escaped-receipt CPU fell only 1.59%–3.94%.
These are owned-versus-projected reader measurements within one qualified opt-level-1
library-test executable, not old-versus-new release or SSH throughput claims.

R13 does not solve all resource pressure from parallel cancellation preparation.
Against R11, the two large escaped cancellation cases still use 45.20%–56.27%
more controller CPU per mixed RPC and 3.91–5.19 times the whole-child memory
high-water mark, while substantially improving control-plane responsiveness.
This residual is why a separately bounded physical preparation stage is a subsequent
candidate. No result in this report assumes that candidate succeeds.

The six-host observation campaign is approximately flat: throughput changes range
from -1.52% to +2.37%, and controller CPU per call changes by about -0.28% to -0.36%.
It does not establish a general six-host throughput increase. The successful recovery
campaign provides bounded fault-recovery evidence, not proof of arbitrary distributed
exactly-once execution.

## Implementation

The six Rust paths changed relative to R12 are:

- `src/mcp/runtime/jobs.rs`
- `src/mcp/runtime/jobs_record_projection.rs`
- `src/mcp/runtime/jobs_observation_read_tests.rs`
- `src/mcp/runtime/jobs_operation_record.rs`
- `src/mcp/runtime/jobs_operation_record_tests.rs`
- `src/mcp/runtime/jobs_operation_record_bench.rs`

A shared 17-field schema declaration preserves required fields, defaults, field order,
duplicate handling, unknown-field handling and both map and sequence decoding.
Its text parameter distinguishes retained routing text from validated private text.
`ValidatedJobString` deserializes an actual string, validating string type, escapes
and Unicode, and then drops the private value. It does not skip validation using
`IgnoredAny`. Its serialization deliberately fails so the compact view cannot be
persisted as a complete job record.

The compact `OperationRecord` retains execution mode, system-jobctl selection, job ID,
host, SSH target, unit, remote job directory and request digest.
`OperationRecordRef` permits the existing owned start/reuse path and the compact
operation path to share routing logic. Start/reuse and registry recovery continue
to own the complete original record.

Guarded reads still enforce the original size, file, descriptor, host and path
bindings before acting. The raw receipt buffer and validated private payload are
released before remote waits. Escaped JSON still requires parser scratch storage;
other metadata can still allocate. This is not a zero-allocation reader or a hard
global allocation bound.

Cancellation retains the R12 eight-slot publication ownership model in this
checkpoint. A submitted blocking preparation owns its permit even when its caller
disappears. The permit is returned with the prepared operation for subsequent
remote work and completion-audit custody. This does not newly bound all physical
remote SSH attempts after an awaiting caller disappears.

The original durable-record protocol is retained: single-pass encoding, the existing
post-encode size limit, writer lock, file sync, rename and directory sync. No durability
step is removed for performance. R12's capacity hint remains a hint, not an allocation
limit.

## Qualification and provenance

Host: `qian-ThinkPad-X230`, four logical CPUs, approximately 7.6 GiB memory.
Pinned toolchain: Rust 1.95.0. Offline, locked, all-feature/all-target qualification;
two Cargo jobs; incremental compilation disabled; isolated tests use one test
thread and two Tokio workers. The release profile is opt-level 3, full LTO and one
codegen unit, with `panic = "abort"`. Inherited `CARGO_PROFILE_*`,
`CARGO_TARGET_*` and `CARGO_BUILD_*` environment names are removed and recorded
by the qualification launcher.

Final run: `qualification-03`. Every required stage returned zero:

| Stage | Seconds |
|---|---:|
| format | 2.872 |
| fmt-check | 2.720 |
| harness-tests | 6.432 |
| clippy | 63.849 |
| test-build | 268.916 |
| isolated-tests | 231.361 |
| audit-isolated-tests | 5.326 |
| release | 500.534 |

The independent raw-test audit found **1636 passed, 0
failed, 33 ignored, 1669 unique selected cases and
zero retries**. Ignored cases are not counted as executed passes.
The 219 project compiler inputs in `source_tested`,
`source_after` and the current frozen source are identical. The audit also checked
executed test rows against the preserved executable digest, attempt, exit and stdout proof.

| Artifact | SHA-256 |
|---|---|
| R11 comparison runtime | `660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c` |
| R12 comparison runtime | `e7f1f8275c6735a6823f35b6367baf9fc9f943ea7e62a1114fe1187e82cd1c1f` |
| R13 runtime | `91baf096139002075ead3c2b9043ffe12269c155650c41bd4258efd3ac5ef364` |
| R13 jobctl | `84572095b80a56ff893ea41b01e170444dc2483a49091277d0b4ada4fbc1c1b0` |
| R13 native process driver | `496573d75e1f93a7a4d3b1e3a2c92d7645199e0181fa506e59579df265107391` |
| R13 preserved libtest | `9751bb413ec9ed05566fb4dc5d724c93794edb2bfe2a04f2ece02ca04c5d9909` |
| Final qualification report | `fabf43fed5a839923b436ef370b70023cfef90e265d696b1095f37f31e24d0e9` |
| Canonical 219-input source map | `02cd7d96c705b5f00d076bf6163d7bbb68118df7671202886bc320c6abfdee51` |
| Independent raw-test qualification audit | `c1fc88d25e3e09f6301b793533b2c9760cb2e12f0dfee9694b7b804263ad8b65` |

### Failed attempts retained

1. `qualification-01` stopped at strict Clippy because two owned-only wrapper helpers
   became unused in production. They were scoped with `#[cfg(test)]`; the failure
   remains in the archive.
2. `qualification-02` passed formatting, harness tests, Clippy and compilation, then
   produced 1635 passes, one failure and 33 ignored cases. The failing exact oracle
   was `projection_preserves_top_level_and_sequence_struct_decoding`.
   Serde's derived visitor used the actual compact type name in a top-level error.
   A serialization rename did not preserve the original error text.
3. The first repair helper (`failure-fix-03`) could not run Cargo formatting because
   its PATH lacked the toolchain. It did not compile or execute a test.
4. `failure-fix-04` corrected the schema declaration to define an actual nested
   `JobRecord<Text>` and expose it through the compact alias. The existing exact
   error oracle was preserved, covering non-record scalar inputs, every sequence
   prefix through 17 fields, an overlong sequence and routing parity. The exact
   test passed, followed by the complete successful `qualification-03`.

The first local and remote campaign runners observed the failed qualification and
stopped with **zero measurement stages**. The v2 runners bound the successful final
qualification, source map, copied binaries and harnesses before measuring.
No failed qualification was relabeled as successful and no test was automatically retried.

Because release uses `panic = "abort"`, a preparation panic terminates the controller.
Only an unwinding test/profile can turn a blocking-worker panic into a join failure.
The separate controller-crash recovery evidence is the relevant release behavior;
this report does not claim in-process panic recovery for the release binary.
The R12 concurrency-review wording is corrected in this checkpoint while its original
checkpoint and raw evidence are preserved.

## Guarded operation-record experiment

Inputs are independently reproducible 4,194,272-byte synthetic plain and escaped
receipts. The generator, fixture manifest and reproduction check are retained;
the two generated 4 MiB files and compiled executables are not embedded in the archive.
The full guarded read, schema validation and routing result are checked for equality.

The same preserved qualified library-test binary runs both owned and projected
paths. Each payload/retention case uses fresh ABBA children, two per arm.
There are 16 measured children, 640 measured guarded reads and 16 owned warmup
reads. Warmup is excluded from read-rate and CPU denominators but may affect the
whole-child high-water mark.

| Payload | Simultaneously retained results | CPU µs/read | Reads/s | Held-cohort VmRSS KiB, median |
|---|---:|---:|---:|---:|
| plain | 8 | 4931.000 → 2079.063 (-57.84%) | 201.420 → 481.043 | 50670 → 18342 (-63.80%) |
| plain | 32 | 3574.398 → 2046.102 (-42.76%) | 279.714 → 488.753 | 149036 → 18254 (-87.75%) |
| escaped | 8 | 31708.875 → 30460.906 (-3.94%) | 31.533 → 32.829 | 34416 → 18324 (-46.76%) |
| escaped | 32 | 31377.813 → 30878.602 (-1.59%) | 31.859 → 32.383 | 85552 → 18352 (-78.55%) |

The table reports resident memory while the requested cohort remains held.
GNU-time whole-child peak RSS is recorded separately and is not interchangeable
with held-cohort VmRSS. Two children per arm do not establish statistical significance.
Escaped decoding still dominates CPU, explaining why the large reduction in retained
memory does not imply a comparable escaped-input CPU reduction.

## Cancellation responsiveness and resource cost

Each comparison is a separate ABBA campaign using the copied release binaries.
The synthetic fixture deliberately binds to the wrong host: every cancellation
must fail with the original error before audit intent or SSH work. A wave mixes
eight cancellation calls with one `host_list` call, with 24 measured waves and two
warmup waves per process. Workers are tested at one and two, using 1,024-byte and
4,194,272-byte escaped receipts.

Per arm/case the measured denominator is **432 mixed RPCs**:
384 expected cancellation refusals plus 48 successful host-list responses.
A full comparison contains 16 controller processes, 3,456 measured mixed RPCs and
288 warmup RPCs. The analyzer's total refusal and host-list success fields include
warmup; they must not be relabeled as measured-only counts.

CPU is controller CPU divided by all measured mixed RPCs, not cancellation-only
CPU. Rate is measured mixed RPCs divided by total measured wall time.
Host-list p95 is nearest-rank over 48 observations per arm/case; cancellation p95
is nearest-rank over 384. VmHWM is the median of two whole-child values since exec,
including startup and warmup. It is not a per-request allocation measurement.

### R12 → R13

| Workers | Receipt bytes | CPU ms / mixed RPC | Host-list p95 ms | Mixed RPC/s | Whole-child VmHWM KiB, median |
|---:|---:|---:|---:|---:|---:|
| 1 | 1024 | 1.736 → 1.759 (+1.33%) | 18.297 → 19.036 (+4.04%) | 531.645 → 523.803 | 14388 → 14340 (-0.33%) |
| 1 | 4194272 | 37.431 → 36.181 (-3.34%) | 39.919 → 43.858 (+9.87%) | 90.134 → 93.024 | 132020 → 120062 (-9.06%) |
| 2 | 1024 | 1.898 → 1.944 (+2.44%) | 21.628 → 21.970 (+1.58%) | 507.605 → 499.878 | 15510 → 15552 (+0.27%) |
| 2 | 4194272 | 37.731 → 35.972 (-4.66%) | 51.747 → 55.291 (+6.85%) | 85.065 → 93.098 | 136948 → 128842 (-5.92%) |

### R11 → R13

| Workers | Receipt bytes | CPU ms / mixed RPC | Host-list p95 ms | Mixed RPC/s | Whole-child VmHWM KiB, median |
|---:|---:|---:|---:|---:|---:|
| 1 | 1024 | 1.736 → 1.759 (+1.33%) | 17.666 → 18.753 (+6.15%) | 539.308 → 533.567 | 13806 → 14484 (+4.91%) |
| 1 | 4194272 | 23.241 → 36.319 (+56.27%) | 214.904 → 47.106 (-78.08%) | 44.970 → 92.158 | 22268 → 115612 (+419.18%) |
| 2 | 1024 | 1.829 → 1.806 (-1.27%) | 21.174 → 17.664 (-16.58%) | 516.207 → 546.908 | 15340 → 15648 (+2.01%) |
| 2 | 4194272 | 24.838 → 36.065 (+45.20%) | 120.514 → 49.543 (-58.89%) | 78.608 → 91.981 | 34514 → 134954 (+291.01%) |

R13 improves the large cancellation CPU and memory readings modestly relative
to R12, but host-list p95 worsens 6.85%–9.87% in those comparisons. Small-receipt
cases are mixed. Relative to R11, large-receipt host-list p95 improves
58.89%–78.08%, but CPU and peak memory remain substantially higher.
The post-workload VmRSS snapshots also preserve a contrary result. For the large
R12 → R13 cases, the two-child medians increase from 100,838 to 109,726 KiB
(+8.81%) with one worker and from 107,854 to 119,716 KiB (+11.00%) with two
workers, even though their whole-child high-water marks decrease. Post-workload
resident memory and lifetime high-water memory are different observations;
neither is substituted for the other.

Both positive and negative results are retained; they motivate the next bounded
preparation candidate rather than a universal performance claim.

## Six-host native observation

Hosts: ai395, mac, main, pocket4, rog and x230. Frozen job references and the
existing profile are used. The measured operations are `process_status` and
`process_read`; this is not a `process_wait` throughput result.

The independent campaign has ABBA order, two controller processes per version,
concurrencies one, four and eight, 96 measured calls and 24 warmup calls per cell.
Each arm/concurrency contributes 192 measured calls. Totals: 1,152 measured calls,
288 warmup calls and 72 preflight/restart checks, or 1,512 native calls. All returned
the expected result. Warmup and restart checks are excluded from performance
denominators. Earlier R12 campaigns are not pooled with this one.

| Concurrency | Calls/s, R11 → R13 | Controller CPU ms/call | P95 ms |
|---:|---:|---:|---:|
| 1 | 4.2600 → 4.2970 (+0.87%) | 129.115 → 128.698 (-0.32%) | 289.539 → 289.871 (+0.11%) |
| 4 | 17.3768 → 17.7882 (+2.37%) | 74.219 → 74.010 (-0.28%) | 298.540 → 285.407 (-4.40%) |
| 8 | 22.9767 → 22.6278 (-1.52%) | 72.500 → 72.240 (-0.36%) | 420.658 → 427.375 (+1.60%) |

CPU is a synchronous utime+stime delta for the same controller PID/start generation,
not total CPU consumed by all six hosts. Sampled process-tree memory, file descriptors
and CPU remain diagnostic, with incomplete/non-simultaneous samples and all
permission errors retained. They do not replace the measured controller CPU numerator.

The native report does not retain complete transport envelopes. Its independent
audit checks the saved results, matrices, finite latency values, counters and binary
bindings; it does not claim to recompute hashes of unretained native response bodies.
Raw response-body digests are independently checked where those bodies are retained,
including the cancellation and recovery evidence.

The C8 rate decrease and p95 increase are retained. Small percentage changes in
this finite shared-host campaign do not establish a statistically significant
improvement or regression. The earlier R12 C1 slowdown is historical evidence;
this later near-flat result does not by itself identify its cause.

## Recovery and persistence scope

The final copied R13 release binary was used in the six-host cancellation/recovery
campaign. It started isolated synthetic fixtures, reused the same idempotency keys,
interrupted the campaign-owned ROG SSH master, killed the isolated controller,
restarted it, completed terminal cancellations and repeated them to obtain
`already_exited`. Each fixture's independently observed execution count remained one.

The independent recovery audit validates 90 native replies, 36 independent SSH
checks, 72 raw stream files and 150 embedded evidence files (224,875 bytes).
There are six starts and twelve same-key reuses. The six initial cancellation
RPCs overlap in real time (six-way peak overlap), with a 2.716 ms dispatch span.
The retained controller and owned ROG master interruption records are SIGKILL
events. No extra poll or automatic retry is introduced by the audit.

All twelve cancellation replies have `termination_confirmed: false`:
the initial Linux replies say `stop_requested`, the macOS reply says `term_sent`,
and the repeated terminal replies say `already_exited`.
Confirmed terminal state is established separately by status, persisted exit
records, output and independent witness data. A cancellation ACK is never treated
as termination proof.

Independent recovery audit SHA-256:
`81c49ddaf525aeaea8e638672f0ca6c710ee7978b8ae12acd7b33f3e2917ad0a`.
Live successful cancellation was measured at concurrency six; eight-way capacity
is not claimed from this campaign.

The test uses owned synthetic jobs and campaign-specific sockets. It does not
restart production services or mutate the parallel #84 and #88 work.
This is evidence for the exercised interruption and controller-crash sequence.
It does not test physical power loss, target reboot, WAN partition, cross-owner
handoff or universal external-side-effect exactly-once behavior. macOS PID/start/
account identity remains best effort where the existing backend specifies it.

## Evidence and reproducibility

The final source-to-Git manifest binds every project compiler input to the bytes
tested on X230. The staged tools contain the original benchmark and analyzer
programs, v1 failed-gate runners, v2 successful runners and the final qualification
launcher. Qualification logs include failed runs rather than just the successful run.

The independent performance audit recomputes the original matrices, finite
latencies, nearest-rank quantiles, CPU and rate denominators, memory samples,
fixture and runtime bindings, raw response digests and the projection benchmark
stdout. Its SHA-256 is
`ea7d9efc5e93a7ea20345089b1ba07dac9ef243b2fe9d804c3dc43a47956d75e`.
The first audit parser assumed the libtest marker began a new line; libtest
printed the test name before the marker. All sixteen embedded BENCH JSON results
match the raw stdout exactly after correcting the auditor. The original auditor
attempt is retained, and the benchmarks were not rerun.

The root independently retrieved Git tree
`0b85435c1120c5eeb3bec149be3e4282c09f5ca7` and its source/example subtrees.
All 219 project inputs match the qualified compiler-input manifest by Git blob
SHA and mode, with no missing or extra input. Adding reports and evidence later
does not alter those source subtrees. The standalone qualification, performance,
recovery and Git-source verification JSON records are published under
`tests/evidence/20261103-x230-r13/`.

Original evidence:
[`r13-original-evidence-01.tar.gz`](../tests/evidence/20261103-x230-r13/r13-original-evidence-01.tar.gz),
6,065,688 bytes, SHA-256
`f0dd8d28b2d4cc56d1bcca8efeff0f2778efad20cf75465ab74297411fab6635`.

Compressed selection and per-file hash manifest:
[`archive-selection-01.json.gz`](../tests/evidence/20261103-x230-r13/archive-selection-01.json.gz),
1,652,643 bytes, SHA-256
`1e1e9e4ff95035d7621c5f26888f618d2fefceb829dc34152788999d471fa319`.

The archive contains 22,000 original files totaling 90,910,854 bytes, plus the
selection manifest (22,001 members). Every member was reread and checked against
the selection. Paths are validated, compiled binaries and the two projection
payloads are excluded, and the configured credential-pattern scan has zero matches.
The packaging summary records the exact selection and validation scope.

The evidence archive excludes compiled binaries, build caches and full generated
large fixtures. Their digests, sizes, source/generator bindings and exact commands
remain available. Raw records and original summaries are immutable; the independent
audit is an additional result.

A subsequent checkpoint may change preparation admission. It must be separately
qualified and measured against these preserved binaries. No absolute optimum,
production deployment or default-branch merge is claimed here.
