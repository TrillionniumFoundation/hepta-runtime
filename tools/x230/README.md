# Reproducing the x230 optimization evidence

These helpers qualify an isolated source snapshot and measure the native stdio
MCP controller against original job records. They do not install a runtime,
replace a service, increase production limits, or retry an ambiguous launch.
The dated reports under `docs/evidence/` identify the source and binary that were
actually tested. A helper's presence is not a claim that every possible test was
run for every candidate.

## Inputs and isolation

Use a private development directory on the x230, a short private socket parent,
and an existing authorized SSH agent that remains available for the entire
experiment. The observation scripts create fresh private profiles bound to that
agent. An old profile from a completed forwarding session is not reusable.
Do not put credentials, SSH configuration, known-host contents, private job
records, or unsanitized reports in the repository.

The six-host fixture consists of the original completed operator-job records
used by the A17 observation experiment. Preserve their bytes and identities.
The observation driver configures those copied records for read-only access and
checks complete outputs, offsets, hashes, and status counts. It does not create
replacement jobs when an observation fails.

The measured controller uses two Tokio workers. Do not run compilation or other
benchmarks on the x230 during a timed comparison. Record changed environment or
transport conditions instead of silently comparing unlike runs.

## Source qualification

```sh
python3 qualify_runtime_candidate.py \
  --source "$candidate_source" \
  --output "$fresh_qualification_dir" \
  --target-dir "$development_build_cache" \
  --cargo "$cargo_binary" --toolchain 1.95.0 --jobs 2
```

The output directory must be new. The helper runs formatting, a formatting
check, strict Clippy for all targets and features, all-feature tests, and an
all-feature release build with the lockfile and offline dependencies. It records
the formatted source map before tests, verifies the map after the build, and
copies the compiler-identified test and release executables with their SHA256s.
The source-map digest in the compact qualification receipts is SHA256 of the
UTF-8 JSON map with sorted keys and `(',', ':')` separators, without a trailing
newline. Nested isolated-helper test summaries are not additional top-level
test suites.

## Six-host comparison

```sh
python3 x230_observation_benchmark.py \
  --baseline "$baseline_binary" --candidate "$candidate_binary" \
  --profile-template "$profile_template" --frozen-jobs "$original_records" \
  --socket-parent "$short_private_socket_parent" --out "$fresh_report_dir" \
  --calls 96 --concurrency 1 4 8 --order ABBA
```

This is the frozen comparison driver. It sends 96 timed calls per concurrency
cell, per round: 1,152 timed calls in four ABBA rounds. Each version therefore
has two cells and 192 calls at each concurrency. Each round uses a fresh
controller, verifies the original outputs, measures the cells, shuts down by
stdin EOF, restarts from the same controller state, and checks the same jobs
again. The comparison combines elapsed cell durations and complete call rows;
it does not average rates or omit failed requests.

Concurrency values above the configured capacity are capacity experiments.
Keep their refusals and timeouts in the evidence. They must not be substituted
for a fully successful throughput comparison.

The workload is small-output `process_status` / `process_read` observation of
completed operator jobs. Results do not establish job-launch throughput, HTTP
session capacity, large-output transfer bandwidth, or total resource usage on
the remote hosts.

## Sustained observation

```sh
python3 x230_observation_soak.py \
  --baseline "$candidate_binary" --candidate "$candidate_binary" \
  --profile-template "$profile_template" --frozen-jobs "$original_records" \
  --socket-parent "$short_private_socket_parent" --out "$fresh_soak_dir" \
  --calls 5760 --concurrency 8 --order B
```

The soak script changes only the original driver's command-line order selection
to permit a single candidate round. It uses the same checks and measurement
logic. A round lasting more than the configured 120-second master age exercises
the elapsed-age boundary; the generic process sampler does not identify SSH
master generations by executable name, so that duration alone is not a count of
successful renewals.

Choose the call count from a completed same-binary C8 measurement when a
particular duration is required, and retain that plan separately. The A23 plan
uses 10,356 calls to target 360 seconds and checks at least 300 seconds of
observed request span. Each count remains a multiple of 12 so the six hosts and
two tools stay balanced. Actual duration, failures and all rows must be retained
even when the planned duration is not reached.

When aggregating a B-only run whose unused A path points to the same binary,
use distinct accurate labels such as `--baseline unused-A23 --candidate A23`.
There are no A observations in that experiment, so it is not an A17/A23
performance comparison and must not borrow a baseline from another run.

`review_x230_soak_windows.py` analyzes a single B-only cell after measurement.
It requires the actual raw report, exact binary hash, unchanged six-job reference
report, and the planned count and concurrency. It preserves every failed row,
uses separate start and completion windows, and divides a final partial window
by its actual observed span. It does not assign whole-cell CPU to time windows
or infer memory trends or master renewals from request timing.

```sh
python3 review_x230_soak_windows.py analyze \
  --input "$original_soak_report" --expected-input-sha256 "$raw_sha256" \
  --output "$new_private_window_review" \
  --expected-binary-sha256 "$candidate_sha256" \
  --originals-report "$same_binary_reference_report" \
  --expected-originals-report-sha256 "$reference_sha256" \
  --expected-calls 10356 --expected-concurrency 8 --window-seconds 30 \
  --minimum-observed-seconds 300 --long-request-ms 1000 --completion-gap-ms 1000
```

Its raw analysis output can contain private identities and requires a separate
privacy review before publication. The A23 failed-soak summary binds a complete
sanitized report and a complete relative-time window projection, both stored as
deterministic gzip files. All 10,356 attempts and 6,132 failures remain present.
The lower duration and failure verdicts are retained; neither fast refusals nor
complete consumption of a fixed attempt count satisfies sustained-success
coverage.

## Abrupt controller recovery

```sh
python3 x230_controller_recovery_check.py \
  --candidate "$candidate_binary" --profile-template "$profile_template" \
  --frozen-jobs "$original_records" \
  --socket-parent "$short_private_socket_parent" --out "$fresh_recovery_dir"

python3 x230_native_lifecycle_canary.py \
  --candidate "$candidate_binary" --profile-template "$profile_template" \
  --x230-record "$original_x230_record" \
  --socket-parent "$short_private_socket_parent" --out "$fresh_canary_dir"
```

The first helper checks six original completed jobs before and after killing
only its directly owned controller. It records observed descendant survival and
residual socket artifacts separately. Successful data recovery does not imply
that all crash artifacts were removed.

The lifecycle canary creates one private x230 workload with 4 KiB stdin. It
requires `running` and `BEGIN`, kills only its own controller through a pidfd,
restarts with the same state, and requires the same idempotency key to return
the same still-running job without a new launch. Only then does it release the
workload. Completion requires exact stdout/stderr, a single execution marker,
unchanged original metadata and stdin, synchronized logs, and the A20 request /
exit / witness identity and exact-byte digest agreement. A failed or uncertain
canary keeps its original identity and artifacts; it must not be rerun under a
new key to conceal the result.

These checks validate controller recovery and controlled filesystem failure
paths. They do not demonstrate physical power-loss recovery, target reboot,
network partitions, automatic ownership transfer, or transactional exactly-once
external effects.

## Resource and evidence interpretation

Controller CPU is the same-PID, same-start-ticks delta of `/proc` user plus
system CPU across each timed cell. Reported memory, descriptor, and descendant
peaks are sampled at 100 ms and are lower bounds. Descendant CPU may miss
short-lived processes. Permission errors remain in the reports; descendants
are not classified into SSH-only and other executables.

`build_x230_evidence.py` creates a compact, privacy-safe report from an original
report. It retains failed calls, missing evidence, sampler errors, shutdown
results, and recovery caveats. It supports ABBA comparisons, a single candidate
soak, and the two recovery schemas. Its output is create-only.

```sh
python3 build_x230_evidence.py \
  --input "$original_report" --output "$new_evidence_file" \
  --baseline A17 --candidate A20 \
  --harness x230_observation_benchmark.py --label comparison
```

Use the actual labels and harness for the experiment. Preserve the original
report's SHA256 and the harness SHA256. Recalculate aggregate rates from all
calls and elapsed durations, and compute nearest-rank percentiles from all call
latencies. A missing or invalid latency must not silently disappear from the
percentile calculation.

## Rejected request-hash experiment

`request_hash_benchmark.rs` reproduces the request binding and JSON streaming
writer, compares complete digests before timing, and measures six ABBA cycles
for small, plain 1 MiB, and heavily escaped 1 MiB inputs. Its compiler helper
uses the qualified release dependency artifacts. The dated decision and raw
JSONL retain all 72 timing cells and 18 paired cycle results.

The unconditional request-writer replacement was rejected because the common
small request became slower despite gains on large inputs. That experiment is
separate from the adopted full-file validation hash optimization. Neither
microbenchmark by itself establishes native job-launch throughput.

## Published copies and exact measured hashes

`publication-manifest.json` maps every original helper/source, protocol or microbenchmark
report to the published artifact, with exact SHA256s and byte sizes for both.
The original measurement scripts and Rust sources remain frozen. Nine published
tool, source or protocol copies differ only by the individually listed edits. Four original scripts
have portability edits: the benchmark and soak
scripts replace one private-account path example in a comment with
`/home/user/hx230-opt-20261023`; the lifecycle and fairness scripts define their
development root as
`Path.home() / "hepta-runtime-optimization-20261023"`. For the original x230
account this resolves to the same guarded development directory. The two Rust
microbenchmark sources, `ssh_hash_benchmark.rs` and `request_hash_benchmark.rs`,
add only the required `// Copyright 2026 Muvon Un Limited` header line before
their existing Foundation copyright and SPDX line. The D2 driver, reviewer and
protocol have the additional portability and header edits described below. All
remaining listed files are exact byte copies.

The nine edited publication copies are **not byte-identical** to the original
scripts, sources or protocol used in the recorded experiments. An evidence report's `harness_source_sha256`
identifies the measured original, and the manifest's `published_sha256`
identifies this repository copy. The manifest records each changed original
segment by byte offset, byte length and SHA256 without publishing its private
path. The complete files retain all other bytes, and the portable copies were
not substituted into already recorded runs or described as separately tested
binaries. Reproduction with a published helper records its own current helper
hash and must retain that distinction.

The standalone fairness harness compares balanced, hot-only and skewed
read-only workloads using the same eight-head/admission-snapshot/two-tail
shape. A native `accepted` snapshot proves dispatch admission, not possession
of a pool permit or remote execution admission. It retains failed admission
gates, refusals, timeouts and all calls; its presence does not imply that an
experimental scheduler was adopted.

The evidence generator received a separately recorded privacy correction before
publication: `controller_hostname` is now replaced by a whole-value SHA receipt,
while the public `x230` alias is retained. Its previous source version was
preserved separately. `evidence_generator_revision` in the manifest records
both exact generator hashes; this change affects no metric, verdict, measured
driver or canary. Observation and recovery evidence generated with the previous
version were preserved privately and regenerated without changing their input
report hashes or numerical results.

## Fairness aggregation and comparison gates

`build_x230_fairness_evidence.py` handles the separate fairness schema. It pins
the reviewed generic evidence helper by SHA256 and retains every raw wave, row,
refusal, timeout, invalid admission gate, metadata failure and resource sampling
error. Head and tail rates use the full cell elapsed-time denominator; CPU is
reported for the complete cell rather than allocated to a role. Their latency
quantiles include failed calls.

```sh
python3 build_x230_fairness_evidence.py \
  --input "$original_fairness_report" --output "$new_fairness_evidence" \
  --baseline A20 --candidate A21 --mode comparison \
  --harness "$measured_fairness_harness" \
  --base-driver "$measured_observation_driver"
```

The two helper paths must match the exact hashes recorded by that run; use the
publication manifest to distinguish measured originals from portable copies.
A performance comparison is emitted only after checking A20/A21 ABBA order and
continuous round indices, two rounds per version, 16 waves and 160 calls per
cell per version, 32 cold read calls per version, complete metadata cursor
chains and admission receipts, unchanged inputs, and both measured helper
hashes. It independently recomputes whether a head completed before the first
tail started, and whether final history records actually completed. A complete
comparison can still contain explicit RPC failures; success counts, goodput
and each version's verdict remain separate. The helper does not infer adoption.

For an A20/A20 pipeline check, select `--baseline A20 --candidate A20 --mode
smoke`. Smoke retains distinct A/B records and never emits a performance
comparison, even if its call counts happen to match the full experiment.
Incomplete or invalid comparisons retain their complete available evidence and
show the unmet comparison requirements. Output files are create-only.

## Qualified version provenance for fairness v2

`build_x230_fairness_evidence_v2.py` preserves the reviewed v1 statistics,
admission gates, failure retention and separate A/B verdicts. It adds explicit
qualification provenance for A20/A21 or A20/A22 comparisons. The v1 builder and
its existing evidence remain unchanged. Both v2 and its qualified-version
registry are separate artifacts with their own exact hashes.

The registry maps each version label to its binary SHA256, tested-source-map
SHA256, source-file count and original qualification-report SHA256. Create an
A22 entry only from its completed, successful qualification; do not prefill
unmeasured or placeholder hashes. The builder requires matching binary hashes
in the fairness report and the original qualification report, a qualified
verdict, successful format/fmt-check/Clippy/test/release stages, and identical
tested/after source maps. Known A20/A21 entries are pinned; an A22 label cannot
reuse either known binary, source map or original qualification report.

```sh
python3 build_x230_fairness_evidence_v2.py \
  --input "$original_fairness_report" --output "$new_fairness_evidence" \
  --baseline A20 --candidate A22 --mode comparison \
  --harness "$measured_fairness_harness" \
  --base-driver "$measured_observation_driver" \
  --registry "$qualified_version_registry" \
  --baseline-qualification "$original_A20_qualification_report" \
  --candidate-qualification "$original_A22_qualification_report"
```

The two qualification inputs are the complete original
`qualification-report.json` files retained in the private x230 qualification
directories. Preserve their exact bytes when copying them locally. The registry
binds their raw-file SHA256s. A published compact qualification receipt can
corroborate the binary/source-map values; the registry separately declares the
original-report hashes. A compact receipt's sanitized or wrapped bytes are not
the original report and cannot be substituted for these CLI inputs. Original
qualification reports can contain private paths and belong outside the public
repository.

Source-map hashes use sorted, compact UTF-8 JSON with `(',', ':')` separators
and no trailing newline. This differs from the newline-terminated evidence-file
serialization. The v2 helper reads and hashes the original qualification report
bytes; it does not independently rehash the executable or every source file and
reports that boundary explicitly. Reconstructing source or binary artifacts is
a separate verification step.

Use the exact measured fairness and observation helpers for the run's helper
hash checks. CPU remains attributed to complete cells, including metadata
queries; it is not allocated to cold probes. A verified provenance chain does
not imply successful observations, a performance improvement or adoption.

## Qualified version provenance for fairness v3

`build_x230_fairness_evidence_v3.py` adds A23 to the allowed separately qualified
candidate labels and pins the completed A22 qualification. Existing v1/v2
builders and their evidence remain unchanged. The v3 statistical and admission
gate functions are unchanged; the same real A22 input preserves the v2 numerical
results and verdicts. An A23 label cannot reuse A20, A21 or A22 qualification
identities. It requires the actual successful original qualification report and
a registry entry derived from that report, with no placeholder hashes.

Use the v2 command above with the v3 script, `--candidate A23`, and the original
A23 qualification report plus its matching registry. The qualification input is
still the raw private report, not a published compact receipt. The two measurement
helpers must still match the original hashes recorded by the experiment. No
comparison, provenance check or registry entry implies adoption.


## D2 diagnostic calibration

The separate [D2 driver](x230_observation_diagnostic_d2.py),
[local reviewer](review_x230_diagnostic_d2.py),
[review protocol](a23-d2-calibration-review-protocol.md), and
[exact 151-file source map](a23-diagnostic-d2-r02-source-map.json) reproduce the
D2 r02 diagnostic scope. They do not change the standard comparison drivers or
qualify A24. Use the same actually qualified D2 binary for diagnostic off and on.
An on/off comparison does not measure disabled-hook cost against production A23.

The recorded original driver, reviewer and protocol hashes are respectively
`7d44502e1977b99aa663260870984b300d2125dab1a19cbef1b27b32b27b9e8a`,
`ced3c7e0fe19c00c4d7db8338061a0fc31deea58475d850346244ba7ffcee065`, and
`07de7671208af6714f99312264ffd3fe7987c8c882edd0306be5839e8e812410`.
The publication manifest binds their distinct portable copies and every edit.
The driver changes only one comment. The reviewer adds the required copyright
line, makes local input paths explicit, and replaces its fixed driver SHA with
the required `--driver-sha256` binding. Its source-map pins, arithmetic, quality
checks and cost gates are unchanged. The protocol preserves every original byte
and adds only headers and a publication note.

### Measurement arguments

The driver requires `--baseline`, `--candidate`, `--profile-template`,
`--frozen-jobs`, `--out`, `--socket-parent`, and `--diagnostic-mode off|on`.
Both binary paths must hash identically. Inputs are the same six original
completed-job records and a validated profile template; each output path must be
new. The current held agent is explicitly rebound for each invocation.

| Optional argument | Driver default | Frozen calibration setting |
|---|---|---|
| `--calls` | 96 | 384, a positive multiple of 12 |
| `--concurrency` | `1 4 8` | `8`, one continuous cell |
| `--workers` | 2 | 2 |
| `--order` | `B`, the only accepted order | `B` |

The calibration settings must be passed explicitly: running the driver with its
defaults does not satisfy this review protocol. There is no default diagnostic
mode. The driver passes environment value `0` or `1` explicitly, retains native
errors, and never retries a request. Its `driver_sha256` is its actual current
file hash, so a new portable run must not be labeled with the recorded original
driver hash.

Run four separate invocations serially in **off, on, on, off** order. Use the
following command for each, with a distinct fresh output and the indicated mode:

```sh
python3 x230_observation_diagnostic_d2.py \
  --baseline "$qualified_d2_binary" --candidate "$qualified_d2_binary" \
  --profile-template "$profile_template" --frozen-jobs "$original_records" \
  --socket-parent "$short_private_socket_parent" --out "$fresh_run_dir" \
  --calls 384 --concurrency 8 --workers 2 --order B \
  --diagnostic-mode "$diagnostic_mode"
```

Retain every raw report and both `round-0-B/first/stderr.log` and
`round-0-B/restart/stderr.log` as exact bytes, including empty off-mode files.
Do not substitute a later run for a failure. The protocol asks the operator to
retain one continuous forwarded-agent session and avoid compilation overlap;
report timestamps alone do not attest those external conditions.

### Local review arguments and boundaries

All reviewer paths and identity inputs are required: `--qualification`,
`--qualification-sha256`, `--binary-sha256`, `--source-map`,
`--source-directory`, `--driver`, `--driver-sha256`, `--protocol`, four ordered
`--run MODE REPORT RAW_SHA STDERR_ROOT` arguments, and a fresh `--out`.
There are no optional local path defaults. The raw qualification report must be
the complete original, not a sanitized compact receipt. The supplied source
tree must match all 151 fixed D2 r02 files and both qualification source maps.
The included map's exact file SHA is
`8f41879846cdf57964f1238de5e6db04d58333cd7797d32baa2325a957c512da`;
its canonical map SHA is
`ec4419489f6499bdbecab9402d78e1997171bfeea1eda4be193b0af5f9688dc2`.

```sh
python3 review_x230_diagnostic_d2.py \
  --qualification "$actual_qualification_report" \
  --qualification-sha256 "$qualification_sha256" --binary-sha256 "$binary_sha256" \
  --source-map a23-diagnostic-d2-r02-source-map.json \
  --source-directory "$qualified_d2_source" \
  --driver "$measured_d2_driver" --driver-sha256 "$measured_d2_driver_sha256" \
  --protocol a23-d2-calibration-review-protocol.md \
  --run off "$off1_report" "$off1_sha256" "$off1_stderr_root" \
  --run on  "$on2_report"  "$on2_sha256"  "$on2_stderr_root" \
  --run on  "$on3_report"  "$on3_sha256"  "$on3_stderr_root" \
  --run off "$off4_report" "$off4_sha256" "$off4_stderr_root" \
  --out "$fresh_private_review"
```

`--driver` identifies the trusted helper that actually produced these reports.
Its bytes and every report's driver receipt must match `--driver-sha256` before
the reviewer can accept the binding. Historical reports require the original
measured driver; new portable reports require the portable driver's own SHA.
The reviewer imports that explicitly pinned helper's stderr parser and performs
its own metric, workload and cost arithmetic. A caller-supplied SHA does not
certify an unrelated helper. This reviewer intentionally keeps the fixed D2 r02
source scope, 384-call C8 workload, four-run order, and predeclared tolerances.

All 1,536 timed rows, 24 preflight rows, 48 restart rows, eight normal controller
shutdowns, and diagnostic evidence must pass before cost ratios are trusted.
Off mode requires zero summary/event records; on mode requires one complete
32-metric summary per controller. Missing stderr, invalid clocks, lost records,
or a native failure cannot be rescued by a complete diagnostic event.
The pooled CPU/goodput/p95 tolerances remain +5%/-5%/+10%, and each temporal
pair remains +10%/-10%/+20%. These are exploratory gates, not confidence bounds
or proof of zero instrumentation effect.

Owner-thread lifetime counters include initialization, preflight, background
activity and shutdown. Keep `first` and `restart` separate, do not add nested
spans, and do not assign lifetime phase shares to timed-cell or whole-controller
CPU. `read_and_hash` combines reads, buffers and digest updates; agent wall
intervals can overlap and have no CPU attribution. See the protocol for the
complete interpretation and failure rules.

The reviewer reads local inputs only and creates a new review file. Its output
records its own helper hash and the exact protocol hash used. Raw inputs and
review output can contain private paths, process identities and resource errors;
they require separate sanitization before publication. Offline validation of a
portable reviewer is separate from rerunning a controller experiment. The
manifest records which occurred; the published measurement driver has not been
substituted into any already recorded calibration.

Local validation replayed the four existing measured inputs through the portable
reviewer and rehashed all 151 source files. Every review output field except the
reviewer's own helper identity and the publication protocol identity matched the
frozen review. Negative checks rejected a mismatched driver file and prevented
historical reports from being relabeled with the portable driver's hash. This
was an offline analysis check; it produced no new controller measurements.
