# X230 A40 qualification and recovery evidence tools

These scripts reproduce the isolated X230 checks recorded in
[`docs/X230_A40_20261025.md`](../../../docs/X230_A40_20261025.md).
They do not install or restart a runtime service. Keep all helper modules in
the same directory. The full series uses one qualified A40 revision-02
executable, with SHA256
`3238c9d4bb2f8dc4dbb86e591ce774bea70c6785c159cf27b70003f00623540c`.

## Qualification and input binding

`qualify_runtime_candidate.py` runs formatting, strict all-target/all-feature
Clippy, all-feature tests and the release build on X230 with Rust 1.95.0. It
cleans only the candidate package's copied artifacts, preserves dependency
caches, rejects compiler artifacts marked `fresh=true`, verifies the compiler
source path, and compares all 165 source hashes before and after qualification.

The established offline dependency cache is
`/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02`.
The qualification launcher uses two Cargo build jobs and two runtime/test
workers, removes inherited build/profile overrides, and writes to a new
isolated output directory. A missing offline cache is a failed prerequisite,
not a reason to substitute an unqualified executable.

`prequalify_a40r02_and_qualify.py` is the exact recorded launcher for eight
source-bound X230 fixtures followed by full qualification. It includes the
rejected A39 staggered-output and A40 revision-01 read-error counterexamples.
The rejected sources are reconstructable from the A38 commit and the patches
in `docs/evidence/x230-a40`. The launcher has fixed experiment paths and
requires new output names for a separate reproduction; it does not rerun an
existing failed directory automatically.

## Final serial series

`run_a40_final_validation.py` waits for the recorded A40 revision-02
qualification, checks both fresh compiler artifacts and the source map, then
runs these stages serially:

1. `x230_small_archive_benchmark.py`: four ABBA rounds of A35 versus A40,
   64 original native-owner records per round, C1, 1,024 measured queries per
   round. Exact original archive/hot maps and public metadata projections are
   checked before and after measurement and controller shutdown.
2. `x230_inherited_pipe_canary_a40.py`: six native cases on X230 and Mac,
   covering natural completion, staggered stdout/stderr EOF and inherited-pipe
   timeout. It binds the expected executable digest and original job/output
   files. Fixed fixture descendants self-exit; the harness never rescues a
   failed case by signaling a reconstructed remote PID.
3. `x230_six_running_recovery_canary.py`: six original running remote jobs,
   original-controller crash, restart and six same-key lookups. It independently
   checks the surviving originals, execution markers, output and witnesses.
4. `x230_file_pool_benchmark.py`: same-executable off/on/on/off comparison,
   96 measured requests per cell at C1, C4 and C8 over all six hosts.
5. The same file helper: a 600-second C8 pool-on soak.
6. The same file helper: one fixed 192-request C16 capacity cell. The
   `--soak-seconds 1` argument selects a single pool-on round; the complete
   192-request cell runs to completion. It is not a one-second throughput test.

Each stage retains original stdout/stderr and report hashes. Any failed stage
stops the series; the driver does not relaunch a job or manufacture a successful
subset. The same binary hash is checked before every stage and after the series.
This frozen driver records absolute X230 paths and a fresh short socket parent;
a separate experiment must choose new private output/socket names.

The native helpers use the existing profile template and frozen synthetic
job outputs. A fresh profile binds the current forwarded SSH agent, public-key
identities, known-host/config hashes and private socket root. Existing
credentials are used through agent forwarding without copying private keys.
Native canary output directories must be fresh direct children of the X230
optimization root. Archive-only benchmarking uses no SSH profile.

The standalone file helper accepts, for example:

```sh
python3 x230_file_pool_benchmark.py \
  --candidate /abs/qualified/hepta-runtime \
  --profile-template /abs/profile-template.json \
  --frozen-jobs /abs/frozen/state/jobs \
  --socket-parent /abs/new-private-short-parent \
  --out /abs/new-file-abba \
  --calls 96 --concurrency 1 4 8
```

Run performance stages after compilation and other experiment workloads have
finished. The six files contain only 44–48 synthetic bytes. This workload
measures observation overhead and latency, not bulk transfer bandwidth.

## Independent analysis and evidence preservation

`analyze_file_abba.py` independently recomputes the complete fixed ABBA report
from every original JSONL row, accepting plain or gzip input. It validates
phase/round/host/tool coverage, cell statistics and original hashes. It reports
weighted calls per second, per-round p95, full waited local process-tree CPU,
sampled RSS/FD and all accumulated observation errors. It rejects a soak
passed as an ABBA comparison. Example:

```sh
python3 analyze_file_abba.py \
  --report /abs/file-abba/report.json \
  --calls /abs/file-abba/calls.jsonl \
  --out /abs/new-independent-analysis.json
```

`collect_x230_validation_evidence.py` preserves the completed rejected A39/A40
attempts and prequalification evidence. Its descriptive candidate scope is
deliberately A39-specific. `collect_x230_final_evidence.py` retains the same
collection and statistics logic with neutral A40 revision-02 collection
metadata for the final series. Neither collector decides product acceptance.

Both collectors require explicitly selected quiescent input paths, two complete
hash/length reads, stable descriptor/path metadata and an unchanged final
inventory. They emit a deterministic `evidence.tar.gz`, an exact file manifest,
a derived summary and a collection receipt. They reject symlinks, special files
and changing inputs. Explicit exclusions omit executable/build/state/profile
and credential/configuration directories; the manifest lists every exclusion.
Original reports, raw wire transcripts, call rows and ordinary logs remain.
The final checked source and executable are bound through the qualification
receipt rather than bundled copies of build caches or private profiles.

Logical request-slot uniqueness does not establish RPC-level exactly-once
delivery. Resource samples are non-atomic and non-exhaustive; observation
errors remain visible. Waited CPU covers complete local controller rounds and
their reaped descendants, excluding remote-host and sampler CPU.

`analyze_recovery_evidence.py`, `analyze_small_archive.py` and
`analyze_soak_tail.py` preserve the additional offline checks behind the
published independent analyses. They consume recorded evidence and source
bindings; they do not launch workloads. Use a new output path for reproduction.
The recovery analyzer recomputes embedded original request/output/exit/witness
bytes and checks recorded original-controller waits. The archive analyzer
binds every tool call to captured wire offsets, hashes and RPC IDs, and checks
captured original maps and public projections. The tail analyzer retains every
soak row and distinguishes the observed long-tail window from static timeout
and synchronous-validation risks. Excluded private state and ELF files are
not silently treated as newly read inputs by these offline analyses.

The small-archive reproducer accepts `--bundle`, `--harness` and `--out` absolute
paths. The tail reproducer accepts `--repository-root /abs/hepta-runtime` and
`--out /abs/new-analysis.json`; its optional `--workspace-root` mode preserves
the original isolated workspace layout. Both pin the recorded A40r02 inputs
and are intended to reproduce this immutable evidence, not to silently accept
new candidate data.

`verify_inherited_pipe_red_green.py`,
`reproduce_a39_staggered_regression.py` and
`x230_inherited_pipe_canary_a39.py` preserve historical A39 harness versions.
Their successful results do not qualify the final A40 executable. See the
complete failure history and the recovery design for what each fixture proves.
