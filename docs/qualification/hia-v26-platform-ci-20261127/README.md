# HIA v26 platform and CI continuation — 2026-11-27

This continuation publishes the previously completed commits
`2d041153810ba6670946ce5801d65526641ee9b3` and
`55b4422538019a02f750a49bd03ed3b89df3aa06` without rewriting their identity.
Their public parent is `d022649c64b48fb2a43263faf90103a9a8957b94`.

The eight-file repair enables `hia/**` push/base branch CI; refuses native
job Submit/Read/Status/Cancel before transport on non-Linux controllers; gates
Linux-only HIA provider admission; keeps checkpoint numeric-key ordering
portable; and flushes the artifact cohort test file before synchronous
admission. The original Mac working tree was not modified.

## Source-bound Mac validation

[macos.json](macos.json) binds the original five command results and full log
identities to commit `55b4422538019a02f750a49bd03ed3b89df3aa06`,
tree `491bcf00734d652afa1c10ca47f00a0fa23e7919`, on ARM64 Darwin 25.6.0
with Rust 1.95.0. The isolated checkout was
`/Users/qianqi/work/hia-v26-platform-ci-20261127-589c`.
The original durable job `1a21b3281cf-ffbe-4ec4` completed successfully with
complete, durable output. No second run substituted for its initially timed-out
MCP launch response.

| Check | Actual result |
| --- | --- |
| `cargo fmt --all -- --check` | exit 0 |
| CI contract unittest discovery | 6 passed |
| Offline locked all-target, all-feature `cargo check` | exit 0 |
| Offline locked all-feature `cargo test --lib native_jobs` | 7 passed |

The native job tests include all four non-Linux operation refusal paths.
These targeted tests do not replace the Ubuntu isolated-process nextest matrix.
Mac compilation emitted existing unused/dead-code warnings; this receipt does
not claim a Mac Clippy or complete nextest pass.

## Current source projection repair

The first real Repository Hygiene run on the published source failed at
`rea_compatibility_ledger.py check-mapping`.
[ci-before-refresh.json](ci-before-refresh.json) retains the exact run, job,
command and error. It remains a failed historical run.

The original `published_pin`, `snapshot_rows`, and `assemble_ledger`
functions were used to refresh the current generated ledger after checking the
immutable catalog projection against its existing pin. Only 13 existing
`runtime.source_files` records and `runtime.source_manifest_sha256` changed.
[source-projection.json](source-projection.json) records their exact before/after
identities. Original ledger bytes remain recoverable from the recorded Git
revision and path; no duplicate large ledger is added here.

All 229 tool rows, behavior gates, summary counts, other runtime fields and
other top-level fields compare exactly equal. INPUTS, CAPABILITY_MAP,
ENVIRONMENT, published pin and generator bytes are unchanged. The result
remains **229 OPEN operations and 0 qualified operations**. This refresh does
not establish behavioral parity, requalify any earlier binary, or change any
historical qualification pin.

Raw frozen reference bytes were **NOT_REVERIFIED** by this local projection
refresh. An attempted independent restore on the Mac produced an MCP request
timeout and no observable result file at the time of recording; it is not
counted as a successful restore or input authentication.

[mapping-validation.json](mapping-validation.json) retains all local commands,
exit codes, durations and complete log digests. The mapping check returned 0;
strict parity returned its expected 3; all 29 ledger integrity tests passed.
The complete REA consumer suite ran 362 tests: 361 passed and one errored because
this container lacks `/proc/<pid>/task/<pid>/children`, preventing a required
real owner/drain observation. That failure is retained, and the test was not
weakened or skipped. The GitHub Ubuntu job must independently establish its
complete consumer result.

## Qualification boundary

This branch integrates v25/v26 job lifecycle and controller work plus platform
repairs. The fresh v26 native Worker installation, public-tool campaign,
whole-runtime replacement, public activation and old-stack removal remain
separate unfinished gates. No production activation or stack deletion occurred.
The PR links the current exact-head and prospective-merge Actions results;
pending, skipped, failed and superseded runs are not presented as passes.
