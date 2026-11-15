# D1 first qualification preparation

This package prepares one original eight-stage qualification of the frozen D1 diagnostic source. It does not qualify, adopt, benchmark, or optimize a runtime by itself. No Cargo command, Rust formatter, Rust test, diagnostic fixture, host API, or remote shell was run while preparing these files.

## Source and publication identities

The source construction anchor is accepted R24, `baab4def80be7af015b2e7a594cb302f66c4130e`. The source package is the already published `recovery-02` package: 39 files, with a 220-input baseline map and a 222-input candidate map. The patch modifies 11 existing paths and adds `phase_cost.rs` and `phase_cost_tests.rs`; the other 209 compiler inputs remain R24 bytes. The package, its unformatted source, its patch and its source maps have not been modified by qualification preparation.

The first publication commit is `5d3fecbeb1d67c288917598f55932e64c878f1e5`. Its actual Git parent is `86155fbf3b89e5a77e2a4aadebd2128c663fe50b`. The root agent's 2,400-byte provenance receipt distinguishes these commit identities and records equal `src`, `examples`, `Cargo.toml`, `Cargo.lock`, and `rustfmt.toml` Git identities between the actual publication parent and the R24 construction anchor. Subsequent evidence commits do not change this source construction record.

## Original qualification behavior

The generated `prepare_qualify.py` retains 13 general helper functions byte for byte from the successful R35 preparer. `helper-reuse-static.json` identifies every preserved source segment. The unchanged helpers include the source map, stable file reader, native terminal and single-page log verification, cache process scan, nondumpable helper classification, retained executable checks, original successful stage checks, and completed qualification check.

The original qualifier and its 18 sibling harness files are pinned as the same 19-file set. The qualifier runs the original stages, in order:

1. `format`
2. `fmt-check`
3. `harness-tests`
4. `clippy`
5. `test-build`
6. `isolated-tests`
7. `audit-isolated-tests`
8. `release`

The original `--jobs 2`, offline and locked dependency selection, Rust 1.95.0 toolchain, release profile, isolated test methodology, zero retries, and minimum 3 GiB free space remain intact. The preparer calls the original `qualify.py` once. It does not implement a replacement qualifier or predict new test counts.

The original Clippy, test-build and release commands use `--all-features`. They therefore compile D1's `phase-cost-diagnostics` feature. All three `HEPTA_RUNTIME_PHASE_COST_*` environment variables must be absent during qualification. The qualification executable is a feature-enabled ELF with diagnostic mode unset. A successful build alone would not establish trace correctness or performance.

The ordinary supplemental check/build is separate and is not launched by this preparer. The original package feature set is empty; the supplement removes only the new diagnostic feature from that original selection, retaining dependency defaults and the rest of the command. It must not use `--no-default-features`. The original qualified feature ELF must remain preserved before any later shared-target supplemental build.

## R35 cache owner closure

R35 supplies only its reusable `target-build` directory. The new source tree is copied from R24 and receives the frozen D1 patch. The preparer does not copy R35 source into D1.

The cache-owner evidence records the actual history: R35 qualification and exact CI succeeded; observation passed its nonregression gate; normal lifecycle ran all four ABBA rounds and closed all eight standard controller shutdowns, but its required concurrent-cancel throughput gate failed. Its original lifecycle holder completed with state `failed`, exit 1, complete durable output, and a reaped owned agent. Performance rejection is preserved and is not converted into adoption.

The new post-lifecycle read-only postflight was the original job `1a1afe8986e-fc05-6ca9`. It succeeded with exit 0 and emitted 46,206 stdout bytes and zero stderr bytes. Its actual 51,666-byte report is bound to the exact 46,387-byte postflight tool. The three original `process_read` responses are retained separately, with stdout offsets 0, 16,384, and 32,768. The new `native_stream_pages` verifier checks per-stream offsets, progress, byte counts, EOF, hex/text agreement and complete terminal sizes. It does not rewrite these responses into a purported single-page native receipt. The old `native_streams` helper is unchanged.

The postflight report names 150 original artifacts totaling 10,029,336 bytes; the largest is 3,557,457 bytes. The preparer rechecks each original artifact with the unchanged bounded file reader, checks the actual Q/CI/OBS and failed-LC schemas and outcomes, verifies the current 220-input R35 source, the 19 harness files and retained executables, and then performs the original live cache-reference/compiler process scan. The historical observation postflight is retained as a historical snapshot. It is not used to claim that normal lifecycle never ran.

The cache transfer remains a same-filesystem rename after the guards. No full cache copy or deletion is introduced. Original receipts and separately preserved executables remain in R35. The pre-rename cache helper includes an inode identity check and must not be called unchanged by a later post-rename parent binder; that binder can use the original postflight bytes, preparation receipt, renamed-cache result and retained artifacts.

## Creation and failure behavior

`ready_inputs` rejects unsealed or incomplete prior-owner bindings before the first preparation receipt, source copy, or cache rename. The actual future D1 qualification, formatter map, counts, release binaries and measurements remain null in the sealed input. Sealing refers only to immutable input identity and the already completed R35 custody evidence.

The new host root is `/home/qian/hepta-runtime-phase-cost-20261106-d1`. Preparation requires `preparation.json`, `source`, `qualification-01`, and `target-build` to be absent. The original exclusive `preparation.json` claim remains outside `try/finally`; a duplicate invocation cannot replace the first attempt's receipt. A failure preserves that attempt's artifacts and error. There is no automatic retry or cache rollback.

`seal_inputs.py` imports only preparer definitions and validates supplied local original byte streams. It does not call `main`, `cache_owner_closed`, or any host process scan. It creates the requested output directory and every member exclusively, rechecks every copied byte, and leaves partial output on error. The `--seal` switch binds only the already available actual postflight inputs.

The unsealed 51-file package remains at `unsealed-package/`. The actual sealed 51-file package is in the sibling `d1-qualification-sealed-01/`. The standalone installer and deterministic transport archive are in `d1-qualification-transport-01/`. The transport archive contains the complete sealed package, including the original 39-file diagnostic source package, the actual five postflight receipt files, the original postflight tool and publication provenance. The installation receipt is created on the host only after a future successful install; no such receipt is fabricated locally.

## Remaining actual work

The root agent owns deployment, the original first qualification, exact CI, ordinary supplemental checks and any later diagnostic measurement. Source formatting, all Rust compilation/tests, native Q/CI job IDs, final maps, executable identities, trace contents, lifecycle results and timing results for D1 remain unobserved at this preparation step. Existing acceptance thresholds are not changed, and D1 is a diagnostic experiment rather than an accepted optimization.
