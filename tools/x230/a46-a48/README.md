# X230 A46–A48 validation tools

These files preserve the executed or prepared experiment tools and the immutable
helper definitions they reuse. The proposed publication groups are
`tools/x230/a46`, `tools/x230/a47`, and `tools/x230/a48`;
`dependency-summary.json` records exact local bytes, SHA-256 pins, dependency
edges, and the remaining publication choices. Tool publication does not itself
establish a performance result or authorize adoption.

## Execution layout and prerequisites

The recorded execution root is
`/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01`.
Most tools require their original flat `tools/` paths under that root. Repository
grouping is an archive layout, not an automatic installer. The A48 binder also
expects the frozen A46 templates in an `a46-bound/` directory beside the binder.
Stage identical bytes at the expected paths; changing a filename in a repository
does not change the path or SHA pinned by a running tool.

**A fresh clone is not a standalone reproduction environment.** Historical
qualification reports, original worker/entry receipts, logs, private fixtures,
source trees, executable bodies, file identities and timestamps remain on X230.
The tools recheck these originals. Copying a JSON receipt cannot recreate its
original inode or prove the historical source/worker chain. Rust 1.95.0, the
offline Cargo cache, locked dependencies, Linux `/proc`, pidfds, and the retained
target directory are also execution prerequisites. Large raw evidence and
compiled binaries are deliberately outside this helper publication.

## Serialized run order

1. **A46 A42 release completion:** `continue_a42_release_a46.py` uses the frozen
   release implementation, source proof and owned-worker cleanup. It verifies
   the five successful original r03 stages and performs one new release build.
   Its composed qualification preserves the previous failed attempts; it does
   not turn them into successful six-stage runs.
2. **A46 archive comparison:** the bound loader checks ordinary r07 evidence and
   the explicit A42 composition. Run the small comparison, then its independent
   numeric evaluator. Only an accepted small guard admits the large fixed ABBA
   comparison. All failed large calls remain in the result.
3. **A43 qualification and A47 lifecycle:** after archive workloads finish,
   `qualify_a43_a46.py` runs all six stages for the separate owner-barrier source.
   `validate_owner_lifecycle_a47.py` requires both complete qualifications and
   the final A46 guardian, then runs its fixed correctness, crash-cut and local
   lifecycle comparison. The A43 source is separate from A48.
4. **A48 qualification:** `qualify_a48_page_fullscan_r01.py` prepares the four-file
   overlay from the exact qualified A42 parent and runs all six stages anew.
   Final worker checks require strictly fresh test/release artifacts, the two
   added tests plus eleven existing tests in the original full-suite log, and
   unchanged dependencies. The overlay's input map may differ from the actual
   post-format tested map; the qualification must bind both.
5. **A48 benchmark binding and comparison:** only after final qualification,
   entry and worker reports succeed, use `bind_a48_archive_experiments.py` with
   all three actual files and SHA pins. It emits new protocols/runners without
   executing benchmarks. Both runners pin, copy and fence the final guardians;
   the evaluator rechecks captured originals. Run small, evaluate its fixed
   gates, and only then run large. Prepared or mock-bound files are not results.

Build and test settings remain `CARGO_BUILD_JOBS=2`,
`TOKIO_WORKER_THREADS=2`, `RUST_TEST_THREADS=2`, and `CARGO_INCREMENTAL=0`.
Serialize builds and experiments: no Cargo/rustc work overlaps a benchmark,
another qualification, or lifecycle measurements. Each actual Cargo stage
requires a fresh complete host observation, at least 2 GiB available memory and
disk, and no matching live busy process. A clear observation is a point check,
not an exclusive host lease. Busy or incomplete gates refuse the attempt.

Qualification stages retain 1,800-second budgets, the full qualification worker
6,600 seconds and outer guardian 7,000 seconds. A46's release-only worker/outer
budgets are 1,900/2,100 seconds. Owned cleanup retains its separate 30-second
TERM and 30-second KILL budgets; no historical window supplies new admission.

## Fixed measurement scope

| Experiment | Fixed inventory | Interpretation |
|---|---|---|
| Small archive | Two opposite-order ABBA blocks; 8,192 measured and 8,848 total tool calls; C1; two runtime workers | Native local MCP regression guard; numeric rules remain in the pinned protocol. |
| Large archive | Four fresh A/B/B/A controllers; 80 measured slots, 32 waves, C1/C4; 65,536-record fixture | Native local archive comparison; the product metadata deadline remains 3 seconds. No retry or failed-slot replacement. |
| A47 lifecycle | r07/A43/A43/r07; C1/C4; 16 jobs per cell; 128 measured jobs | Verbatim extracted production Python with synthetic local effects and controlled process crash cuts. |

A47 does not establish native MCP/SSH acceptance, host reboot or power-loss
durability. These experiments do not establish multi-host acceptance or complete
caller isolation. CPU, RSS, timing and correctness results retain their original
measurement scopes; successful functional calls do not imply a numeric pass.
The separate evidence publications determine result status and adoption.

## Existing immutable aliases and retained versions

At PR71 head `eb57edfbb0db8b934534bb511674ab4635e5e31a`, the following repository
files were read and their SHA-256 values matched the required X230 helper pins:

- [`tools/x230/a40/qualify_runtime_candidate.py`](https://github.com/TrillionniumFoundation/hepta-runtime/blob/eb57edfbb0db8b934534bb511674ab4635e5e31a/tools/x230/a40/qualify_runtime_candidate.py): 5,915 bytes, SHA-256 `64efa0da0d22e2ad8d10eb6f8a91ab158a234b331383bbd595e65fc9bd47d1d2`.
- [`tools/x230/a40/x230_small_archive_benchmark.py`](https://github.com/TrillionniumFoundation/hepta-runtime/blob/eb57edfbb0db8b934534bb511674ab4635e5e31a/tools/x230/a40/x230_small_archive_benchmark.py): 37,646 bytes, SHA-256 `98413b4b177ec3bf68b7fe67de153376465374a9e74690c337633b3b4a912ffb`.

The small runner separately requires `run_a41_native_validation.py`: its exact
47,629-byte original has been retrieved from X230 and verified against SHA-256
`d35bfe354d405b6efb2d2ca28e06bb6469016cc6cf0c611ca3c107b043ea0d32`.
It is included in the proposed A46 publication inventory and is not
interchangeable with the r07 helper, whose SHA starts `61236609`. The final
upload map remains the publisher's choice.

## Frozen A48 qualification export and actual bindings

A48's ordinary qualification and final guardians succeeded. The actual bound
small/large runners, protocols, offline evaluator, binding diff and binding
manifest are now in the proposed A48 inventory. Their exact bodies were checked
against the actual manifest; no mock output is included. Qualification success
and emitted bindings do not imply benchmark success.

The qualified 168-file map has compact SHA-256
`be631e20eb7ec586c77807bb4e38b6529c5cda1fcc906eb1fac20f793c8c0ff1`.
Preserve the prepared overlay/input bundle unchanged, but publish the exact
post-format four-file source export. Only `request_archive_page_batch_tests.rs`
changed during fmt: the actual tested body is 4,912 bytes with SHA-256
`93b1f5031025746227368ab02f259fe3251a597ba3f4af79304e66018a9ded67`.
The dependency summary references the complete tested map and source-export
manifest, and distinguishes those exports from the retained X230 raw logs,
source identities and ELF bodies. The separate A48 qualification/design section
records all six stages, 1,266 top-level passes and 23 ignored tests; benchmark
outcomes remain separate evidence.
