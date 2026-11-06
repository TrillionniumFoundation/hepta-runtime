# R32 and R33 allocation component results

The two complete original runs each contain **256 hot sample rows and 16,384 completed opens**. Recomputing every case/arm counter from the raw rows reproduces all original case summaries, with no internal discrepancies. The full source/control/cache reconciliation is in [allocation-static-review.json](allocation-static-review.json); original bytes remain in [r32-run-01.jsonl](r32-run-01.jsonl) and [r33-run-01.jsonl](r33-run-01.jsonl), with [transfer evidence](raw-transfer-01.json).

These are instrumented Rust allocation-request counts for specific methods. Neither run measured whole-runtime throughput, concurrency, latency, CPU or RSS.

## Hot requests per completed open

A is the original R24 opener in each respective run. R32 B removes its temporary component Vec; R33 B is the final cached `PinnedFile::open_path` method. Each table cell is recomputed from 2,048 completed calls per arm and shape.

| Shape | Normal components | A requests/open | R32 B requests/open | R33 B hot requests/open |
|---|---:|---:|---:|---:|
| Root | 0 | 0 | 0 | 0 |
| Shallow file | 3 | 4 | 3 | 0 |
| Deep file | 9 | 12 | 9 | 0 |
| Directory | 8 | 10 | 8 | 0 |

“Requests” is `alloc + alloc_zeroed + realloc`. Root retains its original **no improvement** flag. The R33 endpoint comparison includes the R24 → R32 → R33 path changes; its zero hot count does not isolate the contribution of each change.

The frozen protocol is 16 ABBA rounds × 64 calls × four shapes. Its separate warmup is one ABBA cycle of 16 calls per block for each shape; warmup is outside the reported hot samples. The raw grids have unique case/round/position coordinates and preserve ABBA order.

## Cold cache cost and final release

R33 constructs one cache before each shape's hot series and releases its last owner afterward. All four construction/release pairs reconcile exactly.

| Shape | Live allocation requests after construction | Live requested bytes | Net requests after final release | Net requested bytes after final release |
|---|---:|---:|---:|---:|
| Root | 1 | 16 | 0 | 0 |
| Shallow file | 4 | 122 | 0 | 0 |
| Deep file | 10 | 236 | 0 | 0 |
| Directory | 9 | 215 | 0 | 0 |

Live requested bytes are `alloc_bytes + alloc_zeroed_bytes + realloc_requested_bytes - realloc_previous_bytes - dealloc_bytes`. Each reported cold byte total also equals its recorded CString payload, descriptor and holder decomposition. R33's hot blocks balance both request counts and requested bytes. R32's older eight-counter format lacks prior realloc sizes, so this review does not invent that missing byte-balance measurement.

These values describe Rust allocation requests. Allocator arenas, usable allocation sizes, C-library allocations and process RSS are outside the counters. The persistent cold cache cost remains separate from the zero hot allocation count.

## Source and correctness reconciliation

The [R32 package](r32-allocation-component-package.tar.gz) and [R33 package](r33-allocation-component-package.tar.gz) are bound to Git and SHA-256. All 17 and 19 manifest-listed package members respectively were checked, without extracting files or executing package programs. Original JSONL source labels match the frozen input manifests and extracted function hashes.

The R24 A profile is byte-identical to accepted R24. The R33 component uses the frozen **pre-format** profile SHA `8a8721585d9c5e06e8962a6d3a3f4d1976e694ce641d41254f5e693ae81e3007`; published PR #99 uses **formatted** profile SHA `0aa75f16ac55285f536c72c0ffcbea13fcc74ab2c735cd3b04108b475ab0ba34`. Those whole files differ. Every measured method and cache-expression byte slice occurs exactly once in its bound published source; the R32 B opener also occurs unchanged in the R33 source. The review is pinned to source commit `2e2057d1af4d0205ee84933484beb5d598d72fe1`.

R32 has 10 original controls and R33 has 11; all report agreement between arms. R33's six invalid-syntax controls are cold preconditions with `B_open_path_called=false`. Its open-method controls include a missing leaf, symlink rejection and replacement of an already-cached ancestor. All 256 samples in each run report functional/FD success. Both terminal records report unchanged FD inventory, successful fixture removal, no errors and no automatic rerun. Those original outcomes were reconciled, not re-executed or independently syscall-traced here.

R33 uses a one-field holder and does not exercise full production `PinnedFile::load` or `verify`. Root and directory are method edge shapes with A's directory flag false; they are not successful regular-file PinnedFile loads. R32's file-as-directory control is therefore not carried over as a claim about R33.

## Earlier failures and remaining evidence boundaries

The first R32 build, job `1a1ae6fdbf2-fc05-5f97`, failed because the original PATH did not resolve rustc, according to the parent execution record. That failed build remains separate evidence; these successful raw runs do not reclassify it. Complete compiler logs and native build/run receipts were not independently re-read in this static review.

Package documents retain their preparation-time “not yet built/executed” state. The later original JSONL records establish the reported component executions. No component, build, test or original auditor was rerun here. The counts do not establish runtime adoption or the still-separate observation and lifecycle gates.
