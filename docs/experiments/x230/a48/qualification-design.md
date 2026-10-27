# A48 page full-scan: design and qualification

A48 completed a new ordinary six-stage qualification on X230 on 2026-10-26.
All six stages succeeded; the top-level full suite reported **1,266 passed,
0 failed and 23 ignored**. This section records the qualified design and its
source/artifact identities. Throughput, CPU and memory outcomes require the
separate fixed comparisons; no performance improvement or adoption is claimed here.

## Design and preserved behavior

The page path now passes its held store guard through `SnapshotReadMode::Pages`
to `verify_page_members`, which reuses the existing `verify_members_in_mode`
implementation. Above 16,384 base database rows, the complete observation uses
the existing two owned readers. Smaller online observations and cold validation
remain serial. This targets the complete-validation work that remained on the
page path after A42; its effect on C4 deadlines must be measured.

The change retains fresh validation of the complete original archive, including
records outside the requested page. It also retains selected-record rereads,
the state/store guard lifetime, the common final fence, each caller's result,
the fixed 1 ms collection cutoff and frozen membership, and the 3 s metadata
deadline. The reader kernel and its join, timeout and permit-custody behavior are
reused. A48 does not include the separate A43 owner-barrier source change.

Two added tests passed in the original full-suite run. The two-reader test warms
a tiny fixture, changes an original outside both the selected page and lookahead,
and verifies refusal without source/cache repair. The shared-page test mutates a
foreign off-page record just before the final fence and requires the whole page
group to fail. Their small fixtures isolate kernel and fence behavior; they do
not establish performance or production large-selector coverage. Eleven existing
required test names also have original `... ok` lines, including deadline/join,
permit retention, worker spawn failure/panic, bounded lanes and fixed-cutoff tests.
There were no focused reruns. The two nested filtered child-test summaries in the
log are excluded from the 1,266 top-level total. See
[qualification-summary.json](qualification-summary.json) for all names and lines.

## Exact tested source

The complete 168-file map is [source-tested-map.json](source-tested-map.json).
Its compact sorted-JSON SHA-256 is
`be631e20eb7ec586c77807bb4e38b6529c5cda1fcc906eb1fac20f793c8c0ff1`.
It equals the qualification's `source_tested`, `source_after` and final entry map.
Compared with the exact A42 parent map
`c1ae8a69901aee16e03871e920a6a7e321672c9b30b3a6e75d3560390b8c2e11`,
only the following four file hashes differ; the other 164 remain identical.
Paths below are relative to `src/mcp/runtime/`.

| File | Bytes | Actual tested SHA-256 |
|---|---:|---|
| `request_archive_content.rs` | 19459 | `5517200af9889d571a625b31ae30b761f81f0154016181bf6ffd0a8f8357af38` |
| `request_archive_content_parallel_tests.rs` | 19485 | `8b9dddfd5b9fb2577452016d5818ca87c91fb790605e7061d822794b6212851f` |
| `request_archive_index.rs` | 75046 | `5cec6362637d1ac17c9b6ae55e4d5b9c317ae893e818ac8c8d54b5e8b7cd389d` |
| `request_archive_page_batch_tests.rs` | 4912 | `93b1f5031025746227368ab02f259fe3251a597ba3f4af79304e66018a9ded67` |

The prepared input map remains
`f7e2d63efdefd2001519de66e09a5b2ae0f2673db6c36522f56c0040191f332b`.
Rustfmt changed only the multiline assertion in `request_archive_page_batch_tests.rs`
from its 4,905-byte preparation body to the 4,912-byte tested body. Preserve the
original overlay manifest and input bundle as preparation evidence; publish the
actual tested source export without reformatting it.
[source-export-manifest.json](source-export-manifest.json) binds each exact local
export, parent/input hashes, the full map and qualification receipt.

## Six-stage evidence

The ordinary qualification ran from `2026-10-26T03:49:53.391041+00:00` to
`2026-10-26T04:04:17.085695+00:00`. Every stage executed once with a recorded fresh clear gate,
its original 1,800-second limit and return code 0. Cargo/Rust test/Tokio settings
remain 2 jobs/2 threads/2 workers, with incremental compilation disabled.

| Stage | Elapsed seconds | Return code |
|---|---:|---:|
| format | 2.052 | 0 |
| fmt-check | 1.964 | 0 |
| clean-package | 0.334 | 0 |
| clippy | 39.992 | 0 |
| test | 495.212 | 0 |
| release | 320.776 | 0 |

The final guardian records successful postchecks, an unchanged parent and
unchanged reused dependencies. Its original worker was actually reaped with raw
wait status 0, custody retained until reap, a quiet group, and no cleanup signal.
The worker's strict-freshness and required-test-coverage checks both passed.
Qualification, entry and worker receipts are mutually bound; both compiler events
are source-bound and strictly `fresh=false`, and both copied artifact receipts
have `cached=false`.

| Evidence | Bytes | SHA-256 |
|---|---:|---|
| Ordinary qualification | 59526 | `2787841b5242c22e314d46a4e99074fb0b91f04ed4240f230004b5d635c3cd0b` |
| Final entry | 309398 | `871814ec2e5d3b870623fd6496a044626292efbc9b5658f488a6470e2a2cf851` |
| Final worker | 22281 | `758785ba8ecbaef30818cb21e7daa62ce45f3b86c575436c870c1e5f52dea940` |
| Original full test log | 420694 | `121a5e1d0aa8f4f7029e404620f7c22b3c48e019794090bcf7fdb5eff2f62120` |

Qualified release SHA-256:
`252cb58e08559d6cc68a5db19008c20ec858f7693a44ae353e60bbda81a2b386`.
Qualified test ELF SHA-256:
`125d238ca27ad1a1c6f4610cd1bb8207d8078084a0771297170d344a1e81f0bc`.

The publication review independently rehashed the three report bodies, test log,
four changed source exports and actual bound tool outputs. Full stage-gate bodies,
release-log body, all remaining source bodies and ELF bodies remain on X230; their
retained original receipts are not replaced by this local review.

## Benchmark admission

The actual A48 binder output matches this qualification, both final guardians,
the prepared/tested maps and release SHA. Independent AST comparisons retain the
A46 measurement/custody helpers and numeric algorithms, and both protocols retain
the original numeric gates. The binder itself executed zero benchmarks. The fixed
sequence remains small (8,192 measured / 8,848 total calls), independent numeric
evaluation, then large C1/C4 ABBA (80 measured slots) only if small passes.
The failed A46 comparison remains intact; A48 results must be reported separately.

## Additional qualified-source publication check

A separate read-only export on X230 hashed the actual bodies of all 168
qualified source files and recorded their SHA-256, byte length, original stat9
identity and Git blob identity in
[qualified-git-object-map.json](qualified-git-object-map.json)
(48,074 bytes; SHA-256
`c0ca1f80c2eb2eaebb80bdb8d83dfbf57ce3f2c640364b69c20b0bcb1106c9a6`). It binds the same successful qualification.

The complete exported SHA-256 inventory equals the actual tested map. Comparing
its Git blob identities with PR71 commit
`eb57edfbb0db8b934534bb511674ab4635e5e31a` gives exactly the four source changes
listed above, with the same 168 source paths and no additional or missing source
members. The four locally exported bodies also reproduce those Git blob hashes.
This extends the source-publication verification without claiming that ELF,
release-log or raw benchmark bodies were independently re-read by this document.
The original source-object map and raw qualification reports remain unchanged.
