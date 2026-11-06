# R33: reuse immutable path components on accepted R24

**Status: complete x230 qualification passed. Exact Rust CI, six-host observation
and normal lifecycle performance are pending. This candidate is not yet adopted.**

R33 starts directly from accepted R24
`baab4def80be7af015b2e7a594cb302f66c4130e`. It removes repeated path-component
allocation while preserving fresh path resolution and complete file checks.
The accepted version remains R24 until the original full performance gates pass.

## Source and behavior

Only two compilation inputs change:

- `src/mcp/runtime/ssh_observation_profile.rs`
- `src/mcp/runtime/ssh_observation_profile_tests.rs`

The complete compiler-input set remains **220**, with 218 byte-identical to R24.
R32 replaces the temporary component Vec in general absolute opens with a
peekable iterator. R33 retains immutable CString components for validated fixed
file pins, shared by Arc when pins are cloned.

Each verification still opens a fresh root and resolves every current directory
and final inode with the original no-follow, directory, nonblocking and
close-on-exec flags. It caches no file descriptor or resolution result. Complete
reads, metadata/ownership checks, byte/digest validation, deadline/cancellation
checks and the final fresh path reopen remain. Cache construction follows the
successful cold read and expected digest check. Dynamic shell resolution remains
a fresh operation.

Four new regression tests cover absolute path/component boundaries, replacement
ancestors and aliases, final reopen and error precedence, and cold-load error
precedence. They are included in the completed full suite. R31 pidfd, router,
cancellation reserve, deferred JSON and larger observation-pool experiments are
not included.

## Original x230 qualification

The original job is `1a1ae8ce865-fc05-603f`. It completed successfully, with
1,210 stdout bytes, zero stderr bytes, complete/durable/synchronized/untruncated
output and no automatic retry. All eight original stages passed:

| Stage | Seconds | Exit |
| --- | ---: | ---: |
| Format | 2.570 | 0 |
| Format check | 2.521 | 0 |
| Harness tests | 6.181 | 0 |
| Clippy | 49.896 | 0 |
| Test build | 704.172 | 0 |
| Complete isolated tests | 245.744 | 0 |
| Independent isolated-test audit | 5.376 | 0 |
| Release build | 342.497 | 0 |

| Result | Count |
| --- | ---: |
| Passed | 1,649 |
| Failed | 0 |
| Ignored | 34 |
| Selected | 1,683 |
| Retries | 0 |

The original 19 qualification tools and the original jobs=2, toolchain,
Cargo home and test protocol are unchanged. The final 220-input map matches
the tested source. A separate postflight reread confirmed every current source
hash and all three independently retained program hashes.

| Retained binary | Bytes | SHA-256 |
| --- | ---: | --- |
| hepta-runtime | 14377384 | `c55f2f8696e01b239e4948da19279d0a425ac2737d8142b58153da8091d45204` |
| hepta-runtime-jobctl | 739016 | `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62` |
| native_process_driver | 2896456 | `51165c1e38409248f5fdb7da2036ebe5e05eec7576035e95bd4b8e2a5c675530` |

[Original qualification report](qualification/report.json),
[final source map](qualification/source-map.json),
[original native terminal](qualification/native-terminal.json) and
[publication source proof](qualification/source-publication-proof.json) retain
the source/result relationship. The initial patch and input maps remain the
original pre-format bytes under preparation/. The full raw qualification
archive is being prepared separately; no archive completion is claimed here.

R31 contributes only its completed inactive build cache, moved by rename with
no deletion or second full copy. Its C1 rejection and unexecuted lifecycle ABBA
remain required closure evidence; R31 is not the source baseline.

## Measured allocation component

Each original R32 and R33 component run used the exact extracted open method on
x230, four path shapes, 16 ABBA rounds and 64 calls per block: **16,384 measured
opens and 256 sample rows per run**, plus separate warmup and functional controls.

| Fixture | R24 allocation + reallocation calls/open | R32 | R33 hot | R33 retained requested bytes after construction |
| --- | ---: | ---: | ---: | ---: |
| Root | 0 | 0 | 0 | 16 |
| Shallow file | 4 | 3 | 0 | 122 |
| Deep file | 12 | 9 | 0 | 236 |
| Directory | 10 | 8 | 0 | 215 |

Every R33 hot block had zero allocator requests. Its four cached shapes released
all recorded requested bytes and allocations at final owner drop. Functional
controls, returned descriptor closure, final FD inventory and fixture cleanup
passed. Nonempty shapes use fewer cumulative allocation requests and gross
requested bytes from the second open onward; this is algebraic allocation
amortization, not CPU, time or RSS break-even.

The cold measurement includes the actual cache expression and minimal holder,
not complete PinnedFile::load. The root/directory shapes are method boundary
controls, not claims that normal pinned-file loading accepts directories.
The counters exclude allocator metadata, rounding and arena retention. Actual
openat/path checks still run, and no whole-runtime throughput or RSS benefit
is inferred from the component.

Original R32 run: `1a1ae7602c1-fc05-5fb2`, raw 106,523 bytes, SHA-256
`dfba82fb3c1b036f6245bb1d342b71621c5b23a3aaf79d47fd0c926ca86d9e66`.
Its first build wrapper failed before Cargo could execute rustc because PATH
omitted the Cargo bin directory. That original failure is retained. Build-02
uses the unchanged frozen package and a corrected outer PATH; the measurement
itself ran once.

Original R33 run: `1a1ae7d1660-fc05-5fd8`, raw 122,141 bytes, SHA-256
`9037dc7f8c1e1cdc068ae2a18a77f2511e4930b9c2d01402b5ee0029d7a1ea35`.
Its original build and run both succeeded. The complete frozen component source
packages are under components/. Original raw measurements are being transferred
from the unchanged x230 files; their publication is tracked separately.

## Remaining gates and provenance

The preserved parent and CI preparation packages retain their original
pre-execution, unresolved status. Real completed qualification receipts now
supply their input identities. Their templates alone do not establish execution.

The subsequent original six-host ABBA observation retains concurrency 1/8/16,
192 calls per cell, 24 warmup calls, two workers, 90-second quiescence and
continuous compiler sampling. Throughput B/A must be at least 0.95; p95 and
controller CPU ratios must be at most 1.10; sampled controller RSS must not
exceed the tighter of A+512 KiB and A×1.05. Normal lifecycle ABBA can begin only
after every original observation, boundary, recovery and summary gate passes.
No saturated cancellation improvement is claimed by this path-only change.

The exact Rust CI package retains cargo check and nextest 0.9.137 with one
test thread and zero retries. Its actual result, hosted Actions and prospective
merge validation are distinct pending evidence.

The finite 85-input historical Python closure matches accepted R24 by Git blob
and mode, and its three discovery sets are unchanged. R33's two changed Rust
files are outside that closure. [The baseline comparison](qualification/python-closure-baseline.json)
reuses the prior audited 18-command outcome; it is not a new Python execution,
nor proof of current external environment or hosted CI equivalence.

A local execution-environment loss during this work did not stop the durable
x230 qualification. Frozen source packages and reviewed tools were recovered
through exact hashes and immutable Git objects; original benchmarks were not
replayed. New Git trees are independently reconstructed before the leased branch
update.
