# Fixed archive phase diagnostic r01

Status: prepared locally; no diagnostic process has been executed by this agent.
One new x230 fixture and the existing failed-r02 **baseline A** binary only.
No candidate B process, Rust rebuild, installed runtime change, comparison,
deadline extension, weakened authority fence, retry or old-fixture cleanup.

The fixed build report SHA256 is
`4ccfc46a0c0ed40b3a15dc9f496cc986ffa5bac9754df9761598a4fff72fafff`;
the original A binary SHA256 is
`403b9b4978e398775f177f464c5bad3b6b5537270e8ffd433b7d908af3f84f2a`.
The script requires both exact values and verifies the complete existing r02
build/source/helper receipts before launch and after original-child termination.
These pins were supplied by root from the actual failed experiment; this local
preparation does not claim to have downloaded the executable body.

## Fixed operations

1. Retain a direct original `Popen` for exactly one `probe-A`, using a fresh
   sibling output directory and a new 65,536-original, 512-hot-copy fixture.
   Keep the original setup, one index-worker trigger, complete synthetic oracle
   and two setup queries: one usage and one history. No setup query retry.
2. Wait the existing fixed eight-second settle interval once.
3. Send exactly two cells in order: eight **C1 usage** queries, then eight
   **C1 history** queries. Both use case offset zero, no cold-cache clearing.
   Total public queries: **18**. Failure stops all following cells.
4. Use unchanged worker-permit draining, sampler termination and error-log
   receipt, explicit stop, complete final original-fixture hash verification,
   original-child wait and stdout-reader join. Retain the fixture and all logs.

The native API budget stays **3,000 ms from entry** and the actual closure
limit stays eight. Setup/final cooperative budgets and watchdogs are unchanged:
240 seconds for setup, 62 for each fixed C1 cell, 225 for final verification.
A 660-second outer job budget leaves room for fixed teardown and file hashing;
an outer timeout never proves cleanup. Blocked kernel I/O, original-child wait
or reader join can exceed cooperative deadlines. Failure retains partial
evidence and never permits a replacement launch.

## Instrumentation and evidence

The imported frozen runner normally strips every `HEPTA_*` variable. A local
module adapter checks the exact single A launch and adds only
`HEPTA_ARCHIVE_INDEX_TRACE=1` after that sanitization. It does not patch the
standard `subprocess` module, wrap the executable, or change the runtime/probe
source. The original child is therefore still the measured process.

`SteadyTrace` writes directly to stderr after authority guards drop, regardless
of tracing-subscriber initialization. Preserve the full stderr file and all
structured stdout records. New cell markers provide wall-clock boundaries;
the report retains every `archive_index` trace line without success filtering.
Read the three inotify sysctl limits before/after; never write them or read,
duplicate, drain or re-arm the child's inotify event stream.

The existing trace only emits stages above 100 ms. `metadata_drain.state_us`
includes drain/admission state checks; `snapshot_read_us` includes the explicit
unwatched full scan, usage/history work and final version check. `input_rows`
counts pending records, **not** original members scanned. Initial hot-store
preparation and `ready()` happen before this trace. These are wall-time phases,
not CPU samples. The existing cell process CPU clock remains intact, with
diagnostic overhead explicitly included.

This can localize the dominant phase. It **cannot directly observe**
`state.version=None` or an earlier `IN_Q_OVERFLOW`, so both direct-observation
flags remain false. No automatic cause classifier or performance gate is run.
Absence of a slow trace is recorded as missing phase evidence, not fabricated.

## Invocation

Run `run_archive_diagnostic.py` with `--probe-dir` pointing to the exact frozen
r02 probe helper directory, `--build` to its successful isolated build, both
required SHA arguments above, and `--out` to a fresh sibling of that build.
Do not point output at a runtime state directory. Raw inherited process
receipts contain private identities and require the established public
sanitization step before publication.
