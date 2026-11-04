# Bounded diagnosis of the all-features test failures

Five originally failing existing tests passed when run one at a time in fresh
processes, with the **same 1,024 soft file-descriptor limit**. This supports a
resource/concurrency-interference hypothesis. It does not replace a full-suite
qualification or prove that every original failure has the same cause.

## Evidence and scope

The original all-features run reported 1,421 passed, 275 failed, and 36 ignored
tests. One failure was the new mutating-tool inventory expectation omission,
which the main implementation owner subsequently fixed. This diagnosis used a
frozen copy of the **original r2** test executable only for unmodified existing
tests; it did not test that later expectation fix.

Frozen executable SHA256:
`29b2d1df15d0996f8744abb29eddc9af6ca3a93eb9dcbe06beedae845a5a6268`.

The copy was made through an opened source file, checking stable inode, size,
and mtime during the copy and comparing source-stream/copy SHA256. Recompilation
could therefore proceed separately without replacing the executable under test.
The frozen binary and raw operational files are temporary diagnostic material,
not publication artifacts.

The failure modules were request-audit (229), request-results (33), server tests
(10), and one each in owner fencing, job-start I/O, and operation graphs. Error
classification found 228 state-lock-unavailable failures, 25 archive-metadata-
unavailable failures, and 9 dispatch refusals caused by unavailable audit state.
The original log also explicitly contained `Too many open files (os error 24)`,
timeouts, a metadata deadline failure, and permission-related failures.

The host reported 48 logical CPUs. The captured inherited descriptor limits
were soft 1,024 / hard 1,048,576. The original harness worker count was not
recorded, so this report does not equate the host CPU count with a measured
parallel-test count.

## Exactly five isolated executions

Each invocation used one `--exact` test, `--test-threads=1`, a fresh process,
and its own private temporary directory. Descriptor limits were not raised.
No `cargo` invocation, rebuild, or source modification was performed by this
diagnosis.

| Originally failed test, abbreviated | Original failure | Isolated result | Harness time |
|---|---|---|---:|
| `graph_fifo_is_nonblocking_refusal_without_waiting_for_a_writer` | elapsed time exceeded 2 seconds | Pass | 0.51 s |
| `active_capacity_and_lookup_pins_survive_cohort_eviction` | descriptor exhaustion | Pass | 1.79 s |
| `shared_preflight_leaves_a_missing_store_for_the_original_exclusive_path` | preflight result assertion | Pass | 0.08 s |
| `pending_publication_saves_frozen_intent_before_recoverable_identity` | operation-intent audit unavailable | Pass | 0.06 s |
| `one_unsafe_hot_leaf_does_not_rewrite_it_or_reject_other_completion` | private audit inode refused | Pass | 0.13 s |

Full test names, process wall times, load averages, executable identity, log
hashes, and reviewed source hashes are in `qualification.json`. The test
budget was five executions and is exhausted; no additional reruns are implied.

## Source mechanism and remaining uncertainty

`request_audit.rs` stores the audit lock in a process-global `OnceLock`.
`AuditSharedGuard::drop` marks the shared-reader state poisoned during unwinding,
and `AuditStoreGuard::drop` preserves ordinary mutex poison. Future acquisitions
can consequently report `request audit state lock unavailable`. The archive
index maps the same unavailable lock state to `archive metadata unavailable`;
dispatch also depends on audit availability.

This explains how one panic in a held shared audit context can affect many
otherwise unrelated temporary roots in the same test process. Some archive
tests use `serial_test::serial`, while the inspected batch cases are unmarked;
that attribute does not isolate them from unmarked users of the same global
state. Heavy fixtures also retain many open receipts and archive descriptors,
so simultaneous test activity can exceed a limit that each test meets alone.

The original log does **not** identify which panic first poisoned the global
state. An observed descriptor error is not, by itself, proof that it triggered
every later failure. Isolation changed concurrency, process-global state, and
temporary-directory placement together; the five passes are evidence about
those conditions, not a complete causal experiment. Parallel test reliability
and any genuine contention/resource-path defect remain unqualified until the
remaining failures are resolved or independently reproduced.

## Concrete next gate

Run the newly compiled full suite with `--test-threads=1`, retaining the existing
1,024 soft descriptor limit and capturing full failure output/backtraces. The
main owner is performing this gate separately. A complete pass there would
qualify that explicit serial configuration; it would not retroactively turn the
original parallel run into a pass.

If serial execution still fails, investigate the **first** failure in a fresh
process before interpreting later poison-related errors. A persistent isolated
failure requires a real fix, not an environment waiver. For long-term test
isolation, all tests using the same global audit state or hooks must share an
appropriate serialization boundary, or deliberate-poison cases must run in
child processes/test-local injected locks. Do not clear production poison,
silently increase limits, skip assertions, or weaken security checks to obtain
a green test result.
