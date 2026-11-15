# Audit parent binding: isolated test-fixture diagnosis

The existing pending-publication test uses a flat temporary-root/audit.jsonl fixture.
The production audit binding protects both the audit directory and its parent state
directory. Consequently this fixture accidentally includes the shared temporary
directory in its publication fence. Unrelated sibling creation or deletion can
correctly trigger the production guard and incorrectly fail this success-path test.

## Controlled result

The same frozen test executable, the same private temporary directory, one harness
thread, and the unchanged NOFILE limit of 1024 were used for exactly two runs.

| Case | Parent directory | Result | Traced test wall time |
| --- | --- | --- | --- |
| Quiet control | No unrelated namespace mutation | Pass | 0.168 seconds |
| Perturbed | One owned marker repeatedly created and removed | Same panic as the failing test | 0.305 seconds |

The perturbation completed 770 create/unlink pairs with no errors, a maximum of one
marker file present, a 5,000-pair limit, and a three-second time limit. Only a newly
created private directory was touched. No production service, shared source,
resource limit, or poisoned global state was changed. The test itself does not
submit a remote operation.

The failing control reported the same source location and message:

```text
src/mcp/runtime/jobs_start_io_tests.rs:354:27
called Result::unwrap() on an Err value:
Operation intent audit unavailable; no remote operation submitted
```

The wrapper deliberately replaces the underlying audit error, so the internal
branch was reconstructed from the traced system calls and the source, rather than
read from this message.

## Exact binding and validation evidence

In src/mcp/runtime/jobs.rs, AuditBinding::open derives audit_path from the audit
file's parent at lines 2011–2014. It then derives state_path from audit_path.parent()
at line 2015. The original test fixture therefore resolves as follows:

| Value | Original fixture | Proposed fixture |
| --- | --- | --- |
| Audit file | TMPDIR/test_root/audit.jsonl | TMPDIR/test_root/audit/events.jsonl |
| audit_path | TMPDIR/test_root | TMPDIR/test_root/audit |
| state_path | TMPDIR | TMPDIR/test_root |

audit_directory_stamp includes device/inode, mtime, ctime and a namespace version
(lines 1940–1952). The perturbed trace shows successful opens and stable audit-file
and immediate-parent identities. The state directory keeps the same inode, but its
mtime and ctime advance by 582,261 ns from the initial stamp (trace line 36) to the
validation read (line 57). There is no namespace-fingerprint fallback open.
The state-directory mismatch therefore takes the directory-publication branch at
jobs.rs:2062–2065 during the initial validate call at line 2039.
The trace then closes the audit binding; there are no fdatasync or fsync calls.
This refusal occurs before line 2234's audit write, not during the later
post-synchronization validation. The perturbed trace contains no EMFILE.

The quiet control completes the initial validation, file synchronization, parent
directory synchronization, final validation, and record publication.

## Minimal proposed repair

minimal-fixture.patch changes only this test's setup to create its own audit
subdirectory and use audit/events.jsonl. Both directories checked by the binding
then remain within the test-owned root, matching the production layout. It keeps
the original assertion that the exact frozen audit intent is durable before the
recoverable job identity is saved. No production integrity check is weakened.

This diagnosis agent has not applied or tested the proposed patch. The parent
integration task must apply it, rerun this test and required suite gates, and
record those separate results. An unrelated shared-temp-directory mutation is a
demonstrated failure mechanism; the original untraced serial-run failure cannot
identify its exact external trigger retrospectively.

## Reproduction protocol

Use an immutable copy of the pre-fix test executable with the recorded SHA-256.
Create an empty owner-only temporary parent. Run the exact test once with TMPDIR
set to that directory and RUST_TEST_THREADS=1. Run it a second time with the same
configuration while a separate bounded worker creates and immediately unlinks a
single unrelated marker in that parent. Never mutate the test's own child
directory. Preserve the NOFILE limit, use a short subprocess timeout, and capture
strace stat/open/sync operations and the harness panic. The two actual raw logs,
traces, frozen executable and executed driver remain on the authorized host;
their hashes are recorded in qualification.json.

These two observations establish a counterexample and its mechanism, not a flake
rate. Strace changes timing, so the durations are not performance claims. This
diagnosis also does not explain every failure of the earlier parallel suite.
