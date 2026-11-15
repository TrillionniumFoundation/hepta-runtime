# A53: bounded direct SSH ownership

This design accompanies the A53 candidate derived from the published A52 head
`06c18da77a3433a34773c0ed690833cd44db5715`. Qualification and acceptance are separate
from the design: the original reports and the checkpoint README determine which
properties have actually passed on X230. A source review or an earlier A52 pass
does not qualify the A53 release executable.

## Observed problem

The A52 native concurrency attempt submitted eight distinct durable jobs through
one real X230 Rust MCP connection to AI395. All eight initial launches were
acknowledged. The early repeated keys reused the same eight jobs, and the first
terminal observations reported the expected exit codes and durable output.
The subsequent batch contained sixteen simultaneously pending status/read RPCs.
Two original SSH processes returned exit 255 with a connection-closed diagnostic;
the remaining fourteen replies were received. The attempt failed, and its final
same-key batch was never executed.

The complete failed report, independent remote snapshot and original byte
streams are retained. Reconciliation established one recorded effect per original
job, but it does not replace either failed RPC or turn that attempt into a pass.
Source inspection confirms that the default direct path lacked an admission
boundary; the failed attempt motivates bounding it. It does not establish a
particular server-side `MaxStartups` setting as the cause of the two failures.

The optional observation connection pool already has its own limits. Native
operations using the default direct `run_capture` path did not inherit those
limits. A53 therefore gives that path an explicit admission and ownership layer.
The observation pool implementation is unchanged.

## Resource and deadline contract

| Resource | Direct-path bound | Ownership duration |
| --- | ---: | --- |
| Admitted requests | 16 | Queuing, submitted work and original-child cleanup |
| SSH children per exact configured target | 2 | Until that original child is reaped and I/O cleanup completes |
| SSH children across direct targets | 8 | Until that original child is reaped and I/O cleanup completes |
| Direct transport owner | One OS thread and a current-thread Tokio runtime per runtime-enabled MCP process | Joined at normal transport shutdown |
| Child cleanup | One latched 3-second deadline per child | A later observer cannot renew it |

Admission first reserves the bounded admitted-request slot, then awaits the
target slot, and finally awaits a global connection slot. Same-target waiters
therefore do not occupy all global connection slots while waiting for their host.
The seventeenth admitted request is rejected before retaining a new target entry
or copying its request payload. The per-target registry uses weak semaphore
references; active waiters and original children retain the exact semaphore they
acquired. An idle target entry can be reclaimed without replacing a live limit.

The transport keeps the original absolute RPC deadline. Time spent waiting for
admission is part of that deadline. The existing SSH argument construction,
10/15/20-second operation budgets and bounded stream readers are retained. No
timeout path retries a submitted command, and a failed observation does not
authorize relaunching a durable business job.

These limits are per configured target string, not a discovery mechanism for
physical SSH servers. Two different configured aliases are not automatically
merged. At sixteen admitted requests, fail-fast saturation does not promise
cross-target fairness for an additional request. Those are explicit limits of
the design rather than claims of a general cluster scheduler.

## Submission and cancellation

Before submission, cancellation races against a queued-to-committed atomic
transition. The winner determines the contract:

| Outcome at the submission boundary | Required behavior |
| --- | --- |
| Cancellation wins while queued | No SSH child is spawned |
| Original deadline has expired before commit | No SSH child is spawned |
| Transport freeze wins before commit | No new work is submitted |
| Commit wins, then cancellation occurs | The original submitted attempt remains owned through cleanup |
| Caller disappears during execution | The independent owner handles that original child; caller destruction cannot release its permits |

The cancellation transition is short. Dropping a caller does not wait for an OS
spawn, pipe operation or process reap under that transition lock. After commit,
the owner registers the actual `Child` together with all three permits before
fallible pipe preparation or asynchronous I/O. It never reconstructs authority
from a caller-selected PID.

## I/O and original-child custody

Input, stdout, stderr and the original wait are driven together. Success requires
the original process status and completion of the bounded stream readers. On a
timeout, cancellation or capture error, the I/O futures and pipe borrows are
dropped before cleanup starts. Cleanup operates on the retained original
`tokio::process::Child`, and uses its original wait result before releasing any
capacity.

The release order is deliberate: remove the reaped child from the ownership
registry, drop the final child owner and its admitted/host/global permits, then
make the reply visible to the caller. A successful reply followed immediately by
another request therefore sees the released capacity. An expired caller can
return an error while the independent owner still holds its original cleanup
obligation and permits.

If a wait cannot be confirmed, the transport freezes admission and retains the
reachable original child and capacity. It does not substitute a guessed exit,
signal an unrelated PID, create a replacement owner, or report successful
shutdown. This intentionally sacrifices capacity when ownership is uncertain.

## Shutdown and failure boundaries

Normal stdio EOF, termination handling and transport completion freeze direct
admission. Main joins both the direct transport and the existing observation
pool, collecting both cleanup outcomes before propagating either error.

The dedicated owner thread keeps its child registry and task set outside the
fallible actor future. In builds that unwind, an actor or request panic leads to
drain and original-child cleanup. The join worker persists its result in a shared
receipt. Cancelling the first shutdown waiter therefore cannot let a second
waiter replace a pending or failed join with success.

The release profile still uses `panic=abort`. Unwind regression tests do not prove
cleanup after process abort, `SIGKILL`, machine loss or loss of the underlying
kernel. Persistence and recovery at those boundaries require separate evidence;
the native suite below covers only its stated controller/owner `SIGKILL` cases.

## Relationship to persistence and recovery

A53 retains the A52 persistence changes: the original owner publication uses two
file fsyncs and a directory barrier; stable malformed or incomplete started
metadata is classified as unknown only after strict ownership, mode, link,
regular-file, no-follow and unchanged-file checks. Unsafe or changing metadata
still fails closed. Unknown ownership never authorizes automatic business retry.

The archive path also retains A52's owned validation cohort: one original leader
owns the complete validation and its original permits, while followers wait
asynchronously. The one-millisecond cohort window, original three-second
deadline, full-file validation and source fences remain. Page verification uses
the serial full-validation kernel; the separate usage path is unchanged.

These local mechanisms require independent end-to-end evidence. The native
recovery suite kills the original controller or original remote owner only inside
fresh synthetic fixtures, then checks the same original job identity, effects,
durable output and exit witness. Controller loss and lost replies must recover
without a second launch. Owner loss without an authoritative exit witness must
remain an unknown outcome. A53 must run those cases with its own qualified ELF;
the earlier A52 passes are historical evidence only.

## Validation requirements

Twenty new direct-path regression tests cover capacity across two full batches,
same-target and global limits, pre-commit cancellation, post-commit cancellation,
expired admission, capture bounds, nonzero exits, caller-runtime destruction,
owner unwind, uncertain waits, repeated shutdown and weak-target reclamation.
They include actual child submission counts and original cleanup checks. They
run as part of the full X230 Rust suite rather than as a replacement subset.

The first A53 qualification stopped at Clippy because one regression test returned
an awaitable value from an async block. Its complete failed entry, worker, logs
and stage gates are retained under `qualification-r01-failed/`. The second source
attempt changes only that test's registration/wait structure: the caller handle
still lives across destruction of its runtime. It adds no lint suppression and
does not change production source or the test's cleanup assertion.

Final acceptance requires the following evidence against the same qualified A53
source map and release executable:

1. All original format, Clippy, complete test and release qualification stages,
   with the original guarded-worker custody and stage host gates.
2. The original fifteen Python commands and dependency precheck, with the full
   qualified-source and supplemental-source copy fences.
3. The three native controller/reply/owner-loss cases and the eight-job native
   concurrency case, including the sixteen pending mixed observation requests.
4. The unchanged small-archive comparison: 8,192 measured calls, 8,848 total calls,
   two opposite ABBA blocks and all six numeric gates.
5. The unchanged large-archive comparison: 80 calls, 32 waves, 65,536 archive
   entries, 512 hot entries, the fixed idle intervals and all sixteen gates.
6. The original six-host, eight-stage native suite, including both inherited-pipe
   hosts, six-host controller recovery, the fixed file ABBA stages and the
   600-second trace-off soak.
7. GitHub source-tree identity against the actual qualified bytes and the actual
   CI outcome for the published commit.

Each attempt has its own immutable directory and retains failures. Missing calls,
failed SSH replies, unexecuted stages or queued CI are not successful results.
The small A52 comparison passed its six regression limits but measured higher
wall time and CPU; it is not a speedup claim. Performance adoption depends on the
complete final candidate evidence, not a successful subset or a diagnostic trace.
