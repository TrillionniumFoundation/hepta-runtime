# X230 A40 output recovery and persistence design

## Scope and source identity

A40 revision 02 preserves the original per-stream output waiting budgets while
recovering a normally exiting leader whose same-group descendants retain its
stdout or stderr pipes. It also retains A38's post-spawn output-reader startup
recovery. A failed reader is not treated as natural EOF, and terminating an
inherited writer cannot convert incomplete capture into a successful result.

This note describes the implemented supervisor and status protocol. Final X230
qualification and the subsequent same-executable validation series have
completed. Gate outcomes, the qualified executable identity and the full source
map are recorded in the [qualification receipt](evidence/x230-a40/qualification.json);
the follow-up stages are bound by the
[validation-series receipt](evidence/x230-a40/validation-series.json). Acceptance
conclusions and experimental limits should be read with those receipts and the
main A40 checkpoint report. Historical A39 runs do not qualify the A40 executable.

The frozen source reviewed for this design has the following SHA256 values:

| Repository file | SHA256 |
| --- | --- |
| [`src/mcp/runtime/jobs.rs`](../src/mcp/runtime/jobs.rs) | `1d36886898a2ec2bfd6980df7e1901ca378840639c09d47647d77faf3f49ea6d` |
| [`src/mcp/runtime/jobs_output_durability_tests.rs`](../src/mcp/runtime/jobs_output_durability_tests.rs) | `98d1bebeadc09c0b38304c33145c0aac445bc55fb5d547501f1125ef75a1f50f` |

The second digest is the X230-formatted test source, not the earlier local
pre-format draft. A40 changes the supervisor embedded in `jobs.rs` and its
output-durability tests. The archive and file-observation mechanisms described
in the A38 checkpoint retain their separate performance evidence; this recovery
change makes no new throughput claim.

## Execution boundary and original process-group identity

The workload is created with `Popen(..., start_new_session=True)`. Before that
creation, the runner binds its private job directory, request fingerprint and
launch nonce, takes its lifetime owner lock, and publishes owner intent and
started metadata. Staged inputs and runner source have file and directory
synchronization barriers. Existing or ambiguous launch artifacts prevent a
fresh launch from silently replacing an uncertain one. These mechanisms are
implemented in `START_CODE`, `private_bound_job_directory`, `stage_file`, and
the embedded runner in [jobs.rs](../src/mcp/runtime/jobs.rs).

After `Popen` returns, execution may already have had external effects. Failure
to start a capture thread is therefore a post-spawn failure even if no output
has been observed. A missing complete output log cannot establish that the
workload did nothing.

For a normally exiting leader, the supervisor observes exit without consuming
the original child's wait status:

| Platform | Observation used by this supervisor |
| --- | --- |
| Linux | `waitid(P_PID, child.pid, WEXITED | WNOHANG | WNOWAIT)` |
| macOS | A kqueue process-exit event for the original child |

The original child is retained until every required group-signal attempt is
complete. Only then does this path call the original `child.wait()`. Keeping
that unreaped leader is the basis for addressing its original group without
reconstructing authority from a saved PID. The capability checks for these
non-reaping observation mechanisms precede workload submission.

This is live supervisor custody. `child.json`, PID/start information, owner
metadata and a matching job identifier support identity checks, but they do
not independently grant a future process permission to signal an arbitrary
old PID or PGID. This supervisor algorithm is not a pidfd-based recovery
algorithm, and it does not implement custody transfer after the supervisor
itself dies. A controller restart while a remote supervisor remains alive is
a different failure case.

## Reader startup failure after spawn

The retained A37/A38 failure path surrounds construction and startup of the
two output-reader threads. If startup raises an exception after spawn, the
runner performs these actions in order:

1. Preserve the original startup exception as the primary error.
2. Attempt `SIGKILL` on the original child group while the child is still
   unreaped; record whether submission returned, the group was already absent,
   or submission failed.
3. Wait on the original `Popen` child, with a two-second wait timeout, and record
   whether that wait actually reaped it.
4. Join every reader with an observable thread identity, with a two-second
   timeout per such reader. Check whether it is still alive. Close the pipe
   directly only when no started reader identity was observed.
5. Publish an error receipt with `exit_code=125`, `child_spawned=true`,
   `effect_outcome="unknown"`, `automatic_retry=false`, and both output flags
   false. Preserve cleanup errors separately from the startup error.

A returned join is followed by an actual liveness check; the error path does
not assert that all readers stopped merely because it attempted a join. If
publishing the error receipt also fails, the original startup exception is
preserved with the publication failure as its cause. There is no successful
terminal receipt manufactured from that failure.

The normal-exit four-second window described below does not apply to this
separate startup-failure path. Its original-child wait and per-reader join
timeouts are distinct. Blocking kernel operations are also outside any hard
wall-clock guarantee.

The test
`reader_start_failure_reaps_original_child_and_preserves_unknown_effect`
injects failure of the second thread's startup after both a real child receipt
and the child's execution marker exist. It checks the product's own wait and
join events, original receipt bytes and witness, and an empty fixture-rescue
record. The fixture's final cleanup cannot supply the wait or join needed to
pass that test. See the [output-durability tests](../src/mcp/runtime/jobs_output_durability_tests.rs).

## Normal leader exit: retain the original sequential budgets

The earlier normal path waited up to two seconds for stdout, followed by up
to two seconds for stderr. A single two-second natural-drain window is a
compatibility regression: stdout can finish at about one second and stderr
at about 2.5 seconds while both original waits still succeed.

That counterexample was executed on X230. A38 completed naturally with full
output; the rejected A39 candidate killed the original same-group descendant
and reported Unknown. The [original regression report](evidence/x230-a40/a39-staggered-regression.json)
retains the original requests, receipts, signals, waits and descendant exit
results. Passing A39's earlier tests did not invalidate this counterexample.

Let `t0` be the monotonic time at which the supervisor observes normal leader
exit and enters its drain window. A40 revision 02 implements these deadlines:

| Phase | Natural waiting deadline | Condition for advancement |
| --- | --- | --- |
| stdout | `t0 + 2 seconds` | stdout EOF, its reader actually ended, and its drain-completion timestamp is at or before this deadline |
| stderr | `min(t0 + 4 seconds, time stdout completion is observed + 2 seconds)` | stderr satisfies the same EOF, thread-completion and timestamp conditions |
| Cleanup after forced termination | Remaining time before `t0 + 4 seconds` | Check actual reader termination; do not add a new join interval |

An early stdout completion allows stderr its own two-second wait immediately.
A late completion timestamp cannot retrospectively make an expired reader
successful. `log_drain_finished` is recorded after the drain function's stream
close handling; the supervisor also checks `is_alive()`, because the timestamp
alone does not prove the thread has returned.

If a reader does not meet its natural completion conditions by its deadline,
the supervisor retains a drain error and attempts `SIGKILL` on the original
group before reaping the leader. It then waits only within the remaining
absolute window. A final stderr expiry can leave no remaining join time. The
runner still attempts the signal before the original child wait and records
any reader that remains alive; it does not describe that reader as joined.

The four-second limit bounds the normal post-exit drain/join waiting budget.
It is not a four-second bound on job execution, exit detection, OS scheduling,
signal delivery, `fsync`, terminal publication, or arbitrary blocking kernel
calls. Polling and scheduling can also delay observation of a deadline. No
additional eight-second cancellation grace is opened within this window.

These transitions are implemented around `leader_reader_deadline`,
`leader_reader_index`, `leader_drain_until` and the final reader joins in
[jobs.rs](../src/mcp/runtime/jobs.rs). The fixed
`staggered_output_eof_preserves_each_original_reader_budget` test requires
natural child and descendant exit, exact output bytes, no product group signal,
no fixture rescue, and confirmed original receipt/witness binding.

## EOF, reader termination and output errors are different facts

The drain function sets `log_eof[label]` only when `read1` returns no bytes.
An exception from `read1` records a `read:` error and ends the reader without
setting EOF. A reader can therefore be dead while a descendant remains alive
and holds the write ends of its inherited pipes.

The rejected A40 revision 01 advanced on thread termination and its timestamp
without requiring EOF. Two failed readers could take that path directly to
leader reap, losing the original group identity before terminating the live
descendant. Revision 02 requires all three natural-completion facts in the
table above. This is a recovery requirement in addition to the later
`output_complete` check; marking output incomplete after early reap would not
repair the lost process-group custody.

The regression test
`inherited_pipe_read_failures_kill_original_group_before_reap` wraps the
stdout and stderr objects of a real `Popen` child and raises an `OSError` on
each `read1`. The same original descendant retains its pipes and would
self-exit after eight seconds. It does not write to the closed pipes, so
accidental `SIGPIPE` cannot substitute for the product's `SIGKILL`. The test
checks two injected read errors, two false EOF flags, ended readers, a signal
while the original leader is exited but unreaped, original leader exit 0,
descendant exit -9, no fixture rescue, and preservation of the original read
errors in the Unknown receipt. Exact witness binding is checked separately.

Write errors have a different capture behavior: the reader continues draining
to avoid blocking the producer, while retaining the storage failure and
accurate seen/stored counters. Truncation, read errors, write errors, close
errors or synchronization errors prevent a complete successful output result.
Natural EOF plus an ended thread permits the waiting state machine to advance;
it does not erase those errors. See `drain` and the final completeness checks
in [jobs.rs](../src/mcp/runtime/jobs.rs).

## Cancellation during an existing drain window

When cancellation needs to signal an inherited writer during this normal
post-exit window, the runner records the forced-drain error before attempting
`SIGTERM`. This order matters: a descendant with the default TERM disposition
can immediately close both pipes and let both readers return. That new EOF
cannot clear the already recorded Unknown/incomplete outcome.

If TERM does not cause completion, escalation uses the existing reader
deadline and the original four-second absolute window. It does not renew the
window. A failure or an already-absent result from the signal attempt does
not establish successful capture. Existing capture errors are retained when
the forced-drain error is recorded.

This is distinct from cancellation or timeout before entry into the normal
post-exit drain window. That pre-existing running-job path retains its original
TERM and eight-second escalation logic. A40 does not replace that whole
algorithm. The inherited-pipe fixture covers both TERM ignored until KILL and
default TERM closing the pipes immediately; both forced post-exit cases retain
Unknown and prohibit automatic retry.

For a forced drain the receipt preserves the original leader's exit status as
`child_exit_code`, but its terminal `exit_code` is 125. It records
`effect_outcome="unknown"`, `status_authoritative=false`,
`automatic_retry=false`, `output_complete=false`, and `output_durable=false`.
`final_status` gives `effect_unknown` precedence over cancelled and timed-out
labels. A leader exit of zero does not establish the effects of a descendant
that had to be terminated. These semantics are in the runner's terminal
update and `STATUS_CODE.final_status` in [jobs.rs](../src/mcp/runtime/jobs.rs).

`child_group_signal="submitted"` means the original group-signal call
returned. It is not proof that every member of an arbitrary process tree is
dead or reaped. The receipt records signal failures and cleanup errors, and
the controlled fixtures independently verify the one descendant they created.
Descendants that move to another session or process group are outside this
mechanism's coverage.

## Output persistence and the terminal witness

The implementation separates capture completeness from synchronization:

| Field | Meaning in this implementation |
| --- | --- |
| `log_bytes` | Bytes seen and bytes actually stored for each stream |
| `log_errors` / `log_truncated` | Capture, close or sync failures, and any bounded-mode truncation |
| `log_synced` | The completed stream's final flush and file `fsync` returned |
| `output_complete` | Both streams reached EOF, no recorded errors or truncation remain, and no forced-drain error was recorded |
| `output_durable` | `output_complete` is true and both completed streams have `log_synced=true` |

For ended readers, the supervisor performs one final flush and file `fsync`
per output stream before publishing a terminal receipt. It does not synchronize
each chunk. A stream whose reader remains alive cannot claim that final
synchronization. Synchronizing a captured prefix after forced termination is
useful, but it does not make the complete output durable. An output sync failure
can leave a workload exit code of zero in the receipt while the supervisor
exits 74 and status is failed.

Terminal publication is ordered as follows:

1. Write the exact `exit.json` bytes to an exclusively created temporary file.
2. Flush and `fsync` that file, replace `exit.json`, and `fsync` the pinned job
   directory.
3. Only after those operations return, publish `exit.witness.json` containing
   protocol version 1, job ID, launch nonce and SHA256 of those exact exit bytes.
4. Status reads validate the original private regular files, metadata stability,
   request/receipt/witness identities, supported protocol and exact exit hash.

An absent, unsafe, malformed or mismatching required witness leaves publication
unconfirmed, with no automatic retry. Compatible legacy requests and receipts
without the additive protocol fields retain their existing read behavior.

A visible matching witness demonstrates that the preceding exit-file and
directory synchronization operations returned before witness publication was
attempted. It does not demonstrate that the witness's own final directory
sync completed or that either file survived an actual power interruption.
The witness hashes the terminal receipt, not the log files or arbitrary
external effects. Native canaries separately compare the output bytes, hashes,
cursors and metadata with the original job files.

The ordering and its limits are implemented by `atomic`, `publish_terminal`,
`read_terminal_status` and `publication_pending` in
[jobs.rs](../src/mcp/runtime/jobs.rs), with explicit failure cases in the
[terminal-publication tests](../src/mcp/runtime/jobs_terminal_publication_tests.rs).
The output tests check both output-file barriers before terminal publication
and failure of either stream's synchronization.

## Evidence and acceptance boundaries

The [prequalification report](evidence/x230-a40/prequalification-report.json)
contains the eight X230 checks, including the rejected-candidate counterexamples
and the five revision-02 inherited-pipe configurations. Their expected outcomes
were observed before the full qualification sequence. The complete rejected
attempts and prequalification originals are retained in
[rejected-and-prequalification.tar.gz](evidence/x230-a40/rejected-and-prequalification.tar.gz).
The report inside that archive is
`a40-staggered-output-recovery-20261025-r02/prequalification-proofs-r01/report.json`,
69,077 bytes, SHA256
`f1f4eed2f88bc5e196b8a54a057332e540b0852471b64acbadd84603fd81ae27`.
These are targeted recovery observations, not a substitute for the final gates.

The revision-02 configurations cover a persistent inherited pipe, cancellation
with TERM ignored, cancellation with immediate TERM EOF, naturally staggered
stdout/stderr EOF, and two ended readers with injected read failures. The Linux
fixtures record the product's signals and waits separately from fixture rescue,
use the original execution marker and descendant identity, and collect their
fixed descendant even on a rejected baseline. Harness cleanup cannot make an
incorrect product outcome pass.

The additional native script `x230_inherited_pipe_canary_a40.py` defines six
default cases: natural, staggered and timeout on each of X230 and Mac. An
optional X230 cancellation case first requires an observation of the original
bound, unreaped leader. Every start and cancellation is submitted once. The
script retains original native requests/responses, original job metadata and
output, an execution-once marker, witness checks, and cleanup observations.
Its fixed descendants self-exit within their specified eight-second waiting
budget when product termination fails; the harness does not rescue a failed
case by signaling a discovered remote PID. The staged EOF markers record
content and phase completion, not independent measurements of actual EOF time.

The local Rust fixtures are Linux-specific. Full X230 compilation/test gates
and the native Mac kqueue path are separate checks. Completed A39 canaries,
controller recovery or soak runs cannot be relabeled as A40 revision-02 runs.
The completed final series binds its follow-up reports to the same executable
digest as the qualified release, as recorded in the
[validation-series receipt](evidence/x230-a40/validation-series.json).

## Unproved cases and future design work

The implemented mechanisms above remain distinct from the following future
work. None of these items is a claim that A40 already implements or validates
the corresponding recovery guarantee.

| Case | Current boundary | Future design and evidence needed |
| --- | --- | --- |
| Blocking kernel I/O or an uninterruptible process | A Python join deadline and group signal do not force a blocked read, write, close or `fsync` to return. Submission of KILL is not an end-to-end recovery deadline. | Evaluate separate capture custody and watchdog/error-publication protocols; test stuck-I/O behavior without claiming a durable result when its barrier did not return. |
| Ownerless controller sockets and old socket roots | A40 does not add authoritative reclamation of stale controller socket roots. A pathname or old PID alone is insufficient evidence of current ownership. | Design durable resource provenance plus live original-process custody or a verified handoff protocol before automated cleanup. Retain uncertain roots rather than treating a pathname match as authority. |
| Supervisor death or descendants leaving its group | The original-child relationship is held by the live supervisor; same-group signals cannot control escaped descendants. | Design independent custody, explicit group/container coverage and reconciliation rules; validate the relevant OS and failure modes separately. |
| Host reboot and abrupt power loss | Returning file/directory barriers and observing controller-crash recovery do not constitute a reboot or power-cut experiment. A visible witness does not prove its own final directory barrier. | Exercise reboot, power-cut and storage-fault points; reconcile boot/incarnation changes and uncertain publications without automatically recreating external effects. |
| General exactly-once external execution | Launch bindings, retained originals, execution markers and no automatic retry constrain this protocol. They cannot prove whether an arbitrary remote business effect committed before failure. | Use application-specific idempotency or a transactional external commit/query protocol, with explicit handling of effects that cannot be reconciled. Unknown must remain a valid outcome. |

These boundaries also apply when a controlled fixture is fully cleaned up.
One known descendant's termination and one matching witness do not establish
universal process cleanup, power-loss durability, or exactly-once execution.
