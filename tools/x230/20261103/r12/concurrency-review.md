# R12 concurrency review

This review covers the R11 baseline published at
`fe7d2b8afba882d06b607ec00b8756eed62f6a1f` and the proposed R12 cancellation change.
Source references below name functions rather than mutable line numbers.

## Cancellation change and error ordering

In `src/mcp/runtime/jobs.rs`, R11 `cancel_job` calls `check_ref` synchronously before
acquiring its cancellation publication permit. That path performs the complete
descriptor-checked receipt read and owned JSON decode, up to the existing 4 MiB
source limit, on the asynchronous executor worker.

R12 uses the existing `run_cancel_intent` reservation for the complete preparation:
acquire one of the existing eight cancellation permits, submit one blocking closure,
run `check_ref`, prepare the original intent, append and synchronize it, then return
the permit and the verified original job binding to the remote continuation.
The same permit continues through the response and completion audit. Caller
cancellation cannot release a submitted physical worker early; cancellation before
admission submits no worker. An abandoned preparation may finish its original intent
append but cannot submit the remote cancellation. The observation pool remains separate.

The runtime configuration is an immutable installed `OnceLock`. `check_ref` already
validates its configured host and binding, so the repeated host lookup now occurring
after intent publication does not introduce a configuration-switch window.
The request, remote operation and completion publication remain unchanged.

There are intentional timing differences. A saturated cancellation pool now delays
invalid-receipt validation too. A closed pool returns the existing intent-unavailable
error before reading the receipt; formerly a bad receipt could fail first. With a
permit available, receipt errors still precede intent preparation/append failures and
retain their original message. The intent timestamp is now captured when the blocking
preparation runs, rather than before capacity backpressure. Byte-identical audit
timestamps are not claimed. When using an unwinding test/build profile, a preparation panic is converted to the
existing worker failure result before any remote operation. The release profile
retains `panic = "abort"`, so a panic terminates the controller and is not caught
as a worker failure result.

Eight permits bound submitted cancellation preparation and retained continuation
records, not all incoming request objects or the shared Tokio blocking pool. Compared
with a single executor worker, concurrent large rejected reads can temporarily decode
more records; compared with the old successful-cancellation backlog, admission now
occurs before owned receipt allocation. Memory results therefore depend on workload.

## Duplicate remote request checks: candidate deferred

The following are in `src/mcp/runtime/jobs.rs`:

- `BOUND_OBSERVATION_CODE` calls `private_job_directory` and `private_read_json` for
  `request.json`, checks the original job ID, path, unit and full request digest, and
  keeps that decoded value in `_bound_request`.
- `STATUS_CODE` opens the directory again and `one_status` rereads `request.json`;
  status polling repeats its observations.
- `READ_CODE` and `CANCEL_CODE` also open the directory and read the request again.
- `private_read_json` validates descriptor and current-path metadata before and
  after each read; `private_job_directory` pins a newly verified descriptor chain.

Reusing the initial `_bound_request` and final directory descriptor could avoid
duplicate traversal and JSON decoding. It would also change which subsequent
filesystem changes the operation observes. A directory pathname can be replaced
while its old open descriptor remains valid. A request file can be atomically replaced
after the first read. A still-valid old descriptor, equal file length, or unchanged
mtime alone does not prove that the current pathname still denotes the same bytes.
Checking only a final file's mtime also omits directory and inode identity, ctime,
ownership, mode, link count and the existing before/after read checks.

A subsequent design must first specify whether one operation uses a validated
request snapshot throughout or refuses later replacement, and how this interacts
with repeated status polling. It needs deterministic phase-boundary tests for
directory replacement, request replacement/content change, original descriptor
retention and terminal publication. No new claim of hostile-same-UID isolation
follows merely from caching an already-read value.

This candidate is **deferred**. The current six-host workload has not isolated the
cost of these checks from SSH process startup, helper startup and durable request
audits. Small requests may save too little to distinguish from shared-host noise.
R12 does not delete or cache any of these remote checks.

## Responsiveness measurement boundary

`run_cancel_responsiveness.py` uses fresh local native MCP controllers, synthetic
hosts and identical receipts, with ordinary request audits enabled. Every cancellation
uses a configured host different from the stored owner and must fail with the exact
host-binding error after complete receipt validation. Each wave submits the same
number of cancellations followed by one `host_list`; two waves warm up each fresh
controller before an ABBA measurement. The original receipt must remain unchanged,
no cancellation operation intent may appear and the fixture SSH guard must remain
unused. There are no retries or successful-response filtering.

Host-list latency is measured from the common wave send boundary to the reader
thread's receipt timestamp. CPU uses same-PID/start-ticks controller counters.
Optional `/proc/status` VmHWM is whole-child memory since exec, not per-call memory.
The results describe finite rejection-load control-plane responsiveness; they do not
measure successful remote cancellations, production task throughput, target reboot
or distributed ownership transfer.

## Final diff review after source formatting

The final R11-to-candidate diff was reread independently after the X230 formatting
sync. Cancellation changes are confined to `run_cancel_intent`, `cancel_job` and
their tests; the remote request fields, transport call, cancellation grace limit
and completion-audit submission sequence are unchanged. The persistence encoder
change is separate from this cancellation review. No new blocking operation is
left on the executor in the changed receipt-preparation path.

The memory benefit is admission order: previously every valid cancellation could
decode and retain a full owned receipt while waiting behind the eight publication
permits. Now a queued caller retains its request parameters before admission;
full receipt decoding begins only after its original permit is obtained. This
bounds the submitted preparation cohort and the retained records of active callers,
but does not bound the number or total size of all queued request parameters.
The 4 MiB encoded receipt limit is also not an equal-size bound on decoded heap
allocation, which includes collection and string allocation overhead.

The wrong-host rejection benchmark exercises a different tradeoff. The old code
could decode only on the available asynchronous executor workers, whereas the new
code can have up to eight admitted blocking preparations decoding simultaneously.
Short-lived RSS can therefore rise on the large rejected-receipt workload even
when control-plane responsiveness improves. The measurements must retain that
increase; this patch does not imply universally lower RSS.

The eight cancellation permits are not a new global bound on physically outstanding
remote cancellation attempts. If the whole caller future is dropped during its
remote await, its local continuation permit can be released while the existing
direct-transport owner still owns the original SSH child. This behavior predates
the patch. A submitted blocking preparation still holds its permit until exit,
and the unchanged completion path submits the received ACK's audit worker before
its next cancellable suspension. Transport custody and publication capacity remain
separate mechanisms.

Error-order and timestamp changes described above are intentional: exhausted
capacity delays validation, closed capacity can fail before validation, and an
available permit retains the original receipt-error-before-intent-error ordering.
Intent timestamps now describe actual blocking preparation time. Configuration
immutability prevents the relocated repeated host lookup from observing a new
policy version.

The added functional assertions are falsifiable rather than unconditional counters.
Moving preparation back onto the current-thread executor makes the worker-thread
identity/blocked-reader checks fail; releasing a permit when the caller is aborted
makes the physical-capacity and queued-worker assertions fail; admitting the ninth
preparation changes its entry counter; swallowing a corrupt or missing receipt
error makes `unwrap_err` fail or allows an observable intent append. The public
`cancel_job` test separately saturates the actual cancellation semaphore and polls
an invalid reference, detecting a return to validation-before-admission wiring.
The helper tests use a counter after preparation to represent remote continuation;
they are not a substitute for the actual MCP refusal campaign or successful
six-host cancellation/recovery checks. No claim is made here that qualification
or those separate live scenarios have already completed.
