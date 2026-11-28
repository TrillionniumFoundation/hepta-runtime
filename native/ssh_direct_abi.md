# Direct SSH native owner

The unchanged five-policy native actor has completed the frozen thirteen-case
Linux x86-64 lifecycle domain. Actual original and native captures comprise
26 processes and 51 requests per implementation, including 37 simultaneously
live children, one-shot Entry refusal, real exec ENOENT, missing pipes, and
both sides of the 8 MiB capture boundary. All 27,612 HIA calls and 39,439,050
full input/work/output bytes were independently read with actual kernel effects.
Eight physical refusals and two complete relocations of each capture cohort
passed; the final uploaded read executes no application or control again.

The five HIA policies decide one-shot admission, original-child custody, shared
owner/registry/join transitions, bounded concurrent pipe I/O, and the original
outer caller-future timeout/post-reply completion. The native
adapter owns actual Linux mappings, threads, descriptor tables and original
processes. It links without libc or Rust. The owner is independent of callers.
A completed or uncertain original attempt is never automatically replaced.

## Native capability API

* start(observer, opaque) returns the original process-global context or negative errno.
* submit(context, command frame, frame extent, input, input extent, options)
  returns a caller-owned request, including a completed early-error handle.
* cancel(request) performs separate actual queued CAS and token publication.
* result(request, 96-byte result) returns 1 pending or 0 with the owner's raw result.
* capture_result(request, 96-byte result) polls the original caller future. HIA
  decides pending, owner error, success, original deadline, or post-reply inactive.
  Completion is cached, hides partial bytes on errors and performs CancelOnDrop.
* request_release(request) cancels and drops the caller's one reference.
* freeze() makes global admission stop permanently.
* shutdown(context) creates at most one independent original join worker and
  returns 1 pending, 0 confirmed original join success, or negative error.
* join_result(context) observes that same persistent join receipt.

Exact original process-local pointers are capabilities. Public JSON cannot
select a PID, callback, executable, or ownership identity. result is the owner's
raw borrowed view. capture_result is the outer future. The SSH command/configuration
builder and public async caller integration remain separate obligations.

Observer receives immutable HSSJRN01 records containing complete input, work and
output before and after every real HIA call, including the raw return and actual
addresses. It runs after policy locks and the commit/freeze gate are released.
Callbacks must return and cannot reenter start. Instrumentation may block without
holding that admission gate. Production may omit the observer.

A request owns copied command/input, argv/env pointers, three pipe ends, one
original PID, two bounded 8-MiB output mappings, an 8192-byte read scratch, its
four request policy workspaces and its Entry/guard. The registry grows without a fixed
child/task limit. Entry is consumed on the independent owner immediately before
fork/exec. Failed spawn drops the guard. Successful spawn retains it until the
original wait confirms reap, the exact registry row is removed and pipe borrows
have ended. Cleanup error retains the original child for final drain; uncertain
wait forbids an uncertain signal.

The owner blocks SIGPIPE only on its own thread so actual EPIPE reaches HIA, and
restores its prior signal mask before child exec. Every child installs Linux
PDEATHSIG SIGKILL and checks its controller. After fork, only syscalls and reads
of already-owned primitive memory occur.

The kernel clear_child_tid slot identifies actual original owner termination.
Only then does the join worker acknowledge HIA completion and free the original
owner stack. The process-global context, failed custody and join worker stack
remain for process lifetime. A failed join-worker creation reports a native error
without falsely acknowledging an actual join.

## Installation and qualification scope

The production package contains only the five raw HIA modules, their exact
composition identities, seven syscall ownership files and the direct build
recipe. Authoring pseudocode, C carriers and Rust reference tests are retained
only in immutable qualification commits. The build emits an ordinary relocatable
native library plus an inspection ELF; do not execute the inspection entry as
an application. It has no libc, Python or Rust runtime dependency.

The actual thirteen-case domain closes the captured original-child ownership,
pipe/stream/result, caller cancellation/deadline, guard retention, shared
registry growth and unique persistent clear_tid join observations. Completion
of this domain does not qualify configured SSH command construction, a real
network session, remote helper deployment, observation pools, public routing,
all SDK behavior or every possible kernel-failure path. Those integrations
remain explicit caller obligations. Production can omit its observer; the
current actor application domain used complete observation, so observer-off
integration still needs its own actual qualification.

All original captures and the first pure pipe-label reader failure remain
preserved. The corrected reader changed no production bytes or completed
application. Budgets remain 60 seconds per new application, 180 seconds per
pure reader, 900 seconds per build and 15 minutes per CI job. Completed or
UNKNOWN captures are never replayed.
