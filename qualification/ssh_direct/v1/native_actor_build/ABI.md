# Direct SSH native owner: build candidate

This source is an unqualified native actor candidate. No original target
application, HIA runtime application, or lifecycle domain has executed for it.

The four HIA policies decide one-shot admission, original-child custody, shared
owner/registry/join transitions, and bounded concurrent pipe I/O. The native
adapter owns actual Linux mappings, threads, descriptor tables and original
processes. It links without libc or Rust. The owner is independent of callers.
A completed or uncertain original attempt is never automatically replaced.

## Native capability API

* start(observer, opaque) returns the original process-global context or negative errno.
* submit(context, command frame, frame extent, input, input extent, options)
  returns a caller-owned request, including a completed early-error handle.
* cancel(request) performs separate actual queued CAS and token publication.
* result(request, 96-byte result) returns 1 pending or 0 with the owner's result.
* request_release(request) cancels and drops the caller's one reference.
* freeze() makes global admission stop permanently.
* shutdown(context) creates at most one independent original join worker and
  returns 1 pending, 0 confirmed original join success, or negative error.
* join_result(context) observes that same persistent join receipt.

Exact original process-local pointers are capabilities. Public JSON cannot
select a PID, callback, executable, or ownership identity. result is the owner's
raw borrowed view. The outer caller deadline/post-reply future adapter and SSH
command/configuration builder remain separate integration obligations.

Observer receives immutable HSSJRN01 records containing complete input, work and
output before and after every real HIA call, including the raw return and actual
addresses. It runs after policy locks and the commit/freeze gate are released.
Callbacks must return and cannot reenter start. Instrumentation may block without
holding that admission gate. Production may omit the observer.

A request owns copied command/input, argv/env pointers, three pipe ends, one
original PID, two bounded 8-MiB output mappings, an 8192-byte read scratch, its
three policy workspaces and its Entry/guard. The registry grows without a fixed
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

## Build scope

The recipe compiles HIA and assembles/links an inspection image only. That image
is a library inspection artifact; direct execution at its start symbol is
forbidden. Runtime qualification requires a separately frozen domain, harness,
observer and independent complete-byte reader. Limits are 60 seconds per new
application, 180 seconds per pure reader, 900 seconds per build and 15 minutes
per CI job. Completed or UNKNOWN application captures cannot be replayed.

The installed-source binder reads immutable artifact 14375126162 only. Its 42
refusals and relocation 1 are complete. It exports actual retained reader source
before the remaining relocation 2 pure continuation, executing no retained code.

No public route, full SSH SDK, cold qualification or old-stack removal is claimed.
