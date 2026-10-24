# Standalone controller-custody slice, r01

This is a prepared experiment, not a runtime recovery implementation. The
probe driver is an already existing owner process. It creates exactly two
fixed children: a controller client and a socket writer. Thus there are three
subject processes; a production controller launching its own owner is not
the topology under test.

Run the frozen `custody_harness.py` once on x230 with the existing Python
interpreter and no arguments. The script requires a fresh
`/home/qian/hepta-runtime-optimization-20261023/a27-custody-owner-r01`
directory and refuses to reuse it. It accepts no path or command overrides.
It invokes no SSH, production runtime, remote job, or historical-root scan.
The existing six A26 sockets are outside its scope.

## What the experiment can establish

The owner stores each `OriginalChild` object before calling its `start`
method. The original `Popen` is stored immediately on creation, before
subsequent log closure, pidfd acquisition, identity checks, or publication can
fail. A pidfd is opened before that child is polled or reaped. The owner holds
the new root's directory descriptor throughout the experiment.

The controller requests its one writer over an inherited socket pair. The
owner creates the writer, checks its exact parent/birth/UID/executable/argv
identity, and verifies the new listening socket's peer PID and UID. It then
allows the controller to enter its waiting state. The writer receives only
its directory and readiness/stop/notice descriptors; neither controller
socket endpoint is included in its inherited descriptor set.

The sole SIGKILL is sent through the original controller's pidfd. The owner
requires exit code -9 and a terminal pidfd, and reaps the original `Popen`.
The writer must still match its original live identity both before and after
the owner receives control-channel EOF. This is the concrete check that a
live writer is not withholding that channel's final close.

Only after EOF does the owner record its frozen state, send SIGTERM through
the original writer's pidfd, receive the fixed TERM notice, and require exit
zero, terminal pidfd, and reaping of the same writer. It compares the complete
socket stamp before and after termination and **retains that socket**.

The admission flag is a **one-request state-machine observation**. There is
no second client, queued request, or concurrent admission attempt in this
experiment. It is not a general admission-race test. The process and socket
checks also do not establish protection against same-UID path replacement.

## Failure and evidence rules

Every phase has a five-second protocol/wait budget. The owner never searches
for a replacement child by PID, retries a launch, or falls back to a different
root. On an ordinary error it closes its dedicated channel/stop-pipe ends and
waits for the original children. Those fixed helpers can exit on their
respective EOF. A writer that cannot be reaped makes the experiment fail;
there is no writer SIGKILL retry or claim of successful cleanup. No
parent-death signal policy is configured by this fixture.

The output preserves a create-only plan, event stream, four child stdout and
stderr files, original process/root/socket identity records, and a report
binding artifact bytes and SHA256 values. Files ending `.private.json`
contain raw process or inode identities and **must not be published raw**.
Their presence is diagnostic; saved PIDs are never later treated as signal
authority. The public report refers to these files by name and digest and
does not contain their raw identities. Source bytes are checked again at the
end. There is no filesystem deletion code, including on failure.

Passing requires the exact set of fourteen named checks, original-child
reaping, no recorded main or cleanup error, unchanged source, and four empty
child logs. Errors after the final observation phase still prevent success.
The source manifest and static receipt describe preparation only; root owns
the sole x230 execution and must retain a failed attempt without overwriting
it or repeating the workload until it passes.

This experiment does not test owner death, production owner startup, an SSH
master, shared-UID namespace exclusion, old-root reclamation, host reboot,
power loss, or exactly-once external effects. Its purpose is to turn the first
custody requirement in `SOCKET_CUSTODY_DESIGN.md` into a bounded observation
while leaving the separate namespace/deletion requirement unresolved.
